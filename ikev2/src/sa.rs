//! Security associations
//!
//! This module deals with security associations (SA) both for IKE and
//! IPsec. `IkeSa` is the main entry point to this module and can be
//! used in a `select!` loop with other event sources.
//!
//! # Examples
//!
//! ```rust, no_run
//! # async fn main() {
//! let ike_sa_config = create_ike_sa_config(&config.address, &config.psk);
//!
//! let (ike_sa, mut ike_sa_messages) = IkeSa::new(&ike_sa_config)?;
//!
//! loop {
//!     futures::select! {
//!         message = udp_messages.select_next_some() => {
//!             ike_sa.handle_message(...);
//!         },
//!         message = xfrm_messages.select_next_some() => {
//!             ike_sa.handle_acquire(...);
//!         },
//!         message = ike_messages.select_next_some() => {
//!             match message {
//!                 ControlMessage::IkeMessage(message) => {
//!                     // Send it to the peer
//!                 }
//!                 ControlMessage::CreateChildSa(child_sa) => {
//!                     // Create a Child SA with XFRM
//!                 }
//!             }
//!         },
//!     }
//! }
//! # Ok(()) }
//! ```
use crate::{
    config::Config,
    crypto::{self, Cipher, Group, Integ, Prf},
    message::{
        EspSpi, Spi,
        num::{AttributeType, DhId, EncrId, IntegId, Num, PrfId, Protocol, TransformType},
        proposal::Proposal,
        traffic_selector::TrafficSelector,
        transform::Transform,
    },
    state::{self, State, StateData},
};
use anyhow::Result;
use bytes::Buf;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info};

/// Control message `IkeSa` may asynchronously send to the caller event loop
#[derive(Debug)]
pub enum ControlMessage {
    IkeMessage(Vec<u8>),
    CreateChildSa(Box<ChildSa>),
}

/// IKE SA
///
/// The `IkeSa` data structure is an opaque event handle to drive
/// the IKEv2 state machine.
#[derive(Clone)]
pub struct IkeSa {
    data: Arc<RwLock<StateData>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
    config: Config,
    sender: UnboundedSender<ControlMessage>,
}

impl IkeSa {
    /// Create a new IkeSa from the given configuration
    pub fn new(config: &Config) -> Result<(Self, UnboundedReceiver<ControlMessage>)> {
        let mut spi = Spi::default();
        crypto::rand_bytes(&mut spi)?;

        let (sender, receiver) = unbounded();
        let data = StateData::new(&spi);

        Ok((
            Self {
                data: Arc::new(RwLock::new(data)),
                state: Arc::new(Mutex::new(Some(Box::new(state::Initial {})))),
                config: config.to_owned(),
                sender,
            },
            receiver,
        ))
    }

    /// Returns the initiator/responder status if it has been determined
    pub async fn is_initiator(&self) -> Option<bool> {
        let data = self.data.read().await;
        data.is_initiator
    }

    /// Processes IKE message
    pub async fn handle_message(&self, message: impl AsRef<[u8]>) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(old_state) = state.take() {
            drop(state);

            let old_state_name = old_state.to_string();

            let new_state = old_state
                .handle_message(
                    &self.config,
                    self.sender.clone(),
                    self.data.clone(),
                    message.as_ref(),
                )
                .await?;

            let new_state_name = new_state.to_string();

            let mut state = self.state.lock().await;
            *state = Some(new_state);

            info!("state transitioned from {old_state_name} to {new_state_name}");
        }

        Ok(())
    }

    /// Processes XFRM acquire message
    pub async fn handle_acquire(
        &self,
        ts_i: TrafficSelector,
        ts_r: TrafficSelector,
        index: u32,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(old_state) = state.take() {
            drop(state);

            let old_state_name = old_state.to_string();

            let new_state = old_state
                .handle_acquire(
                    &self.config,
                    self.sender.clone(),
                    self.data.clone(),
                    &ts_i,
                    &ts_r,
                    index,
                )
                .await?;

            let new_state_name = new_state.to_string();

            let mut state = self.state.lock().await;
            *state = Some(new_state);

            info!("state transitioned from {old_state_name} to {new_state_name}");
        }

        Ok(())
    }
}

/// Cryptograhic proposal negotiated with the peer
#[derive(Clone, Debug)]
pub struct ChosenProposal {
    protocol: Protocol,
    spi: Vec<u8>,
    cipher: Cipher,
    prf: Prf,
    integ: Option<Integ>,
    group: Option<Group>,
}

impl ChosenProposal {
    /// Creates a new `ChosenProposal` from a proposal on the wire
    pub fn new(proposal: &Proposal) -> Result<Self> {
        let transform = proposal
            .transforms()
            .find(|t| matches!(t.ty().assigned(), Some(TransformType::ENCR)))
            .ok_or_else(|| anyhow::anyhow!("ENCR transform not found"))?;
        let id: EncrId = transform.id().try_into()?;
        let attribute = transform
            .attributes()
            .find(|a| matches!(a.ty().assigned(), Some(AttributeType::KeyLength)))
            .ok_or_else(|| anyhow::anyhow!("KeyLength attribute not found"))?;
        let cipher = Cipher::new(id, Some(u16::from_be_bytes(attribute.value().try_into()?)))?;

        let transform = proposal
            .transforms()
            .find(|t| matches!(t.ty().assigned(), Some(TransformType::PRF)))
            .ok_or_else(|| anyhow::anyhow!("PRF transform not found"))?;
        let id: PrfId = transform.id().try_into()?;
        let prf = Prf::new(id)?;

        let integ = if cipher.is_aead() {
            None
        } else {
            let transform = proposal
                .transforms()
                .find(|t| t.ty() == Num::Assigned(TransformType::INTEG.into()))
                .ok_or_else(|| anyhow::anyhow!("INTEG transform not found"))?;
            let id: IntegId = transform.id().try_into()?;
            Some(Integ::new(id)?)
        };

        let transform = proposal
            .transforms()
            .find(|t| t.ty() == Num::Assigned(TransformType::DH.into()));
        let group = match transform {
            Some(transform) => {
                let id: DhId = transform.id().try_into()?;
                Some(Group::new(id)?)
            }
            None => match proposal.protocol().assigned() {
                Some(Protocol::IKE) => {
                    return Err(anyhow::anyhow!("DH transform not found"));
                }
                _ => None,
            },
        };

        Ok(Self {
            protocol: proposal.protocol().try_into()?,
            spi: proposal.spi().to_vec(),
            cipher,
            prf,
            integ,
            group,
        })
    }

    pub(crate) fn negotiate<'a, 'b>(
        this: impl IntoIterator<Item = &'a Proposal>,
        other: impl IntoIterator<Item = &'b Proposal>,
    ) -> Option<Self> {
        let mut this = this.into_iter();
        let mut other = other.into_iter();
        if let Some(proposal) = this.find_map(|px| other.find_map(|py| px.intersection(py))) {
            match Self::new(&proposal) {
                Ok(proposal) => Some(proposal),
                Err(e) => {
                    debug!(error = %e, "error");
                    None
                }
            }
        } else {
            None
        }
    }

    /// Returns the protocol (IKE, ESP, or AH)
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the SPI
    pub fn spi(&self) -> &[u8] {
        &self.spi
    }

    /// Returns the cipher algorithm
    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }

    /// Returns the PRF algorithm
    pub fn prf(&self) -> &Prf {
        &self.prf
    }

    /// Returns the integrity checking algorithm
    pub fn integ(&self) -> Option<&Integ> {
        self.integ.as_ref()
    }

    /// Returns the key exchange group
    pub fn group(&self) -> Option<&Group> {
        self.group.as_ref()
    }

    pub(crate) fn generate_keys(
        &self,
        skeyseed: impl AsRef<[u8]>,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
        spi_i: &Spi,
        spi_r: &Spi,
    ) -> Result<Keys> {
        let mut buf = nonce_i.as_ref().to_vec();
        buf.extend_from_slice(nonce_r.as_ref());
        buf.extend_from_slice(&spi_i[..]);
        buf.extend_from_slice(&spi_r[..]);
        let integ_key_size = self
            .integ
            .as_ref()
            .map(|integ| integ.key_size())
            .unwrap_or(0);
        let buf = self.prf.prfplus(
            skeyseed,
            &buf,
            self.prf.size() * 3 + self.cipher.key_size() * 2 + integ_key_size * 2,
        )?;
        let mut buf = buf.as_slice();

        let mut d = vec![0; self.prf.size()];
        buf.try_copy_to_slice(&mut d)?;

        let mut ei = vec![0; self.cipher.key_size()];
        buf.try_copy_to_slice(&mut ei)?;

        let mut er = vec![0; self.cipher.key_size()];
        buf.try_copy_to_slice(&mut er)?;

        let (ai, ar) = if self.integ.is_some() {
            let mut ai = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ai)?;

            let mut ar = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ar)?;
            (Some(ai), Some(ar))
        } else {
            (None, None)
        };

        let mut pi = vec![0; self.prf.size()];
        buf.try_copy_to_slice(&mut pi)?;

        let mut pr = vec![0; self.prf.size()];
        buf.try_copy_to_slice(&mut pr)?;

        Ok(Keys {
            deriving: DerivingKeys { d, pi, pr },
            protecting: ProtectingKeys { ei, er, ai, ar },
        })
    }

    /// Turns this into a `Proposal` data structure sent over the wire
    pub fn proposal(
        &self,
        number: u8,
        protocol: Num<u8, Protocol>,
        spi: impl AsRef<[u8]>,
    ) -> Proposal {
        let mut transforms: Vec<Transform> = Vec::new();

        transforms.push(self.cipher().into());
        transforms.push(self.prf().into());
        if let Some(integ) = self.integ() {
            transforms.push(integ.into());
        }
        if let Some(group) = self.group() {
            transforms.push(group.into());
        }

        Proposal::new(number, protocol, spi.as_ref(), transforms)
    }
}

/// Key materials generated and used by the current IKE SA
#[derive(Clone, Debug)]
pub struct Keys {
    pub deriving: DerivingKeys,
    pub protecting: ProtectingKeys,
}

/// Key materials used for key derivation
#[derive(Clone, Debug)]
pub struct DerivingKeys {
    pub d: Vec<u8>,
    pub pi: Vec<u8>,
    pub pr: Vec<u8>,
}

/// Key materials used for encryption and authentication
#[derive(Clone, Debug)]
pub struct ProtectingKeys {
    pub ei: Vec<u8>,
    pub er: Vec<u8>,
    pub ai: Option<Vec<u8>>,
    pub ar: Option<Vec<u8>>,
}

pub(crate) struct LarvalChildSa {
    pub ts_i: Option<TrafficSelector>,
    pub ts_r: Option<TrafficSelector>,
    pub spi: Option<EspSpi>,
    pub proposals: Option<Vec<Proposal>>,
}

impl LarvalChildSa {
    pub fn new(config: &Config, ts_i: &TrafficSelector, ts_r: &TrafficSelector) -> Result<Self> {
        let mut spi = EspSpi::default();
        crypto::rand_bytes(&mut spi)?;

        let proposals: Vec<_> = config.ipsec_proposals(&spi).collect();

        Ok(Self {
            ts_i: Some(ts_i.to_owned()),
            ts_r: Some(ts_r.to_owned()),
            spi: Some(spi),
            proposals: Some(proposals),
        })
    }

    pub fn build(
        mut self,
        chosen_proposal: &ChosenProposal,
        d: impl AsRef<[u8]>,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
    ) -> Result<ChildSa> {
        let mut child_sa = ChildSa {
            ts_i: self.ts_i.take().unwrap(),
            ts_r: self.ts_r.take().unwrap(),
            spi: self.spi.take().unwrap(),
            chosen_proposal: chosen_proposal.to_owned(),
            keys: None,
        };
        child_sa.generate_keys(d.as_ref(), nonce_i.as_ref(), nonce_r.as_ref())?;
        Ok(child_sa)
    }
}

/// IPsec SA
///
/// The `ChildSa` data structure holds information about the
/// established IPsec SA.
#[derive(Clone, Debug)]
pub struct ChildSa {
    ts_i: TrafficSelector,
    ts_r: TrafficSelector,
    spi: EspSpi,
    chosen_proposal: ChosenProposal,
    keys: Option<ProtectingKeys>,
}

impl ChildSa {
    /// Generates key materials used by this Child SA
    pub(crate) fn generate_keys(
        &mut self,
        d: impl AsRef<[u8]>,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
    ) -> Result<()> {
        let mut buf = nonce_i.as_ref().to_vec();
        buf.extend_from_slice(nonce_r.as_ref());
        let integ_key_size = self
            .chosen_proposal
            .integ()
            .as_ref()
            .map(|integ| integ.key_size())
            .unwrap_or(0);
        let encryption_key_size = self.chosen_proposal.cipher().key_size()
            + self.chosen_proposal.cipher().salt_size().unwrap_or(0);
        let buf = self.chosen_proposal.prf().prfplus(
            d.as_ref(),
            &buf,
            encryption_key_size * 2 + integ_key_size * 2,
        )?;
        let mut buf = buf.as_slice();

        let mut ei = vec![0; encryption_key_size];
        buf.try_copy_to_slice(&mut ei)?;

        let mut er = vec![0; encryption_key_size];
        buf.try_copy_to_slice(&mut er)?;

        let (ai, ar) = if self.chosen_proposal.integ().is_some() {
            let mut ai = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ai)?;

            let mut ar = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ar)?;
            (Some(ai), Some(ar))
        } else {
            (None, None)
        };

        self.keys = Some(ProtectingKeys { ei, er, ai, ar });

        Ok(())
    }

    /// Returns the intiator's traffic selector
    pub fn ts_i(&self) -> &TrafficSelector {
        &self.ts_i
    }

    /// Returns the responder's traffic selector
    pub fn ts_r(&self) -> &TrafficSelector {
        &self.ts_r
    }

    /// Returns the SPI
    pub fn spi(&self) -> &EspSpi {
        &self.spi
    }

    /// Returns the cryptographic proposal chosen
    pub fn chosen_proposal(&self) -> &ChosenProposal {
        &self.chosen_proposal
    }

    /// Returns the key materials
    pub fn keys(&self) -> Option<&ProtectingKeys> {
        self.keys.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, message::traffic_selector};
    use futures::stream::StreamExt;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_sa() {
        let config = config::tests::create_config(b"initiator");
        let (initiator, mut messages_i) = IkeSa::new(&config).expect("unable to create IKE SA");

        let config = config::tests::create_config(b"responder");
        let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

        let initiator2 = initiator.clone();

        tokio::spawn(async move {
            let initiator_addr: IpAddr = "192.168.1.2".parse().unwrap();
            let responder_addr: IpAddr = "192.168.1.3".parse().unwrap();
            let ts_i = traffic_selector::tests::create_traffic_selector(&initiator_addr);
            let ts_r = traffic_selector::tests::create_traffic_selector(&responder_addr);
            initiator2
                .handle_acquire(ts_i, ts_r, 1)
                .await
                .expect("unable to handle acquire");
        });

        let message = match messages_i.next().await {
            Some(ControlMessage::IkeMessage(message)) => message,
            _ => panic!("unexpected message"),
        };

        let responder2 = responder.clone();

        tokio::spawn(async move {
            responder2
                .handle_message(message)
                .await
                .expect("unable to handle message");
        });

        let _message = match messages_r.next().await {
            Some(ControlMessage::IkeMessage(message)) => message,
            _ => panic!("unexpected message"),
        };
    }
}
