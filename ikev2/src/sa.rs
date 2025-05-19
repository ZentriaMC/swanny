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

#[derive(Debug)]
pub enum ControlMessage {
    IkeMessage(Vec<u8>),
}

#[derive(Clone)]
pub struct IkeSa {
    data: Arc<RwLock<StateData>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
    config: Config,
    sender: UnboundedSender<ControlMessage>,
}

impl IkeSa {
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

    pub(crate) fn choose_proposal<'a, 'b>(
        this: impl IntoIterator<Item = &'a Proposal>,
        other: impl IntoIterator<Item = &'b Proposal>,
    ) -> Option<ChosenProposal> {
        let mut this = this.into_iter();
        let mut other = other.into_iter();
        if let Some(proposal) = this.find_map(|px| other.find_map(|py| px.intersection(py))) {
            match ChosenProposal::new(&proposal) {
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

pub(crate) struct ChosenProposal {
    protocol: Protocol,
    cipher: Cipher,
    prf: Prf,
    integ: Option<Integ>,
    group: Option<Group>,
}

impl ChosenProposal {
    pub fn new(proposal: &Proposal) -> Result<Self> {
        let transform = proposal
            .transforms()
            .find(|t| t.ty() == Num::Assigned(TransformType::ENCR))
            .ok_or_else(|| anyhow::anyhow!("ENCR transform not found"))?;
        let id: EncrId = transform.id().try_into()?;
        let attribute = transform
            .attributes()
            .find(|a| a.ty() == Num::Assigned(AttributeType::KeyLength))
            .ok_or_else(|| anyhow::anyhow!("KeyLength attribute not found"))?;
        let cipher = Cipher::new(id, Some(u16::from_be_bytes(attribute.value().try_into()?)))?;

        let transform = proposal
            .transforms()
            .find(|t| t.ty() == Num::Assigned(TransformType::PRF))
            .ok_or_else(|| anyhow::anyhow!("PRF transform not found"))?;
        let id: PrfId = transform.id().try_into()?;
        let prf = Prf::new(id)?;

        let integ = if cipher.is_aead() {
            None
        } else {
            let transform = proposal
                .transforms()
                .find(|t| t.ty() == Num::Assigned(TransformType::INTEG))
                .ok_or_else(|| anyhow::anyhow!("INTEG transform not found"))?;
            let id: IntegId = transform.id().try_into()?;
            Some(Integ::new(id)?)
        };

        let transform = proposal
            .transforms()
            .find(|t| t.ty() == Num::Assigned(TransformType::DH));
        let group = match transform {
            Some(transform) => {
                let id: DhId = transform.id().try_into()?;
                Some(Group::new(id)?)
            }
            None => match proposal.protocol() {
                Num::Assigned(Protocol::IKE) => {
                    return Err(anyhow::anyhow!("DH transform not found"));
                }
                _ => None,
            },
        };

        Ok(Self {
            protocol: proposal.protocol().try_into()?,
            cipher,
            prf,
            integ,
            group,
        })
    }

    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }

    pub fn prf(&self) -> &Prf {
        &self.prf
    }

    pub fn integ(&self) -> Option<&Integ> {
        self.integ.as_ref()
    }

    pub fn group(&self) -> Option<&Group> {
        self.group.as_ref()
    }

    pub fn generate_keys(
        &self,
        skeyseed: impl AsRef<[u8]>,
        n_i: impl AsRef<[u8]>,
        n_r: impl AsRef<[u8]>,
        spi_i: &Spi,
        spi_r: &Spi,
    ) -> Result<Keys> {
        let mut buf = n_i.as_ref().to_vec();
        buf.extend_from_slice(n_r.as_ref());
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

        let mut ai = vec![0; integ_key_size];
        buf.try_copy_to_slice(&mut ai)?;

        let mut ar = vec![0; integ_key_size];
        buf.try_copy_to_slice(&mut ar)?;

        let mut pi = vec![0; self.prf.size()];
        buf.try_copy_to_slice(&mut pi)?;

        let mut pr = vec![0; self.prf.size()];
        buf.try_copy_to_slice(&mut pr)?;

        Ok(Keys {
            deriving: DerivingKeys { d, pi, pr },
            protecting: ProtectingKeys { ei, er, ai, ar },
        })
    }

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

#[derive(Debug)]
pub(crate) struct Keys {
    pub deriving: DerivingKeys,
    pub protecting: ProtectingKeys,
}

#[derive(Debug)]
pub(crate) struct DerivingKeys {
    pub d: Vec<u8>,
    pub pi: Vec<u8>,
    pub pr: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct ProtectingKeys {
    pub ei: Vec<u8>,
    pub er: Vec<u8>,
    pub ai: Vec<u8>,
    pub ar: Vec<u8>,
}

pub(crate) struct ChildSa {
    pub ts_i: TrafficSelector,
    pub ts_r: TrafficSelector,
    pub spi: EspSpi,
    pub peer_spi: Option<EspSpi>,
    pub chosen_proposal: Option<ChosenProposal>,
}

impl ChildSa {
    pub fn new(ts_i: &TrafficSelector, ts_r: &TrafficSelector) -> Result<Self> {
        let mut spi = EspSpi::default();
        crypto::rand_bytes(&mut spi)?;

        Ok(Self {
            ts_i: ts_i.to_owned(),
            ts_r: ts_r.to_owned(),
            spi,
            peer_spi: None,
            chosen_proposal: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config,
        message::{
            Message,
            num::{Num, TrafficSelectorType},
            traffic_selector,
        },
    };
    use futures::{
        SinkExt,
        channel::mpsc,
        stream::{FuturesUnordered, StreamExt},
    };
}
