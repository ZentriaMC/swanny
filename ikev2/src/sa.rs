//! Security associations
//!
//! This module deals with security associations (SA) both for IKE and
//! IPsec. The main entry point to this module is [`IkeSa`], which
//! maintains state transitions of an IKE SA, triggered by external
//! event sources, such as IKE messages from the peer, Netlink XFRM
//! messages, and timers.
//!
//! # Examples
//!
//! ```rust, ignore
//! # async fn main() {
//! let ike_sa_config = create_ike_sa_config(&config.address, &config.psk);
//!
//! let (ike_sa, mut ike_sa_messages) = IkeSa::new(&ike_sa_config)?;
//!
//! loop {
//!     futures::select! {
//!         message = udp_messages.select_next_some() => {
//!             ike_sa.handle_message(/* ... */).await;
//!         },
//!         message = xfrm_messages.select_next_some() => {
//!             ike_sa.handle_acquire(/* ... */).await;
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
//!
//! [`IkeSa`]: crate::sa::IkeSa
//!
use crate::{
    config::Config,
    crypto::{
        self, AuthenticationKey, Cipher, CryptoError, DerivationKey, EncryptionKey, Group,
        GroupPrivateKey, Integ, Key, Prf,
    },
    message::{
        EspSpi, Spi,
        num::{
            AttributeType, DhId, EncrId, ExchangeType, IntegId, Num, PayloadType, PrfId, Protocol,
            TransformType, TryFromTransformIdError,
        },
        proposal::Proposal,
        serialize::DeserializeError,
        traffic_selector::TrafficSelector,
        transform::Transform,
    },
    state::{self, State, StateData, StateError},
};
use bytes::Buf;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

/// Control message `IkeSa` may asynchronously send to the caller event loop
#[derive(Debug)]
pub enum ControlMessage {
    IkeMessage(Vec<u8>),
    CreateChildSa(Box<ChildSa>),
    DeleteChildSa(Box<ChildSa>),
    RekeyChildSa(Box<ChildSa>),
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("missing payload")]
    MissingPayload(PayloadType),

    #[error("missing transform")]
    MissingTransform(TransformType),

    #[error("missing SPI")]
    MissingSpi,

    #[error("transform ID conversion error")]
    TryFromTransformId(#[from] TryFromTransformIdError),

    #[error("missing attribute")]
    MissingAttribute(AttributeType),

    #[error("invalid attribute")]
    InvalidAttribute(AttributeType),

    #[error("unexpected exchange")]
    UnexpectedExchange(Num<u8, ExchangeType>),

    #[error("cryptographic error")]
    Crypto(#[from] CryptoError),

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("integrity check failed")]
    IntegrityCheckFailed,

    #[error("no proposal chosen")]
    NoProposalChosen,

    #[error("no proposals received from peer")]
    NoProposalsReceived,

    #[error("no traffic selectors received from peer are acceptable")]
    TrafficSelectorUnacceptable,

    #[error("inconsistent KE group received")]
    InconsistentKeGroup(Num<u16, DhId>),

    #[error("unknown IPsec protocol")]
    UnknownProtocol(Num<u8, Protocol>),

    #[error("deserialization error")]
    DeserializeError(#[from] DeserializeError),

    #[error("temporary failure")]
    TemporaryFailure,
}

/// IKE SA abstraction
///
/// The `IkeSa` data structure is an opaque handle to the IKEv2 state
/// machine.
#[derive(Clone)]
pub struct IkeSa {
    data: Arc<RwLock<StateData>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
    config: Config,
    sender: UnboundedSender<ControlMessage>,
}

impl IkeSa {
    /// Create a new IkeSa from the given configuration
    pub fn new(config: &Config) -> Result<(Self, UnboundedReceiver<ControlMessage>), CryptoError> {
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
        data.is_initiator()
    }

    /// Returns true if this `IkeSa` is in the given state
    pub async fn in_state<T: 'static>(&self, _expected: &T) -> bool {
        let state = self.state.lock().await;
        state
            .as_ref()
            .expect("state should be set")
            .as_ref()
            .as_any()
            .downcast_ref::<T>()
            .is_some()
    }

    /// Processes IKE message
    pub async fn handle_message(&self, message: impl AsRef<[u8]>) -> Result<(), StateError> {
        let mut state = self.state.lock().await;
        if let Some(old_state) = state.take() {
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
    ) -> Result<(), StateError> {
        let mut state = self.state.lock().await;
        if let Some(old_state) = state.take() {
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

            *state = Some(new_state);

            info!("state transitioned from {old_state_name} to {new_state_name}");
        }

        Ok(())
    }

    /// Processes XFRM acquire message
    pub async fn handle_expire(&self, spi: EspSpi, hard: bool) -> Result<(), StateError> {
        let mut state = self.state.lock().await;
        if let Some(old_state) = state.take() {
            let old_state_name = old_state.to_string();

            let new_state = old_state
                .handle_expire(
                    &self.config,
                    self.sender.clone(),
                    self.data.clone(),
                    &spi,
                    hard,
                )
                .await?;

            let new_state_name = new_state.to_string();

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
    prf: Option<Prf>,
    integ: Option<Integ>,
    group: Option<Group>,
}

impl ChosenProposal {
    /// Creates a new `ChosenProposal` from a proposal on the wire
    pub fn new(proposal: &Proposal) -> Result<Self, ProtocolError> {
        let transform = proposal
            .transforms()
            .find(|t| matches!(t.ty().assigned(), Some(TransformType::ENCR)))
            .ok_or(ProtocolError::MissingTransform(TransformType::ENCR))?;
        let id: EncrId = transform.id().try_into()?;
        let attribute = transform
            .attributes()
            .find(|a| matches!(a.ty().assigned(), Some(AttributeType::KeyLength)))
            .ok_or(ProtocolError::MissingAttribute(AttributeType::KeyLength))?;
        if attribute.value().len() != 2 {
            return Err(ProtocolError::InvalidAttribute(AttributeType::KeyLength));
        }
        let cipher = Cipher::new(
            id,
            Some(u16::from_be_bytes(
                attribute.value().try_into().expect("buffer too short"),
            )),
        )?;

        let prf = if let Some(Protocol::IKE) = proposal.protocol().assigned() {
            let transform = proposal
                .transforms()
                .find(|t| matches!(t.ty().assigned(), Some(TransformType::PRF)))
                .ok_or(ProtocolError::MissingTransform(TransformType::PRF))?;
            let id: PrfId = transform.id().try_into()?;
            Some(Prf::new(id)?)
        } else {
            None
        };

        let integ = if cipher.is_aead() {
            None
        } else {
            let transform = proposal
                .transforms()
                .find(|t| matches!(t.ty().assigned(), Some(TransformType::INTEG)))
                .ok_or(ProtocolError::MissingTransform(TransformType::INTEG))?;
            let id: IntegId = transform.id().try_into()?;
            Some(Integ::new(id)?)
        };

        let transform = proposal
            .transforms()
            .find(|t| matches!(t.ty().assigned(), Some(TransformType::DH)));
        let group = match transform {
            Some(transform) => {
                let id: DhId = transform.id().try_into()?;
                Some(Group::new(id)?)
            }
            None => match proposal.protocol().assigned() {
                Some(Protocol::IKE) => {
                    return Err(ProtocolError::MissingTransform(TransformType::DH));
                }
                _ => None,
            },
        };

        Ok(Self {
            protocol: proposal
                .protocol()
                .assigned()
                .ok_or(ProtocolError::UnknownProtocol(proposal.protocol()))?,
            spi: proposal.spi().to_vec(),
            cipher,
            prf,
            integ,
            group,
        })
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
    pub fn prf(&self) -> Option<&Prf> {
        self.prf.as_ref()
    }

    /// Returns the integrity checking algorithm
    pub fn integ(&self) -> Option<&Integ> {
        self.integ.as_ref()
    }

    /// Returns the key exchange group
    pub fn group(&self) -> Option<&Group> {
        self.group.as_ref()
    }

    /// Generates SKEYSEED
    pub(crate) fn generate_skeyseed(
        &self,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
        private_key: &GroupPrivateKey,
        peer_public_key: impl AsRef<[u8]>,
    ) -> Result<DerivationKey, CryptoError> {
        let g_ir = private_key.compute_key(peer_public_key)?;
        let mut buf = nonce_i.as_ref().to_vec();
        buf.extend_from_slice(nonce_r.as_ref());
        let prf = self.prf().expect("PRF must be set");
        Ok(DerivationKey::new(prf, prf.prf(&Key::new(buf), g_ir)?))
    }

    /// Generates key materials for IKE SA
    pub(crate) fn generate_keys(
        &self,
        skeyseed: &DerivationKey,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
        spi_i: &Spi,
        spi_r: &Spi,
    ) -> Result<Keys, CryptoError> {
        let mut buf = nonce_i.as_ref().to_vec();
        buf.extend_from_slice(nonce_r.as_ref());
        buf.extend_from_slice(&spi_i[..]);
        buf.extend_from_slice(&spi_r[..]);
        let integ_key_size = self
            .integ
            .as_ref()
            .map(|integ| integ.key_size())
            .unwrap_or(0);
        let prf = skeyseed.prf();
        let buf = prf.prfplus(
            skeyseed.key(),
            &buf,
            prf.size() * 3 + self.cipher.key_size() * 2 + integ_key_size * 2,
        )?;
        let mut buf = buf.as_slice();

        let mut d = vec![0; prf.size()];
        buf.try_copy_to_slice(&mut d).expect("buffer too short");
        let d = DerivationKey::new(prf, d);

        let (ai, ar) = if let Some(integ) = &self.integ {
            let mut ai = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ai).expect("buffer too short");

            let mut ar = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ar).expect("buffer too short");
            (
                Some(AuthenticationKey::new(integ, ai)),
                Some(AuthenticationKey::new(integ, ar)),
            )
        } else {
            (None, None)
        };

        let mut ei = vec![0; self.cipher.key_size()];
        buf.try_copy_to_slice(&mut ei).expect("buffer too short");
        let ei = EncryptionKey::new(&self.cipher, ei);

        let mut er = vec![0; self.cipher.key_size()];
        buf.try_copy_to_slice(&mut er).expect("buffer too short");
        let er = EncryptionKey::new(&self.cipher, er);

        let mut pi = vec![0; prf.size()];
        buf.try_copy_to_slice(&mut pi).expect("buffer too short");
        let pi = DerivationKey::new(prf, pi);

        let mut pr = vec![0; prf.size()];
        buf.try_copy_to_slice(&mut pr).expect("buffer too short");
        let pr = DerivationKey::new(prf, pr);

        Ok(Keys {
            derivation: DerivationKeys { d, pi, pr },
            protection: ProtectionKeys { ei, er, ai, ar },
        })
    }

    /// Generates key materials used by a Child SA
    fn generate_child_sa_keys(
        &self,
        d: &DerivationKey,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
        peer_public_key: Option<&[u8]>,
    ) -> Result<(ProtectionKeys, Option<Vec<u8>>), CryptoError> {
        let mut buf = Vec::new();

        let public_key = if let Some(peer_public_key) = peer_public_key {
            let private_key = self.group().expect("group must be set").generate_key()?;
            let g_ir = private_key.compute_key(peer_public_key)?;
            buf.extend_from_slice(g_ir.as_ref());
            Some(private_key.public_key()?)
        } else {
            None
        };

        buf.extend_from_slice(nonce_i.as_ref());
        buf.extend_from_slice(nonce_r.as_ref());
        let integ_key_size = self
            .integ()
            .as_ref()
            .map(|integ| integ.key_size())
            .unwrap_or(0);
        let encryption_key_size = self.cipher().key_size() + self.cipher().salt_size().unwrap_or(0);
        let buf = d
            .prf()
            .prfplus(d.key(), &buf, encryption_key_size * 2 + integ_key_size * 2)?;
        let mut buf = buf.as_slice();

        let (ai, ar) = if let Some(integ) = &self.integ() {
            let mut ai = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ai).expect("buffer too short");

            let mut ar = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ar).expect("buffer too short");
            (
                Some(AuthenticationKey::new(integ, ai)),
                Some(AuthenticationKey::new(integ, ar)),
            )
        } else {
            (None, None)
        };

        let mut ei = vec![0; encryption_key_size];
        buf.try_copy_to_slice(&mut ei).expect("buffer too short");
        let ei = EncryptionKey::new(&self.cipher, ei);

        let mut er = vec![0; encryption_key_size];
        buf.try_copy_to_slice(&mut er).expect("buffer too short");
        let er = EncryptionKey::new(&self.cipher, er);

        Ok((ProtectionKeys { ei, er, ai, ar }, public_key))
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
        if let Some(prf) = self.prf() {
            transforms.push(prf.into());
        }
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
    pub derivation: DerivationKeys,
    pub protection: ProtectionKeys,
}

/// Key materials used for key derivation
#[derive(Clone, Debug)]
pub struct DerivationKeys {
    pub d: DerivationKey,
    pub pi: DerivationKey,
    pub pr: DerivationKey,
}

/// Key materials used for encryption and authentication
#[derive(Clone, Debug)]
pub struct ProtectionKeys {
    pub ei: EncryptionKey,
    pub er: EncryptionKey,
    pub ai: Option<AuthenticationKey>,
    pub ar: Option<AuthenticationKey>,
}

#[derive(Clone, Debug)]
pub(crate) struct LarvalChildSa {
    pub ts_i: TrafficSelector,
    pub ts_r: TrafficSelector,
    pub spi: EspSpi,
    pub proposals: Vec<Proposal>,
    pub on_initiator: bool,
}

impl LarvalChildSa {
    pub fn new(
        config: &Config,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        on_initiator: bool,
    ) -> Result<Self, CryptoError> {
        let mut spi = EspSpi::default();
        crypto::rand_bytes(&mut spi)?;

        let proposals: Vec<_> = config.ipsec_proposals(&spi).collect();

        Ok(Self {
            ts_i: ts_i.to_owned(),
            ts_r: ts_r.to_owned(),
            spi,
            proposals,
            on_initiator,
        })
    }

    pub fn build(
        self,
        chosen_proposal: &ChosenProposal,
        d: &DerivationKey,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
    ) -> Result<ChildSa, CryptoError> {
        let (keys, _) =
            chosen_proposal.generate_child_sa_keys(d, nonce_i.as_ref(), nonce_r.as_ref(), None)?;
        Ok(ChildSa {
            ts_i: self.ts_i,
            ts_r: self.ts_r,
            spi: self.spi,
            chosen_proposal: chosen_proposal.to_owned(),
            keys,
            on_initiator: self.on_initiator,
        })
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
    keys: ProtectionKeys,
    on_initiator: bool,
}

impl ChildSa {
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

    /// Returns the initiator SPI
    pub fn spi_i(&self) -> &EspSpi {
        if self.on_initiator {
            &self.spi
        } else {
            let spi = self.chosen_proposal.spi.as_slice();
            spi.try_into().expect("SPI should be longer than 4 octets")
        }
    }

    /// Returns the responder SPI
    pub fn spi_r(&self) -> &EspSpi {
        if self.on_initiator {
            let spi = self.chosen_proposal.spi.as_slice();
            spi.try_into().expect("SPI should be longer than 4 octets")
        } else {
            &self.spi
        }
    }

    /// Returns the cryptographic proposal chosen
    pub fn chosen_proposal(&self) -> &ChosenProposal {
        &self.chosen_proposal
    }

    /// Returns the key materials
    pub fn keys(&self) -> &ProtectionKeys {
        &self.keys
    }

    /// Rekey this Child SA
    pub fn rekey(
        &mut self,
        key: &DerivationKey,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
        peer_public_key: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        let (keys, public_key) =
            self.chosen_proposal
                .generate_child_sa_keys(key, nonce_i, nonce_r, peer_public_key)?;
        self.keys = keys;
        Ok(public_key)
    }
}
