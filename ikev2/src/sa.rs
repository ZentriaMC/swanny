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
        EspSpi, Header, Spi,
        num::{
            AttributeType, DhId, EncrId, EsnId, ExchangeType, IntegId, Num, PayloadType, PrfId,
            Protocol, TransformType, TryFromTransformIdError,
        },
        payload::{self, Payload},
        proposal::Proposal,
        serialize::{self, DeserializeError},
        traffic_selector::TrafficSelector,
        transform::{Attribute, Transform},
    },
    state::{self, State, StateData, StateDataCache, StateError},
};
#[cfg(test)]
use crate::message::{Message, ProtectedMessage};
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
    InitialContact(payload::Id),
}

/// Errors at the protocol level
///
/// Error codes defined here will trigger sending a Notify payload
/// when it happens on the responder side.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("missing payload")]
    MissingPayload(PayloadType),

    #[error("missing transform")]
    MissingTransform(TransformType),

    #[error("missing SPI")]
    MissingSpi,

    #[error("invalid SPI length {0} (expected 4)")]
    InvalidSpiLength(usize),

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

    #[error("peer identity mismatch")]
    PeerIdentityMismatch,

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

/// Buffer for collecting IKE message fragments (RFC 7383)
#[derive(Debug)]
struct FragmentBuffer {
    message_id: u32,
    total_fragments: u16,
    inner: Num<u8, PayloadType>,
    fragments: std::collections::BTreeMap<u16, Vec<u8>>,
}

impl Default for FragmentBuffer {
    fn default() -> Self {
        Self {
            message_id: 0,
            total_fragments: 0,
            inner: 0u8.into(),
            fragments: std::collections::BTreeMap::new(),
        }
    }
}

impl FragmentBuffer {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// IKE SA abstraction
///
/// The `IkeSa` data structure is an opaque handle to the IKEv2 state
/// machine.
#[derive(Clone)]
pub struct IkeSa {
    spi: Spi,
    data: Arc<RwLock<StateData>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
    config: Config,
    sender: UnboundedSender<ControlMessage>,
    fragment_buffer: Arc<Mutex<FragmentBuffer>>,
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
                spi,
                data: Arc::new(RwLock::new(data)),
                state: Arc::new(Mutex::new(Some(Box::new(state::Initial {})))),
                config: config.to_owned(),
                sender,
                fragment_buffer: Arc::new(Mutex::new(FragmentBuffer::default())),
            },
            receiver,
        ))
    }

    /// Returns the local SPI for this IKE SA
    pub fn spi(&self) -> Spi {
        self.spi
    }

    /// Returns the initiator/responder status if it has been determined
    pub async fn is_initiator(&self) -> Option<bool> {
        let data = self.data.read().await;
        data.is_initiator()
    }

    /// Returns the pending request to be retransmitted in a certain period
    pub async fn pending_request(&self) -> Option<Vec<u8>> {
        let data = self.data.read().await;
        data.pending_request()
    }

    /// Returns all active Child SAs for this IKE SA
    pub async fn child_sas(&self) -> Vec<Box<ChildSa>> {
        let data = self.data.read().await;
        data.child_sas().to_vec()
    }

    /// Returns true if this `IkeSa` is in the given state
    #[cfg(test)]
    pub(crate) async fn in_state<T: 'static>(&self, _expected: &T) -> bool {
        let state = self.state.lock().await;
        state
            .as_ref()
            .expect("state should be set")
            .as_ref()
            .as_any()
            .downcast_ref::<T>()
            .is_some()
    }

    /// Unprotect a `ProtectedMessage` with the currently installed IKE SA keys
    #[cfg(test)]
    pub(crate) async fn unprotect_message(
        &self,
        message: ProtectedMessage,
    ) -> Result<Message, StateError> {
        let data = self.data.read().await;
        let data = StateDataCache::new_borrowed(&data);
        Ok(message
            .unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())
            .map_err(|e| StateError::Protocol(e.into()))?)
    }

    /// Protect a `Message` with the currently installed IKE SA keys
    #[cfg(test)]
    pub(crate) async fn protect_message(
        &self,
        message: Message,
    ) -> Result<ProtectedMessage, StateError> {
        let data = self.data.read().await;
        let data = StateDataCache::new_borrowed(&data);
        Ok(message.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?)
    }

    /// Checks if the message contains an SKF payload and attempts fragment reassembly.
    /// Returns `Some(reassembled_bytes)` when all fragments are collected, `None` if
    /// still waiting for more fragments, or passes through non-fragmented messages.
    async fn try_reassemble_fragments(
        &self,
        message: &[u8],
    ) -> Result<Option<Vec<u8>>, StateError> {
        use bytes::{Buf, BytesMut};

        // Parse just the header to check the first payload type (peek, don't consume).
        // If the header can't be parsed, pass the message through so the state handler
        // can generate the appropriate error notification.
        let mut buf: &[u8] = message;
        let (header, first_payload_type) = match Header::deserialize(&mut buf) {
            Ok(result) => result,
            Err(_) => return Ok(Some(message.to_vec())),
        };

        if first_payload_type.assigned() != Some(PayloadType::SKF) {
            return Ok(Some(message.to_vec()));
        }

        // Skip message length (4 bytes)
        if buf.remaining() < 4 {
            return Err(ProtocolError::DeserializeError(DeserializeError::PrematureEof).into());
        }
        buf.advance(4);

        // Parse generic payload header: next_payload(1), critical(1), length(2)
        if buf.remaining() < 4 {
            return Err(ProtocolError::DeserializeError(DeserializeError::PrematureEof).into());
        }
        let inner_payload_type: u8 = buf.get_u8();
        let _critical = buf.get_u8();
        let _payload_len = buf.get_u16();

        // Parse fragment header: fragment_number(2), total_fragments(2)
        if buf.remaining() < 4 {
            return Err(ProtocolError::DeserializeError(DeserializeError::PrematureEof).into());
        }
        let fragment_number = buf.get_u16();
        let total_fragments = buf.get_u16();

        // The rest is encrypted content (IV + ciphertext + padding + ICV inside the payload,
        // plus the message-level ICV appended after the serialized message)
        let encrypted_content = buf.to_vec();

        let mut frag_buf = self.fragment_buffer.lock().await;

        // If this is a new message ID or mismatched total, reset the buffer
        if frag_buf.fragments.is_empty()
            || frag_buf.message_id != header.id()
            || frag_buf.total_fragments != total_fragments
        {
            frag_buf.reset();
            frag_buf.message_id = header.id();
            frag_buf.total_fragments = total_fragments;
        }

        // Store the inner payload type from fragment 1
        if fragment_number == 1 {
            frag_buf.inner = inner_payload_type.into();
        }

        frag_buf.fragments.insert(fragment_number, encrypted_content);

        info!(
            fragment_number,
            total_fragments,
            collected = frag_buf.fragments.len(),
            "received IKE fragment"
        );

        if frag_buf.fragments.len() as u16 != total_fragments {
            return Ok(None); // Still waiting for more fragments
        }

        // All fragments collected — reassemble
        let inner = frag_buf.inner;
        let fragments: Vec<_> = (1..=total_fragments)
            .map(|i| frag_buf.fragments.remove(&i).expect("fragment should exist"))
            .collect();
        frag_buf.reset();
        drop(frag_buf);

        // Decrypt each fragment and concatenate plaintext
        let data = self.data.read().await;
        let data = StateDataCache::new_borrowed(&data);
        let decrypt_key = data.decrypting_key()?;
        let integ = data.chosen_proposal()?.integ();

        let mut plaintext = Vec::new();
        for fragment_data in &fragments {
            let skf = payload::Skf::new(0, 0, &fragment_data[..], inner, None);
            let chunk = skf.decrypt_raw(decrypt_key, integ)
                .map_err(|err| StateError::Protocol(err.into()))?;
            plaintext.extend_from_slice(&chunk);
        }

        // Re-encrypt the concatenated plaintext as a single SK payload using the
        // peer's encrypting key (= our decrypting key). The state handler will
        // decrypt with the same key, recovering the original plaintext.
        let sk = payload::Sk::encrypt_raw(decrypt_key, &plaintext, inner, integ)?;

        let reassembled = crate::message::ProtectedMessage::from_parts(
            header,
            vec![Payload::new(
                PayloadType::SK.into(),
                payload::Content::Sk(sk),
                true,
            )],
        );

        // Serialize the reassembled message
        let len = serialize::Serialize::size(&reassembled)?;
        let mut buf = BytesMut::with_capacity(len);
        serialize::Serialize::serialize(&reassembled, &mut buf)?;

        // Sign with the peer's auth key so verify_message() in the state handler succeeds
        if let Some(checksum) = data.message_sign_as_peer(&buf)? {
            buf.extend_from_slice(&checksum);
        }

        drop(data);

        info!(
            total_fragments = fragments.len(),
            "reassembled IKE fragments into complete message"
        );
        Ok(Some(buf.to_vec()))
    }

    /// Processes IKE message
    pub async fn handle_message(&self, message: impl AsRef<[u8]>) -> Result<(), StateError> {
        let message = match self.try_reassemble_fragments(message.as_ref()).await? {
            Some(msg) => msg,
            None => return Ok(()), // Fragment buffered, waiting for more
        };

        let mut state = self.state.lock().await;
        if let Some(old_state) = state.take() {
            let old_state_name = old_state.to_string();

            let new_state = old_state
                .handle_message(
                    &self.config,
                    self.sender.clone(),
                    self.data.clone(),
                    &message,
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

    /// Initiates IKE SA rekeying
    pub async fn handle_rekey_ike_sa(&self) -> Result<(), StateError> {
        let mut state = self.state.lock().await;
        if let Some(old_state) = state.take() {
            let old_state_name = old_state.to_string();

            let new_state = old_state
                .handle_rekey_ike_sa(
                    &self.config,
                    self.sender.clone(),
                    self.data.clone(),
                )
                .await?;

            let new_state_name = new_state.to_string();

            *state = Some(new_state);

            info!("state transitioned from {old_state_name} to {new_state_name}");
        }

        Ok(())
    }

    /// Sends a Dead Peer Detection probe
    pub async fn handle_dpd(&self) -> Result<(), StateError> {
        let mut state = self.state.lock().await;
        if let Some(old_state) = state.take() {
            let old_state_name = old_state.to_string();

            let new_state = old_state
                .handle_dpd(
                    &self.config,
                    self.sender.clone(),
                    self.data.clone(),
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
    esn: Option<EsnId>,
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

        let esn = proposal
            .transforms()
            .find(|t| matches!(t.ty().assigned(), Some(TransformType::ESN)))
            .map(|t| t.id().try_into())
            .transpose()?;

        let protocol = proposal
            .protocol()
            .assigned()
            .ok_or(ProtocolError::UnknownProtocol(proposal.protocol()))?;

        let spi = proposal.spi();
        if matches!(protocol, Protocol::ESP | Protocol::AH) && spi.len() != 4 {
            return Err(ProtocolError::InvalidSpiLength(spi.len()));
        }

        Ok(Self {
            protocol,
            spi: spi.to_vec(),
            cipher,
            prf,
            integ,
            group,
            esn,
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

    /// Returns the ESN option
    pub fn esn(&self) -> Option<EsnId> {
        self.esn
    }

    /// Generates SKEYSEED for IKE SA rekeying
    ///
    /// Uses `prf(SK_d_old, g^ir_new | Ni | Nr)` per RFC 7296 section 2.18
    pub(crate) fn generate_rekey_skeyseed(
        &self,
        old_sk_d: &DerivationKey,
        nonce_i: impl AsRef<[u8]>,
        nonce_r: impl AsRef<[u8]>,
        private_key: &GroupPrivateKey,
        peer_public_key: impl AsRef<[u8]>,
    ) -> Result<DerivationKey, CryptoError> {
        let g_ir = private_key.compute_key(peer_public_key)?;
        let mut buf = g_ir.as_ref().to_vec();
        buf.extend_from_slice(nonce_i.as_ref());
        buf.extend_from_slice(nonce_r.as_ref());
        let prf = self.prf().expect("PRF must be set");
        Ok(DerivationKey::new(
            prf,
            old_sk_d.prf().prf(old_sk_d.key(), buf)?,
        ))
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

        // RFC 7296 §2.17: KEYMAT = SK_ei | SK_ai | SK_er | SK_ar
        // Encryption keys before integrity keys within each direction,
        // initiator direction before responder direction.
        let mut ei = vec![0; encryption_key_size];
        buf.try_copy_to_slice(&mut ei).expect("buffer too short");
        let ei = EncryptionKey::new(&self.cipher, ei);

        let ai = if let Some(integ) = &self.integ() {
            let mut ai = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ai).expect("buffer too short");
            Some(AuthenticationKey::new(integ, ai))
        } else {
            None
        };

        let mut er = vec![0; encryption_key_size];
        buf.try_copy_to_slice(&mut er).expect("buffer too short");
        let er = EncryptionKey::new(&self.cipher, er);

        let ar = if let Some(integ) = &self.integ() {
            let mut ar = vec![0; integ_key_size];
            buf.try_copy_to_slice(&mut ar).expect("buffer too short");
            Some(AuthenticationKey::new(integ, ar))
        } else {
            None
        };

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
        if let Some(esn) = self.esn {
            transforms.push(Transform::new(
                TransformType::ESN.into(),
                esn.into(),
                None::<Attribute>,
            ));
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

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum ChildSaMode {
    #[default]
    Transport,
    Tunnel,
}

#[derive(Clone, Debug)]
pub(crate) struct LarvalChildSa {
    pub ts_i: TrafficSelector,
    pub ts_r: TrafficSelector,
    pub spi: EspSpi,
    pub mode: ChildSaMode,
    pub proposals: Vec<Proposal>,
    pub on_initiator: bool,
}

impl LarvalChildSa {
    pub fn new(
        config: &Config,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        mode: ChildSaMode,
        on_initiator: bool,
    ) -> Result<Self, CryptoError> {
        let mut spi = EspSpi::default();
        crypto::rand_bytes(&mut spi)?;

        let proposals: Vec<_> = config.ipsec_proposals(&spi).collect();

        Ok(Self {
            ts_i: ts_i.to_owned(),
            ts_r: ts_r.to_owned(),
            spi,
            mode,
            proposals,
            on_initiator,
        })
    }

    pub fn from_existing(child_sa: &ChildSa, on_initiator: bool) -> Result<Self, CryptoError> {
        let mut spi = EspSpi::default();
        crypto::rand_bytes(&mut spi)?;

        let proposal = child_sa.chosen_proposal().proposal(
            1,
            child_sa.chosen_proposal().protocol().into(),
            spi,
        );
        let proposals = vec![proposal];

        Ok(Self {
            ts_i: child_sa.ts_i().to_owned(),
            ts_r: child_sa.ts_r().to_owned(),
            spi,
            mode: child_sa.mode(),
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
        peer_public_key: Option<&[u8]>,
    ) -> Result<ChildSa, CryptoError> {
        let (keys, public_key) = chosen_proposal.generate_child_sa_keys(
            d,
            nonce_i.as_ref(),
            nonce_r.as_ref(),
            peer_public_key,
        )?;
        Ok(ChildSa {
            ts_i: self.ts_i,
            ts_r: self.ts_r,
            spi: self.spi,
            mode: self.mode,
            chosen_proposal: chosen_proposal.to_owned(),
            keys,
            public_key,
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
    mode: ChildSaMode,
    chosen_proposal: ChosenProposal,
    keys: ProtectionKeys,
    public_key: Option<Vec<u8>>,
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
            self.chosen_proposal.spi.as_slice().try_into().expect(
                "SPI length validated in ChosenProposal::new",
            )
        }
    }

    /// Returns the responder SPI
    pub fn spi_r(&self) -> &EspSpi {
        if self.on_initiator {
            self.chosen_proposal.spi.as_slice().try_into().expect(
                "SPI length validated in ChosenProposal::new",
            )
        } else {
            &self.spi
        }
    }

    /// Returns the Child SA mode
    pub fn mode(&self) -> ChildSaMode {
        self.mode
    }

    /// Returns the cryptographic proposal chosen
    pub fn chosen_proposal(&self) -> &ChosenProposal {
        &self.chosen_proposal
    }

    /// Returns the key materials
    pub fn keys(&self) -> &ProtectionKeys {
        &self.keys
    }

    /// Returns the group public key used to derive keys
    pub fn public_key(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }
}
