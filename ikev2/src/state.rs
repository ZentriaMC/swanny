use crate::{
    config::{Config, ConfigError},
    crypto::{CryptoError, EncryptionKey, GroupPrivateKey, Nonce},
    message::{
        EspSpi, Message, ProtectedMessage, Spi,
        num::{ExchangeType, MessageFlags, NotifyType, PayloadType, Protocol},
        payload::{self, Id, Payload},
        serialize::{DeserializeError, Serialize, SerializeError},
        traffic_selector::TrafficSelector,
    },
    sa::{
        ChildSa, ChildSaMode, ChosenProposal, ControlMessage, Keys, LarvalChildSa, ProtocolError,
    },
};
use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc::{TrySendError, UnboundedSender};
use std::{
    borrow::{Borrow, Cow},
    ops::DerefMut,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::debug;

mod initial;
pub(crate) use initial::Initial;

mod ike_sa_init_request_sent;
pub(crate) use ike_sa_init_request_sent::IkeSaInitRequestSent;

mod ike_sa_init_response_sent;
pub(crate) use ike_sa_init_response_sent::IkeSaInitResponseSent;

mod ike_auth_request_sent;
pub(crate) use ike_auth_request_sent::IkeAuthRequestSent;

mod established;
pub(crate) use established::Established;

mod delete_child_sa_request_sent;
pub(crate) use delete_child_sa_request_sent::DeleteChildSaRequestSent;

mod new_child_sa_request_sent;
pub(crate) use new_child_sa_request_sent::NewChildSaRequestSent;

mod rekey_child_sa_request_sent;
pub(crate) use rekey_child_sa_request_sent::RekeyChildSaRequestSent;

mod rekey_ike_sa_request_sent;
pub(crate) use rekey_ike_sa_request_sent::RekeyIkeSaRequestSent;

mod dpd_request_sent;
pub(crate) use dpd_request_sent::DpdRequestSent;

#[derive(Debug, thiserror::Error)]
pub enum InvalidStateError {
    #[error("no proposal chosen")]
    NoProposalChosen,

    #[error("no keys set")]
    NoKeysSet,

    #[error("peer SPI not set")]
    PeerSpiNotSet,

    #[error("IKE_SA_INIT not recorded")]
    IkeSaInitNotRecorded,

    #[error("nonce not recorded")]
    NonceNotRecorded,

    #[error("initiator/responder not determined")]
    InitiatorNotDetermined,

    #[error("unknown Child SA")]
    UnknownChildSa(EspSpi),

    #[error("larval Child SA not set")]
    LarvalChildSaNotSet,

    #[error("Child SA not set")]
    ChildSaNotSet,

    #[error("group private key not set")]
    GroupPrivateKeyNotSet,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("invalid state")]
    InvalidState(#[from] InvalidStateError),

    #[error("configuration error")]
    Config(#[from] ConfigError),

    #[error("error at the protocol level")]
    Protocol(#[from] ProtocolError),

    #[error("cryptographic error")]
    Crypto(#[from] CryptoError),

    #[error("serialization error")]
    SerializeError(#[from] SerializeError),

    #[error("try send error")]
    TrySend(#[from] TrySendError<ControlMessage>),
}

#[async_trait]
pub(crate) trait State: Send + Sync + std::fmt::Display {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        message: &[u8],
    ) -> Result<Box<dyn State>, StateError>;

    async fn handle_acquire(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
    ) -> Result<Box<dyn State>, StateError>;

    async fn handle_expire(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        spi: &EspSpi,
        hard: bool,
    ) -> Result<Box<dyn State>, StateError>;

    async fn handle_rekey_ike_sa(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
    ) -> Result<Box<dyn State>, StateError>;

    async fn handle_dpd(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
    ) -> Result<Box<dyn State>, StateError>;

    #[cfg(test)]
    fn as_any(&self) -> &(dyn std::any::Any + Send);
}

macro_rules! cache_cow {
    (
        $(#[$outer:meta])*
            $vis:vis struct $Struct:ident: $StructCache:ident {
                $(
                    $field:ident: $ty:ty,
                )*
            }
    ) => {
        $(#[$outer])*
            $vis struct $Struct {
                $(
                    $field: $ty,
                )*
            }

        // A data structure to cache $Struct allowing temporary writes
        // while it is borrowed as an immutable reference.
        $(#[$outer])*
            $vis struct $StructCache<'a> {
                $(
                    $field: Cow<'a, $ty>,
                )*
            }

        impl<'a, 'b: 'c, 'c> $StructCache<'a> {
            // Creates a new $StructCache borrowing from a given
            // $Struct reference
            pub(crate) fn new_borrowed(data: &'a $Struct) -> Self {
                Self {
                    $(
                        $field: Cow::Borrowed(&data.$field),
                    )*
                }
            }

            // Swaps the currently borrowed reference and another
            fn swap(&self, other: &'b $StructCache<'b>) -> $StructCache<'c> {
                $StructCache {
                    $(
                        $field: match &self.$field {
                            Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                            _ => Cow::Borrowed(other.$field.borrow()),
                        },
                    )*
                }
            }

            // Writes changed values in this $StructCache into $Struct
            fn write_into<D>(self, dest: &mut D)
            where
                D: DerefMut<Target = $Struct>,
            {
                $(
                    if let Cow::Owned(owned) = self.$field {
                        debug!("updating {}", stringify!($field));
                        dest.$field = owned;
                    }
                )*
            }

            // Converts all values in this $StructCache as owned
            fn into_owned(self) -> Self {
                Self {
                    $(
                        $field: Cow::Owned(self.$field.into_owned()),
                    )*
                }
            }
        }
    }
}

cache_cow! {
    #[derive(Default)]
    pub(crate) struct StateData: StateDataCache {
        is_initiator: Option<bool>,
        spi: Spi,
        peer_spi: Option<Spi>,
        message_id: u32,
        received_message_id: Option<u32>,
        chosen_proposal: Option<ChosenProposal>,
        public_key: Option<Vec<u8>>,
        private_key: Option<GroupPrivateKey>,
        keys: Option<Keys>,
        nonce_i: Option<Nonce>,
        nonce_r: Option<Nonce>,
        ike_sa_init_request: Option<Vec<u8>>,
        ike_sa_init_response: Option<Vec<u8>>,
        last_request: Option<Vec<u8>>,
        child_sas: Vec<Box<ChildSa>>,
        creating_child_sa: Option<LarvalChildSa>,
        rekeying_child_sa: Option<Box<ChildSa>>,
        created_child_sa: Option<Box<ChildSa>>,
        rekeyed_child_sa: Option<Box<ChildSa>>,
        deleted_child_sas: Vec<Box<ChildSa>>,
        rekeying_ike_spi: Option<Spi>,
        fragmentation_supported: bool,
    }
}

impl StateDataCache<'_> {
    fn initiator_spi(&self) -> Result<&Spi, StateError> {
        match *self.is_initiator {
            Some(true) => Ok(&*self.spi),
            Some(false) => (*self.peer_spi)
                .as_ref()
                .ok_or(StateError::InvalidState(InvalidStateError::PeerSpiNotSet)),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    fn responder_spi(&self) -> Result<&Spi, StateError> {
        match *self.is_initiator {
            Some(false) => Ok(&*self.spi),
            Some(true) => (*self.peer_spi)
                .as_ref()
                .ok_or(StateError::InvalidState(InvalidStateError::PeerSpiNotSet)),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    pub(crate) fn encrypting_key(&self) -> Result<&EncryptionKey, StateError> {
        match *self.is_initiator {
            Some(true) => Ok(&self.keys()?.protection.ei),
            Some(false) => Ok(&self.keys()?.protection.er),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    pub(crate) fn decrypting_key(&self) -> Result<&EncryptionKey, StateError> {
        match *self.is_initiator {
            Some(true) => Ok(&self.keys()?.protection.er),
            Some(false) => Ok(&self.keys()?.protection.ei),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    pub(crate) fn chosen_proposal(&self) -> Result<&ChosenProposal, StateError> {
        (*self.chosen_proposal)
            .as_ref()
            .ok_or(StateError::InvalidState(
                InvalidStateError::NoProposalChosen,
            ))
    }

    fn keys(&self) -> Result<&Keys, StateError> {
        (*self.keys)
            .as_ref()
            .ok_or(StateError::InvalidState(InvalidStateError::NoKeysSet))
    }

    fn initiator_signed_data(&self, id: &Id) -> Result<Vec<u8>, StateError> {
        let len = id.size()?;
        let mut buf = BytesMut::with_capacity(len);
        id.serialize(&mut buf)?;

        let ike_sa_init_request =
            (*self.ike_sa_init_request)
                .as_ref()
                .ok_or(StateError::InvalidState(
                    InvalidStateError::IkeSaInitNotRecorded,
                ))?;
        let nonce_r = (*self.nonce_r).as_ref().ok_or(StateError::InvalidState(
            InvalidStateError::NonceNotRecorded,
        ))?;

        let pi = &self.keys()?.derivation.pi;
        let mut mac = pi.prf().prf(pi.key(), &buf[..])?;

        let mut signed_data = Vec::new();
        signed_data.append(&mut ike_sa_init_request.to_vec());
        signed_data.append(&mut nonce_r.as_ref().to_vec());
        signed_data.append(&mut mac);
        Ok(signed_data)
    }

    fn responder_signed_data(&self, id: &Id) -> Result<Vec<u8>, StateError> {
        let len = id.size()?;
        let mut buf = BytesMut::with_capacity(len);
        id.serialize(&mut buf)?;

        let ike_sa_init_response =
            (*self.ike_sa_init_response)
                .as_ref()
                .ok_or(StateError::InvalidState(
                    InvalidStateError::IkeSaInitNotRecorded,
                ))?;
        let nonce_i = (*self.nonce_i).as_ref().ok_or(StateError::InvalidState(
            InvalidStateError::NonceNotRecorded,
        ))?;

        let pr = &self.keys()?.derivation.pr;
        let mut mac = pr.prf().prf(pr.key(), &buf[..])?;

        let mut signed_data = Vec::new();
        signed_data.append(&mut ike_sa_init_response.to_vec());
        signed_data.append(&mut nonce_i.as_ref().to_vec());
        signed_data.append(&mut mac);
        Ok(signed_data)
    }

    fn auth_data_for_signing(&self, id: &Id) -> Result<Vec<u8>, StateError> {
        match *self.is_initiator {
            Some(true) => self.initiator_signed_data(id),
            Some(false) => self.responder_signed_data(id),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    fn auth_data_for_verification(&self, id: &Id) -> Result<Vec<u8>, StateError> {
        match *self.is_initiator {
            Some(true) => self.responder_signed_data(id),
            Some(false) => self.initiator_signed_data(id),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    fn message_sign(&self, message: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, StateError> {
        if self.chosen_proposal()?.integ().is_none() {
            return Ok(None);
        }

        let key = match *self.is_initiator {
            Some(true) => self
                .keys()?
                .protection
                .ai
                .as_ref()
                .ok_or(StateError::InvalidState(InvalidStateError::NoKeysSet))?,
            Some(false) => self
                .keys()?
                .protection
                .ar
                .as_ref()
                .ok_or(StateError::InvalidState(InvalidStateError::NoKeysSet))?,
            None => {
                return Err(StateError::InvalidState(
                    InvalidStateError::InitiatorNotDetermined,
                ));
            }
        };

        debug!(key = ?&key, message = ?message.as_ref(), "signing message");

        Ok(Some(key.integ().sign(key.key(), message.as_ref())?))
    }

    /// Signs a message as if it were from the peer (for fragment reassembly)
    pub(crate) fn message_sign_as_peer(&self, message: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, StateError> {
        if self.chosen_proposal()?.integ().is_none() {
            return Ok(None);
        }

        let key = match *self.is_initiator {
            Some(true) => self
                .keys()?
                .protection
                .ar
                .as_ref()
                .ok_or(StateError::InvalidState(InvalidStateError::NoKeysSet))?,
            Some(false) => self
                .keys()?
                .protection
                .ai
                .as_ref()
                .ok_or(StateError::InvalidState(InvalidStateError::NoKeysSet))?,
            None => {
                return Err(StateError::InvalidState(
                    InvalidStateError::InitiatorNotDetermined,
                ));
            }
        };

        Ok(Some(key.integ().sign(key.key(), message.as_ref())?))
    }

    fn message_verify(&self, message: impl AsRef<[u8]>) -> Result<bool, StateError> {
        if self.chosen_proposal()?.integ().is_none() {
            return Ok(true);
        }

        let key = match *self.is_initiator {
            Some(true) => self
                .keys()?
                .protection
                .ar
                .as_ref()
                .ok_or(StateError::InvalidState(InvalidStateError::NoKeysSet))?,
            Some(false) => self
                .keys()?
                .protection
                .ai
                .as_ref()
                .ok_or(StateError::InvalidState(InvalidStateError::NoKeysSet))?,
            None => {
                return Err(StateError::InvalidState(
                    InvalidStateError::InitiatorNotDetermined,
                ));
            }
        };

        if message.as_ref().len() < key.integ().output_size() {
            return Err(ProtocolError::DeserializeError(DeserializeError::PrematureEof).into());
        }

        let (message, checksum) = message
            .as_ref()
            .split_at(message.as_ref().len() - key.integ().output_size());
        Ok(key.integ().verify(key.key(), message, checksum)?)
    }
}

impl StateData {
    pub fn new(spi: &Spi) -> Self {
        Self {
            spi: spi.to_owned(),
            ..Default::default()
        }
    }

    pub fn is_initiator(&self) -> Option<bool> {
        self.is_initiator
    }

    pub fn pending_request(&self) -> Option<Vec<u8>> {
        self.last_request.clone()
    }
}

trait SendMessage {
    fn send_message(
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        message: Message,
    ) -> Result<(), StateError> {
        let len = message.size()?;
        let mut buf = BytesMut::with_capacity(len);
        message.serialize(&mut buf)?;

        if let Some(ExchangeType::IKE_SA_INIT) = message.exchange().assigned() {
            if message.flags().contains(MessageFlags::I) {
                *data.ike_sa_init_request.to_mut() = Some(buf.to_vec());
            } else if message.flags().contains(MessageFlags::R) {
                *data.ike_sa_init_response.to_mut() = Some(buf.to_vec());
            } else {
                debug!("message flags are not set");
            }
        }

        if message.flags().contains(MessageFlags::I) {
            *data.last_request.to_mut() = Some(buf.to_vec());
            *data.message_id.to_mut() = message.id().wrapping_add(1);
        }

        Ok(sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?)
    }
}

/// Maximum IKE message size before fragmentation kicks in.
/// Based on a conservative 1280-byte IPv6 minimum MTU minus IP (40) and UDP (8) headers.
const FRAGMENT_MAX_MESSAGE_SIZE: usize = 1232;

trait SendProtectedMessage {
    fn send_message(
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        message: ProtectedMessage,
    ) -> Result<(), StateError> {
        let len = message.size()?;
        let integ_size = data
            .chosen_proposal()
            .ok()
            .and_then(|p| p.integ())
            .map(|i| i.output_size())
            .unwrap_or(0);

        // If fragmentation is negotiated and the message (with ICV) exceeds
        // the threshold, decrypt the SK payload back to plaintext and
        // re-encrypt as SKF fragments. This avoids changing every caller.
        if *data.fragmentation_supported && len + integ_size > FRAGMENT_MAX_MESSAGE_SIZE {
            return Self::send_fragmented(sender, data, message);
        }

        let mut buf = BytesMut::with_capacity(len);
        message.serialize(&mut buf)?;

        if let Some(checksum) = data.message_sign(&buf)? {
            debug!(checksum = ?&checksum, "signature");
            buf.extend_from_slice(&checksum);
        }

        if message.flags().contains(MessageFlags::I) {
            *data.last_request.to_mut() = Some(buf.to_vec());
            *data.message_id.to_mut() = message.id().wrapping_add(1);
        }

        Ok(sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?)
    }

    /// Sends a message as SKF fragments (RFC 7383).
    fn send_fragmented(
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        message: ProtectedMessage,
    ) -> Result<(), StateError> {
        // Decrypt the SK payload to recover the inner plaintext
        let inner_message = message
            .unprotect(data.encrypting_key()?, data.chosen_proposal()?.integ())
            .map_err(|err| StateError::Protocol(err.into()))?;

        let key = data.encrypting_key()?;
        let integ = data.chosen_proposal()?.integ();
        let fragments =
            inner_message.protect_fragmented(key, integ, FRAGMENT_MAX_MESSAGE_SIZE)?;

        debug!(
            total_fragments = fragments.len(),
            "sending fragmented IKE message"
        );

        let is_request = message.flags().contains(MessageFlags::I);

        // For retransmission of fragmented requests, store all fragment
        // datagrams concatenated so the retransmit path can split them.
        let mut all_fragments = Vec::new();

        for fragment in fragments {
            let frag_len = fragment.size()?;
            let mut buf = BytesMut::with_capacity(frag_len);
            fragment.serialize(&mut buf)?;

            if let Some(checksum) = data.message_sign(&buf)? {
                buf.extend_from_slice(&checksum);
            }

            all_fragments.push(buf.to_vec());
            sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?;
        }

        if is_request {
            // Store the first fragment as the retransmit payload. The server
            // will re-send all fragments when it retransmits.
            *data.last_request.to_mut() = all_fragments.into_iter().next();
            *data.message_id.to_mut() = message.id().wrapping_add(1);
        }

        Ok(())
    }
}

trait CreateChildSa {
    fn create_child_sa(
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        child_sa: Box<ChildSa>,
    ) -> Result<(), StateError> {
        debug!(child_sa = ?&child_sa, "Child SA created");
        data.child_sas.to_mut().push(child_sa.clone());
        sender.unbounded_send(ControlMessage::CreateChildSa(child_sa))?;
        Ok(())
    }
}

trait DeleteChildSa {
    fn delete_child_sa(
        sender: UnboundedSender<ControlMessage>,
        child_sa: Box<ChildSa>,
    ) -> Result<(), StateError> {
        debug!(child_sa = ?&child_sa, "Child SA deleted");
        sender.unbounded_send(ControlMessage::DeleteChildSa(child_sa))?;
        Ok(())
    }
}

trait VerifyMessage {
    fn verify_message(data: &StateDataCache<'_>, message: &[u8]) -> Result<(), StateError> {
        if data.message_verify(message)? {
            debug!("checksum verified");
            Ok(())
        } else {
            Err(ProtocolError::IntegrityCheckFailed.into())
        }
    }
}

fn generate_informational_error(
    data: &StateDataCache<'_>,
    error: ProtocolError,
    message_id: u32,
) -> Result<ProtectedMessage, StateError> {
    let spi = Spi::default();
    let mut response = Message::new(
        data.peer_spi.as_ref().as_ref().unwrap_or(&spi),
        &data.spi,
        ExchangeType::INFORMATIONAL.into(),
        MessageFlags::R,
        message_id,
    );

    let notification = match error {
        ProtocolError::TemporaryFailure => NotifyType::TEMPORARY_FAILURE,
        _ => NotifyType::INVALID_SYNTAX,
    };

    response.add_payloads([Payload::new(
        PayloadType::NOTIFY.into(),
        payload::Content::Notify(payload::Notify::new(
            Protocol::IKE.into(),
            Some(&spi[..]),
            notification.into(),
            b"",
        )),
        true,
    )]);

    debug!(response = ?&response, "sending protected response");

    response
        .protect(data.encrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(Into::into)
}
