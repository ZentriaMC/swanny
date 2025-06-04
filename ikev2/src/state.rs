use crate::{
    config::{Config, ConfigError},
    crypto::{CryptoError, EncryptionKey, GroupPrivateKey, Nonce},
    message::{
        EspSpi, Message, ProtectedMessage, Spi,
        num::{ExchangeType, MessageFlags},
        payload::Id,
        serialize::{DeserializeError, Serialize, SerializeError},
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ChosenProposal, ControlMessage, Keys, LarvalChildSa, ProtocolError},
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

    #[error("deserialization error")]
    DeserializeError(#[from] DeserializeError),

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
        index: u32,
    ) -> Result<Box<dyn State>, StateError>;

    async fn handle_expire(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        spi: &EspSpi,
        hard: bool,
    ) -> Result<Box<dyn State>, StateError>;

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
            fn new_borrowed(data: &'a $Struct) -> Self {
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
        received_message_id: u32,
        chosen_proposal: Option<ChosenProposal>,
        public_key: Option<Vec<u8>>,
        private_key: Option<GroupPrivateKey>,
        keys: Option<Keys>,
        nonce_i: Option<Nonce>,
        nonce_r: Option<Nonce>,
        ike_sa_init_request: Option<Vec<u8>>,
        ike_sa_init_response: Option<Vec<u8>>,
        last_request: Option<Vec<u8>>,
        larval_child_sa: Option<LarvalChildSa>,
        created_child_sa: Option<Box<ChildSa>>,
        rekeyed_child_sa: Option<Box<ChildSa>>,
        child_sas: Vec<Box<ChildSa>>,
        deleted_child_sas: Vec<Box<ChildSa>>,
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

    fn encrypting_key(&self) -> Result<&EncryptionKey, StateError> {
        match *self.is_initiator {
            Some(true) => Ok(&self.keys()?.protection.ei),
            Some(false) => Ok(&self.keys()?.protection.er),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    fn decrypting_key(&self) -> Result<&EncryptionKey, StateError> {
        match *self.is_initiator {
            Some(true) => Ok(&self.keys()?.protection.er),
            Some(false) => Ok(&self.keys()?.protection.ei),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    fn chosen_proposal(&self) -> Result<&ChosenProposal, StateError> {
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
            return Err(DeserializeError::PrematureEof.into());
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

trait SendProtectedMessage {
    fn send_message(
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        message: ProtectedMessage,
    ) -> Result<(), StateError> {
        let len = message.size()?;
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

trait RekeyChildSa {
    fn rekey_child_sa(
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        child_sa: Box<ChildSa>,
    ) -> Result<(), StateError> {
        debug!(child_sa = ?&child_sa, "Child SA rekeyed");
        data.child_sas.to_mut().push(child_sa.clone());
        sender.unbounded_send(ControlMessage::RekeyChildSa(child_sa))?;
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
