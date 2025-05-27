use crate::{
    config::{Config, ConfigError},
    crypto::{CryptoError, GroupPrivateKey},
    message::{
        Spi,
        payload::{self, Id},
        serialize::{DeserializeError, Serialize, SerializeError},
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, Keys, LarvalChildSa, ProtocolError},
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

#[derive(Debug, thiserror::Error)]
pub enum InvalidStateError {
    #[error("no proposal chosen")]
    NoProposalChosen,

    #[error("no keys set")]
    NoKeysSet,

    #[error("IKE_SA_INIT not recorded")]
    IkeSaInitNotRecorded,

    #[error("nonce not recorded")]
    NonceNotRecorded,

    #[error("initiator/responder not determined")]
    InitiatorNotDetermined,
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
}

#[derive(Default)]
pub(crate) struct StateData {
    is_initiator: Option<bool>,
    spi: Spi,
    peer_spi: Option<Spi>,
    message_id: u32,
    chosen_proposal: Option<ChosenProposal>,
    public_key: Option<Vec<u8>>,
    private_key: Option<GroupPrivateKey>,
    keys: Option<Keys>,
    nonce_i: Option<Vec<u8>>,
    nonce_r: Option<Vec<u8>>,
    ike_sa_init_request: Option<Vec<u8>>,
    ike_sa_init_response: Option<Vec<u8>>,
    larval_child_sa: Option<LarvalChildSa>,
}

/// A data structure to cache `StateData` allowing temporary writes
/// while it is borrowed as an immutable reference from `RwLock`.
#[derive(Default)]
pub(crate) struct StateDataCache<'a> {
    is_initiator: Cow<'a, Option<bool>>,
    spi: Cow<'a, Spi>,
    peer_spi: Cow<'a, Option<Spi>>,
    message_id: Cow<'a, u32>,
    chosen_proposal: Cow<'a, Option<ChosenProposal>>,
    public_key: Cow<'a, Option<Vec<u8>>>,
    private_key: Cow<'a, Option<GroupPrivateKey>>,
    keys: Cow<'a, Option<Keys>>,
    nonce_i: Cow<'a, Option<Vec<u8>>>,
    nonce_r: Cow<'a, Option<Vec<u8>>>,
    ike_sa_init_request: Cow<'a, Option<Vec<u8>>>,
    ike_sa_init_response: Cow<'a, Option<Vec<u8>>>,
    larval_child_sa: Cow<'a, Option<LarvalChildSa>>,
}

impl<'a, 'b: 'c, 'c> StateDataCache<'a> {
    /// Creates a new `StateDataCache` borrowing from a given data
    fn new_borrowed(data: &'a StateData) -> Self {
        Self {
            is_initiator: Cow::Borrowed(&data.is_initiator),
            spi: Cow::Borrowed(&data.spi),
            peer_spi: Cow::Borrowed(&data.peer_spi),
            message_id: Cow::Borrowed(&data.message_id),
            chosen_proposal: Cow::Borrowed(&data.chosen_proposal),
            public_key: Cow::Borrowed(&data.public_key),
            private_key: Cow::Borrowed(&data.private_key),
            keys: Cow::Borrowed(&data.keys),
            nonce_i: Cow::Borrowed(&data.nonce_i),
            nonce_r: Cow::Borrowed(&data.nonce_r),
            ike_sa_init_request: Cow::Borrowed(&data.ike_sa_init_request),
            ike_sa_init_response: Cow::Borrowed(&data.ike_sa_init_response),
            larval_child_sa: Cow::Borrowed(&data.larval_child_sa),
        }
    }

    /// Swaps borrowed references to the ones from another
    fn swap(&self, other: &'b StateDataCache<'b>) -> StateDataCache<'c> {
        StateDataCache {
            is_initiator: match &self.is_initiator {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.is_initiator.borrow()),
            },
            spi: match &self.spi {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.spi.borrow()),
            },
            peer_spi: match &self.peer_spi {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.peer_spi.borrow()),
            },
            message_id: match &self.message_id {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.message_id.borrow()),
            },
            chosen_proposal: match &self.chosen_proposal {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.chosen_proposal.borrow()),
            },
            public_key: match &self.public_key {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.public_key.borrow()),
            },
            private_key: match &self.private_key {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.private_key.borrow()),
            },
            keys: match &self.keys {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.keys.borrow()),
            },
            nonce_i: match &self.nonce_i {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.nonce_i.borrow()),
            },
            nonce_r: match &self.nonce_r {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.nonce_r.borrow()),
            },
            ike_sa_init_request: match &self.ike_sa_init_request {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.ike_sa_init_request.borrow()),
            },
            ike_sa_init_response: match &self.ike_sa_init_response {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.ike_sa_init_response.borrow()),
            },
            larval_child_sa: match &self.larval_child_sa {
                Cow::Owned(owned) => Cow::Owned(owned.to_owned()),
                _ => Cow::Borrowed(other.larval_child_sa.borrow()),
            },
        }
    }

    /// Writes changed values in this `StateDataCache` into `StateData`
    fn write_into<D>(self, dest: &mut D)
    where
        D: DerefMut<Target = StateData>,
    {
        if let Cow::Owned(owned) = self.is_initiator {
            debug!("updating is_initiator");
            dest.is_initiator = owned;
        }
        if let Cow::Owned(owned) = self.spi {
            debug!("updating spi");
            dest.spi = owned;
        }
        if let Cow::Owned(owned) = self.peer_spi {
            debug!("updating peer_spi");
            dest.peer_spi = owned;
        }
        if let Cow::Owned(owned) = self.message_id {
            debug!("updating message_id");
            dest.message_id = owned;
        }
        if let Cow::Owned(owned) = self.chosen_proposal {
            debug!("updating chosen_proposal");
            dest.chosen_proposal = owned;
        }
        if let Cow::Owned(owned) = self.public_key {
            debug!("updating public_key");
            dest.public_key = owned;
        }
        if let Cow::Owned(owned) = self.private_key {
            debug!("updating private_key");
            dest.private_key = owned;
        }
        if let Cow::Owned(owned) = self.keys {
            debug!("updating keys");
            dest.keys = owned;
        }
        if let Cow::Owned(owned) = self.nonce_i {
            debug!("updating nonce_i");
            dest.nonce_i = owned;
        }
        if let Cow::Owned(owned) = self.nonce_r {
            debug!("updating nonce_r");
            dest.nonce_r = owned;
        }
        if let Cow::Owned(owned) = self.ike_sa_init_request {
            debug!("updating ike_sa_init_request");
            dest.ike_sa_init_request = owned;
        }
        if let Cow::Owned(owned) = self.ike_sa_init_response {
            debug!("updating ike_sa_init_response");
            dest.ike_sa_init_response = owned;
        }
        if let Cow::Owned(owned) = self.larval_child_sa {
            debug!("updating larval_child_sa");
            dest.larval_child_sa = owned;
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

        let prf = self.chosen_proposal()?.prf();
        let mut mac = prf.prf(&self.keys()?.deriving.pi, &buf[payload::HEADER_SIZE..])?;

        let mut signed_data = Vec::new();
        signed_data.append(&mut ike_sa_init_request.to_vec());
        signed_data.append(&mut nonce_r.to_vec());
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

        let prf = self.chosen_proposal()?.prf();
        let mut mac = prf.prf(&self.keys()?.deriving.pr, &buf[payload::HEADER_SIZE..])?;

        let mut signed_data = Vec::new();
        signed_data.append(&mut ike_sa_init_response.to_vec());
        signed_data.append(&mut nonce_i.to_vec());
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
            Some(true) => &self.keys()?.protecting.ai,
            Some(false) => &self.keys()?.protecting.ar,
            None => {
                return Err(StateError::InvalidState(
                    InvalidStateError::InitiatorNotDetermined,
                ));
            }
        };

        let integ = self.chosen_proposal()?.integ().unwrap();
        Ok(Some(integ.sign(key.as_ref().unwrap(), message.as_ref())?))
    }

    fn message_verify(&self, message: impl AsRef<[u8]>) -> Result<bool, StateError> {
        if self.chosen_proposal()?.integ().is_none() {
            return Ok(true);
        }

        let key = match *self.is_initiator {
            Some(true) => &self.keys()?.protecting.ar,
            Some(false) => &self.keys()?.protecting.ai,
            None => {
                return Err(StateError::InvalidState(
                    InvalidStateError::InitiatorNotDetermined,
                ));
            }
        };

        let integ = self.chosen_proposal()?.integ().unwrap();
        if message.as_ref().len() < integ.output_size() {
            return Err(DeserializeError::PrematureEof.into());
        }

        let (message, checksum) = message
            .as_ref()
            .split_at(message.as_ref().len() - integ.output_size());
        Ok(integ.verify(key.as_ref().unwrap(), message, checksum)?)
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
