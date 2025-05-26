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
use std::sync::Arc;
use tokio::sync::RwLock;

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
    private_key: Option<GroupPrivateKey>,
    keys: Option<Keys>,
    nonce_i: Option<Vec<u8>>,
    nonce_r: Option<Vec<u8>>,
    ike_sa_init_request: Option<Vec<u8>>,
    ike_sa_init_response: Option<Vec<u8>>,
    larval_child_sa: Option<LarvalChildSa>,
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

    fn chosen_proposal(&self) -> Result<&ChosenProposal, StateError> {
        self.chosen_proposal
            .as_ref()
            .ok_or(StateError::InvalidState(
                InvalidStateError::NoProposalChosen,
            ))
    }

    fn keys(&self) -> Result<&Keys, StateError> {
        self.keys
            .as_ref()
            .ok_or(StateError::InvalidState(InvalidStateError::NoKeysSet))
    }

    fn initiator_signed_data(&self, id: &Id) -> Result<Vec<u8>, StateError> {
        let len = id.size()?;
        let mut buf = BytesMut::with_capacity(len);
        id.serialize(&mut buf)?;

        let ike_sa_init_request =
            self.ike_sa_init_request
                .as_ref()
                .ok_or(StateError::InvalidState(
                    InvalidStateError::IkeSaInitNotRecorded,
                ))?;
        let nonce_r = self.nonce_r.as_ref().ok_or(StateError::InvalidState(
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
            self.ike_sa_init_response
                .as_ref()
                .ok_or(StateError::InvalidState(
                    InvalidStateError::IkeSaInitNotRecorded,
                ))?;
        let nonce_i = self.nonce_i.as_ref().ok_or(StateError::InvalidState(
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
        match self.is_initiator {
            Some(true) => self.initiator_signed_data(id),
            Some(false) => self.responder_signed_data(id),
            None => Err(StateError::InvalidState(
                InvalidStateError::InitiatorNotDetermined,
            )),
        }
    }

    fn auth_data_for_verification(&self, id: &Id) -> Result<Vec<u8>, StateError> {
        match self.is_initiator {
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

        let key = match self.is_initiator() {
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

        let key = match self.is_initiator() {
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
