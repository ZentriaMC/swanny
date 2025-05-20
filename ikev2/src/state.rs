use crate::{
    config::Config,
    crypto::GroupPrivateKey,
    message::{
        self, Spi,
        num::{AuthType, Num},
        payload::{self, Auth, Id},
        serialize::Serialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, Keys, LarvalChildSa},
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc::UnboundedSender;
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

#[async_trait]
pub(crate) trait State: Send + Sync + std::fmt::Display {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        message: &[u8],
    ) -> Result<Box<dyn State>>;

    async fn handle_acquire(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: u32,
    ) -> Result<Box<dyn State>>;
}

#[derive(Default)]
pub(crate) struct StateData {
    initiator: Option<bool>,
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

    fn initiator_signed_data(
        &self,
        chosen_proposal: &ChosenProposal,
        keys: &Keys,
        id: &Id,
    ) -> Result<Vec<u8>> {
        let len = id.size()?;
        let mut buf = BytesMut::with_capacity(len);
        id.serialize(&mut buf)?;

        let ike_sa_init_request = self
            .ike_sa_init_request
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IKE_SA_INIT request is not set"))?;
        let nonce_r = self
            .nonce_r
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Nr not received"))?;

        let prf = chosen_proposal.prf();
        let mut mac = prf.prf(&keys.deriving.pi, &buf[payload::HEADER_SIZE..])?;

        let mut signed_data = Vec::new();
        signed_data.append(&mut ike_sa_init_request.to_vec());
        signed_data.append(&mut nonce_r.to_vec());
        signed_data.append(&mut mac);
        Ok(signed_data)
    }

    fn responder_signed_data(
        &self,
        chosen_proposal: &ChosenProposal,
        keys: &Keys,
        id: &Id,
    ) -> Result<Vec<u8>> {
        let len = id.size()?;
        let mut buf = BytesMut::with_capacity(len);
        id.serialize(&mut buf)?;

        let ike_sa_init_response = self
            .ike_sa_init_response
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IKE_SA_INIT response is not set"))?;
        let nonce_i = self
            .nonce_i
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ni not received"))?;

        let prf = chosen_proposal.prf();
        let mut mac = prf.prf(&keys.deriving.pr, &buf[payload::HEADER_SIZE..])?;

        let mut signed_data = Vec::new();
        signed_data.append(&mut ike_sa_init_response.to_vec());
        signed_data.append(&mut nonce_i.to_vec());
        signed_data.append(&mut mac);
        Ok(signed_data)
    }

    fn auth_sign(&self, config: &Config) -> Result<payload::Auth> {
        let chosen_proposal = self
            .chosen_proposal
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no proposal chosen"))?;
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no keys generated"))?;

        let signed_data = match self.initiator {
            Some(true) => self.initiator_signed_data(chosen_proposal, keys, config.id())?,
            Some(false) => self.responder_signed_data(chosen_proposal, keys, config.id())?,
            _ => return Err(anyhow::anyhow!("initiator/responder not determined")),
        };

        let prf = chosen_proposal.prf();
        if let Some(psk) = config.psk() {
            Ok(payload::Auth::new(
                Num::Assigned(AuthType::PSK),
                prf.prf(prf.prf(psk, message::KEY_PAD)?, &signed_data)?,
            ))
        } else {
            Err(anyhow::anyhow!("PSK not set"))
        }
    }

    fn auth_verify(&self, config: &Config, id: &Id, auth: &Auth) -> Result<bool> {
        let chosen_proposal = self
            .chosen_proposal
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no proposal chosen"))?;
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no keys generated"))?;

        let signed_data = match self.initiator {
            Some(true) => self.responder_signed_data(chosen_proposal, keys, id)?,
            Some(false) => self.initiator_signed_data(chosen_proposal, keys, id)?,
            _ => return Err(anyhow::anyhow!("initiator/responder not determined")),
        };

        let prf = chosen_proposal.prf();
        if let Some(psk) = config.psk() {
            Ok(prf.verify(
                prf.prf(psk, message::KEY_PAD)?,
                &signed_data,
                auth.auth_data(),
            )?)
        } else {
            return Err(anyhow::anyhow!("PSK not set"));
        }
    }

    fn message_sign(&self, message: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let chosen_proposal = self
            .chosen_proposal
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no proposal chosen"))?;

        if chosen_proposal.integ().is_none() {
            return Ok(None);
        }

        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no keys generated"))?;

        let key = match self.initiator {
            Some(true) => &keys.protecting.ai,
            Some(false) => &keys.protecting.ar,
            _ => return Err(anyhow::anyhow!("initiator/responder not determined")),
        };

        let integ = chosen_proposal.integ().unwrap();
        Ok(Some(integ.sign(key, message.as_ref())?))
    }

    fn message_verify(&self, message: impl AsRef<[u8]>) -> Result<bool> {
        let chosen_proposal = self
            .chosen_proposal
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no proposal chosen"))?;

        if chosen_proposal.integ().is_none() {
            return Ok(true);
        }

        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no keys generated"))?;

        let key = match self.initiator {
            Some(true) => &keys.protecting.ar,
            Some(false) => &keys.protecting.ai,
            _ => return Err(anyhow::anyhow!("initiator/responder not determined")),
        };

        let integ = chosen_proposal.integ().unwrap();
        if message.as_ref().len() < integ.output_size() {
            return Err(anyhow::anyhow!("invalid checksum size"));
        }

        let (message, checksum) = message
            .as_ref()
            .split_at(message.as_ref().len() - integ.output_size());
        Ok(integ.verify(key, message, checksum)?)
    }
}
