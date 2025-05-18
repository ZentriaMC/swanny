use crate::{
    config::Config,
    crypto::GroupPrivateKey,
    message::{
        Spi,
        payload::{self, Id},
        serialize::Serialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ChosenProposal, ControlMessage, Keys},
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
pub(crate) trait State: Send + Sync {
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
    larval_child_sa: Option<ChildSa>,
}

impl StateData {
    pub fn new(spi: &Spi) -> Self {
        Self {
            spi: spi.to_owned(),
            ..Default::default()
        }
    }

    fn initiator_signed_data(&self, id: &Id) -> Result<Vec<u8>> {
        let len = id.size()?;
        let mut buf = BytesMut::with_capacity(len);
        id.serialize(&mut buf)?;

        let chosen_proposal = self.chosen_proposal.as_ref().ok_or_else(|| anyhow::anyhow!("no proposal chosen"))?;
        let keys = self.keys.as_ref().ok_or_else(|| anyhow::anyhow!("no keys generated"))?;
        let ike_sa_init_request = self.ike_sa_init_request.as_ref().ok_or_else(|| anyhow::anyhow!("IKE_SA_INIT request is not set"))?;
        let nonce_r = self.nonce_r.as_ref().ok_or_else(|| anyhow::anyhow!("Nr not received"))?;

        let prf = chosen_proposal.prf();
        let mut mac = prf.prf(
            &keys.deriving.pi,
            &buf[payload::HEADER_SIZE..],
        )?;

        let mut signed_data = Vec::new();
        signed_data.append(&mut ike_sa_init_request.to_vec());
        signed_data.append(&mut nonce_r.to_vec());
        signed_data.append(&mut mac);
        Ok(signed_data)
    }

    fn responder_signed_data(&self, id: &Id) -> Result<Vec<u8>> {
        let len = id.size()?;
        let mut buf = BytesMut::with_capacity(len);
        id.serialize(&mut buf);

        let chosen_proposal = self.chosen_proposal.as_ref().ok_or_else(|| anyhow::anyhow!("no proposal chosen"))?;
        let keys = self.keys.as_ref().ok_or_else(|| anyhow::anyhow!("no keys generated"))?;
        let ike_sa_init_response = self.ike_sa_init_response.as_ref().ok_or_else(|| anyhow::anyhow!("IKE_SA_INIT response is not set"))?;
        let nonce_r = self.nonce_r.as_ref().ok_or_else(|| anyhow::anyhow!("Nr not received"))?;

        let prf = chosen_proposal.prf();
        let mut mac = prf.prf(
            &keys.deriving.pr,
            &buf[payload::HEADER_SIZE..],
        )?;

        let mut signed_data = Vec::new();
        signed_data.append(&mut ike_sa_init_response.to_vec());
        signed_data.append(&mut nonce_r.to_vec());
        signed_data.append(&mut mac);
        Ok(signed_data)
    }
}
