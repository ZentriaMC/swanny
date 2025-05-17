use crate::{
    config::Config,
    crypto::GroupPrivateKey,
    message::{Spi, traffic_selector::TrafficSelector},
    sa::{ChildSa, ChosenProposal, ControlMessage, Keys},
};
use anyhow::Result;
use async_trait::async_trait;
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
    nonce: Option<Vec<u8>>,
    larval_child_sa: Option<ChildSa>,
}

impl StateData {
    pub fn new(spi: &Spi) -> Self {
        Self {
            spi: spi.to_owned(),
            ..Default::default()
        }
    }
}
