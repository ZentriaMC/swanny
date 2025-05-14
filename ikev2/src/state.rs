use crate::{
    config::Config,
    message::{Message, SPI, traffic_selector::TrafficSelector},
    sa::{ChildSa, ChosenProposal, ControlMessage},
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
        data: Arc<RwLock<StateData>>,
        message: &Message,
    ) -> Result<Box<dyn State>>;

    async fn handle_acquire(
        self: Box<Self>,
        data: Arc<RwLock<StateData>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: u32,
    ) -> Result<Box<dyn State>>;
}

pub(crate) struct StateData {
    config: Config,
    initiator: Option<bool>,
    spi: SPI,
    peer_spi: Option<SPI>,
    message_id: u32,
    chosen_proposal: Option<ChosenProposal>,
    nonce: Option<Vec<u8>>,
    larval_sa: Option<ChildSa>,
    sender: UnboundedSender<ControlMessage>,
}

impl StateData {
    pub fn new(config: &Config, spi: &SPI, sender: UnboundedSender<ControlMessage>) -> Self {
        Self {
            config: config.to_owned(),
            initiator: None,
            spi: spi.to_owned(),
            peer_spi: None,
            message_id: 0,
            chosen_proposal: None,
            nonce: None,
            larval_sa: None,
            sender,
        }
    }
}
