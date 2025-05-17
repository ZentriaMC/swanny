use crate::{
    config::Config,
    message::traffic_selector::TrafficSelector,
    sa::ControlMessage,
    state::{State, StateData},
};
use anyhow::Result;
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) struct IkeAuthRequestSent {}

#[async_trait]
impl State for IkeAuthRequestSent {
    async fn handle_message(
        self: Box<Self>,
        _config: &Config,
        _sender: UnboundedSender<ControlMessage>,
        _data: Arc<RwLock<StateData>>,
        _message: &[u8],
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }

    async fn handle_acquire(
        self: Box<Self>,
        _config: &Config,
        _sender: UnboundedSender<ControlMessage>,
        _data: Arc<RwLock<StateData>>,
        _ts_i: &TrafficSelector,
        _ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}
