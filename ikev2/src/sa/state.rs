use crate::{
    config::Config,
    crypto::rand_bytes,
    message::{Message, SPI, traffic_selector::TrafficSelector},
    sa::ControlMessage,
};
use anyhow::Result;
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

pub(crate) struct StateData {
    pub(crate) config: Config,
    pub(crate) initiator: bool,
    pub(crate) address: SocketAddr,
    pub(crate) spi: SPI,
    pub(crate) peer_address: SocketAddr,
    pub(crate) peer_spi: Option<SPI>,
}

#[async_trait]
pub(crate) trait State {
    async fn handle_message(
        self: Box<Self>,
        data: Arc<RwLock<StateData>>,
        message: &[u8],
    ) -> Result<Box<dyn State>>;

    async fn handle_acquire(
        self: Box<Self>,
        data: Arc<RwLock<StateData>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: usize,
    ) -> Result<Box<dyn State>>;
}

pub(crate) struct Initial {}

#[async_trait]
impl State for Initial {
    async fn handle_message(
        self: Box<Self>,
        data: Arc<RwLock<StateData>>,
        message: &[u8],
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
    async fn handle_acquire(
        self: Box<Self>,
        data: Arc<RwLock<StateData>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: usize,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}
