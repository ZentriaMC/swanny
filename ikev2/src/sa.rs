use crate::{
    config::Config,
    crypto::rand_bytes,
    message::{Message, SPI, traffic_selector::TrafficSelector},
};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

mod state;
use state::{State, StateData};

#[derive(Clone)]
pub struct IkeSa {
    inner: Arc<RwLock<StateData>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
}

impl IkeSa {
    fn new(
        initiator: bool,
        config: &Config,
        address: &SocketAddr,
        peer_address: &SocketAddr,
        peer_spi: Option<&SPI>,
    ) -> Result<Self> {
        let mut spi = SPI::default();
        rand_bytes(&mut spi)?;

        let inner = StateData {
            initiator: true,
            config: config.to_owned(),
            address: address.to_owned(),
            peer_address: address.to_owned(),
            spi,
            peer_spi: peer_spi.map(ToOwned::to_owned),
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            state: Arc::new(Mutex::new(Some(Box::new(state::Initial {})))),
        })
    }

    pub fn initiator(
        config: &Config,
        address: &SocketAddr,
        peer_address: &SocketAddr,
    ) -> Result<Self> {
        Self::new(true, config, address, peer_address, None)
    }

    pub fn responder(
        config: &Config,
        address: &SocketAddr,
        peer_address: &SocketAddr,
        peer_spi: &SPI,
    ) -> Result<Self> {
        Self::new(false, config, address, peer_address, Some(peer_spi))
    }

    pub async fn handle_message(&mut self, data: &[u8]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(s) = state.take() {
            drop(state);

            let s = s.handle_message(data).await?;
            let mut state = self.state.lock().unwrap();
            *state = Some(s);
        }
        Ok(())
    }

    pub async fn handle_acquire(
        &mut self,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: usize,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(s) = state.take() {
            drop(state);

            let s = s.handle_acquire(ts_i, ts_r, index).await?;
            let mut state = self.state.lock().unwrap();
            *state = Some(s);
        }
        Ok(())
    }
}
