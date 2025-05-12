use crate::{
    config::Config,
    crypto::rand_bytes,
    message::{Message, SPI, traffic_selector::TrafficSelector},
};
use anyhow::Result;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

mod state;
use state::State;

pub enum ControlMessage {
    Ike(Vec<u8>),
}

struct IkeSaInner {
    config: Config,
    initiator: bool,
    address: SocketAddr,
    spi: SPI,
    peer_address: SocketAddr,
    peer_spi: Option<SPI>,
    message_id: u32,
    sender: UnboundedSender<ControlMessage>,
}

#[derive(Clone)]
pub struct IkeSa {
    inner: Arc<RwLock<IkeSaInner>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
}

impl IkeSa {
    fn new(
        config: &Config,
        initiator: bool,
        address: &SocketAddr,
        peer_address: &SocketAddr,
        peer_spi: Option<&SPI>,
    ) -> Result<(Self, UnboundedReceiver<ControlMessage>)> {
        let mut spi = SPI::default();
        rand_bytes(&mut spi)?;

        let (sender, receiver) = unbounded();

        let inner = IkeSaInner {
            initiator: true,
            config: config.to_owned(),
            address: address.to_owned(),
            peer_address: address.to_owned(),
            spi,
            peer_spi: peer_spi.map(ToOwned::to_owned),
            message_id: 1,
            sender,
        };

        Ok((
            Self {
                inner: Arc::new(RwLock::new(inner)),
                state: Arc::new(Mutex::new(Some(Box::new(state::Initial {})))),
            },
            receiver,
        ))
    }

    pub fn initiator(
        config: &Config,
        address: &SocketAddr,
        peer_address: &SocketAddr,
    ) -> Result<(Self, UnboundedReceiver<ControlMessage>)> {
        Self::new(config, true, address, peer_address, None)
    }

    pub fn responder(
        config: &Config,
        address: &SocketAddr,
        peer_address: &SocketAddr,
        peer_spi: &SPI,
    ) -> Result<(Self, UnboundedReceiver<ControlMessage>)> {
        Self::new(config, false, address, peer_address, Some(peer_spi))
    }

    pub async fn handle_message(&mut self, message: &[u8]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(s) = state.take() {
            drop(state);

            let s = s.handle_message(self.inner.clone(), message).await?;
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

            let s = s
                .handle_acquire(self.inner.clone(), ts_i, ts_r, index)
                .await?;
            let mut state = self.state.lock().unwrap();
            *state = Some(s);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_state() {
    }
}
