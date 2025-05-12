use crate::{
    config::Config,
    crypto::rand_bytes,
    message::{Message, SPI, traffic_selector::TrafficSelector},
};
use anyhow::Result;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

mod state;
use state::State;

#[derive(Debug)]
pub enum ControlMessage {
    IkeMessage(Message),
}

struct IkeSaInner {
    config: Config,
    initiator: Option<bool>,
    address: IpAddr,
    spi: SPI,
    peer_address: IpAddr,
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
    pub fn new(
        config: &Config,
        address: &IpAddr,
        peer_address: &IpAddr,
    ) -> Result<(Self, UnboundedReceiver<ControlMessage>)> {
        let mut spi = SPI::default();
        rand_bytes(&mut spi)?;

        let (sender, receiver) = unbounded();

        let inner = IkeSaInner {
            initiator: None,
            config: config.to_owned(),
            address: address.to_owned(),
            peer_address: address.to_owned(),
            spi,
            peer_spi: None,
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

    pub async fn set_peer_spi(&mut self, spi: &SPI) {
        let mut inner = self.inner.write().await;
        let _ = inner.peer_spi.replace(spi.to_owned());
    }

    pub async fn handle_message(&mut self, message: &Message) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(s) = state.take() {
            drop(state);

            let s = s.handle_message(self.inner.clone(), message).await?;
            let mut state = self.state.lock().await;
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
        let mut state = self.state.lock().await;
        if let Some(s) = state.take() {
            drop(state);

            let s = s
                .handle_acquire(self.inner.clone(), ts_i, ts_r, index)
                .await?;
            let mut state = self.state.lock().await;
            *state = Some(s);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config,
        message::{
            Message,
            num::{Num, TrafficSelectorType},
            serialize::Deserialize,
            traffic_selector::TrafficSelector,
        },
    };
    use futures::stream::StreamExt;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_state() {
        let config = config::tests::create_config();
        let address = IpAddr::from_str("192.168.1.2").unwrap();
        let peer_address = IpAddr::from_str("192.168.1.3").unwrap();
        let (mut ike_sa, mut messages) =
            IkeSa::new(&config, &address, &peer_address).expect("unable to create IKE SA");
        tokio::spawn(async move {
            ike_sa
                .handle_acquire(
                    &TrafficSelector::new(
                        Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE),
                        0,
                        &address,
                        &address,
                        0,
                        0,
                    ),
                    &TrafficSelector::new(
                        Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE),
                        0,
                        &peer_address,
                        &peer_address,
                        0,
                        0,
                    ),
                    1,
                )
                .await
                .expect("unable to handle acquire");
        });

        tokio::select! {
            Some(ControlMessage::IkeMessage(message)) = messages.next() => {
                println!("{:?}", message);
            },
        }
    }
}
