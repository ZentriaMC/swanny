use crate::{
    config::Config,
    crypto::{Group, rand_bytes},
    message::{Message, SPI, proposal::Proposal, traffic_selector::TrafficSelector},
};
use anyhow::Result;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
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
    spi: SPI,
    peer_spi: Option<SPI>,
    message_id: u32,
    proposals: Option<Vec<Proposal>>,
    group: Option<Group>,
    nonce: Option<Vec<u8>>,
    larval_sa: Option<ChildSa>,
    sender: UnboundedSender<ControlMessage>,
}

#[derive(Clone)]
pub struct IkeSa {
    inner: Arc<RwLock<IkeSaInner>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
}

impl IkeSa {
    pub fn new(config: &Config) -> Result<(Self, UnboundedReceiver<ControlMessage>)> {
        let mut spi = SPI::default();
        rand_bytes(&mut spi)?;

        let (sender, receiver) = unbounded();

        let inner = IkeSaInner {
            initiator: None,
            config: config.to_owned(),
            spi,
            peer_spi: None,
            message_id: 1,
            sender,
            group: None,
            nonce: None,
            proposals: None,
            larval_sa: None,
        };

        Ok((
            Self {
                inner: Arc::new(RwLock::new(inner)),
                state: Arc::new(Mutex::new(Some(Box::new(state::Initial {})))),
            },
            receiver,
        ))
    }

    pub(crate) fn choose_proposal<'a, 'b>(
        mut this: impl Iterator<Item = &'a Proposal>,
        mut other: impl Iterator<Item = &'b Proposal>,
    ) -> Option<Proposal> {
        this.find_map(|px| other.find_map(|py| px.intersection(py)))
    }

    pub async fn handle_message(&self, message: Message) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(s) = state.take() {
            drop(state);

            let s = s.handle_message(self.inner.clone(), &message).await?;
            let mut state = self.state.lock().await;
            *state = Some(s);
        }

        Ok(())
    }

    pub async fn handle_acquire(
        &self,
        ts_i: TrafficSelector,
        ts_r: TrafficSelector,
        index: u32,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(s) = state.take() {
            drop(state);

            let s = s
                .handle_acquire(self.inner.clone(), &ts_i, &ts_r, index)
                .await?;
            let mut state = self.state.lock().await;
            *state = Some(s);
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct ChildSa {
    ts_i: TrafficSelector,
    ts_r: TrafficSelector,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config,
        message::{
            Message,
            num::{Num, TrafficSelectorType},
            traffic_selector,
        },
    };
    use futures::{
        SinkExt,
        channel::mpsc,
        stream::{FuturesUnordered, StreamExt},
    };

    #[tokio::test]
    async fn test_state() {
        let config = config::tests::create_config();
        let (mut initiator, mut messages_i) = IkeSa::new(&config).expect("unable to create IKE SA");
        let (mut responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");
        let mut initiator2 = initiator.clone();
        let mut responder2 = responder.clone();

        let handle = tokio::spawn(async move {
            let mut pending_operations = FuturesUnordered::new();

            loop {
                let res = futures::select! {
                    message = messages_i.select_next_some() => {
                        match message {
                            ControlMessage::IkeMessage(message) => {
                                eprintln!("INITIATOR: {:?}", message);
                                pending_operations.push(responder2.handle_message(message));
                            },
                            _ => {},
                        }
                    },
                    message = messages_r.select_next_some() => {
                        match message {
                            ControlMessage::IkeMessage(message) => {
                                eprintln!("RESPONDER: {:?}", message);
                                pending_operations.push(initiator2.handle_message(message));
                            },
                            _ => {},
                        }
                    },
                    _ = pending_operations.select_next_some() => {},
                };
            }
        });

        initiator
            .handle_acquire(
                traffic_selector::tests::create_traffic_selector(),
                traffic_selector::tests::create_traffic_selector(),
                1,
            )
            .await
            .expect("unable to handle acquire");

        handle.await.unwrap();
    }
}
