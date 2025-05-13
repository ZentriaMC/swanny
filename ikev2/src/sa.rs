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
    group: Option<Group>,
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

    fn choose_proposal<'a, 'b>(
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
    use futures::stream::StreamExt;

    #[tokio::test]
    async fn test_state() {
        let config = config::tests::create_config();
        let (mut ike_sa, mut messages) = IkeSa::new(&config).expect("unable to create IKE SA");
        tokio::spawn(async move {
            ike_sa
                .handle_acquire(
                    traffic_selector::tests::create_traffic_selector(),
                    traffic_selector::tests::create_traffic_selector(),
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
