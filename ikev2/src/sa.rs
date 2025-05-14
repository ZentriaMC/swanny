use crate::{
    config::Config,
    crypto::{self, Cipher, Group, Integ, Prf},
    message::{
        Message, SPI,
        num::{AttributeType, DhId, EncrId, IntegId, Num, PrfId, TransformType},
        proposal::Proposal,
        traffic_selector::TrafficSelector,
    },
    state::{self, State, StateData},
};
use anyhow::Result;
use futures::channel::mpsc::{UnboundedReceiver, unbounded};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

#[derive(Debug)]
pub enum ControlMessage {
    IkeMessage(Message),
}

#[derive(Clone)]
pub struct IkeSa {
    data: Arc<RwLock<StateData>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
}

impl IkeSa {
    pub fn new(config: &Config) -> Result<(Self, UnboundedReceiver<ControlMessage>)> {
        let mut spi = SPI::default();
        crypto::rand_bytes(&mut spi)?;

        let (sender, receiver) = unbounded();
        let data = StateData::new(config, &spi, sender);

        Ok((
            Self {
                data: Arc::new(RwLock::new(data)),
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

            let s = s.handle_message(self.data.clone(), &message).await?;
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
                .handle_acquire(self.data.clone(), &ts_i, &ts_r, index)
                .await?;
            let mut state = self.state.lock().await;
            *state = Some(s);
        }

        Ok(())
    }
}

pub(crate) struct ChosenProposal {
    cipher: Cipher,
    prf: Prf,
    integ: Option<Integ>,
    group: Group,
}

impl ChosenProposal {
    pub fn new(proposal: &Proposal) -> Result<Self> {
        let transform = proposal
            .transforms()
            .find(|t| t.r#type() == Num::Assigned(TransformType::ENCR))
            .ok_or_else(|| anyhow::anyhow!("ENCR transform not found"))?;
        let id: EncrId = transform.id().try_into()?;
        let attribute = transform
            .attributes()
            .find(|a| a.r#type() == Num::Assigned(AttributeType::KeyLength))
            .ok_or_else(|| anyhow::anyhow!("KeyLength attribute not found"))?;
        let cipher = Cipher::new(id, Some(u16::from_be_bytes(attribute.value().try_into()?)))?;

        let transform = proposal
            .transforms()
            .find(|t| t.r#type() == Num::Assigned(TransformType::PRF))
            .ok_or_else(|| anyhow::anyhow!("PRF transform not found"))?;
        let id: PrfId = transform.id().try_into()?;
        let prf = Prf::new(id)?;

        let integ = if cipher.is_aead() {
            None
        } else {
            let transform = proposal
                .transforms()
                .find(|t| t.r#type() == Num::Assigned(TransformType::INTEG))
                .ok_or_else(|| anyhow::anyhow!("INTEG transform not found"))?;
            let id: IntegId = transform.id().try_into()?;
            Some(Integ::new(id)?)
        };

        let transform = proposal
            .transforms()
            .find(|t| t.r#type() == Num::Assigned(TransformType::DH))
            .ok_or_else(|| anyhow::anyhow!("DH transform not found"))?;
        let id: DhId = transform.id().try_into()?;
        let group = Group::new(id)?;

        Ok(Self {
            cipher,
            prf,
            integ,
            group,
        })
    }

    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }

    pub fn prf(&self) -> &Prf {
        &self.prf
    }

    pub fn integ(&self) -> Option<&Integ> {
        self.integ.as_ref()
    }

    pub fn group(&self) -> &Group {
        &self.group
    }
}

pub(crate) struct ChildSa {
    ts_i: TrafficSelector,
    ts_r: TrafficSelector,
}

impl ChildSa {
    pub fn new(ts_i: &TrafficSelector, ts_r: &TrafficSelector) -> Self {
        Self {
            ts_i: ts_i.to_owned(),
            ts_r: ts_r.to_owned(),
        }
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
