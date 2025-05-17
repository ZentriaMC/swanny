use crate::{
    config::Config,
    crypto::{self, Cipher, Group, Integ, Prf},
    message::{
        EspSpi, Message, Spi,
        num::{AttributeType, DhId, EncrId, IntegId, Num, PrfId, TransformType},
        proposal::Proposal,
        traffic_selector::TrafficSelector,
    },
    state::{self, State, StateData},
};
use anyhow::Result;
use bytes::Buf;
use futures::channel::mpsc::{UnboundedReceiver, unbounded};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

#[derive(Debug)]
pub enum ControlMessage {
    IkeMessage(Vec<u8>),
}

#[derive(Clone)]
pub struct IkeSa {
    data: Arc<RwLock<StateData>>,
    state: Arc<Mutex<Option<Box<dyn State>>>>,
}

impl IkeSa {
    pub fn new(config: &Config) -> Result<(Self, UnboundedReceiver<ControlMessage>)> {
        let mut spi = Spi::default();
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
        this: impl IntoIterator<Item = &'a Proposal>,
        other: impl IntoIterator<Item = &'b Proposal>,
    ) -> Option<Proposal> {
        let mut this = this.into_iter();
        let mut other = other.into_iter();
        this.find_map(|px| other.find_map(|py| px.intersection(py)))
    }

    pub async fn handle_message(&self, message: impl AsRef<[u8]>) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(s) = state.take() {
            drop(state);

            let s = s
                .handle_message(self.data.clone(), message.as_ref())
                .await?;
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
            .find(|t| t.ty() == Num::Assigned(TransformType::ENCR))
            .ok_or_else(|| anyhow::anyhow!("ENCR transform not found"))?;
        let id: EncrId = transform.id().try_into()?;
        let attribute = transform
            .attributes()
            .find(|a| a.ty() == Num::Assigned(AttributeType::KeyLength))
            .ok_or_else(|| anyhow::anyhow!("KeyLength attribute not found"))?;
        let cipher = Cipher::new(id, Some(u16::from_be_bytes(attribute.value().try_into()?)))?;

        let transform = proposal
            .transforms()
            .find(|t| t.ty() == Num::Assigned(TransformType::PRF))
            .ok_or_else(|| anyhow::anyhow!("PRF transform not found"))?;
        let id: PrfId = transform.id().try_into()?;
        let prf = Prf::new(id)?;

        let integ = if cipher.is_aead() {
            None
        } else {
            let transform = proposal
                .transforms()
                .find(|t| t.ty() == Num::Assigned(TransformType::INTEG))
                .ok_or_else(|| anyhow::anyhow!("INTEG transform not found"))?;
            let id: IntegId = transform.id().try_into()?;
            Some(Integ::new(id)?)
        };

        let transform = proposal
            .transforms()
            .find(|t| t.ty() == Num::Assigned(TransformType::DH))
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

    pub fn generate_keys(
        &self,
        skeyseed: impl AsRef<[u8]>,
        n_i: impl AsRef<[u8]>,
        n_r: impl AsRef<[u8]>,
        spi_i: &Spi,
        spi_r: &Spi,
    ) -> Result<Keys> {
        let mut buf = n_i.as_ref().to_vec();
        buf.extend_from_slice(n_r.as_ref());
        buf.extend_from_slice(&spi_i[..]);
        buf.extend_from_slice(&spi_r[..]);
        let integ_key_size = self
            .integ
            .as_ref()
            .map(|integ| integ.key_size())
            .unwrap_or(0);
        let buf = self.prf.prfplus(
            skeyseed,
            &buf,
            self.prf.size() * 3 + self.cipher.key_size() * 2 + integ_key_size * 2,
        )?;
        let mut buf = buf.as_slice();

        let mut d = vec![0; self.prf.size()];
        buf.try_copy_to_slice(&mut d)?;

        let mut ei = vec![0; self.cipher.key_size()];
        buf.try_copy_to_slice(&mut ei)?;

        let mut er = vec![0; self.cipher.key_size()];
        buf.try_copy_to_slice(&mut er)?;

        let mut ai = vec![0; integ_key_size];
        buf.try_copy_to_slice(&mut ai)?;

        let mut ar = vec![0; integ_key_size];
        buf.try_copy_to_slice(&mut ar)?;

        let mut pi = vec![0; self.prf.size()];
        buf.try_copy_to_slice(&mut pi)?;

        let mut pr = vec![0; self.prf.size()];
        buf.try_copy_to_slice(&mut pr)?;

        Ok(Keys {
            d,
            ei,
            er,
            ai,
            ar,
            pi,
            pr,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Keys {
    pub d: Vec<u8>,
    pub ei: Vec<u8>,
    pub er: Vec<u8>,
    pub ai: Vec<u8>,
    pub ar: Vec<u8>,
    pub pi: Vec<u8>,
    pub pr: Vec<u8>,
}

pub(crate) struct ChildSa {
    pub ts_i: TrafficSelector,
    pub ts_r: TrafficSelector,
    pub spi: EspSpi,
    pub peer_spi: Option<EspSpi>,
    pub chosen_proposal: Option<ChosenProposal>,
}

impl ChildSa {
    pub fn new(ts_i: &TrafficSelector, ts_r: &TrafficSelector) -> Result<Self> {
        let mut spi = EspSpi::default();
        crypto::rand_bytes(&mut spi)?;

        Ok(Self {
            ts_i: ts_i.to_owned(),
            ts_r: ts_r.to_owned(),
            spi,
            peer_spi: None,
            chosen_proposal: None,
        })
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
