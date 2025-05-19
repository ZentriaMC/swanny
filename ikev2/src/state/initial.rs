use crate::{
    config::Config,
    crypto::{self, GroupPrivateKey},
    message::{
        Message, Spi,
        num::{ExchangeType, MessageFlags, Num, PayloadType, Protocol},
        payload::{self, Payload},
        serialize::{Deserialize, Serialize},
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ChosenProposal, ControlMessage, IkeSa},
    state::{self, Keys, State, StateData},
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc::UnboundedSender;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub(crate) struct Initial {}

impl Initial {
    fn generate_ike_sa_init_request<D>(
        config: &Config,
        data: &D,
    ) -> Result<(Message, ChosenProposal, GroupPrivateKey, Vec<u8>)>
    where
        D: Deref<Target = StateData>,
    {
        let proposals: Vec<_> = config.ike_proposals(&data.spi).collect();
        if proposals.is_empty() {
            return Err(anyhow::anyhow!("no proposal to send"));
        }

        let chosen_proposal = ChosenProposal::new(&proposals[0])?;

        let mut nonce = vec![0u8; 32];
        crypto::rand_bytes(&mut nonce[..])?;

        let private_key = chosen_proposal.group().generate_key()?;
        let public_key = private_key.public_key()?;

        let mut message = Message::new(
            &data.spi,
            &Spi::default(),
            Num::Assigned(ExchangeType::IKE_SA_INIT),
            MessageFlags::I,
            1,
        );

        message.add_payloads([
            Payload::new(
                Num::Assigned(PayloadType::SA),
                payload::Content::Sa(payload::Sa::new(proposals)),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::NONCE),
                payload::Content::Nonce(payload::Nonce::new(&nonce[..])),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::KE),
                payload::Content::Ke(payload::Ke::new(
                    Num::Assigned(chosen_proposal.group().id()),
                    &public_key,
                )),
                true,
            ),
        ]);

        Ok((message, chosen_proposal, private_key, nonce))
    }

    fn handle_ike_sa_init_request<D>(
        config: &Config,
        data: &D,
        request: &Message,
    ) -> Result<(ChosenProposal, Vec<u8>, Keys, Vec<u8>, Vec<u8>)>
    where
        D: Deref<Target = StateData>,
    {
        let sa: &payload::Sa = request
            .get(PayloadType::SA)
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;

        let ke: &payload::Ke = request
            .get(PayloadType::KE)
            .ok_or_else(|| anyhow::anyhow!("no KE payload"))?;

        let nonce_i: &payload::Nonce = request
            .get(PayloadType::NONCE)
            .ok_or_else(|| anyhow::anyhow!("no NONCE payload"))?;

        let proposals: Vec<_> = config.ike_proposals(request.spi_i()).collect();
        if proposals.is_empty() {
            return Err(anyhow::anyhow!("no proposal to send"));
        }

        let proposal = IkeSa::choose_proposal(&proposals, sa.proposals())
            .ok_or_else(|| anyhow::anyhow!("no matching proposal"))?;

        let chosen_proposal = ChosenProposal::new(&proposal)?;
        let private_key = chosen_proposal.group().generate_key()?;
        let public_key = private_key.public_key()?;

        let mut nonce_r = vec![0u8; 32];
        crypto::rand_bytes(&mut nonce_r)?;

        let skeyseed = crypto::generate_skeyseed(
            chosen_proposal.prf(),
            nonce_i.nonce(),
            &nonce_r[..],
            &private_key,
            ke.ke_data(),
        )?;
        debug!("SKEYSEED generated: {:?}", &skeyseed);

        let keys = chosen_proposal.generate_keys(
            &skeyseed,
            nonce_i.nonce(),
            &nonce_r,
            request.spi_i(),
            &data.spi,
        )?;
        debug!("Keys generated: {:?}", &keys);

        Ok((
            chosen_proposal,
            public_key,
            keys,
            nonce_i.nonce().to_vec(),
            nonce_r,
        ))
    }

    fn generate_ike_sa_init_response<D>(
        config: &Config,
        data: &D,
        request: &Message,
        public_key: impl AsRef<[u8]>,
    ) -> Result<Message>
    where
        D: Deref<Target = StateData>,
    {
        let chosen_proposal = data.chosen_proposal.as_ref().unwrap();
        let nonce_r = data.nonce_r.as_ref().unwrap();

        let mut message = Message::new(
            data.peer_spi.as_ref().unwrap(),
            &data.spi,
            Num::Assigned(ExchangeType::IKE_SA_INIT),
            MessageFlags::R,
            request.id(),
        );

        message.add_payloads([
            Payload::new(
                Num::Assigned(PayloadType::KE),
                payload::Content::Ke(payload::Ke::new(
                    Num::Assigned(chosen_proposal.group().id()),
                    &public_key,
                )),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::SA),
                payload::Content::Sa(payload::Sa::new([chosen_proposal.proposal(
                    1,
                    Num::Assigned(Protocol::IKE),
                    b"",
                )])),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::NONCE),
                payload::Content::Nonce(payload::Nonce::new(&nonce_r[..])),
                true,
            ),
        ]);

        Ok(message)
    }
}

#[async_trait]
impl State for Initial {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>> {
        let serialized_request = message;
        let request = Message::deserialize(&mut message)?;
        match request.exchange() {
            Num::Assigned(ExchangeType::IKE_SA_INIT) => {
                let (chosen_proposal, public_key, keys, nonce_i, nonce_r) = {
                    let data = data.read().await;

                    Self::handle_ike_sa_init_request(config, &data, &request)?
                };

                {
                    let mut data = data.write().await;
                    data.initiator = Some(false);
                    data.chosen_proposal = Some(chosen_proposal);
                    data.keys = Some(keys);
                    data.nonce_i = Some(nonce_i);
                    data.nonce_r = Some(nonce_r);
                    data.peer_spi = Some(request.spi_i().to_owned());
                }

                let response = {
                    let data = data.read().await;

                    Self::generate_ike_sa_init_response(config, &data, &request, &public_key)?
                };

                let len = response.size()?;
                let mut buf = BytesMut::with_capacity(len);
                response.serialize(&mut buf)?;

                {
                    let mut data = data.write().await;
                    data.ike_sa_init_request = Some(serialized_request.to_vec());
                    data.ike_sa_init_response = Some(buf.to_vec());
                }

                sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?;

                Ok(Box::new(state::IkeSaInitResponseSent {}))
            }
            exchange => {
                return Err(anyhow::anyhow!("unknown exchange {:?}", exchange));
            }
        }
    }

    async fn handle_acquire(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        let inner = data.read().await;

        let (request, chosen_proposal, private_key, nonce) =
            Self::generate_ike_sa_init_request(config, &inner)?;
        let message_id = request.id();

        drop(inner);

        let len = request.size()?;
        let mut buf = BytesMut::with_capacity(len);
        request.serialize(&mut buf)?;

        let mut inner = data.write().await;
        inner.initiator = Some(true);
        inner.chosen_proposal = Some(chosen_proposal);
        inner.private_key = Some(private_key);
        inner.nonce_i = Some(nonce);
        inner.message_id = message_id;
        inner.larval_child_sa = Some(ChildSa::new(ts_i, ts_r)?);
        inner.ike_sa_init_request = Some(buf.to_vec());

        sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?;

        Ok(Box::new(state::IkeSaInitRequestSent {}))
    }
}
