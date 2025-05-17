use crate::{
    config::Config,
    crypto::{self, GroupPrivateKey},
    message::{
        Message, Spi,
        num::{ExchangeType, MessageFlags, Num, PayloadType},
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

    fn generate_ike_sa_init_response(
        config: &Config,
        spi: &Spi,
        request: &Message,
    ) -> Result<(Message, ChosenProposal, Keys, Vec<u8>)> {
        let sa_i: &payload::Sa = request
            .get(PayloadType::SA)
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;

        let ke_i: &payload::Ke = request
            .get(PayloadType::KE)
            .ok_or_else(|| anyhow::anyhow!("no KE payload"))?;

        let nonce_i: &payload::Nonce = request
            .get(PayloadType::NONCE)
            .ok_or_else(|| anyhow::anyhow!("no NONCE payload"))?;

        let proposals: Vec<_> = config.ike_proposals(request.spi_i()).collect();
        if proposals.is_empty() {
            return Err(anyhow::anyhow!("no proposal to send"));
        }

        let proposal = IkeSa::choose_proposal(&proposals, sa_i.proposals())
            .ok_or_else(|| anyhow::anyhow!("no matching proposal"))?;

        let chosen_proposal = ChosenProposal::new(&proposal)?;
        let private_key = chosen_proposal.group().generate_key()?;
        let public_key = private_key.public_key()?;

        let mut nonce_r = [0u8; 32];
        crypto::rand_bytes(&mut nonce_r[..])?;

        let skeyseed = crypto::generate_skeyseed(
            chosen_proposal.prf(),
            nonce_i.nonce(),
            &nonce_r[..],
            &private_key,
            ke_i.ke_data(),
        )?;
        eprintln!("SKEYSEED generated: {:?}", &skeyseed);

        let keys = chosen_proposal.generate_keys(
            &skeyseed,
            nonce_i.nonce(),
            &nonce_r[..],
            request.spi_i(),
            spi,
        )?;
        eprintln!("Keys generated: {:?}", &keys);

        let mut message = Message::new(
            request.spi_i(),
            spi,
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
                payload::Content::Sa(payload::Sa::new([proposal])),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::NONCE),
                payload::Content::Nonce(payload::Nonce::new(&nonce_r[..])),
                true,
            ),
        ]);

        Ok((message, chosen_proposal, keys, nonce_r.to_vec()))
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
        let message = Message::deserialize(&mut message)?;
        match message.exchange() {
            Num::Assigned(ExchangeType::IKE_SA_INIT) => {
                let inner = data.read().await;

                let (response, chosen_proposal, keys, nonce) =
                    Self::generate_ike_sa_init_response(config, &inner.spi, &message)?;
                let len = response.size()?;
                let mut buf = BytesMut::with_capacity(len);
                response.serialize(&mut buf)?;
                sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?;
                drop(inner);

                let mut inner = data.write().await;
                inner.initiator = Some(false);
                inner.chosen_proposal = Some(chosen_proposal);
                inner.keys = Some(keys);
                inner.nonce = Some(nonce);
                drop(inner);

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

        let len = request.size()?;
        let mut buf = BytesMut::with_capacity(len);
        request.serialize(&mut buf)?;
        sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?;
        drop(inner);

        let mut inner = data.write().await;
        inner.initiator = Some(true);
        inner.chosen_proposal = Some(chosen_proposal);
        inner.private_key = Some(private_key);
        inner.nonce = Some(nonce);
        inner.message_id = message_id;
        inner.larval_child_sa = Some(ChildSa::new(ts_i, ts_r)?);

        Ok(Box::new(state::IkeSaInitRequestSent {}))
    }
}
