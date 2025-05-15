use crate::{
    config::Config,
    crypto::{self, GroupPrivateKey},
    message::{
        Message, SPI,
        num::{ExchangeType, MessageFlags, Num, PayloadType},
        payload::{self, Payload},
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ChosenProposal, ControlMessage, IkeSa},
    state::{self, State, StateData},
};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) struct Initial {}

impl Initial {
    fn generate_ike_sa_init_request(
        config: &Config,
        spi: &SPI,
    ) -> Result<(Message, ChosenProposal, GroupPrivateKey, Vec<u8>)> {
        let mut message = Message::new(
            spi,
            &SPI::default(),
            Num::Assigned(ExchangeType::IKE_SA_INIT),
            MessageFlags::I,
            1,
        );

        let proposals: Vec<_> = config.ike_proposals(spi).collect();

        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::SA),
            payload::Content::SA(payload::SA::new(&proposals)),
            true,
        ));

        let mut nonce = vec![0u8; 32];
        crypto::rand_bytes(&mut nonce[..])?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::NONCE),
            payload::Content::Nonce(payload::Nonce::new(&nonce[..])),
            true,
        ));

        if proposals.is_empty() {
            return Err(anyhow::anyhow!("no proposal"));
        }

        let chosen_proposal = ChosenProposal::new(&proposals[0])?;
        let private_key = chosen_proposal.group().generate_key()?;
        let public_key = private_key.public_key()?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::KE),
            payload::Content::KE(payload::KE::new(
                Num::Assigned(chosen_proposal.group().id()),
                &public_key,
            )),
            true,
        ));

        Ok((message, chosen_proposal, private_key, nonce))
    }

    fn generate_ike_sa_init_response(
        config: &Config,
        spi: &SPI,
        request: &Message,
    ) -> Result<(Message, ChosenProposal, GroupPrivateKey, Vec<u8>)> {
        let mut message = Message::new(
            request.spi_i(),
            spi,
            Num::Assigned(ExchangeType::IKE_SA_INIT),
            MessageFlags::R,
            request.id(),
        );
        let proposals: Vec<_> = config.ike_proposals(request.spi_i()).collect();

        let sa = request
            .payloads()
            .find(|payload| payload.ty() == Num::Assigned(PayloadType::SA))
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;
        let sa: &payload::SA = sa.try_into()?;

        let ke = request
            .payloads()
            .find(|payload| payload.ty() == Num::Assigned(PayloadType::KE))
            .ok_or_else(|| anyhow::anyhow!("no KE payload"))?;
        let ke: &payload::KE = ke.try_into()?;

        let nonce = request
            .payloads()
            .find(|payload| payload.ty() == Num::Assigned(PayloadType::NONCE))
            .ok_or_else(|| anyhow::anyhow!("no NONCE payload"))?;
        let nonce: &payload::Nonce = nonce.try_into()?;

        let proposal =
            IkeSa::choose_proposal(proposals.iter().map(|proposal| proposal), sa.proposals())
                .ok_or_else(|| anyhow::anyhow!("no matching proposal"))?;

        let chosen_proposal = ChosenProposal::new(&proposal)?;
        let private_key = chosen_proposal.group().generate_key()?;
        let public_key = private_key.public_key()?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::KE),
            payload::Content::KE(payload::KE::new(
                Num::Assigned(chosen_proposal.group().id()),
                &public_key,
            )),
            true,
        ));

        let n_i = nonce.nonce();
        let mut n_r = [0u8; 32];
        crypto::rand_bytes(&mut n_r[..])?;

        let skeyseed = crypto::generate_skeyseed(
            chosen_proposal.prf(),
            n_i,
            &n_r[..],
            &private_key,
            ke.ke_data(),
        )?;
        eprintln!("SKEYSEED generated: {:?}", &skeyseed);

        let keys = chosen_proposal.generate_keys(&skeyseed, n_i, &n_r[..], request.spi_i(), spi)?;

        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::SA),
            payload::Content::SA(payload::SA::new(&[proposal])),
            true,
        ));

        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::NONCE),
            payload::Content::Nonce(payload::Nonce::new(&n_r[..])),
            true,
        ));

        Ok((message, chosen_proposal, private_key, n_r.to_vec()))
    }
}

#[async_trait]
impl State for Initial {
    async fn handle_message(
        self: Box<Self>,
        data: Arc<RwLock<StateData>>,
        message: &Message,
    ) -> Result<Box<dyn State>> {
        match message.exchange() {
            Num::Assigned(ExchangeType::IKE_SA_INIT) => {
                let inner = data.read().await;

                let (message, chosen_proposal, private_key, nonce) =
                    Self::generate_ike_sa_init_response(&inner.config, &inner.spi, message)?;
                inner
                    .sender
                    .unbounded_send(ControlMessage::IkeMessage(message))?;
                drop(inner);

                let mut inner = data.write().await;
                inner.initiator = Some(false);
                inner.chosen_proposal = Some(chosen_proposal);
                inner.private_key = Some(private_key);
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
        data: Arc<RwLock<StateData>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        let inner = data.read().await;

        let (message, chosen_proposal, private_key, nonce) =
            Self::generate_ike_sa_init_request(&inner.config, &inner.spi)?;
        let message_id = message.id();

        inner
            .sender
            .unbounded_send(ControlMessage::IkeMessage(message))?;
        drop(inner);

        let mut inner = data.write().await;
        inner.initiator = Some(true);
        inner.chosen_proposal = Some(chosen_proposal);
        inner.private_key = Some(private_key);
        inner.nonce = Some(nonce);
        inner.message_id = message_id;
        inner.larval_sa = Some(ChildSa::new(ts_i, ts_r));
        drop(inner);

        Ok(Box::new(state::IkeSaInitRequestSent {}))
    }
}
