use crate::{
    config::Config,
    crypto::{self, Group},
    message::{
        Message, SPI,
        num::{ExchangeType, MessageFlags, Num, PayloadType},
        payload,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage},
    state::{self, State, StateData},
};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) struct IkeSaInitRequestSent {}

impl IkeSaInitRequestSent {
    fn generate_skeyseed(
        response: &Message,
        group: &Group,
        n_i: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>> {
        let sa = response
            .payloads()
            .find(|payload| payload.r#type() == Num::Assigned(PayloadType::SA))
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;
        let sa: &payload::SA = sa.try_into()?;

        let ke = response
            .payloads()
            .find(|payload| payload.r#type() == Num::Assigned(PayloadType::KE))
            .ok_or_else(|| anyhow::anyhow!("no KE payload"))?;
        let ke: &payload::KE = ke.try_into()?;

        let nonce = response
            .payloads()
            .find(|payload| payload.r#type() == Num::Assigned(PayloadType::NONCE))
            .ok_or_else(|| anyhow::anyhow!("no NONCE payload"))?;
        let nonce: &payload::Nonce = nonce.try_into()?;

        if ke.dh_group() != Num::Assigned(group.id()) {
            return Err(anyhow::anyhow!("unmatched DH group"));
        }

        let proposal = sa
            .proposals()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no matching proposal"))?;

        let chosen_proposal = ChosenProposal::new(&proposal)?;
        let n_r = nonce.nonce();

        crypto::generate_skeyseed(
            chosen_proposal.prf(),
            n_i,
            n_r,
            chosen_proposal.group(),
            ke.ke_data(),
        )
    }

    fn generate_ike_auth_request(config: &Config, spi: &SPI, peer_spi: &SPI) -> Result<Message> {
        let message = Message::new(
            spi,
            peer_spi,
            Num::Assigned(ExchangeType::IKE_AUTH),
            MessageFlags::I,
            2,
        );

        Ok(message)
    }
}

#[async_trait]
impl State for IkeSaInitRequestSent {
    async fn handle_message(
        self: Box<Self>,
        data: Arc<RwLock<StateData>>,
        message: &Message,
    ) -> Result<Box<dyn State>> {
        match message.exchange() {
            Num::Assigned(ExchangeType::IKE_SA_INIT) => {
                let inner = data.read().await;

                let skeyseed = Self::generate_skeyseed(
                    message,
                    inner.chosen_proposal.as_ref().unwrap().group(),
                    inner.nonce.as_ref().unwrap(),
                )?;
                eprintln!("SKEYSEED generated: {:?}", &skeyseed);

                let request =
                    Self::generate_ike_auth_request(&inner.config, &inner.spi, message.spi_r())?;

                inner
                    .sender
                    .unbounded_send(ControlMessage::IkeMessage(request))?;
                drop(inner);

                let mut inner = data.write().await;
                inner.initiator = Some(false);
                drop(inner);

                Ok(Box::new(state::IkeAuthRequestSent {}))
            }
            exchange => {
                return Err(anyhow::anyhow!("unknown exchange {:?}", exchange));
            }
        }
    }

    async fn handle_acquire(
        self: Box<Self>,
        _data: Arc<RwLock<StateData>>,
        _ts_i: &TrafficSelector,
        _ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}
