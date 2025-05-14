use crate::{
    config::Config,
    crypto::{self, Group, Prf},
    message::{
        Message, SPI,
        num::{ExchangeType, MessageFlags, Num, PayloadType, TransformType},
        payload,
        proposal::Proposal,
        traffic_selector::TrafficSelector,
        transform::TransformId,
    },
    sa::{ControlMessage, IkeSa},
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
        nonce: impl AsRef<[u8]>,
        proposals: &[Proposal],
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

        let proposal =
            IkeSa::choose_proposal(proposals.iter().map(|proposal| proposal), sa.proposals())
                .ok_or_else(|| anyhow::anyhow!("no matching proposal"))?;

        let transform = proposal
            .transforms()
            .find(|t| t.r#type() == Num::Assigned(TransformType::PRF))
            .ok_or_else(|| anyhow::anyhow!("PRF transform not found"))?;
        let prf_id = match transform.id() {
            Num::Assigned(TransformId::Prf(Num::Assigned(prf_id))) => prf_id,
            _ => return Err(anyhow::anyhow!("invalid PRF transform")),
        };
        let prf = Prf::new(prf_id)?;

        let n_i = nonce.as_ref();

        let nonce = response
            .payloads()
            .find(|payload| payload.r#type() == Num::Assigned(PayloadType::NONCE))
            .ok_or_else(|| anyhow::anyhow!("no NONCE payload"))?;
        let nonce: &payload::Nonce = nonce.try_into()?;
        let n_r = nonce.nonce();

        crypto::generate_skeyseed(&prf, n_i, n_r, &group, ke.ke_data())
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

                let request =
                    Self::generate_ike_auth_request(&inner.config, &inner.spi, message.spi_r())?;

                let skeyseed = Self::generate_skeyseed(
                    message,
                    inner.group.as_ref().unwrap(),
                    inner.nonce.as_ref().unwrap(),
                    inner.proposals.as_ref().unwrap(),
                )?;
                eprintln!("SKEYSEED generated: {:?}", &skeyseed);

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
