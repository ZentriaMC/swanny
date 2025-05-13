use crate::{
    config::Config,
    crypto::{Group, rand_bytes},
    message::{
        Message, SPI,
        num::{ExchangeType, MessageFlags, Num, PayloadType, Protocol, TransformType},
        payload::{self, Payload},
        traffic_selector::TrafficSelector,
        transform::TransformId,
    },
    sa::{ChildSa, ControlMessage, IkeSa, IkeSaInner},
};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub(in crate::sa) trait State: Send + Sync {
    async fn handle_message(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        message: &Message,
    ) -> Result<Box<dyn State>>;

    async fn handle_acquire(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: u32,
    ) -> Result<Box<dyn State>>;
}

pub(in crate::sa) struct Initial {}

impl Initial {
    fn generate_ike_sa_init_request(config: &Config, spi: &SPI) -> Result<(Message, Group)> {
        let mut message = Message::new(
            spi,
            &SPI::default(),
            Num::Assigned(ExchangeType::IKE_SA_INIT),
            MessageFlags::I,
            1,
        );

        let proposals: Result<Vec<_>> = config
            .ike_proposals()
            .enumerate()
            .map(|(i, pb)| Ok(pb.build((i + 1).try_into()?, Protocol::IKE, spi)))
            .collect();
        let proposals = proposals?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::SA),
            payload::Content::SA(payload::SA::new(&proposals)),
            true,
        ));

        let mut nonce = [0u8; 32];
        rand_bytes(&mut nonce[..])?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::NONCE),
            payload::Content::Nonce(payload::Nonce::new(&nonce[..])),
            true,
        ));

        let proposal = proposals
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no proposal"))?;
        let transform = proposal
            .transforms()
            .find(|t| t.r#type() == Num::Assigned(TransformType::DH))
            .ok_or_else(|| anyhow::anyhow!("DH transform not found"))?;
        let dh_id = match transform.id() {
            Num::Assigned(TransformId::Dh(Num::Assigned(dh_id))) => dh_id,
            _ => return Err(anyhow::anyhow!("invalid DH transform")),
        };
        let group = Group::new(dh_id)?;
        let public_key = group.public_key()?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::KE),
            payload::Content::KE(payload::KE::new(Num::Assigned(dh_id), &public_key)),
            true,
        ));

        Ok((message, group))
    }

    fn generate_ike_sa_init_response(
        config: &Config,
        spi: &SPI,
        request: &Message,
    ) -> Result<Message> {
        let mut message = Message::new(
            request.spi_i(),
            spi,
            Num::Assigned(ExchangeType::IKE_SA_INIT),
            MessageFlags::R,
            request.id(),
        );
        let proposals: Result<Vec<_>> = config
            .ike_proposals()
            .enumerate()
            .map(|(i, pb)| Ok(pb.build((i + 1).try_into()?, Protocol::IKE, spi)))
            .collect();

        let proposals = proposals?;
        let sa = request
            .payloads()
            .find(|payload| payload.r#type() == Num::Assigned(PayloadType::SA))
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;
        let sa = match sa.content() {
            payload::Content::SA(sa) => sa,
            _ => return Err(anyhow::anyhow!("no matching SA content")),
        };

        let proposal =
            IkeSa::choose_proposal(proposals.iter().map(|proposal| proposal), sa.proposals())
                .ok_or_else(|| anyhow::anyhow!("no matching proposal"))?;
        let transform = proposal
            .transforms()
            .find(|t| t.r#type() == Num::Assigned(TransformType::DH))
            .ok_or_else(|| anyhow::anyhow!("DH transform not found"))?;
        let dh_id = match transform.id() {
            Num::Assigned(TransformId::Dh(Num::Assigned(dh_id))) => dh_id,
            _ => return Err(anyhow::anyhow!("invalid DH transform")),
        };

        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::SA),
            payload::Content::SA(payload::SA::new(&[proposal])),
            true,
        ));

        let mut nonce = [0u8; 32];
        rand_bytes(&mut nonce[..])?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::NONCE),
            payload::Content::Nonce(payload::Nonce::new(&nonce[..])),
            true,
        ));

        let group = Group::new(dh_id)?;
        let public_key = group.public_key()?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::KE),
            payload::Content::KE(payload::KE::new(Num::Assigned(dh_id), &public_key)),
            true,
        ));

        Ok(message)
    }
}

#[async_trait]
impl State for Initial {
    async fn handle_message(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        message: &Message,
    ) -> Result<Box<dyn State>> {
        match message.exchange() {
            Num::Assigned(ExchangeType::IKE_SA_INIT) => {
                let inner = ike_sa.read().await;

                let message =
                    Self::generate_ike_sa_init_response(&inner.config, &inner.spi, message)?;
                inner
                    .sender
                    .unbounded_send(ControlMessage::IkeMessage(message))?;
                drop(inner);

                let mut inner = ike_sa.write().await;
                inner.initiator = Some(false);
                drop(inner);

                Ok(Box::new(IkeSaInitResponseSent {}))
            }
            exchange => {
                return Err(anyhow::anyhow!("unknown exchange {:?}", exchange));
            }
        }
    }

    async fn handle_acquire(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        let inner = ike_sa.read().await;

        let (message, group) = Self::generate_ike_sa_init_request(&inner.config, &inner.spi)?;
        let message_id = message.id();

        inner
            .sender
            .unbounded_send(ControlMessage::IkeMessage(message))?;
        drop(inner);

        let mut inner = ike_sa.write().await;
        inner.initiator = Some(true);
        inner.group = Some(group);
        inner.message_id = message_id;
        inner.larval_sa = Some(ChildSa {
            ts_i: ts_i.to_owned(),
            ts_r: ts_r.to_owned(),
        });
        drop(inner);

        Ok(Box::new(IkeSaInitRequestSent {}))
    }
}

pub(in crate::sa) struct IkeSaInitRequestSent {}

impl IkeSaInitRequestSent {
    fn generate_ike_auth_request(
        config: &Config,
        spi: &SPI,
        peer_spi: &SPI,
    ) -> Result<Message> {
        let mut message = Message::new(
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
        ike_sa: Arc<RwLock<IkeSaInner>>,
        message: &Message,
    ) -> Result<Box<dyn State>> {
        match message.exchange() {
            Num::Assigned(ExchangeType::IKE_SA_INIT) => {
                let inner = ike_sa.read().await;

                let message = Self::generate_ike_auth_request(&inner.config, &inner.spi, message.spi_r())?;

                inner
                    .sender
                    .unbounded_send(ControlMessage::IkeMessage(message))?;
                drop(inner);

                let mut inner = ike_sa.write().await;
                inner.initiator = Some(false);
                drop(inner);

                Ok(Box::new(IkeAuthRequestSent {}))
            }
            exchange => {
                return Err(anyhow::anyhow!("unknown exchange {:?}", exchange));
            }
        }
    }

    async fn handle_acquire(
        self: Box<Self>,
        _ike_sa: Arc<RwLock<IkeSaInner>>,
        _ts_i: &TrafficSelector,
        _ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}

pub(in crate::sa) struct IkeSaInitResponseSent {}

#[async_trait]
impl State for IkeSaInitResponseSent {
    async fn handle_message(
        self: Box<Self>,
        _ike_sa: Arc<RwLock<IkeSaInner>>,
        _message: &Message,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }

    async fn handle_acquire(
        self: Box<Self>,
        _ike_sa: Arc<RwLock<IkeSaInner>>,
        _ts_i: &TrafficSelector,
        _ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}

pub(in crate::sa) struct IkeAuthRequestSent {}

#[async_trait]
impl State for IkeAuthRequestSent {
    async fn handle_message(
        self: Box<Self>,
        _ike_sa: Arc<RwLock<IkeSaInner>>,
        _message: &Message,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }

    async fn handle_acquire(
        self: Box<Self>,
        _ike_sa: Arc<RwLock<IkeSaInner>>,
        _ts_i: &TrafficSelector,
        _ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}
