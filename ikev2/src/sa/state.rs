use crate::{
    config::Config,
    crypto::{Group, Prf, rand_bytes},
    message::{
        Message, SPI,
        num::{ExchangeType, MessageFlags, Num, PayloadType, Protocol, TransformType},
        payload::{self, Payload},
        proposal::Proposal,
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

fn generate_skeyseed(
    prf: &Prf,
    n_i: impl AsRef<[u8]>,
    n_r: impl AsRef<[u8]>,
    group: &Group,
    peer_public_key: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let g_ir = group.compute_key(peer_public_key)?;
    let mut n_i_n_r = n_i.as_ref().to_vec();
    n_i_n_r.extend_from_slice(n_r.as_ref());
    prf.prf(n_i_n_r, g_ir)
}

pub(in crate::sa) struct Initial {}

impl Initial {
    fn generate_ike_sa_init_request(config: &Config, spi: &SPI) -> Result<(Message, Group, Vec<u8>, Vec<Proposal>)> {
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

        let mut nonce = vec![0u8; 32];
        rand_bytes(&mut nonce[..])?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::NONCE),
            payload::Content::Nonce(payload::Nonce::new(&nonce[..])),
            true,
        ));

        let proposal = proposals
            .iter()
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

        Ok((message, group, nonce, proposals))
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
        let sa: &payload::SA = sa.try_into()?;

        let ke = request
            .payloads()
            .find(|payload| payload.r#type() == Num::Assigned(PayloadType::KE))
            .ok_or_else(|| anyhow::anyhow!("no KE payload"))?;
        let ke: &payload::KE = ke.try_into()?;

        let nonce = request
            .payloads()
            .find(|payload| payload.r#type() == Num::Assigned(PayloadType::NONCE))
            .ok_or_else(|| anyhow::anyhow!("no NONCE payload"))?;
        let nonce: &payload::Nonce = nonce.try_into()?;
        let n_i = nonce.nonce();

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

        let group = Group::new(dh_id)?;
        let public_key = group.public_key()?;
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::KE),
            payload::Content::KE(payload::KE::new(Num::Assigned(dh_id), &public_key)),
            true,
        ));

        let transform = proposal
            .transforms()
            .find(|t| t.r#type() == Num::Assigned(TransformType::PRF))
            .ok_or_else(|| anyhow::anyhow!("PRF transform not found"))?;
        let prf_id = match transform.id() {
            Num::Assigned(TransformId::Prf(Num::Assigned(prf_id))) => prf_id,
            _ => return Err(anyhow::anyhow!("invalid PRF transform")),
        };
        let prf = Prf::new(prf_id)?;

        let mut nonce = [0u8; 32];
        rand_bytes(&mut nonce[..])?;

        let skeyseed = generate_skeyseed(&prf, n_i, &nonce[..], &group, ke.ke_data())?;
        eprintln!("SKEYSEED generated: {:?}", &skeyseed);

        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::SA),
            payload::Content::SA(payload::SA::new(&[proposal])),
            true,
        ));

        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::NONCE),
            payload::Content::Nonce(payload::Nonce::new(&nonce[..])),
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

        let (message, group, nonce, proposals) = Self::generate_ike_sa_init_request(&inner.config, &inner.spi)?;
        let message_id = message.id();

        inner
            .sender
            .unbounded_send(ControlMessage::IkeMessage(message))?;
        drop(inner);

        let mut inner = ike_sa.write().await;
        inner.initiator = Some(true);
        inner.group = Some(group);
        inner.nonce = Some(nonce);
        inner.proposals = Some(proposals);
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
    fn generate_skeyseed(
        config: &Config,
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

        generate_skeyseed(&prf, n_i, n_r, &group, ke.ke_data())
    }

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

                let request = Self::generate_ike_auth_request(&inner.config, &inner.spi, message.spi_r())?;

                let skeyseed = Self::generate_skeyseed(&inner.config, message, inner.group.as_ref().unwrap(), inner.nonce.as_ref().unwrap(), inner.proposals.as_ref().unwrap())?;
                eprintln!("SKEYSEED generated: {:?}", &skeyseed);

                inner
                    .sender
                    .unbounded_send(ControlMessage::IkeMessage(request))?;
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
