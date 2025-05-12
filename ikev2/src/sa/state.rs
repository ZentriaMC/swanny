use crate::{
    config::Config,
    crypto::rand_bytes,
    message::{
        Message, SPI,
        num::{ExchangeType, MessageFlags, Num, PayloadType, Protocol},
        payload::{self, Payload},
        serialize::Serialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ControlMessage, IkeSaInner},
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc::UnboundedSender;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

#[async_trait]
pub(in crate::sa) trait State {
    async fn handle_message(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        data: &[u8],
    ) -> Result<Box<dyn State>>;

    async fn handle_acquire(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: usize,
    ) -> Result<Box<dyn State>>;
}

pub(in crate::sa) struct Initial {}

#[async_trait]
impl State for Initial {
    async fn handle_message(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        data: &[u8],
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }

    async fn handle_acquire(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: usize,
    ) -> Result<Box<dyn State>> {
        let inner = ike_sa.read().unwrap();

        let mut message = Message::new(
            &inner.spi,
            &SPI::default(),
            Num::Assigned(ExchangeType::IKE_SA_INIT),
            MessageFlags::I,
            inner.message_id,
        );
        let proposals: Result<Vec<_>> = inner
            .config
            .ike_proposals()
            .enumerate()
            .map(|(i, pb)| Ok(pb.build((i + 1).try_into()?, Protocol::IKE, &inner.spi)))
            .collect();
        message.add_payload(Payload::new(
            Num::Assigned(PayloadType::SA),
            payload::Content::SA(payload::SA::new(&proposals?)),
            true,
        ));

        let len = message.size()?;
        let mut buf = BytesMut::with_capacity(len);
        message.serialize(&mut buf)?;

        inner
            .sender
            .unbounded_send(ControlMessage::Ike(buf.to_vec()))?;

        let mut inner = ike_sa.write().unwrap();
        inner.initiator = true;

        Ok(Box::new(IkeSaInitRequestSent {}))
    }
}

pub(in crate::sa) struct IkeSaInitRequestSent {}

#[async_trait]
impl State for IkeSaInitRequestSent {
    async fn handle_message(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        data: &[u8],
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }

    async fn handle_acquire(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: usize,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}

pub(in crate::sa) struct IkeSaInitResponseSent {}

#[async_trait]
impl State for IkeSaInitResponseSent {
    async fn handle_message(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        data: &[u8],
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }

    async fn handle_acquire(
        self: Box<Self>,
        ike_sa: Arc<RwLock<IkeSaInner>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        index: usize,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}
