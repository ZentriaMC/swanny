use crate::{
    message::{
        Message,
        num::{Num, PayloadType},
        payload,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    state::{State, StateData},
};
use anyhow::Result;
use async_trait::async_trait;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) struct IkeSaInitResponseSent {}

impl IkeSaInitResponseSent {
    fn handle_ike_auth_request<D>(data: &D, request: &Message) -> Result<()>
    where
        D: Deref<Target = StateData>,
    {
        let last = request
            .payloads()
            .last()
            .ok_or_else(|| anyhow::anyhow!("no payload"))?;
        if last.ty() != Num::Assigned(PayloadType::SK) {
            return Err(anyhow::anyhow!("no SK payload"));
        }
        let sk: &payload::Sk = last.try_into()?;
        let payloads = sk.decrypt(
            data.chosen_proposal.as_ref().unwrap().cipher(),
            &data.keys.as_ref().unwrap().ei,
        )?;
        eprintln!("{:?}", &payloads);
        Ok(())
    }
}

#[async_trait]
impl State for IkeSaInitResponseSent {
    async fn handle_message(
        self: Box<Self>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>> {
        let message = Message::deserialize(&mut message)?;
        let inner = data.read().await;
        Self::handle_ike_auth_request(&inner, &message)?;
        Ok(self)
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
