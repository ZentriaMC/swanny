use crate::{
    config::Config,
    message::{
        self, Message,
        num::{ExchangeType, Num, PayloadType},
        payload,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::ControlMessage,
    state::{self, State, StateData},
};
use anyhow::Result;
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) struct IkeAuthRequestSent {}

impl IkeAuthRequestSent {
    fn handle_ike_auth_response<D>(config: &Config, data: &D, response: &Message) -> Result<()>
    where
        D: Deref<Target = StateData>,
    {
        let last = response
            .payloads()
            .last()
            .ok_or_else(|| anyhow::anyhow!("no payload"))?;
        if last.ty() != Num::Assigned(PayloadType::SK) {
            return Err(anyhow::anyhow!("no SK payload"));
        }
        let sk: &payload::Sk = last.try_into()?;

        let payloads = sk.decrypt(
            data.chosen_proposal.as_ref().unwrap().cipher(),
            &data.keys.as_ref().unwrap().protecting.er,
        )?;

        let auth = payloads
            .iter()
            .find(|payload| payload.ty() == Num::Assigned(PayloadType::AUTH))
            .ok_or_else(|| anyhow::anyhow!("no AUTH payload"))?;
        let auth: &payload::Auth = auth.try_into()?;

        let id_r = payloads
            .iter()
            .find(|payload| payload.ty() == Num::Assigned(PayloadType::IDr))
            .ok_or_else(|| anyhow::anyhow!("no IDr payload"))?;
        let id_r: &payload::Id = id_r.try_into()?;

        data.verify(config, id_r, auth)?;

        Ok(())
    }
}

#[async_trait]
impl State for IkeAuthRequestSent {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        _sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>> {
        let response = Message::deserialize(&mut message)?;
        match response.exchange() {
            Num::Assigned(ExchangeType::IKE_AUTH) => {
                {
                    let data = data.read().await;
                    Self::handle_ike_auth_response(config, &data, &response)?;
                }
                Ok(Box::new(state::Established {}))
            }
            exchange => {
                return Err(anyhow::anyhow!("unknown exchange {:?}", exchange));
            }
        }
    }

    async fn handle_acquire(
        self: Box<Self>,
        _config: &Config,
        _sender: UnboundedSender<ControlMessage>,
        _data: Arc<RwLock<StateData>>,
        _ts_i: &TrafficSelector,
        _ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}
