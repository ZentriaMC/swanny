use crate::{
    config::Config,
    message::{
        Message,
        num::{ExchangeType, Num, PayloadType},
        payload,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ChosenProposal, ControlMessage, LarvalChildSa},
    state::{self, State, StateData},
};
use anyhow::Result;
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

pub struct IkeAuthRequestSent;

impl std::fmt::Display for IkeAuthRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("IkeAuthRequestSent").finish()
    }
}

impl IkeAuthRequestSent {
    fn handle_ike_auth_response<D>(
        config: &Config,
        data: &D,
        response: &Message,
    ) -> Result<ChosenProposal>
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

        let keys = data.keys.as_ref().unwrap();

        let payloads = sk.decrypt(
            data.chosen_proposal.as_ref().unwrap().cipher(),
            &keys.protecting.er,
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

        let sa_r = payloads
            .iter()
            .find(|payload| payload.ty() == Num::Assigned(PayloadType::SA))
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;
        let sa_r: &payload::Sa = sa_r.try_into()?;

        if data.verify(config, id_r, auth)? {
            info!(
                spi = &data.peer_spi.as_ref().unwrap()[..],
                "initiator authenticated responder"
            );
        } else {
            return Err(anyhow::anyhow!("authentication failed"));
        }

        let proposals = data
            .larval_child_sa
            .as_ref()
            .unwrap()
            .proposals
            .as_ref()
            .unwrap();

        Ok(ChosenProposal::negotiate(proposals, sa_r.proposals())
            .ok_or_else(|| anyhow::anyhow!("no matching proposal"))?)
    }

    fn create_child_sa<D>(
        data: &D,
        chosen_proposal: &ChosenProposal,
        larval_child_sa: LarvalChildSa,
    ) -> Result<ChildSa>
    where
        D: Deref<Target = StateData>,
    {
        let keys = data.keys.as_ref().unwrap();
        Ok(larval_child_sa.build(
            &chosen_proposal,
            &keys.deriving.d,
            &data.nonce_i.as_ref().unwrap(),
            &data.nonce_r.as_ref().unwrap(),
        )?)
    }
}

#[async_trait]
impl State for IkeAuthRequestSent {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>> {
        let response = Message::deserialize(&mut message)?;
        match response.exchange() {
            Num::Assigned(ExchangeType::IKE_AUTH) => {
                let chosen_proposal = {
                    let data = data.read().await;
                    Self::handle_ike_auth_response(config, &data, &response)?
                };
                let larval_child_sa = {
                    let mut data = data.write().await;
                    data.larval_child_sa.take().unwrap()
                };
                let child_sa = {
                    let data = data.read().await;
                    Self::create_child_sa(&data, &chosen_proposal, larval_child_sa)?
                };
                sender.unbounded_send(ControlMessage::CreateChildSa(child_sa))?;
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
