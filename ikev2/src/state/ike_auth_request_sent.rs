use crate::{
    config::Config,
    message::{
        ProtectedMessage,
        num::{ExchangeType, PayloadType},
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
use tracing::{debug, info};

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
        response: &ProtectedMessage,
    ) -> Result<ChosenProposal>
    where
        D: Deref<Target = StateData>,
    {
        let keys = data.keys.as_ref().unwrap();

        let response = response.unprotect(data.chosen_proposal()?.cipher(), &keys.protecting.er)?;

        debug!(response = ?&response, "unprotected response");

        let auth: &payload::Auth = response
            .get(PayloadType::AUTH)
            .ok_or_else(|| anyhow::anyhow!("no AUTH payload"))?;

        let id_r: &payload::Id = response
            .get(PayloadType::IDr)
            .ok_or_else(|| anyhow::anyhow!("no IDr payload"))?;

        let sa: &payload::Sa = response
            .get(PayloadType::SA)
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;

        let authenticated = if let Some(psk) = config.psk() {
            let prf = data.chosen_proposal()?.prf();
            let signed_data = data.auth_data_for_verification(id_r)?;
            Ok(auth.verify_with_psk(prf, psk, &signed_data)?)
        } else {
            Err(anyhow::anyhow!("PSK not set"))
        };

        if authenticated? {
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

        ChosenProposal::negotiate(proposals, sa.proposals())
            .ok_or_else(|| anyhow::anyhow!("no matching proposal"))
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
        larval_child_sa.build(
            chosen_proposal,
            &keys.deriving.d,
            data.nonce_i.as_ref().unwrap(),
            data.nonce_r.as_ref().unwrap(),
        )
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
        let serialized_response = message;
        let response = ProtectedMessage::deserialize(&mut message)?;
        match response.exchange().assigned() {
            Some(ExchangeType::IKE_AUTH) => {
                {
                    let data = data.read().await;
                    if data.message_verify(serialized_response)? {
                        debug!("checksum verified");
                    } else {
                        return Err(anyhow::anyhow!("checksum mismatch"));
                    }
                }
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

                debug!(child_sa = ?&child_sa, "Child SA created");

                sender.unbounded_send(ControlMessage::CreateChildSa(Box::new(child_sa)))?;
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
