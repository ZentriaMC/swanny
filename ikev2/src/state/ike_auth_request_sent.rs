use crate::{
    config::{Config, ConfigError},
    message::{
        EspSpi, ProtectedMessage,
        num::{ExchangeType, PayloadType},
        payload,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ChosenProposal, ControlMessage, ProtocolError},
    state::{self, CreateChildSa, State, StateData, StateDataCache, StateError},
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct IkeAuthRequestSent;

impl CreateChildSa for IkeAuthRequestSent {}

impl std::fmt::Display for IkeAuthRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("IkeAuthRequestSent").finish()
    }
}

fn handle_ike_auth_response(
    config: &Config,
    data: &mut StateDataCache<'_>,
    response: &ProtectedMessage,
) -> Result<ChildSa, StateError> {
    let response = response.unprotect(data.chosen_proposal()?.cipher(), data.decrypting_key()?)?;

    debug!(response = ?&response, "unprotected response");

    let auth: &payload::Auth = response
        .get(PayloadType::AUTH)
        .ok_or(ProtocolError::MissingPayload(PayloadType::AUTH))?;

    let id_r: &payload::Id = response
        .get(PayloadType::IDr)
        .ok_or(ProtocolError::MissingPayload(PayloadType::IDr))?;

    let sa: &payload::Sa = response
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let authenticated = if let Some(psk) = config.psk() {
        let prf = data.chosen_proposal()?.prf();
        let signed_data = data.auth_data_for_verification(id_r)?;
        Ok(auth.verify_with_psk(prf, psk, &signed_data)?)
    } else {
        Err(ConfigError::NoPSK)
    };

    if authenticated? {
        info!(
            spi = &data.peer_spi.as_ref().unwrap()[..],
            "initiator authenticated responder"
        );
    } else {
        return Err(ProtocolError::AuthenticationFailed.into());
    }

    let proposals = &(*data.larval_child_sa).as_ref().unwrap().proposals;

    let chosen_proposal = ChosenProposal::negotiate(proposals, sa.proposals())?;

    let larval_child_sa = data.larval_child_sa.to_mut().take().unwrap();
    larval_child_sa
        .build(
            &chosen_proposal,
            &data.keys()?.deriving.d,
            (*data.nonce_i).as_ref().unwrap(),
            (*data.nonce_r).as_ref().unwrap(),
        )
        .map_err(Into::into)
}

#[async_trait]
impl State for IkeAuthRequestSent {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>, StateError> {
        let serialized_response = message;
        let response = ProtectedMessage::deserialize(&mut message)?;
        match response.exchange().assigned() {
            Some(ExchangeType::IKE_AUTH) => {
                let default = StateData::default();
                let default = StateDataCache::new_borrowed(&default);

                let cache = {
                    let data = data.read().await;
                    let mut data = StateDataCache::new_borrowed(&data);

                    if data.message_verify(serialized_response)? {
                        debug!("checksum verified");
                    } else {
                        return Err(ProtocolError::IntegrityCheckFailed.into());
                    }

                    let child_sa = handle_ike_auth_response(config, &mut data, &response)?;
                    Self::create_child_sa(sender.clone(), &mut data, Box::new(child_sa))?;
                    data.swap(&default)
                };

                {
                    let mut data = data.write().await;
                    cache.write_into(&mut data);
                }

                Ok(Box::new(state::Established {}))
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
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
    ) -> Result<Box<dyn State>, StateError> {
        Ok(self)
    }

    async fn handle_expire(
        self: Box<Self>,
        _config: &Config,
        _sender: UnboundedSender<ControlMessage>,
        _data: Arc<RwLock<StateData>>,
        _spi: &EspSpi,
    ) -> Result<Box<dyn State>, StateError> {
        Ok(self)
    }
}
