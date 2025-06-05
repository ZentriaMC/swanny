use crate::{
    config::{Config, ConfigError},
    message::{
        EspSpi, ProtectedMessage,
        num::{ExchangeType, PayloadType},
        payload,
        proposal::Proposal,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, ProtocolError},
    state::{
        self, CreateChildSa, InvalidStateError, State, StateData, StateDataCache, StateError,
        VerifyMessage,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct IkeAuthRequestSent;

impl CreateChildSa for IkeAuthRequestSent {}
impl VerifyMessage for IkeAuthRequestSent {}

impl std::fmt::Display for IkeAuthRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("IkeAuthRequestSent").finish()
    }
}

fn handle_ike_auth_response(
    config: &Config,
    data: &mut StateDataCache<'_>,
    response: &ProtectedMessage,
) -> Result<(), StateError> {
    let response = response
        .unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(|e| StateError::Protocol(e.into()))?;

    debug!(response = ?&response, "received protected response");

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
        let prf = data.chosen_proposal()?.prf().expect("PRF must be set");
        let signed_data = data.auth_data_for_verification(id_r)?;
        Ok(auth.verify_with_psk(prf, psk, &signed_data)?)
    } else {
        Err(ConfigError::NoPSK)
    };

    if authenticated? {
        info!(spi = &data.responder_spi()?[..], "authenticated responder");
    } else {
        return Err(ProtocolError::AuthenticationFailed.into());
    }

    let larval_child_sa = data
        .larval_child_sa
        .to_mut()
        .take()
        .ok_or(InvalidStateError::LarvalChildSaNotSet)?;

    let proposal = Proposal::negotiate(&larval_child_sa.proposals, sa.proposals())
        .ok_or(ProtocolError::NoProposalChosen)?;
    info!(proposal = ?&proposal, "negotiated proposal");
    let chosen_proposal = ChosenProposal::new(&proposal)?;

    let child_sa = larval_child_sa.build(
        &chosen_proposal,
        &data.keys()?.derivation.d,
        (*data.nonce_i)
            .as_ref()
            .ok_or(InvalidStateError::NonceNotRecorded)?,
        (*data.nonce_r)
            .as_ref()
            .ok_or(InvalidStateError::NonceNotRecorded)?,
    )?;

    *data.created_child_sa.to_mut() = Some(Box::new(child_sa));

    Ok(())
}

impl IkeAuthRequestSent {
    async fn handle_response(
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        mut message: &[u8],
    ) -> Result<(), StateError> {
        let serialized_response = message;
        let response = ProtectedMessage::deserialize(&mut message)
            .map_err(|e| StateError::Protocol(e.into()))?;

        Self::verify_message(data, serialized_response)?;

        match response.exchange().assigned() {
            Some(ExchangeType::IKE_AUTH) => {
                handle_ike_auth_response(config, data, &response)?;

                if let Some(child_sa) = data.created_child_sa.to_mut().take() {
                    Self::create_child_sa(sender.clone(), data, child_sa)?;
                }
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
            }
        }

        Ok(())
    }
}

#[async_trait]
impl State for IkeAuthRequestSent {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        message: &[u8],
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let (next_state, cache): (Box<dyn State>, _) = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            if let Err(e) = Self::handle_response(config, sender.clone(), &mut data, message).await
            {
                debug!(error = %e, "error processing IKE_AUTH response");
                (Box::new(state::Initial {}), default.into_owned())
            } else {
                (Box::new(state::Established {}), data.swap(&default))
            }
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(next_state)
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
        _hard: bool,
    ) -> Result<Box<dyn State>, StateError> {
        Ok(self)
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send) {
        self
    }
}
