use crate::{
    config::{Config, ConfigError},
    crypto,
    message::{
        Message, ProtectedMessage, Spi,
        num::{ExchangeType, MessageFlags, PayloadType},
        payload::{self, Payload},
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, ProtocolError},
    state::{self, SendProtectedMessage, State, StateData, StateDataCache, StateError},
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

pub struct IkeSaInitRequestSent;

impl SendProtectedMessage for IkeSaInitRequestSent {}

impl std::fmt::Display for IkeSaInitRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("IkeSaInitRequestSent").finish()
    }
}

fn handle_ike_sa_init_response(
    data: &mut StateDataCache<'_>,
    response: &Message,
) -> Result<(), StateError> {
    let sa: &payload::Sa = response
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let ke: &payload::Ke = response
        .get(PayloadType::KE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::KE))?;

    let nonce_r: &payload::Nonce = response
        .get(PayloadType::NONCE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::NONCE))?;

    let proposal = if let Some(proposal) = sa.proposals().next() {
        proposal
    } else {
        return Err(ProtocolError::NoProposalsReceived.into());
    };

    let chosen_proposal = ChosenProposal::new(proposal)?;

    let private_key = data.private_key.as_ref().as_ref().unwrap();
    if ke.dh_group().assigned() != Some(private_key.group().id()) {
        return Err(ProtocolError::InconsistentKeGroup(ke.dh_group()).into());
    }

    let nonce_i = data.nonce_i.as_ref().as_ref().unwrap();
    let skeyseed = crypto::generate_skeyseed(
        chosen_proposal.prf(),
        nonce_i,
        nonce_r.nonce(),
        private_key,
        ke.ke_data(),
    )?;
    debug!(skeyseed = ?&skeyseed, "SKEYSEED generated");

    let keys = chosen_proposal.generate_keys(
        &skeyseed,
        nonce_i,
        nonce_r.nonce(),
        response.spi_i(),
        response.spi_r(),
    )?;
    debug!(keys = ?&keys, "keys generated");

    *data.chosen_proposal.to_mut() = Some(chosen_proposal);
    *data.keys.to_mut() = Some(keys);
    *data.nonce_r.to_mut() = Some(nonce_r.nonce().to_vec());
    *data.peer_spi.to_mut() = Some(response.spi_r().to_owned());

    Ok(())
}

fn generate_ike_auth_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    spi_r: &Spi,
) -> Result<ProtectedMessage, StateError> {
    let mut request = Message::new(
        &data.spi,
        spi_r,
        ExchangeType::IKE_AUTH.into(),
        MessageFlags::I,
        data.message_id.wrapping_add(1),
    );

    let larval_child_sa = data.larval_child_sa.as_ref().as_ref().unwrap();
    let proposals = larval_child_sa.proposals.as_ref().unwrap();
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    let auth = if let Some(psk) = config.psk() {
        let prf = data.chosen_proposal()?.prf();
        let signed_data = data.auth_data_for_signing(config.id())?;
        Ok(payload::Auth::sign_with_psk(prf, psk, &signed_data)?)
    } else {
        Err(ConfigError::NoPSK)
    };
    let auth = auth?;

    request.add_payloads([
        Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(payload::Sa::new(proposals.clone())),
            true,
        ),
        Payload::new(
            PayloadType::IDi.into(),
            payload::Content::Id(config.id().clone()),
            true,
        ),
        Payload::new(PayloadType::AUTH.into(), payload::Content::Auth(auth), true),
        Payload::new(
            PayloadType::TSi.into(),
            payload::Content::Ts(payload::Ts::new(Some(
                larval_child_sa.ts_i.as_ref().unwrap().clone(),
            ))),
            true,
        ),
        Payload::new(
            PayloadType::TSr.into(),
            payload::Content::Ts(payload::Ts::new(Some(
                larval_child_sa.ts_r.as_ref().unwrap().clone(),
            ))),
            true,
        ),
    ]);

    let request = request.protect(
        data.chosen_proposal()?.cipher(),
        &data.keys()?.protecting.ei,
    )?;

    *data.message_id.to_mut() = request.id();

    Ok(request)
}

#[async_trait]
impl State for IkeSaInitRequestSent {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>, StateError> {
        let serialized_response = message;
        let response = Message::deserialize(&mut message)?;
        match response.exchange().assigned() {
            Some(ExchangeType::IKE_SA_INIT) => {
                let default = StateData::default();
                let default = StateDataCache::new_borrowed(&default);

                let cache = {
                    let data = data.read().await;
                    let mut data = StateDataCache::new_borrowed(&data);

                    handle_ike_sa_init_response(&mut data, &response)?;
                    *data.ike_sa_init_response.to_mut() = Some(serialized_response.to_vec());

                    let request = generate_ike_auth_request(config, &mut data, response.spi_r())?;
                    Self::send_message(sender.clone(), &mut data, request)?;
                    data.swap(&default)
                };

                {
                    let mut data = data.write().await;
                    cache.write_into(&mut data);
                }

                Ok(Box::new(state::IkeAuthRequestSent {}))
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
}
