use crate::{
    config::{Config, ConfigError},
    message::{
        EspSpi, Message, ProtectedMessage, Spi,
        num::{ExchangeType, MessageFlags, NotifyType, PayloadType, Protocol},
        payload::{self, Payload},
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, ProtocolError},
    state::{
        self, InvalidStateError, SendProtectedMessage, State, StateData, StateDataCache, StateError,
    },
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

    let private_key = data
        .private_key
        .as_ref()
        .as_ref()
        .ok_or(InvalidStateError::GroupPrivateKeyNotSet)?;
    if ke.dh_group().assigned() != Some(private_key.group().id()) {
        return Err(ProtocolError::InconsistentKeGroup(ke.dh_group()).into());
    }

    let nonce_i = data
        .nonce_i
        .as_ref()
        .as_ref()
        .ok_or(InvalidStateError::NonceNotRecorded)?;
    let skeyseed =
        chosen_proposal.generate_skeyseed(nonce_i, nonce_r.nonce(), private_key, ke.ke_data())?;
    debug!(skeyseed = ?&skeyseed, "generated SKEYSEED");

    let keys = chosen_proposal.generate_keys(
        &skeyseed,
        nonce_i,
        nonce_r.nonce(),
        response.spi_i(),
        response.spi_r(),
    )?;
    debug!(keys = ?&keys, "generated keys");

    *data.chosen_proposal.to_mut() = Some(chosen_proposal);
    *data.keys.to_mut() = Some(keys);
    *data.nonce_r.to_mut() = Some(nonce_r.nonce().clone());
    *data.peer_spi.to_mut() = Some(response.spi_r().to_owned());
    *data.last_request.to_mut() = None;

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
        *data.message_id,
    );

    let larval_child_sa = data
        .larval_child_sa
        .as_ref()
        .as_ref()
        .ok_or(InvalidStateError::LarvalChildSaNotSet)?;
    let proposals = &larval_child_sa.proposals;
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    let auth = if let Some(psk) = config.psk() {
        let prf = data.chosen_proposal()?.prf().expect("PRF must be set");
        let signed_data = data.auth_data_for_signing(config.id())?;
        debug!(signed_data = ?signed_data, "signing auth data");
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
            payload::Content::Ts(payload::Ts::new(Some(larval_child_sa.ts_i.clone()))),
            true,
        ),
        Payload::new(
            PayloadType::TSr.into(),
            payload::Content::Ts(payload::Ts::new(Some(larval_child_sa.ts_r.clone()))),
            true,
        ),
        Payload::new(
            PayloadType::NOTIFY.into(),
            payload::Content::Notify(payload::Notify::new(
                Protocol::ESP.into(),
                Some(&larval_child_sa.spi[..]),
                NotifyType::USE_TRANSPORT_MODE.into(),
                b"",
            )),
            true,
        ),
    ]);

    debug!(request = ?&request, "sending protected request");

    let request = request.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;

    Ok(request)
}

impl IkeSaInitRequestSent {
    async fn handle_response(
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        mut message: &[u8],
    ) -> Result<(), StateError> {
        let serialized_response = message;
        let response =
            Message::deserialize(&mut message).map_err(|e| StateError::Protocol(e.into()))?;

        if !response.flags().contains(MessageFlags::R) {
            return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
        }

        if response.id().wrapping_add(1) != *data.message_id {
            return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
        }

        match response.exchange().assigned() {
            Some(ExchangeType::IKE_SA_INIT) => {
                handle_ike_sa_init_response(data, &response)?;
                *data.ike_sa_init_response.to_mut() = Some(serialized_response.to_vec());

                let request = generate_ike_auth_request(config, data, response.spi_r())?;
                Self::send_message(sender.clone(), data, request)?;
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
            }
        }
        Ok(())
    }
}

#[async_trait]
impl State for IkeSaInitRequestSent {
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
                debug!(error = ?e, "error processing IKE_SA_INIT response");
                (Box::new(state::Initial {}), default.into_owned())
            } else {
                (Box::new(state::IkeAuthRequestSent {}), data.swap(&default))
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
