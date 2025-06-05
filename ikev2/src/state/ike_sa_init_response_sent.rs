use crate::{
    config::{Config, ConfigError},
    message::{
        EspSpi, Message, ProtectedMessage, Spi,
        num::{ExchangeType, MessageFlags, NotifyType, PayloadType, Protocol},
        payload::{self, Payload},
        proposal::Proposal,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, LarvalChildSa, ProtocolError},
    state::{
        self, CreateChildSa, Established, InvalidStateError, SendMessage, SendProtectedMessage,
        State, StateData, StateDataCache, StateError, VerifyMessage,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct IkeSaInitResponseSent;

impl SendMessage for IkeSaInitResponseSent {}
impl VerifyMessage for IkeSaInitResponseSent {}
impl CreateChildSa for IkeSaInitResponseSent {}

impl std::fmt::Display for IkeSaInitResponseSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("IkeSaInitResponseSent").finish()
    }
}

fn handle_ike_auth_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<(), StateError> {
    let request = request
        .unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(|e| StateError::Protocol(e.into()))?;

    debug!(request = ?&request, "received protected request");

    let auth: &payload::Auth = request
        .get(PayloadType::AUTH)
        .ok_or(ProtocolError::MissingPayload(PayloadType::AUTH))?;

    let id_i: &payload::Id = request
        .get(PayloadType::IDi)
        .ok_or(ProtocolError::MissingPayload(PayloadType::IDi))?;

    let sa: &payload::Sa = request
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let ts_i: &payload::Ts = request
        .get(PayloadType::TSi)
        .ok_or(ProtocolError::MissingPayload(PayloadType::TSi))?;

    let ts_r: &payload::Ts = request
        .get(PayloadType::TSr)
        .ok_or(ProtocolError::MissingPayload(PayloadType::TSr))?;

    let authenticated = if let Some(psk) = config.psk() {
        let prf = data.chosen_proposal()?.prf().expect("PRF must be set");
        let signed_data = data.auth_data_for_verification(id_i)?;
        Ok(auth.verify_with_psk(prf, psk, &signed_data)?)
    } else {
        Err(ConfigError::NoPSK)
    };

    if authenticated? {
        info!(spi = &data.initiator_spi()?[..], "authenticated initiator");
    } else {
        return Err(ProtocolError::AuthenticationFailed.into());
    }

    let ts_i =
        TrafficSelector::negotiate(config.inbound_traffic_selectors(), ts_i.traffic_selectors())
            .ok_or(ProtocolError::TrafficSelectorUnacceptable)?;
    info!(ts_i = ?&ts_i, "negotiated TSi");

    let ts_r = TrafficSelector::negotiate(
        config.outbound_traffic_selectors(),
        ts_r.traffic_selectors(),
    )
    .ok_or(ProtocolError::TrafficSelectorUnacceptable)?;
    info!(ts_r = ?&ts_r, "negotiated TSr");

    let larval_child_sa = LarvalChildSa::new(config, &ts_i, &ts_r, false)?;
    let proposals: Vec<_> = config.ipsec_proposals(&larval_child_sa.spi).collect();
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    let proposal =
        Proposal::negotiate(&proposals, sa.proposals()).ok_or(ProtocolError::NoProposalChosen)?;
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
    *data.received_message_id.to_mut() = request.id();

    Ok(())
}

fn generate_ike_auth_response(
    config: &Config,
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<ProtectedMessage, StateError> {
    let mut response = Message::new(
        request.spi_i(),
        &data.spi,
        ExchangeType::IKE_AUTH.into(),
        MessageFlags::R,
        request.id(),
    );

    let child_sa = data
        .created_child_sa
        .as_ref()
        .as_ref()
        .ok_or(InvalidStateError::ChildSaNotSet)?;

    let proposal = child_sa.chosen_proposal().proposal(
        1,
        child_sa.chosen_proposal().protocol().into(),
        child_sa.spi(),
    );

    let auth = if let Some(psk) = config.psk() {
        let prf = data.chosen_proposal()?.prf().expect("PRF must be set");
        let signed_data = data.auth_data_for_signing(config.id())?;
        Ok(payload::Auth::sign_with_psk(prf, psk, &signed_data)?)
    } else {
        Err(ConfigError::NoPSK)
    };
    let auth = auth?;

    response.add_payloads([
        Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(payload::Sa::new(Some(proposal))),
            true,
        ),
        Payload::new(PayloadType::AUTH.into(), payload::Content::Auth(auth), true),
        Payload::new(
            PayloadType::IDr.into(),
            payload::Content::Id(config.id().clone()),
            true,
        ),
    ]);

    debug!(response = ?&response, "sending protected response");

    response
        .protect(data.encrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(Into::into)
}

fn generate_error_response(data: &StateDataCache<'_>, _error: ProtocolError) -> Message {
    let spi = Spi::default();
    let mut response = Message::new(
        data.peer_spi.as_ref().as_ref().unwrap_or(&spi),
        &data.spi,
        ExchangeType::IKE_AUTH.into(),
        MessageFlags::R,
        *data.received_message_id,
    );

    response.add_payloads([Payload::new(
        PayloadType::NOTIFY.into(),
        payload::Content::Notify(payload::Notify::new(
            Protocol::IKE.into(),
            Some(&spi[..]),
            NotifyType::INVALID_SYNTAX.into(),
            b"",
        )),
        true,
    )]);

    debug!(response = ?&response, "sending unprotected response");

    response
}

impl IkeSaInitResponseSent {
    async fn handle_request(
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        mut message: &[u8],
    ) -> Result<(), StateError> {
        let serialized_request = message;
        let request = ProtectedMessage::deserialize(&mut message)
            .map_err(|e| StateError::Protocol(e.into()))?;

        if !request.flags().contains(MessageFlags::I) {
            return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
        }

        match request.exchange().assigned() {
            Some(ExchangeType::IKE_AUTH) => {
                Self::verify_message(&data, serialized_request)?;

                handle_ike_auth_request(config, data, &request)?;

                let response = generate_ike_auth_response(config, data, &request)?;

                Established::send_message(sender.clone(), data, response)?;

                if let Some(child_sa) = data.created_child_sa.to_mut().take() {
                    Self::create_child_sa(sender.clone(), data, child_sa)?;
                }
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
            }
        }

        Ok(())
    }
}

#[async_trait]
impl State for IkeSaInitResponseSent {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        message: &[u8],
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            if let Err(e) = Self::handle_request(config, sender.clone(), &mut data, message).await {
                if let StateError::Protocol(pe) = e {
                    let response = generate_error_response(&mut data, pe);
                    Self::send_message(sender.clone(), &mut data, response)?;
                }
                return Ok(self);
            }

            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(Box::new(state::Established {}))
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
