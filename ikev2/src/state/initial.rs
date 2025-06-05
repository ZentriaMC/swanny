use crate::{
    config::{Config, ConfigError},
    crypto::Nonce,
    message::{
        EspSpi, Message, Spi,
        num::{ExchangeType, MessageFlags, NotifyType, PayloadType, Protocol},
        payload::{self, Payload},
        proposal::Proposal,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, LarvalChildSa, ProtocolError},
    state::{self, SendMessage, State, StateData, StateDataCache, StateError},
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct Initial;

impl SendMessage for Initial {}

impl std::fmt::Display for Initial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Initial").finish()
    }
}

fn generate_ike_sa_init_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
) -> Result<Message, StateError> {
    let proposals: Vec<_> = config.ike_proposals(None).collect();
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    let chosen_proposal = ChosenProposal::new(&proposals[0])?;

    let nonce = Nonce::new()?;

    let group = chosen_proposal
        .group()
        .ok_or(ConfigError::InsufficientProposal)?;
    let private_key = group.generate_key()?;
    let public_key = private_key.public_key()?;

    let mut request = Message::new(
        &data.spi,
        &Spi::default(),
        ExchangeType::IKE_SA_INIT.into(),
        MessageFlags::I,
        *data.message_id,
    );

    request.add_payloads([
        Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(payload::Sa::new(proposals)),
            true,
        ),
        Payload::new(
            PayloadType::NONCE.into(),
            payload::Content::Nonce(payload::Nonce::new(nonce.as_ref())),
            true,
        ),
        Payload::new(
            PayloadType::KE.into(),
            payload::Content::Ke(payload::Ke::new(group.id().into(), &public_key)),
            true,
        ),
    ]);

    *data.is_initiator.to_mut() = Some(true);
    *data.chosen_proposal.to_mut() = Some(chosen_proposal);
    *data.private_key.to_mut() = Some(private_key);
    *data.nonce_i.to_mut() = Some(nonce);

    Ok(request)
}

fn handle_ike_sa_init_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    request: &Message,
) -> Result<(), StateError> {
    debug!(request = ?&request, "received unprotected request");

    let sa: &payload::Sa = request
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let ke: &payload::Ke = request
        .get(PayloadType::KE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::KE))?;

    let nonce_i: &payload::Nonce = request
        .get(PayloadType::NONCE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::NONCE))?;

    let proposals: Vec<_> = config.ike_proposals(None).collect();
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    let proposal =
        Proposal::negotiate(&proposals, sa.proposals()).ok_or(ProtocolError::NoProposalChosen)?;
    info!(proposal = ?&proposal, "negotiated proposal");
    let chosen_proposal = ChosenProposal::new(&proposal)?;

    let group = chosen_proposal
        .group()
        .ok_or(ConfigError::InsufficientProposal)?;
    let private_key = group.generate_key()?;
    let public_key = private_key.public_key()?;

    let nonce = Nonce::new()?;

    let skeyseed = chosen_proposal.generate_skeyseed(
        nonce_i.nonce(),
        nonce.as_ref(),
        &private_key,
        ke.ke_data(),
    )?;
    debug!(skeyseed = ?&skeyseed, "generated SKEYSEED");

    let keys = chosen_proposal.generate_keys(
        &skeyseed,
        nonce_i.nonce(),
        nonce.as_ref(),
        request.spi_i(),
        &data.spi,
    )?;
    debug!(keys = ?&keys, "generated keys");

    *data.is_initiator.to_mut() = Some(false);
    *data.chosen_proposal.to_mut() = Some(chosen_proposal);
    *data.public_key.to_mut() = Some(public_key);
    *data.keys.to_mut() = Some(keys);
    *data.nonce_i.to_mut() = Some(nonce_i.nonce().clone());
    *data.nonce_r.to_mut() = Some(nonce);
    *data.peer_spi.to_mut() = Some(request.spi_i().to_owned());
    *data.received_message_id.to_mut() = request.id();

    Ok(())
}

fn generate_ike_sa_init_response(data: &StateDataCache<'_>) -> Result<Message, StateError> {
    let group = data
        .chosen_proposal()?
        .group()
        .ok_or(ConfigError::InsufficientProposal)?;
    let nonce_r = (*data.nonce_r).as_ref().expect("nonce should be set");

    let mut response = Message::new(
        data.peer_spi
            .as_ref()
            .as_ref()
            .expect("peer SPI should be set"),
        &data.spi,
        ExchangeType::IKE_SA_INIT.into(),
        MessageFlags::R,
        *data.received_message_id,
    );

    response.add_payloads([
        Payload::new(
            PayloadType::KE.into(),
            payload::Content::Ke(payload::Ke::new(
                group.id().into(),
                (*data.public_key)
                    .as_ref()
                    .expect("DH public key should be set"),
            )),
            true,
        ),
        Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(payload::Sa::new(Some(data.chosen_proposal()?.proposal(
                1,
                Protocol::IKE.into(),
                b"",
            )))),
            true,
        ),
        Payload::new(
            PayloadType::NONCE.into(),
            payload::Content::Nonce(payload::Nonce::new(nonce_r.as_ref())),
            true,
        ),
    ]);

    debug!(response = ?&response, "sending unprotected response");

    Ok(response)
}

fn generate_error_response(data: &StateDataCache<'_>, _error: ProtocolError) -> Message {
    let spi = Spi::default();
    let mut response = Message::new(
        data.peer_spi.as_ref().as_ref().unwrap_or(&spi),
        &data.spi,
        ExchangeType::IKE_SA_INIT.into(),
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

impl Initial {
    async fn handle_request(
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        mut message: &[u8],
    ) -> Result<(), StateError> {
        let serialized_request = message;
        let request =
            Message::deserialize(&mut message).map_err(|e| StateError::Protocol(e.into()))?;

        if !request.flags().contains(MessageFlags::I) {
            return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
        }

        match request.exchange().assigned() {
            Some(ExchangeType::IKE_SA_INIT) => {
                if request.id() != 0 {
                    debug!("IKE_SA_INIT request must have message ID 0, {} found", request.id());
                    return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
                }

                handle_ike_sa_init_request(config, data, &request)?;

                let response = generate_ike_sa_init_response(&data)?;
                Self::send_message(sender.clone(), data, response)?;

                *data.ike_sa_init_request.to_mut() = Some(serialized_request.to_vec());
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
            }
        }

        Ok(())
    }
}

#[async_trait]
impl State for Initial {
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

        Ok(Box::new(state::IkeSaInitResponseSent {}))
    }

    async fn handle_acquire(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        ts_i: &TrafficSelector,
        ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            let request = generate_ike_sa_init_request(config, &mut data)?;

            Self::send_message(sender.clone(), &mut data, request)?;
            *data.larval_child_sa.to_mut() = Some(LarvalChildSa::new(config, ts_i, ts_r, true)?);
            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(Box::new(state::IkeSaInitRequestSent {}))
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
