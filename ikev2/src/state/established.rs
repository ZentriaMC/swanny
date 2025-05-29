use crate::{
    config::{Config, ConfigError},
    crypto,
    message::{
        EspSpi, Message, ProtectedMessage,
        num::{ExchangeType, MessageFlags, PayloadType, Protocol},
        payload::{self, Payload},
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, LarvalChildSa},
    state::{
        self, ChildSa, CreateChildSa, DeleteChildSa, InvalidStateError, ProtocolError,
        SendProtectedMessage, State, StateData, StateDataCache, StateError, VerifyMessage,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::RwLock;
use tracing::debug;

pub struct Established;

impl SendProtectedMessage for Established {}
impl VerifyMessage for Established {}
impl CreateChildSa for Established {}
impl DeleteChildSa for Established {}

impl std::fmt::Display for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Established").finish()
    }
}

fn handle_informational_request(
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<(), StateError> {
    let request = request.unprotect(data.chosen_proposal()?.cipher(), data.decrypting_key()?)?;

    debug!(request = ?&request, "unprotected request");

    let delete: Option<&payload::Delete> = request.get(PayloadType::DELETE);
    if let Some(delete) = delete {
        for spi in delete.spis() {
            let child_sas = data.child_sas.to_mut();
            let index = child_sas
                .iter()
                .position(|child_sa| child_sa.chosen_proposal().spi() == spi);
            if let Some(index) = index {
                let child_sa = child_sas.swap_remove(index);
                data.deleted_child_sas.to_mut().push(child_sa);
            }
        }
    }
    Ok(())
}

fn generate_informational_response(
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<ProtectedMessage, StateError> {
    let mut child_sas_by_protocol: BTreeMap<Protocol, Vec<&ChildSa>> = BTreeMap::new();
    for child_sa in data.deleted_child_sas.iter() {
        match child_sas_by_protocol.get_mut(&child_sa.chosen_proposal().protocol()) {
            Some(v) => v.push(child_sa),
            None => {
                let _ = child_sas_by_protocol
                    .insert(child_sa.chosen_proposal().protocol(), vec![child_sa]);
            }
        }
    }

    let mut response = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::INFORMATIONAL.into(),
        MessageFlags::R,
        request.id(),
    );

    let payloads: Vec<_> = child_sas_by_protocol
        .iter()
        .map(|(protocol, child_sas)| {
            let spis: Vec<EspSpi> = child_sas.iter().map(|child_sa| *child_sa.spi()).collect();
            Payload::new(
                PayloadType::DELETE.into(),
                payload::Content::Delete(payload::Delete::new((*protocol).into(), spis)),
                false,
            )
        })
        .collect();
    response.add_payloads(payloads);
    response
        .protect(data.chosen_proposal()?.cipher(), data.encrypting_key()?)
        .map_err(Into::into)
}

fn handle_create_child_sa_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<(), StateError> {
    let request = request.unprotect(data.chosen_proposal()?.cipher(), data.decrypting_key()?)?;

    debug!(request = ?&request, "unprotected request");

    let mut nonce = vec![0u8; 32];
    crypto::rand_bytes(&mut nonce[..])?;

    let sa: &payload::Sa = request
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let nonce_i: &payload::Nonce = request
        .get(PayloadType::NONCE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::NONCE))?;

    let ts_i: Option<&payload::Ts> = request.get(PayloadType::TSi);
    let ts_r: Option<&payload::Ts> = request.get(PayloadType::TSr);

    if let (Some(ts_i), Some(ts_r)) = (ts_i, ts_r) {
        // Create a new Child SA, if TSi and TSr are present

        let ts_i = TrafficSelector::negotiate(
            config.inbound_traffic_selectors(),
            ts_i.traffic_selectors(),
        )
        .ok_or(ProtocolError::TrafficSelectorUnacceptable)?;

        let ts_r = TrafficSelector::negotiate(
            config.outbound_traffic_selectors(),
            ts_r.traffic_selectors(),
        )
        .ok_or(ProtocolError::TrafficSelectorUnacceptable)?;

        let larval_child_sa = LarvalChildSa::new(config, &ts_r, &ts_i)?;
        let proposals: Vec<_> = config.ipsec_proposals(&larval_child_sa.spi).collect();
        if proposals.is_empty() {
            return Err(ConfigError::NoProposalsSet.into());
        }

        let chosen_proposal = ChosenProposal::negotiate(&proposals, sa.proposals())?;
        let child_sa = larval_child_sa.build(
            &chosen_proposal,
            &data.keys()?.deriving.d,
            nonce_i.nonce(),
            &nonce[..],
        )?;
        *data.created_child_sa.to_mut() = Some(Box::new(child_sa));
    } else {
        // Otherwise, rekey SA
    }

    *data.nonce_r.to_mut() = Some(nonce);

    Ok(())
}

fn generate_create_child_sa_response(
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<ProtectedMessage, StateError> {
    let mut response = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::CREATE_CHILD_SA.into(),
        MessageFlags::R,
        request.id(),
    );

    let child_sa = (*data.created_child_sa).as_ref().unwrap();
    let proposal = child_sa.chosen_proposal().proposal(
        1,
        child_sa.chosen_proposal().protocol().into(),
        child_sa.spi(),
    );

    response.add_payloads([
        Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(payload::Sa::new(Some(proposal))),
            true,
        ),
        Payload::new(
            PayloadType::NONCE.into(),
            payload::Content::Nonce(payload::Nonce::new((*data.nonce_r).as_ref().unwrap())),
            true,
        ),
        Payload::new(
            PayloadType::TSi.into(),
            payload::Content::Ts(payload::Ts::new(Some(child_sa.ts_i().clone()))),
            true,
        ),
        Payload::new(
            PayloadType::TSr.into(),
            payload::Content::Ts(payload::Ts::new(Some(child_sa.ts_r().clone()))),
            true,
        ),
    ]);
    response
        .protect(data.chosen_proposal()?.cipher(), data.encrypting_key()?)
        .map_err(Into::into)
}

fn generate_delete_child_sa_request(
    data: &mut StateDataCache<'_>,
    spi: &EspSpi,
) -> Result<ProtectedMessage, StateError> {
    let child_sa =
        data.child_sa(spi)
            .ok_or(StateError::InvalidState(InvalidStateError::UnknownChildSa(
                *spi,
            )))?;

    let mut request = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::INFORMATIONAL.into(),
        MessageFlags::I,
        (*data.message_id).wrapping_add(1),
    );

    request.add_payloads(Some(Payload::new(
        PayloadType::DELETE.into(),
        payload::Content::Delete(payload::Delete::new(
            child_sa.chosen_proposal().protocol().into(),
            Some(*child_sa.spi()),
        )),
        false,
    )));

    let request = request.protect(data.chosen_proposal()?.cipher(), data.encrypting_key()?)?;

    *data.message_id.to_mut() = request.id();

    Ok(request)
}

fn generate_create_child_sa_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    ts_i: &TrafficSelector,
    ts_r: &TrafficSelector,
) -> Result<ProtectedMessage, StateError> {
    let mut request = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::CREATE_CHILD_SA.into(),
        MessageFlags::I,
        data.message_id.wrapping_add(1),
    );

    let mut nonce = vec![0u8; 32];
    crypto::rand_bytes(&mut nonce[..])?;

    let larval_child_sa = LarvalChildSa::new(config, ts_i, ts_r)?;
    let proposals = &larval_child_sa.proposals;
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    request.add_payloads([
        Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(payload::Sa::new(proposals.clone())),
            true,
        ),
        Payload::new(
            PayloadType::NONCE.into(),
            payload::Content::Nonce(payload::Nonce::new(&nonce[..])),
            true,
        ),
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
    ]);

    let request = request.protect(
        data.chosen_proposal()?.cipher(),
        &data.keys()?.protecting.ei,
    )?;

    *data.message_id.to_mut() = request.id();
    *data.larval_child_sa.to_mut() = Some(larval_child_sa);
    *data.nonce_i.to_mut() = Some(nonce);

    Ok(request)
}

#[async_trait]
impl State for Established {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>, StateError> {
        let serialized_request = message;
        let request = ProtectedMessage::deserialize(&mut message)?;
        match request.exchange().assigned() {
            Some(ExchangeType::INFORMATIONAL) => {
                let default = StateData::default();
                let default = StateDataCache::new_borrowed(&default);

                let cache = {
                    let data = data.read().await;
                    let mut data = StateDataCache::new_borrowed(&data);

                    Self::verify_message(&data, serialized_request)?;

                    handle_informational_request(&mut data, &request)?;

                    let response = generate_informational_response(&mut data, &request)?;

                    Self::send_message(sender.clone(), &mut data, response)?;

                    for child_sa in data.deleted_child_sas.to_mut().iter_mut() {
                        Self::delete_child_sa(sender.clone(), child_sa.clone())?;
                    }

                    data.swap(&default)
                };

                {
                    let mut data = data.write().await;
                    cache.write_into(&mut data);
                }
            }
            Some(ExchangeType::CREATE_CHILD_SA) => {
                let default = StateData::default();
                let default = StateDataCache::new_borrowed(&default);

                let cache = {
                    let data = data.read().await;
                    let mut data = StateDataCache::new_borrowed(&data);

                    Self::verify_message(&data, serialized_request)?;

                    handle_create_child_sa_request(config, &mut data, &request)?;

                    let response = generate_create_child_sa_response(&mut data, &request)?;

                    Self::send_message(sender.clone(), &mut data, response)?;

                    if let Some(child_sa) = data.created_child_sa.to_mut().take() {
                        Self::create_child_sa(sender.clone(), &mut data, child_sa)?;
                    }

                    data.swap(&default)
                };

                {
                    let mut data = data.write().await;
                    cache.write_into(&mut data);
                }
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
            }
        }
        Ok(self)
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

            let request = generate_create_child_sa_request(config, &mut data, ts_i, ts_r)?;
            Self::send_message(sender.clone(), &mut data, request)?;
            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(Box::new(state::CreateChildSaRequestSent {}))
    }

    async fn handle_expire(
        self: Box<Self>,
        _config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        spi: &EspSpi,
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            let request = generate_delete_child_sa_request(&mut data, spi)?;

            Self::send_message(sender.clone(), &mut data, request)?;
            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(Box::new(state::DeleteChildSaRequestSent {}))
    }
}
