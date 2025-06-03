use crate::{
    config::{Config, ConfigError},
    crypto::Nonce,
    message::{
        EspSpi, Message, ProtectedMessage,
        num::{ExchangeType, MessageFlags, NotifyType, PayloadType, Protocol},
        payload::{self, Payload},
        proposal::Proposal,
        serialize::{Deserialize, DeserializeError},
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, LarvalChildSa},
    state::{
        self, ChildSa, CreateChildSa, DeleteChildSa, ProtocolError, RekeyChildSa,
        SendProtectedMessage, State, StateData, StateDataCache, StateError, VerifyMessage,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct Established;

impl SendProtectedMessage for Established {}
impl VerifyMessage for Established {}
impl CreateChildSa for Established {}
impl DeleteChildSa for Established {}
impl RekeyChildSa for Established {}

impl std::fmt::Display for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Established").finish()
    }
}

fn handle_informational_request(
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<(), StateError> {
    let request = request.unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())?;

    debug!(request = ?&request, "received protected request");

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

    debug!(response = ?&response, "sending protected response");

    let response = response.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;
    Ok(response)
}

fn handle_rekey_child_sa_request(
    data: &mut StateDataCache<'_>,
    spi: &EspSpi,
    nonce_i: &Nonce,
    nonce_r: &Nonce,
    peer_public_key: Option<&[u8]>,
) -> Result<(), StateError> {
    let child_sas = data.child_sas.to_mut();
    let index = child_sas
        .iter()
        .position(|child_sa| child_sa.chosen_proposal().spi() == spi);
    if let Some(index) = index {
        let mut child_sa = child_sas.swap_remove(index);
        let public_key = child_sa.rekey(
            &data.keys()?.derivation.d,
            nonce_i,
            nonce_r,
            peer_public_key,
        )?;
        *data.public_key.to_mut() = public_key;
        *data.rekeyed_child_sa.to_mut() = Some(child_sa);
    }
    Ok(())
}

fn handle_create_new_child_sa_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    sa: &payload::Sa,
    ts_i: &payload::Ts,
    ts_r: &payload::Ts,
    nonce_i: &Nonce,
    nonce_r: &Nonce,
) -> Result<(), StateError> {
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
        nonce_i,
        nonce_r,
    )?;
    *data.created_child_sa.to_mut() = Some(Box::new(child_sa));

    Ok(())
}

fn handle_create_child_sa_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<(), StateError> {
    let request = request.unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())?;

    debug!(request = ?&request, "received protected request");

    let nonce = Nonce::new()?;

    let sa: &payload::Sa = request
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let nonce_i: &payload::Nonce = request
        .get(PayloadType::NONCE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::NONCE))?;

    let ts_i: Option<&payload::Ts> = request.get(PayloadType::TSi);
    let ts_r: Option<&payload::Ts> = request.get(PayloadType::TSr);

    let notifications: Result<Vec<_>, _> = request
        .payloads()
        .filter(|p| matches!(p.ty().assigned(), Some(PayloadType::NOTIFY)))
        .map(TryInto::<&payload::Notify>::try_into)
        .collect();

    let notifications = notifications.map_err(Into::<DeserializeError>::into)?;

    let rekey_sa = notifications
        .into_iter()
        .find(|n| matches!(n.ty().assigned(), Some(NotifyType::REKEY_SA)));

    if let Some(rekey_sa) = rekey_sa {
        // Rekey a Child SA, if a REKEY_SA notification payload present
        let spi = rekey_sa.spi().ok_or(ProtocolError::MissingSpi)?;
        let ke: Option<&payload::Ke> = request.get(PayloadType::KE);
        handle_rekey_child_sa_request(
            data,
            spi.try_into().map_err(Into::<DeserializeError>::into)?,
            nonce_i.nonce(),
            &nonce,
            ke.map(|ke| ke.ke_data()),
        )?;
    } else if let (Some(ts_i), Some(ts_r)) = (ts_i, ts_r) {
        // Create a new Child SA, if TSi and TSr are present
        handle_create_new_child_sa_request(config, data, sa, ts_i, ts_r, nonce_i.nonce(), &nonce)?;
    } else {
        // Otherwise, rekey an IKE SA
    }

    *data.nonce_r.to_mut() = Some(nonce);

    Ok(())
}

fn generate_rekey_child_sa_response(
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

    if let Some(public_key) = data.public_key.to_mut().take() {
        let group = data.chosen_proposal()?.group().expect("group must be set");
        response.add_payloads(Some(Payload::new(
            PayloadType::KE.into(),
            payload::Content::Ke(payload::Ke::new(group.id().into(), public_key)),
            true,
        )));
    }

    debug!(response = ?&response, "sending protected response");

    response
        .protect(data.encrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(Into::into)
}

fn generate_create_new_child_sa_response(
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

    debug!(response = ?&response, "sending protected response");

    response
        .protect(data.encrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(Into::into)
}

fn generate_create_child_sa_response(
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<ProtectedMessage, StateError> {
    let response = if data.rekeyed_child_sa.is_some() {
        generate_rekey_child_sa_response(data, request)?
    } else if data.created_child_sa.is_some() {
        generate_create_new_child_sa_response(data, request)?
    } else {
        todo!()
    };
    Ok(response)
}

fn generate_delete_child_sa_request(
    data: &StateDataCache<'_>,
    child_sa: &ChildSa,
) -> Result<ProtectedMessage, StateError> {
    let mut request = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::INFORMATIONAL.into(),
        MessageFlags::I,
        *data.message_id,
    );

    request.add_payloads(Some(Payload::new(
        PayloadType::DELETE.into(),
        payload::Content::Delete(payload::Delete::new(
            child_sa.chosen_proposal().protocol().into(),
            Some(*child_sa.spi()),
        )),
        false,
    )));

    let request = request.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;

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
        *data.message_id,
    );

    let nonce = Nonce::new()?;

    let larval_child_sa = LarvalChildSa::new(config, ts_i, ts_r, true)?;
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
            payload::Content::Nonce(payload::Nonce::new(nonce.as_ref())),
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

    debug!(request = ?&request, "sending protected request");

    let request = request.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;

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
                    data.deleted_child_sas.to_mut().clear();

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

                    if let Some(child_sa) = data.rekeyed_child_sa.to_mut().take() {
                        Self::rekey_child_sa(sender.clone(), &mut data, child_sa)?;
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

        Ok(Box::new(state::NewChildSaRequestSent {}))
    }

    async fn handle_expire(
        self: Box<Self>,
        _config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        spi: &EspSpi,
        _hard: bool,
    ) -> Result<Box<dyn State>, StateError> {
        let mut deleted_child_sas = Vec::new();

        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            let child_sas = data.child_sas.to_mut();
            let index = child_sas.iter().position(|child_sa| child_sa.spi() == spi);
            if let Some(index) = index {
                let child_sa = child_sas.swap_remove(index);
                deleted_child_sas.push(child_sa);
            }

            for child_sa in deleted_child_sas.iter() {
                debug!(spi = ?spi, "sending delete Child SA request");
                let request = generate_delete_child_sa_request(&data, child_sa)?;
                Self::send_message(sender.clone(), &mut data, request)?;
            }
            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        if deleted_child_sas.is_empty() {
            Ok(self)
        } else {
            Ok(Box::new(state::DeleteChildSaRequestSent {}))
        }
    }
}
