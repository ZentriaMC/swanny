use crate::{
    config::{Config, ConfigError},
    crypto::{self, Nonce},
    message::{
        EspSpi, Message, ProtectedMessage, Spi,
        num::{ExchangeType, MessageFlags, NotifyType, PayloadType, Protocol},
        payload::{self, Payload},
        proposal::Proposal,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, Keys, LarvalChildSa},
    state::{
        self, ChildSa, ChildSaMode, CreateChildSa, DeleteChildSa, InvalidStateError, ProtocolError,
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

impl std::fmt::Display for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Established").finish()
    }
}

fn handle_informational_request(
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<(), StateError> {
    let request = request
        .unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(|e| StateError::Protocol(e.into()))?;

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
    sa: &payload::Sa,
    nonce_i: &Nonce,
    nonce_r: &Nonce,
    peer_public_key: Option<&[u8]>,
) -> Result<(), StateError> {
    let child_sas = data.child_sas.to_mut();
    let index = child_sas
        .iter()
        .position(|child_sa| child_sa.chosen_proposal().spi() == spi);
    if let Some(index) = index {
        let rekeying_child_sa = child_sas.swap_remove(index);
        let creating_child_sa = LarvalChildSa::from_existing(&rekeying_child_sa, false)?;

        let proposals = &creating_child_sa.proposals;
        if proposals.is_empty() {
            return Err(ConfigError::NoProposalsSet.into());
        }

        let proposal = Proposal::negotiate(proposals, sa.proposals())
            .ok_or(ProtocolError::NoProposalChosen)?;
        info!(proposal = ?&proposal, "negotiated proposal");
        let chosen_proposal = ChosenProposal::new(&proposal)?;

        let child_sa = creating_child_sa.build(
            &chosen_proposal,
            &data.keys()?.derivation.d,
            nonce_i,
            nonce_r,
            peer_public_key,
        )?;
        *data.created_child_sa.to_mut() = Some(Box::new(child_sa));
        *data.rekeyed_child_sa.to_mut() = Some(rekeying_child_sa);
    }
    Ok(())
}

fn handle_new_child_sa_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    sa: &payload::Sa,
    ts_i: &payload::Ts,
    ts_r: &payload::Ts,
    nonce_i: &Nonce,
    nonce_r: &Nonce,
    use_transport_mode: bool,
) -> Result<(), StateError> {
    let ts_i = if config.strict_ts() {
        TrafficSelector::exact_match(config.inbound_traffic_selectors(), ts_i.traffic_selectors())
    } else {
        TrafficSelector::negotiate(config.inbound_traffic_selectors(), ts_i.traffic_selectors())
    }
    .ok_or(ProtocolError::TrafficSelectorUnacceptable)?;
    info!(ts_i = ?&ts_i, "negotiated TSi");

    let ts_r = if config.strict_ts() {
        TrafficSelector::exact_match(
            config.outbound_traffic_selectors(),
            ts_r.traffic_selectors(),
        )
    } else {
        TrafficSelector::negotiate(
            config.outbound_traffic_selectors(),
            ts_r.traffic_selectors(),
        )
    }
    .ok_or(ProtocolError::TrafficSelectorUnacceptable)?;
    info!(ts_r = ?&ts_r, "negotiated TSr");

    let mode = if use_transport_mode {
        ChildSaMode::Transport
    } else {
        ChildSaMode::Tunnel
    };

    let creating_child_sa = LarvalChildSa::new(config, &ts_i, &ts_r, mode, false)?;
    let proposals: Vec<_> = config.ipsec_proposals(&creating_child_sa.spi).collect();
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    let proposal =
        Proposal::negotiate(&proposals, sa.proposals()).ok_or(ProtocolError::NoProposalChosen)?;
    info!(proposal = ?&proposal, "negotiated proposal");
    let chosen_proposal = ChosenProposal::new(&proposal)?;

    let child_sa = creating_child_sa.build(
        &chosen_proposal,
        &data.keys()?.derivation.d,
        nonce_i,
        nonce_r,
        None,
    )?;
    *data.created_child_sa.to_mut() = Some(Box::new(child_sa));

    Ok(())
}

struct IkeSaRekeyResult {
    new_spi: Spi,
    peer_new_spi: Spi,
    public_key: Vec<u8>,
    chosen_proposal: ChosenProposal,
    keys: Keys,
}

fn handle_rekey_ike_sa_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    sa: &payload::Sa,
    nonce_i: &Nonce,
    nonce_r: &Nonce,
    ke: &payload::Ke,
) -> Result<IkeSaRekeyResult, StateError> {
    // Generate our new SPI
    let mut new_spi = Spi::default();
    crypto::rand_bytes(&mut new_spi)?;

    // Negotiate IKE proposals
    let proposals: Vec<_> = config.ike_proposals(Some(&new_spi)).collect();
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    let proposal =
        Proposal::negotiate(&proposals, sa.proposals()).ok_or(ProtocolError::NoProposalChosen)?;
    info!(proposal = ?&proposal, "negotiated IKE SA rekey proposal");
    let chosen_proposal = ChosenProposal::new(&proposal)?;

    // Get peer's new SPI from their SA proposal
    let peer_proposal = sa
        .proposals()
        .next()
        .ok_or(ProtocolError::NoProposalsReceived)?;
    let peer_new_spi: Spi = peer_proposal
        .spi()
        .try_into()
        .map_err(|_| ProtocolError::MissingSpi)?;

    // Generate our DH key pair
    let group = chosen_proposal
        .group()
        .ok_or(ConfigError::InsufficientProposal)?;
    let private_key = group.generate_key()?;
    let public_key = private_key.public_key()?;

    // Compute SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr)
    let old_sk_d = &data.keys()?.derivation.d;
    let skeyseed = chosen_proposal.generate_rekey_skeyseed(
        old_sk_d,
        nonce_i,
        nonce_r,
        &private_key,
        ke.ke_data(),
    )?;
    debug!(skeyseed = ?&skeyseed, "generated rekey SKEYSEED");

    // Derive new keys (SPI order follows original initiator/responder roles)
    let is_initiator = (*data.is_initiator).ok_or(InvalidStateError::InitiatorNotDetermined)?;
    let (spi_i, spi_r) = if is_initiator {
        (&new_spi, &peer_new_spi)
    } else {
        (&peer_new_spi, &new_spi)
    };
    let keys = chosen_proposal.generate_keys(&skeyseed, nonce_i, nonce_r, spi_i, spi_r)?;
    debug!(keys = ?&keys, "generated rekey keys");

    Ok(IkeSaRekeyResult {
        new_spi,
        peer_new_spi,
        public_key,
        chosen_proposal,
        keys,
    })
}

fn generate_rekey_ike_sa_response(
    data: &mut StateDataCache<'_>,
    rekey: &IkeSaRekeyResult,
    request: &ProtectedMessage,
) -> Result<ProtectedMessage, StateError> {
    let mut response = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::CREATE_CHILD_SA.into(),
        MessageFlags::R,
        request.id(),
    );

    let proposal = rekey
        .chosen_proposal
        .proposal(1, Protocol::IKE.into(), &rekey.new_spi[..]);

    let group = rekey.chosen_proposal.group().expect("group must be set");

    response.add_payloads([
        Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(payload::Sa::new(Some(proposal))),
            true,
        ),
        Payload::new(
            PayloadType::NONCE.into(),
            payload::Content::Nonce(payload::Nonce::new(
                (*data.nonce_r)
                    .as_ref()
                    .ok_or(InvalidStateError::NonceNotRecorded)?,
            )),
            true,
        ),
        Payload::new(
            PayloadType::KE.into(),
            payload::Content::Ke(payload::Ke::new(group.id().into(), &rekey.public_key)),
            true,
        ),
    ]);

    debug!(response = ?&response, "sending IKE SA rekey response");

    response
        .protect(data.encrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(Into::into)
}

fn handle_create_child_sa_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
    request: &ProtectedMessage,
) -> Result<Option<IkeSaRekeyResult>, StateError> {
    let request = request
        .unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(|e| StateError::Protocol(e.into()))?;

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

    let notifications = notifications
        .map_err(|e| StateError::Protocol(ProtocolError::DeserializeError(e.into())))?;

    let rekey_sa = notifications
        .iter()
        .find(|n| matches!(n.ty().assigned(), Some(NotifyType::REKEY_SA)));

    let use_transport_mode = notifications
        .iter()
        .find(|n| matches!(n.ty().assigned(), Some(NotifyType::USE_TRANSPORT_MODE)));

    if let Some(rekey_sa) = rekey_sa {
        // Rekey a Child SA, if a REKEY_SA notification payload present
        let spi = rekey_sa.spi().ok_or(ProtocolError::MissingSpi)?;
        let ke: Option<&payload::Ke> = request.get(PayloadType::KE);
        handle_rekey_child_sa_request(
            data,
            spi.try_into().map_err(|e: std::array::TryFromSliceError| {
                StateError::Protocol(ProtocolError::DeserializeError(e.into()))
            })?,
            sa,
            nonce_i.nonce(),
            &nonce,
            ke.map(|ke| ke.ke_data()),
        )?;
    } else if let (Some(ts_i), Some(ts_r)) = (ts_i, ts_r) {
        // Create a new Child SA, if TSi and TSr are present
        handle_new_child_sa_request(
            config,
            data,
            sa,
            ts_i,
            ts_r,
            nonce_i.nonce(),
            &nonce,
            use_transport_mode.is_some(),
        )?;
    } else {
        // Otherwise, rekey an IKE SA
        let ke: &payload::Ke = request
            .get(PayloadType::KE)
            .ok_or(ProtocolError::MissingPayload(PayloadType::KE))?;
        let result = handle_rekey_ike_sa_request(config, data, sa, nonce_i.nonce(), &nonce, ke)?;
        *data.nonce_r.to_mut() = Some(nonce);
        return Ok(Some(result));
    }

    *data.nonce_r.to_mut() = Some(nonce);

    Ok(None)
}

fn generate_new_child_sa_response(
    data: &mut StateDataCache<'_>,
    child_sa: &ChildSa,
    request: &ProtectedMessage,
) -> Result<ProtectedMessage, StateError> {
    let mut response = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::CREATE_CHILD_SA.into(),
        MessageFlags::R,
        request.id(),
    );

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
            payload::Content::Nonce(payload::Nonce::new(
                (*data.nonce_r)
                    .as_ref()
                    .ok_or(InvalidStateError::NonceNotRecorded)?,
            )),
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

    if let Some(public_key) = child_sa.public_key().as_ref() {
        let group = data.chosen_proposal()?.group().expect("group must be set");
        response.add_payloads(Some(Payload::new(
            PayloadType::KE.into(),
            payload::Content::Ke(payload::Ke::new(group.id().into(), public_key)),
            true,
        )));
    }

    if child_sa.mode() == ChildSaMode::Transport {
        response.add_payloads(Some(Payload::new(
            PayloadType::NOTIFY.into(),
            payload::Content::Notify(payload::Notify::new(
                Protocol::ESP.into(),
                Some(&child_sa.spi()[..]),
                NotifyType::USE_TRANSPORT_MODE.into(),
                b"",
            )),
            true,
        )));
    }

    debug!(response = ?&response, "sending protected response");

    response
        .protect(data.encrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(Into::into)
}

fn generate_new_child_sa_request(
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

    let creating_child_sa = LarvalChildSa::new(config, ts_i, ts_r, config.mode(), true)?;
    let proposals = &creating_child_sa.proposals;
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
            payload::Content::Ts(payload::Ts::new(Some(creating_child_sa.ts_i.clone()))),
            true,
        ),
        Payload::new(
            PayloadType::TSr.into(),
            payload::Content::Ts(payload::Ts::new(Some(creating_child_sa.ts_r.clone()))),
            true,
        ),
    ]);

    if creating_child_sa.mode == ChildSaMode::Transport {
        request.add_payloads(Some(Payload::new(
            PayloadType::NOTIFY.into(),
            payload::Content::Notify(payload::Notify::new(
                Protocol::ESP.into(),
                Some(&creating_child_sa.spi[..]),
                NotifyType::USE_TRANSPORT_MODE.into(),
                b"",
            )),
            true,
        )));
    }

    debug!(request = ?&request, "sending protected request");

    let request = request.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;

    *data.creating_child_sa.to_mut() = Some(creating_child_sa);
    *data.nonce_i.to_mut() = Some(nonce);

    Ok(request)
}

fn generate_dpd_request(data: &StateDataCache<'_>) -> Result<ProtectedMessage, StateError> {
    let request = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::INFORMATIONAL.into(),
        MessageFlags::I,
        *data.message_id,
    );

    debug!(request = ?&request, "sending DPD request");

    let request = request.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;

    Ok(request)
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

    debug!(request = ?&request, "sending protected request");

    let request = request.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;

    Ok(request)
}

fn generate_rekey_child_sa_request(
    data: &mut StateDataCache<'_>,
    child_sa: Box<ChildSa>,
) -> Result<ProtectedMessage, StateError> {
    let mut request = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::CREATE_CHILD_SA.into(),
        MessageFlags::I,
        *data.message_id,
    );

    let nonce = Nonce::new()?;

    let creating_child_sa = LarvalChildSa::from_existing(&child_sa, true)?;
    let proposals = &creating_child_sa.proposals;
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    request.add_payloads([
        Payload::new(
            PayloadType::NOTIFY.into(),
            payload::Content::Notify(payload::Notify::new(
                child_sa.chosen_proposal().protocol().into(),
                Some(child_sa.spi()),
                NotifyType::REKEY_SA.into(),
                b"",
            )),
            true,
        ),
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
            payload::Content::Ts(payload::Ts::new(Some(creating_child_sa.ts_i.clone()))),
            true,
        ),
        Payload::new(
            PayloadType::TSr.into(),
            payload::Content::Ts(payload::Ts::new(Some(creating_child_sa.ts_r.clone()))),
            true,
        ),
    ]);

    debug!(request = ?&request, "sending protected request");

    let request = request.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;

    *data.creating_child_sa.to_mut() = Some(creating_child_sa);
    *data.rekeying_child_sa.to_mut() = Some(child_sa);
    *data.nonce_i.to_mut() = Some(nonce);

    Ok(request)
}

fn generate_rekey_ike_sa_request(
    config: &Config,
    data: &mut StateDataCache<'_>,
) -> Result<ProtectedMessage, StateError> {
    let mut request = Message::new(
        data.initiator_spi()?,
        data.responder_spi()?,
        ExchangeType::CREATE_CHILD_SA.into(),
        MessageFlags::I,
        *data.message_id,
    );

    // Generate new SPI
    let mut new_spi = Spi::default();
    crypto::rand_bytes(&mut new_spi)?;

    // Get proposals with our new SPI
    let proposals: Vec<_> = config.ike_proposals(Some(&new_spi)).collect();
    if proposals.is_empty() {
        return Err(ConfigError::NoProposalsSet.into());
    }

    // Generate nonce
    let nonce = Nonce::new()?;

    // Generate DH key pair
    let chosen_proposal = ChosenProposal::new(&proposals[0])?;
    let group = chosen_proposal
        .group()
        .ok_or(ConfigError::InsufficientProposal)?;
    let private_key = group.generate_key()?;
    let public_key = private_key.public_key()?;

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

    debug!(request = ?&request, "sending IKE SA rekey request");

    let request = request.protect(data.encrypting_key()?, data.chosen_proposal()?.integ())?;

    *data.rekeying_ike_spi.to_mut() = Some(new_spi);
    *data.private_key.to_mut() = Some(private_key);
    *data.nonce_i.to_mut() = Some(nonce);

    Ok(request)
}

impl Established {
    async fn handle_request(
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        mut message: &[u8],
    ) -> Result<(), StateError> {
        let serialized_request = message;
        let request = ProtectedMessage::deserialize(&mut message)
            .map_err(|e| StateError::Protocol(e.into()))?;

        Self::verify_message(data, serialized_request)?;

        let expected_id = (*data.received_message_id)
            .map(|id| id.wrapping_add(1))
            .unwrap_or(0);
        if request.id() != expected_id {
            debug!(
                expected = expected_id,
                received = request.id(),
                "dropping request with unexpected message ID"
            );
            return Ok(());
        }
        *data.received_message_id.to_mut() = Some(request.id());

        match request.exchange().assigned() {
            Some(ExchangeType::INFORMATIONAL) => {
                handle_informational_request(data, &request)?;

                let response = generate_informational_response(data, &request)?;

                Self::send_message(sender.clone(), data, response)?;

                for child_sa in data.deleted_child_sas.to_mut().iter_mut() {
                    Self::delete_child_sa(sender.clone(), child_sa.clone())?;
                }
                data.deleted_child_sas.to_mut().clear();
            }
            Some(ExchangeType::CREATE_CHILD_SA) => {
                let ike_rekey = handle_create_child_sa_request(config, data, &request)?;

                if let Some(child_sa) = data.created_child_sa.to_mut().take() {
                    let response = generate_new_child_sa_response(data, &child_sa, &request)?;
                    Self::send_message(sender.clone(), data, response)?;
                    Self::create_child_sa(sender.clone(), data, child_sa)?;
                }

                if let Some(child_sa) = data.rekeyed_child_sa.to_mut().take() {
                    Self::delete_child_sa(sender.clone(), child_sa)?;
                }

                // IKE SA rekey: send response with old keys, then atomic switchover
                if let Some(rekey) = ike_rekey {
                    let response = generate_rekey_ike_sa_response(data, &rekey, &request)?;
                    Self::send_message(sender.clone(), data, response)?;

                    info!("IKE SA rekeyed, switching to new keys");
                    *data.spi.to_mut() = rekey.new_spi;
                    *data.peer_spi.to_mut() = Some(rekey.peer_new_spi);
                    *data.chosen_proposal.to_mut() = Some(rekey.chosen_proposal);
                    *data.keys.to_mut() = Some(rekey.keys);
                    *data.message_id.to_mut() = 0;
                    *data.received_message_id.to_mut() = None;
                    *data.ike_sa_init_request.to_mut() = None;
                    *data.ike_sa_init_response.to_mut() = None;
                    *data.last_request.to_mut() = None;
                    *data.public_key.to_mut() = None;
                    *data.private_key.to_mut() = None;
                }
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
            }
        }

        Ok(())
    }
}

fn generate_error_response(
    data: &StateDataCache<'_>,
    _error: ProtocolError,
) -> Result<ProtectedMessage, StateError> {
    let spi = Spi::default();
    let mut response = Message::new(
        data.peer_spi.as_ref().as_ref().unwrap_or(&spi),
        &data.spi,
        ExchangeType::INFORMATIONAL.into(),
        MessageFlags::R,
        (*data.received_message_id).unwrap_or(0),
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

    debug!(response = ?&response, "sending protected response");

    response
        .protect(data.encrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(Into::into)
}

#[async_trait]
impl State for Established {
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
                    let response = generate_error_response(&data, pe)?;
                    Self::send_message(sender.clone(), &mut data, response)?;
                }

                // Do not write partial state data upon error
                return Ok(self);
            }

            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
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
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            let request = generate_new_child_sa_request(config, &mut data, ts_i, ts_r)?;
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
        hard: bool,
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            let child_sas = data.child_sas.to_mut();
            let index = child_sas.iter().position(|child_sa| child_sa.spi() == spi);
            if let Some(index) = index {
                let child_sa = child_sas.swap_remove(index);
                if hard {
                    debug!(spi = ?spi, "sending delete Child SA request");
                    let request = generate_delete_child_sa_request(&data, &child_sa)?;
                    Self::send_message(sender.clone(), &mut data, request)?;
                } else {
                    debug!(spi = ?spi, "sending rekey Child SA request");
                    let request = generate_rekey_child_sa_request(&mut data, child_sa)?;
                    Self::send_message(sender.clone(), &mut data, request)?;
                }
            } else {
                // No matching Child SA, no need to do anything
                return Ok(self);
            }

            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        if hard {
            Ok(Box::new(state::DeleteChildSaRequestSent {}))
        } else {
            Ok(Box::new(state::RekeyChildSaRequestSent {}))
        }
    }

    async fn handle_rekey_ike_sa(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            let request = generate_rekey_ike_sa_request(config, &mut data)?;
            Self::send_message(sender.clone(), &mut data, request)?;
            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(Box::new(state::RekeyIkeSaRequestSent {}))
    }

    async fn handle_dpd(
        self: Box<Self>,
        _config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            let request = generate_dpd_request(&data)?;
            Self::send_message(sender.clone(), &mut data, request)?;
            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(Box::new(state::DpdRequestSent {}))
    }

    #[cfg(test)]
    fn as_any(&self) -> &(dyn std::any::Any + Send) {
        self
    }
}
