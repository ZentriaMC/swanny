use crate::{
    config::Config,
    message::{
        EspSpi, ProtectedMessage, Spi,
        num::{ExchangeType, MessageFlags, PayloadType},
        payload,
        proposal::Proposal,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage},
    state::{
        Established, InvalidStateError, ProtocolError, SendProtectedMessage, State, StateData,
        StateDataCache, StateError, VerifyMessage, generate_informational_error,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct RekeyIkeSaRequestSent;

impl SendProtectedMessage for RekeyIkeSaRequestSent {}
impl VerifyMessage for RekeyIkeSaRequestSent {}

impl std::fmt::Display for RekeyIkeSaRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("RekeyIkeSaRequestSent").finish()
    }
}

fn handle_create_child_sa_response(
    data: &mut StateDataCache<'_>,
    response: &ProtectedMessage,
) -> Result<(), StateError> {
    let response = response
        .unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(|err| StateError::Protocol(err.into()))?;

    debug!(response = ?&response, "received IKE SA rekey response");

    let sa: &payload::Sa = response
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let ke: &payload::Ke = response
        .get(PayloadType::KE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::KE))?;

    let nonce_r: &payload::Nonce = response
        .get(PayloadType::NONCE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::NONCE))?;

    // Get peer's new SPI from SA proposal
    let peer_proposal = sa
        .proposals()
        .next()
        .ok_or(ProtocolError::NoProposalsReceived)?;
    let peer_new_spi: Spi = peer_proposal
        .spi()
        .try_into()
        .map_err(|_| ProtocolError::MissingSpi)?;

    // Get our new SPI from rekeying_ike_spi
    let our_new_spi = data
        .rekeying_ike_spi
        .to_mut()
        .take()
        .ok_or(InvalidStateError::PeerSpiNotSet)?;

    // Negotiate proposal
    let proposals: Vec<_> = vec![peer_proposal.clone()];
    let config_proposals = [data.chosen_proposal()?.proposal(1, crate::message::num::Protocol::IKE.into(), &our_new_spi[..])];
    let proposal = Proposal::negotiate(&config_proposals, proposals.iter())
        .ok_or(ProtocolError::NoProposalChosen)?;
    info!(proposal = ?&proposal, "negotiated IKE SA rekey proposal");
    let chosen_proposal = ChosenProposal::new(&proposal)?;

    // Compute SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr)
    let private_key = data
        .private_key
        .as_ref()
        .as_ref()
        .ok_or(InvalidStateError::GroupPrivateKeyNotSet)?;
    let nonce_i = (*data.nonce_i)
        .as_ref()
        .ok_or(InvalidStateError::NonceNotRecorded)?;
    let old_sk_d = &data.keys()?.derivation.d;
    let skeyseed = chosen_proposal.generate_rekey_skeyseed(
        old_sk_d,
        nonce_i,
        nonce_r.nonce(),
        private_key,
        ke.ke_data(),
    )?;
    debug!(skeyseed = ?&skeyseed, "generated rekey SKEYSEED");

    // Derive new keys (SPI order follows original initiator/responder roles)
    let is_initiator = (*data.is_initiator)
        .ok_or(InvalidStateError::InitiatorNotDetermined)?;
    let (spi_i, spi_r) = if is_initiator {
        (&our_new_spi, &peer_new_spi)
    } else {
        (&peer_new_spi, &our_new_spi)
    };
    let keys = chosen_proposal.generate_keys(&skeyseed, nonce_i, nonce_r.nonce(), spi_i, spi_r)?;
    debug!(keys = ?&keys, "generated rekey keys");

    // Atomic switchover
    info!("IKE SA rekeyed, switching to new keys");
    *data.spi.to_mut() = our_new_spi;
    *data.peer_spi.to_mut() = Some(peer_new_spi);
    *data.chosen_proposal.to_mut() = Some(chosen_proposal);
    *data.keys.to_mut() = Some(keys);
    *data.message_id.to_mut() = 0;
    *data.received_message_id.to_mut() = None;
    *data.ike_sa_init_request.to_mut() = None;
    *data.ike_sa_init_response.to_mut() = None;
    *data.last_request.to_mut() = None;
    *data.public_key.to_mut() = None;
    *data.private_key.to_mut() = None;

    Ok(())
}

impl RekeyIkeSaRequestSent {
    async fn handle_response(
        _config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        mut message: &[u8],
    ) -> Result<(), StateError> {
        let serialized_response = message;
        let response = ProtectedMessage::deserialize(&mut message)
            .map_err(|err| StateError::Protocol(err.into()))?;

        Self::verify_message(data, serialized_response)?;

        if !response.flags().contains(MessageFlags::R) {
            return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
        }

        if response.id().wrapping_add(1) != *data.message_id {
            return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
        }

        if response.flags().contains(MessageFlags::I) {
            debug!(exchange = ?response.exchange(), "crossing exchange detected, responding with an error");
            let response = generate_informational_error(data, ProtocolError::TemporaryFailure)?;
            Self::send_message(sender.clone(), data, response)?;
            return Ok(());
        }

        match response.exchange().assigned() {
            Some(ExchangeType::CREATE_CHILD_SA) => {
                handle_create_child_sa_response(data, &response)?;
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
            }
        }
        Ok(())
    }
}

#[async_trait]
impl State for RekeyIkeSaRequestSent {
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

            if let Err(err) =
                Self::handle_response(config, sender.clone(), &mut data, message).await
            {
                debug!(?err, "error processing CREATE_CHILD_SA response for rekeying IKE SA");
                return Ok(Box::new(Established {}));
            }

            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(Box::new(Established {}))
    }

    async fn handle_acquire(
        self: Box<Self>,
        _config: &Config,
        _sender: UnboundedSender<ControlMessage>,
        _data: Arc<RwLock<StateData>>,
        _ts_i: &TrafficSelector,
        _ts_r: &TrafficSelector,
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

    async fn handle_rekey_ike_sa(
        self: Box<Self>,
        _config: &Config,
        _sender: UnboundedSender<ControlMessage>,
        _data: Arc<RwLock<StateData>>,
    ) -> Result<Box<dyn State>, StateError> {
        Ok(self)
    }

    async fn handle_dpd(
        self: Box<Self>,
        _config: &Config,
        _sender: UnboundedSender<ControlMessage>,
        _data: Arc<RwLock<StateData>>,
    ) -> Result<Box<dyn State>, StateError> {
        Ok(self)
    }

    #[cfg(test)]
    fn as_any(&self) -> &(dyn std::any::Any + Send) {
        self
    }
}
