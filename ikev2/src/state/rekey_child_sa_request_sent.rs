use crate::{
    config::Config,
    message::{
        EspSpi, ProtectedMessage,
        num::{ExchangeType, MessageFlags, PayloadType},
        payload,
        proposal::Proposal,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage},
    state::{
        CreateChildSa, DeleteChildSa, Established, ProtocolError, SendProtectedMessage, State,
        StateData, StateDataCache, StateError, VerifyMessage, generate_informational_error,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct RekeyChildSaRequestSent;

impl SendProtectedMessage for RekeyChildSaRequestSent {}
impl VerifyMessage for RekeyChildSaRequestSent {}
impl CreateChildSa for RekeyChildSaRequestSent {}
impl DeleteChildSa for RekeyChildSaRequestSent {}

impl std::fmt::Display for RekeyChildSaRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("RekeyChildSaRequestSent").finish()
    }
}

fn handle_create_child_sa_response(
    config: &Config,
    data: &mut StateDataCache<'_>,
    response: &ProtectedMessage,
) -> Result<(), StateError> {
    let response = response
        .unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(|e| StateError::Protocol(e.into()))?;

    debug!(response = ?&response, "received protected response");

    let sa: &payload::Sa = response
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let nonce_r: &payload::Nonce = response
        .get(PayloadType::NONCE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::NONCE))?;

    // Need to take it out of `data` first, as `data` is still
    // immutably referenced in the below if block
    let creating_child_sa = data.creating_child_sa.to_mut().take();

    if let Some(creating_child_sa) = creating_child_sa {
        // For rekeying, only check the peer TSi/TSr match the current one
        let ts_i: &payload::Ts = response
            .get(PayloadType::TSi)
            .ok_or(ProtocolError::MissingPayload(PayloadType::TSi))?;
        if config.strict_ts() {
            TrafficSelector::exact_match(
                Some(&creating_child_sa.ts_i),
                ts_i.traffic_selectors(),
            )
        } else {
            TrafficSelector::negotiate(Some(&creating_child_sa.ts_i), ts_i.traffic_selectors())
        }
        .ok_or(ProtocolError::TrafficSelectorUnacceptable)?;

        let ts_r: &payload::Ts = response
            .get(PayloadType::TSr)
            .ok_or(ProtocolError::MissingPayload(PayloadType::TSr))?;
        if config.strict_ts() {
            TrafficSelector::exact_match(
                Some(&creating_child_sa.ts_r),
                ts_r.traffic_selectors(),
            )
        } else {
            TrafficSelector::negotiate(Some(&creating_child_sa.ts_r), ts_r.traffic_selectors())
        }
        .ok_or(ProtocolError::TrafficSelectorUnacceptable)?;

        // For rekeying, only check the peer proposal matches the current one
        let proposals = &creating_child_sa.proposals;

        let proposal = Proposal::negotiate(proposals, sa.proposals())
            .ok_or(ProtocolError::NoProposalChosen)?;
        info!(proposal = ?&proposal, "negotiated proposal");
        let chosen_proposal = ChosenProposal::new(&proposal)?;

        let ke: Option<&payload::Ke> = response.get(PayloadType::KE);

        let child_sa = creating_child_sa.build(
            &chosen_proposal,
            &data.keys()?.derivation.d,
            (*data.nonce_i).as_ref().expect("nonce should be set"),
            nonce_r.nonce(),
            ke.map(|ke| ke.ke_data()),
        )?;
        *data.created_child_sa.to_mut() = Some(Box::new(child_sa));

        if let Some(rekeyed_child_sa) = data.rekeying_child_sa.to_mut().take() {
            *data.rekeyed_child_sa.to_mut() = Some(rekeyed_child_sa);
        }
    }

    *data.last_request.to_mut() = None;

    Ok(())
}

impl RekeyChildSaRequestSent {
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
                handle_create_child_sa_response(config, data, &response)?;

                if let Some(child_sa) = data.created_child_sa.to_mut().take() {
                    Self::create_child_sa(sender.clone(), data, child_sa)?;
                }
                if let Some(child_sa) = data.rekeyed_child_sa.to_mut().take() {
                    Self::delete_child_sa(sender.clone(), child_sa)?;
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
impl State for RekeyChildSaRequestSent {
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

            if let Err(e) = Self::handle_response(config, sender.clone(), &mut data, message).await
            {
                debug!(error = ?e, "error processing CREATE_CHILD_SA response for rekeying Child SA");
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

    #[cfg(test)]
    fn as_any(&self) -> &(dyn std::any::Any + Send) {
        self
    }
}
