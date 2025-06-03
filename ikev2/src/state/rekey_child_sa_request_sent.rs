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
    sa::ControlMessage,
    state::{
        Established, ProtocolError, RekeyChildSa, SendProtectedMessage, State, StateData,
        StateDataCache, StateError, VerifyMessage,
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
impl RekeyChildSa for RekeyChildSaRequestSent {}

impl std::fmt::Display for RekeyChildSaRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("RekeyChildSaRequestSent").finish()
    }
}

fn handle_create_child_sa_response(
    data: &mut StateDataCache<'_>,
    response: &ProtectedMessage,
) -> Result<(), StateError> {
    let response = response.unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())?;

    debug!(response = ?&response, "received protected response");

    let sa: &payload::Sa = response
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let nonce_r: &payload::Nonce = response
        .get(PayloadType::NONCE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::NONCE))?;

    // Need to take it out of `data` first, as `data` is still
    // immutably referenced in the below if block
    let rekeyed_child_sa = data.rekeyed_child_sa.to_mut().take();

    let child_sa = if let Some(mut child_sa) = rekeyed_child_sa {
        let _ts_i: &payload::Ts = response
            .get(PayloadType::TSi)
            .ok_or(ProtocolError::MissingPayload(PayloadType::TSi))?;

        let _ts_r: &payload::Ts = response
            .get(PayloadType::TSr)
            .ok_or(ProtocolError::MissingPayload(PayloadType::TSr))?;

        // For rekeying, only check the peer proposal matches the current one
        let proposal = child_sa.chosen_proposal().proposal(
            1,
            child_sa.chosen_proposal().protocol().into(),
            child_sa.spi(),
        );
        let proposal = Proposal::negotiate(Some(&proposal), sa.proposals())
            .ok_or(ProtocolError::NoProposalChosen)?;
        info!(proposal = ?&proposal, "negotiated proposal");

        let ke: Option<&payload::Ke> = response.get(PayloadType::KE);

        let _ = child_sa.rekey(
            &data.keys()?.derivation.d,
            (*data.nonce_i).as_ref().expect("nonce should be set"),
            nonce_r.nonce(),
            ke.map(|ke| ke.ke_data()),
        )?;
        Some(child_sa)
    } else {
        None
    };

    *data.rekeyed_child_sa.to_mut() = child_sa;

    Ok(())
}

impl RekeyChildSaRequestSent {
    async fn handle_response(
        self: Box<Self>,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        response: ProtectedMessage,
        serialized_response: &[u8],
    ) -> Result<Box<dyn State>, StateError> {
        match response.exchange().assigned() {
            Some(ExchangeType::CREATE_CHILD_SA) => {
                let default = StateData::default();
                let default = StateDataCache::new_borrowed(&default);

                let cache = {
                    let data = data.read().await;
                    let mut data = StateDataCache::new_borrowed(&data);

                    Self::verify_message(&data, serialized_response)?;

                    handle_create_child_sa_response(&mut data, &response)?;

                    if let Some(child_sa) = data.rekeyed_child_sa.to_mut().take() {
                        Self::rekey_child_sa(sender.clone(), &mut data, child_sa.clone())?;
                    }

                    data.swap(&default)
                };

                {
                    let mut data = data.write().await;
                    cache.write_into(&mut data);
                }

                Ok(Box::new(Established {}))
            }
            _ => Err(ProtocolError::UnexpectedExchange(response.exchange()).into()),
        }
    }
}

#[async_trait]
impl State for RekeyChildSaRequestSent {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>, StateError> {
        let serialized_message = message;
        let message = ProtectedMessage::deserialize(&mut message)?;
        if message.flags().contains(MessageFlags::I) {
            // Divert to the Established state if a request is
            // received while a response is expected
            Box::new(Established {})
                .handle_message(config, sender, data, serialized_message)
                .await
        } else {
            self.handle_response(sender, data, message, serialized_message)
                .await
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
