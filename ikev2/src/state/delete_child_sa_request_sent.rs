use crate::{
    config::Config,
    message::{
        EspSpi, ProtectedMessage,
        num::{ExchangeType, MessageFlags, PayloadType},
        payload,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::ControlMessage,
    state::{
        DeleteChildSa, Established, ProtocolError, SendProtectedMessage, State, StateData,
        StateDataCache, StateError, VerifyMessage, generate_informational_error,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

pub struct DeleteChildSaRequestSent;

impl SendProtectedMessage for DeleteChildSaRequestSent {}
impl VerifyMessage for DeleteChildSaRequestSent {}
impl DeleteChildSa for DeleteChildSaRequestSent {}

impl std::fmt::Display for DeleteChildSaRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("DeleteChildSaRequestSent").finish()
    }
}

fn handle_informational_response(
    data: &mut StateDataCache<'_>,
    response: &ProtectedMessage,
) -> Result<(), StateError> {
    let response = response
        .unprotect(data.decrypting_key()?, data.chosen_proposal()?.integ())
        .map_err(|e| StateError::Protocol(e.into()))?;

    debug!(response = ?&response, "received protected response");

    let delete: Option<&payload::Delete> = response.get(PayloadType::DELETE);
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
    *data.last_request.to_mut() = None;
    Ok(())
}

impl DeleteChildSaRequestSent {
    async fn handle_response(
        _config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: &mut StateDataCache<'_>,
        mut message: &[u8],
    ) -> Result<(), StateError> {
        let serialized_response = message;
        let response = ProtectedMessage::deserialize(&mut message)
            .map_err(|e| StateError::Protocol(e.into()))?;

        Self::verify_message(data, serialized_response)?;

        if response.flags().contains(MessageFlags::I) {
            debug!(exchange = ?response.exchange(), "crossing exchange detected, responding with an error");
            let response = generate_informational_error(data, ProtocolError::TemporaryFailure, response.id())?;
            Self::send_message(sender.clone(), data, response)?;
            return Ok(());
        }

        if response.id().wrapping_add(1) != *data.message_id {
            return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
        }

        match response.exchange().assigned() {
            Some(ExchangeType::INFORMATIONAL) => {
                handle_informational_response(data, &response)?;

                for child_sa in data.deleted_child_sas.iter() {
                    Self::delete_child_sa(sender.clone(), child_sa.clone())?;
                }
                data.deleted_child_sas.to_mut().clear();
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(response.exchange()).into());
            }
        }

        Ok(())
    }
}

#[async_trait]
impl State for DeleteChildSaRequestSent {
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
                debug!(error = ?e, "error processing INFORMATIONAL response for deleting Child SA");
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
