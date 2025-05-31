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
        StateDataCache, StateError, VerifyMessage,
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
    let response = response.unprotect(data.chosen_proposal()?.cipher(), data.decrypting_key()?)?;

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
    Ok(())
}

impl DeleteChildSaRequestSent {
    async fn handle_response(
        self: Box<Self>,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        response: ProtectedMessage,
        serialized_response: &[u8],
    ) -> Result<Box<dyn State>, StateError> {
        match response.exchange().assigned() {
            Some(ExchangeType::INFORMATIONAL) => {
                let default = StateData::default();
                let default = StateDataCache::new_borrowed(&default);

                let cache = {
                    let data = data.read().await;
                    let mut data = StateDataCache::new_borrowed(&data);

                    Self::verify_message(&data, serialized_response)?;

                    handle_informational_response(&mut data, &response)?;

                    for child_sa in data.deleted_child_sas.iter() {
                        Self::delete_child_sa(sender.clone(), child_sa.clone())?;
                    }
                    data.deleted_child_sas.to_mut().clear();

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
impl State for DeleteChildSaRequestSent {
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
}
