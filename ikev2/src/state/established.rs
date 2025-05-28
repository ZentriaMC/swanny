use crate::{
    config::Config,
    message::{
        EspSpi, Message, ProtectedMessage,
        num::{ExchangeType, MessageFlags, PayloadType, Protocol},
        payload::{self, Payload},
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::ControlMessage,
    state::{
        self, ChildSa, DeleteChildSa, InvalidStateError, ProtocolError, SendProtectedMessage,
        State, StateData, StateDataCache, StateError,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::RwLock;
use tracing::debug;

pub struct Established;

impl SendProtectedMessage for Established {}
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

fn generate_delete_child_request(
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

    request
        .protect(data.chosen_proposal()?.cipher(), data.encrypting_key()?)
        .map_err(Into::into)
}

#[async_trait]
impl State for Established {
    async fn handle_message(
        self: Box<Self>,
        _config: &Config,
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

                    if data.message_verify(serialized_request)? {
                        debug!("checksum verified");
                    } else {
                        return Err(ProtocolError::IntegrityCheckFailed.into());
                    }

                    handle_informational_request(&mut data, &request)?;

                    let response = generate_informational_response(&mut data, &request)?;

                    Self::send_message(sender.clone(), &mut data, response)?;

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
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
            }
        }
        Ok(self)
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
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        spi: &EspSpi,
    ) -> Result<Box<dyn State>, StateError> {
        let default = StateData::default();
        let default = StateDataCache::new_borrowed(&default);

        let cache = {
            let data = data.read().await;
            let mut data = StateDataCache::new_borrowed(&data);

            let request = generate_delete_child_request(&mut data, spi)?;

            Self::send_message(sender.clone(), &mut data, request)?;
            data.swap(&default)
        };

        {
            let mut data = data.write().await;
            cache.write_into(&mut data);
        }

        Ok(Box::new(state::DeleteChildRequestSent {}))
    }
}
