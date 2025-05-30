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
        CreateChildSa, Established, ProtocolError, SendProtectedMessage, State, StateData,
        StateDataCache, StateError, VerifyMessage,
    },
};
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct CreateChildSaRequestSent;

impl SendProtectedMessage for CreateChildSaRequestSent {}
impl VerifyMessage for CreateChildSaRequestSent {}
impl CreateChildSa for CreateChildSaRequestSent {}

impl std::fmt::Display for CreateChildSaRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("CreateChildSaRequestSent").finish()
    }
}

fn handle_create_child_sa_response(
    data: &mut StateDataCache<'_>,
    response: &ProtectedMessage,
) -> Result<(), StateError> {
    let response = response.unprotect(data.chosen_proposal()?.cipher(), data.decrypting_key()?)?;

    debug!(response = ?&response, "received protected response");

    let sa: &payload::Sa = response
        .get(PayloadType::SA)
        .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

    let nonce_r: &payload::Nonce = response
        .get(PayloadType::NONCE)
        .ok_or(ProtocolError::MissingPayload(PayloadType::NONCE))?;

    let larval_child_sa = data.larval_child_sa.to_mut().take();

    if let Some(larval_child_sa) = larval_child_sa {
        // Create a new Child SA, if larval_child_sa is set
        let _ts_i: &payload::Ts = response
            .get(PayloadType::TSi)
            .ok_or(ProtocolError::MissingPayload(PayloadType::TSi))?;

        let _ts_r: &payload::Ts = response
            .get(PayloadType::TSr)
            .ok_or(ProtocolError::MissingPayload(PayloadType::TSr))?;

        let proposals = &larval_child_sa.proposals;

        let proposal = Proposal::negotiate(proposals, sa.proposals())
            .ok_or(ProtocolError::NoProposalChosen)?;
        info!(proposal = ?&proposal, "negotiated proposal");
        let chosen_proposal = ChosenProposal::new(&proposal)?;

        let child_sa = larval_child_sa.build(
            &chosen_proposal,
            &data.keys()?.deriving.d,
            (*data.nonce_i).as_ref().expect("nonce should be set"),
            nonce_r.nonce(),
        )?;
        *data.created_child_sa.to_mut() = Some(Box::new(child_sa));
    } else {
        // Otherwise, rekey SA
    }

    Ok(())
}

impl CreateChildSaRequestSent {
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

                    if let Some(child_sa) = data.created_child_sa.to_mut().take() {
                        Self::create_child_sa(sender.clone(), &mut data, child_sa)?;
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
impl State for CreateChildSaRequestSent {
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
    ) -> Result<Box<dyn State>, StateError> {
        Ok(self)
    }
}
