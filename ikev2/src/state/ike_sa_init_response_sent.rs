use crate::{
    config::{Config, ConfigError},
    message::{
        Message, ProtectedMessage,
        num::{ExchangeType, MessageFlags, PayloadType},
        payload::{self, Payload},
        serialize::{Deserialize, Serialize},
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ChosenProposal, ControlMessage, LarvalChildSa, ProtocolError},
    state::{self, State, StateData, StateError},
};
use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc::UnboundedSender;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct IkeSaInitResponseSent;

impl std::fmt::Display for IkeSaInitResponseSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("IkeSaInitResponseSent").finish()
    }
}

impl IkeSaInitResponseSent {
    fn handle_ike_auth_request<D>(
        config: &Config,
        data: &D,
        request: &ProtectedMessage,
    ) -> Result<(ProtectedMessage, ChildSa), StateError>
    where
        D: Deref<Target = StateData>,
    {
        let request = request.unprotect(
            data.chosen_proposal()?.cipher(),
            &data.keys()?.protecting.ei,
        )?;

        debug!(request = ?&request, "unprotected request");

        let auth: &payload::Auth = request
            .get(PayloadType::AUTH)
            .ok_or(ProtocolError::MissingPayload(PayloadType::AUTH))?;

        let id_i: &payload::Id = request
            .get(PayloadType::IDi)
            .ok_or(ProtocolError::MissingPayload(PayloadType::IDi))?;

        let sa: &payload::Sa = request
            .get(PayloadType::SA)
            .ok_or(ProtocolError::MissingPayload(PayloadType::SA))?;

        let ts_i: &payload::Ts = request
            .get(PayloadType::TSi)
            .ok_or(ProtocolError::MissingPayload(PayloadType::TSi))?;

        let ts_r: &payload::Ts = request
            .get(PayloadType::TSr)
            .ok_or(ProtocolError::MissingPayload(PayloadType::TSr))?;

        let authenticated = if let Some(psk) = config.psk() {
            let prf = data.chosen_proposal()?.prf();
            let signed_data = data.auth_data_for_verification(id_i)?;
            Ok(auth.verify_with_psk(prf, psk, &signed_data)?)
        } else {
            Err(ConfigError::NoPSK)
        };

        if authenticated? {
            info!(
                spi = &data.peer_spi.as_ref().unwrap()[..],
                "responder authenticated initiator"
            );
        } else {
            return Err(ProtocolError::AuthenticationFailed.into());
        }

        let mut response = Message::new(
            request.spi_i(),
            &data.spi,
            ExchangeType::IKE_AUTH.into(),
            MessageFlags::R,
            request.id(),
        );

        let larval_child_sa = LarvalChildSa::new(
            config,
            ts_r.traffic_selectors().next().unwrap(),
            ts_i.traffic_selectors().next().unwrap(),
        )?;
        let proposals: Vec<_> = config
            .ipsec_proposals(larval_child_sa.spi.as_ref().unwrap())
            .collect();
        if proposals.is_empty() {
            return Err(ConfigError::NoProposalsSet.into());
        }

        let chosen_proposal = ChosenProposal::negotiate(&proposals, sa.proposals())?;
        let child_sa = larval_child_sa.build(
            &chosen_proposal,
            &data.keys()?.deriving.d,
            data.nonce_i.as_ref().unwrap(),
            data.nonce_r.as_ref().unwrap(),
        )?;
        let proposal =
            chosen_proposal.proposal(1, chosen_proposal.protocol().into(), child_sa.spi());

        let auth = if let Some(psk) = config.psk() {
            let prf = data.chosen_proposal()?.prf();
            let signed_data = data.auth_data_for_signing(config.id())?;
            Ok(payload::Auth::sign_with_psk(prf, psk, &signed_data)?)
        } else {
            Err(ConfigError::NoPSK)
        };
        let auth = auth?;

        response.add_payloads([
            Payload::new(
                PayloadType::SA.into(),
                payload::Content::Sa(payload::Sa::new(Some(proposal))),
                true,
            ),
            Payload::new(PayloadType::AUTH.into(), payload::Content::Auth(auth), true),
            Payload::new(
                PayloadType::IDr.into(),
                payload::Content::Id(config.id().clone()),
                true,
            ),
        ]);

        let response = response.protect(
            data.chosen_proposal()?.cipher(),
            &data.keys()?.protecting.er,
        )?;

        Ok((response, child_sa))
    }
}

#[async_trait]
impl State for IkeSaInitResponseSent {
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
            Some(ExchangeType::IKE_AUTH) => {
                {
                    let data = data.read().await;
                    if data.message_verify(serialized_request)? {
                        debug!("checksum verified");
                    } else {
                        return Err(ProtocolError::IntegrityCheckFailed.into());
                    }
                }

                let (response, child_sa) = {
                    let data = data.read().await;

                    Self::handle_ike_auth_request(config, &data, &request)?
                };

                debug!(child_sa = ?&child_sa, "Child SA created");

                let len = response.size()?;
                let mut buf = BytesMut::with_capacity(len);
                response.serialize(&mut buf)?;

                {
                    let data = data.read().await;
                    if let Some(checksum) = data.message_sign(&buf)? {
                        buf.extend_from_slice(&checksum);
                    }
                }

                sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?;
                sender.unbounded_send(ControlMessage::CreateChildSa(Box::new(child_sa)))?;
                Ok(Box::new(state::Established {}))
            }
            _ => {
                return Err(ProtocolError::UnexpectedExchange(request.exchange()).into());
            }
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
}
