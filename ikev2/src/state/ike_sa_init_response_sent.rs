use crate::{
    config::Config,
    message::{
        Message,
        num::{ExchangeType, MessageFlags, Num, PayloadType},
        payload::{self, Payload},
        serialize::{Deserialize, Serialize},
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ChosenProposal, ControlMessage, LarvalChildSa},
    state::{self, State, StateData},
};
use anyhow::Result;
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
        request: &Message,
    ) -> Result<(Message, ChildSa)>
    where
        D: Deref<Target = StateData>,
    {
        let last = request
            .payloads()
            .last()
            .ok_or_else(|| anyhow::anyhow!("no payload"))?;
        if !matches!(last.ty().assigned(), Some(PayloadType::SK)) {
            return Err(anyhow::anyhow!("no SK payload"));
        }
        let sk: &payload::Sk = last.try_into()?;

        let keys = data.keys.as_ref().unwrap();

        let payloads = sk.decrypt(
            data.chosen_proposal.as_ref().unwrap().cipher(),
            &keys.protecting.ei,
        )?;

        debug!(payloads = ?&payloads, "encrypted payloads");

        let auth = payloads
            .iter()
            .find(|payload| matches!(payload.ty().assigned(), Some(PayloadType::AUTH)))
            .ok_or_else(|| anyhow::anyhow!("no AUTH payload"))?;
        let auth: &payload::Auth = auth.try_into()?;

        let id_i = payloads
            .iter()
            .find(|payload| matches!(payload.ty().assigned(), Some(PayloadType::IDi)))
            .ok_or_else(|| anyhow::anyhow!("no ID payload"))?;
        let id_i: &payload::Id = id_i.try_into()?;

        let sa_i = payloads
            .iter()
            .find(|payload| matches!(payload.ty().assigned(), Some(PayloadType::SA)))
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;
        let sa_i: &payload::Sa = sa_i.try_into()?;

        let ts_i = payloads
            .iter()
            .find(|payload| matches!(payload.ty().assigned(), Some(PayloadType::TSi)))
            .ok_or_else(|| anyhow::anyhow!("no TSi payload"))?;
        let ts_i: &payload::Ts = ts_i.try_into()?;

        let ts_r = payloads
            .iter()
            .find(|payload| matches!(payload.ty().assigned(), Some(PayloadType::TSr)))
            .ok_or_else(|| anyhow::anyhow!("no TSr payload"))?;
        let ts_r: &payload::Ts = ts_r.try_into()?;

        if data.auth_verify(config, id_i, auth)? {
            info!(
                spi = &data.peer_spi.as_ref().unwrap()[..],
                "responder authenticated initiator"
            );
        } else {
            return Err(anyhow::anyhow!("authentication failed"));
        }

        let mut message = Message::new(
            request.spi_i(),
            &data.spi,
            Num::Assigned(ExchangeType::IKE_AUTH.into()),
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
            return Err(anyhow::anyhow!("no proposal to send"));
        }

        let chosen_proposal = ChosenProposal::negotiate(&proposals, sa_i.proposals())
            .ok_or_else(|| anyhow::anyhow!("no matching proposal"))?;
        let child_sa = larval_child_sa.build(
            &chosen_proposal,
            &keys.deriving.d,
            data.nonce_i.as_ref().unwrap(),
            data.nonce_r.as_ref().unwrap(),
        )?;
        let proposal = chosen_proposal.proposal(
            1,
            Num::Assigned(chosen_proposal.protocol().into()),
            child_sa.spi(),
        );

        let payloads = [
            Payload::new(
                Num::Assigned(PayloadType::SA.into()),
                payload::Content::Sa(payload::Sa::new(Some(proposal))),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::AUTH.into()),
                payload::Content::Auth(data.auth_sign(config)?),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::IDr.into()),
                payload::Content::Id(config.id().clone()),
                true,
            ),
        ];

        message.add_payloads([Payload::new(
            Num::Assigned(PayloadType::SK.into()),
            payload::Content::Sk(payload::Sk::encrypt(
                data.chosen_proposal.as_ref().unwrap().cipher(),
                &keys.protecting.er,
                &payloads,
            )?),
            true,
        )]);
        Ok((message, child_sa))
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
    ) -> Result<Box<dyn State>> {
        let serialized_request = message;
        let request = Message::deserialize(&mut message)?;
        match request.exchange().assigned() {
            Some(ExchangeType::IKE_AUTH) => {
                {
                    let data = data.read().await;
                    if data.message_verify(serialized_request)? {
                        debug!("checksum verified");
                    } else {
                        return Err(anyhow::anyhow!("checksum mismatch"));
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
            exchange => {
                return Err(anyhow::anyhow!("unknown exchange {:?}", exchange));
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
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}
