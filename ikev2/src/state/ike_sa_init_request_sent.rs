use crate::{
    config::Config,
    crypto,
    message::{
        Message, ProtectedMessage, Spi,
        num::{ExchangeType, MessageFlags, PayloadType},
        payload::{self, Payload},
        serialize::{Deserialize, Serialize},
        traffic_selector::TrafficSelector,
    },
    sa::{ChosenProposal, ControlMessage, Keys},
    state::{self, State, StateData},
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc::UnboundedSender;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

pub struct IkeSaInitRequestSent;

impl std::fmt::Display for IkeSaInitRequestSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("IkeSaInitRequestSent").finish()
    }
}

impl IkeSaInitRequestSent {
    fn handle_ike_sa_init_response<D>(
        data: &D,
        response: &Message,
    ) -> Result<(ChosenProposal, Keys, Vec<u8>)>
    where
        D: Deref<Target = StateData>,
    {
        let sa_r: &payload::Sa = response
            .get(PayloadType::SA)
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;

        let ke_r: &payload::Ke = response
            .get(PayloadType::KE)
            .ok_or_else(|| anyhow::anyhow!("no KE payload"))?;

        let nonce_r: &payload::Nonce = response
            .get(PayloadType::NONCE)
            .ok_or_else(|| anyhow::anyhow!("no NONCE payload"))?;

        let proposal = if let Some(proposal) = sa_r.proposals().next() {
            proposal
        } else {
            return Err(anyhow::anyhow!("no proposals received"));
        };

        let chosen_proposal = ChosenProposal::new(proposal)?;

        let private_key = data.private_key.as_ref().unwrap();
        if ke_r.dh_group().assigned() != Some(private_key.group().id()) {
            return Err(anyhow::anyhow!("unmatched DH group"));
        }

        let nonce_i = data.nonce_i.as_ref().unwrap();
        let skeyseed = crypto::generate_skeyseed(
            chosen_proposal.prf(),
            nonce_i,
            nonce_r.nonce(),
            private_key,
            ke_r.ke_data(),
        )?;
        debug!(skeyseed = ?&skeyseed, "SKEYSEED generated");

        let keys = chosen_proposal.generate_keys(
            &skeyseed,
            nonce_i,
            nonce_r.nonce(),
            response.spi_i(),
            response.spi_r(),
        )?;
        debug!(keys = ?&keys, "keys generated");

        Ok((chosen_proposal, keys, nonce_r.nonce().to_vec()))
    }

    fn generate_ike_auth_request<D>(
        config: &Config,
        data: &D,
        spi_r: &Spi,
    ) -> Result<ProtectedMessage>
    where
        D: Deref<Target = StateData>,
    {
        let mut request = Message::new(
            &data.spi,
            spi_r,
            ExchangeType::IKE_AUTH.into(),
            MessageFlags::I,
            data.message_id.wrapping_add(1),
        );

        let larval_child_sa = data.larval_child_sa.as_ref().unwrap();
        let proposals = larval_child_sa.proposals.as_ref().unwrap();
        if proposals.is_empty() {
            return Err(anyhow::anyhow!("no proposal to send"));
        }

        request.add_payloads([
            Payload::new(
                PayloadType::SA.into(),
                payload::Content::Sa(payload::Sa::new(proposals.clone())),
                true,
            ),
            Payload::new(
                PayloadType::IDi.into(),
                payload::Content::Id(config.id().clone()),
                true,
            ),
            Payload::new(
                PayloadType::AUTH.into(),
                payload::Content::Auth(data.auth_sign(config)?),
                true,
            ),
            Payload::new(
                PayloadType::TSi.into(),
                payload::Content::Ts(payload::Ts::new(Some(
                    larval_child_sa.ts_i.as_ref().unwrap().clone(),
                ))),
                true,
            ),
            Payload::new(
                PayloadType::TSr.into(),
                payload::Content::Ts(payload::Ts::new(Some(
                    larval_child_sa.ts_r.as_ref().unwrap().clone(),
                ))),
                true,
            ),
        ]);

        let chosen_proposal = data.chosen_proposal.as_ref().unwrap();
        let keys = data.keys.as_ref().unwrap();

        let request = request.protect(chosen_proposal.cipher(), &keys.protecting.ei)?;
        Ok(request)
    }
}

#[async_trait]
impl State for IkeSaInitRequestSent {
    async fn handle_message(
        self: Box<Self>,
        config: &Config,
        sender: UnboundedSender<ControlMessage>,
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>> {
        let serialized_response = message;
        let response = Message::deserialize(&mut message)?;
        match response.exchange().assigned() {
            Some(ExchangeType::IKE_SA_INIT) => {
                let (chosen_proposal, keys, nonce_r) = {
                    let data = data.read().await;
                    Self::handle_ike_sa_init_response(&data, &response)?
                };

                {
                    let mut data = data.write().await;
                    data.chosen_proposal = Some(chosen_proposal);
                    data.keys = Some(keys);
                    data.nonce_r = Some(nonce_r);
                }

                let request = {
                    let data = data.read().await;

                    Self::generate_ike_auth_request(config, &data, response.spi_r())?
                };

                {
                    let mut data = data.write().await;
                    data.peer_spi = Some(request.spi_r().to_owned());
                    data.message_id = request.id();
                    data.ike_sa_init_response = Some(serialized_response.to_vec());
                }

                let len = request.size()?;
                let mut buf = BytesMut::with_capacity(len);
                request.serialize(&mut buf)?;

                {
                    let data = data.read().await;
                    if let Some(checksum) = data.message_sign(&buf)? {
                        buf.extend_from_slice(&checksum);
                    }
                }

                sender.unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?;

                Ok(Box::new(state::IkeAuthRequestSent {}))
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
