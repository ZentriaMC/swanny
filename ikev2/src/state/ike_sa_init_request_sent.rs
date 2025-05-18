use crate::{
    config::Config,
    crypto,
    message::{
        self,
        Message, Spi,
        num::{AuthType, ExchangeType, MessageFlags, Num, PayloadType},
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

pub(crate) struct IkeSaInitRequestSent {}

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
        if ke_r.dh_group() != Num::Assigned(private_key.group().id()) {
            return Err(anyhow::anyhow!("unmatched DH group"));
        }

        let nonce_i = data.nonce_i.as_ref().unwrap();
        let skeyseed =
            crypto::generate_skeyseed(chosen_proposal.prf(), nonce_i, nonce_r.nonce(), private_key, ke_r.ke_data())?;
        eprintln!("SKEYSEED generated: {:?}", &skeyseed);

        let keys = chosen_proposal.generate_keys(
            &skeyseed,
            nonce_i,
            nonce_r.nonce(),
            response.spi_i(),
            response.spi_r(),
        )?;
        eprintln!("Keys generated: {:?}", &keys);

        Ok((chosen_proposal, keys, nonce_r.nonce().to_vec()))
    }

    fn generate_ike_auth_request<D>(
        config: &Config,
        data: &D,
        spi_r: &Spi,
    ) -> Result<Message>
    where
        D: Deref<Target = StateData>,
    {
        let mut message = Message::new(
            &data.spi,
            spi_r,
            Num::Assigned(ExchangeType::IKE_AUTH),
            MessageFlags::I,
            data.message_id.wrapping_add(1),
        );

        let larval_child_sa = data.larval_child_sa.as_ref().unwrap();
        let proposals: Vec<_> = config.ipsec_proposals(&larval_child_sa.spi).collect();
        if proposals.is_empty() {
            return Err(anyhow::anyhow!("no proposal to send"));
        }

        let chosen_proposal = data.chosen_proposal.as_ref().unwrap();
        let prf = chosen_proposal.prf();
        let keys = data.keys.as_ref().unwrap();

        let signed_data = data.initiator_signed_data(config.id())?;
        let auth_data = prf.prf(prf.prf(b"foo", message::KEY_PAD)?, &signed_data)?;

        let payloads = [
            Payload::new(
                Num::Assigned(PayloadType::SA),
                payload::Content::Sa(payload::Sa::new(proposals)),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::IDi),
                payload::Content::Id(config.id().clone()),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::AUTH),
                payload::Content::Auth(payload::Auth::new(Num::Assigned(AuthType::PSK), &auth_data)),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::TSi),
                payload::Content::Ts(payload::Ts::new(Some(larval_child_sa.ts_i.clone()))),
                true,
            ),
            Payload::new(
                Num::Assigned(PayloadType::TSr),
                payload::Content::Ts(payload::Ts::new(Some(larval_child_sa.ts_r.clone()))),
                true,
            ),
        ];

        message.add_payloads([Payload::new(
            Num::Assigned(PayloadType::SK),
            payload::Content::Sk(payload::Sk::encrypt(
                chosen_proposal.cipher(),
                &keys.protecting.ei,
                &payloads,
            )?),
            true,
        )]);
        Ok(message)
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
        match response.exchange() {
            Num::Assigned(ExchangeType::IKE_SA_INIT) => {
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

                    Self::generate_ike_auth_request(
                        &config,
                        &data,
                        response.spi_r(),
                    )?

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
