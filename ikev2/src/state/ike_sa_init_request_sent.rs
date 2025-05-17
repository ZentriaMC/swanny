use crate::{
    config::Config,
    crypto::{self, GroupPrivateKey},
    message::{
        Message, Spi,
        num::{ExchangeType, MessageFlags, Num, PayloadType},
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
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) struct IkeSaInitRequestSent {}

impl IkeSaInitRequestSent {
    fn handle_ike_sa_init_response<D>(
        data: &D,
        response: &Message,
    ) -> Result<(ChosenProposal, Keys)>
    where
        D: Deref<Target = StateData>,
    {
        let sa: &payload::Sa = response
            .get(PayloadType::SA)
            .ok_or_else(|| anyhow::anyhow!("no SA payload"))?;

        let ke: &payload::Ke = response
            .get(PayloadType::KE)
            .ok_or_else(|| anyhow::anyhow!("no KE payload"))?;

        let nonce: &payload::Nonce = response
            .get(PayloadType::NONCE)
            .ok_or_else(|| anyhow::anyhow!("no NONCE payload"))?;

        let proposal = if let Some(proposal) = sa.proposals().next() {
            proposal
        } else {
            return Err(anyhow::anyhow!("no proposals received"));
        };

        let chosen_proposal = ChosenProposal::new(proposal)?;

        let private_key = data.private_key.as_ref().unwrap();
        if ke.dh_group() != Num::Assigned(private_key.group().id()) {
            return Err(anyhow::anyhow!("unmatched DH group"));
        }

        let n_i = data.nonce.as_ref().unwrap();
        let n_r = nonce.nonce();
        let skeyseed =
            crypto::generate_skeyseed(chosen_proposal.prf(), n_i, n_r, private_key, ke.ke_data())?;
        eprintln!("SKEYSEED generated: {:?}", &skeyseed);

        let keys = chosen_proposal.generate_keys(
            &skeyseed,
            n_i,
            n_r,
            response.spi_i(),
            response.spi_r(),
        )?;
        eprintln!("Keys generated: {:?}", &keys);

        Ok((chosen_proposal, keys))
    }

    fn generate_ike_auth_request<D>(
        data: &D,
        chosen_proposal: &ChosenProposal,
        keys: &Keys,
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
        let proposals: Vec<_> = data.config.ipsec_proposals(&larval_child_sa.spi).collect();
        if proposals.is_empty() {
            return Err(anyhow::anyhow!("no proposal to send"));
        }

        let payloads = [Payload::new(
            Num::Assigned(PayloadType::SA),
            payload::Content::Sa(payload::Sa::new(proposals)),
            true,
        )];

        message.add_payloads([Payload::new(
            Num::Assigned(PayloadType::SK),
            payload::Content::Sk(payload::Sk::encrypt(
                chosen_proposal.cipher(),
                &keys.ei,
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
        data: Arc<RwLock<StateData>>,
        mut message: &[u8],
    ) -> Result<Box<dyn State>> {
        let message = Message::deserialize(&mut message)?;
        match message.exchange() {
            Num::Assigned(ExchangeType::IKE_SA_INIT) => {
                let inner = data.read().await;

                let (chosen_proposal, keys) = Self::handle_ike_sa_init_response(&inner, &message)?;

                let request = Self::generate_ike_auth_request(
                    &inner,
                    &chosen_proposal,
                    &keys,
                    message.spi_r(),
                )?;

                drop(inner);

                let mut inner = data.write().await;
                inner.chosen_proposal = Some(chosen_proposal);
                inner.keys = Some(keys);
                inner.peer_spi = Some(request.spi_r().to_owned());
                inner.message_id = request.id();

                let len = request.size()?;
                let mut buf = BytesMut::with_capacity(len);
                request.serialize(&mut buf)?;
                inner
                    .sender
                    .unbounded_send(ControlMessage::IkeMessage(buf.to_vec()))?;

                Ok(Box::new(state::IkeAuthRequestSent {}))
            }
            exchange => {
                return Err(anyhow::anyhow!("unknown exchange {:?}", exchange));
            }
        }
    }

    async fn handle_acquire(
        self: Box<Self>,
        _data: Arc<RwLock<StateData>>,
        _ts_i: &TrafficSelector,
        _ts_r: &TrafficSelector,
        _index: u32,
    ) -> Result<Box<dyn State>> {
        Ok(self)
    }
}
