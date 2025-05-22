use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::IpAddr;
use swanny_ikev2::{
    config::{Config, ConfigBuilder},
    message::{
        Message,
        num::{DhId, EncrId, EsnId, IdType, IntegId, Num, PrfId, Protocol, TrafficSelectorType},
        payload::Id,
        serialize::Deserialize,
        traffic_selector::TrafficSelector,
    },
    sa::{ControlMessage, IkeSa},
};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn create_config(id: impl AsRef<[u8]>) -> Config {
    let builder = ConfigBuilder::default();
    builder
        .ike_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(256))
                .prf(PrfId::PRF_HMAC_SHA1)
                .integrity(IntegId::AUTH_HMAC_SHA1_96)
                .dh(DhId::SECP256R1)
                .esn(EsnId::NoEsn)
                .esn(EsnId::Esn)
        })
        .ipsec_protocol(Protocol::ESP)
        .ipsec_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(256))
                .prf(PrfId::PRF_HMAC_SHA1)
                .integrity(IntegId::AUTH_HMAC_SHA1_96)
        })
        .psk(b"test test test")
        .build(Id::new(
            Num::Assigned(IdType::ID_KEY_ID.into()),
            id.as_ref(),
        ))
}

fn create_traffic_selector(address: &IpAddr) -> TrafficSelector {
    TrafficSelector::new(
        Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE.into()),
        0,
        &address,
        &address,
        0,
        0,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let config = create_config(b"initiator");
    let (initiator, mut messages_i) = IkeSa::new(&config).expect("unable to create IKE SA");

    let config = create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    let initiator2 = initiator.clone();
    let responder2 = responder.clone();

    let handle = tokio::spawn(async move {
        let mut pending_operations = FuturesUnordered::new();

        loop {
            futures::select! {
                message = messages_i.select_next_some() => {
                    match message {
                        ControlMessage::IkeMessage(message) => {
                            let serialized_message = message.as_slice();
                            let mut buf = serialized_message;
                            let message = Message::deserialize(&mut buf)
                                .expect("unable to deserialize message");
                            eprintln!("INITIATOR: {:?}", message);
                            pending_operations.push(responder2.handle_message(serialized_message.to_vec()));
                        }
                        ControlMessage::CreateChildSa(child_sa) => {
                            eprintln!("INITIATOR: created Child SA {:?}", child_sa);
                        }
                    }
                },
                message = messages_r.select_next_some() => {
                    match message {
                        ControlMessage::IkeMessage(message) => {
                            let serialized_message = message.as_slice();
                            let mut buf = serialized_message;
                            let message = Message::deserialize(&mut buf)
                                .expect("unable to deserialize message");
                            eprintln!("RESPONDER: {:?}", message);
                            pending_operations.push(initiator2.handle_message(serialized_message.to_vec()));
                        }
                        ControlMessage::CreateChildSa(child_sa) => {
                            eprintln!("RESPONDER: created Child SA {:?}", child_sa);
                        }
                    }
                },
                res = pending_operations.select_next_some() => {
                    eprintln!("{:?}", res);
                },
            };
        }
    });

    let initiator_addr: IpAddr = "192.168.1.2".parse().unwrap();
    let responder_addr: IpAddr = "192.168.1.3".parse().unwrap();
    let ts_i = create_traffic_selector(&initiator_addr);
    let ts_r = create_traffic_selector(&responder_addr);
    initiator
        .handle_acquire(ts_i, ts_r, 1)
        .await
        .expect("unable to handle acquire");

    handle.await.unwrap();
    Ok(())
}
