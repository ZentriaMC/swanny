use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_xfrm::{address::Address, XfrmMessage, XFRMNLGRP_ACQUIRE, XFRMNLGRP_EXPIRE};
use netlink_proto::sys::{protocols::NETLINK_XFRM, AsyncSocket, SocketAddr};
use std::net::IpAddr;
use std::str::FromStr;
use swanny_ikev2::{
    config::Config,
    message::{
        num::{Num, TrafficSelectorType},
        traffic_selector::TrafficSelector,
    },
    sa::{ControlMessage, IkeSa},
};
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn create_config() -> Config {
    use swanny_ikev2::config::ConfigBuilder;
    use swanny_ikev2::message::num::{DhId, EncrId, IntegId, PrfId, Protocol};

    ConfigBuilder::default()
        .ike_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                .prf(PrfId::PRF_HMAC_SHA1)
                .integrity(IntegId::AUTH_HMAC_SHA1_96)
                .dh(DhId::MODP2048)
        })
        .ipsec_protocol(Protocol::ESP)
        .ipsec_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                .prf(PrfId::PRF_HMAC_SHA1)
                .integrity(IntegId::AUTH_HMAC_SHA1_96)
                .dh(DhId::MODP2048)
        })
        .build()
}

fn create_traffic_selector(
    family: u16,
    proto: u8,
    addr: &Address,
    port: u16,
) -> Result<TrafficSelector> {
    match family {
        2 => Ok(TrafficSelector::new(
            Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE),
            proto,
            &IpAddr::V4(addr.to_ipv4()),
            &IpAddr::V4(addr.to_ipv4()),
            port,
            port,
        )),
        10 => Ok(TrafficSelector::new(
            Num::Assigned(TrafficSelectorType::TS_IPV6_ADDR_RANGE),
            proto,
            &IpAddr::V6(addr.to_ipv6()),
            &IpAddr::V6(addr.to_ipv6()),
            port,
            port,
        )),
        _ => Err(anyhow::anyhow!("unsupported address family")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let (mut connection, _handle, mut xfrm_messages) =
        netlink_proto::new_connection::<XfrmMessage>(NETLINK_XFRM)?;

    let addr = SocketAddr::new(0, XFRMNLGRP_ACQUIRE | XFRMNLGRP_EXPIRE);

    connection
        .socket_mut()
        .socket_mut()
        .bind(&addr)
        .expect("failed to bind");

    tokio::spawn(connection);

    let config = create_config();

    let (ike_sa, mut ike_sa_messages) = IkeSa::new(&config)?;

    let mut pending_operations = FuturesUnordered::new();

    loop {
        futures::select! {
            netlink_message = xfrm_messages.select_next_some() => {
                let (netlink_message, _) = netlink_message;
                let payload = netlink_message.payload;
                if let NetlinkPayload::InnerMessage(xfrm_message) = payload {
                    match xfrm_message {
                        XfrmMessage::Acquire(acquire) => {
                            let ts_i = create_traffic_selector(
                                acquire.acquire.selector.family,
                                acquire.acquire.selector.proto,
                                &acquire.acquire.selector.daddr,
                                acquire.acquire.selector.dport,
                            )?;
                            let ts_r = create_traffic_selector(
                                acquire.acquire.selector.family,
                                acquire.acquire.selector.proto,
                                &acquire.acquire.selector.saddr,
                                acquire.acquire.selector.sport,
                            )?;
                            pending_operations.push(ike_sa.handle_acquire(ts_i, ts_r, acquire.acquire.policy.index));
                        },
                        XfrmMessage::Expire(_expire) => {
                        },
                        _ => info!("Other XFRM event message - {:?}", xfrm_message),
                    };
                } else {
                    info!("Other netlink message - {:?}", payload);
                }
            }
            ike_sa_message = ike_sa_messages.select_next_some() => {
                match ike_sa_message {
                    ControlMessage::IkeMessage(message) => {
                        info!("IKE SA message - {:?}", message);
                    },
                }
            },
            result = pending_operations.select_next_some() => {
                debug!("result: {:?}", result);
            }
        }
    }
}
