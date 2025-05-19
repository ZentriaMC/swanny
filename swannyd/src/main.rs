use anyhow::Result;
use bytes::Bytes;
use futures::{
    future::Either,
    stream::{FuturesUnordered, StreamExt},
    SinkExt,
};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_xfrm::{address::Address, XfrmMessage, XFRMNLGRP_ACQUIRE, XFRMNLGRP_EXPIRE};
use netlink_proto::sys::{protocols::NETLINK_XFRM, AsyncSocket, SocketAddr};
use std::net::IpAddr;
use std::net::UdpSocket as StdUdpSocket;
use swanny_ikev2::{
    config::Config,
    message::{
        num::{IdType, Num, TrafficSelectorType},
        payload::Id,
        traffic_selector::TrafficSelector,
    },
    sa::{ControlMessage, IkeSa},
};
use tokio::net::UdpSocket;
use tokio_util::{codec::BytesCodec, udp::UdpFramed};
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
mod config;

fn create_ike_sa_config(address: &IpAddr, psk: impl AsRef<[u8]>) -> Config {
    use swanny_ikev2::config::ConfigBuilder;
    use swanny_ikev2::message::num::{DhId, EncrId, IntegId, PrfId, Protocol};

    let id = match address {
        IpAddr::V4(v4) => Id::new(Num::Assigned(IdType::ID_IPV4_ADDR), &v4.octets()[..]),
        IpAddr::V6(v6) => Id::new(Num::Assigned(IdType::ID_IPV6_ADDR), &v6.octets()[..]),
    };
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
        .psk(psk.as_ref())
        .build(id)
}

fn create_traffic_selector(
    family: u16,
    proto: u8,
    address: &Address,
    port: u16,
) -> Result<TrafficSelector> {
    match family {
        2 => Ok(TrafficSelector::new(
            Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE),
            proto,
            &IpAddr::V4(address.to_ipv4()),
            &IpAddr::V4(address.to_ipv4()),
            port,
            port,
        )),
        10 => Ok(TrafficSelector::new(
            Num::Assigned(TrafficSelectorType::TS_IPV6_ADDR_RANGE),
            proto,
            &IpAddr::V6(address.to_ipv6()),
            &IpAddr::V6(address.to_ipv6()),
            port,
            port,
        )),
        _ => Err(anyhow::anyhow!("unsupported address family")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let (mut connection, _handle, mut xfrm_messages) =
        netlink_proto::new_connection::<XfrmMessage>(NETLINK_XFRM)?;

    let nl_addr = SocketAddr::new(0, XFRMNLGRP_ACQUIRE | XFRMNLGRP_EXPIRE);

    connection
        .socket_mut()
        .socket_mut()
        .bind(&nl_addr)
        .expect("failed to bind");

    tokio::spawn(connection);

    let incoming_socket = StdUdpSocket::bind((config.address, 500))?;
    incoming_socket.set_nonblocking(true)?;
    let incoming_socket = UdpSocket::from_std(incoming_socket)?;
    let mut incoming_framed = UdpFramed::new(incoming_socket, BytesCodec::new()).fuse();

    let outgoing_socket = StdUdpSocket::bind((config.address, 0))?;
    outgoing_socket.set_nonblocking(true)?;
    let outgoing_socket = UdpSocket::from_std(outgoing_socket)?;
    let mut outgoing_framed = UdpFramed::new(outgoing_socket, BytesCodec::new()).fuse();

    let ike_sa_config = create_ike_sa_config(&config.address, &config.psk);

    let (ike_sa, mut ike_sa_messages) = IkeSa::new(&ike_sa_config)?;

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
                            pending_operations.push(Either::Left(ike_sa.handle_acquire(ts_i, ts_r, acquire.acquire.policy.index)));
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
                        let message: Bytes = message.into();
                        let peer_address: std::net::SocketAddr = (config.peer_address, 500).into();
                        outgoing_framed.send((message, peer_address)).await?;
                    },
                }
            },
            result = incoming_framed.select_next_some() => {
                match result {
                    Ok((message, _peer_address)) => {
                        pending_operations.push(Either::Right(ike_sa.handle_message(message.to_vec())));
                    },
                    _ => {},
                }
            }
            result = pending_operations.select_next_some() => {
                debug!("result: {:?}", result);
            }
        }
    }
}
