use anyhow::Result;
use bytes::Bytes;
use futures::{
    SinkExt,
    future::Either,
    stream::{FuturesUnordered, StreamExt},
};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_xfrm::{XFRMNLGRP_ACQUIRE, XFRMNLGRP_EXPIRE, XfrmMessage, address::Address};
use netlink_proto::sys::{AsyncSocket, SocketAddr};
use std::net::IpAddr;
use std::net::UdpSocket as StdUdpSocket;
use swanny_ikev2::{
    config::{Config, ConfigBuilder},
    crypto::{AuthenticationKey, Cipher, EncryptionKey, Integ},
    message::{
        EspSpi,
        num::{DhId, EncrId, EsnId, IdType, IntegId, PrfId, Protocol, TrafficSelectorType},
        payload::Id,
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ControlMessage, IkeSa},
};
use tokio::net::UdpSocket;
use tokio_util::{codec::BytesCodec, udp::UdpFramed};
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use xfrmnetlink::Handle;
mod config;

fn create_ike_sa_config(config: &config::Config) -> Config {
    let id = match &config.address {
        IpAddr::V4(v4) => Id::new(IdType::ID_IPV4_ADDR.into(), &v4.octets()[..]),
        IpAddr::V6(v6) => Id::new(IdType::ID_IPV6_ADDR.into(), &v6.octets()[..]),
    };
    ConfigBuilder::default()
        .ike_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                .prf(PrfId::PRF_HMAC_SHA2_256)
                .integrity(IntegId::AUTH_HMAC_SHA2_256_128)
                .dh(DhId::MODP2048)
        })
        .ipsec_protocol(Protocol::ESP)
        .ipsec_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_GCM_16, Some(256))
                .esn(EsnId::NoEsn)
        })
        .ipsec_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                .integrity(IntegId::AUTH_HMAC_SHA2_256_128)
                .esn(EsnId::NoEsn)
        })
        .inbound_traffic_selector(|tc| {
            tc.start_address(config.address)
                .start_port(0)
                .end_port(65535)
        })
        .inbound_traffic_selector(|tc| {
            tc.start_address(config.peer_address)
                .start_port(0)
                .end_port(0)
        })
        .outbound_traffic_selector(|tc| {
            tc.start_address(config.address)
                .start_port(0)
                .end_port(65535)
        })
        .outbound_traffic_selector(|tc| {
            tc.start_address(config.peer_address)
                .start_port(0)
                .end_port(0)
        })
        .psk(&config.psk)
        .build(id)
        .expect("building config should succeed")
}

fn create_traffic_selector(
    family: u16,
    proto: u8,
    address: &Address,
    _port: u16,
) -> Result<TrafficSelector> {
    match family as i32 {
        libc::AF_INET => Ok(TrafficSelector::new(
            TrafficSelectorType::TS_IPV4_ADDR_RANGE.into(),
            proto,
            &IpAddr::V4(address.to_ipv4()),
            &IpAddr::V4(address.to_ipv4()),
            0,
            65535,
        )),
        libc::AF_INET6 => Ok(TrafficSelector::new(
            TrafficSelectorType::TS_IPV6_ADDR_RANGE.into(),
            proto,
            &IpAddr::V6(address.to_ipv6()),
            &IpAddr::V6(address.to_ipv6()),
            0,
            65535,
        )),
        _ => Err(anyhow::anyhow!("unsupported address family")),
    }
}

fn ipsec_to_xfrm(ipsec_protocol: Protocol) -> u8 {
    match ipsec_protocol {
        Protocol::AH => libc::IPPROTO_AH.try_into().expect("value out of range"),
        Protocol::ESP => libc::IPPROTO_ESP.try_into().expect("value out of range"),
        _ => unreachable!("unsupported IPsec protocol"),
    }
}

fn integ_to_xfrm(integ: &Integ) -> (&'static str, usize) {
    match integ.id() {
        IntegId::AUTH_HMAC_MD5_96 => ("hmac(md5)", 12),
        IntegId::AUTH_HMAC_SHA1_96 => ("hmac(sha1)", 12),
        IntegId::AUTH_HMAC_SHA2_256_128 => ("hmac(sha256)", 16),
        IntegId::AUTH_HMAC_SHA2_384_192 => ("hmac(sha384)", 24),
        IntegId::AUTH_HMAC_SHA2_512_256 => ("hmac(sha512)", 32),
        _ => unreachable!("unsupported integrity checking algorithm"),
    }
}

fn cipher_to_xfrm(cipher: &Cipher) -> &'static str {
    match cipher.id() {
        EncrId::ENCR_AES_GCM_8 | EncrId::ENCR_AES_GCM_12 | EncrId::ENCR_AES_GCM_16 => {
            "rfc4106(gcm(aes))"
        }
        EncrId::ENCR_AES_CBC => "cbc(aes)",
        _ => unreachable!("unsupported encryption algorithm"),
    }
}

async fn create_sa(
    handle: Handle,
    src_address: IpAddr,
    dst_address: IpAddr,
    protocol: u8,
    ipsec_protocol: Protocol,
    spi: &EspSpi,
    integ_key: Option<&AuthenticationKey>,
    cipher_key: &EncryptionKey,
    expires: Option<u64>,
) -> Result<()> {
    let req = handle.state().add(src_address, dst_address);

    let mut req = req
        .protocol(ipsec_to_xfrm(ipsec_protocol))
        .spi(u32::from_be_bytes(*spi))
        .byte_limit(u64::MAX, u64::MAX)
        .packet_limit(u64::MAX, u64::MAX)
        .selector_protocol(protocol)
        .selector_addresses(src_address, 32, dst_address, 32);

    if let Some(expires) = expires {
        req = req.time_limit(expires, expires + 10);
    }

    if let Some(integ_key) = integ_key {
        let (alg_name, trunc_len) = integ_to_xfrm(integ_key.integ());
        req = req.authentication_trunc(
            alg_name,
            &integ_key.key().as_ref().to_vec(),
            trunc_len.try_into().expect("value out of range"),
        )?;
    }

    let alg_name = cipher_to_xfrm(cipher_key.cipher());
    if cipher_key.cipher().is_aead() {
        req = req.encryption_aead(
            alg_name,
            &cipher_key.key().as_ref().to_vec(),
            cipher_key
                .cipher()
                .tag_size()
                .expect("tag size should be given")
                .checked_mul(8)
                .expect("overflow")
                .try_into()?,
        )?;
    } else {
        req = req.encryption(alg_name, &cipher_key.key().as_ref().to_vec())?;
    }

    Ok(req.execute().await?)
}

async fn create_child_sa(handle: Handle, child_sa: &ChildSa, expires: Option<u64>) -> Result<()> {
    create_sa(
        handle.clone(),
        *child_sa.ts_i().start_address(),
        *child_sa.ts_r().start_address(),
        child_sa.ts_i().ip_proto(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_r(),
        child_sa.keys().ai.as_ref(),
        &child_sa.keys().ei,
        expires,
    )
    .await?;
    debug!("created inbound state");
    create_sa(
        handle.clone(),
        *child_sa.ts_r().start_address(),
        *child_sa.ts_i().start_address(),
        child_sa.ts_r().ip_proto(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_i(),
        child_sa.keys().ar.as_ref(),
        &child_sa.keys().er,
        expires,
    )
    .await?;
    debug!("created outbound state");
    Ok(())
}

async fn delete_sa(
    handle: Handle,
    src_address: IpAddr,
    dst_address: IpAddr,
    ipsec_protocol: Protocol,
    spi: &EspSpi,
) -> Result<()> {
    let req = handle
        .state()
        .delete(src_address, dst_address)
        .protocol(ipsec_to_xfrm(ipsec_protocol))
        .spi(u32::from_be_bytes(*spi));

    Ok(req.execute().await?)
}

async fn delete_child_sa(handle: Handle, child_sa: &ChildSa) -> Result<()> {
    delete_sa(
        handle.clone(),
        *child_sa.ts_i().start_address(),
        *child_sa.ts_r().start_address(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_r(),
    )
    .await?;
    debug!("deleted inbound state");
    delete_sa(
        handle.clone(),
        *child_sa.ts_r().start_address(),
        *child_sa.ts_i().start_address(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_i(),
    )
    .await?;
    debug!("deleted outbound state");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let (mut connection, handle, mut xfrm_messages) = xfrmnetlink::new_connection()?;

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

    let ike_sa_config = create_ike_sa_config(&config);

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
                                &acquire.acquire.selector.saddr,
                                acquire.acquire.selector.sport,
                            )?;
                            let ts_r = create_traffic_selector(
                                acquire.acquire.selector.family,
                                acquire.acquire.selector.proto,
                                &acquire.acquire.selector.daddr,
                                acquire.acquire.selector.dport,
                            )?;
                            pending_operations.push(Either::Left(Either::Right(ike_sa.handle_acquire(ts_i, ts_r, acquire.acquire.policy.index))));
                        },
                        XfrmMessage::Expire(expire) => {
                            let spi = expire.expire.state.id.spi.to_be_bytes();
                            debug!("expired: {:?}", &spi);
                            pending_operations.push(Either::Left(Either::Left(ike_sa.handle_expire(spi, expire.expire.hard != 0))));
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
                    ControlMessage::CreateChildSa(child_sa) => {
                        create_child_sa(
                            handle.clone(),
                            &child_sa,
                            config.expires,
                        ).await?;
                    }
                    ControlMessage::DeleteChildSa(child_sa) => {
                        delete_child_sa(
                            handle.clone(),
                            &child_sa,
                        ).await?;
                    }
                    ControlMessage::RekeyChildSa(_child_sa) => {
                    }
                }
            },
            result = incoming_framed.select_next_some() => {
                match result {
                    Ok((message, _peer_address)) => {
                        pending_operations.push(Either::Right(Either::Left(ike_sa.handle_message(message.to_vec()))));
                    },
                    Err(e) => {
                        debug!(error = %e, "error receiving IKEv2 message");
                    },
                }
            }
            result = outgoing_framed.select_next_some() => {
                match result {
                    Ok((message, _peer_address)) => {
                        pending_operations.push(Either::Right(Either::Right(ike_sa.handle_message(message.to_vec()))));
                    },
                    Err(e) => {
                        debug!(error = %e, "error receiving IKEv2 message");
                    },
                }
            }
            result = pending_operations.select_next_some() => {
                debug!(result = ?result, "pending operation completed");
            }
        }
    }
}
