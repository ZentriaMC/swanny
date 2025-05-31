use anyhow::Result;
use bytes::Bytes;
use futures::{
    SinkExt,
    future::Either,
    stream::{FuturesUnordered, StreamExt},
};
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_xfrm::{
    Alg, AlgAead, AlgAuth, XFRM_ALG_AEAD_NAME_LEN, XFRM_ALG_AUTH_NAME_LEN, XFRM_ALG_NAME_LEN,
    XFRMNLGRP_ACQUIRE, XFRMNLGRP_EXPIRE, XfrmAttrs, XfrmMessage, address::Address,
    state::DelGetMessage, state::ModifyMessage,
};
use netlink_proto::{
    ConnectionHandle,
    sys::{AsyncSocket, SocketAddr, protocols::NETLINK_XFRM},
};
use std::ffi::CString;
use std::net::IpAddr;
use std::net::UdpSocket as StdUdpSocket;
use swanny_ikev2::{
    config::Config,
    crypto::{Cipher, Integ},
    message::{
        EspSpi,
        num::{EncrId, IdType, IntegId, Protocol, TrafficSelectorType},
        payload::Id,
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSa, ControlMessage, IkeSa},
};
use tokio::net::UdpSocket;
use tokio_util::{codec::BytesCodec, udp::UdpFramed};
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
mod config;

fn create_ike_sa_config(config: &config::Config) -> Config {
    use swanny_ikev2::config::ConfigBuilder;
    use swanny_ikev2::message::num::{DhId, EncrId, IntegId, PrfId, Protocol};

    let id = match &config.address {
        IpAddr::V4(v4) => Id::new(IdType::ID_IPV4_ADDR.into(), &v4.octets()[..]),
        IpAddr::V6(v6) => Id::new(IdType::ID_IPV6_ADDR.into(), &v6.octets()[..]),
    };
    ConfigBuilder::default()
        .ike_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                .prf(PrfId::PRF_HMAC_SHA2_256)
                .integrity(IntegId::AUTH_HMAC_SHA2_256_128)
                .dh(DhId::SECP256R1)
        })
        .ipsec_protocol(Protocol::ESP)
        .ipsec_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_GCM_8, Some(128))
                .prf(PrfId::PRF_HMAC_SHA2_256)
        })
        .inbound_traffic_selector(|tc| {
            tc.start_address(config.address)
                .start_port(0)
                .end_port(65535)
        })
        .inbound_traffic_selector(|tc| {
            tc.start_address(config.peer_address)
                .start_port(0)
                .end_port(65535)
        })
        .outbound_traffic_selector(|tc| {
            tc.start_address(config.address)
                .start_port(0)
                .end_port(65535)
        })
        .outbound_traffic_selector(|tc| {
            tc.start_address(config.peer_address)
                .start_port(0)
                .end_port(65535)
        })
        .psk(&config.psk)
        .build(id)
        .expect("building config should succeed")
}

fn create_traffic_selector(
    family: u16,
    proto: u8,
    address: &Address,
    port: u16,
) -> Result<TrafficSelector> {
    match family as i32 {
        libc::AF_INET => Ok(TrafficSelector::new(
            TrafficSelectorType::TS_IPV4_ADDR_RANGE.into(),
            proto,
            &IpAddr::V4(address.to_ipv4()),
            &IpAddr::V4(address.to_ipv4()),
            port,
            port,
        )),
        libc::AF_INET6 => Ok(TrafficSelector::new(
            TrafficSelectorType::TS_IPV6_ADDR_RANGE.into(),
            proto,
            &IpAddr::V6(address.to_ipv6()),
            &IpAddr::V6(address.to_ipv6()),
            port,
            port,
        )),
        _ => Err(anyhow::anyhow!("unsupported address family")),
    }
}

fn create_alg_auth(integ: &Integ, key: impl AsRef<[u8]>) -> Result<AlgAuth> {
    let (alg_name, trunc_len) = match integ.id() {
        IntegId::AUTH_HMAC_MD5_96 => ("hmac(md5)", 12),
        IntegId::AUTH_HMAC_SHA1_96 => ("hmac(sha1)", 12),
        IntegId::AUTH_HMAC_SHA2_256_128 => ("hmac(sha256)", 16),
        IntegId::AUTH_HMAC_SHA2_384_192 => ("hmac(sha384)", 24),
        IntegId::AUTH_HMAC_SHA2_512_256 => ("hmac(sha512)", 32),
        id => {
            return Err(anyhow::anyhow!(
                "unsupported integrity checking algorithm {:?}",
                id
            ));
        }
    };

    let mut auth_name: [u8; XFRM_ALG_AUTH_NAME_LEN] = [0; XFRM_ALG_AUTH_NAME_LEN];
    let mut c_auth_name = CString::new(alg_name)?.into_bytes_with_nul();
    if c_auth_name.len() > XFRM_ALG_AUTH_NAME_LEN {
        c_auth_name.truncate(XFRM_ALG_AUTH_NAME_LEN);
        c_auth_name[XFRM_ALG_AUTH_NAME_LEN - 1] = 0;
    }
    auth_name[0..c_auth_name.len()].copy_from_slice(c_auth_name.as_slice());
    let alg_auth = AlgAuth {
        alg_name: auth_name,
        alg_key_len: (key.as_ref().len() * 8) as u32,
        alg_trunc_len: trunc_len,
        alg_key: key.as_ref().to_vec(),
    };
    Ok(alg_auth)
}

fn create_alg_enc_aead(cipher: &Cipher, key: impl AsRef<[u8]>) -> Result<AlgAead> {
    let alg_name = match cipher.id() {
        EncrId::ENCR_AES_GCM_8 | EncrId::ENCR_AES_GCM_12 | EncrId::ENCR_AES_GCM_16 => {
            "rfc4106(gcm(aes))"
        }
        id => return Err(anyhow::anyhow!("unsupported AEAD algorithm {:?}", id)),
    };

    let mut enc_name: [u8; XFRM_ALG_AEAD_NAME_LEN] = [0; XFRM_ALG_AEAD_NAME_LEN];
    let mut c_enc_name = CString::new(alg_name)?.into_bytes_with_nul();

    if c_enc_name.len() > XFRM_ALG_AEAD_NAME_LEN {
        c_enc_name.truncate(XFRM_ALG_AEAD_NAME_LEN);
        c_enc_name[XFRM_ALG_AEAD_NAME_LEN - 1] = 0;
    }
    enc_name[0..c_enc_name.len()].copy_from_slice(c_enc_name.as_slice());

    let alg_enc = AlgAead {
        alg_name: enc_name,
        alg_key_len: (key.as_ref().len() * 8) as u32,
        alg_icv_len: (cipher.tag_size().unwrap() * 8) as u32,
        alg_key: key.as_ref().to_vec(),
    };
    Ok(alg_enc)
}

fn create_alg_enc(cipher: &Cipher, key: impl AsRef<[u8]>) -> Result<Alg> {
    let alg_name = match cipher.id() {
        EncrId::ENCR_AES_CBC => "cbc(aes)",
        id => return Err(anyhow::anyhow!("unsupported cipher algorithm {:?}", id)),
    };

    let mut enc_name: [u8; XFRM_ALG_NAME_LEN] = [0; XFRM_ALG_NAME_LEN];
    let mut c_enc_name = CString::new(alg_name)?.into_bytes_with_nul();

    if c_enc_name.len() > XFRM_ALG_NAME_LEN {
        c_enc_name.truncate(XFRM_ALG_NAME_LEN);
        c_enc_name[XFRM_ALG_NAME_LEN - 1] = 0;
    }
    enc_name[0..c_enc_name.len()].copy_from_slice(c_enc_name.as_slice());

    let alg_enc = Alg {
        alg_name: enc_name,
        alg_key_len: (key.as_ref().len() * 8) as u32,
        alg_key: key.as_ref().to_vec(),
    };
    Ok(alg_enc)
}

fn create_modify_message(
    src_address: &IpAddr,
    dst_address: &IpAddr,
    protocol: u8,
    ipsec_protocol: Protocol,
    spi: &EspSpi,
    integ: Option<&Integ>,
    integ_key: Option<impl AsRef<[u8]>>,
    cipher: &Cipher,
    cipher_key: impl AsRef<[u8]>,
    expires: Option<u64>,
) -> Result<ModifyMessage> {
    let mut message = ModifyMessage::default();
    message.user_sa_info.source(src_address);
    message.user_sa_info.mode = 0;
    message.user_sa_info.family = match src_address {
        IpAddr::V4(_) => libc::AF_INET.try_into()?,
        IpAddr::V6(_) => libc::AF_INET6.try_into()?,
    };

    message.user_sa_info.selector.source_prefix(src_address, 32);
    message
        .user_sa_info
        .selector
        .destination_prefix(dst_address, 32);
    message.user_sa_info.selector.sport = 0;
    message.user_sa_info.selector.dport = 0;
    message.user_sa_info.selector.proto = protocol;
    message.user_sa_info.selector.family = match dst_address {
        IpAddr::V4(_) => libc::AF_INET.try_into()?,
        IpAddr::V6(_) => libc::AF_INET6.try_into()?,
    };

    message.user_sa_info.id.daddr = Address::from_ip(dst_address);
    message.user_sa_info.id.proto = match ipsec_protocol {
        Protocol::AH => libc::IPPROTO_AH.try_into()?,
        Protocol::ESP => libc::IPPROTO_ESP.try_into()?,
        _ => return Err(anyhow::anyhow!("unsupported IPsec protocol")),
    };
    message.user_sa_info.id.spi = u32::from_be_bytes(*spi);
    message.user_sa_info.lifetime_cfg.soft_byte_limit = 0xFFFFFFFFFFFFFFFF;
    message.user_sa_info.lifetime_cfg.hard_byte_limit = 0xFFFFFFFFFFFFFFFF;
    message.user_sa_info.lifetime_cfg.soft_packet_limit = 0xFFFFFFFFFFFFFFFF;
    message.user_sa_info.lifetime_cfg.hard_packet_limit = 0xFFFFFFFFFFFFFFFF;
    if let Some(expires) = expires {
        message.user_sa_info.lifetime_cfg.soft_add_expires_seconds = expires;
        message.user_sa_info.lifetime_cfg.hard_add_expires_seconds = expires + 10;
    }

    if let (Some(integ), Some(integ_key)) = (integ, integ_key) {
        let alg_auth = create_alg_auth(integ, integ_key)?;
        message
            .nlas
            .push(XfrmAttrs::AuthenticationAlgTrunc(alg_auth));
    }

    if cipher.is_aead() {
        let alg_enc_aead = create_alg_enc_aead(cipher, cipher_key.as_ref())?;
        message
            .nlas
            .push(XfrmAttrs::EncryptionAlgAead(alg_enc_aead));
    } else {
        let alg_enc = create_alg_enc(cipher, cipher_key.as_ref())?;
        message.nlas.push(XfrmAttrs::EncryptionAlg(alg_enc));
    }

    Ok(message)
}

async fn create_sa(
    handle: ConnectionHandle<XfrmMessage>,
    src_address: &IpAddr,
    dst_address: &IpAddr,
    protocol: u8,
    ipsec_protocol: Protocol,
    spi: &EspSpi,
    integ: Option<&Integ>,
    integ_key: Option<impl AsRef<[u8]>>,
    cipher: &Cipher,
    cipher_key: impl AsRef<[u8]>,
    expires: Option<u64>,
) -> Result<()> {
    let message = create_modify_message(
        src_address,
        dst_address,
        protocol,
        ipsec_protocol,
        spi,
        integ,
        integ_key,
        cipher,
        cipher_key,
        expires,
    )?;
    let mut request = NetlinkMessage::from(XfrmMessage::AddSa(message));
    request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    debug!(request = ?&request, "sending netlink request");
    let mut response = handle.request(request, SocketAddr::new(0, 0))?;
    while let Some(message) = response.next().await {
        debug!(message = ?message, "received netlink response");
    }
    Ok(())
}

async fn create_child_sa(
    handle: ConnectionHandle<XfrmMessage>,
    child_sa: &ChildSa,
    expires: Option<u64>,
) -> Result<()> {
    create_sa(
        handle.clone(),
        child_sa.ts_i().start_address(),
        child_sa.ts_r().start_address(),
        child_sa.ts_i().ip_proto(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_i(),
        child_sa.chosen_proposal().integ(),
        child_sa.keys().ai.as_ref(),
        child_sa.chosen_proposal().cipher(),
        &child_sa.keys().ei,
        expires,
    )
    .await?;
    debug!("created inbound state");
    create_sa(
        handle.clone(),
        child_sa.ts_r().start_address(),
        child_sa.ts_i().start_address(),
        child_sa.ts_r().ip_proto(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_r(),
        child_sa.chosen_proposal().integ(),
        child_sa.keys().ar.as_ref(),
        child_sa.chosen_proposal().cipher(),
        &child_sa.keys().er,
        expires,
    )
    .await?;
    debug!("created outbound state");
    Ok(())
}

async fn delete_sa(
    handle: ConnectionHandle<XfrmMessage>,
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    ipsec_protocol: Protocol,
    spi: &EspSpi,
) -> Result<()> {
    let mut message = DelGetMessage::default();
    message.user_sa_id.destination(dst_addr);
    message
        .nlas
        .push(XfrmAttrs::SrcAddr(Address::from_ip(src_addr)));
    message.user_sa_id.proto = match ipsec_protocol {
        Protocol::AH => libc::IPPROTO_AH.try_into()?,
        Protocol::ESP => libc::IPPROTO_ESP.try_into()?,
        _ => return Err(anyhow::anyhow!("unsupported IPsec protocol")),
    };
    message.user_sa_id.spi = u32::from_be_bytes(*spi);
    let mut request = NetlinkMessage::from(XfrmMessage::DeleteSa(message));
    request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    debug!(request = ?&request, "sending netlink request");
    let mut response = handle.request(request, SocketAddr::new(0, 0))?;
    while let Some(message) = response.next().await {
        debug!(message = ?message, "received netlink response");
    }
    Ok(())
}

async fn delete_child_sa(handle: ConnectionHandle<XfrmMessage>, child_sa: &ChildSa) -> Result<()> {
    delete_sa(
        handle.clone(),
        child_sa.ts_i().start_address(),
        child_sa.ts_r().start_address(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_i(),
    )
    .await?;

    delete_sa(
        handle.clone(),
        child_sa.ts_r().start_address(),
        child_sa.ts_i().start_address(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_r(),
    )
    .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let (mut connection, handle, mut xfrm_messages) =
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
                        pending_operations.push(Either::Right(ike_sa.handle_message(message.to_vec())));
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
