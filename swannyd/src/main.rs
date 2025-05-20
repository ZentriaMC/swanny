use anyhow::Result;
use bytes::Bytes;
use futures::{
    future::Either,
    stream::{FuturesUnordered, StreamExt},
    SinkExt,
};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_xfrm::{
    address::Address, state::ModifyMessage, Alg, AlgAuth, XfrmAttrs, XfrmMessage,
    XFRMNLGRP_ACQUIRE, XFRMNLGRP_EXPIRE, XFRM_ALG_AUTH_NAME_LEN, XFRM_ALG_NAME_LEN,
};
use netlink_proto::{
    sys::{protocols::NETLINK_XFRM, AsyncSocket, SocketAddr},
    ConnectionHandle,
};
use std::ffi::CString;
use std::net::IpAddr;
use std::net::UdpSocket as StdUdpSocket;
use swanny_ikev2::{
    config::Config,
    crypto::{Cipher, Integ},
    message::{
        num::{EncrId, IdType, IntegId, Num, TrafficSelectorType},
        payload::Id,
        traffic_selector::TrafficSelector,
        EspSpi,
    },
    sa::{ChildSa, ControlMessage, IkeSa},
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

fn create_alg_auth(integ: &Integ, key: impl AsRef<[u8]>) -> Result<AlgAuth> {
    let (alg_name, trunc_len) = match integ.id() {
        IntegId::AUTH_HMAC_MD5_96 => ("hmac(md5)", 12),
        IntegId::AUTH_HMAC_SHA1_96 => ("hmac(sha1)", 12),
        id => {
            return Err(anyhow::anyhow!(
                "unsupported integrity checking algorithm {:?}",
                id
            ))
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
    spi: &EspSpi,
    integ: Option<&Integ>,
    integ_key: Option<impl AsRef<[u8]>>,
    cipher: &Cipher,
    cipher_key: impl AsRef<[u8]>,
) -> Result<ModifyMessage> {
    let mut message = ModifyMessage::default();
    message.user_sa_info.source(src_address);
    message.user_sa_info.mode = 0; // transport
    message.user_sa_info.family = 2; // AF_INET
    message.user_sa_info.reqid = 42;

    message.user_sa_info.selector.source_prefix(src_address, 32);
    message
        .user_sa_info
        .selector
        .destination_prefix(dst_address, 32);
    message.user_sa_info.selector.sport = 0;
    message.user_sa_info.selector.dport = 0;
    message.user_sa_info.selector.proto = protocol;
    message.user_sa_info.selector.family = 2; // AF_INET

    message.user_sa_info.id.daddr = Address::from_ip(dst_address);
    message.user_sa_info.id.proto = 50; // IPPROTO_ESP
    message.user_sa_info.id.spi = u32::from_be_bytes(*spi);
    message.user_sa_info.lifetime_cfg.soft_byte_limit = 0xFFFFFFFFFFFFFFFF;
    message.user_sa_info.lifetime_cfg.hard_byte_limit = 0xFFFFFFFFFFFFFFFF;
    message.user_sa_info.lifetime_cfg.soft_packet_limit = 0xFFFFFFFFFFFFFFFF;
    message.user_sa_info.lifetime_cfg.hard_packet_limit = 0xFFFFFFFFFFFFFFFF;

    if let (Some(integ), Some(integ_key)) = (integ, integ_key) {
        let alg_auth = create_alg_auth(integ, integ_key)?;
        message
            .nlas
            .push(XfrmAttrs::AuthenticationAlgTrunc(alg_auth));
    }

    let alg_enc = create_alg_enc(cipher, cipher_key.as_ref())?;
    message.nlas.push(XfrmAttrs::EncryptionAlg(alg_enc));

    Ok(message)
}

async fn create_sa(
    handle: ConnectionHandle<XfrmMessage>,
    src_address: &IpAddr,
    dst_address: &IpAddr,
    protocol: u8,
    spi: &EspSpi,
    integ: Option<&Integ>,
    integ_key: Option<impl AsRef<[u8]>>,
    cipher: &Cipher,
    cipher_key: impl AsRef<[u8]>,
) -> Result<()> {
    let message = create_modify_message(
        src_address,
        dst_address,
        protocol,
        spi,
        integ,
        integ_key,
        cipher,
        cipher_key,
    )?;
    let mut request = NetlinkMessage::from(XfrmMessage::AddSa(message));
    request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    debug!("sending netlink request {:?}", &request);
    let mut response = handle.request(request, SocketAddr::new(0, 0))?;
    while let Some(message) = response.next().await {
        debug!("netlink ack {:?}", message);
    }
    Ok(())
}

async fn create_child_sa(
    handle: ConnectionHandle<XfrmMessage>,
    child_sa: &ChildSa,
    is_initiator: bool,
) -> Result<()> {
    create_sa(
        handle.clone(),
        child_sa.ts_i().start_address(),
        child_sa.ts_r().start_address(),
        child_sa.ts_i().ip_proto(),
        child_sa.spi(),
        child_sa.chosen_proposal().integ(),
        if is_initiator {
            child_sa.keys().unwrap().ai.as_ref()
        } else {
            child_sa.keys().unwrap().ar.as_ref()
        },
        child_sa.chosen_proposal().cipher(),
        if is_initiator {
            &child_sa.keys().unwrap().ei
        } else {
            &child_sa.keys().unwrap().er
        },
    )
    .await?;
    debug!("created inbound SA");
    create_sa(
        handle.clone(),
        child_sa.ts_r().start_address(),
        child_sa.ts_i().start_address(),
        child_sa.ts_r().ip_proto(),
        child_sa.chosen_proposal().spi().try_into().unwrap(),
        child_sa.chosen_proposal().integ(),
        if is_initiator {
            child_sa.keys().unwrap().ar.as_ref()
        } else {
            child_sa.keys().unwrap().ai.as_ref()
        },
        child_sa.chosen_proposal().cipher(),
        if is_initiator {
            &child_sa.keys().unwrap().er
        } else {
            &child_sa.keys().unwrap().ei
        },
    )
    .await?;
    debug!("created outbound SA");
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
                            debug!("acquire");
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
                    ControlMessage::CreateChildSa(child_sa) => {
                        eprintln!("Created Child SA {:?}", &child_sa);
                        create_child_sa(
                            handle.clone(),
                            &child_sa,
                            ike_sa.is_initiator().await,
                        ).await?;
                    }
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
