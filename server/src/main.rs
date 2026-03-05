use anyhow::Result;
use bytes::Bytes;
use cidr::IpCidr;
use futures::{
    FutureExt, SinkExt,
    stream::{FuturesUnordered, StreamExt},
};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_xfrm::{
    UserTemplate, XFRM_MODE_TRANSPORT, XFRM_MODE_TUNNEL, XFRM_POLICY_FWD, XFRM_POLICY_IN,
    XFRM_POLICY_OUT, XFRMNLGRP_ACQUIRE, XFRMNLGRP_EXPIRE, XfrmMessage,
};
use netlink_proto::sys::{AsyncSocket, SocketAddr};
use std::future::Future;
use std::net::IpAddr;
use std::net::UdpSocket as StdUdpSocket;
use std::pin::Pin;
use swanny_ikev2::{
    config::{Config, ConfigBuilder},
    crypto::{AuthenticationKey, Cipher, EncryptionKey, Integ},
    message::{
        EspSpi,
        num::{DhId, EncrId, EsnId, IdType, IntegId, PrfId, Protocol, TrafficSelectorType},
        payload::Id,
        traffic_selector::TrafficSelector,
    },
    StateError,
    sa::{ChildSa, ChildSaMode, ControlMessage, IkeSa},
};
use tokio::net::UdpSocket;
use tokio::time::sleep;
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
    let mut builder = ConfigBuilder::default()
        .ike_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(256))
                .prf(PrfId::PRF_HMAC_SHA2_256)
                .integrity(IntegId::AUTH_HMAC_SHA2_256_128)
                .dh(DhId::MODP2048)
        })
        .ike_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                .prf(PrfId::PRF_HMAC_SHA2_256)
                .integrity(IntegId::AUTH_HMAC_SHA2_256_128)
                .dh(DhId::MODP2048)
        })
        .ipsec_protocol(Protocol::ESP)
        .ipsec_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(256))
                .integrity(IntegId::AUTH_HMAC_SHA2_256_128)
                .dh(DhId::MODP2048)
                .esn(EsnId::NoEsn)
        })
        .ipsec_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_GCM_16, Some(256))
                .esn(EsnId::NoEsn)
        })
        .ipsec_proposal(|pc| {
            pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                .integrity(IntegId::AUTH_HMAC_SHA2_256_128)
                .esn(EsnId::NoEsn)
        });

    for cidr in &config.local_ts {
        builder = builder.inbound_traffic_selector(|tc| {
            tc.start_address(cidr.first_address())
                .end_address(cidr.last_address())
        });
        builder = builder.outbound_traffic_selector(|tc| {
            tc.start_address(cidr.first_address())
                .end_address(cidr.last_address())
        });
    }
    for cidr in &config.remote_ts {
        builder = builder.inbound_traffic_selector(|tc| {
            tc.start_address(cidr.first_address())
                .end_address(cidr.last_address())
        });
        builder = builder.outbound_traffic_selector(|tc| {
            tc.start_address(cidr.first_address())
                .end_address(cidr.last_address())
        });
    }

    builder
        .psk(&config.psk)
        .mode(config.mode.into())
        .strict_ts(config.strict_ts)
        .build(id)
        .expect("building config should succeed")
}

fn traffic_selector_from_cidr(cidr: &IpCidr) -> TrafficSelector {
    let (ty, start, end) = match cidr {
        IpCidr::V4(v4) => (
            TrafficSelectorType::TS_IPV4_ADDR_RANGE,
            IpAddr::V4(v4.first_address()),
            IpAddr::V4(v4.last_address()),
        ),
        IpCidr::V6(v6) => (
            TrafficSelectorType::TS_IPV6_ADDR_RANGE,
            IpAddr::V6(v6.first_address()),
            IpAddr::V6(v6.last_address()),
        ),
    };
    TrafficSelector::new(ty.into(), 0, start, end, 0, 65535)
}

fn ipsec_to_xfrm(ipsec_protocol: Protocol) -> u8 {
    match ipsec_protocol {
        Protocol::AH => libc::IPPROTO_AH.try_into().expect("value out of range"),
        Protocol::ESP => libc::IPPROTO_ESP.try_into().expect("value out of range"),
        _ => unreachable!("unsupported IPsec protocol"),
    }
}

async fn create_policy(
    handle: Handle,
    selector_src: IpAddr,
    selector_src_prefix: u8,
    selector_dst: IpAddr,
    selector_dst_prefix: u8,
    template_src: IpAddr,
    template_dst: IpAddr,
    direction: u8,
    ipsec_protocol: Protocol,
    mode: ChildSaMode,
    if_id: Option<u32>,
) -> Result<()> {
    let xfrm_mode = match mode {
        ChildSaMode::Transport => XFRM_MODE_TRANSPORT,
        ChildSaMode::Tunnel => XFRM_MODE_TUNNEL,
    };

    let mut template = UserTemplate::default();
    template.source(&template_src);
    template.destination(&template_dst);
    template.protocol(ipsec_to_xfrm(ipsec_protocol));
    template.mode(xfrm_mode);

    let mut req = handle
        .policy()
        .add(
            selector_src,
            selector_src_prefix,
            selector_dst,
            selector_dst_prefix,
        )
        .direction(direction)
        .priority(1000)
        .add_template(template);

    if let Some(id) = if_id {
        req = req.ifid(id);
    }

    Ok(req.execute().await?)
}

async fn create_ike_bypass_policy(
    handle: Handle,
    src_address: IpAddr,
    dst_address: IpAddr,
    direction: u8,
    port: u16,
) -> Result<()> {
    let prefix_len = if src_address.is_ipv4() { 32 } else { 128 };

    // No template = bypass (allow without IPsec transforms)
    handle
        .policy()
        .add(src_address, prefix_len, dst_address, prefix_len)
        .direction(direction)
        .priority(500)
        .selector_protocol(libc::IPPROTO_UDP.try_into().expect("value out of range"))
        .selector_protocol_dst_port(port)
        .execute()
        .await?;

    Ok(())
}

async fn install_policies(
    handle: Handle,
    local_ts: &[IpCidr],
    remote_ts: &[IpCidr],
    src_address: IpAddr,
    dst_address: IpAddr,
    ipsec_protocol: Protocol,
    mode: ChildSaMode,
    if_id: Option<u32>,
    ike_port: u16,
) -> Result<()> {
    // Bypass policies for IKE traffic so SA negotiation can proceed
    // without IPsec — evaluated before ESP policies due to higher
    // priority (lower number).
    create_ike_bypass_policy(handle.clone(), src_address, dst_address, XFRM_POLICY_OUT, ike_port)
        .await?;
    create_ike_bypass_policy(handle.clone(), dst_address, src_address, XFRM_POLICY_IN, ike_port)
        .await?;
    create_ike_bypass_policy(handle.clone(), dst_address, src_address, XFRM_POLICY_FWD, ike_port)
        .await?;
    debug!(ike_port, "installed IKE bypass policies");

    for local in local_ts {
        for remote in remote_ts {
            let local_addr = local.first_address();
            let local_prefix = local.network_length();
            let remote_addr = remote.first_address();
            let remote_prefix = remote.network_length();

            create_policy(
                handle.clone(),
                local_addr,
                local_prefix,
                remote_addr,
                remote_prefix,
                src_address,
                dst_address,
                XFRM_POLICY_OUT,
                ipsec_protocol,
                mode,
                if_id,
            )
            .await?;
            debug!(
                local = %local, remote = %remote,
                "installed outbound policy"
            );

            create_policy(
                handle.clone(),
                remote_addr,
                remote_prefix,
                local_addr,
                local_prefix,
                dst_address,
                src_address,
                XFRM_POLICY_IN,
                ipsec_protocol,
                mode,
                if_id,
            )
            .await?;
            debug!(
                local = %local, remote = %remote,
                "installed inbound policy"
            );

            create_policy(
                handle.clone(),
                remote_addr,
                remote_prefix,
                local_addr,
                local_prefix,
                dst_address,
                src_address,
                XFRM_POLICY_FWD,
                ipsec_protocol,
                mode,
                if_id,
            )
            .await?;
            debug!(
                local = %local, remote = %remote,
                "installed forward policy"
            );
        }
    }

    info!("XFRM policies installed");
    Ok(())
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
    mode: ChildSaMode,
    if_id: Option<u32>,
) -> Result<()> {
    let req = handle.state().add(src_address, dst_address);

    let xfrm_mode = match mode {
        ChildSaMode::Transport => XFRM_MODE_TRANSPORT,
        ChildSaMode::Tunnel => XFRM_MODE_TUNNEL,
    };

    let mut req = req
        .protocol(ipsec_to_xfrm(ipsec_protocol))
        .spi(u32::from_be_bytes(*spi))
        .byte_limit(u64::MAX, u64::MAX)
        .packet_limit(u64::MAX, u64::MAX)
        .mode(xfrm_mode);

    // In transport mode, set explicit selectors matching the endpoints.
    // In tunnel mode, leave the default 0/0 selector — traffic matching
    // is handled by XFRM policy + if_id.
    match mode {
        ChildSaMode::Transport => {
            req = req.selector_protocol(protocol).selector_addresses(
                src_address,
                32,
                dst_address,
                32,
            );
        }
        ChildSaMode::Tunnel => {}
    }

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

    if let Some(id) = if_id {
        req = req.ifid(id);
    }

    Ok(req.execute().await?)
}

async fn create_child_sa(
    handle: Handle,
    child_sa: &ChildSa,
    local_ts: &[IpCidr],
    src_address: IpAddr,
    dst_address: IpAddr,
    expires: Option<u64>,
    mode: ChildSaMode,
    if_id: Option<u32>,
) -> Result<()> {
    // Resolve SA endpoint addresses per direction.  In transport mode the
    // SA endpoints equal the traffic-selector addresses.  In tunnel mode
    // they are the outer tunnel endpoints (config.address / peer_address).
    //
    // ts_i always covers the IKE *initiator's* traffic.  Comparing against
    // local_ts tells us whether we are the initiator or the responder so
    // we can assign the tunnel endpoints to the right direction.
    let (fwd_src, fwd_dst, rev_src, rev_dst) = match mode {
        ChildSaMode::Transport => (
            child_sa.ts_i().start_address(),
            child_sa.ts_r().start_address(),
            child_sa.ts_r().start_address(),
            child_sa.ts_i().start_address(),
        ),
        ChildSaMode::Tunnel => {
            let ts_i_is_local = local_ts
                .iter()
                .any(|cidr| cidr.contains(&child_sa.ts_i().start_address()));
            if ts_i_is_local {
                // We are the initiator: ts_i direction = local → remote
                (src_address, dst_address, dst_address, src_address)
            } else {
                // We are the responder: ts_i direction = remote → local
                (dst_address, src_address, src_address, dst_address)
            }
        }
    };

    create_sa(
        handle.clone(),
        fwd_src,
        fwd_dst,
        child_sa.ts_i().ip_proto(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_r(),
        child_sa.keys().ai.as_ref(),
        &child_sa.keys().ei,
        expires,
        mode,
        if_id,
    )
    .await?;
    debug!("created inbound state");
    create_sa(
        handle.clone(),
        rev_src,
        rev_dst,
        child_sa.ts_r().ip_proto(),
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_i(),
        child_sa.keys().ar.as_ref(),
        &child_sa.keys().er,
        expires,
        mode,
        if_id,
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

async fn delete_child_sa(
    handle: Handle,
    child_sa: &ChildSa,
    local_ts: &[IpCidr],
    src_address: IpAddr,
    dst_address: IpAddr,
    mode: ChildSaMode,
) -> Result<()> {
    let (fwd_src, fwd_dst, rev_src, rev_dst) = match mode {
        ChildSaMode::Transport => (
            child_sa.ts_i().start_address(),
            child_sa.ts_r().start_address(),
            child_sa.ts_r().start_address(),
            child_sa.ts_i().start_address(),
        ),
        ChildSaMode::Tunnel => {
            let ts_i_is_local = local_ts
                .iter()
                .any(|cidr| cidr.contains(&child_sa.ts_i().start_address()));
            if ts_i_is_local {
                (src_address, dst_address, dst_address, src_address)
            } else {
                (dst_address, src_address, src_address, dst_address)
            }
        }
    };

    delete_sa(
        handle.clone(),
        fwd_src,
        fwd_dst,
        child_sa.chosen_proposal().protocol(),
        child_sa.spi_r(),
    )
    .await?;
    debug!("deleted inbound state");
    delete_sa(
        handle.clone(),
        rev_src,
        rev_dst,
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

    let socket = StdUdpSocket::bind((config.address, 500))?;
    let ike_port = socket.local_addr()?.port();
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket)?;
    let mut framed = UdpFramed::new(socket, BytesCodec::new()).fuse();

    install_policies(
        handle.clone(),
        &config.local_ts,
        &config.remote_ts,
        config.address,
        config.peer_address,
        Protocol::ESP,
        config.mode.into(),
        config.if_id,
        ike_port,
    )
    .await?;

    let ike_sa_config = create_ike_sa_config(&config);

    let (ike_sa, mut ike_sa_messages) = IkeSa::new(&ike_sa_config)?;

    let mut pending_operations: FuturesUnordered<Pin<Box<dyn Future<Output = Result<(), StateError>>>>> =
        FuturesUnordered::new();

    let ike_lifetime_duration = config
        .ike_lifetime
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(u64::MAX));
    let mut ike_rekey_timer = sleep(ike_lifetime_duration).boxed().fuse();

    let dpd_interval = config
        .dpd_interval
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(u64::MAX));
    let mut dpd_timer = sleep(dpd_interval).boxed().fuse();

    loop {
        futures::select! {
            netlink_message = xfrm_messages.select_next_some() => {
                let (netlink_message, _) = netlink_message;
                let payload = netlink_message.payload;
                if let NetlinkPayload::InnerMessage(xfrm_message) = payload {
                    match xfrm_message {
                        XfrmMessage::Acquire(_) => {
                            let ts_i = traffic_selector_from_cidr(&config.local_ts[0]);
                            let ts_r = traffic_selector_from_cidr(&config.remote_ts[0]);
                            pending_operations.push(ike_sa.handle_acquire(ts_i, ts_r).boxed_local());
                        },
                        XfrmMessage::Expire(expire) => {
                            let spi = expire.expire.state.id.spi.to_be_bytes();
                            debug!("expired: {:?}", &spi);
                            pending_operations.push(ike_sa.handle_expire(spi, expire.expire.hard != 0).boxed_local());
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
                        framed.send((message, peer_address)).await?;
                    },
                    ControlMessage::CreateChildSa(child_sa) => {
                        create_child_sa(
                            handle.clone(),
                            &child_sa,
                            &config.local_ts,
                            config.address,
                            config.peer_address,
                            config.expires,
                            config.mode.into(),
                            config.if_id,
                        ).await?;
                    }
                    ControlMessage::DeleteChildSa(child_sa) => {
                        delete_child_sa(
                            handle.clone(),
                            &child_sa,
                            &config.local_ts,
                            config.address,
                            config.peer_address,
                            config.mode.into(),
                        ).await?;
                    }
                }
            },
            result = framed.select_next_some() => {
                match result {
                    Ok((message, _peer_address)) => {
                        pending_operations.push(ike_sa.handle_message(message.to_vec()).boxed_local());
                        dpd_timer = sleep(dpd_interval).boxed().fuse();
                    },
                    Err(e) => {
                        debug!(error = %e, "error receiving IKEv2 message");
                    },
                }
            }
            _ = &mut ike_rekey_timer => {
                info!("IKE SA lifetime expired, initiating rekey");
                pending_operations.push(ike_sa.handle_rekey_ike_sa().boxed_local());
                ike_rekey_timer = sleep(ike_lifetime_duration).boxed().fuse();
            }
            _ = &mut dpd_timer => {
                debug!("DPD interval expired, sending probe");
                pending_operations.push(ike_sa.handle_dpd().boxed_local());
                dpd_timer = sleep(dpd_interval).boxed().fuse();
            }
            result = pending_operations.select_next_some() => {
                debug!(result = ?result, "pending operation completed");
            }
        }
    }
}
