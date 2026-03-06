use std::net::IpAddr;

use anyhow::{Result, bail};
use netlink_packet_xfrm::{
    UserTemplate, XFRM_MODE_TRANSPORT, XFRM_MODE_TUNNEL,
    XFRM_POLICY_FWD, XFRM_POLICY_IN, XFRM_POLICY_OUT,
};
use swanny_proto::api;
use tracing::debug;
use xfrmnetlink::Handle;

use crate::tunnel_if_id;

/// Map proto encryption algorithm name to Linux crypto API name.
fn encryption_alg_name(name: &str) -> Result<(&'static str, bool)> {
    match name {
        "ENCR_AES_CBC_128" | "ENCR_AES_CBC_192" | "ENCR_AES_CBC_256" | "ENCR_AES_CBC" => {
            Ok(("cbc(aes)", false))
        }
        "ENCR_AES_GCM_8" | "ENCR_AES_GCM_12" | "ENCR_AES_GCM_16"
        | "ENCR_AES_GCM_8_128" | "ENCR_AES_GCM_8_256"
        | "ENCR_AES_GCM_12_128" | "ENCR_AES_GCM_12_256"
        | "ENCR_AES_GCM_16_128" | "ENCR_AES_GCM_16_256" => {
            Ok(("rfc4106(gcm(aes))", true))
        }
        _ => bail!("unsupported encryption algorithm: {name}"),
    }
}

/// Map proto integrity algorithm name to Linux crypto API name + truncation bits.
fn integrity_alg(name: &str) -> Result<(&'static str, usize)> {
    match name {
        "AUTH_HMAC_MD5_96" => Ok(("hmac(md5)", 96)),
        "AUTH_HMAC_SHA1_96" => Ok(("hmac(sha1)", 96)),
        "AUTH_HMAC_SHA2_256_128" => Ok(("hmac(sha256)", 128)),
        "AUTH_HMAC_SHA2_384_192" => Ok(("hmac(sha384)", 192)),
        "AUTH_HMAC_SHA2_512_256" => Ok(("hmac(sha512)", 256)),
        _ => bail!("unsupported integrity algorithm: {name}"),
    }
}

/// AEAD tag size in bits from the algorithm name.
fn aead_tag_bits(name: &str) -> Result<u32> {
    if name.contains("GCM_8") {
        Ok(64)
    } else if name.contains("GCM_12") {
        Ok(96)
    } else if name.contains("GCM_16") {
        Ok(128)
    } else {
        bail!("cannot determine AEAD tag size for: {name}")
    }
}

fn xfrm_mode(mode: api::sa_keying::Mode) -> u8 {
    match mode {
        api::sa_keying::Mode::Tunnel => XFRM_MODE_TUNNEL,
        api::sa_keying::Mode::Transport => XFRM_MODE_TRANSPORT,
    }
}

fn new_handle() -> Result<Handle> {
    let (connection, handle, _) = xfrmnetlink::new_connection()?;
    tokio::spawn(connection);
    Ok(handle)
}

async fn add_sa(
    handle: &Handle,
    src: IpAddr,
    dst: IpAddr,
    spi_bytes: &[u8],
    enc_alg: &str,
    enc_key: &[u8],
    integ_alg: &str,
    integ_key: &[u8],
    mode: u8,
    expires: u64,
    if_id: Option<u32>,
) -> Result<()> {
    let spi = u32::from_be_bytes(spi_bytes.try_into()?);
    let (alg_name, is_aead) = encryption_alg_name(enc_alg)?;

    let mut req = handle
        .state()
        .add(src, dst)
        .protocol(libc::IPPROTO_ESP.try_into()?)
        .spi(spi)
        .byte_limit(u64::MAX, u64::MAX)
        .packet_limit(u64::MAX, u64::MAX)
        .mode(mode);

    if mode == XFRM_MODE_TRANSPORT {
        req = req.selector_protocol(0).selector_addresses(src, 32, dst, 32);
    }

    if expires > 0 {
        req = req.time_limit(expires, expires + 10);
    }

    if is_aead {
        let tag_bits = aead_tag_bits(enc_alg)?;
        req = req.encryption_aead(alg_name, &enc_key.to_vec(), tag_bits)?;
    } else {
        req = req.encryption(alg_name, &enc_key.to_vec())?;
        if !integ_alg.is_empty() {
            let (integ_name, trunc_len) = integrity_alg(integ_alg)?;
            req = req.authentication_trunc(integ_name, &integ_key.to_vec(), trunc_len.try_into()?)?;
        }
    }

    if let Some(id) = if_id {
        req = req.ifid(id);
    }

    req.execute().await?;
    Ok(())
}

async fn del_sa(
    handle: &Handle,
    src: IpAddr,
    dst: IpAddr,
    spi_bytes: &[u8],
) -> Result<()> {
    let spi = u32::from_be_bytes(spi_bytes.try_into()?);
    handle
        .state()
        .delete(src, dst)
        .protocol(libc::IPPROTO_ESP.try_into()?)
        .spi(spi)
        .execute()
        .await?;
    Ok(())
}

/// Install both directions of a child SA from proto keying material.
pub async fn install_child_sa(tunnel_id: &str, keying: &api::SaKeying) -> Result<()> {
    let handle = new_handle()?;
    let mode = xfrm_mode(keying.mode());
    let if_id = if keying.mode() == api::sa_keying::Mode::Tunnel {
        Some(tunnel_if_id(tunnel_id).get())
    } else {
        None
    };

    let sa_src: IpAddr = keying.sa_src.parse()?;
    let sa_dst: IpAddr = keying.sa_dst.parse()?;

    // Inbound SA (peer → us)
    add_sa(
        &handle,
        sa_dst,
        sa_src,
        &keying.spi_inbound,
        &keying.encryption_algorithm,
        &keying.encryption_key_inbound,
        &keying.integrity_algorithm,
        &keying.integrity_key_inbound,
        mode,
        keying.expires,
        if_id,
    )
    .await?;
    debug!(tunnel_id, "installed inbound SA");

    // Outbound SA (us → peer)
    add_sa(
        &handle,
        sa_src,
        sa_dst,
        &keying.spi_outbound,
        &keying.encryption_algorithm,
        &keying.encryption_key_outbound,
        &keying.integrity_algorithm,
        &keying.integrity_key_outbound,
        mode,
        keying.expires,
        if_id,
    )
    .await?;
    debug!(tunnel_id, "installed outbound SA");

    Ok(())
}

fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8)> {
    if let Some((addr_str, prefix_str)) = cidr.split_once('/') {
        let addr: IpAddr = addr_str.parse()?;
        let prefix: u8 = prefix_str.parse()?;
        Ok((addr, prefix))
    } else {
        let addr: IpAddr = cidr.parse()?;
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Ok((addr, prefix))
    }
}

fn policy_priority(src_prefix: u8, dst_prefix: u8) -> u32 {
    const BASE: u32 = 2000;
    BASE - u32::from(src_prefix) - u32::from(dst_prefix)
}

async fn add_policy(
    handle: &Handle,
    sel_src: IpAddr,
    sel_src_prefix: u8,
    sel_dst: IpAddr,
    sel_dst_prefix: u8,
    tmpl_src: IpAddr,
    tmpl_dst: IpAddr,
    direction: u8,
    mode: u8,
    if_id: Option<u32>,
) -> Result<()> {
    let mut template = UserTemplate::default();
    template.source(&tmpl_src);
    template.destination(&tmpl_dst);
    template.protocol(libc::IPPROTO_ESP.try_into()?);
    template.mode(mode);

    let mut req = handle
        .policy()
        .add(sel_src, sel_src_prefix, sel_dst, sel_dst_prefix)
        .direction(direction)
        .priority(policy_priority(sel_src_prefix, sel_dst_prefix))
        .add_template(template);

    if let Some(id) = if_id {
        req = req.ifid(id);
    }

    req.execute().await?;
    Ok(())
}

async fn add_ike_bypass(
    handle: &Handle,
    src: IpAddr,
    dst: IpAddr,
    direction: u8,
) -> Result<()> {
    let prefix = if src.is_ipv4() { 32 } else { 128 };
    handle
        .policy()
        .add(src, prefix, dst, prefix)
        .direction(direction)
        .priority(500)
        .selector_protocol(libc::IPPROTO_UDP.try_into()?)
        .selector_protocol_dst_port(500)
        .execute()
        .await?;
    Ok(())
}

/// Install XFRM policies for a child SA (outbound, inbound, forward).
/// For transport mode, also installs IKE bypass policies.
pub async fn install_policies(tunnel_id: &str, child_up: &api::ChildUp) -> Result<()> {
    let keying = child_up
        .keying
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ChildUp missing keying material"))?;
    let handle = new_handle()?;
    let mode = keying.mode();
    let mode_val = xfrm_mode(mode);
    let if_id = if mode == api::sa_keying::Mode::Tunnel {
        Some(tunnel_if_id(tunnel_id).get())
    } else {
        None
    };

    let sa_src: IpAddr = keying.sa_src.parse()?;
    let sa_dst: IpAddr = keying.sa_dst.parse()?;

    if mode == api::sa_keying::Mode::Transport {
        add_ike_bypass(&handle, sa_src, sa_dst, XFRM_POLICY_OUT).await?;
        add_ike_bypass(&handle, sa_dst, sa_src, XFRM_POLICY_IN).await?;
        add_ike_bypass(&handle, sa_dst, sa_src, XFRM_POLICY_FWD).await?;
        debug!(tunnel_id, "installed IKE bypass policies");
    }

    for local in &child_up.local_prefixes {
        for remote in &child_up.remote_prefixes {
            let (local_addr, local_prefix) = parse_cidr(&local.cidr)?;
            let (remote_addr, remote_prefix) = parse_cidr(&remote.cidr)?;

            add_policy(
                &handle, local_addr, local_prefix, remote_addr, remote_prefix,
                sa_src, sa_dst, XFRM_POLICY_OUT, mode_val, if_id,
            )
            .await?;
            add_policy(
                &handle, remote_addr, remote_prefix, local_addr, local_prefix,
                sa_dst, sa_src, XFRM_POLICY_IN, mode_val, if_id,
            )
            .await?;
            add_policy(
                &handle, remote_addr, remote_prefix, local_addr, local_prefix,
                sa_dst, sa_src, XFRM_POLICY_FWD, mode_val, if_id,
            )
            .await?;
        }
    }

    debug!(tunnel_id, "installed XFRM policies");
    Ok(())
}

/// Remove both directions of a child SA.
pub async fn remove_child_sa(child_down: &api::ChildDown) -> Result<()> {
    let handle = new_handle()?;

    let sa_src: IpAddr = child_down.sa_src.parse()?;
    let sa_dst: IpAddr = child_down.sa_dst.parse()?;

    del_sa(&handle, sa_dst, sa_src, &child_down.spi_inbound).await?;
    debug!(tunnel_id = %child_down.tunnel_id, "removed inbound SA");

    del_sa(&handle, sa_src, sa_dst, &child_down.spi_outbound).await?;
    debug!(tunnel_id = %child_down.tunnel_id, "removed outbound SA");

    Ok(())
}
