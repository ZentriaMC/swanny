use cidr::IpCidr;
use std::net::IpAddr;
use swanny_ikev2::{
    message::num::{EncrId, IntegId},
    sa::{ChildSa, ChildSaMode},
};
use swanny_proto::api;

use crate::grpc::now_timestamp;

fn encr_id_to_proto(id: EncrId) -> &'static str {
    match id {
        EncrId::ENCR_AES_CBC => "ENCR_AES_CBC",
        EncrId::ENCR_AES_GCM_8 => "ENCR_AES_GCM_8",
        EncrId::ENCR_AES_GCM_12 => "ENCR_AES_GCM_12",
        EncrId::ENCR_AES_GCM_16 => "ENCR_AES_GCM_16",
        _ => "UNKNOWN",
    }
}

fn integ_id_to_proto(id: IntegId) -> &'static str {
    match id {
        IntegId::AUTH_HMAC_MD5_96 => "AUTH_HMAC_MD5_96",
        IntegId::AUTH_HMAC_SHA1_96 => "AUTH_HMAC_SHA1_96",
        IntegId::AUTH_HMAC_SHA2_256_128 => "AUTH_HMAC_SHA2_256_128",
        IntegId::AUTH_HMAC_SHA2_384_192 => "AUTH_HMAC_SHA2_384_192",
        IntegId::AUTH_HMAC_SHA2_512_256 => "AUTH_HMAC_SHA2_512_256",
        _ => "UNKNOWN",
    }
}

fn mode_to_proto(mode: ChildSaMode) -> i32 {
    match mode {
        ChildSaMode::Tunnel => api::sa_keying::Mode::Tunnel as i32,
        ChildSaMode::Transport => api::sa_keying::Mode::Transport as i32,
    }
}

fn cidrs_to_prefixes(cidrs: &[IpCidr]) -> Vec<api::IpPrefix> {
    cidrs
        .iter()
        .map(|c| api::IpPrefix {
            cidr: c.to_string(),
        })
        .collect()
}

/// Determine whether we are the IKE initiator (ts_i covers local traffic).
fn ts_i_is_local(child: &ChildSa, local_ts: &[IpCidr]) -> bool {
    local_ts
        .iter()
        .any(|cidr| cidr.contains(&child.ts_i().start_address()))
}

/// Build SaKeying from a ChildSa.
///
/// All directional fields (sa_src/sa_dst, SPIs, keys) are from the
/// **local** perspective:
/// - sa_src = local endpoint, sa_dst = remote endpoint
/// - spi_inbound = our SPI (peer uses this when sending to us)
/// - spi_outbound = peer's SPI (we use this when sending to them)
/// - key_inbound = key to decrypt incoming traffic
/// - key_outbound = key to encrypt outgoing traffic
fn build_sa_keying(
    child: &ChildSa,
    local_ts: &[IpCidr],
    src_address: IpAddr,
    dst_address: IpAddr,
    mode: ChildSaMode,
    expires: Option<u64>,
) -> api::SaKeying {
    let we_are_initiator = ts_i_is_local(child, local_ts);

    let (sa_src, sa_dst) = match mode {
        ChildSaMode::Transport => {
            if we_are_initiator {
                (child.ts_i().start_address().to_string(), child.ts_r().start_address().to_string())
            } else {
                (child.ts_r().start_address().to_string(), child.ts_i().start_address().to_string())
            }
        }
        // In tunnel mode, src/dst_address are always from the local perspective
        // (config.address / config.peer_address), regardless of IKE role.
        ChildSaMode::Tunnel => (src_address.to_string(), dst_address.to_string()),
    };

    // SPIs: initiator assigned spi_i for its inbound, responder assigned spi_r for its inbound.
    // Keys: ei/ai are used by the initiator for outbound; er/ar by the responder for outbound.
    let (spi_inbound, spi_outbound, enc_key_in, enc_key_out, integ_key_in, integ_key_out) =
        if we_are_initiator {
            (
                child.spi_i().to_vec(),
                child.spi_r().to_vec(),
                child.keys().er.key().as_ref().to_vec(),
                child.keys().ei.key().as_ref().to_vec(),
                child.keys().ar.as_ref().map(|k| k.key().as_ref().to_vec()).unwrap_or_default(),
                child.keys().ai.as_ref().map(|k| k.key().as_ref().to_vec()).unwrap_or_default(),
            )
        } else {
            (
                child.spi_r().to_vec(),
                child.spi_i().to_vec(),
                child.keys().ei.key().as_ref().to_vec(),
                child.keys().er.key().as_ref().to_vec(),
                child.keys().ai.as_ref().map(|k| k.key().as_ref().to_vec()).unwrap_or_default(),
                child.keys().ar.as_ref().map(|k| k.key().as_ref().to_vec()).unwrap_or_default(),
            )
        };

    let enc_alg = encr_id_to_proto(child.chosen_proposal().cipher().id());
    let integ_alg = child
        .chosen_proposal()
        .integ()
        .map(|i| integ_id_to_proto(i.id()))
        .unwrap_or("");

    api::SaKeying {
        spi_inbound,
        spi_outbound,
        encryption_algorithm: enc_alg.to_string(),
        integrity_algorithm: integ_alg.to_string(),
        encryption_key_inbound: enc_key_in,
        encryption_key_outbound: enc_key_out,
        integrity_key_inbound: integ_key_in,
        integrity_key_outbound: integ_key_out,
        sa_src,
        sa_dst,
        mode: mode_to_proto(mode),
        expires: expires.unwrap_or(0),
    }
}

/// Build a ChildUp event from a newly created ChildSa.
pub fn child_up_event(
    tunnel_id: &str,
    child: &ChildSa,
    local_ts: &[IpCidr],
    remote_ts: &[IpCidr],
    src_address: IpAddr,
    dst_address: IpAddr,
    mode: ChildSaMode,
    expires: Option<u64>,
) -> api::Event {
    let keying = build_sa_keying(child, local_ts, src_address, dst_address, mode, expires);

    api::Event {
        timestamp: now_timestamp(),
        event: Some(api::event::Event::ChildUp(api::ChildUp {
            tunnel_id: tunnel_id.to_string(),
            peer_address: dst_address.to_string(),
            local_prefixes: cidrs_to_prefixes(local_ts),
            remote_prefixes: cidrs_to_prefixes(remote_ts),
            keying: Some(keying),
        })),
    }
}

/// Build a ChildDown event from a deleted ChildSa.
pub fn child_down_event(
    tunnel_id: &str,
    child: &ChildSa,
    local_ts: &[IpCidr],
    remote_ts: &[IpCidr],
    src_address: IpAddr,
    dst_address: IpAddr,
    mode: ChildSaMode,
    reason: api::child_down::Reason,
) -> api::Event {
    let we_are_initiator = ts_i_is_local(child, local_ts);

    let (sa_src, sa_dst) = match mode {
        ChildSaMode::Transport => {
            if we_are_initiator {
                (child.ts_i().start_address().to_string(), child.ts_r().start_address().to_string())
            } else {
                (child.ts_r().start_address().to_string(), child.ts_i().start_address().to_string())
            }
        }
        ChildSaMode::Tunnel => (src_address.to_string(), dst_address.to_string()),
    };

    let (spi_inbound, spi_outbound) = if we_are_initiator {
        (child.spi_i().to_vec(), child.spi_r().to_vec())
    } else {
        (child.spi_r().to_vec(), child.spi_i().to_vec())
    };

    api::Event {
        timestamp: now_timestamp(),
        event: Some(api::event::Event::ChildDown(api::ChildDown {
            tunnel_id: tunnel_id.to_string(),
            peer_address: dst_address.to_string(),
            local_prefixes: cidrs_to_prefixes(local_ts),
            remote_prefixes: cidrs_to_prefixes(remote_ts),
            spi_inbound,
            spi_outbound,
            sa_src,
            sa_dst,
            reason: reason as i32,
        })),
    }
}
