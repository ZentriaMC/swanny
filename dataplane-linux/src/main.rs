use std::collections::HashSet;
use std::num::NonZeroU32;

use anyhow::Result;
use blake2::{Blake2s256, Digest};
use clap::{Command, arg, command};
use swanny_proto::api::{self, tunnel_service_client::TunnelServiceClient};
use tonic::transport::Channel;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod xfrm;

/// Deterministic mapping from tunnel ID to a non-zero u32 XFRM `if_id`.
///
/// Derived from `blake2s(tunnel_id)` truncated to 4 bytes.
pub fn tunnel_if_id(tunnel_id: &str) -> NonZeroU32 {
    let hash = Blake2s256::digest(tunnel_id.as_bytes());
    let raw = u32::from_le_bytes(hash[..4].try_into().expect("slice is 4 bytes"));
    NonZeroU32::new(raw).unwrap_or(NonZeroU32::new(1).unwrap())
}

async fn run(mut client: TunnelServiceClient<Channel>) -> Result<()> {
    let mut policies_installed: HashSet<String> = HashSet::new();

    // Reconcile existing state on startup.
    let snapshot = client
        .snapshot(api::SnapshotRequest {
            tunnel_id: String::new(),
        })
        .await?
        .into_inner();

    for tunnel in &snapshot.tunnels {
        info!(
            tunnel_id = %tunnel.id,
            status = ?tunnel.status(),
            children = tunnel.children.len(),
            "reconciling tunnel from snapshot"
        );
        for child in &tunnel.children {
            if let Some(keying) = &child.keying {
                if let Err(err) = xfrm::install_child_sa(&tunnel.id, keying).await {
                    warn!(?err, tunnel_id = %tunnel.id, "failed to reconcile child SA");
                }
            }
        }
        if !tunnel.children.is_empty() {
            if let Some(first_child) = tunnel.children.first() {
                let child_up = api::ChildUp {
                    tunnel_id: tunnel.id.clone(),
                    peer_address: tunnel.peer_address.clone(),
                    local_prefixes: first_child.local_prefixes.clone(),
                    remote_prefixes: first_child.remote_prefixes.clone(),
                    keying: first_child.keying.clone(),
                };
                if let Err(err) = xfrm::install_policies(&tunnel.id, &child_up).await {
                    warn!(?err, tunnel_id = %tunnel.id, "failed to reconcile policies");
                } else {
                    policies_installed.insert(tunnel.id.clone());
                }
            }
        }
    }

    // Subscribe to the event stream.
    let mut stream = client
        .subscribe(api::SubscribeRequest {
            tunnel_id: String::new(),
        })
        .await?
        .into_inner();

    info!("subscribed to event stream");

    while let Some(event) = stream.message().await? {
        match event.event {
            Some(api::event::Event::ChildUp(child_up)) => {
                info!(tunnel_id = %child_up.tunnel_id, "child SA up");
                if let Some(keying) = &child_up.keying {
                    if let Err(err) = xfrm::install_child_sa(&child_up.tunnel_id, keying).await {
                        error!(?err, tunnel_id = %child_up.tunnel_id, "failed to install child SA");
                    }
                } else {
                    warn!(tunnel_id = %child_up.tunnel_id, "ChildUp without keying material");
                }
                if !policies_installed.contains(&child_up.tunnel_id) {
                    if let Err(err) = xfrm::install_policies(&child_up.tunnel_id, &child_up).await {
                        error!(?err, tunnel_id = %child_up.tunnel_id, "failed to install policies");
                    } else {
                        policies_installed.insert(child_up.tunnel_id.clone());
                    }
                }
            }
            Some(api::event::Event::ChildDown(child_down)) => {
                info!(tunnel_id = %child_down.tunnel_id, "child SA down");
                if let Err(err) = xfrm::remove_child_sa(&child_down).await {
                    error!(?err, tunnel_id = %child_down.tunnel_id, "failed to remove child SA");
                }
            }
            Some(api::event::Event::ChildRekeyed(rekeyed)) => {
                info!(tunnel_id = %rekeyed.tunnel_id, "child SA rekeyed");
                if let Some(keying) = &rekeyed.keying {
                    if let Err(err) = xfrm::install_child_sa(&rekeyed.tunnel_id, keying).await {
                        error!(?err, tunnel_id = %rekeyed.tunnel_id, "failed to install rekeyed child SA");
                    }
                }
            }
            Some(api::event::Event::TunnelUp(up)) => {
                info!(tunnel_id = %up.tunnel_id, peer = %up.peer_address, "tunnel up");
            }
            Some(api::event::Event::TunnelDown(down)) => {
                info!(tunnel_id = %down.tunnel_id, reason = ?down.reason(), "tunnel down");
            }
            Some(api::event::Event::PeerReachable(dpd)) => {
                if !dpd.alive {
                    warn!(tunnel_id = %dpd.tunnel_id, "peer unreachable");
                }
            }
            None => {}
        }
    }

    info!("event stream ended");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .map_err(|err| anyhow::anyhow!(err))?;

    let matches = command!()
        .arg(arg!(--endpoint <URI> "swanny gRPC endpoint").default_value("http://[::1]:50051"))
        .subcommand(
            Command::new("print-if-id")
                .about("Print the XFRM if_id for a tunnel ID and exit")
                .arg(arg!(<TUNNEL_ID> "Tunnel identifier")),
        )
        .get_matches();

    if let Some(sub) = matches.subcommand_matches("print-if-id") {
        let tunnel_id: &String = sub.get_one("TUNNEL_ID").unwrap();
        println!("{}", tunnel_if_id(tunnel_id));
        return Ok(());
    }

    let endpoint: &String = matches.get_one("endpoint").unwrap();

    info!(endpoint = %endpoint, "connecting to swanny");
    let client = TunnelServiceClient::connect(endpoint.clone()).await?;

    run(client).await
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tunnel_if_id_deterministic() {
        let a = tunnel_if_id("energycorp-site-north");
        let b = tunnel_if_id("energycorp-site-north");
        assert_eq!(a, b);
    }

    #[test]
    fn tunnel_if_id_different_inputs() {
        let a = tunnel_if_id("energycorp-site-north");
        let b = tunnel_if_id("energycorp-site-south");
        assert_ne!(a, b);
    }

    #[test]
    fn tunnel_if_id_nonzero() {
        for i in 0..1000 {
            let id = format!("tunnel-{i}");
            assert_ne!(tunnel_if_id(&id).get(), 0);
        }
    }
}
