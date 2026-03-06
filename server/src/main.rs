use anyhow::Result;
use bytes::Bytes;
use cidr::IpCidr;
use futures::{
    FutureExt, SinkExt,
    channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded},
    stream::{FuturesUnordered, StreamExt},
};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::net::UdpSocket as StdUdpSocket;
use std::pin::Pin;
use swanny_ikev2::{
    StateError,
    config::ConfigBuilder,
    message::{
        Header, Spi,
        num::{
            DhId, EncrId, EsnId, ExchangeType, IdType, IntegId, MessageFlags, PrfId, Protocol,
            TrafficSelectorType,
        },
        payload::Id,
        traffic_selector::TrafficSelector,
    },
    sa::{ChildSaMode, ControlMessage, IkeSa},
};
use swanny_proto::api::tunnel_service_server::TunnelServiceServer;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tokio_util::{codec::BytesCodec, udp::UdpFramed};
use tonic::transport::Server;
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod config;
mod events;
mod grpc;

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

fn create_ike_sa_config(config: &config::Config) -> swanny_ikev2::config::Config {
    let id = config
        .local_identity
        .clone()
        .unwrap_or_else(|| match &config.address {
            IpAddr::V4(v4) => Id::new(IdType::ID_IPV4_ADDR.into(), &v4.octets()[..]),
            IpAddr::V6(v6) => Id::new(IdType::ID_IPV6_ADDR.into(), &v6.octets()[..]),
        });
    info!(identity = %id, "using local IKE identity");
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

    let mut builder = builder
        .psk(&config.psk)
        .mode(config.mode.into())
        .strict_ts(config.strict_ts);

    if let Some(remote_id) = &config.remote_identity {
        info!(remote_identity = %remote_id, "expecting remote IKE identity");
        builder = builder.remote_id(remote_id.clone());
    }

    builder.build(id).expect("building config should succeed")
}

/// Spawns a task that forwards control messages from an SA's receiver
/// to the shared tagged channel.
fn register_sa(
    sa_table: &mut HashMap<Spi, IkeSa>,
    spi: Spi,
    sa: IkeSa,
    rx: UnboundedReceiver<ControlMessage>,
    shared_tx: UnboundedSender<(Spi, ControlMessage)>,
) {
    sa_table.insert(spi, sa);
    tokio::spawn(async move {
        let mut rx = rx;
        while let Some(msg) = rx.next().await {
            if shared_tx.unbounded_send((spi, msg)).is_err() {
                break;
            }
        }
    });
    info!(spi = ?&spi, "registered IKE SA");
}

/// Routes an incoming IKE message to the correct SA by parsing the header.
///
/// Returns the local SPI to route to, creating a new SA if this is an
/// IKE_SA_INIT request from the peer.
fn route_incoming_message(
    message: &[u8],
    sa_table: &mut HashMap<Spi, IkeSa>,
    ike_sa_config: &swanny_ikev2::config::Config,
    shared_tx: &UnboundedSender<(Spi, ControlMessage)>,
) -> Result<Option<Spi>> {
    let mut buf: &[u8] = message;
    let (header, _) = Header::deserialize(&mut buf)?;

    let zero_spi = Spi::default();

    // IKE_SA_INIT request from peer: SPI_r == 0, I flag set
    if *header.spi_r() == zero_spi
        && header.flags().contains(MessageFlags::I)
        && header.exchange().assigned() == Some(ExchangeType::IKE_SA_INIT)
    {
        let (sa, rx) = IkeSa::new(ike_sa_config)?;
        let spi = sa.spi();
        register_sa(sa_table, spi, sa, rx, shared_tx.clone());
        return Ok(Some(spi));
    }

    // Determine our local SPI from the message flags:
    // - I flag set: sender is the initiator → we're responder → our SPI is SPI_r
    // - I flag not set: sender is the responder → we're initiator → our SPI is SPI_i
    let local_spi = if header.flags().contains(MessageFlags::I) {
        *header.spi_r()
    } else {
        *header.spi_i()
    };

    if sa_table.contains_key(&local_spi) {
        Ok(Some(local_spi))
    } else {
        debug!(spi = ?&local_spi, "no SA found for SPI, dropping message");
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let socket = StdUdpSocket::bind((config.address, 500))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket)?;
    let mut framed = UdpFramed::new(socket, BytesCodec::new()).fuse();

    // gRPC event bus and server.
    let event_bus = grpc::EventBus::new(256);
    let grpc_service = grpc::TunnelServiceImpl::new(event_bus.clone());
    let grpc_addr = config.grpc_listen;
    tokio::spawn(async move {
        info!(addr = %grpc_addr, "starting gRPC server");
        if let Err(err) = Server::builder()
            .add_service(TunnelServiceServer::new(grpc_service))
            .serve(grpc_addr)
            .await
        {
            tracing::error!(?err, "gRPC server failed");
        }
    });

    let ike_sa_config = create_ike_sa_config(&config);

    let tunnel_id = &config.tunnel_id;

    // SA table keyed by local SPI, with a shared control message channel.
    let mut sa_table: HashMap<Spi, IkeSa> = HashMap::new();
    let (shared_tx, mut shared_rx) = unbounded::<(Spi, ControlMessage)>();

    let mut pending_operations: FuturesUnordered<
        Pin<Box<dyn Future<Output = Result<(), StateError>>>>,
    > = FuturesUnordered::new();

    // Track the primary (most recently established) SA for DPD and rekey.
    let mut primary_spi: Option<Spi> = None;

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

    if config.initiate {
        let ts_i = traffic_selector_from_cidr(&config.local_ts[0]);
        let ts_r = traffic_selector_from_cidr(&config.remote_ts[0]);

        let (sa, rx) = IkeSa::new(&ike_sa_config)?;
        let spi = sa.spi();
        register_sa(&mut sa_table, spi, sa.clone(), rx, shared_tx.clone());
        primary_spi = Some(spi);

        pending_operations.push(async move { sa.handle_acquire(ts_i, ts_r).await }.boxed_local());

        info!("auto-initiating IKE negotiation");
    }

    loop {
        futures::select! {
            tagged_msg = shared_rx.select_next_some() => {
                let (sa_spi, msg) = tagged_msg;
                match msg {
                    ControlMessage::IkeMessage(message) => {
                        let message: Bytes = message.into();
                        let peer_address: std::net::SocketAddr = (config.peer_address, 500).into();
                        framed.send((message, peer_address)).await?;
                    },
                    ControlMessage::CreateChildSa(child_sa) => {
                        event_bus.emit(events::child_up_event(
                            tunnel_id,
                            &child_sa,
                            &config.local_ts,
                            &config.remote_ts,
                            config.address,
                            config.peer_address,
                            config.mode.into(),
                            config.expires,
                        ));
                        primary_spi = Some(sa_spi);
                        ike_rekey_timer = sleep(ike_lifetime_duration).boxed().fuse();
                        dpd_timer = sleep(dpd_interval).boxed().fuse();
                    }
                    ControlMessage::DeleteChildSa(child_sa) => {
                        event_bus.emit(events::child_down_event(
                            tunnel_id,
                            &child_sa,
                            &config.local_ts,
                            &config.remote_ts,
                            config.address,
                            config.peer_address,
                            config.mode.into(),
                            swanny_proto::api::child_down::Reason::Peer,
                        ));
                    }
                    ControlMessage::InitialContact(peer_id) => {
                        let stale_spis: Vec<Spi> = sa_table
                            .keys()
                            .filter(|&&spi| spi != sa_spi)
                            .copied()
                            .collect();

                        info!(
                            peer_id = %peer_id,
                            sa_spi = ?&sa_spi,
                            stale_count = stale_spis.len(),
                            "INITIAL_CONTACT received, tearing down stale SAs"
                        );

                        for spi in stale_spis {
                            if let Some(sa) = sa_table.remove(&spi) {
                                let local_ts = config.local_ts.clone();
                                let remote_ts = config.remote_ts.clone();
                                let src = config.address;
                                let dst = config.peer_address;
                                let mode: ChildSaMode = config.mode.into();
                                let event_bus = event_bus.clone();
                                let tunnel_id = tunnel_id.to_string();
                                pending_operations.push(async move {
                                    let child_sas = sa.child_sas().await;
                                    for child in &child_sas {
                                        event_bus.emit(events::child_down_event(
                                            &tunnel_id,
                                            child,
                                            &local_ts,
                                            &remote_ts,
                                            src,
                                            dst,
                                            mode,
                                            swanny_proto::api::child_down::Reason::Peer,
                                        ));
                                    }
                                    info!(spi = ?spi, child_sas = child_sas.len(), "tore down stale IKE SA");
                                    Ok(())
                                }.boxed_local());
                            }
                        }

                        primary_spi = Some(sa_spi);
                    }
                }
            },
            result = framed.select_next_some() => {
                match result {
                    Ok((message, _peer_address)) => {
                        if let Some(spi) = route_incoming_message(
                            &message,
                            &mut sa_table,
                            &ike_sa_config,
                            &shared_tx,
                        )? {
                            if let Some(sa) = sa_table.get(&spi).cloned() {
                                let message = message.to_vec();
                                pending_operations.push(async move {
                                    sa.handle_message(message).await
                                }.boxed_local());
                            }
                        }
                        dpd_timer = sleep(dpd_interval).boxed().fuse();
                    },
                    Err(err) => {
                        debug!(?err, "error receiving IKEv2 message");
                    },
                }
            }
            _ = &mut ike_rekey_timer => {
                if let Some(spi) = primary_spi {
                    if let Some(sa) = sa_table.get(&spi).cloned() {
                        info!("IKE SA lifetime expired, initiating rekey");
                        pending_operations.push(async move {
                            sa.handle_rekey_ike_sa().await
                        }.boxed_local());
                    }
                }
                ike_rekey_timer = sleep(ike_lifetime_duration).boxed().fuse();
            }
            _ = &mut dpd_timer => {
                if let Some(spi) = primary_spi {
                    if let Some(sa) = sa_table.get(&spi).cloned() {
                        debug!("DPD interval expired, sending probe");
                        pending_operations.push(async move {
                            sa.handle_dpd().await
                        }.boxed_local());
                    }
                }
                dpd_timer = sleep(dpd_interval).boxed().fuse();
            }
            result = pending_operations.select_next_some() => {
                debug!(result = ?result, "pending operation completed");
            }
        }
    }
}
