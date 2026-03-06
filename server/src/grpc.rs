use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use prost_types::Timestamp;
use swanny_proto::api::{self, tunnel_service_server::TunnelService};
use tokio::sync::broadcast;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};

/// Tracks active child SAs per tunnel for snapshot reconciliation.
///
/// When a dataplane daemon connects after IKE has already completed,
/// it calls `Snapshot()` to retrieve the current state.
#[derive(Clone, Default)]
pub struct TunnelState {
    inner: Arc<Mutex<HashMap<String, TunnelEntry>>>,
}

struct TunnelEntry {
    peer_address: String,
    children: Vec<api::ChildSnapshot>,
}

impl TunnelState {
    pub fn child_up(&self, tunnel_id: &str, child_up: &api::ChildUp) {
        let mut map = self.inner.lock().unwrap();
        let entry = map
            .entry(tunnel_id.to_string())
            .or_insert_with(|| TunnelEntry {
                peer_address: child_up.peer_address.clone(),
                children: Vec::new(),
            });
        entry.children.push(api::ChildSnapshot {
            local_prefixes: child_up.local_prefixes.clone(),
            remote_prefixes: child_up.remote_prefixes.clone(),
            negotiated: None,
            keying: child_up.keying.clone(),
        });
    }

    pub fn child_down(&self, tunnel_id: &str, child_down: &api::ChildDown) {
        let mut map = self.inner.lock().unwrap();
        if let Some(entry) = map.get_mut(tunnel_id) {
            entry.children.retain(|c| {
                c.keying.as_ref().map(|k| &k.spi_inbound) != Some(&child_down.spi_inbound)
            });
        }
    }

    pub fn snapshots(&self) -> Vec<api::TunnelSnapshot> {
        let map = self.inner.lock().unwrap();
        map.iter()
            .map(|(id, entry)| api::TunnelSnapshot {
                id: id.clone(),
                status: api::TunnelStatus::Established as i32,
                peer_address: entry.peer_address.clone(),
                children: entry.children.clone(),
            })
            .collect()
    }
}

/// Shared event broadcaster. The event loop sends events here;
/// Subscribe() clients receive them via broadcast receivers.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<api::Event>,
    state: TunnelState,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            state: TunnelState::default(),
        }
    }

    /// Send an event to all subscribers and update tracked state.
    pub fn emit(&self, event: api::Event) {
        match &event.event {
            Some(api::event::Event::ChildUp(child_up)) => {
                self.state.child_up(&child_up.tunnel_id, child_up);
            }
            Some(api::event::Event::ChildDown(child_down)) => {
                self.state.child_down(&child_down.tunnel_id, child_down);
            }
            _ => {}
        }
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<api::Event> {
        self.tx.subscribe()
    }

    pub fn state(&self) -> &TunnelState {
        &self.state
    }
}

pub struct TunnelServiceImpl {
    event_bus: EventBus,
}

impl TunnelServiceImpl {
    pub fn new(event_bus: EventBus) -> Self {
        Self { event_bus }
    }
}

#[tonic::async_trait]
impl TunnelService for TunnelServiceImpl {
    type SubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<api::Event, Status>> + Send>>;

    async fn create(
        &self,
        _request: Request<api::CreateTunnelRequest>,
    ) -> Result<Response<api::Tunnel>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn delete(
        &self,
        _request: Request<api::DeleteTunnelRequest>,
    ) -> Result<Response<api::DeleteTunnelResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn get(
        &self,
        _request: Request<api::GetTunnelRequest>,
    ) -> Result<Response<api::Tunnel>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn list(
        &self,
        _request: Request<api::ListTunnelsRequest>,
    ) -> Result<Response<api::ListTunnelsResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn up(
        &self,
        _request: Request<api::TunnelUpRequest>,
    ) -> Result<Response<api::TunnelUpResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn down(
        &self,
        _request: Request<api::TunnelDownRequest>,
    ) -> Result<Response<api::TunnelDownResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn subscribe(
        &self,
        request: Request<api::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let filter_tunnel_id = request.into_inner().tunnel_id;
        let rx = self.event_bus.subscribe();

        let stream = BroadcastStream::new(rx)
            .filter_map(|result| match result {
                Ok(event) => Some(event),
                Err(err) => {
                    tracing::warn!(?err, "broadcast receive error");
                    None
                }
            })
            .filter(move |event| {
                filter_tunnel_id.is_empty()
                    || event_tunnel_id(event) == Some(filter_tunnel_id.as_str())
            })
            .map(Ok);

        Ok(Response::new(Box::pin(stream)))
    }

    async fn snapshot(
        &self,
        request: Request<api::SnapshotRequest>,
    ) -> Result<Response<api::SnapshotResponse>, Status> {
        let filter = request.into_inner().tunnel_id;
        let mut tunnels = self.event_bus.state().snapshots();
        if !filter.is_empty() {
            tunnels.retain(|t| t.id == filter);
        }
        Ok(Response::new(api::SnapshotResponse { tunnels }))
    }
}

/// Extract tunnel_id from an event for filtering.
fn event_tunnel_id(event: &api::Event) -> Option<&str> {
    match &event.event {
        Some(api::event::Event::TunnelUp(e)) => Some(&e.tunnel_id),
        Some(api::event::Event::TunnelDown(e)) => Some(&e.tunnel_id),
        Some(api::event::Event::ChildUp(e)) => Some(&e.tunnel_id),
        Some(api::event::Event::ChildDown(e)) => Some(&e.tunnel_id),
        Some(api::event::Event::ChildRekeyed(e)) => Some(&e.tunnel_id),
        Some(api::event::Event::PeerReachable(e)) => Some(&e.tunnel_id),
        None => None,
    }
}

/// Helper to create a proto timestamp for now.
pub fn now_timestamp() -> Option<Timestamp> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| Timestamp {
            seconds: d.as_secs() as i64,
            nanos: d.subsec_nanos() as i32,
        })
}
