use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use metrics::{counter, gauge, histogram};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, RwLock, Semaphore};
use uuid::Uuid;

/// Lightweight registry for active agent tunnels.
#[derive(Clone, Default)]
pub struct TunnelRegistry {
    inner: Arc<RwLock<HashMap<Uuid, TunnelSession>>>,
    failures: Arc<RwLock<HashMap<Uuid, TunnelFailure>>>,
}

#[derive(Clone)]
pub struct TunnelSession {
    pub tunnel_id: Uuid,
    pub last_heartbeat: Instant,
    pub command_tx: mpsc::Sender<TunnelCommand>,
    pub inflight: Arc<Semaphore>,
}

#[derive(Clone, Debug)]
struct TunnelFailure {
    pub reason: String,
    pub at: Instant,
}

impl TunnelRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            failures: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn upsert(
        &self,
        node_id: Uuid,
        tunnel_id: Uuid,
        command_tx: mpsc::Sender<TunnelCommand>,
        inflight: Arc<Semaphore>,
    ) {
        let mut guard = self.inner.write().await;
        guard.insert(
            node_id,
            TunnelSession {
                tunnel_id,
                last_heartbeat: Instant::now(),
                command_tx,
                inflight,
            },
        );
        // Clear any previous failure record now that the node is connected again.
        let mut failures = self.failures.write().await;
        failures.remove(&node_id);
        gauge!("control_plane_tunnel_sessions").set(guard.len() as f64);
    }

    pub async fn touch_heartbeat(&self, node_id: Uuid) {
        let mut guard = self.inner.write().await;
        if let Some(session) = guard.get_mut(&node_id) {
            session.last_heartbeat = Instant::now();
        }
    }

    pub async fn remove(&self, node_id: Uuid, reason: &str) {
        let mut guard = self.inner.write().await;
        let existed = guard.remove(&node_id).is_some();
        if existed {
            counter!(
                "control_plane_tunnel_disconnect_total",
                "reason" => reason.to_string()
            )
            .increment(1);
            gauge!("control_plane_tunnel_sessions").set(guard.len() as f64);
            let mut failures = self.failures.write().await;
            failures.insert(
                node_id,
                TunnelFailure {
                    reason: reason.to_string(),
                    at: Instant::now(),
                },
            );
        }
    }

    pub async fn snapshot(&self) -> TunnelRegistrySnapshot {
        let guard = self.inner.read().await;
        let total = guard.len();
        let newest = guard
            .values()
            .map(|s| Instant::now().saturating_duration_since(s.last_heartbeat))
            .min();
        let now = Instant::now();
        let failures = self.failures.read().await;
        let mut statuses: Vec<NodeTunnelStatus> = guard
            .iter()
            .map(|(node_id, session)| NodeTunnelStatus {
                node_id: *node_id,
                status: TunnelStatus::Connected,
                last_heartbeat_secs: Some(
                    now.saturating_duration_since(session.last_heartbeat)
                        .as_secs(),
                ),
                last_error: None,
                last_event_secs: None,
            })
            .collect();
        statuses.extend(failures.iter().map(|(node_id, failure)| NodeTunnelStatus {
            node_id: *node_id,
            status: TunnelStatus::Disconnected,
            last_heartbeat_secs: None,
            last_error: Some(failure.reason.clone()),
            last_event_secs: Some(now.saturating_duration_since(failure.at).as_secs()),
        }));
        TunnelRegistrySnapshot {
            total,
            freshest_heartbeat_age: newest,
            statuses,
        }
    }

    pub async fn contains(&self, node_id: Uuid) -> bool {
        let guard = self.inner.read().await;
        guard.contains_key(&node_id)
    }

    pub async fn acquire(
        &self,
        node_id: Uuid,
    ) -> Result<(mpsc::Sender<TunnelCommand>, OwnedSemaphorePermit), ForwardError> {
        let guard = self.inner.read().await;
        let Some(session) = guard.get(&node_id) else {
            return Err(ForwardError::NoTunnel);
        };

        let permit = session
            .inflight
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForwardError::Overloaded)?;

        Ok((session.command_tx.clone(), permit))
    }
}

#[derive(Clone, Debug)]
pub struct TunnelRegistrySnapshot {
    pub total: usize,
    pub freshest_heartbeat_age: Option<Duration>,
    pub statuses: Vec<NodeTunnelStatus>,
}

#[derive(Debug, Clone)]
pub struct ForwardResponse {
    pub id: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body_b64: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("no active tunnel for node")]
    NoTunnel,
    #[error("tunnel overloaded")]
    Overloaded,
    #[error("tunnel channel closed")]
    ChannelClosed,
    #[error("tunnel response timeout")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

#[derive(Debug)]
pub enum TunnelCommand {
    Forward {
        id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        started_at: Instant,
        response_tx: oneshot::Sender<anyhow::Result<ForwardResponse>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    Connected,
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct NodeTunnelStatus {
    pub node_id: Uuid,
    pub status: TunnelStatus,
    pub last_heartbeat_secs: Option<u64>,
    pub last_error: Option<String>,
    pub last_event_secs: Option<u64>,
}

/// Relay health status shared with the health endpoint.
#[derive(Clone, Default)]
pub struct RelayHealthState {
    inner: Arc<RwLock<RelayHealthSnapshot>>,
}

#[derive(Debug, Clone, Default)]
pub struct RelayHealthSnapshot {
    pub last_ok_at: Option<Instant>,
    pub last_error: Option<String>,
    pub last_error_at: Option<Instant>,
}

impl RelayHealthState {
    pub async fn record_success(&self) {
        let mut guard = self.inner.write().await;
        guard.last_ok_at = Some(Instant::now());
    }

    pub async fn record_error(&self, reason: impl Into<String>) {
        let mut guard = self.inner.write().await;
        guard.last_error = Some(reason.into());
        guard.last_error_at = Some(Instant::now());
    }

    pub async fn snapshot(&self) -> RelayHealthSnapshot {
        self.inner.read().await.clone()
    }
}

impl TunnelRegistry {
    pub async fn forward_request(
        &self,
        node_id: Uuid,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<ForwardResponse, ForwardError> {
        // Keep the permit alive for the duration of the request to enforce the
        // per-node concurrency limit.
        let (command_tx, permit) = self.acquire(node_id).await?;
        let _permit = permit;

        let (response_tx, response_rx) = oneshot::channel();
        let id = format!("r-{}", Uuid::new_v4());
        let body_len = body.len();
        let started_at = Instant::now();

        histogram!(
            "control_plane_tunnel_forward_payload_bytes",
            "direction" => "request"
        )
        .record(body_len as f64);

        let send_res = command_tx
            .send(TunnelCommand::Forward {
                id: id.clone(),
                method,
                path,
                headers,
                body,
                started_at,
                response_tx,
            })
            .await;

        if send_res.is_err() {
            return Err(ForwardError::ChannelClosed);
        }

        match tokio::time::timeout(timeout, response_rx).await {
            Ok(Ok(Ok(resp))) => {
                histogram!(
                    "control_plane_tunnel_forward_payload_bytes",
                    "direction" => "response"
                )
                .record(resp.body_b64.len() as f64);
                Ok(resp)
            }
            Ok(Ok(Err(err))) => Err(ForwardError::Other(err.to_string())),
            Ok(Err(_canceled)) => Err(ForwardError::ChannelClosed),
            Err(_elapsed) => Err(ForwardError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn registry_tracks_sessions_and_failures() {
        let registry = TunnelRegistry::new();
        let node_id = Uuid::new_v4();
        let tunnel_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(4);
        let inflight = Arc::new(Semaphore::new(2));

        registry.upsert(node_id, tunnel_id, tx, inflight).await;
        assert!(registry.contains(node_id).await);

        let snapshot = registry.snapshot().await;
        assert_eq!(snapshot.total, 1);
        assert_eq!(snapshot.statuses.len(), 1);
        assert_eq!(snapshot.statuses[0].status, TunnelStatus::Connected);

        registry.remove(node_id, "gone").await;
        assert!(!registry.contains(node_id).await);

        let snapshot = registry.snapshot().await;
        assert_eq!(snapshot.total, 0);
        let status = snapshot
            .statuses
            .iter()
            .find(|entry| entry.node_id == node_id)
            .expect("disconnected entry");
        assert_eq!(status.status, TunnelStatus::Disconnected);
        assert_eq!(status.last_error.as_deref(), Some("gone"));
        assert!(status.last_event_secs.is_some());
    }

    #[tokio::test]
    async fn registry_acquire_respects_inflight_limit() {
        let registry = TunnelRegistry::new();
        let node_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(1);
        let inflight = Arc::new(Semaphore::new(1));
        registry.upsert(node_id, Uuid::new_v4(), tx, inflight).await;

        let (_tx, permit) = registry.acquire(node_id).await.expect("permit");
        let err = registry.acquire(node_id).await.expect_err("overloaded");
        assert!(matches!(err, ForwardError::Overloaded));
        drop(permit);
        assert!(registry.acquire(node_id).await.is_ok());
    }

    #[tokio::test]
    async fn forward_request_succeeds_and_returns_response() {
        let registry = TunnelRegistry::new();
        let node_id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        let inflight = Arc::new(Semaphore::new(1));
        registry.upsert(node_id, Uuid::new_v4(), tx, inflight).await;

        let handler = tokio::spawn(async move {
            if let Some(TunnelCommand::Forward {
                id, response_tx, ..
            }) = rx.recv().await
            {
                let response = ForwardResponse {
                    id,
                    status: 200,
                    headers: HashMap::new(),
                    body_b64: "aGVsbG8=".to_string(),
                };
                let _ = response_tx.send(Ok(response));
            }
        });

        let response = registry
            .forward_request(
                node_id,
                "GET".to_string(),
                "/".to_string(),
                HashMap::new(),
                b"ping".to_vec(),
                Duration::from_secs(1),
            )
            .await
            .expect("response");
        assert_eq!(response.status, 200);
        handler.await.expect("handler");
    }

    #[tokio::test]
    async fn forward_request_reports_channel_close() {
        let registry = TunnelRegistry::new();
        let node_id = Uuid::new_v4();
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let inflight = Arc::new(Semaphore::new(1));
        registry.upsert(node_id, Uuid::new_v4(), tx, inflight).await;

        let err = registry
            .forward_request(
                node_id,
                "POST".to_string(),
                "/".to_string(),
                HashMap::new(),
                Vec::new(),
                Duration::from_millis(10),
            )
            .await
            .expect_err("closed");
        assert!(matches!(err, ForwardError::ChannelClosed));
    }

    #[tokio::test(start_paused = true)]
    async fn forward_request_times_out() {
        let registry = TunnelRegistry::new();
        let node_id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        let inflight = Arc::new(Semaphore::new(1));
        registry.upsert(node_id, Uuid::new_v4(), tx, inflight).await;

        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            if let Some(TunnelCommand::Forward { response_tx, .. }) = rx.recv().await {
                let _ = hold_rx.await;
                drop(response_tx);
            }
        });

        let fut = registry.forward_request(
            node_id,
            "GET".to_string(),
            "/".to_string(),
            HashMap::new(),
            Vec::new(),
            Duration::from_secs(1),
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        let err = fut.await.expect_err("timeout");
        assert!(matches!(err, ForwardError::Timeout));

        let _ = hold_tx.send(());
        handle.await.expect("handler");
    }

    #[tokio::test]
    async fn relay_health_tracks_success_and_error() {
        let state = RelayHealthState::default();
        state.record_success().await;
        let snapshot = state.snapshot().await;
        assert!(snapshot.last_ok_at.is_some());
        assert!(snapshot.last_error.is_none());

        state.record_error("nope").await;
        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.last_error.as_deref(), Some("nope"));
        assert!(snapshot.last_error_at.is_some());
    }
}
