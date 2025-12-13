use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::{
    api::{CapacityHints, InstanceStatus},
    compat::{self, CompatError},
    config,
    cp_client::{ControlPlaneClient, CpResponse},
    state::{self, SharedState},
    telemetry,
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Ready,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeartbeatPayload {
    pub node_status: NodeStatus,
    pub containers: Vec<InstanceStatus>,
    pub timestamp: String,
    pub inventory: NodeInventoryPayload,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeInventoryPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<CapacityHints>,
}

#[async_trait]
pub trait HeartbeatClient: Send + Sync {
    async fn send_heartbeat<P: serde::Serialize + Sync>(
        &self,
        state: &SharedState,
        payload: &P,
    ) -> anyhow::Result<CpResponse<()>>;

    fn request_id(&self) -> &str;
}

#[async_trait]
impl HeartbeatClient for ControlPlaneClient {
    async fn send_heartbeat<P: serde::Serialize + Sync>(
        &self,
        state: &SharedState,
        payload: &P,
    ) -> anyhow::Result<CpResponse<()>> {
        ControlPlaneClient::send_heartbeat(self, state, payload).await
    }

    fn request_id(&self) -> &str {
        ControlPlaneClient::request_id(self)
    }
}

pub async fn heartbeat_with_retry<C: HeartbeatClient>(
    state: &SharedState,
    client: C,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    if *shutdown.borrow() {
        anyhow::bail!("shutdown requested");
    }

    compat::enforce(state, "heartbeat").await?;

    let cfg = {
        let guard = state.lock().await;
        guard.cfg.clone()
    };

    let request_id = state::ensure_request_id(state).await;
    let span = tracing::info_span!("heartbeat", %request_id);
    let _span_guard = span.enter();

    let timeout = Duration::from_secs(cfg.heartbeat_timeout_secs);
    let max_retries = cfg.heartbeat_max_retries.max(1);
    let base_backoff = Duration::from_millis(cfg.heartbeat_backoff_ms.max(50));
    let max_backoff = Duration::from_secs(5);

    for attempt in 1..=max_retries {
        let result =
            send_heartbeat_once_with_timeout(state, &client, timeout, shutdown.clone()).await;
        match result {
            Ok(_) => {
                telemetry::record_heartbeat_result("success");
                return Ok(());
            }
            Err(err) => {
                if *shutdown.borrow() {
                    telemetry::record_heartbeat_result("failed");
                    return Err(err);
                }

                if err.downcast_ref::<CompatError>().is_some() {
                    telemetry::record_heartbeat_result("failed");
                    return Err(err);
                }

                if attempt == max_retries {
                    telemetry::record_heartbeat_result("failed");
                    return Err(err);
                }

                let backoff = state::backoff_with_jitter(base_backoff, max_backoff, attempt);
                warn!(
                    attempt,
                    max_retries,
                    backoff_ms = backoff.as_millis(),
                    error = %err,
                    "heartbeat attempt failed, backing off"
                );

                tokio::select! {
                    _ = shutdown.changed() => return Err(anyhow::anyhow!("shutdown requested")),
                    _ = tokio::time::sleep(backoff) => {}
                }
            }
        }
    }

    Ok(())
}

async fn send_heartbeat_once_with_timeout<C: HeartbeatClient>(
    state: &SharedState,
    client: &C,
    timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    if *shutdown.borrow() {
        anyhow::bail!("shutdown requested");
    }

    tokio::select! {
        _ = shutdown.changed() => anyhow::bail!("shutdown requested"),
        res = tokio::time::timeout(timeout, send_heartbeat_once(state, client)) => {
            match res {
                Ok(inner) => inner,
                Err(_) => anyhow::bail!("heartbeat request timed out after {:?}", timeout),
            }
        }
    }
}

async fn send_heartbeat_once<C: HeartbeatClient>(
    state: &SharedState,
    client: &C,
) -> anyhow::Result<()> {
    let cfg = {
        let guard = state.lock().await;
        guard.cfg.clone()
    };
    let aggregation = {
        let store = state.managed_read().await;
        state::collect_instance_statuses_with_metrics(&store, cfg.heartbeat_max_metrics)
    };
    let containers = aggregation.instances;
    let dropped_invalid_metrics = aggregation.dropped_invalid;
    let dropped_overflow_metrics = aggregation.dropped_overflow;

    if dropped_invalid_metrics > 0 {
        warn!(
            request_id = %client.request_id(),
            dropped_invalid_metrics,
            "omitting invalid resource samples from heartbeat metrics"
        );
    }

    if dropped_overflow_metrics > 0 {
        warn!(
            request_id = %client.request_id(),
            dropped_overflow_metrics,
            max_metrics = cfg.heartbeat_max_metrics,
            "downsampled resource metrics to fit heartbeat limit"
        );
    }

    let payload = HeartbeatPayload {
        node_status: NodeStatus::Ready,
        containers,
        timestamp: Utc::now().to_rfc3339(),
        inventory: build_inventory_payload(&cfg),
    };

    let response = client
        .send_heartbeat(state, &payload)
        .await
        .map_err(|err| {
            warn!(request_id = %client.request_id(), ?err, "heartbeat request failed");
            err
        })?;

    info!(request_id = %response.request_id, "heartbeat ok");

    Ok(())
}

pub fn build_inventory_payload(cfg: &config::AppConfig) -> NodeInventoryPayload {
    let capacity = match (cfg.capacity_cpu_millis, cfg.capacity_memory_bytes) {
        (None, None) if !cfg.force_empty_capacity => None,
        _ => Some(CapacityHints {
            cpu_millis: cfg.capacity_cpu_millis,
            memory_bytes: cfg.capacity_memory_bytes,
        }),
    };

    let labels = if cfg.labels.is_empty() && !cfg.force_empty_labels {
        None
    } else {
        Some(cfg.labels.clone())
    };

    NodeInventoryPayload {
        arch: Some(cfg.arch.clone()),
        os: Some(cfg.os.clone()),
        labels,
        capacity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime;
    use crate::test_support::{
        base_config, state_with_runtime_and_config, FakeCpClient, MockRuntime,
    };
    use tokio::sync::watch;

    #[tokio::test]
    async fn heartbeat_sends_payload_once() {
        let runtime: runtime::DynContainerRuntime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, base_config());
        let client = FakeCpClient::with_request_id("abc-123");
        let (_tx, rx) = watch::channel(false);

        heartbeat_with_retry(&state, client.clone(), rx)
            .await
            .expect("heartbeat succeeds");

        let sent = client.sent_heartbeats();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].node_status, NodeStatus::Ready);
    }

    #[tokio::test]
    async fn heartbeat_bails_when_shutdown_already_requested() {
        let runtime: runtime::DynContainerRuntime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, base_config());
        let client = FakeCpClient::default();
        let (_tx, rx) = watch::channel(true);

        let result = heartbeat_with_retry(&state, client, rx).await;
        assert!(result.is_err(), "should abort when shutdown flagged");
    }

    #[tokio::test]
    async fn heartbeat_propagates_client_errors() {
        let runtime: runtime::DynContainerRuntime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, base_config());
        let client = {
            let client = FakeCpClient::default();
            client.set_heartbeat_error("boom");
            client
        };
        let (_tx, rx) = watch::channel(false);

        let result = heartbeat_with_retry(&state, client, rx).await;
        assert!(result.is_err(), "client failures should bubble up");
    }
}
