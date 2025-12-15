use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use crate::{
    app_state::AppState,
    audit::{self, AuditContext, AuditStatus},
    auth::{extract_bearer, require_operator_auth, OperatorIdentity},
    config::{LimitsConfig, PortsConfig},
    error::{ApiResult, AppError},
    metrics::HttpMetricsLayer,
    persistence::{
        self as db, configs as config_store, deployments as deployment_store, logs as log_store,
        nodes as node_store, ports as port_store, tokens as token_store, usage as usage_store,
    },
    scheduler, services, telemetry,
    tokens::{hash_token, match_token, TokenMatch},
    validation,
};
use ::metrics::{counter, gauge};
use axum::{
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{
        header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH},
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    middleware::{self, Next},
    response::IntoResponse,
    response::Response,
    Json, Router,
};
use chrono::{DateTime, Duration as ChronoDuration, Timelike, Utc};
#[allow(unused_imports)]
use common::api::{self, DeploymentHealth, MetricSample, MetricsSummary};
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceBuilder;
use tower_http::request_id::RequestId;
use tracing::{info, warn};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use uuid::Uuid;

mod agents;
mod auth;
mod deployments;
mod error_mapper;
pub(crate) use error_mapper::map_service_error;
mod metrics;
mod nodes;
mod relay;
mod system;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

const AGENT_VERSION_HEADER: &str = "x-agent-version";
const AGENT_BUILD_HEADER: &str = "x-agent-build";
const CONTROL_PLANE_VERSION_HEADER: &str = "x-control-plane-version";
const AGENT_COMPAT_MIN_HEADER: &str = "x-agent-compat-min";
const AGENT_COMPAT_MAX_HEADER: &str = "x-agent-compat-max";
const AGENT_COMPAT_UPGRADE_URL_HEADER: &str = "x-agent-compat-upgrade-url";
const UNSUPPORTED_AGENT_ERROR: &str = "unsupported_agent_version";
/// Error payload returned when an agent's version header is missing, invalid,
/// or outside the compatibility window.
///
/// The control-plane follows semver. By default, agents from the previous
/// minor through the next minor release (inclusive, any patch) are accepted,
/// but operators can override the bounds with
/// `compatibility.min_agent_version` / `compatibility.max_agent_version`.
/// When set, `upgrade_url` points agents to upgrade instructions.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AgentVersionError {
    pub error: &'static str,
    pub agent_version: String,
    pub min_supported: String,
    pub max_supported: String,
    pub upgrade_url: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct ErrorResponse {
    pub error: String,
    pub code: String,
}

pub fn build_router(state: AppState) -> Router<AppState> {
    let middleware_stack =
        ServiceBuilder::new().layer(HttpMetricsLayer::new(state.metrics_history.clone()));
    Router::<AppState>::new()
        .merge(system::router())
        .merge(agents::router(state.clone()))
        .merge(deployments::router(state.clone()))
        .merge(relay::router(state.clone()))
        .merge(nodes::router(state.clone()))
        .merge(metrics::router(state.clone()))
        .merge(auth::router(state.clone()))
        .layer(middleware_stack)
}

async fn enforce_agent_compatibility(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .map(str::to_string);

    let headers = req.headers();
    let agent_build = headers
        .get(AGENT_BUILD_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    if !state.enforce_agent_compatibility {
        if let Some(raw) = headers
            .get(AGENT_VERSION_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            match Version::parse(raw) {
                Ok(version) if !state.agent_compat.is_supported(&version) => {
                    warn!(
                        ?request_id,
                        agent_version = raw,
                        min_supported = %state.agent_compat.min_supported,
                        max_supported = %state.agent_compat.max_supported,
                        "compatibility enforcement disabled; allowing out-of-window agent"
                    );
                }
                Err(_) => {
                    warn!(
                        ?request_id,
                        agent_version = raw,
                        "compatibility enforcement disabled; invalid agent version header"
                    );
                }
                _ => {}
            }
        } else {
            warn!(
                ?request_id,
                "compatibility enforcement disabled; missing agent version header"
            );
        }

        let mut response = next.run(req).await;
        add_compatibility_headers(&state, response.headers_mut());
        return response;
    }

    let (raw_version, parsed_version) = match headers
        .get(AGENT_VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => match Version::parse(value) {
            Ok(parsed) => (value.to_string(), parsed),
            Err(_) => {
                return reject_agent_version(
                    &state,
                    request_id.as_deref(),
                    agent_build.as_deref(),
                    Some(value),
                    "invalid_version",
                    StatusCode::BAD_REQUEST,
                )
                .await;
            }
        },
        None => {
            let fallback = Version::new(0, 0, 0);
            warn!(
                ?request_id,
                compat_min = %state.agent_compat.min_supported,
                compat_max = %state.agent_compat.max_supported,
                fallback_agent_version = %fallback,
                "missing agent version header; assuming legacy agent"
            );

            (fallback.to_string(), fallback)
        }
    };

    if !state.agent_compat.is_supported(&parsed_version) {
        return reject_agent_version(
            &state,
            request_id.as_deref(),
            agent_build.as_deref(),
            Some(&raw_version),
            "unsupported_version",
            StatusCode::UPGRADE_REQUIRED,
        )
        .await;
    }

    let mut response = next.run(req).await;
    add_compatibility_headers(&state, response.headers_mut());
    response
}

async fn reject_agent_version(
    state: &AppState,
    request_id: Option<&str>,
    agent_build: Option<&str>,
    agent_version: Option<&str>,
    reason: &'static str,
    status: StatusCode,
) -> Response {
    counter!("control_plane_agent_version_mismatch_total", "reason" => reason).increment(1);

    let agent_version_value = agent_version.unwrap_or_default().to_string();
    let min_supported = state.agent_compat.min_supported.to_string();
    let max_supported = state.agent_compat.max_supported.to_string();
    let upgrade_url = state.agent_compat.upgrade_url.clone().unwrap_or_default();

    let payload = AgentVersionError {
        error: UNSUPPORTED_AGENT_ERROR,
        agent_version: agent_version_value.clone(),
        min_supported: min_supported.clone(),
        max_supported: max_supported.clone(),
        upgrade_url: upgrade_url.clone(),
    };

    let audit_payload = json!({
        "reason": reason,
        "agent_version": agent_version_value,
        "agent_build": agent_build.unwrap_or(""),
        "min_supported": min_supported,
        "max_supported": max_supported,
        "upgrade_url": upgrade_url,
    })
    .to_string();

    if let Err(err) = audit::record(
        state,
        "agent_version_rejected",
        "agent",
        AuditStatus::Failure,
        AuditContext {
            resource_id: None,
            actor: None,
            request_id,
            payload: Some(audit_payload),
        },
    )
    .await
    {
        warn!(?err, "failed to record agent version audit log");
    }

    let mut response: Response = (status, Json(payload)).into_response();
    add_compatibility_headers(state, response.headers_mut());
    response
}

pub(crate) fn add_compatibility_headers(state: &AppState, headers: &mut HeaderMap) {
    headers.insert(
        CONTROL_PLANE_VERSION_HEADER,
        HeaderValue::from_static(crate::version::VERSION),
    );

    if let Ok(value) = HeaderValue::from_str(&state.agent_compat.min_supported.to_string()) {
        headers.insert(AGENT_COMPAT_MIN_HEADER, value);
    }

    if let Ok(value) = HeaderValue::from_str(&state.agent_compat.max_supported.to_string()) {
        headers.insert(AGENT_COMPAT_MAX_HEADER, value);
    }

    if let Some(url) = state.agent_compat.upgrade_url.as_deref() {
        if let Ok(value) = HeaderValue::from_str(url) {
            headers.insert(AGENT_COMPAT_UPGRADE_URL_HEADER, value);
        }
    }
}

fn tunnel_endpoint_from_state(state: &AppState) -> api::TunnelEndpoint {
    api::TunnelEndpoint {
        host: state.tunnel.advertised_host.clone(),
        port: state.tunnel.advertised_port,
        use_tls: state.tunnel.use_tls,
        connect_timeout_secs: state.tunnel.connect_timeout_secs,
        heartbeat_interval_secs: state.tunnel.heartbeat_interval_secs,
        heartbeat_timeout_secs: state.tunnel.heartbeat_timeout_secs,
        token_header: state.tunnel.token_header.clone(),
    }
}

/// Health response including version metadata and the active compatibility
/// window so agents can self-validate before running workloads.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct HealthResponse {
    status: &'static str,
    control_plane_version: &'static str,
    version: &'static str,
    git_sha: &'static str,
    dirty: bool,
    built_at: &'static str,
    min_supported_agent_version: String,
    max_supported_agent_version: String,
    schema_version: Option<i64>,
    target_schema_version: Option<i64>,
    pending_migrations: usize,
    tunnel_sessions_active: usize,
    tunnel_freshest_heartbeat_secs: Option<u64>,
    tunnel_statuses: Vec<NodeTunnelHealth>,
    relay: RelayHealth,
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct NodeTunnelHealth {
    pub node_id: Uuid,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_secs: Option<u64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RelayHealth {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[utoipa::path(
    get,
    path = "/health",
    responses((status = 200, description = "Health check", body = HealthResponse)),
    tag = "system"
)]
pub(crate) async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let tunnel_snapshot = state.tunnel_registry.snapshot().await;
    let relay_snapshot = state.relay_health.snapshot().await;

    let mut headers = HeaderMap::new();
    add_compatibility_headers(&state, &mut headers);

    let tunnel_statuses: Vec<NodeTunnelHealth> = tunnel_snapshot
        .statuses
        .iter()
        .map(|status| NodeTunnelHealth {
            node_id: status.node_id,
            status: match status.status {
                crate::tunnel::TunnelStatus::Connected => "connected",
                crate::tunnel::TunnelStatus::Disconnected => "disconnected",
            },
            last_heartbeat_secs: status.last_heartbeat_secs,
            last_error: status.last_error.clone(),
            last_event_secs: status.last_event_secs,
        })
        .collect();

    let relay_status = match (relay_snapshot.last_error_at, relay_snapshot.last_ok_at) {
        (Some(err_at), Some(ok_at)) if ok_at >= err_at => "ok",
        (Some(_), _) => "degraded",
        (None, _) => "unknown",
    };

    (
        StatusCode::OK,
        headers,
        Json(HealthResponse {
            status: "ok",
            control_plane_version: crate::version::VERSION,
            version: crate::version::VERSION,
            git_sha: crate::version::GIT_SHA,
            dirty: crate::version::GIT_DIRTY,
            built_at: crate::version::BUILD_TIMESTAMP,
            min_supported_agent_version: state.agent_compat.min_supported.to_string(),
            max_supported_agent_version: state.agent_compat.max_supported.to_string(),
            schema_version: state.schema.latest_applied,
            target_schema_version: state.schema.latest_available,
            pending_migrations: state.schema.pending.len(),
            tunnel_sessions_active: tunnel_snapshot.total,
            tunnel_freshest_heartbeat_secs: tunnel_snapshot
                .freshest_heartbeat_age
                .map(|d| d.as_secs()),
            tunnel_statuses,
            relay: RelayHealth {
                status: relay_status,
                last_error: relay_snapshot.last_error.clone(),
            },
        }),
    )
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses((status = 200, description = "Prometheus metrics", content_type = "text/plain")),
    tag = "system"
)]
pub(crate) async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics_handle.render();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

#[derive(Clone, Deserialize, utoipa::ToSchema)]
pub(crate) struct RegistrationRequest {
    pub(crate) name: Option<String>,
    pub(crate) arch: Option<String>,
    pub(crate) os: Option<String>,
    #[serde(default)]
    pub(crate) labels: Option<HashMap<String, String>>,
    #[serde(default)]
    pub(crate) capacity: Option<CapacityHints>,
    #[serde(default)]
    pub(crate) public_ip: Option<String>,
    #[serde(default)]
    pub(crate) public_host: Option<String>,
}

impl From<RegistrationRequest> for services::nodes::RegistrationRequest {
    fn from(value: RegistrationRequest) -> Self {
        Self {
            name: value.name,
            arch: value.arch,
            os: value.os,
            labels: value.labels,
            capacity: value.capacity,
            public_ip: value.public_ip,
            public_host: value.public_host,
        }
    }
}

type RegistrationResponse = api::RegistrationResponse;

#[utoipa::path(
    post,
    path = "/api/v1/nodes/register",
    request_body = RegistrationRequest,
    responses(
        (status = 201, description = "Node registered", body = RegistrationResponse),
        (status = 400, description = "Missing or invalid agent version header", body = AgentVersionError),
        (status = 401, description = "Unauthorized"),
        (status = 426, description = "Agent version unsupported", body = AgentVersionError),
        (status = 429, description = "Rate limited")
    ),
    security(("registrationBearer" = [])),
    tag = "nodes"
)]
pub(crate) async fn register_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegistrationRequest>,
) -> ApiResult<(StatusCode, Json<RegistrationResponse>)> {
    let provided_token = match extract_bearer(&headers) {
        Ok(token) => token,
        Err(err) => {
            warn!(
                reason = "missing or invalid authorization header",
                "node registration rejected"
            );
            return Err(err);
        }
    };

    let service_req: services::nodes::RegistrationRequest = req.into();
    let result = services::nodes::register_node(&state, &provided_token, service_req).await?;
    info!(node_id = %result.node_id, "node registered");

    Ok((
        StatusCode::CREATED,
        Json(RegistrationResponse {
            node_id: result.node_id,
            node_token: result.node_token,
            tunnel: Some(result.tunnel),
        }),
    ))
}

/// Heartbeat payload posted by a node agent; includes recent usage metrics.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[schema(example = json!({
    "node_status": "ready",
    "containers": [
        {
            "deployment_id": "00000000-0000-0000-0000-00000000cafe",
            "replica_number": 0,
            "container_id": "sha256:abc123",
            "state": "running",
            "message": null,
            "restart_count": 1,
            "generation": 3,
            "last_updated": "2025-02-03T04:05:05Z",
            "endpoints": ["127.0.0.1:18081"],
            "metrics": [
                {
                    "collected_at": "2025-02-03T04:05:00Z",
                    "cpu_percent": 12.3,
                    "memory_bytes": 230686720,
                    "network_rx_bytes": 10240,
                    "network_tx_bytes": 9216,
                    "blk_read_bytes": 4096,
                    "blk_write_bytes": 0
                }
            ]
        }
    ],
    "timestamp": "2025-02-03T04:05:06Z",
    "inventory": {
        "arch": "x86_64",
        "os": "Linux",
        "labels": {"region": "lab-1"},
        "capacity": {"cpu_millis": 2000, "memory_bytes": 4294967296u64}
    }
}))]
pub(crate) struct HeartbeatRequest {
    /// Current node status (ready|unreachable|error|registering).
    pub(crate) node_status: NodeStatus,
    /// Per-replica status and recent usage samples (bounded by control-plane limits).
    #[serde(default)]
    pub(crate) containers: Vec<InstanceStatus>,
    /// Optional timestamp set by the agent for skew detection.
    #[allow(dead_code)]
    pub(crate) timestamp: Option<DateTime<Utc>>,
    /// Optional inventory updates merged into the stored node record.
    #[serde(default)]
    pub(crate) inventory: Option<NodeInventoryPayload>,
    #[serde(default)]
    pub(crate) public_ip: Option<String>,
    #[serde(default)]
    pub(crate) public_host: Option<String>,
}

impl From<HeartbeatRequest> for services::nodes::HeartbeatRequest {
    fn from(value: HeartbeatRequest) -> Self {
        Self {
            node_status: value.node_status,
            containers: value.containers,
            timestamp: value.timestamp,
            inventory: value.inventory.map(Into::into),
            public_ip: value.public_ip,
            public_host: value.public_host,
        }
    }
}

pub(crate) fn record_resource_gauges(
    sample: &db::ResourceMetricSample,
    deployment_id: Uuid,
    deployment_name: &str,
    node_id: Uuid,
    replica_number: i64,
) {
    let deployment_id_label = deployment_id.to_string();
    let node_id_label = node_id.to_string();
    let replica_label = replica_number.to_string();
    let deployment_label = deployment_name.to_string();

    gauge!(
        "deployment_cpu_percent",
        "deployment_id" => deployment_id_label.clone(),
        "deployment" => deployment_label.clone(),
        "node_id" => node_id_label.clone(),
        "replica" => replica_label.clone()
    )
    .set(sample.cpu_percent);

    gauge!(
        "deployment_memory_bytes",
        "deployment_id" => deployment_id_label.clone(),
        "deployment" => deployment_label.clone(),
        "node_id" => node_id_label.clone(),
        "replica" => replica_label.clone()
    )
    .set(sample.memory_bytes as f64);

    gauge!(
        "deployment_network_rx_bytes",
        "deployment_id" => deployment_id_label.clone(),
        "deployment" => deployment_label.clone(),
        "node_id" => node_id_label.clone(),
        "replica" => replica_label.clone()
    )
    .set(sample.network_rx_bytes as f64);

    gauge!(
        "deployment_network_tx_bytes",
        "deployment_id" => deployment_id_label.clone(),
        "deployment" => deployment_label.clone(),
        "node_id" => node_id_label.clone(),
        "replica" => replica_label.clone()
    )
    .set(sample.network_tx_bytes as f64);

    if let Some(bytes) = sample.blk_read_bytes {
        gauge!(
            "deployment_blk_read_bytes",
            "deployment_id" => deployment_id_label.clone(),
            "deployment" => deployment_label.clone(),
            "node_id" => node_id_label.clone(),
            "replica" => replica_label.clone()
        )
        .set(bytes as f64);
    }

    if let Some(bytes) = sample.blk_write_bytes {
        gauge!(
            "deployment_blk_write_bytes",
            "deployment_id" => deployment_id_label,
            "deployment" => deployment_label,
            "node_id" => node_id_label,
            "replica" => replica_label
        )
        .set(bytes as f64);
    }
}

pub(crate) fn record_usage_gauges(
    rollups: &[db::UsageRollup],
    deployment_labels: &HashMap<Uuid, String>,
) {
    let mut latest: HashMap<(Uuid, Uuid, i64), &db::UsageRollup> = HashMap::new();
    for rollup in rollups {
        let key = (rollup.deployment_id, rollup.node_id, rollup.replica_number);
        match latest.get(&key) {
            Some(existing) if existing.bucket_start >= rollup.bucket_start => continue,
            _ => {
                latest.insert(key, rollup);
            }
        }
    }

    for rollup in latest.values() {
        let deployment_id_label = rollup.deployment_id.to_string();
        let node_id_label = rollup.node_id.to_string();
        let replica_label = rollup.replica_number.to_string();
        let deployment_label = deployment_labels
            .get(&rollup.deployment_id)
            .map(String::as_str)
            .unwrap_or("");

        gauge!(
            "deployment_usage_cpu_percent",
            "deployment_id" => deployment_id_label.clone(),
            "deployment" => deployment_label.to_string(),
            "node_id" => node_id_label.clone(),
            "replica" => replica_label.clone()
        )
        .set(rollup.avg_cpu_percent);

        gauge!(
            "deployment_usage_memory_bytes",
            "deployment_id" => deployment_id_label.clone(),
            "deployment" => deployment_label.to_string(),
            "node_id" => node_id_label.clone(),
            "replica" => replica_label.clone()
        )
        .set(rollup.avg_memory_bytes as f64);

        gauge!(
            "deployment_usage_network_rx_bytes",
            "deployment_id" => deployment_id_label.clone(),
            "deployment" => deployment_label.to_string(),
            "node_id" => node_id_label.clone(),
            "replica" => replica_label.clone()
        )
        .set(rollup.avg_network_rx_bytes as f64);

        gauge!(
            "deployment_usage_network_tx_bytes",
            "deployment_id" => deployment_id_label.clone(),
            "deployment" => deployment_label.to_string(),
            "node_id" => node_id_label.clone(),
            "replica" => replica_label.clone()
        )
        .set(rollup.avg_network_tx_bytes as f64);

        if let Some(bytes) = rollup.avg_blk_read_bytes {
            gauge!(
                "deployment_usage_blk_read_bytes",
                "deployment_id" => deployment_id_label.clone(),
                "deployment" => deployment_label.to_string(),
                "node_id" => node_id_label.clone(),
                "replica" => replica_label.clone()
            )
            .set(bytes as f64);
        }

        if let Some(bytes) = rollup.avg_blk_write_bytes {
            gauge!(
                "deployment_usage_blk_write_bytes",
                "deployment_id" => deployment_id_label,
                "deployment" => deployment_label.to_string(),
                "node_id" => node_id_label,
                "replica" => replica_label
            )
            .set(bytes as f64);
        }
    }
}

pub(crate) fn ensure_health_last_error(
    health: Option<api::HealthStatus>,
) -> Option<api::HealthStatus> {
    health.map(|mut status| {
        if status.last_error.is_none() {
            if let Some(reason) = status.reason.clone() {
                status.last_error = Some(reason);
            }
        }
        status
    })
}

#[derive(Debug, Default)]
pub(crate) struct UsageAggregationStats {
    pub(crate) accepted_samples: usize,
    pub(crate) dropped_samples: usize,
    pub(crate) truncated_buckets: usize,
}

#[derive(Default)]
struct UsageBucketAccum {
    samples: usize,
    sum_cpu_percent: f64,
    sum_memory_bytes: u128,
    sum_network_rx_bytes: u128,
    sum_network_tx_bytes: u128,
    sum_blk_read_bytes: u128,
    sum_blk_write_bytes: u128,
}

fn truncate_to_minute(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    timestamp
        .with_second(0)
        .and_then(|dt| dt.with_nanosecond(0))
        .unwrap_or(timestamp)
}

pub(crate) fn aggregate_usage_rollups(
    node_id: Uuid,
    instances: &[db::InstanceStatusUpsert],
    max_buckets: usize,
    usage_window_secs: u64,
    now: DateTime<Utc>,
) -> (Vec<db::UsageRollup>, UsageAggregationStats) {
    let mut buckets: HashMap<(Uuid, i64, DateTime<Utc>), UsageBucketAccum> = HashMap::new();
    let mut stats = UsageAggregationStats::default();

    let cutoff = if usage_window_secs == 0 {
        None
    } else {
        Some(now - ChronoDuration::seconds(usage_window_secs.min(i64::MAX as u64) as i64))
    };

    for inst in instances {
        for sample in &inst.metrics {
            if let Some(cutoff) = cutoff {
                if sample.collected_at < cutoff {
                    stats.dropped_samples += 1;
                    continue;
                }
            }

            let bucket_start = truncate_to_minute(sample.collected_at);
            let key = (inst.deployment_id, inst.replica_number, bucket_start);
            let entry = buckets.entry(key).or_default();

            entry.samples += 1;
            entry.sum_cpu_percent += sample.cpu_percent;
            entry.sum_memory_bytes += sample.memory_bytes as u128;
            entry.sum_network_rx_bytes += sample.network_rx_bytes as u128;
            entry.sum_network_tx_bytes += sample.network_tx_bytes as u128;
            entry.sum_blk_read_bytes += sample.blk_read_bytes.unwrap_or(0) as u128;
            entry.sum_blk_write_bytes += sample.blk_write_bytes.unwrap_or(0) as u128;

            stats.accepted_samples += 1;
        }
    }

    let mut rollups: Vec<db::UsageRollup> = buckets
        .into_iter()
        .filter_map(|((deployment_id, replica_number, bucket_start), acc)| {
            if acc.samples == 0 {
                return None;
            }

            let samples = acc.samples as i64;
            let divisor = acc.samples as f64;

            let avg_cpu_percent = acc.sum_cpu_percent / divisor;
            let avg_memory_bytes = (acc.sum_memory_bytes / acc.samples as u128) as i64;
            let avg_network_rx_bytes = (acc.sum_network_rx_bytes / acc.samples as u128) as i64;
            let avg_network_tx_bytes = (acc.sum_network_tx_bytes / acc.samples as u128) as i64;
            let avg_blk_read_bytes = if acc.sum_blk_read_bytes == 0 {
                None
            } else {
                Some((acc.sum_blk_read_bytes / acc.samples as u128) as i64)
            };
            let avg_blk_write_bytes = if acc.sum_blk_write_bytes == 0 {
                None
            } else {
                Some((acc.sum_blk_write_bytes / acc.samples as u128) as i64)
            };

            Some(db::UsageRollup {
                deployment_id,
                node_id,
                replica_number,
                bucket_start,
                samples,
                avg_cpu_percent,
                avg_memory_bytes,
                avg_network_rx_bytes,
                avg_network_tx_bytes,
                avg_blk_read_bytes,
                avg_blk_write_bytes,
            })
        })
        .collect();

    rollups.sort_by_key(|r| r.bucket_start);
    if max_buckets > 0 && rollups.len() > max_buckets {
        let dropped = rollups.len() - max_buckets;
        stats.truncated_buckets = dropped;
        rollups.drain(0..dropped);
    }

    (rollups, stats)
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct NodeInventoryPayload {
    pub(crate) arch: Option<String>,
    pub(crate) os: Option<String>,
    #[serde(default)]
    pub(crate) labels: Option<HashMap<String, String>>,
    #[serde(default)]
    pub(crate) capacity: Option<CapacityHints>,
}

impl From<NodeInventoryPayload> for services::nodes::NodeInventoryPayload {
    fn from(value: NodeInventoryPayload) -> Self {
        Self {
            arch: value.arch,
            os: value.os,
            labels: value.labels,
            capacity: value.capacity,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OkResponse {
    ok: bool,
}

pub(crate) type NodeStatusResponse = api::NodeStatusResponse;
pub(crate) type DeploymentStatusResponse = api::DeploymentStatusResponse;
type InstanceStatusResponse = api::InstanceStatusResponse;
pub(crate) type DeploymentSpec = api::DeploymentSpec;
type DeploymentCreateResponse = api::DeploymentCreateResponse;
pub(crate) type DeploymentUpdate = api::DeploymentUpdate;
type DesiredStateResponse = api::DesiredStateResponse;
pub(crate) type DeploymentMetricsResponse = api::DeploymentMetricsResponse;
pub(crate) type ReplicaResourceMetrics = api::ReplicaResourceMetrics;
type DeploymentDesired = api::DeploymentDesired;
type NodeSummary = api::NodeSummary;
pub(crate) type DeploymentSummary = api::DeploymentSummary;
type ConfigResponse = api::ConfigResponse;
type ConfigSummary = api::ConfigSummary;
type ConfigSummaryPage = api::ConfigSummaryPage;
type ConfigCreateRequest = api::ConfigCreateRequest;
type ConfigUpdateRequest = api::ConfigUpdateRequest;
type ConfigAttachmentResponse = api::ConfigAttachmentResponse;
type ConfigDesired = api::ConfigDesired;
type NodeConfigResponse = api::NodeConfigResponse;
type ConfigMetadata = api::ConfigMetadata;
type ApiConfigEntry = api::ConfigEntry;
type ApiConfigFile = api::ConfigFile;
type NodeSummaryPage = api::NodeSummaryPage;
type DeploymentSummaryPage = api::DeploymentSummaryPage;
type UsageRollupPage = api::UsageRollupPage;
pub(crate) type UsageRollupResponse = api::UsageRollup;
pub(crate) type UsageSummary = api::UsageSummary;
pub(crate) type NodeStatus = api::NodeStatus;
type CapacityHints = api::CapacityHints;
pub(crate) type InstanceStatus = api::InstanceStatus;
pub(crate) type HealthStatus = api::HealthStatus;
type TokenRotateRequest = api::TokenRotateRequest;
type TokenResponse = api::TokenResponse;

const DEFAULT_PAGE_LIMIT: u32 = 50;
const MAX_PAGE_LIMIT: u32 = 100;
const DEFAULT_USAGE_QUERY_WINDOW_SECS: u64 = 60 * 60;
const USAGE_SUMMARY_WINDOW_SECS: u64 = 300;

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct ListParams {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct ConfigListParams {
    #[serde(default)]
    #[param(example = 50, minimum = 1, maximum = 100)]
    limit: Option<u32>,
    #[serde(default)]
    #[param(example = 0, minimum = 0)]
    offset: Option<u32>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct MetricsSummaryParams {
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct UsageQueryParams {
    /// Page size (1-100, defaults to 50 when omitted).
    #[serde(default)]
    #[param(example = 50, minimum = 1, maximum = 100)]
    limit: Option<u32>,
    /// Pagination offset (defaults to 0).
    #[serde(default)]
    #[param(example = 0, minimum = 0)]
    offset: Option<u32>,
    /// Deployment to filter by (required if `node_id` is absent).
    #[serde(default)]
    #[param(example = "00000000-0000-0000-0000-00000000cafe")]
    deployment_id: Option<Uuid>,
    /// Node to filter by (required if `deployment_id` is absent).
    #[serde(default)]
    #[param(example = "00000000-0000-0000-0000-00000000beef")]
    node_id: Option<Uuid>,
    /// Specific replica ordinal (optional).
    #[serde(default)]
    #[param(example = 0, minimum = 0)]
    replica_number: Option<i64>,
    /// RFC3339 timestamp for the start of the window. Defaults to now minus the allowed window.
    #[serde(default, deserialize_with = "deserialize_opt_rfc3339")]
    #[param(example = "2025-02-03T04:00:00Z")]
    since: Option<DateTime<Utc>>,
    /// RFC3339 timestamp for the end of the window. Defaults to current time.
    #[serde(default, deserialize_with = "deserialize_opt_rfc3339")]
    #[param(example = "2025-02-03T04:05:00Z")]
    until: Option<DateTime<Utc>>,
}

pub(crate) fn to_db_desired_state(state: api::DesiredState) -> db::DesiredState {
    match state {
        api::DesiredState::Running => db::DesiredState::Running,
        api::DesiredState::Stopped => db::DesiredState::Stopped,
    }
}

pub(crate) fn to_api_desired_state(state: db::DesiredState) -> api::DesiredState {
    match state {
        db::DesiredState::Running => api::DesiredState::Running,
        db::DesiredState::Stopped => api::DesiredState::Stopped,
    }
}

pub(crate) fn to_db_instance_state(state: api::InstanceState) -> db::InstanceState {
    match state {
        api::InstanceState::Running => db::InstanceState::Running,
        api::InstanceState::Pending => db::InstanceState::Pending,
        api::InstanceState::Stopped => db::InstanceState::Stopped,
        api::InstanceState::Failed => db::InstanceState::Failed,
        api::InstanceState::Unknown => db::InstanceState::Unknown,
    }
}

fn to_api_instance_state(state: db::InstanceState) -> api::InstanceState {
    match state {
        db::InstanceState::Running => api::InstanceState::Running,
        db::InstanceState::Pending => api::InstanceState::Pending,
        db::InstanceState::Stopped => api::InstanceState::Stopped,
        db::InstanceState::Failed => api::InstanceState::Failed,
        db::InstanceState::Unknown => api::InstanceState::Unknown,
    }
}

fn to_api_deployment_status(status: db::DeploymentStatus) -> api::DeploymentStatus {
    match status {
        db::DeploymentStatus::Pending => api::DeploymentStatus::Pending,
        db::DeploymentStatus::Deploying => api::DeploymentStatus::Deploying,
        db::DeploymentStatus::Running => api::DeploymentStatus::Running,
        db::DeploymentStatus::Stopped => api::DeploymentStatus::Stopped,
        db::DeploymentStatus::Failed => api::DeploymentStatus::Failed,
    }
}

fn to_api_node_status(status: db::NodeStatus) -> api::NodeStatus {
    match status {
        db::NodeStatus::Ready => api::NodeStatus::Ready,
        db::NodeStatus::Unreachable => api::NodeStatus::Unreachable,
        db::NodeStatus::Error => api::NodeStatus::Error,
        db::NodeStatus::Registering => api::NodeStatus::Registering,
    }
}

pub(crate) fn to_db_node_status(status: api::NodeStatus) -> db::NodeStatus {
    match status {
        api::NodeStatus::Ready => db::NodeStatus::Ready,
        api::NodeStatus::Unreachable => db::NodeStatus::Unreachable,
        api::NodeStatus::Error => db::NodeStatus::Error,
        api::NodeStatus::Registering => db::NodeStatus::Registering,
    }
}

fn parse_pagination(params: &ListParams) -> std::result::Result<(u32, u32), AppError> {
    parse_limit_offset(params.limit, params.offset)
}

pub fn parse_limit_offset(
    limit: Option<u32>,
    offset: Option<u32>,
) -> std::result::Result<(u32, u32), AppError> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(AppError::bad_request(format!(
            "limit must be between 1 and {}",
            MAX_PAGE_LIMIT
        )));
    }
    let offset = offset.unwrap_or(0);
    Ok((limit, offset))
}

fn parse_metrics_limit(limit: Option<u32>, max_limit: u32) -> std::result::Result<u32, AppError> {
    let limit = limit.unwrap_or(max_limit);
    if limit == 0 || limit > max_limit {
        return Err(AppError::bad_request(format!(
            "limit must be between 1 and {}",
            max_limit
        )));
    }
    Ok(limit)
}

fn parse_rfc3339_tolerant(raw: &str) -> std::result::Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(raw)
        .or_else(|_| DateTime::parse_from_rfc3339(&raw.replace(' ', "+")))
        .map(|dt| dt.with_timezone(&Utc))
}

fn deserialize_opt_rfc3339<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw {
        Some(value) => parse_rfc3339_tolerant(&value)
            .map(Some)
            .map_err(|err| serde::de::Error::custom(err.to_string())),
        None => Ok(None),
    }
}

fn usage_time_bounds(
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    retention_secs: u64,
) -> std::result::Result<(DateTime<Utc>, Option<DateTime<Utc>>), AppError> {
    let now = Utc::now();
    let reference_end = until.unwrap_or(now);
    let default_window_secs = if retention_secs == 0 {
        DEFAULT_USAGE_QUERY_WINDOW_SECS
    } else {
        DEFAULT_USAGE_QUERY_WINDOW_SECS.min(retention_secs)
    };
    let default_window = ChronoDuration::seconds(default_window_secs.min(i64::MAX as u64) as i64);
    let mut start = since.unwrap_or(reference_end - default_window);

    if let Some(cutoff) = (retention_secs > 0)
        .then(|| now - ChronoDuration::seconds(retention_secs.min(i64::MAX as u64) as i64))
    {
        if let Some(end) = until {
            if end < cutoff {
                return Err(AppError::bad_request(
                    "requested window is outside the retention period",
                ));
            }
        }
        if start < cutoff {
            start = cutoff;
        }
    }

    if let Some(end) = until {
        if start > end {
            return Err(AppError::bad_request(
                "since must be earlier than or equal to until",
            ));
        }
    }

    Ok((start, until))
}

fn usage_summary_bounds(retention_secs: u64) -> (DateTime<Utc>, DateTime<Utc>) {
    let now = Utc::now();
    let summary_secs = if retention_secs == 0 {
        USAGE_SUMMARY_WINDOW_SECS
    } else {
        USAGE_SUMMARY_WINDOW_SECS.min(retention_secs)
    };
    let duration = ChronoDuration::seconds(summary_secs.min(i64::MAX as u64) as i64);
    let mut start = now - duration;
    let end = now;
    if let Some(cutoff) = (retention_secs > 0)
        .then(|| now - ChronoDuration::seconds(retention_secs.min(i64::MAX as u64) as i64))
    {
        if start < cutoff {
            start = cutoff;
        }
    }
    (start, end)
}

fn config_metadata(record: db::ConfigRecord) -> ConfigMetadata {
    ConfigMetadata {
        config_id: record.id,
        name: record.name,
        version: record.version,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn to_api_config_entry(entry: db::ConfigEntryRecord) -> ApiConfigEntry {
    ApiConfigEntry {
        key: entry.key,
        value: entry.value,
        secret_ref: entry.secret_ref,
    }
}

fn to_api_config_file(file: db::ConfigFileRecord) -> ApiConfigFile {
    ApiConfigFile {
        path: file.path,
        file_ref: file.file_ref,
    }
}

fn ensure_config_version(version: i64) -> ApiResult<()> {
    if version < 1 {
        return Err(AppError::bad_request("version must be at least 1"));
    }
    Ok(())
}

fn validate_config_payload(
    entries: &[ApiConfigEntry],
    files: &[ApiConfigFile],
    limits: &LimitsConfig,
) -> ApiResult<(Vec<db::ConfigEntry>, Vec<db::ConfigFileRef>)> {
    let db_entries: Vec<db::ConfigEntry> = entries
        .iter()
        .map(|entry| db::ConfigEntry {
            key: entry.key.clone(),
            value: entry.value.clone(),
            secret_ref: entry.secret_ref.clone(),
        })
        .collect();
    validation::validate_config_entries(&db_entries, limits)?;

    let db_files: Vec<db::ConfigFileRef> = files
        .iter()
        .map(|file| db::ConfigFileRef {
            path: file.path.clone(),
            file_ref: file.file_ref.clone(),
        })
        .collect();
    validation::validate_config_files(&db_files, limits)?;

    Ok((db_entries, db_files))
}

async fn build_config_response(
    state: &AppState,
    record: db::ConfigRecord,
) -> Result<ConfigResponse> {
    let (entries, files, deployments, nodes) = tokio::try_join!(
        config_store::list_config_entries(&state.db, record.id),
        config_store::list_config_files(&state.db, record.id),
        config_store::deployments_for_config(&state.db, record.id),
        config_store::nodes_for_config(&state.db, record.id),
    )?;

    let entries = entries.into_iter().map(to_api_config_entry).collect();
    let files = files.into_iter().map(to_api_config_file).collect();

    Ok(ConfigResponse {
        metadata: config_metadata(record),
        entries,
        files,
        attached_deployments: deployments,
        attached_nodes: nodes,
    })
}

pub fn request_id_from_extension(request_id: Option<Extension<RequestId>>) -> Option<String> {
    telemetry::request_id_from_extension(request_id)
}

pub async fn record_audit_log(
    state: &AppState,
    action: &str,
    resource_type: &str,
    status: audit::AuditStatus,
    context: audit::AuditContext<'_>,
) {
    telemetry::record_audit_log(state, action, resource_type, status, context).await
}

fn safe_deployment_spec_audit(spec: &DeploymentSpec) -> Option<String> {
    let summary = json!({
        "name": spec.name,
        "image": spec.image,
        "replicas": spec.replicas,
        "desired_state": spec.desired_state,
        "ports": spec.ports.as_ref().map(|ports| ports.len()),
        "constraints": spec.constraints.as_ref().map(|_| "set"),
        "placement": spec.placement.as_ref().map(|_| "set"),
        "volumes": spec.volumes.as_ref().map(|vols| vols.len()),
        "health": spec.health.as_ref().map(|_| "set"),
    });
    serde_json::to_string(&summary).ok()
}

fn safe_deployment_update_audit(update: &DeploymentUpdate) -> Option<String> {
    let ports = match update.ports.as_ref() {
        Some(Some(ports)) => Some(json!({ "count": ports.len() })),
        Some(None) => Some(json!("clear")),
        None => None,
    };
    let summary = json!({
        "name": update.name,
        "image": update.image,
        "replicas": update.replicas,
        "desired_state": update.desired_state,
        "ports": ports,
        "constraints": update.constraints.as_ref().map(|_| "updated"),
        "placement": update
            .placement
            .as_ref()
            .map(|placement| if placement.is_some() { "updated" } else { "clear" }),
        "clear_env": update.env.as_ref().is_some_and(|v| v.is_none()),
        "clear_secret_env": update.secret_env.as_ref().is_some_and(|v| v.is_none()),
        "clear_secret_files": update.secret_files.as_ref().is_some_and(|v| v.is_none()),
        "clear_command": update.command.as_ref().is_some_and(|v| v.is_none()),
        "volumes": match update.volumes.as_ref() {
            Some(Some(vols)) => Some(json!({ "count": vols.len() })),
            Some(None) => Some(json!("clear")),
            None => None,
        },
        "health": match update.health.as_ref() {
            Some(Some(_)) => Some(json!("set")),
            Some(None) => Some(json!("clear")),
            None => None,
        },
    });
    serde_json::to_string(&summary).ok()
}

fn parse_node_status_filter(
    status: Option<String>,
) -> std::result::Result<Option<db::NodeStatus>, AppError> {
    status
        .map(|s| match s.to_ascii_lowercase().as_str() {
            "ready" => Ok(db::NodeStatus::Ready),
            "unreachable" => Ok(db::NodeStatus::Unreachable),
            "error" => Ok(db::NodeStatus::Error),
            "registering" => Ok(db::NodeStatus::Registering),
            other => Err(AppError::bad_request(format!(
                "unsupported node status filter '{}'",
                other
            ))),
        })
        .transpose()
}

fn parse_deployment_status_filter(
    status: Option<String>,
) -> std::result::Result<Option<db::DeploymentStatus>, AppError> {
    status
        .map(|s| match s.to_ascii_lowercase().as_str() {
            "pending" => Ok(db::DeploymentStatus::Pending),
            "deploying" => Ok(db::DeploymentStatus::Deploying),
            "running" => Ok(db::DeploymentStatus::Running),
            "stopped" => Ok(db::DeploymentStatus::Stopped),
            "failed" => Ok(db::DeploymentStatus::Failed),
            other => Err(AppError::bad_request(format!(
                "unsupported deployment status filter '{}'",
                other
            ))),
        })
        .transpose()
}

fn to_node_summary(node: db::NodeRecord) -> NodeSummary {
    NodeSummary {
        node_id: node.id,
        name: node.name,
        status: to_api_node_status(node.status),
        last_seen: node.last_seen,
        arch: node.arch,
        os: node.os,
        public_ip: node.public_ip,
        public_host: node.public_host,
        labels: node.labels.map(|l| l.0),
        capacity: node.capacity.map(|c| c.0),
    }
}

pub(crate) fn to_deployment_summary(
    row: db::DeploymentListRow,
    assignments: Vec<db::DeploymentAssignmentRecord>,
) -> DeploymentSummary {
    let volumes = row
        .volumes_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .unwrap_or(None);

    DeploymentSummary {
        deployment_id: row.id,
        name: row.name,
        image: row.image,
        replicas: row.replicas.max(1) as u32,
        desired_state: to_api_desired_state(row.desired_state),
        status: to_api_deployment_status(row.status),
        assigned_node_id: row.assigned_node_id,
        tunnel_only: row.tunnel_only,
        assignments: assignment_summaries(&assignments),
        generation: row.generation,
        placement: row.placement.map(|p| p.0),
        volumes,
        last_reported: row.last_reported,
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/nodes/{node_id}/heartbeats",
    params(
        ("node_id" = Uuid, Path, description = "Node identifier")
    ),
    request_body = HeartbeatRequest,
    responses(
        (status = 200, description = "Heartbeat recorded", body = OkResponse),
        (
            status = 400,
            description = "Heartbeat payload failed validation (metrics limits, timestamps, or schema)",
            body = ErrorResponse,
            example = json!({
                "error": "metrics samples across heartbeat exceed limit (750 > 500)",
                "code": "bad_request"
            })
        ),
        (
            status = 400,
            description = "Missing or invalid agent version header",
            body = AgentVersionError,
            example = json!({
                "error": "unsupported_agent_version",
                "agent_version": "1.0.0-invalid",
                "min_supported": "0.9.0",
                "max_supported": "1.1.0",
                "upgrade_url": "https://example.invalid/upgrade"
            })
        ),
        (status = 401, description = "Invalid node token", body = ErrorResponse),
        (
            status = 413,
            description = "Heartbeat payload exceeds FLEDX_CP_LIMITS_HEARTBEAT_BODY_BYTES",
            body = ErrorResponse,
            example = json!({
                "error": "request payload too large",
                "code": "payload_too_large"
            })
        ),
        (status = 426, description = "Agent version unsupported", body = AgentVersionError)
    ),
    security(("nodeBearer" = [])),
    tag = "nodes"
)]
pub(crate) async fn heartbeat(
    State(state): State<AppState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<HeartbeatRequest>,
) -> ApiResult<(StatusCode, Json<OkResponse>)> {
    let token = extract_bearer(&headers)?;
    let service_body: services::nodes::HeartbeatRequest = body.into();
    services::nodes::heartbeat(&state, node_id, &token, service_body).await?;
    Ok((StatusCode::OK, Json(OkResponse { ok: true })))
}

#[utoipa::path(
    get,
    path = "/api/v1/nodes/{node_id}",
    params(
        ("node_id" = Uuid, Path, description = "Node identifier")
    ),
    responses((status = 200, description = "Node status", body = NodeStatusResponse)),
    security(("operatorBearer" = [])),
    tag = "nodes"
)]
pub(crate) async fn node_status(
    State(state): State<AppState>,
    Path(node_id): Path<Uuid>,
) -> ApiResult<Json<NodeStatusResponse>> {
    let snapshot = services::nodes::node_status(&state, node_id).await?;
    let usage_summary = snapshot.usage_summary;
    let resp = NodeStatusResponse {
        node_id: snapshot.node.id,
        name: snapshot.node.name,
        status: to_api_node_status(snapshot.node.status),
        last_seen: snapshot.node.last_seen,
        arch: snapshot.node.arch,
        os: snapshot.node.os,
        public_ip: snapshot.node.public_ip,
        public_host: snapshot.node.public_host,
        labels: snapshot.node.labels.as_ref().map(|labels| labels.0.clone()),
        capacity: snapshot.node.capacity.as_ref().map(|cap| cap.0.clone()),
        instances: snapshot
            .instances
            .iter()
            .map(to_instance_status_response)
            .collect(),
        usage_summary,
    };

    Ok(Json(resp))
}

#[utoipa::path(
    get,
    path = "/api/v1/nodes",
    params(ListParams),
    responses((status = 200, description = "List nodes", body = NodeSummaryPage)),
    security(("operatorBearer" = [])),
    tag = "nodes"
)]
pub(crate) async fn list_nodes(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> ApiResult<Json<NodeSummaryPage>> {
    let (limit, offset) = parse_pagination(&params)?;
    let status_filter = parse_node_status_filter(params.status.clone())?;
    let nodes = services::nodes::list_nodes(
        &state,
        services::nodes::ListNodesRequest {
            status: status_filter,
            limit,
            offset,
        },
    )
    .await?;
    let items = nodes.into_iter().map(to_node_summary).collect();
    Ok(Json(NodeSummaryPage {
        limit,
        offset,
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/configs",
    params(ConfigListParams),
    responses(
        (
            status = 200,
            description = "List configs",
            body = ConfigSummaryPage,
            example = json!({
                "limit": 50,
                "offset": 0,
                "items": [{
                    "metadata": {
                        "config_id": "00000000-0000-0000-0000-00000000cafe",
                        "name": "app-config",
                        "version": 2,
                        "created_at": "2025-01-10T12:00:00Z",
                        "updated_at": "2025-02-11T15:30:00Z"
                    },
                    "entry_count": 3,
                    "file_count": 1
                }]
            })
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn list_configs(
    State(state): State<AppState>,
    Query(params): Query<ConfigListParams>,
) -> ApiResult<Json<ConfigSummaryPage>> {
    let (limit, offset) = parse_limit_offset(params.limit, params.offset)?;
    let rows = config_store::list_configs(&state.db, limit, offset).await?;
    let items = rows
        .into_iter()
        .map(|row| ConfigSummary {
            metadata: ConfigMetadata {
                config_id: row.id,
                name: row.name,
                version: row.version,
                created_at: row.created_at,
                updated_at: row.updated_at,
            },
            entry_count: row.entry_count,
            file_count: row.file_count,
        })
        .collect();

    Ok(Json(ConfigSummaryPage {
        limit,
        offset,
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/configs/{config_id}",
    params(("config_id" = Uuid, Path, description = "Config identifier")),
    responses(
        (
            status = 200,
            description = "Config detail",
            body = ConfigResponse,
            example = json!({
                "metadata": {
                    "config_id": "00000000-0000-0000-0000-00000000cafe",
                    "name": "app-config",
                    "version": 2,
                    "created_at": "2025-01-10T12:00:00Z",
                    "updated_at": "2025-02-11T15:30:00Z"
                },
                "entries": [
                    { "key": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app" }
                ],
                "files": [
                    { "path": "/etc/app/config.yaml", "file_ref": "config-blobs/app-v2" }
                ],
                "attached_deployments": ["00000000-0000-0000-0000-00000000beef"],
                "attached_nodes": ["00000000-0000-0000-0000-00000000babe"]
            })
        ),
        (
            status = 404,
            description = "Config not found",
            body = ErrorResponse,
            example = json!({"error": "config not found", "code": "not_found"})
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn get_config(
    State(state): State<AppState>,
    Path(config_id): Path<Uuid>,
) -> ApiResult<Json<ConfigResponse>> {
    let record = config_store::get_config(&state.db, config_id)
        .await?
        .ok_or_else(|| AppError::not_found("config not found"))?;

    let response = build_config_response(&state, record).await?;

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/configs",
    request_body = ConfigCreateRequest,
    responses(
        (
            status = 201,
            description = "Config created",
            body = ConfigResponse,
            example = json!({
                "metadata": {
                    "config_id": "00000000-0000-0000-0000-00000000cafe",
                    "name": "app-config",
                    "version": 1,
                    "created_at": "2025-02-11T15:30:00Z",
                    "updated_at": "2025-02-11T15:30:00Z"
                },
                "entries": [
                    { "key": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app" },
                    { "key": "REDIS_HOST", "value": "redis.internal" }
                ],
                "files": [
                    { "path": "/etc/app/config.yaml", "file_ref": "config-blobs/app-v1" }
                ],
                "attached_deployments": [],
                "attached_nodes": []
            })
        ),
        (
            status = 400,
            description = "Validation failure (name uniqueness, version < 1, entry/file rules, or mixed plaintext/secret entries)",
            body = ErrorResponse,
            example = json!({
                "error": "config entry value too long",
                "code": "bad_request"
            })
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn create_config(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Json(body): Json<ConfigCreateRequest>,
) -> ApiResult<(StatusCode, Json<ConfigResponse>)> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();

    let result = async {
        let ConfigCreateRequest {
            name,
            version,
            entries,
            files,
        } = body;

        ensure_config_version(version.unwrap_or(1))?;
        validation::validate_config_name(&name, &state.limits)?;
        if config_store::get_config_by_name(&state.db, &name)
            .await?
            .is_some()
        {
            return Err(AppError::bad_request("config name already exists"));
        }

        let (entries, files) = validate_config_payload(&entries, &files, &state.limits)?;
        let record = config_store::create_config(
            &state.db,
            db::NewConfig {
                id: Uuid::new_v4(),
                name: name.clone(),
                version: version.unwrap_or(1),
                entries,
                files,
            },
        )
        .await?;

        let response = build_config_response(&state, record).await?;
        Ok((StatusCode::CREATED, Json(response)))
    }
    .await;

    match &result {
        Ok((_status, Json(response))) => {
            record_audit_log(
                &state,
                "config.create",
                "config",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(response.metadata.config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(format!(
                        "name={}, version={}",
                        response.metadata.name, response.metadata.version
                    )),
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "config.create",
                "config",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: None,
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    put,
    path = "/api/v1/configs/{config_id}",
    params(("config_id" = Uuid, Path, description = "Config identifier")),
    request_body = ConfigUpdateRequest,
    responses(
        (
            status = 200,
            description = "Config updated",
            body = ConfigResponse,
            example = json!({
                "metadata": {
                    "config_id": "00000000-0000-0000-0000-00000000cafe",
                    "name": "app-config",
                    "version": 2,
                    "created_at": "2025-01-10T12:00:00Z",
                    "updated_at": "2025-02-12T09:00:00Z"
                },
                "entries": [
                    { "key": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app?sslmode=disable" }
                ],
                "files": [
                    { "path": "/etc/app/config.yaml", "file_ref": "config-blobs/app-v2" }
                ],
                "attached_deployments": ["00000000-0000-0000-0000-00000000beef"],
                "attached_nodes": []
            })
        ),
        (
            status = 400,
            description = "Validation failure (name uniqueness, version must increase, entry/file rules, or mixed plaintext/secret entries)",
            body = ErrorResponse,
            example = json!({
                "error": "version must be greater than current version",
                "code": "bad_request"
            })
        ),
        (
            status = 404,
            description = "Config not found",
            body = ErrorResponse,
            example = json!({"error": "config not found", "code": "not_found"})
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn update_config(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path(config_id): Path<Uuid>,
    Json(body): Json<ConfigUpdateRequest>,
) -> ApiResult<Json<ConfigResponse>> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();

    let result = async {
        let current = config_store::get_config(&state.db, config_id)
            .await?
            .ok_or_else(|| AppError::not_found("config not found"))?;

        let ConfigUpdateRequest {
            name,
            version,
            entries,
            files,
        } = body;

        let new_name = name.unwrap_or_else(|| current.name.clone());
        validation::validate_config_name(&new_name, &state.limits)?;
        if new_name != current.name {
            if let Some(existing) = config_store::get_config_by_name(&state.db, &new_name).await? {
                if existing.id != config_id {
                    return Err(AppError::bad_request("config name already exists"));
                }
            }
        }

        let next_version = match version {
            Some(v) => {
                ensure_config_version(v)?;
                if v <= current.version {
                    return Err(AppError::bad_request(
                        "version must be greater than current version",
                    ));
                }
                v
            }
            None => current.version + 1,
        };

        let current_entries = if entries.is_none() || files.is_none() {
            Some(config_store::list_config_entries(&state.db, config_id).await?)
        } else {
            None
        };
        let current_files = if entries.is_none() || files.is_none() {
            Some(config_store::list_config_files(&state.db, config_id).await?)
        } else {
            None
        };

        let entries = match entries {
            Some(values) => values,
            None => current_entries
                .unwrap_or_default()
                .into_iter()
                .map(to_api_config_entry)
                .collect(),
        };
        let files = match files {
            Some(values) => values,
            None => current_files
                .unwrap_or_default()
                .into_iter()
                .map(to_api_config_file)
                .collect(),
        };

        let (entries, files) = validate_config_payload(&entries, &files, &state.limits)?;
        let updated = config_store::replace_config_data(
            &state.db,
            config_id,
            &new_name,
            next_version,
            &entries,
            &files,
        )
        .await?;

        let response = build_config_response(&state, updated).await?;
        Ok(Json(response))
    }
    .await;

    match &result {
        Ok(Json(response)) => {
            record_audit_log(
                &state,
                "config.update",
                "config",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(response.metadata.config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(format!(
                        "name={}, version={}",
                        response.metadata.name, response.metadata.version
                    )),
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "config.update",
                "config",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    delete,
    path = "/api/v1/configs/{config_id}",
    params(("config_id" = Uuid, Path, description = "Config identifier")),
    responses(
        (
            status = 200,
            description = "Config deleted",
            body = ConfigMetadata,
            example = json!({
                "config_id": "00000000-0000-0000-0000-00000000cafe",
                "name": "app-config",
                "version": 2,
                "created_at": "2025-01-10T12:00:00Z",
                "updated_at": "2025-02-12T09:00:00Z"
            })
        ),
        (
            status = 404,
            description = "Config not found",
            body = ErrorResponse,
            example = json!({"error": "config not found", "code": "not_found"})
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn delete_config(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path(config_id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<ConfigMetadata>)> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();

    let result = async {
        let record = config_store::get_config(&state.db, config_id)
            .await?
            .ok_or_else(|| AppError::not_found("config not found"))?;
        let metadata = config_metadata(record);
        let deleted = config_store::delete_config(&state.db, config_id).await?;
        if deleted == 0 {
            return Err(AppError::not_found("config not found"));
        }

        Ok((StatusCode::OK, Json(metadata)))
    }
    .await;

    match &result {
        Ok((_status, Json(metadata))) => {
            record_audit_log(
                &state,
                "config.delete",
                "config",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(metadata.config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(format!(
                        "name={}, version={}",
                        metadata.name, metadata.version
                    )),
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "config.delete",
                "config",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    post,
    path = "/api/v1/configs/{config_id}/deployments/{deployment_id}",
    params(
        ("config_id" = Uuid, Path, description = "Config identifier"),
        ("deployment_id" = Uuid, Path, description = "Deployment identifier")
    ),
    responses(
        (
            status = 201,
            description = "Attachment created",
            body = ConfigAttachmentResponse,
            example = json!({
                "metadata": {
                    "config_id": "00000000-0000-0000-0000-00000000cafe",
                    "name": "app-config",
                    "version": 2,
                    "created_at": "2025-01-10T12:00:00Z",
                    "updated_at": "2025-02-12T09:00:00Z"
                },
                "deployment_id": "00000000-0000-0000-0000-00000000beef",
                "node_id": null,
                "attached": true,
                "attached_at": "2025-02-12T09:05:00Z"
            })
        ),
        (
            status = 200,
            description = "Attachment already existed",
            body = ConfigAttachmentResponse
        ),
        (
            status = 404,
            description = "Config or deployment not found",
            body = ErrorResponse,
            example = json!({"error": "deployment not found", "code": "not_found"})
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn attach_config_to_deployment(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path((config_id, deployment_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<ConfigAttachmentResponse>)> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();

    let result = async {
        let config = config_store::get_config(&state.db, config_id)
            .await?
            .ok_or_else(|| AppError::not_found("config not found"))?;
        if deployment_store::get_deployment(&state.db, deployment_id)
            .await?
            .is_none()
        {
            return Err(AppError::not_found("deployment not found"));
        }

        let rows =
            config_store::attach_config_to_deployment(&state.db, config_id, deployment_id).await?;
        let attached_at =
            config_store::config_deployment_attachment(&state.db, config_id, deployment_id).await?;
        let status = if rows > 0 {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        let response = ConfigAttachmentResponse {
            metadata: config_metadata(config),
            deployment_id: Some(deployment_id),
            node_id: None,
            attached: true,
            attached_at,
        };

        Ok((status, Json(response)))
    }
    .await;

    match &result {
        Ok((_status, Json(response))) => {
            record_audit_log(
                &state,
                "config.attach.deployment",
                "config",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(response.metadata.config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(format!("deployment_id={}", response.deployment_id.unwrap())),
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "config.attach.deployment",
                "config",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    delete,
    path = "/api/v1/configs/{config_id}/deployments/{deployment_id}",
    params(
        ("config_id" = Uuid, Path, description = "Config identifier"),
        ("deployment_id" = Uuid, Path, description = "Deployment identifier")
    ),
    responses(
        (
            status = 200,
            description = "Config detached",
            body = ConfigAttachmentResponse,
            example = json!({
                "metadata": {
                    "config_id": "00000000-0000-0000-0000-00000000cafe",
                    "name": "app-config",
                    "version": 2,
                    "created_at": "2025-01-10T12:00:00Z",
                    "updated_at": "2025-02-12T09:00:00Z"
                },
                "deployment_id": "00000000-0000-0000-0000-00000000beef",
                "node_id": null,
                "attached": false,
                "attached_at": null
            })
        ),
        (
            status = 404,
            description = "Config or deployment not found",
            body = ErrorResponse,
            example = json!({"error": "config not found", "code": "not_found"})
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn detach_config_from_deployment(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path((config_id, deployment_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<ConfigAttachmentResponse>> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();

    let result = async {
        let config = config_store::get_config(&state.db, config_id)
            .await?
            .ok_or_else(|| AppError::not_found("config not found"))?;
        if deployment_store::get_deployment(&state.db, deployment_id)
            .await?
            .is_none()
        {
            return Err(AppError::not_found("deployment not found"));
        }

        let _ = config_store::detach_config_from_deployment(&state.db, config_id, deployment_id)
            .await?;
        let response = ConfigAttachmentResponse {
            metadata: config_metadata(config),
            deployment_id: Some(deployment_id),
            node_id: None,
            attached: false,
            attached_at: None,
        };

        Ok(Json(response))
    }
    .await;

    match &result {
        Ok(Json(response)) => {
            record_audit_log(
                &state,
                "config.detach.deployment",
                "config",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(response.metadata.config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(format!("deployment_id={}", deployment_id)),
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "config.detach.deployment",
                "config",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    post,
    path = "/api/v1/configs/{config_id}/nodes/{node_id}",
    params(
        ("config_id" = Uuid, Path, description = "Config identifier"),
        ("node_id" = Uuid, Path, description = "Node identifier")
    ),
    responses(
        (
            status = 201,
            description = "Attachment created",
            body = ConfigAttachmentResponse,
            example = json!({
                "metadata": {
                    "config_id": "00000000-0000-0000-0000-00000000cafe",
                    "name": "app-config",
                    "version": 2,
                    "created_at": "2025-01-10T12:00:00Z",
                    "updated_at": "2025-02-12T09:00:00Z"
                },
                "deployment_id": null,
                "node_id": "00000000-0000-0000-0000-00000000babe",
                "attached": true,
                "attached_at": "2025-02-12T09:05:00Z"
            })
        ),
        (
            status = 200,
            description = "Attachment already existed",
            body = ConfigAttachmentResponse
        ),
        (
            status = 404,
            description = "Config or node not found",
            body = ErrorResponse,
            example = json!({"error": "node not found", "code": "not_found"})
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn attach_config_to_node(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path((config_id, node_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<ConfigAttachmentResponse>)> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();

    let result = async {
        let config = config_store::get_config(&state.db, config_id)
            .await?
            .ok_or_else(|| AppError::not_found("config not found"))?;
        if node_store::get_node(&state.db, node_id).await?.is_none() {
            return Err(AppError::not_found("node not found"));
        }

        let rows = config_store::attach_config_to_node(&state.db, config_id, node_id).await?;
        let attached_at =
            config_store::config_node_attachment(&state.db, config_id, node_id).await?;
        let status = if rows > 0 {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        let response = ConfigAttachmentResponse {
            metadata: config_metadata(config),
            deployment_id: None,
            node_id: Some(node_id),
            attached: true,
            attached_at,
        };

        Ok((status, Json(response)))
    }
    .await;

    match &result {
        Ok((_status, Json(response))) => {
            record_audit_log(
                &state,
                "config.attach.node",
                "config",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(response.metadata.config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(format!("node_id={}", response.node_id.unwrap())),
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "config.attach.node",
                "config",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    delete,
    path = "/api/v1/configs/{config_id}/nodes/{node_id}",
    params(
        ("config_id" = Uuid, Path, description = "Config identifier"),
        ("node_id" = Uuid, Path, description = "Node identifier")
    ),
    responses(
        (
            status = 200,
            description = "Config detached",
            body = ConfigAttachmentResponse,
            example = json!({
                "metadata": {
                    "config_id": "00000000-0000-0000-0000-00000000cafe",
                    "name": "app-config",
                    "version": 2,
                    "created_at": "2025-01-10T12:00:00Z",
                    "updated_at": "2025-02-12T09:00:00Z"
                },
                "deployment_id": null,
                "node_id": "00000000-0000-0000-0000-00000000babe",
                "attached": false,
                "attached_at": null
            })
        ),
        (
            status = 404,
            description = "Config or node not found",
            body = ErrorResponse,
            example = json!({"error": "config not found", "code": "not_found"})
        )
    ),
    security(("operatorBearer" = [])),
    tag = "configs"
)]
pub(crate) async fn detach_config_from_node(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path((config_id, node_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<ConfigAttachmentResponse>> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();

    let result = async {
        let config = config_store::get_config(&state.db, config_id)
            .await?
            .ok_or_else(|| AppError::not_found("config not found"))?;
        if node_store::get_node(&state.db, node_id).await?.is_none() {
            return Err(AppError::not_found("node not found"));
        }

        let _ = config_store::detach_config_from_node(&state.db, config_id, node_id).await?;
        let response = ConfigAttachmentResponse {
            metadata: config_metadata(config),
            deployment_id: None,
            node_id: Some(node_id),
            attached: false,
            attached_at: None,
        };

        Ok(Json(response))
    }
    .await;

    match &result {
        Ok(Json(response)) => {
            record_audit_log(
                &state,
                "config.detach.node",
                "config",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(response.metadata.config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(format!("node_id={}", node_id)),
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "config.detach.node",
                "config",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(config_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    get,
    path = "/api/v1/metrics/summary",
    params(MetricsSummaryParams),
    responses((status = 200, description = "Top HTTP request metrics", body = MetricsSummary)),
    security(("operatorBearer" = [])),
    tag = "observability"
)]
pub(crate) async fn metrics_summary(
    State(state): State<AppState>,
    Query(params): Query<MetricsSummaryParams>,
) -> ApiResult<Json<MetricsSummary>> {
    let MetricsSummaryParams { limit } = params;
    let limit = parse_metrics_limit(limit, state.limits.metrics_summary_limit)?;

    let counts = state.metrics_history.aggregate().await;

    let mut samples: Vec<MetricSample> = counts
        .into_iter()
        .map(|((method, path, status), count)| MetricSample {
            method,
            path,
            status,
            count,
        })
        .collect();
    samples.sort_by(|a, b| b.count.partial_cmp(&a.count).unwrap_or(Ordering::Equal));
    samples.truncate(limit as usize);

    Ok(Json(MetricsSummary {
        limit,
        window_secs: state.limits.metrics_summary_window_secs,
        as_of: Utc::now(),
        items: samples,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/deployments/{deployment_id}/metrics",
    params(("deployment_id" = Uuid, Path, description = "Deployment identifier")),
    responses(
        (
            status = 200,
            description = "Recent deployment resource metrics",
            body = DeploymentMetricsResponse
        ),
        (status = 404, description = "Deployment not found", body = ErrorResponse)
    ),
    security(("operatorBearer" = [])),
    tag = "observability"
)]
pub(crate) async fn deployment_metrics(
    State(state): State<AppState>,
    Path(deployment_id): Path<Uuid>,
) -> ApiResult<Json<DeploymentMetricsResponse>> {
    let metrics = services::deployments::deployment_metrics(&state, deployment_id).await?;
    Ok(Json(metrics))
}

#[utoipa::path(
    get,
    path = "/api/v1/usage",
    params(UsageQueryParams),
    responses(
        (
            status = 200,
            description = "Aggregated resource usage rollups (per-minute buckets)",
            body = UsageRollupPage,
            example = json!({
                "limit": 50,
                "offset": 0,
                "items": [
                    {
                        "deployment_id": "00000000-0000-0000-0000-00000000cafe",
                        "node_id": "00000000-0000-0000-0000-00000000beef",
                        "replica_number": 0,
                        "bucket_start": "2025-02-03T04:05:00Z",
                        "samples": 2,
                        "avg_cpu_percent": 12.3,
                        "avg_memory_bytes": 230686720,
                        "avg_network_rx_bytes": 10240,
                        "avg_network_tx_bytes": 9216,
                        "avg_blk_read_bytes": 4096,
                        "avg_blk_write_bytes": 0
                    }
                ]
            })
        ),
        (
            status = 400,
            description = "Missing required filter, malformed timestamp, or window outside retention",
            body = ErrorResponse,
            example = json!({
                "error": "deployment_id or node_id is required to query usage",
                "code": "bad_request"
            })
        )
    ),
    security(("operatorBearer" = [])),
    tag = "observability"
)]
pub(crate) async fn list_usage_rollups(
    State(state): State<AppState>,
    Query(params): Query<UsageQueryParams>,
) -> ApiResult<Json<UsageRollupPage>> {
    let (limit, offset) = parse_limit_offset(params.limit, params.offset)?;
    if params.deployment_id.is_none() && params.node_id.is_none() {
        return Err(AppError::bad_request(
            "deployment_id or node_id is required to query usage",
        ));
    }

    let (since, until) = usage_time_bounds(
        params.since,
        params.until,
        state.retention.usage_window_secs,
    )?;
    let filters = db::UsageRollupFilters {
        deployment_id: params.deployment_id,
        node_id: params.node_id,
        replica_number: params.replica_number,
        since: Some(since),
        until,
    };

    let items = services::deployments::list_usage_rollups(&state, filters, limit, offset).await?;

    Ok(Json(UsageRollupPage {
        limit,
        offset,
        items,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/nodes/{node_id}/tokens",
    params(
        ("node_id" = Uuid, Path, description = "Node identifier")
    ),
    request_body = TokenRotateRequest,
    responses((status = 201, description = "Token rotated", body = TokenResponse)),
    security(("operatorBearer" = [])),
    tag = "auth"
)]
pub async fn rotate_node_token(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path(node_id): Path<Uuid>,
    Json(body): Json<TokenRotateRequest>,
) -> ApiResult<(StatusCode, Json<TokenResponse>)> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();
    let payload = format!(
        "disable_existing={}, expires_at={}",
        body.disable_existing,
        body.expires_at
            .map(|ts| ts.to_rfc3339())
            .unwrap_or_else(|| "-".into())
    );

    let result: ApiResult<_> = async {
        let service_req = services::tokens::RotateNodeTokenRequest {
            node_id,
            expires_at: body.expires_at,
            disable_existing: body.disable_existing,
        };
        let token = services::tokens::rotate_node_token(&state, service_req).await?;

        Ok((
            StatusCode::CREATED,
            Json(TokenResponse {
                token_id: token.token_id,
                token: token.token,
                expires_at: token.expires_at,
            }),
        ))
    }
    .await;

    match &result {
        Ok((_status, Json(response))) => {
            record_audit_log(
                &state,
                "node.token.rotate",
                "node",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(node_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(format!(
                        "token_id={}, {}",
                        response.token_id,
                        payload.clone()
                    )),
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "node.token.rotate",
                "node",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(node_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    get,
    path = "/api/v1/deployments/{deployment_id}",
    params(
        ("deployment_id" = Uuid, Path, description = "Deployment identifier")
    ),
    responses((status = 200, description = "Deployment status", body = DeploymentStatusResponse)),
    security(("operatorBearer" = [])),
    tag = "deployments"
)]
pub(crate) async fn deployment_status(
    State(state): State<AppState>,
    Path(deployment_id): Path<Uuid>,
) -> ApiResult<Json<DeploymentStatusResponse>> {
    let resp = services::deployments::deployment_status(&state, deployment_id).await?;
    Ok(Json(resp))
}

#[utoipa::path(
    get,
    path = "/api/v1/deployments",
    params(ListParams),
    responses((status = 200, description = "List deployments", body = DeploymentSummaryPage)),
    security(("operatorBearer" = [])),
    tag = "deployments"
)]
pub(crate) async fn list_deployments(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> ApiResult<Json<DeploymentSummaryPage>> {
    let (limit, offset) = parse_pagination(&params)?;
    let status_filter = parse_deployment_status_filter(params.status.clone())?;
    let items =
        services::deployments::list_deployments(&state, status_filter, limit, offset).await?;
    Ok(Json(DeploymentSummaryPage {
        limit,
        offset,
        items,
    }))
}

pub(crate) struct DeploymentFields {
    pub(crate) replicas: i64,
    pub(crate) command: Option<Vec<String>>,
    pub(crate) env: Option<HashMap<String, String>>,
    pub(crate) secret_env: Option<Vec<db::SecretEnv>>,
    pub(crate) secret_files: Option<Vec<db::SecretFile>>,
    pub(crate) volumes: Option<Vec<db::VolumeMount>>,
    pub(crate) ports: Option<Vec<db::PortMapping>>,
    pub(crate) requires_public_ip: bool,
    pub(crate) tunnel_only: bool,
    pub(crate) constraints: Option<db::PlacementConstraints>,
    pub(crate) placement: Option<db::PlacementHints>,
    pub(crate) health: Option<DeploymentHealth>,
}

pub(crate) fn record_replica_schedule_decision(
    context: &str,
    decision: &scheduler::ReplicaScheduleDecision,
) {
    let outcome = if decision.placements.is_empty() {
        "unassigned"
    } else {
        "assigned"
    };
    counter!(
        "control_plane_scheduler_decisions_total",
        "context" => context.to_string(),
        "outcome" => outcome
    )
    .increment(1);
    gauge!(
        "control_plane_scheduler_ready_nodes",
        "context" => context.to_string()
    )
    .set(decision.ready_nodes as f64);
    gauge!(
        "control_plane_scheduler_compatible_nodes",
        "context" => context.to_string()
    )
    .set(decision.compatible_nodes as f64);
    gauge!(
        "control_plane_scheduler_total_nodes",
        "context" => context.to_string()
    )
    .set(decision.total_nodes as f64);
    gauge!(
        "control_plane_scheduler_port_conflicted_nodes",
        "context" => context.to_string()
    )
    .set(decision.port_conflicted_nodes as f64);
    gauge!(
        "control_plane_scheduler_placed_replicas",
        "context" => context.to_string()
    )
    .set(decision.placements.len() as f64);
    gauge!(
        "control_plane_scheduler_unplaced_replicas",
        "context" => context.to_string()
    )
    .set(decision.unplaced_replicas as f64);
}

pub(crate) fn assignments_from_decision(
    decision: &scheduler::ReplicaScheduleDecision,
) -> Vec<db::NewDeploymentAssignment> {
    decision
        .placements
        .iter()
        .map(|placement| db::NewDeploymentAssignment {
            replica_number: placement.replica_number as i64,
            node_id: placement.node_id,
            ports: placement.resolved_ports.clone(),
        })
        .collect()
}

pub(crate) fn assignments_from_records(
    records: &[db::DeploymentAssignmentRecord],
) -> Vec<db::NewDeploymentAssignment> {
    records
        .iter()
        .map(|rec| db::NewDeploymentAssignment {
            replica_number: rec.replica_number,
            node_id: rec.node_id,
            ports: rec.ports.as_ref().map(|ports| ports.0.clone()),
        })
        .collect()
}

pub(crate) fn assignments_changed(
    current: &[db::DeploymentAssignmentRecord],
    next: &[db::NewDeploymentAssignment],
) -> bool {
    if current.len() != next.len() {
        return true;
    }

    for (existing, new) in current.iter().zip(next.iter()) {
        if existing.replica_number != new.replica_number || existing.node_id != new.node_id {
            return true;
        }

        if existing.ports.as_ref().map(|p| &p.0) != new.ports.as_ref() {
            return true;
        }
    }

    false
}

fn assignment_summaries(records: &[db::DeploymentAssignmentRecord]) -> Vec<api::ReplicaAssignment> {
    records
        .iter()
        .map(|rec| api::ReplicaAssignment {
            replica_number: rec.replica_number.max(0) as u32,
            node_id: rec.node_id,
        })
        .collect()
}

fn first_assignment_ports(
    assignments: &[db::NewDeploymentAssignment],
    fallback: Option<Vec<db::PortMapping>>,
) -> Option<Vec<db::PortMapping>> {
    assignments
        .first()
        .and_then(|assignment| assignment.ports.clone())
        .or(fallback)
}

pub(crate) fn deployment_ports_for_storage(
    replicas: u32,
    assignments: &[db::NewDeploymentAssignment],
    fallback: Option<Vec<db::PortMapping>>,
) -> Option<Vec<db::PortMapping>> {
    if replicas <= 1 {
        return first_assignment_ports(assignments, fallback);
    }

    fallback
}

fn format_port_conflict(conflict: &db::PortReservationConflict) -> String {
    format!(
        "host port {} ({}) already reserved on node {} by deployment {}",
        db::PortReservationConflict::format_host(&conflict.host_ip, conflict.host_port),
        conflict.protocol,
        conflict.node_id,
        conflict.deployment_id
    )
}

fn port_conflict_to_app_error(conflict: &db::PortReservationConflict) -> AppError {
    AppError::bad_request(format_port_conflict(conflict))
}

pub(crate) fn map_port_error(err: anyhow::Error) -> AppError {
    if let Some(conflict) = err.downcast_ref::<db::PortReservationConflict>() {
        return port_conflict_to_app_error(conflict);
    }

    if let Some(allocation) = err.downcast_ref::<db::PortAllocationError>() {
        return match allocation {
            db::PortAllocationError::AutoAssignDisabled => {
                AppError::bad_request("auto host_port assignment is disabled")
            }
            db::PortAllocationError::Exhausted {
                range_start,
                range_end,
                ..
            } => AppError::bad_request(format!(
                "no available host ports in configured range {}-{}",
                range_start, range_end
            )),
            db::PortAllocationError::Conflict(conflict) => port_conflict_to_app_error(conflict),
        };
    }

    err.into()
}

pub(crate) fn port_allocation_config(cfg: &PortsConfig) -> db::PortAllocationConfig {
    db::PortAllocationConfig {
        enable_auto_assign: cfg.auto_assign,
        range_start: cfg.range_start,
        range_end: cfg.range_end,
    }
}

pub(crate) fn no_compatible_nodes_error_replicas(
    decision: &scheduler::ReplicaScheduleDecision,
    requires_public_ip: bool,
) -> AppError {
    if let Some(conflict) = decision.port_conflicts.first() {
        return AppError::bad_request(format!(
            "no nodes have required host ports free: {} ({} nodes blocked, total_nodes={})",
            format_port_conflict(conflict),
            decision.port_conflicted_nodes,
            decision.total_nodes
        ));
    }

    if let Some(err) = decision.allocation_errors.first() {
        if let db::PortAllocationError::Exhausted {
            range_start,
            range_end,
            ..
        } = err
        {
            return AppError::bad_request(format!(
                "no nodes have host ports available in range {}-{}",
                range_start, range_end
            ));
        }
        if let db::PortAllocationError::AutoAssignDisabled = err {
            return AppError::bad_request("auto host_port assignment is disabled");
        }
    }

    if requires_public_ip {
        return AppError::bad_request(
            "no public nodes available for requires_public_ip deployments",
        );
    }

    AppError::bad_request(format!(
        "no nodes satisfy placement constraints (total_nodes={})",
        decision.total_nodes
    ))
}

pub(crate) fn no_ready_nodes_error_replicas(
    decision: &scheduler::ReplicaScheduleDecision,
) -> AppError {
    AppError::service_unavailable(format!(
        "no ready nodes available for constraints (ready={}, compatible={}, total={}, port_conflicted={}, placed={}, unplaced={})",
        decision.ready_nodes,
        decision.compatible_nodes,
        decision.total_nodes,
        decision.port_conflicted_nodes,
        decision.placements.len(),
        decision.unplaced_replicas
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/deployments",
    request_body = DeploymentSpec,
    responses(
        (status = 201, description = "Deployment created", body = DeploymentCreateResponse),
        (status = 400, description = "Invalid deployment spec"),
        (status = 503, description = "No ready nodes")
    ),
    security(("operatorBearer" = [])),
    tag = "deployments"
)]
pub(crate) async fn create_deployment(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Json(spec): Json<DeploymentSpec>,
) -> ApiResult<(StatusCode, Json<DeploymentCreateResponse>)> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();
    let deployment_id = Uuid::new_v4();
    let payload_snippet = safe_deployment_spec_audit(&spec);

    let result: ApiResult<_> = async {
        let created = services::deployments::create_deployment(&state, deployment_id, spec).await?;
        Ok((
            StatusCode::CREATED,
            Json(DeploymentCreateResponse {
                deployment_id: created.deployment_id,
                assigned_node_id: created.assigned_node_id,
                assigned_node_ids: created.assigned_node_ids,
                unplaced_replicas: created.unplaced_replicas,
                generation: created.generation,
            }),
        ))
    }
    .await;

    match &result {
        Ok((_status, Json(response))) => {
            record_audit_log(
                &state,
                "deployment.create",
                "deployment",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(response.deployment_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: payload_snippet,
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "deployment.create",
                "deployment",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(deployment_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    patch,
    path = "/api/v1/deployments/{deployment_id}",
    params(
        ("deployment_id" = Uuid, Path, description = "Deployment identifier")
    ),
    request_body = DeploymentUpdate,
    responses((status = 200, description = "Deployment updated", body = DeploymentStatusResponse)),
    security(("operatorBearer" = [])),
    tag = "deployments"
)]
pub(crate) async fn update_deployment(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path(deployment_id): Path<Uuid>,
    Json(update): Json<DeploymentUpdate>,
) -> ApiResult<Json<DeploymentStatusResponse>> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();
    let payload_snippet = safe_deployment_update_audit(&update);
    let action = match update.desired_state {
        Some(api::DesiredState::Stopped) => "deployment.stop",
        Some(api::DesiredState::Running) => "deployment.start",
        None => "deployment.update",
    };

    let result: ApiResult<_> = async {
        let status =
            services::deployments::update_deployment(&state, deployment_id, update).await?;
        Ok(Json(status))
    }
    .await;

    match &result {
        Ok(Json(_response)) => {
            record_audit_log(
                &state,
                action,
                "deployment",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(deployment_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: payload_snippet,
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                action,
                "deployment",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(deployment_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    delete,
    path = "/api/v1/deployments/{deployment_id}",
    params(
        ("deployment_id" = Uuid, Path, description = "Deployment identifier")
    ),
    responses(
        (status = 204, description = "Deployment deleted"),
        (status = 404, description = "Deployment not found")
    ),
    security(("operatorBearer" = [])),
    tag = "deployments"
)]
pub(crate) async fn delete_deployment(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorIdentity>,
    request_id: Option<Extension<RequestId>>,
    Path(deployment_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let request_id = request_id_from_extension(request_id);
    let audit_actor = operator.to_audit_actor();
    let result = async {
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(error_mapper::map_service_error)?;
        let deleted = deployment_store::soft_delete_deployment_tx(&mut tx, deployment_id).await?;
        if deleted == 0 {
            return Err(AppError::not_found("deployment not found"));
        }

        port_store::delete_port_reservations(&mut tx, deployment_id).await?;
        tx.commit().await.map_err(error_mapper::map_service_error)?;

        Ok(StatusCode::NO_CONTENT)
    }
    .await;

    match &result {
        Ok(_) => {
            record_audit_log(
                &state,
                "deployment.delete",
                "deployment",
                audit::AuditStatus::Success,
                audit::AuditContext {
                    resource_id: Some(deployment_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: None,
                },
            )
            .await;
        }
        Err(err) => {
            record_audit_log(
                &state,
                "deployment.delete",
                "deployment",
                audit::AuditStatus::Failure,
                audit::AuditContext {
                    resource_id: Some(deployment_id),
                    actor: Some(&audit_actor),
                    request_id: request_id.as_deref(),
                    payload: Some(err.message.clone()),
                },
            )
            .await;
        }
    }

    result
}

#[utoipa::path(
    get,
    path = "/api/v1/nodes/{node_id}/desired-state",
    params(
        ("node_id" = Uuid, Path, description = "Node identifier")
    ),
    responses(
        (status = 200, description = "Desired state for node", body = DesiredStateResponse),
        (status = 400, description = "Missing or invalid agent version header", body = AgentVersionError),
        (status = 401, description = "Invalid node token", body = ErrorResponse),
        (status = 426, description = "Agent version unsupported", body = AgentVersionError)
    ),
    security(("nodeBearer" = [])),
    tag = "nodes"
)]
pub(crate) async fn desired_state(
    State(state): State<AppState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<DesiredStateResponse>> {
    let token = extract_bearer(&headers)?;

    let node = node_store::get_node(&state.db, node_id)
        .await?
        .ok_or_else(|| AppError::not_found("node not found"))?;

    if !verify_node_token(&state, node_id, &token, &node.token_hash).await? {
        return Err(AppError::unauthorized("invalid token"));
    }

    let deployments = deployment_store::list_deployments_for_node(&state.db, node_id).await?;
    let desired: anyhow::Result<Vec<_>> = deployments
        .into_iter()
        .map(|deployment| {
            map_deployment(deployment.deployment, &deployment.assignment, &state.ports)
        })
        .collect();
    let desired = desired?;

    Ok(Json(DesiredStateResponse {
        control_plane_version: crate::version::VERSION.to_string(),
        min_supported_agent_version: state.agent_compat.min_supported.to_string(),
        max_supported_agent_version: Some(state.agent_compat.max_supported.to_string()),
        upgrade_url: state.agent_compat.upgrade_url.clone(),
        tunnel: Some(tunnel_endpoint_from_state(&state)),
        deployments: desired,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/nodes/{node_id}/configs",
    params(("node_id" = Uuid, Path, description = "Node identifier")),
    responses(
        (
            status = 200,
            description = "Configs attached to the node or its deployments",
            body = NodeConfigResponse
        ),
        (status = 304, description = "Configs unchanged"),
        (
            status = 400,
            description = "Missing or invalid agent version header",
            body = AgentVersionError
        ),
        (status = 401, description = "Invalid node token", body = ErrorResponse),
        (
            status = 426,
            description = "Agent version unsupported",
            body = AgentVersionError
        ),
        (
            status = 404,
            description = "Node not found",
            body = ErrorResponse,
            example = json!({"error": "node not found", "code": "not_found"})
        ),
        (
            status = 413,
            description = "Serialized config payload exceeded configured size limit",
            body = ErrorResponse,
            example = json!({
                "error": "config payload exceeds 131072 bytes limit",
                "code": "payload_too_large"
            })
        )
    ),
    security(("nodeBearer" = [])),
    tag = "nodes"
)]
pub(crate) async fn node_configs(
    State(state): State<AppState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let token = extract_bearer(&headers)?;

    let node = node_store::get_node(&state.db, node_id)
        .await?
        .ok_or_else(|| AppError::not_found("node not found"))?;

    if !verify_node_token(&state, node_id, &token, &node.token_hash).await? {
        return Err(AppError::unauthorized("invalid token"));
    }

    let configs = collect_node_configs(&state, node_id).await?;
    let etag_value = configs_etag(&configs);
    let etag_header = HeaderValue::from_str(&etag_value)
        .map_err(|_| AppError::internal("failed to encode etag"))?;

    if etag_matches(&headers, &etag_header) {
        return Ok(not_modified_response(etag_header.clone()));
    }

    let payload = NodeConfigResponse {
        configs,
        service_identities: Vec::new(),
    };
    let serialized = serde_json::to_vec(&payload).map_err(error_mapper::map_service_error)?;

    let limit = state.limits.config_payload_bytes;
    if limit > 0 && serialized.len() as u64 > limit {
        return Err(AppError::payload_too_large(format!(
            "config payload exceeds {limit} bytes limit"
        )));
    }

    let mut response = Response::new(Body::from(serialized));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response.headers_mut().insert(ETAG, etag_header);

    Ok(response)
}

#[derive(Default)]
struct ConfigTargets {
    deployments: HashSet<Uuid>,
    nodes: HashSet<Uuid>,
}

async fn collect_node_configs(state: &AppState, node_id: Uuid) -> Result<Vec<ConfigDesired>> {
    let assignments = deployment_store::list_deployments_for_node(&state.db, node_id).await?;

    let mut targets: HashMap<Uuid, ConfigTargets> = HashMap::new();

    let node_configs = config_store::configs_for_node(&state.db, node_id).await?;
    for config_id in node_configs {
        targets.entry(config_id).or_default().nodes.insert(node_id);
    }

    for deployment in &assignments {
        let dep_id = deployment.deployment.id;
        let configs = config_store::configs_for_deployment(&state.db, dep_id).await?;
        for config_id in configs {
            targets
                .entry(config_id)
                .or_default()
                .deployments
                .insert(dep_id);
        }
    }

    let mut configs = Vec::with_capacity(targets.len());
    for (config_id, attachment) in targets {
        let Some(record) = config_store::get_config(&state.db, config_id).await? else {
            warn!(%config_id, "config attachment missing target record");
            continue;
        };

        let (entries, files) = tokio::try_join!(
            config_store::list_config_entries(&state.db, config_id),
            config_store::list_config_files(&state.db, config_id)
        )?;

        let entries: Vec<ApiConfigEntry> = entries.into_iter().map(to_api_config_entry).collect();
        let files: Vec<ApiConfigFile> = files.into_iter().map(to_api_config_file).collect();
        let metadata = config_metadata(record);
        let checksum = config_checksum(&metadata, &entries, &files);

        let mut desired = ConfigDesired {
            metadata,
            entries,
            files,
            attached_deployments: attachment.deployments.into_iter().collect(),
            attached_nodes: attachment.nodes.into_iter().collect(),
            checksum: Some(checksum),
        };

        desired.attached_deployments.sort();
        desired.attached_nodes.sort();
        configs.push(desired);
    }

    configs.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));

    Ok(configs)
}

fn config_checksum(
    metadata: &ConfigMetadata,
    entries: &[ApiConfigEntry],
    files: &[ApiConfigFile],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(metadata.config_id.as_bytes());
    hasher.update(metadata.version.to_le_bytes());
    hasher.update(metadata.updated_at.timestamp_micros().to_le_bytes());

    for entry in entries {
        hasher.update(entry.key.as_bytes());
        if let Some(value) = &entry.value {
            hasher.update(value.as_bytes());
        }
        hasher.update([0]);
        if let Some(secret) = &entry.secret_ref {
            hasher.update(secret.as_bytes());
        }
        hasher.update([0]);
    }

    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update(file.file_ref.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}

fn configs_etag(configs: &[ConfigDesired]) -> String {
    let mut hasher = Sha256::new();

    for config in configs {
        hasher.update(config.metadata.config_id.as_bytes());
        hasher.update(config.metadata.version.to_le_bytes());
        hasher.update(config.metadata.updated_at.timestamp_micros().to_le_bytes());
        if let Some(checksum) = &config.checksum {
            hasher.update(checksum.as_bytes());
        }
        for dep_id in &config.attached_deployments {
            hasher.update(dep_id.as_bytes());
        }
        for node_id in &config.attached_nodes {
            hasher.update(node_id.as_bytes());
        }
    }

    format!("W/\"{:x}\"", hasher.finalize())
}

fn etag_matches(headers: &HeaderMap, etag: &HeaderValue) -> bool {
    let Some(if_none_match) = headers.get(IF_NONE_MATCH) else {
        return false;
    };

    let Ok(value) = if_none_match.to_str() else {
        return false;
    };

    let Ok(target) = etag.to_str() else {
        return false;
    };

    value
        .split(',')
        .map(|v| v.trim())
        .any(|candidate| candidate == "*" || candidate == target)
}

fn not_modified_response(etag: HeaderValue) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    response.headers_mut().insert(ETAG, etag);
    response
}

fn map_deployment(
    dep: db::DeploymentRecord,
    assignment: &db::DeploymentAssignmentRecord,
    port_cfg: &PortsConfig,
) -> Result<DeploymentDesired> {
    let mut fields = deserialize_deployment_fields(&dep, port_cfg)?;
    if let Some(ports) = assignment.ports.as_ref() {
        fields.ports = Some(ports.0.clone());
    }
    let ports = annotate_ports_with_endpoint(fields.ports.take(), port_cfg);

    Ok(DeploymentDesired {
        deployment_id: dep.id,
        name: dep.name,
        replica_number: assignment.replica_number as u32,
        image: dep.image,
        replicas: fields.replicas.max(1) as u32,
        command: fields.command,
        env: fields.env,
        secret_env: fields.secret_env,
        secret_files: fields.secret_files,
        ports,
        requires_public_ip: fields.requires_public_ip,
        tunnel_only: fields.tunnel_only,
        volumes: fields.volumes,
        placement: fields.placement,
        health: fields.health,
        desired_state: to_api_desired_state(dep.desired_state),
        replica_generation: Some(dep.generation),
        generation: dep.generation,
    })
}

pub(crate) fn deserialize_deployment_fields(
    dep: &db::DeploymentRecord,
    port_cfg: &PortsConfig,
) -> Result<DeploymentFields> {
    let replicas = dep.replicas.max(1);
    let command = dep
        .command_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;
    let env = dep
        .env_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;
    let secret_env = dep
        .secret_env_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;
    let secret_files = dep
        .secret_files_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;
    let volumes = dep
        .volumes_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;
    let ports = dep
        .ports_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;
    let ports = normalize_ports(ports, port_cfg, None);
    let requires_public_ip = dep.requires_public_ip;
    let tunnel_only = dep.tunnel_only;
    let constraints = dep
        .constraints
        .as_ref()
        .map(|constraints| constraints.0.clone());
    let placement = dep.placement.as_ref().map(|placement| placement.0.clone());
    let health = dep.health.as_ref().map(|health| health.0.clone());

    Ok(DeploymentFields {
        replicas,
        command,
        env,
        secret_env,
        secret_files,
        volumes,
        ports,
        requires_public_ip,
        tunnel_only,
        constraints,
        placement,
        health,
    })
}

fn normalize_host_ip_field(host_ip: Option<String>) -> Option<String> {
    host_ip.and_then(|ip| {
        let trimmed = ip.trim();
        if trimmed.is_empty() || trimmed == "0.0.0.0" || trimmed == "::" {
            None
        } else {
            Some(trimmed.to_ascii_lowercase())
        }
    })
}

pub fn normalize_ports(
    ports: Option<Vec<db::PortMapping>>,
    port_cfg: &PortsConfig,
    existing_ports: Option<&[db::PortMapping]>,
) -> Option<Vec<db::PortMapping>> {
    let mut existing_lookup: HashMap<(u16, String, Option<String>), u16> = HashMap::new();
    if let Some(existing) = existing_ports {
        for port in existing {
            if let Some(host_port) = port.host_port {
                let key = (
                    port.container_port,
                    port.protocol.to_ascii_lowercase(),
                    normalize_host_ip_field(port.host_ip.clone()),
                );
                existing_lookup.insert(key, host_port);
            }
        }
    }

    let _ = port_cfg;

    ports.map(|ports| {
        ports
            .into_iter()
            .map(|mut port| {
                port.protocol = port.protocol.to_ascii_lowercase();
                let normalized_ip = normalize_host_ip_field(port.host_ip.take());
                port.host_ip = normalized_ip.clone();
                if port.host_port.is_none() {
                    let key = (
                        port.container_port,
                        port.protocol.clone(),
                        normalized_ip.clone(),
                    );
                    if let Some(existing_host_port) = existing_lookup.get(&key) {
                        port.host_port = Some(*existing_host_port);
                    }
                }
                port
            })
            .collect()
    })
}

fn annotate_ports_with_endpoint(
    ports: Option<Vec<db::PortMapping>>,
    port_cfg: &PortsConfig,
) -> Option<Vec<db::PortMapping>> {
    ports.map(|mut list| {
        for port in &mut list {
            port.endpoint = endpoint_for_port(port, port_cfg);
        }
        list
    })
}

fn endpoint_for_port(port: &db::PortMapping, port_cfg: &PortsConfig) -> Option<String> {
    if !port.expose {
        return None;
    }

    let host_port = port.host_port?;
    let host = port
        .host_ip
        .as_ref()
        .filter(|ip| !ip.is_empty())
        .cloned()
        .or_else(|| port_cfg.public_host.as_ref().map(String::from));
    host.map(|host| format!("{host}:{host_port}"))
}

pub(crate) async fn build_deployment_response(
    state: &AppState,
    deployment: db::DeploymentRecord,
) -> Result<DeploymentStatusResponse> {
    let DeploymentFields {
        replicas,
        command,
        env,
        secret_env,
        secret_files,
        volumes,
        ports: stored_ports,
        requires_public_ip,
        tunnel_only,
        constraints,
        placement,
        health,
    } = deserialize_deployment_fields(&deployment, &state.ports)?;

    let assignments =
        deployment_store::list_assignments_for_deployment(&state.db, deployment.id).await?;
    let assigned_node_id = deployment
        .assigned_node_id
        .or_else(|| assignments.first().map(|a| a.node_id));
    let ports = select_deployment_ports(&assignments, assigned_node_id, stored_ports);
    let ports = annotate_ports_with_endpoint(ports, &state.ports);
    let assignment_nodes = assignment_summaries(&assignments);
    let instance =
        log_store::get_instance_status_for_deployment(&state.db, deployment.id, assigned_node_id)
            .await?;
    let instance_resp = instance.as_ref().map(to_instance_status_response);
    let usage_summary = load_usage_summary(
        state,
        db::UsageSummaryFilters {
            deployment_id: Some(deployment.id),
            ..Default::default()
        },
    )
    .await?;

    Ok(DeploymentStatusResponse {
        deployment_id: deployment.id,
        name: deployment.name,
        image: deployment.image,
        replicas: replicas.max(1) as u32,
        command,
        env,
        secret_env,
        secret_files,
        ports,
        requires_public_ip,
        tunnel_only,
        constraints,
        placement,
        volumes,
        health,
        desired_state: to_api_desired_state(deployment.desired_state),
        status: to_api_deployment_status(deployment.status),
        assigned_node_id,
        assignments: assignment_nodes,
        generation: deployment.generation,
        last_reported: instance.as_ref().map(|i| i.last_seen),
        instance: instance_resp,
        usage_summary,
        created_at: deployment.created_at,
        updated_at: deployment.updated_at,
    })
}

fn select_deployment_ports(
    assignments: &[db::DeploymentAssignmentRecord],
    assigned_node_id: Option<Uuid>,
    fallback: Option<Vec<db::PortMapping>>,
) -> Option<Vec<db::PortMapping>> {
    let mut fallback_ports = None;
    for assignment in assignments {
        if let Some(ports) = assignment.ports.as_ref() {
            let ports_clone = ports.0.clone();
            if Some(assignment.node_id) == assigned_node_id {
                return Some(ports_clone);
            }
            if assignment.replica_number == 0 || fallback_ports.is_none() {
                fallback_ports = Some(ports_clone);
            }
        }
    }

    fallback_ports.or(fallback)
}

fn to_instance_status_response(record: &db::InstanceStatusRecord) -> InstanceStatusResponse {
    InstanceStatusResponse {
        deployment_id: record.deployment_id,
        replica_number: record.replica_number as u32,
        container_id: record.container_id.clone(),
        state: to_api_instance_state(record.state),
        message: record.message.clone(),
        restart_count: record.restart_count.max(0) as u32,
        generation: record.generation,
        last_updated: record.last_updated,
        last_seen: record.last_seen,
        endpoints: record
            .endpoints
            .as_ref()
            .map(|json| json.0.clone())
            .unwrap_or_default(),
        health: record.health.as_ref().map(|health| health.0.clone()),
        metrics: record
            .metrics
            .as_ref()
            .map(|metrics| metrics.0.clone())
            .unwrap_or_default(),
    }
}

pub(crate) async fn load_usage_summary(
    state: &AppState,
    filters: db::UsageSummaryFilters,
) -> Result<Option<UsageSummary>> {
    let (window_start, window_end) = usage_summary_bounds(state.retention.usage_window_secs);
    let summary =
        usage_store::summarize_usage_rollups(&state.db, filters, window_start, window_end).await?;
    Ok(summary.map(|s| UsageSummary {
        window_start: s.window_start,
        window_end: s.window_end,
        samples: s.samples,
        avg_cpu_percent: s.avg_cpu_percent,
        avg_memory_bytes: s.avg_memory_bytes,
        avg_network_rx_bytes: s.avg_network_rx_bytes,
        avg_network_tx_bytes: s.avg_network_tx_bytes,
        avg_blk_read_bytes: s.avg_blk_read_bytes,
        avg_blk_write_bytes: s.avg_blk_write_bytes,
    }))
}

pub(crate) async fn update_deployment_statuses_for_node(
    db: &db::Db,
    deployments: &[db::DeploymentWithAssignment],
) -> Result<()> {
    for deployment in deployments {
        let dep = &deployment.deployment;
        let instances = log_store::list_instance_statuses_for_deployment(db, dep.id).await?;
        let derived = derive_deployment_status(dep.desired_state, &instances);
        if derived != dep.status {
            deployment_store::update_deployment_status(db, dep.id, derived).await?;
        }
    }

    Ok(())
}

fn derive_deployment_status(
    desired_state: db::DesiredState,
    instances: &[db::InstanceStatusRecord],
) -> db::DeploymentStatus {
    if instances.is_empty() {
        return match desired_state {
            db::DesiredState::Running => db::DeploymentStatus::Deploying,
            db::DesiredState::Stopped => db::DeploymentStatus::Stopped,
        };
    }

    let mut any_running = false;
    let mut any_failed = false;
    let mut any_pending = false;
    let mut all_stopped = true;

    for inst in instances {
        match inst.state {
            db::InstanceState::Running => {
                any_running = true;
                all_stopped = false;
            }
            db::InstanceState::Failed => {
                any_failed = true;
                all_stopped = false;
            }
            db::InstanceState::Pending | db::InstanceState::Unknown => {
                any_pending = true;
                all_stopped = false;
            }
            db::InstanceState::Stopped => {}
        }
    }

    if any_failed {
        db::DeploymentStatus::Failed
    } else if any_running {
        db::DeploymentStatus::Running
    } else if all_stopped {
        db::DeploymentStatus::Stopped
    } else if any_pending {
        db::DeploymentStatus::Deploying
    } else {
        match desired_state {
            db::DesiredState::Running => db::DeploymentStatus::Deploying,
            db::DesiredState::Stopped => db::DeploymentStatus::Stopped,
        }
    }
}

async fn verify_node_token(
    state: &AppState,
    node_id: Uuid,
    token: &str,
    fallback_hash: &str,
) -> Result<bool> {
    let active_tokens = token_store::list_active_node_tokens(&state.db, node_id).await?;
    let has_any_tokens = if active_tokens.is_empty() {
        token_store::node_tokens_exist(&state.db, node_id).await?
    } else {
        true
    };
    for node_token in active_tokens {
        if let Some(kind) = match_token(token, &node_token.token_hash, &state.token_pepper)? {
            if matches!(kind, TokenMatch::Legacy) {
                let new_hash = hash_token(token, &state.token_pepper)?;
                if let Err(err) = token_store::update_node_token_record_hash(
                    &state.db,
                    node_token.id,
                    new_hash.clone(),
                )
                .await
                {
                    warn!(?err, %node_id, "failed to upgrade node token hash");
                } else {
                    let _ =
                        node_store::update_node_token_hash(&state.db, node_id, new_hash.clone())
                            .await;
                    info!(%node_id, "upgraded node token hash to argon2");
                }
            }
            let _ = token_store::touch_node_token_last_used(&state.db, node_token.id).await;
            return Ok(true);
        }
    }

    if has_any_tokens {
        return Ok(false);
    }

    if fallback_hash.is_empty() {
        return Ok(false);
    }

    if let Some(kind) = match_token(token, fallback_hash, &state.token_pepper)? {
        let stored_hash = if matches!(kind, TokenMatch::Legacy) {
            hash_token(token, &state.token_pepper)?
        } else {
            fallback_hash.to_string()
        };

        match token_store::create_node_token(&state.db, node_id, stored_hash.clone(), None).await {
            Ok(record) => {
                let _ = token_store::touch_node_token_last_used(&state.db, record.id).await;
            }
            Err(err) => {
                warn!(?err, %node_id, "failed to persist node token record");
            }
        }
        let _ = node_store::update_node_token_hash(&state.db, node_id, stored_hash.clone()).await;
        if matches!(kind, TokenMatch::Legacy) {
            info!(%node_id, "upgraded node token hash to argon2");
        }
        return Ok(true);
    }

    Ok(false)
}

#[derive(OpenApi)]
#[openapi(
    paths(
        healthz,
        metrics,
        register_node,
        heartbeat,
        desired_state,
        node_configs,
        list_nodes,
        node_status,
        list_configs,
        get_config,
        create_config,
        update_config,
        delete_config,
        attach_config_to_deployment,
        detach_config_from_deployment,
        attach_config_to_node,
        detach_config_from_node,
        list_deployments,
        create_deployment,
        deployment_status,
        update_deployment,
        delete_deployment,
        metrics_summary,
        deployment_metrics,
        list_usage_rollups,
    ),
    components(schemas(
        api::DeploymentSpec,
        api::DeploymentUpdate,
        api::DeploymentCreateResponse,
        api::DeploymentStatusResponse,
        api::DeploymentSummary,
        api::DeploymentDesired,
        api::DesiredStateResponse,
        api::NodeStatusResponse,
        api::NodeSummary,
        api::InstanceStatus,
        api::InstanceStatusResponse,
        api::ResourceMetricSample,
        api::RegistrationResponse,
        api::InstanceState,
        api::TunnelEndpoint,
        api::SecretEnv,
        api::SecretFile,
        api::PortMapping,
        api::PlacementHints,
        api::PlacementAffinity,
        api::PlacementConstraints,
        api::DesiredState,
        api::DeploymentStatus,
        api::ReplicaAssignment,
        api::DeploymentUpdate,
        api::DeploymentSummaryPage,
        api::NodeSummaryPage,
        api::NodeStatus,
        api::CapacityHints,
        RegistrationRequest,
        HeartbeatRequest,
        NodeInventoryPayload,
        HealthResponse,
        AgentVersionError,
        ErrorResponse,
        OkResponse,
        ListParams,
        MetricsSummaryParams,
        api::MetricsSummary,
        api::MetricSample,
        api::DeploymentMetricsResponse,
        api::ReplicaResourceMetrics,
        api::UsageRollup,
        api::UsageSummary,
        UsageQueryParams,
        api::UsageRollupPage,
        api::ConfigResponse,
        api::ConfigSummary,
        api::ConfigSummaryPage,
        api::ConfigCreateRequest,
        api::ConfigUpdateRequest,
        api::ConfigEntry,
        api::ConfigFile,
        api::ConfigAttachmentResponse,
        api::ConfigMetadata,
        api::ConfigDesired,
        api::NodeConfigResponse,
        api::DeploymentHealth,
        api::HealthStatus,
        api::HealthProbe,
        api::HealthProbeKind,
        api::VolumeMount,
        NodeTunnelHealth,
        RelayHealth,
        api::ServiceIdentityBundle,
    )),
    tags(
        (name = "system", description = "Health and metrics"),
        (name = "nodes", description = "Node registration and status"),
        (name = "deployments", description = "Deployment management"),
        (name = "configs", description = "Config management and attachments"),
        (name = "observability", description = "Log tail and metrics summaries for UI observability"),
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.info.title = "Distributed Edge Hosting API".to_string();
        openapi.info.version = crate::version::FULL_VERSION.to_string();

        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_schemes_from_iter([
            (
                "registrationBearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque")
                        .description(Some(
                            "Bearer token for node registration (Authorization header).",
                        ))
                        .build(),
                ),
            ),
            (
                "nodeBearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque")
                        .description(Some(
                            "Bearer node token for node heartbeats and desired state.",
                        ))
                        .build(),
                ),
            ),
            (
                "operatorBearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque")
                        .description(Some(
                            "Bearer operator token for operator APIs (header name configurable).",
                        ))
                        .build(),
                ),
            ),
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{self, Body},
        http::{HeaderName, Request},
    };
    use chrono::{Duration as ChronoDuration, Timelike, Utc};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    mod common {
        use super::*;
        use crate::app_state::{NoopRegistrationLimiter, OperatorAuth, RegistrationLimiterRef};
        use std::sync::Arc;

        pub(super) async fn setup_state() -> AppState {
            let db = crate::persistence::migrations::init_pool("sqlite::memory:")
                .await
                .unwrap();
            let migration_outcome = crate::persistence::migrations::run_migrations(&db)
                .await
                .unwrap();
            let scheduler = scheduler::RoundRobinScheduler::new(db.clone());
            let registration_limiter: RegistrationLimiterRef =
                Arc::new(tokio::sync::Mutex::new(NoopRegistrationLimiter));
            let metrics_handle = crate::metrics::init_metrics_recorder();
            crate::metrics::record_build_info(&migration_outcome.snapshot);
            let limits = crate::config::LimitsConfig {
                registration_body_bytes: 1024,
                heartbeat_body_bytes: 1024,
                config_payload_bytes: 1024,
                heartbeat_metrics_per_instance: 60,
                heartbeat_metrics_total: 500,
                resource_metrics_max_series: 500,
                max_field_len: 255,
                log_tail_limit: 10,
                log_tail_max_window_secs: 600,
                metrics_summary_limit: 5,
                metrics_summary_window_secs: 60,
            };
            let metrics_history =
                crate::metrics::MetricsHistory::new(limits.metrics_summary_window_secs);

            AppState {
                db: db.clone(),
                scheduler,
                registration_token: "reg".into(),
                operator_auth: OperatorAuth {
                    tokens: vec!["op-token".into()],
                    header_name: HeaderName::from_static("authorization"),
                },
                operator_token_validator: std::sync::Arc::new(|state, token| {
                    Box::pin(crate::auth::env_only_operator_token_validator(state, token))
                }),
                registration_limiter: Some(registration_limiter),
                token_pepper: "pepper".into(),
                limits,
                retention: crate::config::RetentionConfig {
                    instance_status_secs: 86_400,
                    instance_metrics_secs: 600,
                    usage_window_secs: 604_800,
                    usage_cleanup_interval_secs: 300,
                },
                reachability: crate::config::ReachabilityConfig::default(),
                ports: crate::config::PortsConfig {
                    auto_assign: true,
                    range_start: 30_000,
                    range_end: 30_100,
                    public_host: None,
                },
                volumes: crate::config::VolumesConfig {
                    allowed_host_prefixes: Vec::new(),
                },
                tunnel: crate::config::TunnelConfig::default(),
                metrics_handle,
                metrics_history,
                tunnel_registry: crate::tunnel::TunnelRegistry::new(),
                relay_health: crate::tunnel::RelayHealthState::default(),
                agent_compat: crate::compat::AgentCompatibility::from_config(
                    &crate::config::CompatibilityConfig {
                        min_agent_version: None,
                        max_agent_version: None,
                        upgrade_url: None,
                    },
                )
                .unwrap(),
                schema: migration_outcome.snapshot,
                enforce_agent_compatibility: true,
                pem_key: Some([7u8; 32]),
                audit_sink: None,
            }
        }

        pub(super) fn operator_request(uri: &str) -> Request<Body> {
            Request::builder()
                .uri(uri)
                .header("authorization", "Bearer op-token")
                .body(Body::empty())
                .unwrap()
        }
    }

    mod auth {
        use super::common::setup_state;
        use super::*;

        #[tokio::test]
        async fn list_endpoints_require_operator_auth() {
            let state = setup_state().await;
            let app = build_router(state.clone()).with_state(state);
            for uri in ["/api/v1/nodes", "/api/v1/metrics/summary"] {
                let response = app
                    .clone()
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
        }
    }

    mod deployments {
        use super::api::Page;
        use super::common::{operator_request, setup_state};
        use super::*;
        use chrono::Utc;

        #[tokio::test]
        async fn list_deployments_filters_by_status() {
            let state = setup_state().await;
            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash: "h".into(),
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: Some(Utc::now()),
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let running = db::NewDeployment {
                id: Uuid::new_v4(),
                name: "run".into(),
                image: "img:1".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: db::DesiredState::Running,
                assigned_node_id: Some(node_id),
                status: db::DeploymentStatus::Running,
                generation: 1,
                assignments: vec![db::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id,
                    ports: None,
                }],
            };
            let pending = db::NewDeployment {
                id: Uuid::new_v4(),
                name: "pending".into(),
                image: "img:2".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: db::DesiredState::Running,
                assigned_node_id: Some(node_id),
                status: db::DeploymentStatus::Pending,
                generation: 1,
                assignments: vec![db::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id,
                    ports: None,
                }],
            };
            deployment_store::create_deployment(&state.db, running)
                .await
                .unwrap();
            deployment_store::create_deployment(&state.db, pending)
                .await
                .unwrap();

            let app = build_router(state.clone()).with_state(state);
            let response = app
                .oneshot(operator_request(
                    "/api/v1/deployments?limit=1&offset=0&status=running",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let page: Page<DeploymentSummary> = serde_json::from_slice(&body).unwrap();
            assert_eq!(page.limit, 1);
            assert_eq!(page.offset, 0);
            assert_eq!(page.items.len(), 1);
            assert_eq!(page.items[0].name, "run");
            assert_eq!(page.items[0].status, api::DeploymentStatus::Running);
        }

        #[tokio::test]
        async fn create_deployment_rejects_public_ingress_without_exposed_ports() {
            let state = setup_state().await;
            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash: "h".into(),
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: Some(Utc::now()),
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let spec = api::DeploymentSpec {
                name: Some("web".into()),
                image: "nginx:latest".into(),
                replicas: Some(1),
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                ports: Some(vec![api::PortMapping {
                    container_port: 8080,
                    host_port: None,
                    protocol: "tcp".into(),
                    host_ip: None,
                    expose: false,
                    endpoint: None,
                }]),
                requires_public_ip: true,
                tunnel_only: false,
                constraints: None,
                placement: None,
                desired_state: None,
                volumes: None,
                health: None,
            };

            let app = build_router(state.clone()).with_state(state);
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/deployments")
                        .header("authorization", "Bearer op-token")
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(&spec).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let bytes = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                err.error,
                "requires_public_ip requires at least one port with expose=true"
            );
            assert_eq!(err.code, "bad_request");
        }

        #[tokio::test]
        async fn create_deployment_allows_public_ingress_with_exposed_port() {
            let state = setup_state().await;
            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash: "h".into(),
                arch: None,
                os: None,
                public_ip: Some("203.0.113.10".into()),
                public_host: Some("public.example.test".into()),
                labels: None,
                capacity: None,
                last_seen: Some(Utc::now()),
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let spec = api::DeploymentSpec {
                name: Some("web".into()),
                image: "nginx:latest".into(),
                replicas: Some(1),
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                ports: Some(vec![api::PortMapping {
                    container_port: 8080,
                    host_port: None,
                    protocol: "tcp".into(),
                    host_ip: None,
                    expose: true,
                    endpoint: None,
                }]),
                requires_public_ip: true,
                tunnel_only: false,
                constraints: None,
                placement: None,
                desired_state: None,
                volumes: None,
                health: None,
            };

            let app = build_router(state.clone()).with_state(state.clone());
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/deployments")
                        .header("authorization", "Bearer op-token")
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(&spec).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            let (parts, body) = response.into_parts();
            if parts.status != StatusCode::CREATED {
                let bytes = body::to_bytes(body, usize::MAX).await.unwrap();
                panic!(
                    "unexpected status {} with body: {}",
                    parts.status,
                    String::from_utf8_lossy(&bytes)
                );
            }
        }

        #[tokio::test]
        async fn deployment_metrics_endpoint_trims_window_and_exports_gauges() {
            let mut state = setup_state().await;
            state.retention.instance_metrics_secs = 60;
            state.limits.resource_metrics_max_series = 10;
            let token = "node-token";
            let token_hash = crate::tokens::hash_token(token, &state.token_pepper).unwrap();

            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: None,
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let deployment_id = Uuid::new_v4();
            let deployment = db::NewDeployment {
                id: deployment_id,
                name: "dep".into(),
                image: "img:1".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: db::DesiredState::Running,
                assigned_node_id: Some(node_id),
                status: db::DeploymentStatus::Running,
                generation: 1,
                assignments: vec![db::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id,
                    ports: None,
                }],
            };
            deployment_store::create_deployment(&state.db, deployment)
                .await
                .unwrap();

            let now = Utc::now();
            let old_metric = api::ResourceMetricSample {
                collected_at: now - ChronoDuration::seconds(600),
                cpu_percent: 5.0,
                memory_bytes: 64,
                network_rx_bytes: 10,
                network_tx_bytes: 20,
                blk_read_bytes: None,
                blk_write_bytes: None,
            };
            let recent_metric = api::ResourceMetricSample {
                collected_at: now,
                cpu_percent: 42.0,
                memory_bytes: 1024,
                network_rx_bytes: 100,
                network_tx_bytes: 200,
                blk_read_bytes: Some(1),
                blk_write_bytes: Some(2),
            };

            let heartbeat = HeartbeatRequest {
                node_status: api::NodeStatus::Ready,
                containers: vec![api::InstanceStatus {
                    deployment_id,
                    replica_number: 0,
                    container_id: Some("c1".into()),
                    state: api::InstanceState::Running,
                    message: None,
                    restart_count: 0,
                    generation: 1,
                    last_updated: now,
                    endpoints: Vec::new(),
                    health: None,
                    metrics: vec![old_metric.clone(), recent_metric.clone()],
                }],
                timestamp: Some(now),
                inventory: None,
                public_ip: None,
                public_host: None,
            };

            let app = build_router(state.clone()).with_state(state);
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", node_id))
                .header("authorization", format!("Bearer {token}"))
                .header("x-agent-version", crate::version::VERSION)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&heartbeat).unwrap()))
                .unwrap();

            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let response = app
                .clone()
                .oneshot(operator_request(&format!(
                    "/api/v1/deployments/{deployment_id}/metrics"
                )))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let metrics: DeploymentMetricsResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(metrics.replicas.len(), 1);
            let replica = &metrics.replicas[0];
            assert_eq!(replica.metrics, vec![recent_metric]);

            let response = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/metrics")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body = String::from_utf8_lossy(&body_bytes);
            assert!(
                body.contains("deployment_cpu_percent")
                    && body.contains(&deployment_id.to_string())
            );
        }
    }

    mod metrics {
        use super::common::{operator_request, setup_state};
        use super::*;

        #[tokio::test]
        async fn metrics_summary_returns_samples() {
            let state = setup_state().await;
            let metrics_limit = state.limits.metrics_summary_limit;
            let window_secs = state.limits.metrics_summary_window_secs;
            let app = build_router(state.clone()).with_state(state);
            let response = app
                .oneshot(operator_request("/api/v1/metrics/summary"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let summary: MetricsSummary = serde_json::from_slice(&body).unwrap();
            assert_eq!(summary.limit, metrics_limit);
            assert_eq!(summary.window_secs, window_secs);
            assert!(summary.items.len() <= metrics_limit as usize);
        }

        #[tokio::test]
        async fn metrics_summary_respects_limit() {
            let state = setup_state().await;
            let metrics_limit = state.limits.metrics_summary_limit;
            let app = build_router(state.clone()).with_state(state);
            let response = app
                .oneshot(operator_request(&format!(
                    "/api/v1/metrics/summary?limit={}",
                    metrics_limit + 1
                )))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    mod nodes {
        use super::api::Page;
        use super::common::{operator_request, setup_state};
        use super::*;
        use serde_json::json;

        #[tokio::test]
        async fn list_nodes_filters_and_paginates() {
            let state = setup_state().await;
            let now = Utc::now();
            let ready = db::NewNode {
                id: Uuid::new_v4(),
                name: Some("ready-1".into()),
                token_hash: "h1".into(),
                arch: Some("amd64".into()),
                os: Some("linux".into()),
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: Some(now),
                status: db::NodeStatus::Ready,
            };
            let unreachable = db::NewNode {
                id: Uuid::new_v4(),
                name: Some("unreachable".into()),
                token_hash: "h2".into(),
                arch: Some("arm64".into()),
                os: Some("linux".into()),
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: Some(now),
                status: db::NodeStatus::Unreachable,
            };
            let ready_two = db::NewNode {
                id: Uuid::new_v4(),
                name: Some("ready-2".into()),
                token_hash: "h3".into(),
                arch: Some("amd64".into()),
                os: Some("linux".into()),
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: Some(now),
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, ready).await.unwrap();
            node_store::create_node(&state.db, unreachable)
                .await
                .unwrap();
            node_store::create_node(&state.db, ready_two).await.unwrap();

            let app = build_router(state.clone()).with_state(state);
            let response = app
                .oneshot(operator_request(
                    "/api/v1/nodes?limit=2&offset=0&status=ready",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let page: Page<NodeSummary> = serde_json::from_slice(&body).unwrap();
            assert_eq!(page.limit, 2);
            assert_eq!(page.offset, 0);
            assert_eq!(page.items.len(), 2);
            assert_eq!(page.items[0].name.as_deref(), Some("ready-1"));
            assert_eq!(page.items[1].name.as_deref(), Some("ready-2"));
        }

        #[tokio::test]
        async fn registration_persists_public_ingress_metadata() {
            let state = setup_state().await;
            let app = build_router(state.clone()).with_state(state.clone());

            let req_body = json!({
                "name": "edge-1",
                "public_ip": "203.0.113.10",
                "public_host": "Edge.EXAMPLE.com"
            });

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/nodes/register")
                        .header("authorization", "Bearer reg")
                        .header("x-agent-version", crate::version::VERSION)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(req_body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::CREATED);
            let body = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let registered: api::RegistrationResponse = serde_json::from_slice(&body).unwrap();

            let stored = node_store::get_node(&state.db, registered.node_id)
                .await
                .unwrap()
                .expect("node persisted");

            assert_eq!(stored.public_ip.as_deref(), Some("203.0.113.10"));
            assert_eq!(stored.public_host.as_deref(), Some("edge.example.com"));
        }

        #[tokio::test]
        async fn heartbeat_persists_and_returns_metrics() {
            let state = setup_state().await;
            let token = "node-token";
            let token_hash = crate::tokens::hash_token(token, &state.token_pepper).unwrap();

            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: None,
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let deployment_id = Uuid::new_v4();
            let deployment = db::NewDeployment {
                id: deployment_id,
                name: "dep".into(),
                image: "img:1".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: db::DesiredState::Running,
                assigned_node_id: Some(node_id),
                status: db::DeploymentStatus::Running,
                generation: 1,
                assignments: vec![db::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id,
                    ports: None,
                }],
            };
            deployment_store::create_deployment(&state.db, deployment)
                .await
                .unwrap();

            let metric = api::ResourceMetricSample {
                collected_at: Utc::now(),
                cpu_percent: 25.0,
                memory_bytes: 512 * 1024,
                network_rx_bytes: 100,
                network_tx_bytes: 200,
                blk_read_bytes: Some(50),
                blk_write_bytes: Some(75),
            };

            let heartbeat = HeartbeatRequest {
                node_status: api::NodeStatus::Ready,
                containers: vec![api::InstanceStatus {
                    deployment_id,
                    replica_number: 0,
                    container_id: Some("c1".into()),
                    state: api::InstanceState::Running,
                    message: None,
                    restart_count: 0,
                    generation: 1,
                    last_updated: metric.collected_at,
                    endpoints: Vec::new(),
                    health: None,
                    metrics: vec![metric.clone()],
                }],
                timestamp: Some(metric.collected_at),
                inventory: None,
                public_ip: None,
                public_host: None,
            };

            let app = build_router(state.clone()).with_state(state.clone());
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", node_id))
                .header("authorization", format!("Bearer {token}"))
                .header("x-agent-version", crate::version::VERSION)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&heartbeat).unwrap()))
                .unwrap();

            let response = app.clone().oneshot(request).await.unwrap();
            let status = response.status();
            let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                status == StatusCode::OK,
                "heartbeat failed: {}",
                String::from_utf8_lossy(&body_bytes)
            );

            let response = app
                .oneshot(operator_request(&format!("/api/v1/nodes/{node_id}")))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let status: NodeStatusResponse = serde_json::from_slice(&body).unwrap();
            let metrics = &status.instances[0].metrics;
            assert_eq!(metrics, &[metric]);
        }

        #[tokio::test]
        async fn heartbeat_preserves_existing_public_ingress_when_absent() {
            let state = setup_state().await;
            let token = "node-token";
            let token_hash = crate::tokens::hash_token(token, &state.token_pepper).unwrap();

            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash,
                arch: None,
                os: None,
                public_ip: Some("198.51.100.5".into()),
                public_host: Some("edge.example.com".into()),
                labels: None,
                capacity: None,
                last_seen: None,
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let heartbeat = HeartbeatRequest {
                node_status: api::NodeStatus::Ready,
                containers: Vec::new(),
                timestamp: None,
                inventory: None,
                public_ip: None,
                public_host: None,
            };

            let app = build_router(state.clone()).with_state(state.clone());
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/v1/nodes/{}/heartbeats", node_id))
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-agent-version", crate::version::VERSION)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(&heartbeat).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);

            let stored = node_store::get_node(&state.db, node_id)
                .await
                .unwrap()
                .expect("node persisted");

            assert_eq!(stored.public_ip.as_deref(), Some("198.51.100.5"));
            assert_eq!(stored.public_host.as_deref(), Some("edge.example.com"));
        }

        #[tokio::test]
        async fn heartbeat_ingests_usage_rollups() {
            let state = setup_state().await;
            let token = "node-token";
            let token_hash = crate::tokens::hash_token(token, &state.token_pepper).unwrap();

            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: None,
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let deployment_id = Uuid::new_v4();
            let deployment = db::NewDeployment {
                id: deployment_id,
                name: "dep".into(),
                image: "img:1".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: db::DesiredState::Running,
                assigned_node_id: Some(node_id),
                status: db::DeploymentStatus::Running,
                generation: 1,
                assignments: vec![db::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id,
                    ports: None,
                }],
            };
            deployment_store::create_deployment(&state.db, deployment)
                .await
                .unwrap();

            let base = Utc::now()
                .with_second(5)
                .and_then(|dt| dt.with_nanosecond(0))
                .unwrap();

            let samples = vec![
                api::ResourceMetricSample {
                    collected_at: base,
                    cpu_percent: 20.0,
                    memory_bytes: 200,
                    network_rx_bytes: 20,
                    network_tx_bytes: 10,
                    blk_read_bytes: Some(100),
                    blk_write_bytes: Some(10),
                },
                api::ResourceMetricSample {
                    collected_at: base + ChronoDuration::seconds(10),
                    cpu_percent: 40.0,
                    memory_bytes: 400,
                    network_rx_bytes: 40,
                    network_tx_bytes: 30,
                    blk_read_bytes: Some(200),
                    blk_write_bytes: Some(30),
                },
                api::ResourceMetricSample {
                    collected_at: base + ChronoDuration::seconds(70),
                    cpu_percent: 60.0,
                    memory_bytes: 900,
                    network_rx_bytes: 90,
                    network_tx_bytes: 120,
                    blk_read_bytes: Some(300),
                    blk_write_bytes: Some(60),
                },
            ];

            let heartbeat = HeartbeatRequest {
                node_status: api::NodeStatus::Ready,
                containers: vec![api::InstanceStatus {
                    deployment_id,
                    replica_number: 0,
                    container_id: Some("c1".into()),
                    state: api::InstanceState::Running,
                    message: None,
                    restart_count: 0,
                    generation: 1,
                    last_updated: base,
                    endpoints: Vec::new(),
                    health: None,
                    metrics: samples,
                }],
                timestamp: Some(base),
                inventory: None,
                public_ip: None,
                public_host: None,
            };

            let app = build_router(state.clone()).with_state(state.clone());
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", node_id))
                .header("authorization", format!("Bearer {token}"))
                .header("x-agent-version", crate::version::VERSION)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&heartbeat).unwrap()))
                .unwrap();

            let response = app.clone().oneshot(request).await.unwrap();
            let status = response.status();
            let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                status == StatusCode::OK,
                "heartbeat failed: {}",
                String::from_utf8_lossy(&body_bytes)
            );

            type UsageMetricRow = (
                DateTime<Utc>,
                i64,
                f64,
                i64,
                i64,
                i64,
                Option<i64>,
                Option<i64>,
            );

            let rows: Vec<UsageMetricRow> = sqlx::query_as::<_, UsageMetricRow>(
                r#"
                SELECT bucket_start,
                       samples,
                       avg_cpu_percent,
                       avg_memory_bytes,
                       avg_network_rx_bytes,
                       avg_network_tx_bytes,
                       avg_blk_read_bytes,
                       avg_blk_write_bytes
                FROM deployment_usage_rollups
                WHERE deployment_id = ?1 AND node_id = ?2
                ORDER BY bucket_start ASC
                "#,
            )
            .bind(deployment_id)
            .bind(node_id)
            .fetch_all(&state.db)
            .await
            .unwrap();

            assert_eq!(rows.len(), 2);

            let (first_bucket, samples, cpu, mem, rx, tx, blk_r, blk_w) = &rows[0];
            assert_eq!(first_bucket.second(), 0);
            assert_eq!(*samples, 2);
            assert!((*cpu - 30.0).abs() < 0.001);
            assert_eq!(*mem, 300);
            assert_eq!(*rx, 30);
            assert_eq!(*tx, 20);
            assert_eq!(*blk_r, Some(150));
            assert_eq!(*blk_w, Some(20));

            let (second_bucket, samples, cpu, mem, rx, tx, blk_r, blk_w) = &rows[1];
            assert_eq!(second_bucket.second(), 0);
            assert_eq!(*samples, 1);
            assert!((*cpu - 60.0).abs() < 0.001);
            assert_eq!(*mem, 900);
            assert_eq!(*rx, 90);
            assert_eq!(*tx, 120);
            assert_eq!(*blk_r, Some(300));
            assert_eq!(*blk_w, Some(60));

            let usage_response = app
                .clone()
                .oneshot(operator_request(&format!(
                    "/api/v1/usage?deployment_id={deployment_id}"
                )))
                .await
                .unwrap();
            assert_eq!(usage_response.status(), StatusCode::OK);
            let usage_body = body::to_bytes(usage_response.into_body(), usize::MAX)
                .await
                .unwrap();
            let usage_page: Page<UsageRollupResponse> =
                serde_json::from_slice(&usage_body).unwrap();
            assert_eq!(usage_page.items.len(), 2);
            assert!(usage_page.items[0].bucket_start > usage_page.items[1].bucket_start);
            assert!(usage_page.items.iter().any(|r| r.samples == 2));
            assert!(usage_page.items.iter().any(|r| r.samples == 1));
            assert_eq!(usage_page.items[0].avg_memory_bytes, 900);

            let dep_status_resp = app
                .clone()
                .oneshot(operator_request(&format!(
                    "/api/v1/deployments/{deployment_id}"
                )))
                .await
                .unwrap();
            assert_eq!(dep_status_resp.status(), StatusCode::OK);
            let dep_status_body = body::to_bytes(dep_status_resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let dep_status: DeploymentStatusResponse =
                serde_json::from_slice(&dep_status_body).unwrap();
            let summary = dep_status
                .usage_summary
                .expect("deployment usage summary missing");
            assert_eq!(summary.samples, 3);
            assert!((summary.avg_cpu_percent - 40.0).abs() < 0.001);
            assert_eq!(summary.avg_memory_bytes, 500);
            assert_eq!(summary.avg_network_rx_bytes, 50);
            assert_eq!(summary.avg_network_tx_bytes, 53);
            assert_eq!(summary.avg_blk_read_bytes, Some(200));
            assert_eq!(summary.avg_blk_write_bytes, Some(33));

            let node_status_resp = app
                .clone()
                .oneshot(operator_request(&format!("/api/v1/nodes/{node_id}")))
                .await
                .unwrap();
            assert_eq!(node_status_resp.status(), StatusCode::OK);
            let node_body = body::to_bytes(node_status_resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let node_status: NodeStatusResponse = serde_json::from_slice(&node_body).unwrap();
            assert!(node_status.usage_summary.is_some());

            let metrics_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/metrics")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(metrics_response.status(), StatusCode::OK);
            let metrics_body = metrics_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            let metrics_text = String::from_utf8_lossy(&metrics_body);
            assert!(metrics_text.contains("deployment_usage_cpu_percent"));
            assert!(metrics_text.contains(&deployment_id.to_string()));
        }

        #[tokio::test]
        async fn heartbeat_rejects_metrics_over_limit() {
            let mut state = setup_state().await;
            state.limits.heartbeat_metrics_per_instance = 1;
            state.limits.heartbeat_metrics_total = 1;

            let token = "node-token";
            let token_hash = crate::tokens::hash_token(token, &state.token_pepper).unwrap();
            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: None,
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let deployment_id = Uuid::new_v4();
            let deployment = db::NewDeployment {
                id: deployment_id,
                name: "dep".into(),
                image: "img:1".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: db::DesiredState::Running,
                assigned_node_id: Some(node_id),
                status: db::DeploymentStatus::Running,
                generation: 1,
                assignments: vec![db::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id,
                    ports: None,
                }],
            };
            deployment_store::create_deployment(&state.db, deployment)
                .await
                .unwrap();

            let now = Utc::now();
            let samples = vec![
                api::ResourceMetricSample {
                    collected_at: now,
                    cpu_percent: 10.0,
                    memory_bytes: 128,
                    network_rx_bytes: 1,
                    network_tx_bytes: 1,
                    blk_read_bytes: None,
                    blk_write_bytes: None,
                },
                api::ResourceMetricSample {
                    collected_at: now,
                    cpu_percent: 20.0,
                    memory_bytes: 256,
                    network_rx_bytes: 2,
                    network_tx_bytes: 2,
                    blk_read_bytes: None,
                    blk_write_bytes: None,
                },
            ];

            let heartbeat = HeartbeatRequest {
                node_status: api::NodeStatus::Ready,
                containers: vec![api::InstanceStatus {
                    deployment_id,
                    replica_number: 0,
                    container_id: Some("c1".into()),
                    state: api::InstanceState::Running,
                    message: None,
                    restart_count: 0,
                    generation: 1,
                    last_updated: now,
                    endpoints: Vec::new(),
                    health: None,
                    metrics: samples,
                }],
                timestamp: Some(now),
                inventory: None,
                public_ip: None,
                public_host: None,
            };

            let app = build_router(state.clone()).with_state(state);
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", node_id))
                .header("authorization", format!("Bearer {token}"))
                .header("x-agent-version", crate::version::VERSION)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&heartbeat).unwrap()))
                .unwrap();

            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
            assert!(err.error.contains("metrics samples"));
        }
    }

    mod usage {
        use super::api::Page;
        use super::common::{operator_request, setup_state};
        use super::*;

        #[test]
        fn usage_summary_bounds_cap_at_now() {
            let before = Utc::now();
            let (start, end) = usage_summary_bounds(0);
            let after = Utc::now();

            assert!(
                end >= before && end <= after,
                "window_end {end} not within now bounds {before} - {after}"
            );
            assert!(
                start <= end,
                "window_start {start} should not be after window_end {end}"
            );

            let window = end - start;
            assert!(
                window <= ChronoDuration::seconds(USAGE_SUMMARY_WINDOW_SECS as i64),
                "window length {window:?} exceeds summary window {USAGE_SUMMARY_WINDOW_SECS}s"
            );
        }

        #[test]
        fn usage_time_bounds_rejects_windows_outside_retention() {
            let now = Utc::now();
            let since = now - ChronoDuration::minutes(15);
            let until = now - ChronoDuration::minutes(10);

            let err = usage_time_bounds(Some(since), Some(until), 120).unwrap_err();
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert!(err.message.contains("outside the retention period"));
        }

        #[test]
        fn aggregate_usage_rollups_drops_old_samples_and_trims_limit() {
            let node_id = Uuid::new_v4();
            let deployment_id = Uuid::new_v4();
            let now = Utc::now();

            let ancient = api::ResourceMetricSample {
                collected_at: now - ChronoDuration::seconds(600),
                cpu_percent: 10.0,
                memory_bytes: 64,
                network_rx_bytes: 1,
                network_tx_bytes: 1,
                blk_read_bytes: None,
                blk_write_bytes: None,
            };
            let recent = api::ResourceMetricSample {
                collected_at: now - ChronoDuration::seconds(30),
                cpu_percent: 20.0,
                memory_bytes: 128,
                network_rx_bytes: 2,
                network_tx_bytes: 3,
                blk_read_bytes: Some(4),
                blk_write_bytes: Some(5),
            };
            let previous_minute = api::ResourceMetricSample {
                collected_at: now - ChronoDuration::seconds(90),
                cpu_percent: 30.0,
                memory_bytes: 256,
                network_rx_bytes: 4,
                network_tx_bytes: 6,
                blk_read_bytes: Some(8),
                blk_write_bytes: Some(10),
            };

            let instances = vec![db::InstanceStatusUpsert {
                deployment_id,
                replica_number: 0,
                generation: 1,
                container_id: Some("c1".into()),
                state: db::InstanceState::Running,
                message: None,
                restart_count: 0,
                last_updated: now,
                last_seen: now,
                endpoints: Vec::new(),
                health: None,
                metrics: vec![ancient, recent.clone(), previous_minute.clone()],
            }];

            let (rollups, stats) = aggregate_usage_rollups(node_id, &instances, 1, 180, now);
            assert_eq!(stats.accepted_samples, 2);
            assert_eq!(stats.dropped_samples, 1);
            assert_eq!(stats.truncated_buckets, 1);
            assert_eq!(rollups.len(), 1);

            let expected_bucket = truncate_to_minute(recent.collected_at);
            let kept = &rollups[0];
            assert_eq!(kept.bucket_start, expected_bucket);
            assert_eq!(kept.deployment_id, deployment_id);
            assert_eq!(kept.node_id, node_id);
            assert_eq!(kept.samples, 1);
            assert!((kept.avg_cpu_percent - recent.cpu_percent).abs() < 0.001);
            assert_eq!(kept.avg_memory_bytes, recent.memory_bytes as i64);
            assert_eq!(kept.avg_network_rx_bytes, recent.network_rx_bytes as i64);
            assert_eq!(kept.avg_network_tx_bytes, recent.network_tx_bytes as i64);
            assert_eq!(
                kept.avg_blk_read_bytes,
                recent.blk_read_bytes.map(|v| v as i64)
            );
            assert_eq!(
                kept.avg_blk_write_bytes,
                recent.blk_write_bytes.map(|v| v as i64)
            );
        }

        #[tokio::test]
        async fn usage_query_supports_pagination_and_time_filters() {
            let mut state = setup_state().await;
            state.retention.usage_window_secs = 3_600;

            let token = "node-token";
            let token_hash = crate::tokens::hash_token(token, &state.token_pepper).unwrap();
            let node_id = Uuid::new_v4();
            let node = db::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: None,
                status: db::NodeStatus::Ready,
            };
            node_store::create_node(&state.db, node).await.unwrap();

            let deployment_id = Uuid::new_v4();
            let deployment = db::NewDeployment {
                id: deployment_id,
                name: "dep".into(),
                image: "img:1".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: db::DesiredState::Running,
                assigned_node_id: Some(node_id),
                status: db::DeploymentStatus::Running,
                generation: 1,
                assignments: vec![db::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id,
                    ports: None,
                }],
            };
            deployment_store::create_deployment(&state.db, deployment)
                .await
                .unwrap();

            let base = Utc::now()
                .with_second(0)
                .and_then(|dt| dt.with_nanosecond(0))
                .unwrap();
            let buckets = [
                base,
                base - ChronoDuration::minutes(1),
                base - ChronoDuration::minutes(2),
            ];

            for (idx, bucket) in buckets.iter().enumerate() {
                sqlx::query(
                    r#"
                    INSERT INTO deployment_usage_rollups (
                        deployment_id,
                        node_id,
                        replica_number,
                        bucket_start,
                        samples,
                        avg_cpu_percent,
                        avg_memory_bytes,
                        avg_network_rx_bytes,
                        avg_network_tx_bytes,
                        avg_blk_read_bytes,
                        avg_blk_write_bytes
                    ) VALUES (?1, ?2, 0, ?3, 1, ?4, ?5, 10, 20, NULL, NULL)
                    "#,
                )
                .bind(deployment_id)
                .bind(node_id)
                .bind(*bucket)
                .bind(10.0 * (idx as f64 + 1.0))
                .bind(100 * (idx as i64 + 1))
                .execute(&state.db)
                .await
                .unwrap();
            }

            let app = build_router(state.clone()).with_state(state);

            let resp = app
                .clone()
                .oneshot(operator_request(&format!(
                    "/api/v1/usage?deployment_id={deployment_id}&limit=2&offset=0"
                )))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let page: Page<UsageRollupResponse> = serde_json::from_slice(&body).unwrap();
            assert_eq!(page.limit, 2);
            assert_eq!(page.offset, 0);
            assert_eq!(page.items.len(), 2);
            assert!(page.items[0].bucket_start > page.items[1].bucket_start);
            assert_eq!(page.items[0].bucket_start, buckets[0]);

            let since = (buckets[0] - ChronoDuration::seconds(30)).to_rfc3339();
            let resp = app
                .clone()
                .oneshot(operator_request(&format!(
                    "/api/v1/usage?deployment_id={deployment_id}&since={since}"
                )))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let filtered: Page<UsageRollupResponse> = serde_json::from_slice(&body).unwrap();
            assert_eq!(filtered.items.len(), 1);
            assert_eq!(filtered.items[0].bucket_start, buckets[0]);

            let until = buckets[1].to_rfc3339();
            let resp = app
                .oneshot(operator_request(&format!(
                    "/api/v1/usage?deployment_id={deployment_id}&until={until}&limit=5"
                )))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let bounded: Page<UsageRollupResponse> = serde_json::from_slice(&body).unwrap();
            assert_eq!(bounded.items.len(), 2);
            assert!(bounded.items.iter().all(|r| r.bucket_start <= buckets[1]));
        }
    }

    mod relay {
        use super::common::setup_state;
        use super::*;

        #[tokio::test]
        async fn relay_returns_actionable_error_when_no_tunnel() {
            let state = setup_state().await;
            let app = build_router(state.clone()).with_state(state);

            let node_id = Uuid::new_v4();
            let request = Request::builder()
                .method("POST")
                .uri(format!("/relay/{}/api/v1/test", node_id))
                .body(Body::from("payload"))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), 503);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let text = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                text.contains("tunnel_unavailable"),
                "expected tunnel_unavailable error, got {}",
                text
            );
        }

        #[tokio::test]
        async fn relay_reports_closed_channel_mid_request() {
            let state = setup_state().await;
            let app = build_router(state.clone()).with_state(state.clone());

            let node_id = Uuid::new_v4();
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            drop(rx);
            let inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
            state
                .tunnel_registry
                .upsert(node_id, Uuid::new_v4(), tx, inflight)
                .await;

            let request = Request::builder()
                .method("GET")
                .uri(format!("/relay/{}/status", node_id))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), 502);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let text = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                text.contains("tunnel_closed"),
                "expected tunnel_closed error, got {}",
                text
            );
        }
    }
}
