use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::warn;
use uuid::Uuid;

use crate::{
    api::{
        ConfigDesired, DeploymentHealth, HealthStatus, InstanceState, InstanceStatus, PortMapping,
        ResourceMetricSample, ServiceIdentityBundle, TunnelEndpoint,
    },
    compat, config,
    runtime::{ContainerResourceUsage, ContainerRuntimeError, DynContainerRuntime},
    telemetry, REQUEST_ID_HEADER, TRACEPARENT_HEADER,
};

pub const ENDPOINTS_LABEL: &str = "fledx.endpoints";
pub const CONFIG_FINGERPRINT_LABEL: &str = "fledx.config_fingerprint";

/// Role of a probe within the deployment health configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRole {
    /// Liveness probe indicates whether the container should be restarted.
    Liveness,
    /// Readiness probe gates traffic without triggering restarts.
    Readiness,
}

/// Tracks per-probe execution metadata used by the health loop.
#[derive(Debug, Clone, Default)]
pub struct ProbeState {
    pub consecutive_failures: u32,
    pub healthy: Option<bool>,
    pub reason: Option<String>,
    pub last_probe_result: Option<String>,
    pub last_error: Option<String>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ManagedDeployment {
    pub container_id: Option<String>,
    pub state: InstanceState,
    pub message: Option<String>,
    pub restart_count: u32,
    pub consecutive_failures: u32,
    pub backoff_until: Option<DateTime<Utc>>,
    pub generation: i64,
    pub last_updated: DateTime<Utc>,
    pub endpoints: Vec<String>,
    pub health: Option<HealthStatus>,
    pub health_config: Option<DeploymentHealth>,
    pub ports: Option<Vec<PortMapping>>,
    pub liveness_probe_state: ProbeState,
    pub readiness_probe_state: ProbeState,
    pub last_started_at: Option<DateTime<Utc>>,
    pub failed_probe: Option<ProbeRole>,
}

impl ManagedDeployment {
    pub fn new(generation: i64) -> Self {
        Self {
            container_id: None,
            state: InstanceState::Unknown,
            message: None,
            restart_count: 0,
            consecutive_failures: 0,
            backoff_until: None,
            generation,
            last_updated: Utc::now(),
            endpoints: Vec::new(),
            health: None,
            health_config: None,
            ports: None,
            liveness_probe_state: ProbeState::default(),
            readiness_probe_state: ProbeState::default(),
            last_started_at: None,
            failed_probe: None,
        }
    }

    pub fn reset_for_generation(&mut self, generation: i64) {
        if self.generation != generation {
            self.generation = generation;
            self.restart_count = 0;
            self.consecutive_failures = 0;
            self.backoff_until = None;
            self.message = None;
            self.container_id = None;
            self.endpoints.clear();
            self.health = None;
            self.health_config = None;
            self.ports = None;
            self.liveness_probe_state = ProbeState::default();
            self.readiness_probe_state = ProbeState::default();
            self.last_started_at = None;
            self.failed_probe = None;
        }
    }

    pub fn mark_state(
        &mut self,
        container_id: Option<String>,
        state: InstanceState,
        message: Option<String>,
    ) {
        self.container_id = container_id;
        self.state = state;
        self.message = message;
        self.last_updated = Utc::now();
        if matches!(self.state, InstanceState::Running) {
            self.last_started_at = Some(Utc::now());
        } else {
            self.last_started_at = None;
        }
    }

    pub fn mark_running(&mut self, container_id: Option<String>) {
        self.consecutive_failures = 0;
        self.backoff_until = None;
        self.liveness_probe_state = ProbeState::default();
        self.readiness_probe_state = ProbeState::default();
        self.failed_probe = None;
        self.health = None;
        self.mark_state(container_id, InstanceState::Running, None);
    }

    /// Keep the recorded container details fresh without resetting probe state.
    pub fn refresh_running(&mut self, container_id: Option<String>) {
        self.container_id = container_id;
        self.last_updated = Utc::now();
        if self.state != InstanceState::Running {
            self.state = InstanceState::Running;
        }
    }
}

pub type RuntimeFactory =
    Arc<dyn Fn() -> Result<DynContainerRuntime, ContainerRuntimeError> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplicaKey {
    pub deployment_id: Uuid,
    pub replica_number: u32,
}

impl ReplicaKey {
    pub fn new(deployment_id: Uuid, replica_number: u32) -> Self {
        Self {
            deployment_id,
            replica_number,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TunnelHealthStatus {
    pub healthy: bool,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub cfg: config::AppConfig,
    pub client: reqwest::Client,
    pub runtime: Option<DynContainerRuntime>,
    pub runtime_factory: RuntimeFactory,
    pub runtime_backoff_attempts: u32,
    pub runtime_backoff_until: Option<Instant>,
    pub needs_adoption: bool,
    pub compat: compat::CompatState,
    pub configs: HashMap<Uuid, ConfigDesired>,
    pub configs_etag: Option<String>,
    pub configs_backoff_attempts: u32,
    pub configs_backoff_until: Option<Instant>,
    /// Cached service identity bundles from the control-plane.
    pub service_identities: Vec<ServiceIdentityBundle>,
    /// Hash of the last seen service identity set for change detection.
    pub service_identities_fingerprint: Option<String>,
    pub request_context: RequestContext,
    pub tunnel: TunnelEndpoint,
    pub tunnel_health: TunnelHealthStatus,
}

#[derive(Default)]
pub struct ManagedStore {
    pub managed: HashMap<ReplicaKey, ManagedDeployment>,
    pub resource_samples: HashMap<ReplicaKey, VecDeque<ContainerResourceUsage>>,
}

#[derive(Clone)]
pub struct SharedState {
    app: Arc<Mutex<AppState>>,
    managed: Arc<RwLock<ManagedStore>>,
}

impl SharedState {
    pub fn new(
        cfg: config::AppConfig,
        client: reqwest::Client,
        runtime_factory: RuntimeFactory,
        runtime: Option<DynContainerRuntime>,
    ) -> Self {
        let tunnel = tunnel_from_cfg(&cfg);
        let app = Arc::new(Mutex::new(AppState {
            cfg,
            client,
            runtime,
            runtime_factory,
            runtime_backoff_attempts: 0,
            runtime_backoff_until: None,
            needs_adoption: true,
            compat: compat::CompatState::default(),
            configs: HashMap::new(),
            configs_etag: None,
            configs_backoff_attempts: 0,
            configs_backoff_until: None,
            service_identities: Vec::new(),
            service_identities_fingerprint: None,
            request_context: RequestContext::default(),
            tunnel,
            tunnel_health: TunnelHealthStatus::default(),
        }));

        Self {
            app,
            managed: Arc::new(RwLock::new(ManagedStore::default())),
        }
    }

    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, AppState> {
        self.app.lock().await
    }

    pub async fn managed_read(&self) -> RwLockReadGuard<'_, ManagedStore> {
        self.managed.read().await
    }

    pub async fn managed_write(&self) -> RwLockWriteGuard<'_, ManagedStore> {
        self.managed.write().await
    }

    pub async fn acquire_runtime(&self) -> Result<DynContainerRuntime, anyhow::Error> {
        let mut guard = self.lock().await;
        ensure_runtime(&mut guard)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    current: Option<String>,
    last_invalid: Option<String>,
}

impl RequestContext {
    fn ensure(&mut self) -> String {
        match self.current.as_ref() {
            Some(id) => id.clone(),
            None => self.set_new(),
        }
    }

    fn set_new(&mut self) -> String {
        let next = Uuid::new_v4().to_string();
        self.set(next)
    }

    fn set(&mut self, value: String) -> String {
        self.current = Some(value.clone());
        self.last_invalid = None;
        value
    }

    fn update_from_headers(&mut self, headers: &HeaderMap) -> String {
        match request_id_from_headers(headers) {
            Ok(Some(valid)) => self.set(valid),
            Ok(None) => self.set_new(),
            Err(raw) => {
                if self.last_invalid.as_deref() != Some(raw.as_str()) {
                    warn!(
                        invalid_request_id = raw,
                        "received invalid request id header; generating a new one"
                    );
                    self.last_invalid = Some(raw);
                }
                self.set_new()
            }
        }
    }
}

pub fn new_state(
    cfg: config::AppConfig,
    client: reqwest::Client,
    runtime_factory: RuntimeFactory,
    runtime: Option<DynContainerRuntime>,
) -> SharedState {
    SharedState::new(cfg, client, runtime_factory, runtime)
}

pub async fn ensure_request_id(state: &SharedState) -> String {
    let mut guard = state.lock().await;
    guard.request_context.ensure()
}

pub async fn update_request_id_from_headers(state: &SharedState, headers: &HeaderMap) -> String {
    let mut guard = state.lock().await;
    guard.request_context.update_from_headers(headers)
}

pub async fn current_request_id(state: &SharedState) -> Option<String> {
    let guard = state.lock().await;
    guard.request_context.current.clone()
}

pub async fn set_request_id(state: &SharedState, value: String) {
    let mut guard = state.lock().await;
    guard.request_context.set(value);
}

pub async fn set_service_identities(
    state: &SharedState,
    identities: Vec<ServiceIdentityBundle>,
    fingerprint: Option<String>,
) {
    let mut guard = state.lock().await;
    guard.service_identities = identities;
    guard.service_identities_fingerprint = fingerprint;
}

pub async fn current_service_identities(state: &SharedState) -> Vec<ServiceIdentityBundle> {
    let guard = state.lock().await;
    guard.service_identities.clone()
}

pub async fn current_service_identities_fingerprint(state: &SharedState) -> Option<String> {
    let guard = state.lock().await;
    guard.service_identities_fingerprint.clone()
}

pub async fn set_tunnel_endpoint(state: &SharedState, endpoint: TunnelEndpoint) {
    let mut guard = state.lock().await;
    guard.tunnel = endpoint;
}

pub async fn current_tunnel_endpoint(state: &SharedState) -> TunnelEndpoint {
    let guard = state.lock().await;
    guard.tunnel.clone()
}

pub async fn update_tunnel_health(state: &SharedState, status: TunnelHealthStatus) {
    let mut guard = state.lock().await;
    guard.tunnel_health = status;
}

pub async fn current_tunnel_health(state: &SharedState) -> TunnelHealthStatus {
    let guard = state.lock().await;
    guard.tunnel_health.clone()
}

pub fn backoff_with_jitter(base: Duration, max: Duration, attempt: u32) -> Duration {
    let exp = 2u32.saturating_pow(attempt.saturating_sub(1));
    let mut backoff = base.saturating_mul(exp);
    if backoff > max {
        backoff = max;
    }
    let jitter_max = backoff.as_millis() / 2;
    let jitter_ms: u128 = rand::rng().random_range(0..=jitter_max.max(1));
    backoff + Duration::from_millis(jitter_ms as u64)
}

fn request_id_from_headers(headers: &HeaderMap) -> Result<Option<String>, String> {
    let mut invalid: Option<String> = None;

    if let Some(value) = headers.get(TRACEPARENT_HEADER) {
        match parse_traceparent_trace_id(value) {
            Some(trace_id) => return Ok(Some(trace_id)),
            None => {
                invalid = value
                    .to_str()
                    .ok()
                    .map(|s| format!("traceparent:{s}"))
                    .or_else(|| Some("traceparent:non_utf8".into()))
            }
        }
    }

    if let Some(value) = headers.get(REQUEST_ID_HEADER) {
        match normalize_request_id(value) {
            Ok(id) => return Ok(Some(id)),
            Err(raw) => invalid = Some(raw),
        }
    }

    if let Some(reason) = invalid {
        Err(reason)
    } else {
        Ok(None)
    }
}

fn parse_traceparent_trace_id(value: &HeaderValue) -> Option<String> {
    let raw = value.to_str().ok()?.trim();
    let mut parts = raw.splitn(4, '-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let _flags = parts.next()?;

    let valid_length = version.len() == 2 && trace_id.len() == 32 && span_id.len() == 16;
    let is_hex = trace_id.chars().all(|c| c.is_ascii_hexdigit());
    let non_zero = trace_id.chars().any(|c| c != '0');

    if valid_length && is_hex && non_zero {
        Some(trace_id.to_string())
    } else {
        None
    }
}

fn normalize_request_id(value: &HeaderValue) -> Result<String, String> {
    let raw = value
        .to_str()
        .map_err(|_| "x-request-id:non_utf8".to_string())?
        .trim();

    if raw.is_empty() {
        return Err("x-request-id:empty".into());
    }

    if raw.len() > 128 {
        return Err("x-request-id:too_long".into());
    }

    if !raw.chars().all(|c| c.is_ascii_graphic()) {
        return Err("x-request-id:invalid_chars".into());
    }

    Ok(raw.to_string())
}

fn tunnel_from_cfg(cfg: &config::AppConfig) -> TunnelEndpoint {
    let tunnel = &cfg.tunnel;
    TunnelEndpoint {
        host: tunnel.endpoint_host.clone(),
        port: tunnel.endpoint_port,
        use_tls: tunnel.use_tls,
        connect_timeout_secs: tunnel.connect_timeout_secs,
        heartbeat_interval_secs: tunnel.heartbeat_interval_secs,
        heartbeat_timeout_secs: tunnel.heartbeat_timeout_secs,
        token_header: tunnel.token_header.clone(),
    }
}

pub fn restart_backoff_duration(cfg: &config::AppConfig, attempt: u32) -> Duration {
    let base = Duration::from_millis(cfg.restart_backoff_ms.max(1));
    let max = Duration::from_millis(cfg.restart_backoff_max_ms.max(cfg.restart_backoff_ms));
    backoff_with_jitter(base, max, attempt.max(1))
}

pub fn runtime_reconnect_backoff(cfg: &config::AppConfig, attempt: u32) -> Duration {
    let base = Duration::from_millis(cfg.docker_reconnect_backoff_ms.max(1));
    let max = Duration::from_millis(
        cfg.docker_reconnect_backoff_max_ms
            .max(cfg.docker_reconnect_backoff_ms),
    );
    backoff_with_jitter(base, max, attempt.max(1))
}

pub async fn load_managed_entry(
    state: &SharedState,
    key: ReplicaKey,
    generation: i64,
) -> ManagedDeployment {
    let store = state.managed_read().await;
    let mut entry = store
        .managed
        .get(&key)
        .cloned()
        .unwrap_or_else(|| ManagedDeployment::new(generation));
    entry.reset_for_generation(generation);
    entry
}

pub async fn save_managed_entry(
    state: &SharedState,
    key: ReplicaKey,
    mut managed: ManagedDeployment,
) {
    managed.last_updated = Utc::now();
    let mut store = state.managed_write().await;
    store.managed.insert(key, managed);
}

pub fn backoff_remaining(managed: &ManagedDeployment) -> Option<chrono::Duration> {
    managed.backoff_until.and_then(|until| {
        let now = Utc::now();
        if until > now {
            Some(until - now)
        } else {
            None
        }
    })
}

pub fn apply_failure_backoff(
    cfg: &config::AppConfig,
    managed: &mut ManagedDeployment,
    container_id: Option<String>,
    message: Option<String>,
) {
    managed.consecutive_failures = managed.consecutive_failures.saturating_add(1);
    let backoff = restart_backoff_duration(cfg, managed.consecutive_failures);
    let backoff_until = Utc::now()
        + chrono::Duration::from_std(backoff).unwrap_or_else(|_| chrono::Duration::seconds(1));
    managed.backoff_until = Some(backoff_until);
    managed.mark_state(container_id, InstanceState::Failed, message);
}

pub async fn record_runtime_error(state: &SharedState, err: &ContainerRuntimeError) {
    if !err.is_connection_error() {
        telemetry::record_runtime_error_metric("other");
        return;
    }

    telemetry::record_runtime_error_metric("connection");
    let mut guard = state.lock().await;
    let attempt = guard.runtime_backoff_attempts.saturating_add(1);
    let backoff = runtime_reconnect_backoff(&guard.cfg, attempt);

    guard.runtime = None;
    guard.runtime_backoff_attempts = attempt;
    guard.runtime_backoff_until = Some(Instant::now() + backoff);
    guard.needs_adoption = true;

    warn!(
        attempt,
        backoff_ms = backoff.as_millis(),
        error = %err,
        "docker runtime error; scheduling reconnect with backoff"
    );
}

pub fn ensure_runtime(state: &mut AppState) -> Result<DynContainerRuntime, anyhow::Error> {
    if let Some(rt) = &state.runtime {
        return Ok(rt.clone());
    }

    if let Some(until) = state.runtime_backoff_until {
        if until > Instant::now() {
            anyhow::bail!("docker reconnect backoff in effect");
        }
    }

    let attempt = state.runtime_backoff_attempts.saturating_add(1);
    match state.runtime_factory.as_ref()() {
        Ok(rt) => {
            state.runtime = Some(rt.clone());
            state.runtime_backoff_attempts = 0;
            state.runtime_backoff_until = None;
            state.needs_adoption = true;
            Ok(rt)
        }
        Err(err) => {
            let backoff = runtime_reconnect_backoff(&state.cfg, attempt);
            state.runtime_backoff_attempts = attempt;
            state.runtime_backoff_until = Some(Instant::now() + backoff);
            telemetry::record_runtime_error_metric("connection");
            warn!(
                attempt,
                backoff_ms = backoff.as_millis(),
                error = %err,
                "failed to connect to docker"
            );
            Err(err).context("connect to docker runtime")
        }
    }
}

pub fn collect_instance_statuses(store: &ManagedStore) -> Vec<InstanceStatus> {
    store
        .managed
        .iter()
        .map(|(key, managed)| base_instance_status(key, managed))
        .collect()
}

fn base_instance_status(key: &ReplicaKey, managed: &ManagedDeployment) -> InstanceStatus {
    // Unknown is surfaced to the control-plane as "pending" so operators can
    // distinguish between not-yet-started and failed replicas.
    let state = match managed.state {
        InstanceState::Unknown => InstanceState::Pending,
        other => other,
    };

    InstanceStatus {
        deployment_id: key.deployment_id,
        replica_number: key.replica_number,
        container_id: managed.container_id.clone(),
        state,
        message: managed.message.clone(),
        restart_count: managed.restart_count,
        generation: managed.generation,
        last_updated: managed.last_updated,
        endpoints: managed.endpoints.clone(),
        health: managed.health.clone(),
        metrics: Vec::new(),
    }
}

#[derive(Debug, Default, Clone)]
pub struct MetricsAggregation {
    pub instances: Vec<InstanceStatus>,
    pub dropped_invalid: usize,
    pub dropped_overflow: usize,
}

pub fn collect_instance_statuses_with_metrics(
    store: &ManagedStore,
    max_metrics: usize,
) -> MetricsAggregation {
    let mut aggregation = MetricsAggregation::default();

    for (key, managed) in &store.managed {
        let mut status = base_instance_status(key, managed);
        if let Some(samples) = store.resource_samples.get(key) {
            for sample in samples {
                match resource_sample_from_usage(sample) {
                    Some(metric) => status.metrics.push(metric),
                    None => {
                        aggregation.dropped_invalid = aggregation.dropped_invalid.saturating_add(1)
                    }
                }
            }
        }
        aggregation.instances.push(status);
    }

    let total_metrics: usize = aggregation
        .instances
        .iter()
        .map(|inst| inst.metrics.len())
        .sum();

    if total_metrics == 0 {
        return aggregation;
    }

    if max_metrics == 0 {
        aggregation.dropped_overflow = total_metrics;
        for inst in &mut aggregation.instances {
            inst.metrics.clear();
        }
        return aggregation;
    }

    if total_metrics > max_metrics {
        let overflow = total_metrics - max_metrics;
        aggregation.dropped_overflow = overflow;

        let mut drop_counts = vec![0usize; aggregation.instances.len()];
        let mut all_samples = Vec::with_capacity(total_metrics);

        for (idx, inst) in aggregation.instances.iter().enumerate() {
            for metric in &inst.metrics {
                all_samples.push((metric.collected_at, idx));
            }
        }

        all_samples.sort_by_key(|(ts, _)| *ts);

        for (_, idx) in all_samples.into_iter().take(overflow) {
            drop_counts[idx] = drop_counts[idx].saturating_add(1);
        }

        for (inst, drops) in aggregation.instances.iter_mut().zip(drop_counts) {
            if drops > 0 {
                let drop_n = drops.min(inst.metrics.len());
                inst.metrics.drain(0..drop_n);
            }
        }
    }

    aggregation
}

fn resource_sample_from_usage(sample: &ContainerResourceUsage) -> Option<ResourceMetricSample> {
    if !sample.cpu_percent.is_finite() {
        return None;
    }

    Some(ResourceMetricSample {
        collected_at: sample.collected_at,
        cpu_percent: sample.cpu_percent,
        memory_bytes: sample.memory_bytes,
        network_rx_bytes: sample.network_rx_bytes,
        network_tx_bytes: sample.network_tx_bytes,
        blk_read_bytes: sample.blk_read_bytes,
        blk_write_bytes: sample.blk_write_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::DynContainerRuntime;
    use crate::test_support::base_config;
    use chrono::TimeZone;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn managed_deployment_resets_on_new_generation() {
        let mut deployment = ManagedDeployment::new(1);
        deployment.state = InstanceState::Failed;
        deployment.message = Some("oops".into());
        deployment.endpoints.push("http://example".into());
        deployment.ports = Some(Vec::new());
        deployment.liveness_probe_state.consecutive_failures = 2;
        deployment.failed_probe = Some(ProbeRole::Liveness);

        deployment.reset_for_generation(2);

        assert_eq!(deployment.generation, 2);
        assert_eq!(deployment.state, InstanceState::Failed);
        assert!(deployment.message.is_none());
        assert!(deployment.endpoints.is_empty());
        assert!(deployment.ports.is_none());
        assert!(deployment.failed_probe.is_none());
        assert_eq!(deployment.liveness_probe_state.consecutive_failures, 0);
    }

    #[test]
    fn mark_state_updates_last_started_at() {
        let mut deployment = ManagedDeployment::new(1);
        deployment.mark_state(Some("c1".into()), InstanceState::Running, None);
        assert!(deployment.last_started_at.is_some());

        deployment.mark_state(
            Some("c1".into()),
            InstanceState::Failed,
            Some("boom".into()),
        );
        assert!(deployment.last_started_at.is_none());
        assert_eq!(deployment.message.as_deref(), Some("boom"));
    }

    #[test]
    fn mark_running_clears_failure_state() {
        let mut deployment = ManagedDeployment::new(1);
        deployment.consecutive_failures = 3;
        deployment.backoff_until = Some(Utc::now());
        deployment.failed_probe = Some(ProbeRole::Readiness);
        deployment.mark_running(Some("c2".into()));

        assert_eq!(deployment.consecutive_failures, 0);
        assert!(deployment.backoff_until.is_none());
        assert!(deployment.failed_probe.is_none());
        assert_eq!(deployment.state, InstanceState::Running);
    }

    #[test]
    fn apply_failure_backoff_sets_failed_state() {
        let cfg = base_config();
        let mut deployment = ManagedDeployment::new(1);
        apply_failure_backoff(
            &cfg,
            &mut deployment,
            Some("c3".into()),
            Some("fail".into()),
        );

        assert_eq!(deployment.state, InstanceState::Failed);
        assert!(deployment.backoff_until.is_some());
        assert_eq!(deployment.message.as_deref(), Some("fail"));
    }

    #[test]
    fn backoff_remaining_handles_past_and_future() {
        let mut deployment = ManagedDeployment::new(1);
        deployment.backoff_until = Some(Utc::now() - chrono::Duration::seconds(5));
        assert!(backoff_remaining(&deployment).is_none());

        deployment.backoff_until = Some(Utc::now() + chrono::Duration::seconds(5));
        assert!(backoff_remaining(&deployment).is_some());
    }

    #[tokio::test]
    async fn record_runtime_error_updates_state_on_connection_error() {
        let runtime: DynContainerRuntime = Arc::new(crate::test_support::MockRuntime::default());
        let runtime_for_factory = runtime.clone();
        let cfg = base_config();
        let client = reqwest::Client::new();
        let factory: RuntimeFactory = Arc::new(move || Ok(runtime_for_factory.clone()));
        let state = new_state(cfg, client, factory, Some(runtime.clone()));

        let err = ContainerRuntimeError::Connection {
            context: "test",
            source: anyhow::anyhow!("down"),
        };
        record_runtime_error(&state, &err).await;

        let guard = state.lock().await;
        assert!(guard.runtime.is_none());
        assert_eq!(guard.runtime_backoff_attempts, 1);
        assert!(guard.runtime_backoff_until.is_some());
        assert!(guard.needs_adoption);
    }

    #[tokio::test]
    async fn record_runtime_error_skips_non_connection_errors() {
        let runtime: DynContainerRuntime = Arc::new(crate::test_support::MockRuntime::default());
        let runtime_for_factory = runtime.clone();
        let cfg = base_config();
        let client = reqwest::Client::new();
        let factory: RuntimeFactory = Arc::new(move || Ok(runtime_for_factory.clone()));
        let state = new_state(cfg, client, factory, Some(runtime.clone()));

        let err = ContainerRuntimeError::StartContainer {
            id: "id-1".into(),
            source: anyhow::anyhow!("boom"),
        };
        record_runtime_error(&state, &err).await;

        let guard = state.lock().await;
        assert!(guard.runtime.is_some());
        assert_eq!(guard.runtime_backoff_attempts, 0);
    }

    #[test]
    fn request_context_updates_from_headers() {
        let mut ctx = RequestContext::default();
        let first = ctx.ensure();
        assert!(!first.is_empty());
        assert_eq!(ctx.ensure(), first);

        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("req-123"));
        let updated = ctx.update_from_headers(&headers);
        assert_eq!(updated, "req-123");
        assert_eq!(ctx.current.as_deref(), Some("req-123"));
    }

    #[test]
    fn request_id_from_headers_prefers_traceparent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            TRACEPARENT_HEADER,
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("req-1"));

        let id = request_id_from_headers(&headers).expect("ok");
        assert_eq!(id, Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()));
    }

    #[test]
    fn request_id_from_headers_falls_back_to_request_id() {
        let mut headers = HeaderMap::new();
        headers.insert(TRACEPARENT_HEADER, HeaderValue::from_static("bad-trace"));
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("req-2"));

        let id = request_id_from_headers(&headers).expect("ok");
        assert_eq!(id, Some("req-2".to_string()));
    }

    #[test]
    fn request_id_from_headers_reports_invalid_request_id() {
        let mut headers = HeaderMap::new();
        let too_long = "a".repeat(129);
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_str(&too_long).unwrap());

        let err = request_id_from_headers(&headers).expect_err("invalid");
        assert_eq!(err, "x-request-id:too_long");
    }

    #[test]
    fn normalize_request_id_rejects_invalid_chars() {
        let value = HeaderValue::from_static("hello world");
        let err = normalize_request_id(&value).expect_err("invalid");
        assert_eq!(err, "x-request-id:invalid_chars");
    }

    #[test]
    fn parse_traceparent_rejects_all_zero_trace_id() {
        let value =
            HeaderValue::from_static("00-00000000000000000000000000000000-0000000000000000-01");
        assert!(parse_traceparent_trace_id(&value).is_none());
    }

    #[test]
    fn backoff_with_jitter_stays_within_bounds() {
        let base = Duration::from_millis(100);
        let max = Duration::from_millis(400);
        let backoff = backoff_with_jitter(base, max, 2);
        let expected = base * 2;
        let jitter_max = expected / 2;
        assert!(backoff >= expected);
        assert!(backoff <= expected + jitter_max);
    }

    #[tokio::test]
    async fn reconnects_to_docker_after_errors() {
        let runtime: DynContainerRuntime = Arc::new(crate::test_support::MockRuntime::default());
        let attempts = Arc::new(AtomicUsize::new(0));
        let runtime_for_factory = runtime.clone();
        let factory: RuntimeFactory = {
            let attempts = attempts.clone();
            Arc::new(move || {
                let count = attempts.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    Err(ContainerRuntimeError::Connection {
                        context: "factory",
                        source: anyhow::anyhow!("down"),
                    })
                } else {
                    Ok(runtime_for_factory.clone())
                }
            })
        };

        let cfg = base_config();
        let client = reqwest::Client::new();
        let state = new_state(cfg, client, factory, None);

        {
            let mut guard = state.lock().await;
            let res = ensure_runtime(&mut guard);
            assert!(res.is_err(), "first connect should fail");
            assert!(guard.runtime.is_none());
            assert!(guard.runtime_backoff_attempts >= 1);
            assert!(guard.runtime_backoff_until.is_some());
            guard.runtime_backoff_until = Some(Instant::now());
        }

        {
            let mut guard = state.lock().await;
            let res = ensure_runtime(&mut guard);
            assert!(res.is_ok(), "should reconnect on subsequent attempt");
            assert!(guard.runtime.is_some());
            assert_eq!(guard.runtime_backoff_attempts, 0);
            assert!(guard.runtime_backoff_until.is_none());
            assert!(guard.needs_adoption);
        }

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn downsample_metrics_globally() {
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        let mut managed = HashMap::new();
        let mut deployment = ManagedDeployment::new(1);
        deployment.mark_running(Some("c1".into()));
        managed.insert(key, deployment);

        let mut samples = HashMap::new();
        let mut queue = VecDeque::new();
        queue.push_back(sample_usage(1.0, 0));
        queue.push_back(sample_usage(2.0, 1));
        samples.insert(key, queue);

        let store = ManagedStore {
            managed,
            resource_samples: samples,
        };

        let agg = collect_instance_statuses_with_metrics(&store, 1);

        assert_eq!(agg.dropped_overflow, 1);
        let metrics = &agg.instances[0].metrics;
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cpu_percent, 2.0);
    }

    #[test]
    fn invalid_metrics_are_filtered() {
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        let mut managed = HashMap::new();
        let mut deployment = ManagedDeployment::new(1);
        deployment.mark_running(Some("c2".into()));
        managed.insert(key, deployment);

        let mut samples = HashMap::new();
        let mut queue = VecDeque::new();
        queue.push_back(ContainerResourceUsage {
            collected_at: Utc.timestamp_opt(0, 0).single().unwrap(),
            cpu_percent: f64::NAN,
            memory_bytes: 128,
            network_rx_bytes: 1,
            network_tx_bytes: 2,
            blk_read_bytes: None,
            blk_write_bytes: None,
        });
        queue.push_back(sample_usage(3.0, 1));
        samples.insert(key, queue);

        let store = ManagedStore {
            managed,
            resource_samples: samples,
        };

        let agg = collect_instance_statuses_with_metrics(&store, 10);

        assert_eq!(agg.dropped_invalid, 1);
        assert_eq!(agg.dropped_overflow, 0);
        assert_eq!(agg.instances[0].metrics.len(), 1);
        assert_eq!(agg.instances[0].metrics[0].cpu_percent, 3.0);
    }

    #[test]
    fn downsampling_prefers_newest_across_replicas() {
        let key_a = ReplicaKey::new(Uuid::new_v4(), 0);
        let key_b = ReplicaKey::new(Uuid::new_v4(), 1);

        let mut managed = HashMap::new();
        let mut dep_a = ManagedDeployment::new(1);
        dep_a.mark_running(Some("cA".into()));
        let mut dep_b = ManagedDeployment::new(1);
        dep_b.mark_running(Some("cB".into()));
        managed.insert(key_a, dep_a);
        managed.insert(key_b, dep_b);

        let mut samples = HashMap::new();
        let mut queue_a = VecDeque::new();
        queue_a.push_back(sample_usage(1.0, 0));
        queue_a.push_back(sample_usage(3.0, 2));
        samples.insert(key_a, queue_a);

        let mut queue_b = VecDeque::new();
        queue_b.push_back(sample_usage(2.0, 1));
        samples.insert(key_b, queue_b);

        let store = ManagedStore {
            managed,
            resource_samples: samples,
        };

        let agg = collect_instance_statuses_with_metrics(&store, 2);

        assert_eq!(agg.dropped_overflow, 1);
        let metrics_a = &agg
            .instances
            .iter()
            .find(|inst| inst.deployment_id == key_a.deployment_id)
            .unwrap()
            .metrics;
        let metrics_b = &agg
            .instances
            .iter()
            .find(|inst| inst.deployment_id == key_b.deployment_id)
            .unwrap()
            .metrics;

        assert_eq!(metrics_a.len(), 1);
        assert_eq!(metrics_a[0].cpu_percent, 3.0);
        assert_eq!(metrics_b.len(), 1);
        assert_eq!(metrics_b[0].cpu_percent, 2.0);
    }

    fn sample_usage(cpu: f64, seconds: i64) -> ContainerResourceUsage {
        ContainerResourceUsage {
            collected_at: Utc.timestamp_opt(seconds, 0).single().unwrap(),
            cpu_percent: cpu,
            memory_bytes: 256,
            network_rx_bytes: 10,
            network_tx_bytes: 20,
            blk_read_bytes: Some(5),
            blk_write_bytes: Some(7),
        }
    }
}
