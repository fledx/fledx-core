use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::Client;
use tokio::{net::TcpStream, sync::watch, time};
use tracing::warn;

use crate::api::{DeploymentHealth, HealthProbe, HealthProbeKind, PortMapping};
use crate::config::AppConfig;
use crate::runtime::DynContainerRuntime;
use crate::state::{self, ProbeRole, ProbeState, ReplicaKey, SharedState};

const HEALTH_LOOP_INTERVAL_SECS: u64 = 1;
const DEFAULT_PROBE_INTERVAL_SECS: u64 = 10;
const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 1;
const DEFAULT_FAILURE_THRESHOLD: u32 = 3;
const DEFAULT_START_PERIOD_SECS: u64 = 0;

pub(crate) struct HealthCheckWork {
    pub(crate) key: ReplicaKey,
    pub(crate) container_id: String,
    pub(crate) health_config: DeploymentHealth,
    pub(crate) ports: Option<Vec<PortMapping>>,
    pub(crate) liveness_state: ProbeState,
    pub(crate) readiness_state: ProbeState,
    pub(crate) last_started_at: Option<DateTime<Utc>>,
    pub(crate) failed_probe: Option<ProbeRole>,
    pub(crate) failure_reason: Option<String>,
}

struct ProbeExecutionContext<'a> {
    cfg: &'a AppConfig,
    ports: Option<Vec<PortMapping>>,
    runtime: Option<DynContainerRuntime>,
    http_client: &'a Client,
    container_id: String,
    last_started_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
}

struct ProbeExecutionOutcome {
    success: bool,
    message: String,
    error: Option<String>,
    threshold_just_reached: bool,
}

pub async fn health_loop(state: SharedState, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let client = Client::new();
    let mut interval = time::interval(Duration::from_secs(HEALTH_LOOP_INTERVAL_SECS));

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                if let Err(err) = crate::services::health::health_tick(&state, &client).await {
                    warn!(?err, "health loop iteration failed");
                }
            }
        }
    }

    Ok(())
}

pub async fn health_tick(state: &SharedState, http_client: &Client) -> Result<()> {
    crate::services::health::health_tick(state, http_client).await
}

pub(crate) fn uses_exec_probe(health: &DeploymentHealth) -> bool {
    health
        .liveness
        .as_ref()
        .map(|probe| matches!(probe.kind, HealthProbeKind::Exec { .. }))
        .unwrap_or(false)
        || health
            .readiness
            .as_ref()
            .map(|probe| matches!(probe.kind, HealthProbeKind::Exec { .. }))
            .unwrap_or(false)
}

pub(crate) async fn run_health_for_work(
    cfg: &AppConfig,
    runtime: Option<DynContainerRuntime>,
    work: &mut HealthCheckWork,
    http_client: &Client,
    now: DateTime<Utc>,
) -> Result<()> {
    let ctx = ProbeExecutionContext {
        cfg,
        ports: work.ports.clone(),
        runtime,
        http_client,
        container_id: work.container_id.clone(),
        last_started_at: work.last_started_at,
        now,
    };

    if let Some(probe) = work.health_config.liveness.as_ref() {
        if let Some(outcome) =
            maybe_run_probe(&mut work.liveness_state, probe, ProbeRole::Liveness, &ctx).await?
        {
            if outcome.threshold_just_reached {
                work.failed_probe = Some(ProbeRole::Liveness);
                work.failure_reason = Some(role_failure_reason(ProbeRole::Liveness, &outcome));
            }
        }
    }

    if let Some(probe) = work.health_config.readiness.as_ref() {
        if let Some(outcome) =
            maybe_run_probe(&mut work.readiness_state, probe, ProbeRole::Readiness, &ctx).await?
        {
            if outcome.threshold_just_reached && work.failed_probe.is_none() {
                work.failed_probe = Some(ProbeRole::Readiness);
                work.failure_reason = Some(role_failure_reason(ProbeRole::Readiness, &outcome));
            }
        }
    }

    Ok(())
}

fn role_failure_reason(role: ProbeRole, outcome: &ProbeExecutionOutcome) -> String {
    let detail = outcome
        .error
        .clone()
        .unwrap_or_else(|| outcome.message.clone());
    format!("{} probe threshold reached: {}", role_name(role), detail)
}

async fn maybe_run_probe(
    state: &mut ProbeState,
    probe: &HealthProbe,
    role: ProbeRole,
    ctx: &ProbeExecutionContext<'_>,
) -> Result<Option<ProbeExecutionOutcome>> {
    let interval = Duration::from_secs(
        probe
            .interval_seconds
            .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS),
    );
    let timeout = Duration::from_secs(probe.timeout_seconds.unwrap_or(DEFAULT_PROBE_TIMEOUT_SECS));
    let failure_threshold = probe.failure_threshold.unwrap_or(DEFAULT_FAILURE_THRESHOLD);
    let start_period = Duration::from_secs(
        probe
            .start_period_seconds
            .unwrap_or(DEFAULT_START_PERIOD_SECS),
    );

    if !should_run_probe(state, ctx.last_started_at, start_period, ctx.now) {
        return Ok(None);
    }

    let mut outcome = match &probe.kind {
        HealthProbeKind::Http { port, path } => {
            run_http_probe(ctx.http_client, ctx.cfg, *port, path, timeout, &ctx.ports).await
        }
        HealthProbeKind::Tcp { port } => run_tcp_probe(ctx.cfg, *port, timeout, &ctx.ports).await,
        HealthProbeKind::Exec { command } => {
            run_exec_probe(
                ctx.runtime.clone(),
                ctx.container_id.as_str(),
                command,
                timeout,
            )
            .await
        }
    };

    state.last_checked_at = Some(ctx.now);
    state.next_run_at = Some(ctx.now + chrono_duration_from(interval));
    apply_probe_outcome(state, &mut outcome, failure_threshold, role);

    Ok(Some(outcome))
}

fn apply_probe_outcome(
    state: &mut ProbeState,
    outcome: &mut ProbeExecutionOutcome,
    failure_threshold: u32,
    role: ProbeRole,
) {
    state.last_probe_result = Some(outcome.message.clone());
    if outcome.success {
        state.consecutive_failures = 0;
        state.healthy = Some(true);
        state.reason = None;
        state.last_error = None;
        outcome.threshold_just_reached = false;
        return;
    }

    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    state.last_error = outcome.error.clone();
    let threshold_reached = state.consecutive_failures >= failure_threshold;
    state.healthy = Some(!threshold_reached);
    if threshold_reached {
        state.reason = Some(format!(
            "{} probe failed {} consecutive time{}",
            role_name(role),
            state.consecutive_failures,
            if state.consecutive_failures == 1 {
                ""
            } else {
                "s"
            }
        ));
    } else {
        state.reason = None;
    }
    outcome.threshold_just_reached = state.consecutive_failures == failure_threshold;
}

async fn run_http_probe(
    client: &Client,
    cfg: &AppConfig,
    port: u16,
    path: &str,
    timeout: Duration,
    ports: &Option<Vec<PortMapping>>,
) -> ProbeExecutionOutcome {
    let (host, host_port) = match resolve_host_port(port, ports, cfg) {
        Some(binding) => binding,
        None => {
            return ProbeExecutionOutcome {
                success: false,
                message: format!("http probe port {port} not mapped"),
                error: Some("port not mapped".into()),
                threshold_just_reached: false,
            }
        }
    };

    let normalized_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let url = format!("http://{host}:{host_port}{normalized_path}");

    match time::timeout(timeout, client.get(&url).send()).await {
        Ok(Ok(resp)) => {
            let status = resp.status();
            let message = format!("http {}", status);
            if status.is_success() {
                ProbeExecutionOutcome {
                    success: true,
                    message,
                    error: None,
                    threshold_just_reached: false,
                }
            } else {
                ProbeExecutionOutcome {
                    success: false,
                    message: message.clone(),
                    error: Some(format!("status {}", status.as_u16())),
                    threshold_just_reached: false,
                }
            }
        }
        Ok(Err(err)) => ProbeExecutionOutcome {
            success: false,
            message: "http request failed".into(),
            error: Some(err.to_string()),
            threshold_just_reached: false,
        },
        Err(_) => ProbeExecutionOutcome {
            success: false,
            message: "http request timed out".into(),
            error: Some(format!("timed out after {:?}", timeout)),
            threshold_just_reached: false,
        },
    }
}

async fn run_tcp_probe(
    cfg: &AppConfig,
    port: u16,
    timeout: Duration,
    ports: &Option<Vec<PortMapping>>,
) -> ProbeExecutionOutcome {
    let (host, host_port) = match resolve_host_port(port, ports, cfg) {
        Some(binding) => binding,
        None => {
            return ProbeExecutionOutcome {
                success: false,
                message: format!("tcp probe port {port} not mapped"),
                error: Some("port not mapped".into()),
                threshold_just_reached: false,
            }
        }
    };

    match time::timeout(timeout, TcpStream::connect((&host[..], host_port))).await {
        Ok(Ok(_)) => ProbeExecutionOutcome {
            success: true,
            message: format!("tcp {}:{} succeeded", host, host_port),
            error: None,
            threshold_just_reached: false,
        },
        Ok(Err(err)) => ProbeExecutionOutcome {
            success: false,
            message: "tcp connection failed".into(),
            error: Some(err.to_string()),
            threshold_just_reached: false,
        },
        Err(_) => ProbeExecutionOutcome {
            success: false,
            message: "tcp connection timed out".into(),
            error: Some(format!("timed out after {:?}", timeout)),
            threshold_just_reached: false,
        },
    }
}

async fn run_exec_probe(
    runtime: Option<DynContainerRuntime>,
    container_id: &str,
    command: &[String],
    timeout: Duration,
) -> ProbeExecutionOutcome {
    let runtime = match runtime {
        Some(runtime) => runtime,
        None => {
            return ProbeExecutionOutcome {
                success: false,
                message: "exec runtime unavailable".into(),
                error: Some("docker runtime unavailable".into()),
                threshold_just_reached: false,
            }
        }
    };

    match time::timeout(timeout, runtime.exec_command(container_id, command)).await {
        Ok(Ok(result)) => {
            let success = result.exit_code == 0;
            ProbeExecutionOutcome {
                success,
                message: format!("exec exitcode {}", result.exit_code),
                error: if success { None } else { Some(result.output) },
                threshold_just_reached: false,
            }
        }
        Ok(Err(err)) => ProbeExecutionOutcome {
            success: false,
            message: "exec failed".into(),
            error: Some(err.to_string()),
            threshold_just_reached: false,
        },
        Err(_) => ProbeExecutionOutcome {
            success: false,
            message: "exec timed out".into(),
            error: Some(format!("timed out after {:?}", timeout)),
            threshold_just_reached: false,
        },
    }
}

fn resolve_host_port(
    container_port: u16,
    ports: &Option<Vec<PortMapping>>,
    cfg: &AppConfig,
) -> Option<(String, u16)> {
    let ports = ports.as_ref()?;
    let mapping = ports
        .iter()
        .find(|mapping| mapping.container_port == container_port)?;
    let host_port = mapping.host_port.unwrap_or(mapping.container_port);
    let host = mapping
        .host_ip
        .as_deref()
        .and_then(trimmed_non_empty)
        .or_else(|| cfg.public_host.as_deref().and_then(trimmed_non_empty))
        .or_else(|| cfg.public_ip.as_deref().and_then(trimmed_non_empty))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    Some((host, host_port))
}

fn trimmed_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn should_run_probe(
    state: &ProbeState,
    last_started_at: Option<DateTime<Utc>>,
    start_period: Duration,
    now: DateTime<Utc>,
) -> bool {
    if let Some(start) = last_started_at {
        let ready_after = start + chrono_duration_from(start_period);
        if now < ready_after {
            return false;
        }
    }

    if let Some(next_run) = state.next_run_at {
        if now < next_run {
            return false;
        }
    }

    true
}

fn chrono_duration_from(duration: Duration) -> ChronoDuration {
    ChronoDuration::from_std(duration).unwrap_or_else(|_| ChronoDuration::seconds(0))
}

fn role_name(role: ProbeRole) -> &'static str {
    match role {
        ProbeRole::Liveness => "liveness",
        ProbeRole::Readiness => "readiness",
    }
}

fn aggregate_health_status(
    liveness: &ProbeState,
    readiness: &ProbeState,
) -> Option<crate::api::HealthStatus> {
    let choice = match (liveness.last_checked_at, readiness.last_checked_at) {
        (Some(l), Some(r)) => {
            if l >= r {
                (liveness, Some(ProbeRole::Liveness))
            } else {
                (readiness, Some(ProbeRole::Readiness))
            }
        }
        (Some(_), None) => (liveness, Some(ProbeRole::Liveness)),
        (None, Some(_)) => (readiness, Some(ProbeRole::Readiness)),
        (None, None) => return None,
    };

    let (state, _) = choice;
    Some(crate::api::HealthStatus {
        healthy: state.healthy.unwrap_or(true),
        last_probe_result: state.last_probe_result.clone(),
        reason: state.reason.clone(),
        last_error: state.last_error.clone(),
        last_checked_at: state.last_checked_at,
    })
}

pub(crate) async fn apply_probe_results(
    state: &SharedState,
    work: HealthCheckWork,
    cfg: &AppConfig,
) {
    let mut store = state.managed_write().await;
    if let Some(entry) = store.managed.get_mut(&work.key) {
        entry.liveness_probe_state = work.liveness_state.clone();
        entry.readiness_probe_state = work.readiness_state.clone();
        entry.health =
            aggregate_health_status(&entry.liveness_probe_state, &entry.readiness_probe_state);
        entry.failed_probe = work.failed_probe;

        if let Some(ProbeRole::Liveness) = entry.failed_probe {
            entry.restart_count = entry.restart_count.saturating_add(1);
            state::apply_failure_backoff(
                cfg,
                entry,
                entry.container_id.clone(),
                work.failure_reason,
            );
        }
    }
}

pub(crate) async fn report_tunnel_health(
    state: &SharedState,
    healthy: bool,
    error: Option<String>,
) {
    state::update_tunnel_health(
        state,
        state::TunnelHealthStatus {
            healthy,
            last_checked_at: Some(Utc::now()),
            last_error: error,
        },
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{DeploymentHealth, HealthProbe, HealthProbeKind, InstanceState, PortMapping},
        state::{ManagedDeployment, ReplicaKey},
        test_support::{base_config, state_with_runtime_and_config, ExecAction, MockRuntime},
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use httpmock::{Method::GET, MockServer};
    use reqwest::Client;
    use uuid::Uuid;

    #[tokio::test]
    async fn http_liveness_probe_success_updates_health() {
        let server = MockServer::start();
        let path = "/healthz";
        let _mock = server.mock(|when, then| {
            when.method(GET).path(path);
            then.status(200);
        });

        let runtime: std::sync::Arc<MockRuntime> = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime.clone(), base_config());
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut store = state.managed_write().await;
            let mut entry = ManagedDeployment::new(1);
            entry.container_id = Some("container".into());
            entry.state = InstanceState::Running;
            entry.health_config = Some(DeploymentHealth {
                liveness: Some(HealthProbe {
                    kind: HealthProbeKind::Http {
                        port: 8080,
                        path: path.to_string(),
                    },
                    interval_seconds: Some(1),
                    timeout_seconds: Some(1),
                    failure_threshold: Some(1),
                    start_period_seconds: Some(0),
                }),
                readiness: None,
            });
            entry.ports = Some(vec![PortMapping {
                container_port: 8080,
                host_port: Some(server.port()),
                protocol: "tcp".into(),
                host_ip: Some("127.0.0.1".into()),
                expose: false,
                endpoint: None,
            }]);
            entry.last_started_at = Some(Utc::now() - ChronoDuration::seconds(5));
            store.managed.insert(key, entry);
        }

        health_tick(&state, &Client::new()).await.unwrap();

        let store = state.managed_read().await;
        let entry = store.managed.get(&key).expect("entry");
        let health = entry.health.as_ref().expect("health status");
        assert!(health.healthy);
        assert!(health.last_checked_at.is_some());
    }

    #[tokio::test]
    async fn liveness_failure_triggers_backoff() {
        let server = MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(GET).path("/healthz");
            then.status(500);
        });

        let runtime: std::sync::Arc<MockRuntime> = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime.clone(), base_config());
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut guard = state.managed_write().await;
            let mut entry = ManagedDeployment::new(1);
            entry.container_id = Some("container".into());
            entry.state = InstanceState::Running;
            entry.health_config = Some(DeploymentHealth {
                liveness: Some(HealthProbe {
                    kind: HealthProbeKind::Http {
                        port: 8080,
                        path: "/healthz".into(),
                    },
                    interval_seconds: Some(1),
                    timeout_seconds: Some(1),
                    failure_threshold: Some(1),
                    start_period_seconds: Some(0),
                }),
                readiness: None,
            });
            entry.ports = Some(vec![PortMapping {
                container_port: 8080,
                host_port: Some(server.port()),
                protocol: "tcp".into(),
                host_ip: Some("127.0.0.1".into()),
                expose: false,
                endpoint: None,
            }]);
            entry.last_started_at = Some(Utc::now() - ChronoDuration::seconds(1));
            guard.managed.insert(key, entry);
        }

        health_tick(&state, &Client::new()).await.unwrap();

        let guard = state.managed_read().await;
        let entry = guard.managed.get(&key).expect("entry");
        assert_eq!(entry.state, InstanceState::Failed);
        assert!(entry.backoff_until.is_some());
        assert_eq!(entry.failed_probe, Some(ProbeRole::Liveness));
        let health = entry.health.as_ref().expect("health status");
        assert!(!health.healthy);
    }

    #[tokio::test]
    async fn readiness_failure_does_not_restart() {
        let runtime: std::sync::Arc<MockRuntime> =
            std::sync::Arc::new(MockRuntime::with_exec_actions(vec![ExecAction::Ok {
                exit_code: 1,
                output: "fail".into(),
            }]));
        let state = state_with_runtime_and_config(runtime.clone(), base_config());
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut guard = state.managed_write().await;
            let mut entry = ManagedDeployment::new(1);
            entry.container_id = Some("container".into());
            entry.state = InstanceState::Running;
            entry.health_config = Some(DeploymentHealth {
                liveness: None,
                readiness: Some(HealthProbe {
                    kind: HealthProbeKind::Exec {
                        command: vec!["/bin/check".into()],
                    },
                    interval_seconds: Some(1),
                    timeout_seconds: Some(1),
                    failure_threshold: Some(1),
                    start_period_seconds: Some(0),
                }),
            });
            entry.last_started_at = Some(Utc::now() - ChronoDuration::seconds(1));
            guard.managed.insert(key, entry);
        }

        health_tick(&state, &Client::new()).await.unwrap();

        let guard = state.managed_read().await;
        let entry = guard.managed.get(&key).expect("entry");
        assert_eq!(entry.state, InstanceState::Running);
        assert!(entry.backoff_until.is_none());
        assert_eq!(entry.failed_probe, Some(ProbeRole::Readiness));
        assert_eq!(entry.restart_count, 0);
        let health = entry.health.as_ref().expect("health status");
        assert!(!health.healthy);
        assert_eq!(health.last_error.as_deref(), Some("fail"));
    }

    #[tokio::test]
    async fn http_liveness_probe_timeout_reports_error() {
        let server = MockServer::start();
        let path = "/healthz";
        let _mock = server.mock(|when, then| {
            when.method(GET).path(path);
            then.status(200).delay(Duration::from_secs(2));
        });

        let runtime: std::sync::Arc<MockRuntime> = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime.clone(), base_config());
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut guard = state.managed_write().await;
            let mut entry = ManagedDeployment::new(1);
            entry.container_id = Some("container".into());
            entry.state = InstanceState::Running;
            entry.health_config = Some(DeploymentHealth {
                liveness: Some(HealthProbe {
                    kind: HealthProbeKind::Http {
                        port: 8080,
                        path: path.to_string(),
                    },
                    interval_seconds: Some(1),
                    timeout_seconds: Some(1),
                    failure_threshold: Some(1),
                    start_period_seconds: Some(0),
                }),
                readiness: None,
            });
            entry.ports = Some(vec![PortMapping {
                container_port: 8080,
                host_port: Some(server.port()),
                protocol: "tcp".into(),
                host_ip: Some("127.0.0.1".into()),
                expose: false,
                endpoint: None,
            }]);
            entry.last_started_at = Some(Utc::now() - ChronoDuration::seconds(5));
            guard.managed.insert(key, entry);
        }

        health_tick(&state, &Client::new()).await.unwrap();

        let guard = state.managed_read().await;
        let entry = guard.managed.get(&key).expect("entry");
        assert_eq!(entry.state, InstanceState::Failed);
        assert_eq!(entry.failed_probe, Some(ProbeRole::Liveness));
        let health = entry.health.as_ref().expect("health status");
        assert!(!health.healthy);
        assert!(
            health
                .last_error
                .as_ref()
                .map(|err| err.contains("timed out after"))
                .unwrap_or(false),
            "unexpected last_error: {:?}",
            health.last_error
        );
    }

    #[tokio::test]
    async fn consecutive_liveness_failures_trigger_restart_backoff() {
        let server = MockServer::start();
        let path = "/healthz";
        let _mock = server.mock(|when, then| {
            when.method(GET).path(path);
            then.status(500);
        });

        let runtime: std::sync::Arc<MockRuntime> = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime.clone(), base_config());
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut guard = state.managed_write().await;
            let mut entry = ManagedDeployment::new(1);
            entry.container_id = Some("container".into());
            entry.state = InstanceState::Running;
            entry.health_config = Some(DeploymentHealth {
                liveness: Some(HealthProbe {
                    kind: HealthProbeKind::Http {
                        port: 8080,
                        path: path.to_string(),
                    },
                    interval_seconds: Some(0),
                    timeout_seconds: Some(1),
                    failure_threshold: Some(2),
                    start_period_seconds: Some(0),
                }),
                readiness: None,
            });
            entry.ports = Some(vec![PortMapping {
                container_port: 8080,
                host_port: Some(server.port()),
                protocol: "tcp".into(),
                host_ip: Some("127.0.0.1".into()),
                expose: false,
                endpoint: None,
            }]);
            entry.last_started_at = Some(Utc::now() - ChronoDuration::seconds(5));
            guard.managed.insert(key, entry);
        }

        health_tick(&state, &Client::new()).await.unwrap();

        {
            let guard = state.managed_read().await;
            let entry = guard.managed.get(&key).expect("entry");
            assert_eq!(entry.state, InstanceState::Running);
            assert!(entry.failed_probe.is_none());
            assert_eq!(entry.restart_count, 0);
            let health = entry.health.as_ref().expect("health status");
            assert!(health.healthy);
            assert_eq!(health.last_error.as_deref(), Some("status 500"));
        }

        health_tick(&state, &Client::new()).await.unwrap();

        let guard = state.managed_read().await;
        let entry = guard.managed.get(&key).expect("entry");
        assert_eq!(entry.state, InstanceState::Failed);
        assert_eq!(entry.failed_probe, Some(ProbeRole::Liveness));
        assert!(entry.backoff_until.is_some());
        assert_eq!(entry.restart_count, 1);
        let health = entry.health.as_ref().expect("health status");
        assert!(!health.healthy);
        assert_eq!(
            health.reason.as_deref(),
            Some("liveness probe failed 2 consecutive times")
        );
        assert_eq!(health.last_error.as_deref(), Some("status 500"));
    }
}
