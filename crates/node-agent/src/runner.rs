use std::{net::SocketAddr, sync::Arc};

use tokio::{sync::watch, task::JoinHandle};
use tracing::{error, info, warn};

use crate::{
    build_client, compat, config, configs,
    health::health_loop,
    heartbeat::heartbeat_loop,
    reconcile::reconcile_loop,
    runtime::{DockerRuntime, DynContainerRuntime},
    sampler::resource_sampler_loop,
    services,
    state::{self, ensure_runtime, RuntimeFactory},
    telemetry, validate_control_plane_url, version,
};

/// Controls optional behaviours when starting the agent programmatically.
#[derive(Clone, Debug)]
pub struct AgentOptions {
    /// Initialize a tracing subscriber before starting the agent.
    pub init_tracing: bool,
    /// Start the dedicated `/metrics` HTTP server.
    pub serve_metrics: bool,
    /// Reuse an existing Prometheus recorder instead of installing a new one.
    pub metrics_handle: Option<metrics_exporter_prometheus::PrometheusHandle>,
}

impl Default for AgentOptions {
    fn default() -> Self {
        Self {
            init_tracing: true,
            serve_metrics: true,
            metrics_handle: None,
        }
    }
}

/// Handle returned by [`start_agent`] to manage shutdown when embedded.
pub struct AgentHandle {
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    tasks: Vec<JoinHandle<()>>,
    state: state::SharedState,
    cleanup_on_shutdown: bool,
}

impl AgentHandle {
    /// Returns a cloneable receiver that fires when shutdown is requested.
    pub fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Request a graceful shutdown; idempotent.
    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Wait for all agent tasks to finish and perform optional cleanup.
    pub async fn await_termination(self) -> anyhow::Result<()> {
        for handle in self.tasks {
            if let Err(join_err) = handle.await {
                if join_err.is_panic() {
                    error!(?join_err, "agent task panicked during shutdown");
                    anyhow::bail!("agent task panicked");
                }
            }
        }

        if self.cleanup_on_shutdown {
            cleanup_managed_containers(&self.state).await;
        }

        Ok(())
    }

    /// Request shutdown and block until all tasks have stopped.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.request_shutdown();
        self.await_termination().await
    }
}

/// Start the node-agent using the provided configuration and options.
///
/// - When embedding the agent (e.g., inside `fledx-cp --standalone`), pass
///   `AgentOptions { init_tracing: false, serve_metrics: false, metrics_handle:
///   Some(existing_handle) }` to reuse the existing telemetry setup.
pub async fn start_agent(
    cfg: config::AppConfig,
    mut options: AgentOptions,
) -> anyhow::Result<AgentHandle> {
    if options.init_tracing {
        telemetry::init_tracing();
    }

    validate_control_plane_url(&cfg)?;

    let metrics_handle = match options.metrics_handle.take() {
        Some(handle) => telemetry::register_metrics_handle(handle),
        None => telemetry::init_metrics_recorder(),
    };
    let metrics_addr: SocketAddr = format!("{}:{}", cfg.metrics_host, cfg.metrics_port)
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid metrics bind address: {}", err))?;

    let client = build_client(&cfg)?;
    let runtime_factory: RuntimeFactory =
        Arc::new(|| DockerRuntime::connect().map(|rt| Arc::new(rt) as DynContainerRuntime));
    let runtime = match (runtime_factory.as_ref())() {
        Ok(rt) => Some(rt),
        Err(err) => {
            warn!(?err, "docker not available at startup, will retry");
            None
        }
    };
    let state = state::new_state(cfg, client, runtime_factory, runtime);

    if let Err(err) = compat::prime_control_plane_info(&state).await {
        warn!(
            ?err,
            "failed to prime control-plane compatibility; will rely on agent responses"
        );
    }

    {
        let guard = state.lock().await;
        info!(
            node_id = %guard.cfg.node_id,
            cp = %guard.cfg.control_plane_url,
            insecure_http = guard.cfg.allow_insecure_http,
            tls_skip_verify = guard.cfg.tls_insecure_skip_verify,
            version = version::VERSION,
            agent_version_header = version::VERSION,
            agent_build_header = version::GIT_SHA,
            git_sha = version::GIT_SHA,
            dirty = version::GIT_DIRTY,
            built_at = version::BUILD_TIMESTAMP,
            "node agent starting"
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    if options.serve_metrics {
        let metrics_handle = metrics_handle.clone();
        let mut shutdown = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let shutdown_fut = async move {
                if *shutdown.borrow() {
                    return;
                }
                let _ = shutdown.changed().await;
            };
            if let Err(err) =
                telemetry::serve_metrics_with_shutdown(metrics_handle, metrics_addr, shutdown_fut)
                    .await
            {
                error!(?err, "metrics server exited with error");
            }
        }));
    }

    let hb_state = state.clone();
    let heartbeat_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = heartbeat_loop(hb_state, heartbeat_shutdown).await {
            error!(?err, "heartbeat loop terminated with error");
        }
    }));

    let rc_state = state.clone();
    let shutdown_rx_reconcile = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = reconcile_loop(rc_state, shutdown_rx_reconcile).await {
            error!(?err, "reconcile loop terminated with error");
        }
    }));

    let configs_state = state.clone();
    let shutdown_rx_configs = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = configs::config_sync_loop(configs_state, shutdown_rx_configs).await {
            error!(?err, "config sync loop terminated with error");
        }
    }));

    let sampler_state = state.clone();
    let sampler_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = resource_sampler_loop(sampler_state, sampler_shutdown).await {
            error!(?err, "resource sampler loop terminated with error");
        }
    }));

    let health_state = state.clone();
    let health_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = health_loop(health_state, health_shutdown).await {
            error!(?err, "health loop terminated with error");
        }
    }));

    let gateway_state = state.clone();
    let gateway_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = services::gateway::gateway_loop(gateway_state, gateway_shutdown).await {
            error!(?err, "gateway loop terminated with error");
        }
    }));

    let tunnel_state = state.clone();
    let tunnel_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = services::tunnel::tunnel_loop(tunnel_state, tunnel_shutdown).await {
            error!(?err, "tunnel loop terminated with error");
        }
    }));

    let identities_state = state.clone();
    let client = reqwest::Client::new();
    let identities_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = services::identities::service_identity_loop(
            identities_state,
            identities_shutdown,
            client,
        )
        .await
        {
            error!(?err, "service identity loop terminated with error");
        }
    }));

    let cleanup_on_shutdown = {
        let guard = state.lock().await;
        guard.cfg.cleanup_on_shutdown
    };

    Ok(AgentHandle {
        shutdown_tx,
        shutdown_rx,
        tasks,
        state,
        cleanup_on_shutdown,
    })
}

/// Waits for Ctrl+C or SIGTERM.
pub async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => stream.recv().await,
            Err(err) => {
                error!(%err, "failed to install SIGTERM handler");
                None
            }
        };
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn cleanup_managed_containers(state: &state::SharedState) {
    let runtime = {
        let mut guard = state.lock().await;
        match ensure_runtime(&mut guard) {
            Ok(rt) => rt,
            Err(err) => {
                warn!(?err, "skipping cleanup; docker runtime unavailable");
                return;
            }
        }
    };

    match runtime.list_managed_containers().await {
        Ok(containers) => {
            if containers.is_empty() {
                return;
            }
            for container in containers {
                let id = container.id.clone();
                if let Err(err) = runtime.stop_container(&id).await {
                    warn!(?err, container_id = %id, "failed to stop container during cleanup");
                }
                if let Err(err) = runtime.remove_container(&id).await {
                    warn!(?err, container_id = %id, "failed to remove container during cleanup");
                }
            }
            info!("cleaned up managed containers on shutdown");
        }
        Err(err) => {
            warn!(?err, "failed to list managed containers for cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::ContainerRuntimeError;
    use crate::runtime::{ContainerDetails, ContainerStatus};
    use crate::test_support::{base_config, MockRuntime};
    use std::sync::Arc;
    use tokio::sync::watch;

    fn dummy_state() -> state::SharedState {
        let cfg = base_config();
        let client = reqwest::Client::new();
        let factory: RuntimeFactory = Arc::new(|| {
            Err(ContainerRuntimeError::Connection {
                context: "test",
                source: anyhow::anyhow!("down"),
            })
        });
        state::new_state(cfg, client, factory, None)
    }

    #[test]
    fn agent_options_defaults() {
        let opts = AgentOptions::default();
        assert!(opts.init_tracing);
        assert!(opts.serve_metrics);
        assert!(opts.metrics_handle.is_none());
    }

    #[tokio::test]
    async fn agent_handle_request_shutdown_sets_signal() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = AgentHandle {
            shutdown_tx,
            shutdown_rx,
            tasks: Vec::new(),
            state: dummy_state(),
            cleanup_on_shutdown: false,
        };

        handle.request_shutdown();
        assert!(*handle.shutdown_signal().borrow());
    }

    #[tokio::test]
    async fn agent_handle_reports_task_panics() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async {
            panic!("boom");
        });
        let handle = AgentHandle {
            shutdown_tx,
            shutdown_rx,
            tasks: vec![task],
            state: dummy_state(),
            cleanup_on_shutdown: false,
        };

        let err = handle.await_termination().await.expect_err("panic");
        assert!(err.to_string().contains("panicked"));
    }

    #[tokio::test]
    async fn cleanup_managed_containers_skips_when_runtime_unavailable() {
        let state = dummy_state();
        cleanup_managed_containers(&state).await;
    }

    #[tokio::test]
    async fn cleanup_managed_containers_noops_when_empty() {
        let mock = MockRuntime::default();
        let runtime: DynContainerRuntime = Arc::new(mock.clone());
        let cfg = base_config();
        let client = reqwest::Client::new();
        let factory: RuntimeFactory = Arc::new({
            let runtime = runtime.clone();
            move || Ok(runtime.clone())
        });
        let state = state::new_state(cfg, client, factory, Some(runtime));

        cleanup_managed_containers(&state).await;
        let guard = mock.containers.lock().expect("lock");
        assert!(guard.is_empty());
    }

    #[tokio::test]
    async fn cleanup_managed_containers_removes_existing() {
        let container = ContainerDetails {
            id: "container-1".to_string(),
            name: Some("container-1".to_string()),
            status: ContainerStatus::Running,
            labels: None,
        };
        let mock = MockRuntime::with_containers(vec![container]);
        let runtime: DynContainerRuntime = Arc::new(mock.clone());
        let cfg = base_config();
        let client = reqwest::Client::new();
        let factory: RuntimeFactory = Arc::new({
            let runtime = runtime.clone();
            move || Ok(runtime.clone())
        });
        let state = state::new_state(cfg, client, factory, Some(runtime));

        cleanup_managed_containers(&state).await;
        let guard = mock.containers.lock().expect("lock");
        assert!(guard.is_empty());
    }
}
