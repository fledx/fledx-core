use std::{net::SocketAddr, sync::Arc};

use node_agent::{
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
use tokio::{signal, sync::watch};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init_tracing();
    let cfg = config::load()?;
    validate_control_plane_url(&cfg)?;
    let metrics_handle = telemetry::init_metrics_recorder();
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
        let metrics_handle = metrics_handle.clone();
        tokio::spawn(async move {
            if let Err(err) = telemetry::serve_metrics(metrics_handle, metrics_addr).await {
                error!(?err, "metrics server exited with error");
            }
        });
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
    let hb_state = state.clone();
    let rc_state = state.clone();
    let shutdown_rx_reconcile = shutdown_rx.clone();
    let shutdown_rx_configs = shutdown_rx.clone();
    let heartbeat_shutdown = shutdown_rx.clone();
    let health_shutdown = shutdown_rx.clone();
    let sampler_shutdown = shutdown_rx.clone();
    let gateway_shutdown = shutdown_rx.clone();
    let identities_shutdown = shutdown_rx.clone();
    let cleanup_on_shutdown = {
        let guard = state.lock().await;
        guard.cfg.cleanup_on_shutdown
    };

    let heartbeat_handle = tokio::spawn(async move {
        if let Err(err) = heartbeat_loop(hb_state, heartbeat_shutdown).await {
            error!(?err, "heartbeat loop terminated with error");
        }
    });
    let reconcile_handle = tokio::spawn(async move {
        if let Err(err) = reconcile_loop(rc_state, shutdown_rx_reconcile).await {
            error!(?err, "reconcile loop terminated with error");
        }
    });
    let configs_state = state.clone();
    let configs_handle = tokio::spawn(async move {
        if let Err(err) = configs::config_sync_loop(configs_state, shutdown_rx_configs).await {
            error!(?err, "config sync loop terminated with error");
        }
    });
    let sampler_handle = {
        let sampler_state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = resource_sampler_loop(sampler_state, sampler_shutdown).await {
                error!(?err, "resource sampler loop terminated with error");
            }
        })
    };
    let health_handle = {
        let health_state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = health_loop(health_state, health_shutdown).await {
                error!(?err, "health loop terminated with error");
            }
        })
    };
    let gateway_handle = {
        let gateway_state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = services::gateway::gateway_loop(gateway_state, gateway_shutdown).await
            {
                error!(?err, "gateway loop terminated with error");
            }
        })
    };
    let tunnel_handle = {
        let tunnel_state = state.clone();
        let tunnel_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = services::tunnel::tunnel_loop(tunnel_state, tunnel_shutdown).await {
                error!(?err, "tunnel loop terminated with error");
            }
        })
    };
    let identities_handle = {
        let identities_state = state.clone();
        let client = reqwest::Client::new();
        tokio::spawn(async move {
            if let Err(err) = services::identities::service_identity_loop(
                identities_state,
                identities_shutdown,
                client,
            )
            .await
            {
                error!(?err, "service identity loop terminated with error");
            }
        })
    };

    shutdown_signal().await;
    info!("shutdown signal received, stopping agent");
    let _ = shutdown_tx.send(true);

    let _ = heartbeat_handle.await;
    let _ = reconcile_handle.await;
    let _ = configs_handle.await;
    let _ = sampler_handle.await;
    let _ = health_handle.await;
    let _ = gateway_handle.await;
    let _ = tunnel_handle.await;
    let _ = identities_handle.await;

    if cleanup_on_shutdown {
        cleanup_managed_containers(&state).await;
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
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
