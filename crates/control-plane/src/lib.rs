pub mod app_state;
pub mod audit;
pub mod auth;
pub mod compat;
pub mod config;
pub mod error;
pub mod http;
pub mod metrics;
pub mod openapi;
pub mod persistence;
pub mod rate_limit;
pub mod rbac;
pub mod routes;
pub mod scheduler;
pub mod services;
pub mod tasks;
pub mod telemetry;
pub mod tokens;
pub mod tunnel;
pub mod validation;
pub mod version;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

use std::{env, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use axum::{http::HeaderName, Router};
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::json;
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::app_state::{
    AppState, OperatorAuth, OperatorAuthorizer, OperatorTokenValidator, RegistrationLimiterRef,
};
use crate::metrics::{init_metrics_recorder, record_build_info, MetricsHistory};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandMode {
    Serve,
    ServeStandalone,
    MigrationsDryRun,
}

pub type StartBackgroundFn = Arc<
    dyn Fn(AppState, &config::AppConfig) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct ControlPlaneHooks {
    pub start_background: StartBackgroundFn,
    pub extend_router: fn(AppState, Router<AppState>) -> Router<AppState>,
    pub require_master_key: bool,
    pub make_audit_sink: fn(&AppState) -> Option<std::sync::Arc<dyn crate::audit::AuditSink>>,
    pub master_key: Option<[u8; 32]>,
    pub migrations: &'static sqlx::migrate::Migrator,
    pub registration_limiter: Option<RegistrationLimiterRef>,
    pub operator_limiter: Option<RegistrationLimiterRef>,
    pub agent_limiter: Option<RegistrationLimiterRef>,
    pub operator_token_validator: Option<OperatorTokenValidator>,
    pub operator_authorizer: Option<OperatorAuthorizer>,
}

impl Default for ControlPlaneHooks {
    fn default() -> Self {
        Self {
            start_background: Arc::new(|_, _| Box::pin(async { Ok(()) })),
            extend_router: |_, router| router,
            require_master_key: false,
            make_audit_sink: |_| None,
            master_key: None,
            migrations: crate::persistence::migrations::core_migrator(),
            registration_limiter: None,
            operator_limiter: None,
            agent_limiter: None,
            operator_token_validator: None,
            operator_authorizer: None,
        }
    }
}

pub fn parse_command() -> Result<CommandMode> {
    let mut args = env::args().skip(1);
    let Some(first) = args.next() else {
        return Ok(CommandMode::Serve);
    };

    match first.as_str() {
        "--standalone" | "standalone" => Ok(CommandMode::ServeStandalone),
        "--migrations-dry-run" | "migrations-dry-run" => Ok(CommandMode::MigrationsDryRun),
        "migrate" => match args.next().as_deref() {
            Some("--dry-run") | Some("dry-run") => Ok(CommandMode::MigrationsDryRun),
            _ => anyhow::bail!("unknown migrate option; use --dry-run"),
        },
        "--help" | "-h" => {
            println!(
                "Usage: control-plane [--standalone] [--migrations-dry-run]|[migrate --dry-run]\n\
                 Run without arguments to start the server."
            );
            std::process::exit(0);
        }
        other => anyhow::bail!("unknown argument: {other}"),
    }
}

/// Boot the control-plane using the provided command mode.
pub async fn run(mode: CommandMode) -> Result<()> {
    match mode {
        CommandMode::Serve => run_with(mode, ControlPlaneHooks::default()).await,
        CommandMode::ServeStandalone => run_standalone(ControlPlaneHooks::default()).await,
        CommandMode::MigrationsDryRun => run_with(mode, ControlPlaneHooks::default()).await,
    }
}

pub async fn run_with(mode: CommandMode, hooks: ControlPlaneHooks) -> Result<()> {
    run_with_shutdown(mode, hooks, shutdown_signal()).await
}

pub async fn run_with_shutdown<S>(
    mode: CommandMode,
    hooks: ControlPlaneHooks,
    shutdown: S,
) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    let app_config = config::load()?;
    let metrics_handle = init_metrics_recorder();
    let metrics_history = MetricsHistory::new(app_config.limits.metrics_summary_window_secs);
    let agent_compat = compat::AgentCompatibility::from_config(&app_config.compatibility)?;
    info!(
        min_supported_agent = %agent_compat.min_supported,
        max_supported_agent = %agent_compat.max_supported,
        upgrade_url = agent_compat.upgrade_url.as_deref().unwrap_or(""),
        "agent compatibility window configured"
    );

    let operator_tokens: Vec<String> = app_config
        .operator
        .tokens
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if operator_tokens.is_empty() {
        return Err(anyhow::anyhow!("FLEDX_CP_OPERATOR_TOKENS cannot be empty"));
    }
    let operator_header = app_config
        .operator
        .header_name
        .parse::<HeaderName>()
        .map_err(|err| anyhow::anyhow!("invalid operator header name: {}", err))?;

    let db_pool = persistence::migrations::init_pool(&app_config.database.url).await?;
    if app_config.features.migrations_dry_run_on_start && mode == CommandMode::Serve {
        let snapshot =
            persistence::migrations::dry_run_migrations_with(&db_pool, hooks.migrations).await?;
        info!(
            current_version = snapshot.latest_applied,
            target_version = snapshot.latest_available,
            pending = snapshot.pending.len(),
            "feature flag: migration dry-run completed before startup"
        );
    }
    if mode == CommandMode::MigrationsDryRun {
        let snapshot =
            persistence::migrations::dry_run_migrations_with(&db_pool, hooks.migrations).await?;
        info!(
            current_version = snapshot.latest_applied,
            target_version = snapshot.latest_available,
            pending = snapshot.pending.len(),
            "migration dry-run completed"
        );
        return Ok(());
    }

    let core_migrations = if std::ptr::eq(
        hooks.migrations,
        crate::persistence::migrations::core_migrator(),
    ) {
        persistence::migrations::run_migrations(&db_pool).await?
    } else {
        persistence::migrations::run_migrations_with_allowing_prior_versions(
            &db_pool,
            crate::persistence::migrations::core_migrator(),
        )
        .await?
    };
    let hook_migrations = if std::ptr::eq(
        hooks.migrations,
        crate::persistence::migrations::core_migrator(),
    ) {
        persistence::migrations::MigrationRunOutcome {
            snapshot: core_migrations.snapshot.clone(),
            applied: Vec::new(),
        }
    } else {
        persistence::migrations::run_migrations_with_allowing_prior_versions(
            &db_pool,
            hooks.migrations,
        )
        .await?
    };
    let migration_outcome =
        persistence::migrations::merge_run_outcomes(&core_migrations, &hook_migrations);
    let applied_migrations = migration_outcome.applied.clone();
    if migration_outcome.applied.is_empty() {
        info!(
            current_version = migration_outcome.snapshot.latest_applied,
            target_version = migration_outcome.snapshot.latest_available,
            "database schema is up to date"
        );
    } else {
        for mig in &migration_outcome.applied {
            info!(
                version = mig.version,
                description = mig.description,
                "applied database migration"
            );
        }
    }
    record_build_info(&migration_outcome.snapshot);
    let scheduler = scheduler::RoundRobinScheduler::new(db_pool.clone());
    let registration_limiter: Option<RegistrationLimiterRef> =
        hooks.registration_limiter.clone().or_else(|| {
            let per_minute = app_config.registration.rate_limit_per_minute;
            if per_minute == 0 {
                None
            } else {
                Some(Arc::new(tokio::sync::Mutex::new(
                    crate::app_state::SlidingWindowRegistrationLimiter::per_minute(per_minute),
                )))
            }
        });
    let operator_limiter = hooks.operator_limiter.clone();
    let agent_limiter = hooks.agent_limiter.clone();
    if hooks.require_master_key && hooks.master_key.is_none() {
        anyhow::bail!("master key is required but missing");
    }
    let master_key = hooks.master_key;
    let operator_token_validator = hooks.operator_token_validator.clone().unwrap_or_else(|| {
        Arc::new(|state, token| {
            Box::pin(crate::auth::env_only_operator_token_validator(state, token))
        })
    });
    let operator_authorizer = hooks.operator_authorizer.clone();
    let audit_redactor = Arc::new(crate::audit::AuditRedactor::new(
        &app_config.audit.redaction,
    ));

    let mut state = AppState {
        db: db_pool.clone(),
        scheduler,
        registration_token: app_config.registration.token.clone(),
        operator_auth: OperatorAuth {
            tokens: operator_tokens,
            header_name: operator_header,
        },
        operator_token_validator,
        operator_authorizer,
        registration_limiter,
        operator_limiter,
        agent_limiter,
        token_pepper: app_config.tokens.pepper.clone(),
        limits: app_config.limits.clone(),
        retention: app_config.retention.clone(),
        audit_export: app_config.audit.export.clone(),
        audit_redactor,
        reachability: app_config.reachability.clone(),
        ports: app_config.ports.clone(),
        volumes: app_config.volumes.clone(),
        tunnel: app_config.tunnel.clone(),
        metrics_handle: metrics_handle.clone(),
        metrics_history,
        tunnel_registry: crate::tunnel::TunnelRegistry::new(),
        relay_health: crate::tunnel::RelayHealthState::default(),
        agent_compat,
        schema: migration_outcome.snapshot,
        enforce_agent_compatibility: app_config.features.enforce_agent_compatibility,
        pem_key: master_key,
        audit_sink: None,
    };

    state.audit_sink = (hooks.make_audit_sink)(&state);

    for mig in &applied_migrations {
        telemetry::record_audit_log(
            &state,
            "migration.applied",
            "database",
            audit::AuditStatus::Success,
            audit::AuditContext {
                resource_id: None,
                actor: None,
                request_id: None,
                payload: Some(
                    json!({
                        "version": mig.version,
                        "description": mig.description
                    })
                    .to_string(),
                ),
            },
        )
        .await;
    }

    tokio::spawn(routes::reachability_loop(
        state.db.clone(),
        state.scheduler.clone(),
        state.reachability.clone(),
        state.ports.clone(),
    ));

    tokio::spawn(routes::usage_retention_loop(
        state.db.clone(),
        state.retention.clone(),
    ));

    (hooks.start_background)(state.clone(), &app_config).await?;
    services::tunnel::serve(state.clone()).await?;

    let api_addr: SocketAddr = format!("{}:{}", app_config.server.host, app_config.server.port)
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid listen address: {}", err))?;
    let metrics_addr: SocketAddr =
        format!("{}:{}", app_config.metrics.host, app_config.metrics.port)
            .parse()
            .map_err(|err| anyhow::anyhow!("invalid metrics listen address: {}", err))?;

    let base_router: Router<AppState> = routes::build_router(state.clone());
    let app = (hooks.extend_router)(state.clone(), base_router).with_state(state.clone());
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    let metrics_app = crate::http::build_metrics_router().with_state(state.clone());
    let metrics_service = metrics_app.into_make_service_with_connect_info::<SocketAddr>();

    let api_listener = tokio::net::TcpListener::bind(api_addr).await?;
    let metrics_listener = tokio::net::TcpListener::bind(metrics_addr).await?;
    info!(%api_addr, "control-plane listening");
    info!(%metrics_addr, "control-plane metrics listening");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx_for_signal = shutdown_tx.clone();
    tokio::spawn(async move {
        shutdown.await;
        let _ = shutdown_tx_for_signal.send(true);
    });

    let mut api_shutdown = shutdown_rx.clone();
    let mut metrics_shutdown = shutdown_rx.clone();

    let mut api_task = tokio::spawn(async move {
        axum::serve(api_listener, make_service)
            .with_graceful_shutdown(async move {
                let _ = api_shutdown.changed().await;
            })
            .await
    });

    let mut metrics_task = tokio::spawn(async move {
        axum::serve(metrics_listener, metrics_service)
            .with_graceful_shutdown(async move {
                let _ = metrics_shutdown.changed().await;
            })
            .await
    });

    tokio::select! {
        res = &mut api_task => {
            let _ = shutdown_tx.send(true);
            res.map_err(|err| anyhow::anyhow!("control-plane task failed: {err}"))?
                .map_err(|err| anyhow::anyhow!("control-plane server failed: {err}"))?;
        }
        res = &mut metrics_task => {
            let _ = shutdown_tx.send(true);
            res.map_err(|err| anyhow::anyhow!("control-plane metrics task failed: {err}"))?
                .map_err(|err| anyhow::anyhow!("control-plane metrics server failed: {err}"))?;
        }
    }

    api_task
        .await
        .map_err(|err| anyhow::anyhow!("control-plane task failed: {err}"))?
        .map_err(|err| anyhow::anyhow!("control-plane server failed: {err}"))?;
    metrics_task
        .await
        .map_err(|err| anyhow::anyhow!("control-plane metrics task failed: {err}"))?
        .map_err(|err| anyhow::anyhow!("control-plane metrics server failed: {err}"))?;

    Ok(())
}

/// Run control-plane and an embedded node-agent in the same process.
pub async fn run_standalone(hooks: ControlPlaneHooks) -> Result<()> {
    // Install the metrics recorder once and reuse it for both components so
    // counters land in the same `/metrics` endpoint.
    let metrics_handle: PrometheusHandle = init_metrics_recorder();

    let agent_cfg = node_agent::config::load()?;
    let agent = node_agent::runner::start_agent(
        agent_cfg,
        node_agent::runner::AgentOptions {
            init_tracing: false,
            serve_metrics: false,
            metrics_handle: Some(metrics_handle.clone()),
        },
    )
    .await?;

    let mut cp_shutdown_rx = agent.shutdown_signal();
    let mut cp_task = tokio::spawn(async move {
        run_with_shutdown(CommandMode::Serve, hooks, async move {
            let _ = cp_shutdown_rx.changed().await;
        })
        .await
    });

    tokio::select! {
        cp_res = &mut cp_task => {
            agent.request_shutdown();
            cp_res.map_err(|err| anyhow::anyhow!("control-plane task failed: {err}"))??;
            agent.await_termination().await?;
            return Ok(());
        }
        _ = shutdown_signal() => {
            agent.request_shutdown();
        }
    }

    // Shutdown was requested; wait for the control-plane to exit gracefully.
    cp_task
        .await
        .map_err(|err| anyhow::anyhow!("control-plane task failed: {err}"))??;
    agent.await_termination().await?;
    Ok(())
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();
}

async fn shutdown_signal() {
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
        _ = ctrl_c => {
            info!("received Ctrl+C, shutting down");
        },
        _ = terminate => {
            info!("received SIGTERM, shutting down");
        },
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
}
