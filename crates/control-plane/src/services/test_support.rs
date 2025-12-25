use axum::http::HeaderName;
use std::sync::Arc;

use crate::app_state::{
    AppState, EnvTokenPolicy, NoopRegistrationLimiter, OperatorAuth, RegistrationLimiterRef,
};

pub(crate) async fn setup_state() -> AppState {
    let db = crate::persistence::migrations::init_pool("sqlite::memory:")
        .await
        .expect("pool");
    let migration_outcome = crate::persistence::migrations::run_migrations(&db)
        .await
        .expect("migrations");
    let scheduler = crate::scheduler::RoundRobinScheduler::new(db.clone());
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
    let metrics_history = crate::metrics::MetricsHistory::new(limits.metrics_summary_window_secs);

    AppState {
        db: db.clone(),
        scheduler,
        registration_token: "reg".into(),
        operator_auth: OperatorAuth {
            tokens: vec!["op-token".into()],
            header_name: HeaderName::from_static("authorization"),
            env_policy: EnvTokenPolicy::default(),
        },
        operator_token_validator: std::sync::Arc::new(|state, token| {
            Box::pin(crate::auth::env_only_operator_token_validator(state, token))
        }),
        operator_authorizer: None,
        registration_limiter: Some(registration_limiter),
        operator_limiter: None,
        agent_limiter: None,
        token_pepper: "pepper".into(),
        limits,
        retention: crate::config::RetentionConfig {
            instance_status_secs: 86_400,
            instance_metrics_secs: 600,
            usage_window_secs: 604_800,
            usage_cleanup_interval_secs: 300,
            audit_log_secs: 90 * 24 * 60 * 60,
            audit_log_cleanup_interval_secs: 60 * 60,
        },
        audit_export: crate::config::AuditExportConfig::default(),
        audit_redactor: std::sync::Arc::new(crate::audit::AuditRedactor::new(
            &crate::config::AuditRedactionConfig::default(),
        )),
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
        .expect("agent compatibility"),
        schema: migration_outcome.snapshot,
        enforce_agent_compatibility: true,
        pem_key: Some([7u8; 32]),
        audit_sink: None,
    }
}
