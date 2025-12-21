#![allow(dead_code)]

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::request::Builder as HttpBuilder,
    http::{HeaderName, Request as HttpRequest},
    Router,
};
use chrono::Utc;
use common::api;
use control_plane::{
    app_state::{AppState, NoopRegistrationLimiter, OperatorAuth, RegistrationLimiterRef},
    compat::AgentCompatibility,
    config::{
        CompatibilityConfig, LimitsConfig, PortsConfig, ReachabilityConfig, RetentionConfig,
        TunnelConfig,
    },
    metrics::{init_metrics_recorder, record_build_info, MetricsHistory},
    persistence as db,
    persistence::{migrations, nodes},
    routes::{build_metrics_router, build_router},
    scheduler,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

pub const TEST_REG_TOKEN: &str = "test-registration-token";
pub const TEST_OPERATOR_TOKEN: &str = "test-operator-token";

#[derive(Clone)]
pub struct TestAppConfig {
    pub limit: usize,
    pub window: Duration,
    pub reg_body_limit: Option<u64>,
    pub hb_body_limit: Option<u64>,
    pub config_payload_limit: Option<u64>,
    pub hb_metrics_per_instance: Option<usize>,
    pub hb_metrics_total: Option<usize>,
    pub metrics_prom_series: Option<usize>,
    pub log_tail_limit: Option<u32>,
    pub log_tail_max_window_secs: Option<u64>,
    pub metrics_summary_limit: Option<u32>,
    pub metrics_summary_window_secs: Option<u64>,
    pub retention_secs: Option<u64>,
    pub metrics_retention_secs: Option<u64>,
    pub usage_window_secs: Option<u64>,
    pub usage_cleanup_interval_secs: Option<u64>,
    pub audit_retention_secs: Option<u64>,
    pub audit_cleanup_interval_secs: Option<u64>,
    pub reachability: Option<ReachabilityConfig>,
    pub operator_tokens: Option<Vec<String>>,
    pub operator_header: Option<HeaderName>,
    pub ports: Option<PortsConfig>,
    pub volumes: Option<control_plane::config::VolumesConfig>,
    pub compat_min: Option<String>,
    pub compat_max: Option<String>,
    pub compat_upgrade_url: Option<String>,
    pub enforce_agent_compatibility: Option<bool>,
}

impl Default for TestAppConfig {
    fn default() -> Self {
        Self {
            limit: 10,
            window: Duration::from_secs(60),
            reg_body_limit: None,
            hb_body_limit: None,
            config_payload_limit: None,
            hb_metrics_per_instance: None,
            hb_metrics_total: None,
            metrics_prom_series: None,
            retention_secs: None,
            metrics_retention_secs: None,
            usage_window_secs: None,
            usage_cleanup_interval_secs: None,
            audit_retention_secs: None,
            audit_cleanup_interval_secs: None,
            reachability: None,
            operator_tokens: None,
            operator_header: None,
            ports: None,
            volumes: None,
            log_tail_limit: None,
            log_tail_max_window_secs: None,
            metrics_summary_limit: None,
            metrics_summary_window_secs: None,
            compat_min: None,
            compat_max: None,
            compat_upgrade_url: None,
            enforce_agent_compatibility: None,
        }
    }
}

impl TestAppConfig {
    /// Configure the agent compatibility window to include the current
    /// control-plane build version.
    ///
    /// `agent_request(...)` sends `x-agent-version = control_plane::version::VERSION`.
    /// Pinning min/max to that value keeps tests stable across version bumps.
    pub fn with_current_agent_compat_window(mut self) -> Self {
        let version = control_plane::version::VERSION.to_string();
        self.compat_min = Some(version.clone());
        self.compat_max = Some(version);
        self
    }
}

pub type RegistrationResponse = api::RegistrationResponse;
pub type DeploymentCreateResponse = api::DeploymentCreateResponse;
pub type DeploymentStatusResponse = api::DeploymentStatusResponse;
pub type DesiredStateResponse = api::DesiredStateResponse;
pub type NodeConfigResponse = api::NodeConfigResponse;
pub type NodeStatusResponse = api::NodeStatusResponse;
pub type DesiredState = api::DesiredState;
pub type DeploymentStatus = api::DeploymentStatus;
pub type NodeStatus = api::NodeStatus;
pub type TokenResponse = api::TokenResponse;

pub async fn setup_app() -> (Router, db::Db) {
    setup_app_with_config(TestAppConfig::default()).await
}

pub async fn setup_apps() -> (Router, Router, db::Db) {
    setup_apps_with_config(TestAppConfig::default()).await
}

pub async fn setup_app_with_config(config: TestAppConfig) -> (Router, db::Db) {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");
    let migration_outcome = migrations::run_migrations(&db).await.expect("migrations");
    let state = make_state(db.clone(), &config, migration_outcome.snapshot);
    let app = build_router(state.clone()).with_state(state);
    (app, db)
}

pub async fn setup_apps_with_config(config: TestAppConfig) -> (Router, Router, db::Db) {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");
    let migration_outcome = migrations::run_migrations(&db).await.expect("migrations");
    let state = make_state(db.clone(), &config, migration_outcome.snapshot);
    let app = build_router(state.clone()).with_state(state.clone());
    let metrics_app = build_metrics_router().with_state(state);
    (app, metrics_app, db)
}

pub async fn setup_app_with_state(reachability: Option<ReachabilityConfig>) -> (Router, AppState) {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");
    let migration_outcome = migrations::run_migrations(&db).await.expect("migrations");
    let config = TestAppConfig {
        reachability,
        ..Default::default()
    };
    let state = make_state(db.clone(), &config, migration_outcome.snapshot);
    let app = build_router(state.clone()).with_state(state.clone());
    (app, state)
}

pub async fn register_ready_node(app: &Router, db: &db::Db, name: &str) -> RegistrationResponse {
    let payload = serde_json::json!({ "name": name });
    register_ready_node_with_payload(app, db, payload).await
}

pub async fn register_ready_node_with_payload(
    app: &Router,
    db: &db::Db,
    payload: serde_json::Value,
) -> RegistrationResponse {
    let response = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::CREATED);

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&body_bytes).unwrap();

    nodes::update_node_status(db, reg.node_id, db::NodeStatus::Ready, Some(Utc::now()))
        .await
        .expect("mark node ready");

    reg
}

pub async fn register_ready_node_with_ingress(
    app: &Router,
    db: &db::Db,
    name: &str,
    public_ip: Option<&str>,
    public_host: Option<&str>,
) -> RegistrationResponse {
    let mut payload = serde_json::Map::new();
    payload.insert("name".into(), serde_json::Value::String(name.to_string()));
    if let Some(ip) = public_ip {
        payload.insert(
            "public_ip".into(),
            serde_json::Value::String(ip.to_string()),
        );
    }
    if let Some(host) = public_host {
        payload.insert(
            "public_host".into(),
            serde_json::Value::String(host.to_string()),
        );
    }

    register_ready_node_with_payload(app, db, serde_json::Value::Object(payload)).await
}

pub fn agent_request(builder: HttpBuilder) -> HttpBuilder {
    builder
        .header("x-agent-version", control_plane::version::VERSION)
        .header("x-agent-build", control_plane::version::GIT_SHA)
}

pub fn make_state(db: db::Db, config: &TestAppConfig, schema: db::MigrationSnapshot) -> AppState {
    let scheduler = scheduler::RoundRobinScheduler::new(db.clone());
    let ports_cfg = config.ports.clone().unwrap_or(PortsConfig {
        auto_assign: false,
        range_start: 30000,
        range_end: 40000,
        public_host: None,
    });
    ports_cfg.validate().expect("ports config valid");
    let volumes_cfg = config
        .volumes
        .clone()
        .unwrap_or(control_plane::config::VolumesConfig {
            allowed_host_prefixes: Vec::new(),
        });
    let compat_cfg = CompatibilityConfig {
        min_agent_version: config.compat_min.clone(),
        max_agent_version: config.compat_max.clone(),
        upgrade_url: config.compat_upgrade_url.clone(),
    };
    let agent_compat = AgentCompatibility::from_config(&compat_cfg).expect("compat config");
    let limits = LimitsConfig {
        registration_body_bytes: config.reg_body_limit.unwrap_or(1024 * 16),
        heartbeat_body_bytes: config.hb_body_limit.unwrap_or(1024 * 64),
        config_payload_bytes: config.config_payload_limit.unwrap_or(128 * 1024),
        max_field_len: 255,
        log_tail_limit: config.log_tail_limit.unwrap_or(100),
        log_tail_max_window_secs: config.log_tail_max_window_secs.unwrap_or(300),
        metrics_summary_limit: config.metrics_summary_limit.unwrap_or(16),
        metrics_summary_window_secs: config.metrics_summary_window_secs.unwrap_or(60),
        heartbeat_metrics_per_instance: config.hb_metrics_per_instance.unwrap_or(60),
        heartbeat_metrics_total: config.hb_metrics_total.unwrap_or(500),
        resource_metrics_max_series: config.metrics_prom_series.unwrap_or(500),
    };
    let metrics_history = MetricsHistory::new(limits.metrics_summary_window_secs);
    let metrics_handle = init_metrics_recorder();
    record_build_info(&schema);
    let registration_limiter: RegistrationLimiterRef =
        Arc::new(tokio::sync::Mutex::new(NoopRegistrationLimiter));

    AppState {
        db,
        scheduler,
        registration_token: TEST_REG_TOKEN.into(),
        operator_auth: OperatorAuth {
            tokens: config
                .operator_tokens
                .clone()
                .unwrap_or_else(|| vec![TEST_OPERATOR_TOKEN.into()]),
            header_name: config
                .operator_header
                .clone()
                .unwrap_or_else(|| HeaderName::from_static("authorization")),
        },
        operator_token_validator: Arc::new(|state, token| {
            Box::pin(control_plane::auth::env_only_operator_token_validator(
                state, token,
            ))
        }),
        operator_authorizer: None,
        registration_limiter: Some(registration_limiter),
        operator_limiter: None,
        agent_limiter: None,
        token_pepper: "test-pepper".into(),
        limits,
        retention: RetentionConfig {
            instance_status_secs: config.retention_secs.unwrap_or(24 * 60 * 60),
            instance_metrics_secs: config.metrics_retention_secs.unwrap_or(10 * 60),
            usage_window_secs: config.usage_window_secs.unwrap_or(7 * 24 * 60 * 60),
            usage_cleanup_interval_secs: config.usage_cleanup_interval_secs.unwrap_or(5 * 60),
            audit_log_secs: config.audit_retention_secs.unwrap_or(90 * 24 * 60 * 60),
            audit_log_cleanup_interval_secs: config.audit_cleanup_interval_secs.unwrap_or(60 * 60),
        },
        audit_export: control_plane::config::AuditExportConfig::default(),
        audit_redactor: std::sync::Arc::new(control_plane::audit::AuditRedactor::new(
            &control_plane::config::AuditRedactionConfig::default(),
        )),
        reachability: config.reachability.clone().unwrap_or_default(),
        ports: ports_cfg,
        volumes: volumes_cfg,
        tunnel: TunnelConfig::default(),
        metrics_handle,
        metrics_history,
        tunnel_registry: control_plane::tunnel::TunnelRegistry::new(),
        relay_health: control_plane::tunnel::RelayHealthState::default(),
        agent_compat,
        schema,
        enforce_agent_compatibility: config.enforce_agent_compatibility.unwrap_or(true),
        pem_key: Some([3u8; 32]),
        audit_sink: None,
    }
}

pub fn legacy_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}
