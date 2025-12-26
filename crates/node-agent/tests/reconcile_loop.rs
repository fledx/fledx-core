use std::sync::Arc;
use std::time::Duration;

use httpmock::{Method::GET, MockServer};
use tokio::sync::watch;
use uuid::Uuid;

use node_agent::api::DesiredStateResponse;
use node_agent::config::{self, AppConfig};
use node_agent::reconcile::reconcile_loop;
use node_agent::runtime::ContainerRuntimeError;
use node_agent::state::{self, RuntimeFactory};

fn base_config() -> AppConfig {
    AppConfig {
        control_plane_url: "http://localhost:49421".into(),
        node_id: Uuid::new_v4(),
        node_token: "t".into(),
        secrets_dir: "/var/run/secrets".into(),
        secrets_prefix: "FLEDX_SECRET_".into(),
        heartbeat_interval_secs: 1,
        heartbeat_timeout_secs: 1,
        heartbeat_max_retries: 2,
        heartbeat_backoff_ms: 10,
        heartbeat_max_metrics: 10,
        reconcile_interval_secs: 1,
        docker_reconnect_backoff_ms: 10,
        docker_reconnect_backoff_max_ms: 20,
        restart_backoff_ms: 10,
        restart_backoff_max_ms: 20,
        restart_failure_limit: 3,
        resource_sample_interval_secs: 1,
        resource_sample_window: 5,
        resource_sample_max_concurrency: 2,
        resource_sample_backoff_ms: 10,
        resource_sample_backoff_max_ms: 20,
        allow_insecure_http: true,
        tls_insecure_skip_verify: false,
        ca_cert_path: None,
        service_identity_dir: "/var/lib/fledx/service-identities".into(),
        metrics_host: "127.0.0.1".into(),
        metrics_port: 0,
        arch: std::env::consts::ARCH.into(),
        os: std::env::consts::OS.into(),
        tunnel: config::TunnelConfig::default(),
        tunnel_routes: Vec::new(),
        public_host: None,
        public_ip: None,
        gateway: config::GatewayConfig::default(),
        allowed_volume_prefixes: vec!["/tmp".into()],
        volume_data_dir: "/var/lib/fledx".into(),
        labels: std::collections::HashMap::new(),
        capacity_cpu_millis: None,
        capacity_memory_bytes: None,
        force_empty_labels: false,
        force_empty_capacity: false,
        cleanup_on_shutdown: false,
    }
}

#[tokio::test]
async fn reconcile_loop_runs_and_exits_on_shutdown() {
    let server = MockServer::start();
    let mut cfg = base_config();
    cfg.control_plane_url = server.url("");
    let node_id = cfg.node_id;

    let path = format!("/api/v1/nodes/{}/desired-state", node_id);
    let response = DesiredStateResponse {
        control_plane_version: "1.2.3".into(),
        min_supported_agent_version: "1.0.0".into(),
        max_supported_agent_version: None,
        upgrade_url: None,
        tunnel: None,
        deployments: vec![],
    };
    let mock = server.mock(|when, then| {
        when.method(GET).path(path.clone());
        then.status(200).json_body_obj(&response);
    });

    let runtime_factory: RuntimeFactory = Arc::new(|| {
        Err(ContainerRuntimeError::Connection {
            context: "test",
            source: anyhow::anyhow!("down"),
        })
    });
    let state = state::new_state(cfg, reqwest::Client::new(), runtime_factory, None);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let loop_state = state.clone();
    let handle = tokio::spawn(async move { reconcile_loop(loop_state, shutdown_rx).await });

    let updated = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if mock.calls() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(updated.is_ok(), "reconcile loop did not call desired state");

    shutdown_tx.send(true).expect("send shutdown");
    let joined = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("reconcile loop join timed out")
        .expect("reconcile loop task panicked");
    joined.expect("reconcile loop returned error");
}

#[tokio::test]
async fn reconcile_loop_handles_fetch_errors_and_exits() {
    let server = MockServer::start();
    let mut cfg = base_config();
    cfg.control_plane_url = server.url("");
    let node_id = cfg.node_id;

    let path = format!("/api/v1/nodes/{}/desired-state", node_id);
    let mock = server.mock(|when, then| {
        when.method(GET).path(path.clone());
        then.status(500).body("boom");
    });

    let runtime_factory: RuntimeFactory = Arc::new(|| {
        Err(ContainerRuntimeError::Connection {
            context: "test",
            source: anyhow::anyhow!("down"),
        })
    });
    let state = state::new_state(cfg, reqwest::Client::new(), runtime_factory, None);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let loop_state = state.clone();
    let handle = tokio::spawn(async move { reconcile_loop(loop_state, shutdown_rx).await });

    let updated = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if mock.calls() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(updated.is_ok(), "reconcile loop did not call desired state");

    shutdown_tx.send(true).expect("send shutdown");
    let joined = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("reconcile loop join timed out")
        .expect("reconcile loop task panicked");
    joined.expect("reconcile loop returned error");
}
