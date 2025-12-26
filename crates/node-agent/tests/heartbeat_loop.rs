use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use httpmock::{Method::POST, MockServer};
use tokio::sync::watch;
use uuid::Uuid;

use node_agent::config::{self, AppConfig};
use node_agent::heartbeat::heartbeat_loop;
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
        heartbeat_max_retries: 1,
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
        labels: HashMap::new(),
        capacity_cpu_millis: None,
        capacity_memory_bytes: None,
        force_empty_labels: false,
        force_empty_capacity: false,
        cleanup_on_shutdown: false,
    }
}

#[tokio::test]
async fn heartbeat_loop_runs_and_exits_on_shutdown() {
    let server = MockServer::start();
    let node_id = Uuid::new_v4();
    let path = format!("/api/v1/nodes/{node_id}/heartbeats");

    let mock = server.mock(|when, then| {
        when.method(POST).path(path.clone());
        then.status(200);
    });

    let mut cfg = base_config();
    cfg.control_plane_url = server.url("");
    cfg.node_id = node_id;

    let client = node_agent::build_client(&cfg).expect("client");
    let runtime_factory: RuntimeFactory = Arc::new(|| {
        Err(ContainerRuntimeError::Connection {
            context: "test",
            source: anyhow::anyhow!("down"),
        })
    });
    let state = state::new_state(cfg, client, runtime_factory, None);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let loop_state = state.clone();
    let handle = tokio::spawn(async move { heartbeat_loop(loop_state, shutdown_rx).await });

    let hit = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if mock.calls() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(hit.is_ok(), "heartbeat was not sent");

    shutdown_tx.send(true).expect("send shutdown");
    let joined = tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .expect("heartbeat loop join timed out")
        .expect("heartbeat loop task panicked");
    joined.expect("heartbeat loop returned error");
}
