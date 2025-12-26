use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use httpmock::{Method::GET, MockServer};
use tokio::sync::watch;
use uuid::Uuid;

use node_agent::api::{DeploymentHealth, HealthProbe, HealthProbeKind, InstanceState, PortMapping};
use node_agent::config::{self, AppConfig};
use node_agent::health::health_loop;
use node_agent::runtime::ContainerRuntimeError;
use node_agent::state::{self, ManagedDeployment, ReplicaKey, RuntimeFactory};

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
        labels: HashMap::new(),
        capacity_cpu_millis: None,
        capacity_memory_bytes: None,
        force_empty_labels: false,
        force_empty_capacity: false,
        cleanup_on_shutdown: false,
    }
}

#[tokio::test]
async fn health_loop_runs_and_exits_on_shutdown() {
    let server = MockServer::start();
    let path = "/healthz";
    let _mock = server.mock(|when, then| {
        when.method(GET).path(path);
        then.status(200);
    });

    let runtime_factory: RuntimeFactory = Arc::new(|| {
        Err(ContainerRuntimeError::Connection {
            context: "test",
            source: anyhow::anyhow!("down"),
        })
    });
    let state = state::new_state(base_config(), reqwest::Client::new(), runtime_factory, None);
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
        entry.last_started_at = Some(Utc::now() - ChronoDuration::seconds(2));
        guard.managed.insert(key, entry);
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let loop_state = state.clone();
    let handle = tokio::spawn(async move { health_loop(loop_state, shutdown_rx).await });

    let updated = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let health = {
                let guard = state.managed_read().await;
                guard
                    .managed
                    .get(&key)
                    .and_then(|entry| entry.health.clone())
            };
            if health.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(updated.is_ok(), "health status was not updated");

    shutdown_tx.send(true).expect("send shutdown");
    let joined = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("health loop join timed out")
        .expect("health loop task panicked");
    joined.expect("health loop returned error");
}
