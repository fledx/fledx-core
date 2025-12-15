use std::collections::HashMap;

use node_agent::{config, runner, runner::AgentOptions};

#[tokio::test]
async fn embedded_shutdown_finishes_with_metrics_enabled() {
    let cfg = config::AppConfig {
        control_plane_url: "http://127.0.0.1:1".into(),
        node_id: uuid::Uuid::new_v4(),
        node_token: "itest-token".into(),
        secrets_dir: "/var/run/secrets".into(),
        secrets_prefix: "FLEDX_SECRET_".into(),
        heartbeat_interval_secs: 60,
        heartbeat_timeout_secs: 1,
        heartbeat_max_retries: 1,
        heartbeat_backoff_ms: 10,
        heartbeat_max_metrics: 10,
        reconcile_interval_secs: 60,
        docker_reconnect_backoff_ms: 10,
        docker_reconnect_backoff_max_ms: 100,
        restart_backoff_ms: 10,
        restart_backoff_max_ms: 100,
        restart_failure_limit: 1,
        resource_sample_interval_secs: 60,
        resource_sample_window: 5,
        resource_sample_max_concurrency: 1,
        resource_sample_backoff_ms: 10,
        resource_sample_backoff_max_ms: 100,
        allow_insecure_http: true,
        tls_insecure_skip_verify: false,
        ca_cert_path: None,
        service_identity_dir: "/tmp/fledx-itest/service-identities".into(),
        metrics_host: "127.0.0.1".into(),
        // Let the OS pick an ephemeral port to avoid collisions in CI.
        metrics_port: 0,
        arch: std::env::consts::ARCH.into(),
        os: std::env::consts::OS.into(),
        tunnel: config::TunnelConfig {
            endpoint_host: "127.0.0.1".into(),
            endpoint_port: 1,
            ..Default::default()
        },
        tunnel_routes: Vec::new(),
        public_host: None,
        public_ip: None,
        gateway: config::GatewayConfig::default(),
        allowed_volume_prefixes: vec!["/tmp".into()],
        volume_data_dir: "/tmp/fledx-itest".into(),
        labels: HashMap::new(),
        capacity_cpu_millis: None,
        capacity_memory_bytes: None,
        force_empty_labels: false,
        force_empty_capacity: false,
        cleanup_on_shutdown: false,
    };

    let agent = runner::start_agent(
        cfg,
        AgentOptions {
            // Avoid global tracing subscriber conflicts in tests.
            init_tracing: false,
            serve_metrics: true,
            metrics_handle: None,
        },
    )
    .await
    .expect("agent starts");

    // This used to hang when the metrics task never observed shutdown.
    let shutdown = tokio::time::timeout(std::time::Duration::from_secs(5), agent.shutdown()).await;
    let res = shutdown.expect("shutdown should complete within timeout");
    res.expect("shutdown should succeed");
}
