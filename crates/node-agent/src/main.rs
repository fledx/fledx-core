use node_agent::config;
use node_agent::runner::{self, AgentOptions};
use std::future::Future;
use std::pin::Pin;
use tracing::info;

trait ShutdownHandle {
    type ShutdownFuture: Future<Output = anyhow::Result<()>> + Send;
    fn shutdown(self) -> Self::ShutdownFuture;
}

impl ShutdownHandle for runner::AgentHandle {
    type ShutdownFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

    fn shutdown(self) -> Self::ShutdownFuture {
        Box::pin(self.shutdown())
    }
}

async fn run_with<Load, Start, Wait, Handle, LoadFut, StartFut, WaitFut>(
    load: Load,
    start: Start,
    wait: Wait,
) -> anyhow::Result<()>
where
    Load: FnOnce() -> LoadFut,
    LoadFut: Future<Output = anyhow::Result<config::AppConfig>>,
    Start: FnOnce(config::AppConfig, AgentOptions) -> StartFut,
    StartFut: Future<Output = anyhow::Result<Handle>>,
    Wait: FnOnce() -> WaitFut,
    WaitFut: Future<Output = ()>,
    Handle: ShutdownHandle,
{
    let cfg = load().await?;
    let agent = start(cfg, AgentOptions::default()).await?;

    wait().await;
    info!("shutdown signal received, stopping agent");
    agent.shutdown().await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_with(
        || async { config::load() },
        runner::start_agent,
        runner::wait_for_shutdown_signal,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use uuid::Uuid;

    #[derive(Clone)]
    struct TestHandle {
        shutdown_called: Arc<AtomicBool>,
    }

    impl ShutdownHandle for TestHandle {
        type ShutdownFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

        fn shutdown(self) -> Self::ShutdownFuture {
            let shutdown_called = self.shutdown_called.clone();
            Box::pin(async move {
                shutdown_called.store(true, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    fn base_config() -> config::AppConfig {
        config::AppConfig {
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
    async fn run_with_calls_wait_and_shutdown() {
        let start_called = Arc::new(AtomicBool::new(false));
        let wait_called = Arc::new(AtomicBool::new(false));
        let shutdown_called = Arc::new(AtomicBool::new(false));

        let start_flag = start_called.clone();
        let wait_flag = wait_called.clone();
        let shutdown_flag = shutdown_called.clone();
        let cfg = base_config();

        let result = run_with(
            move || {
                let cfg = cfg.clone();
                async move { Ok(cfg) }
            },
            move |_cfg, _opts| {
                start_flag.store(true, Ordering::SeqCst);
                let shutdown_flag = shutdown_flag.clone();
                async move {
                    Ok(TestHandle {
                        shutdown_called: shutdown_flag,
                    })
                }
            },
            move || {
                let wait_flag = wait_flag.clone();
                async move {
                    wait_flag.store(true, Ordering::SeqCst);
                }
            },
        )
        .await;

        assert!(result.is_ok());
        assert!(start_called.load(Ordering::SeqCst));
        assert!(wait_called.load(Ordering::SeqCst));
        assert!(shutdown_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn run_with_propagates_config_errors() {
        let start_called = Arc::new(AtomicBool::new(false));
        let wait_called = Arc::new(AtomicBool::new(false));

        let start_flag = start_called.clone();
        let wait_flag = wait_called.clone();

        let err =
            run_with(
                || async { Err(anyhow::anyhow!("bad config")) },
                move |_cfg, _opts| {
                    start_flag.store(true, Ordering::SeqCst);
                    async move {
                        Err::<TestHandle, anyhow::Error>(anyhow::anyhow!("start should not run"))
                    }
                },
                move || {
                    wait_flag.store(true, Ordering::SeqCst);
                    async move {}
                },
            )
            .await
            .expect_err("config error");

        assert!(err.to_string().contains("bad config"));
        assert!(!start_called.load(Ordering::SeqCst));
        assert!(!wait_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn run_with_propagates_start_errors() {
        let start_called = Arc::new(AtomicBool::new(false));
        let wait_called = Arc::new(AtomicBool::new(false));

        let start_flag = start_called.clone();
        let wait_flag = wait_called.clone();
        let cfg = base_config();

        let err = run_with(
            move || {
                let cfg = cfg.clone();
                async move { Ok(cfg) }
            },
            move |_cfg, _opts| {
                start_flag.store(true, Ordering::SeqCst);
                async move { Err::<TestHandle, anyhow::Error>(anyhow::anyhow!("start failed")) }
            },
            move || {
                wait_flag.store(true, Ordering::SeqCst);
                async move {}
            },
        )
        .await
        .expect_err("start error");

        assert!(err.to_string().contains("start failed"));
        assert!(start_called.load(Ordering::SeqCst));
        assert!(!wait_called.load(Ordering::SeqCst));
    }
}
