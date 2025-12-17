use std::{
    fs,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Context;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::{
    config::AppConfig,
    runtime::{self, ContainerSpec, FileMount, PortMapping, PortProtocol},
    state::{self, ensure_runtime, record_runtime_error, SharedState},
};

const GATEWAY_CONTAINER_NAME: &str = "fledx-gateway";

#[derive(Default)]
pub(crate) struct GatewayManager {
    container_id: Option<String>,
    last_bootstrap_hash: Option<String>,
    backoff_attempts: u32,
    backoff_until: Option<Instant>,
}

pub async fn gateway_loop(
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    if !gateway_enabled(&state.lock().await.cfg) {
        return Ok(());
    }

    let client = Client::new();
    let mut manager = GatewayManager::default();
    let mut interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                if let Err(err) = manager.tick(&state, &client).await {
                    warn!(?err, "gateway loop iteration failed");
                }
            }
        }
    }

    Ok(())
}

fn gateway_enabled(cfg: &AppConfig) -> bool {
    cfg.gateway.enabled || cfg.public_ip.is_some() || cfg.public_host.is_some()
}

impl GatewayManager {
    async fn tick(&mut self, state: &SharedState, http: &Client) -> anyhow::Result<()> {
        let cfg = { state.lock().await.cfg.clone() };
        if !gateway_enabled(&cfg) {
            return Ok(());
        }

        if let Some(until) = self.backoff_until {
            if until > Instant::now() {
                return Ok(());
            }
        }

        let bootstrap_path = write_bootstrap(&cfg)?;
        let bootstrap_hash = hash_file(&bootstrap_path)?;

        let runtime = {
            let mut guard = state.lock().await;
            match ensure_runtime(&mut guard) {
                Ok(rt) => rt,
                Err(err) => {
                    record_runtime_error(
                        state,
                        &runtime::ContainerRuntimeError::Connection {
                            context: "gateway",
                            source: err,
                        },
                    )
                    .await;
                    self.apply_backoff(&cfg);
                    return Ok(());
                }
            }
        };

        let running = self
            .ensure_running(&cfg, runtime.clone(), &bootstrap_path, &bootstrap_hash)
            .await?;

        if running {
            if let Err(err) = check_admin(http, cfg.gateway.admin_port).await {
                warn!(?err, "envoy admin health check failed");
            }
        }

        Ok(())
    }

    async fn ensure_running(
        &mut self,
        cfg: &AppConfig,
        runtime: runtime::DynContainerRuntime,
        bootstrap_path: &str,
        bootstrap_hash: &str,
    ) -> anyhow::Result<bool> {
        let needs_restart = !self.is_running(&runtime).await?
            || self
                .last_bootstrap_hash
                .as_deref()
                .map(|h| h != bootstrap_hash)
                .unwrap_or(true);

        if !needs_restart {
            return Ok(true);
        }

        // Stop old container best-effort.
        if let Some(id) = self.container_id.take() {
            let _ = runtime.stop_container(&id).await;
            let _ = runtime.remove_container(&id).await;
        }

        let spec = build_spec(cfg, bootstrap_path)?;
        let id = runtime
            .start_container(spec)
            .await
            .inspect_err(|_| self.apply_backoff(cfg))?;

        self.container_id = Some(id);
        self.last_bootstrap_hash = Some(bootstrap_hash.to_string());
        self.backoff_attempts = 0;
        self.backoff_until = None;

        info!(
            image = %cfg.gateway.envoy_image.as_ref().expect("envoy_image validated"),
            admin_port = cfg.gateway.admin_port,
            listener_port = cfg.gateway.listener_port,
            "envoy gateway (re)started"
        );

        Ok(true)
    }

    async fn is_running(&mut self, runtime: &runtime::DynContainerRuntime) -> anyhow::Result<bool> {
        let Some(id) = self.container_id.as_ref() else {
            return Ok(false);
        };

        match runtime.inspect_container(id).await {
            Ok(details) => Ok(matches!(details.status, runtime::ContainerStatus::Running)),
            Err(runtime::ContainerRuntimeError::NotFound { .. }) => {
                self.container_id = None;
                Ok(false)
            }
            Err(err) => Err(err.into()),
        }
    }

    fn apply_backoff(&mut self, cfg: &AppConfig) {
        self.backoff_attempts = self.backoff_attempts.saturating_add(1);
        let backoff = state::backoff_with_jitter(
            Duration::from_millis(cfg.restart_backoff_ms),
            Duration::from_millis(cfg.restart_backoff_max_ms),
            self.backoff_attempts,
        );
        self.backoff_until = Some(Instant::now() + backoff);
    }
}

fn build_spec(cfg: &AppConfig, bootstrap_path: &str) -> anyhow::Result<ContainerSpec> {
    let image = cfg
        .gateway
        .envoy_image
        .as_ref()
        .expect("envoy_image validated when gateway enabled");
    let mut spec = ContainerSpec::new(image.clone());
    spec.name = Some(GATEWAY_CONTAINER_NAME.into());
    spec.command = Some(vec![
        "envoy".into(),
        "-c".into(),
        "/etc/envoy/envoy.yaml".into(),
        "--service-node".into(),
        cfg.node_id.to_string(),
        "--service-cluster".into(),
        "fledx-gateway".into(),
    ]);

    spec.mounts.push(FileMount {
        host_path: bootstrap_path.into(),
        container_path: "/etc/envoy/envoy.yaml".into(),
        readonly: true,
    });

    spec.ports.push(PortMapping {
        container_port: cfg.gateway.admin_port,
        host_port: cfg.gateway.admin_port,
        protocol: PortProtocol::Tcp,
        host_ip: Some("0.0.0.0".into()),
    });

    spec.ports.push(PortMapping {
        container_port: cfg.gateway.listener_port,
        host_port: cfg.gateway.listener_port,
        protocol: PortProtocol::Tcp,
        host_ip: Some("0.0.0.0".into()),
    });

    spec.labels.push(("fledx.gateway".into(), "true".into()));

    Ok(spec)
}

fn write_bootstrap(cfg: &AppConfig) -> anyhow::Result<String> {
    let dir = PathBuf::from(&cfg.volume_data_dir).join("gateway");
    fs::create_dir_all(&dir).context("create gateway config dir")?;
    let path = dir.join("envoy.yaml");

    let xds_host = cfg
        .gateway
        .xds_host
        .clone()
        .or_else(|| control_plane_host(&cfg.control_plane_url))
        .unwrap_or_else(|| "127.0.0.1".into());

    let bootstrap = format!(
        r#"
node:
  id: {node_id}
  cluster: fledx-gateway
dynamic_resources:
  lds_config:
    resource_api_version: V3
    ads: {{}}
  cds_config:
    resource_api_version: V3
    ads: {{}}
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
    - envoy_grpc:
        cluster_name: xds_cluster
static_resources:
  clusters:
  - name: xds_cluster
    type: STRICT_DNS
    connect_timeout: 1s
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: xds_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {xds_host}
                port_value: {xds_port}
    http2_protocol_options: {{}}
  listeners: []
admin:
  access_log_path: /tmp/envoy.admin.log
  address:
    socket_address:
      address: 0.0.0.0
      port_value: {admin_port}
"#,
        node_id = cfg.node_id,
        xds_host = xds_host,
        xds_port = cfg.gateway.xds_port,
        admin_port = cfg.gateway.admin_port
    );

    let mut file = fs::File::create(&path).context("create envoy bootstrap")?;
    file.write_all(bootstrap.as_bytes())
        .context("write envoy bootstrap")?;

    Ok(path.to_string_lossy().to_string())
}

fn hash_file(path: &str) -> anyhow::Result<String> {
    let data = fs::read(path).context("read bootstrap")?;
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(format!("{:x}", hasher.finalize()))
}

fn control_plane_host(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
}

async fn check_admin(client: &Client, admin_port: u16) -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{admin_port}/ready");
    let res = client
        .get(&url)
        .timeout(Duration::from_secs(1))
        .send()
        .await?;
    if res.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("admin endpoint returned {}", res.status());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{base_config, state_with_runtime_and_config, MockRuntime};

    #[tokio::test]
    async fn starts_envoy_when_enabled() -> anyhow::Result<()> {
        let runtime = std::sync::Arc::new(MockRuntime::default());
        let mut cfg = base_config();
        cfg.gateway.enabled = true;
        cfg.gateway.envoy_image = Some("envoyproxy/envoy:v1.33-latest".into());
        cfg.gateway.listener_port = 10080;
        cfg.gateway.admin_port = 49441;
        cfg.gateway.xds_host = Some("127.0.0.1".into());
        cfg.gateway.xds_port = 18000;
        let tmp = tempfile::tempdir()?;
        cfg.volume_data_dir = tmp.path().to_string_lossy().to_string();
        cfg.allowed_volume_prefixes = vec![cfg.volume_data_dir.clone()];
        let admin_port = cfg.gateway.admin_port;

        let state: SharedState = state_with_runtime_and_config(runtime.clone(), cfg);
        let mut manager = GatewayManager::default();
        let client = Client::new();

        manager.tick(&state, &client).await?;

        let started = runtime.last_started();
        assert_eq!(started.len(), 1);
        let spec = &started[0];
        assert_eq!(spec.name.as_deref(), Some("fledx-gateway"));
        assert!(spec
            .ports
            .iter()
            .any(|p| p.container_port == admin_port && p.host_port == admin_port));
        assert!(spec
            .ports
            .iter()
            .any(|p| p.container_port == 10080 && p.host_port == 10080));

        manager.tick(&state, &client).await?;
        assert_eq!(runtime.start_calls(), 1);

        Ok(())
    }
}
