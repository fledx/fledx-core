use config::{Value, ValueKind};
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use uuid::Uuid;

pub const ENV_PREFIX: &str = "FLEDX_AGENT";

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub control_plane_url: String,
    pub node_id: Uuid,
    pub node_token: String,
    pub secrets_dir: String,
    pub secrets_prefix: String,
    pub heartbeat_interval_secs: u64,
    pub heartbeat_timeout_secs: u64,
    pub heartbeat_max_retries: u32,
    pub heartbeat_backoff_ms: u64,
    pub heartbeat_max_metrics: usize,
    pub reconcile_interval_secs: u64,
    pub docker_reconnect_backoff_ms: u64,
    pub docker_reconnect_backoff_max_ms: u64,
    pub restart_backoff_ms: u64,
    pub restart_backoff_max_ms: u64,
    pub restart_failure_limit: u32,
    pub resource_sample_interval_secs: u64,
    pub resource_sample_window: usize,
    pub resource_sample_max_concurrency: usize,
    pub resource_sample_backoff_ms: u64,
    pub resource_sample_backoff_max_ms: u64,
    pub allow_insecure_http: bool,
    pub tls_insecure_skip_verify: bool,
    pub ca_cert_path: Option<String>,
    /// Directory where service identity bundles (cert/key/ca) are stored.
    pub service_identity_dir: String,
    pub metrics_host: String,
    pub metrics_port: u16,
    pub arch: String,
    pub os: String,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub tunnel_routes: Vec<TunnelRoute>,
    #[serde(default)]
    pub public_host: Option<String>,
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub allowed_volume_prefixes: Vec<String>,
    #[serde(default)]
    pub volume_data_dir: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub capacity_cpu_millis: Option<u32>,
    #[serde(default)]
    pub capacity_memory_bytes: Option<u64>,
    #[serde(default)]
    pub force_empty_labels: bool,
    #[serde(default)]
    pub force_empty_capacity: bool,
    #[serde(default)]
    pub cleanup_on_shutdown: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Whether the node should act as an Envoy gateway.
    pub enabled: bool,
    /// Envoy image tag to run for the gateway (required if enabled=true).
    pub envoy_image: Option<String>,
    /// Port Envoy should bind for admin/metrics (exposed on host).
    pub admin_port: u16,
    /// Port Envoy should bind for ingress traffic on the host.
    pub listener_port: u16,
    /// Hostname/IP of the control-plane xDS server; falls back to control_plane_url host.
    pub xds_host: Option<String>,
    /// Port of the control-plane xDS server.
    pub xds_port: u16,
}

impl GatewayConfig {
    pub fn validate(&self, has_public_endpoint: bool) -> anyhow::Result<()> {
        // Gateway is auto-enabled if explicit flag OR public endpoint is configured
        let requires_gateway = self.enabled || has_public_endpoint;
        if requires_gateway && self.envoy_image.is_none() {
            anyhow::bail!(
                "gateway.envoy_image is required when gateway is enabled (via gateway.enabled=true, public_ip, or public_host)"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TunnelConfig {
    /// Gateway host or IP that terminates the CONNECT tunnel.
    pub endpoint_host: String,
    /// Gateway port that terminates the CONNECT tunnel.
    pub endpoint_port: u16,
    /// Whether to use TLS (HTTPS) when opening the tunnel.
    #[serde(default = "default_tunnel_use_tls")]
    pub use_tls: bool,
    /// Maximum seconds allowed for establishing the tunnel.
    #[serde(default = "default_tunnel_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// Expected heartbeat interval on the tunnel.
    #[serde(default = "default_tunnel_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    /// Disconnect if no heartbeat within this window.
    #[serde(default = "default_tunnel_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    /// Header carrying the node token when opening the tunnel.
    #[serde(default = "default_tunnel_token_header")]
    pub token_header: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TunnelRoute {
    pub path_prefix: String,
    pub target_host: String,
    pub target_port: u16,
}

impl TunnelRoute {
    fn normalize(&mut self) {
        self.path_prefix = normalize_path_prefix(&self.path_prefix);
        self.target_host = self.target_host.trim().to_string();
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.path_prefix.is_empty() {
            anyhow::bail!("tunnel route path_prefix cannot be empty");
        }
        if !self.path_prefix.starts_with('/') {
            anyhow::bail!("tunnel route path_prefix must start with '/'");
        }
        if self.target_host.trim().is_empty() {
            anyhow::bail!("tunnel route target_host cannot be empty");
        }
        if self.target_port == 0 {
            anyhow::bail!("tunnel route target_port must be > 0");
        }
        Ok(())
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            envoy_image: None,
            admin_port: default_gateway_admin_port(),
            listener_port: default_gateway_listener_port(),
            xds_host: None,
            xds_port: default_gateway_xds_port(),
        }
    }
}

fn normalize_path_prefix(prefix: &str) -> String {
    let mut normalized = prefix.trim().to_string();
    if normalized.is_empty() {
        return "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

fn default_gateway_admin_port() -> u16 {
    9_901
}

fn default_gateway_listener_port() -> u16 {
    10_000
}

fn default_gateway_xds_port() -> u16 {
    18_000
}

fn default_tunnel_connect_timeout_secs() -> u64 {
    10
}

fn default_tunnel_heartbeat_interval_secs() -> u64 {
    30
}

fn default_tunnel_heartbeat_timeout_secs() -> u64 {
    90
}

fn default_tunnel_token_header() -> String {
    "x-fledx-tunnel-token".into()
}

fn default_tunnel_use_tls() -> bool {
    false
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            endpoint_host: "127.0.0.1".into(),
            endpoint_port: 7443,
            use_tls: default_tunnel_use_tls(),
            connect_timeout_secs: default_tunnel_connect_timeout_secs(),
            heartbeat_interval_secs: default_tunnel_heartbeat_interval_secs(),
            heartbeat_timeout_secs: default_tunnel_heartbeat_timeout_secs(),
            token_header: default_tunnel_token_header(),
        }
    }
}

enum EnvKind {
    String,
    List,
    Labels,
}

// (ENV_NAME, config_key, kind)
const ENV_OVERRIDES: &[(&str, &str, EnvKind)] = &[
    (
        "FLEDX_AGENT_CONTROL_PLANE_URL",
        "control_plane_url",
        EnvKind::String,
    ),
    ("FLEDX_AGENT_NODE_ID", "node_id", EnvKind::String),
    ("FLEDX_AGENT_NODE_TOKEN", "node_token", EnvKind::String),
    ("FLEDX_AGENT_SECRETS_DIR", "secrets_dir", EnvKind::String),
    (
        "FLEDX_AGENT_SECRETS_PREFIX",
        "secrets_prefix",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_HEARTBEAT_INTERVAL_SECS",
        "heartbeat_interval_secs",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_HEARTBEAT_TIMEOUT_SECS",
        "heartbeat_timeout_secs",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_HEARTBEAT_MAX_RETRIES",
        "heartbeat_max_retries",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_HEARTBEAT_BACKOFF_MS",
        "heartbeat_backoff_ms",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_HEARTBEAT_MAX_METRICS",
        "heartbeat_max_metrics",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RECONCILE_INTERVAL_SECS",
        "reconcile_interval_secs",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_DOCKER_RECONNECT_BACKOFF_MS",
        "docker_reconnect_backoff_ms",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_DOCKER_RECONNECT_BACKOFF_MAX_MS",
        "docker_reconnect_backoff_max_ms",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RESTART_BACKOFF_MS",
        "restart_backoff_ms",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RESTART_BACKOFF_MAX_MS",
        "restart_backoff_max_ms",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RESTART_FAILURE_LIMIT",
        "restart_failure_limit",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RESOURCE_SAMPLE_INTERVAL_SECS",
        "resource_sample_interval_secs",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RESOURCE_SAMPLE_WINDOW",
        "resource_sample_window",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RESOURCE_SAMPLE_MAX_CONCURRENCY",
        "resource_sample_max_concurrency",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RESOURCE_SAMPLE_BACKOFF_MS",
        "resource_sample_backoff_ms",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_RESOURCE_SAMPLE_BACKOFF_MAX_MS",
        "resource_sample_backoff_max_ms",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_ALLOW_INSECURE_HTTP",
        "allow_insecure_http",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_TLS_INSECURE_SKIP_VERIFY",
        "tls_insecure_skip_verify",
        EnvKind::String,
    ),
    ("FLEDX_AGENT_CA_CERT_PATH", "ca_cert_path", EnvKind::String),
    (
        "FLEDX_AGENT_SERVICE_IDENTITY_DIR",
        "service_identity_dir",
        EnvKind::String,
    ),
    ("FLEDX_AGENT_METRICS_HOST", "metrics_host", EnvKind::String),
    ("FLEDX_AGENT_METRICS_PORT", "metrics_port", EnvKind::String),
    ("FLEDX_AGENT_ARCH", "arch", EnvKind::String),
    ("FLEDX_AGENT_OS", "os", EnvKind::String),
    (
        "FLEDX_AGENT_TUNNEL_ENDPOINT_HOST",
        "tunnel.endpoint_host",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_TUNNEL_ENDPOINT_PORT",
        "tunnel.endpoint_port",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_TUNNEL_USE_TLS",
        "tunnel.use_tls",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_TUNNEL_CONNECT_TIMEOUT_SECS",
        "tunnel.connect_timeout_secs",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_TUNNEL_HEARTBEAT_INTERVAL_SECS",
        "tunnel.heartbeat_interval_secs",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_TUNNEL_HEARTBEAT_TIMEOUT_SECS",
        "tunnel.heartbeat_timeout_secs",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_TUNNEL_TOKEN_HEADER",
        "tunnel.token_header",
        EnvKind::String,
    ),
    ("FLEDX_AGENT_PUBLIC_HOST", "public_host", EnvKind::String),
    ("FLEDX_AGENT_PUBLIC_IP", "public_ip", EnvKind::String),
    (
        "FLEDX_AGENT_GATEWAY_ENABLED",
        "gateway.enabled",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_GATEWAY_ENVOY_IMAGE",
        "gateway.envoy_image",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_GATEWAY_ADMIN_PORT",
        "gateway.admin_port",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_GATEWAY_LISTENER_PORT",
        "gateway.listener_port",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_GATEWAY_XDS_HOST",
        "gateway.xds_host",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_GATEWAY_XDS_PORT",
        "gateway.xds_port",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES",
        "allowed_volume_prefixes",
        EnvKind::List,
    ),
    ("FLEDX_AGENT_LABELS", "labels", EnvKind::Labels),
    (
        "FLEDX_AGENT_VOLUME_DATA_DIR",
        "volume_data_dir",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_CAPACITY_CPU_MILLIS",
        "capacity_cpu_millis",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_CAPACITY_MEMORY_BYTES",
        "capacity_memory_bytes",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_FORCE_EMPTY_LABELS",
        "force_empty_labels",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_FORCE_EMPTY_CAPACITY",
        "force_empty_capacity",
        EnvKind::String,
    ),
    (
        "FLEDX_AGENT_CLEANUP_ON_SHUTDOWN",
        "cleanup_on_shutdown",
        EnvKind::String,
    ),
];

impl TunnelConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.endpoint_host.trim().is_empty() {
            anyhow::bail!("tunnel.endpoint_host cannot be empty");
        }
        if self.endpoint_port == 0 {
            anyhow::bail!("tunnel.endpoint_port must be > 0");
        }
        if self.connect_timeout_secs == 0 {
            anyhow::bail!("tunnel.connect_timeout_secs must be > 0");
        }
        if self.heartbeat_interval_secs == 0 {
            anyhow::bail!("tunnel.heartbeat_interval_secs must be > 0");
        }
        if self.heartbeat_timeout_secs <= self.heartbeat_interval_secs {
            anyhow::bail!("tunnel.heartbeat_timeout_secs must exceed heartbeat interval");
        }
        if self.token_header.trim().is_empty() {
            anyhow::bail!("tunnel.token_header cannot be empty");
        }
        Ok(())
    }
}

pub fn load() -> anyhow::Result<AppConfig> {
    let mut builder = config::Config::builder()
        .add_source(config::File::with_name("config").required(false))
        // Gateway defaults
        .set_default("gateway.enabled", false)?
        .set_default("gateway.admin_port", default_gateway_admin_port())?
        .set_default("gateway.listener_port", default_gateway_listener_port())?
        .set_default("gateway.xds_host", Option::<String>::None)?
        .set_default("gateway.xds_port", default_gateway_xds_port())?
        .set_default("tunnel.endpoint_host", "127.0.0.1")?
        .set_default("tunnel.endpoint_port", 7443)?
        .set_default("tunnel.use_tls", default_tunnel_use_tls())?
        .set_default(
            "tunnel.connect_timeout_secs",
            default_tunnel_connect_timeout_secs(),
        )?
        .set_default(
            "tunnel.heartbeat_interval_secs",
            default_tunnel_heartbeat_interval_secs(),
        )?
        .set_default(
            "tunnel.heartbeat_timeout_secs",
            default_tunnel_heartbeat_timeout_secs(),
        )?
        .set_default("tunnel.token_header", default_tunnel_token_header())?
        .set_default("control_plane_url", "https://127.0.0.1:8443")?
        .set_default("secrets_dir", "/var/run/secrets")?
        .set_default("secrets_prefix", "FLEDX_SECRET_")?
        .set_default("heartbeat_interval_secs", 30)?
        .set_default("heartbeat_timeout_secs", 5)?
        .set_default("heartbeat_max_retries", 3)?
        .set_default("heartbeat_backoff_ms", 500)?
        .set_default("heartbeat_max_metrics", 50)?
        .set_default("reconcile_interval_secs", 10)?
        .set_default("docker_reconnect_backoff_ms", 500)?
        .set_default("docker_reconnect_backoff_max_ms", 10_000)?
        .set_default("restart_backoff_ms", 1_000)?
        .set_default("restart_backoff_max_ms", 30_000)?
        .set_default("restart_failure_limit", 5)?
        .set_default("resource_sample_interval_secs", 30)?
        .set_default("resource_sample_window", 120)?
        .set_default("resource_sample_max_concurrency", 2)?
        .set_default("resource_sample_backoff_ms", 1_000)?
        .set_default("resource_sample_backoff_max_ms", 10_000)?
        .set_default("allow_insecure_http", false)?
        .set_default("tls_insecure_skip_verify", false)?
        .set_default("service_identity_dir", "/var/lib/fledx/service-identities")?
        .set_default("metrics_host", "127.0.0.1")?
        .set_default("metrics_port", 9091)?
        .set_default("public_host", Option::<String>::None)?
        .set_default("public_ip", Option::<String>::None)?
        .set_default("allowed_volume_prefixes", vec!["/var/lib/fledx/volumes"])? // safe default
        .set_default("volume_data_dir", "/var/lib/fledx")?
        .set_default("arch", std::env::consts::ARCH)?
        .set_default("os", std::env::consts::OS)?
        .set_default("labels", HashMap::<String, String>::new())?
        .set_default("force_empty_labels", false)?
        .set_default("force_empty_capacity", false)?
        .set_default("cleanup_on_shutdown", false)?
        // gateway defaults set above
        ;

    // Override with single-underscore environment variables.
    for (env_key, cfg_key, kind) in ENV_OVERRIDES {
        if let Ok(value) = env::var(env_key) {
            match kind {
                EnvKind::List => {
                    let entries: Vec<String> = value
                        .split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                    builder = builder.set_override(cfg_key, entries)?;
                }
                EnvKind::Labels => {
                    let mut labels = HashMap::new();
                    for entry in value.split(',') {
                        let trimmed = entry.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if let Some((k, v)) = trimmed.split_once('=') {
                            labels.insert(k.trim().to_string(), v.trim().to_string());
                        }
                    }
                    builder = builder.set_override(cfg_key, labels)?;
                }
                EnvKind::String => {
                    builder = builder.set_override(cfg_key, value)?;
                }
            }
        }
    }

    let mut cfg = builder.build()?;

    // Normalize allowed_volume_prefixes to always deserialize as a Vec<String>.
    normalize_allowed_volume_prefixes(&mut cfg.cache);

    let mut app: AppConfig = cfg.try_deserialize()?;
    app.tunnel.endpoint_host = app.tunnel.endpoint_host.trim().to_string();
    app.tunnel.token_header = app.tunnel.token_header.trim().to_string();
    app.tunnel.validate()?;
    let has_public_endpoint = app.public_ip.is_some() || app.public_host.is_some();
    app.gateway.validate(has_public_endpoint)?;
    for route in &mut app.tunnel_routes {
        route.normalize();
        route.validate()?;
    }
    Ok(app)
}

/// Ensure `allowed_volume_prefixes` is always an array, even when provided as
/// a single string or as indexed env vars (which the config crate turns into a
/// table).
fn normalize_allowed_volume_prefixes(root: &mut Value) {
    let ValueKind::Table(root_table) = &mut root.kind else {
        return;
    };

    let Some(allowed) = root_table.get_mut("allowed_volume_prefixes") else {
        return;
    };

    match &allowed.kind {
        ValueKind::Array(_) => {
            // Already in the desired shape.
        }
        ValueKind::Table(t) => {
            // Turn `{ "0": "...", "1": "..." }` into an ordered array.
            let mut entries: Vec<(usize, Value)> = t
                .iter()
                .filter_map(|(k, v)| k.parse::<usize>().ok().map(|i| (i, v.clone())))
                .collect();
            entries.sort_by_key(|(i, _)| *i);
            let arr: Vec<Value> = entries.into_iter().map(|(_, v)| v).collect();
            allowed.kind = ValueKind::Array(arr);
        }
        ValueKind::String(s) => {
            // Wrap single string into a one-element array.
            let origin = allowed.origin().map(|s| s.to_string());
            let v = Value::new(origin.as_ref(), ValueKind::String(s.clone()));
            allowed.kind = ValueKind::Array(vec![v]);
        }
        _ => {
            // Leave other shapes untouched; deserializer will surface any error.
        }
    }
}
