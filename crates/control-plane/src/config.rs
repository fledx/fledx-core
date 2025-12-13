use serde::{Deserialize, Deserializer};
use std::path::{Component, Path};

pub const ENV_PREFIX: &str = "FLEDX_CP";

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub tunnel: TunnelConfig,
    pub database: DatabaseConfig,
    pub registration: RegistrationConfig,
    pub operator: OperatorAuthConfig,
    pub tokens: TokenConfig,
    pub limits: LimitsConfig,
    pub retention: RetentionConfig,
    pub reachability: ReachabilityConfig,
    pub ports: PortsConfig,
    pub volumes: VolumesConfig,
    pub compatibility: CompatibilityConfig,
    pub features: FeatureFlags,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TunnelConfig {
    /// Hostname/IP advertised to agents for the tunnel entrypoint.
    pub advertised_host: String,
    /// Port advertised to agents for the tunnel entrypoint.
    pub advertised_port: u16,
    /// Whether agents should use TLS when connecting to the tunnel endpoint.
    #[serde(default = "default_tunnel_use_tls")]
    pub use_tls: bool,
    /// Max time allowed for establishing the CONNECT tunnel.
    #[serde(default = "default_tunnel_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// How frequently agents should send heartbeat frames on the tunnel.
    #[serde(default = "default_tunnel_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    /// How long the gateway waits for a heartbeat before closing the tunnel.
    #[serde(default = "default_tunnel_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    /// Header used to carry the bearer token during CONNECT.
    #[serde(default = "default_tunnel_token_header")]
    pub token_header: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationConfig {
    pub token: String,
    pub rate_limit_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperatorAuthConfig {
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    pub tokens: Vec<String>,
    pub header_name: String,
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::String(value) => Ok(value.split(',').map(|s| s.to_string()).collect()),
        StringOrVec::Vec(values) => Ok(values),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {
    pub pepper: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    pub registration_body_bytes: u64,
    pub heartbeat_body_bytes: u64,
    pub config_payload_bytes: u64,
    pub heartbeat_metrics_per_instance: usize,
    pub heartbeat_metrics_total: usize,
    pub resource_metrics_max_series: usize,
    pub max_field_len: usize,
    pub log_tail_limit: u32,
    pub log_tail_max_window_secs: u64,
    pub metrics_summary_limit: u32,
    pub metrics_summary_window_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    pub instance_status_secs: u64,
    pub instance_metrics_secs: u64,
    pub usage_window_secs: u64,
    pub usage_cleanup_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReachabilityConfig {
    pub heartbeat_stale_secs: u64,
    pub sweep_interval_secs: u64,
    pub reschedule_on_unreachable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortsConfig {
    pub auto_assign: bool,
    pub range_start: u16,
    pub range_end: u16,
    #[serde(default)]
    pub public_host: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VolumesConfig {
    pub allowed_host_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompatibilityConfig {
    #[serde(default)]
    pub min_agent_version: Option<String>,
    #[serde(default)]
    pub max_agent_version: Option<String>,
    #[serde(default)]
    pub upgrade_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeatureFlags {
    #[serde(default = "default_true")]
    pub enforce_agent_compatibility: bool,
    #[serde(default)]
    pub migrations_dry_run_on_start: bool,
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
    "x-fledx-tunnel-token".to_string()
}

fn default_tunnel_use_tls() -> bool {
    false
}

fn default_true() -> bool {
    true
}

impl PortsConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.range_start == 0 || self.range_end == 0 {
            anyhow::bail!("ports.range_start and ports.range_end must be > 0");
        }
        if self.range_start > self.range_end {
            anyhow::bail!("ports.range_start must be <= ports.range_end");
        }
        if let Some(host) = &self.public_host {
            if host.trim().is_empty() {
                anyhow::bail!("ports.public_host cannot be empty");
            }
        }
        Ok(())
    }
}

impl VolumesConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        for prefix in &self.allowed_host_prefixes {
            let trimmed = prefix.trim();
            if trimmed.is_empty() {
                anyhow::bail!("volumes.allowed_host_prefixes entries cannot be empty");
            }
            if trimmed != prefix {
                anyhow::bail!(
                    "volumes.allowed_host_prefixes entries must not contain surrounding whitespace"
                );
            }
            if !trimmed.starts_with('/') {
                anyhow::bail!(
                    "volumes.allowed_host_prefixes must be absolute paths starting with '/'"
                );
            }
        }
        Ok(())
    }

    pub fn is_allowed_host_path(&self, path: &str) -> bool {
        if self.allowed_host_prefixes.is_empty() {
            return true;
        }

        let host_path = Path::new(path);
        if host_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return false;
        }

        let resolved_host = match host_path.canonicalize() {
            Ok(p) => p,
            // If the full path does not exist yet, canonicalize its parent so we
            // still resolve symlinks within the allowed prefixes. Fall back to
            // the lexical path when nothing exists so we can permit mounts into
            // soon-to-be-created directories under allowed prefixes.
            Err(_) => host_path
                .parent()
                .and_then(|parent| parent.canonicalize().ok())
                .map(|parent| {
                    parent.join(
                        host_path
                            .file_name()
                            .unwrap_or_else(|| std::ffi::OsStr::new("")),
                    )
                })
                .unwrap_or_else(|| host_path.to_path_buf()),
        };

        self.allowed_host_prefixes.iter().any(|prefix| {
            let prefix_path = Path::new(prefix);
            let resolved_prefix = prefix_path
                .canonicalize()
                .unwrap_or_else(|_| prefix_path.to_path_buf());
            resolved_host.starts_with(&resolved_prefix)
        })
    }
}

impl TunnelConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.advertised_host.trim().is_empty() {
            anyhow::bail!("tunnel.advertised_host cannot be empty");
        }
        if self.advertised_port == 0 {
            anyhow::bail!("tunnel.advertised_port must be > 0");
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

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            advertised_host: "127.0.0.1".into(),
            advertised_port: 7443,
            use_tls: default_tunnel_use_tls(),
            connect_timeout_secs: default_tunnel_connect_timeout_secs(),
            heartbeat_interval_secs: default_tunnel_heartbeat_interval_secs(),
            heartbeat_timeout_secs: default_tunnel_heartbeat_timeout_secs(),
            token_header: default_tunnel_token_header(),
        }
    }
}

impl Default for ReachabilityConfig {
    fn default() -> Self {
        Self {
            heartbeat_stale_secs: 90,
            sweep_interval_secs: 15,
            reschedule_on_unreachable: true,
        }
    }
}

pub fn load() -> anyhow::Result<AppConfig> {
    let env = config::Environment::with_prefix(ENV_PREFIX)
        .separator("__")
        // Keep try_parsing disabled so numeric token strings are not coerced.
        .try_parsing(false);

    let builder = config::Config::builder()
        .add_source(config::File::with_name("config").required(false))
        .add_source(env)
        .set_default("server.host", "0.0.0.0")?
        .set_default("server.port", 8080)?
        .set_default("tunnel.advertised_host", "127.0.0.1")?
        .set_default("tunnel.advertised_port", 7443)?
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
        .set_default("database.url", "sqlite://data/control-plane.db")?
        .set_default("registration.token", "dev-registration-token")?
        .set_default("registration.rate_limit_per_minute", 30)?
        .set_default("operator.tokens", vec!["dev-operator-token"])?
        .set_default("operator.header_name", "authorization")?
        .set_default("tokens.pepper", "dev-token-pepper")?
        .set_default("limits.registration_body_bytes", 16 * 1024u64)?
        .set_default("limits.heartbeat_body_bytes", 64 * 1024u64)?
        .set_default("limits.config_payload_bytes", 128 * 1024u64)?
        .set_default("limits.heartbeat_metrics_per_instance", 60i64)?
        .set_default("limits.heartbeat_metrics_total", 500i64)?
        .set_default("limits.resource_metrics_max_series", 500i64)?
        .set_default("limits.max_field_len", 255)?
        .set_default("limits.log_tail_limit", 100u32)?
        .set_default("limits.log_tail_max_window_secs", 300u64)?
        .set_default("limits.metrics_summary_limit", 16u32)?
        .set_default("limits.metrics_summary_window_secs", 60u64)?
        .set_default("retention.instance_status_secs", 24 * 60 * 60)?
        .set_default("retention.instance_metrics_secs", 10 * 60u64)?
        .set_default("retention.usage_window_secs", 7 * 24 * 60 * 60u64)?
        .set_default("retention.usage_cleanup_interval_secs", 5 * 60u64)?
        .set_default("reachability.heartbeat_stale_secs", 90)?
        .set_default("reachability.sweep_interval_secs", 15)?
        .set_default("reachability.reschedule_on_unreachable", true)?
        .set_default("ports.auto_assign", false)?
        .set_default("ports.range_start", 30000)?
        .set_default("ports.range_end", 40000)?
        .set_default("volumes.allowed_host_prefixes", Vec::<String>::new())?
        .set_default("compatibility.min_agent_version", Option::<String>::None)?
        .set_default("compatibility.max_agent_version", Option::<String>::None)?
        .set_default("compatibility.upgrade_url", Option::<String>::None)?
        .set_default("features.enforce_agent_compatibility", true)?
        .set_default("features.migrations_dry_run_on_start", false)?;

    let cfg = builder.build()?;
    let mut app: AppConfig = cfg.try_deserialize()?;
    app.tunnel.advertised_host = app.tunnel.advertised_host.trim().to_string();
    app.tunnel.token_header = app.tunnel.token_header.trim().to_string();
    if let Some(host) = app.ports.public_host.take() {
        let trimmed = host.trim();
        if trimmed.is_empty() {
            anyhow::bail!("ports.public_host cannot be empty");
        }
        app.ports.public_host = Some(trimmed.to_string());
    }
    app.ports.validate()?;
    app.volumes.validate()?;
    app.tunnel.validate()?;
    Ok(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, panic, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_control_plane_env(vars: &[(&str, &str)], test: impl FnOnce() + panic::UnwindSafe) {
        let _guard = ENV_LOCK.lock().expect("env mutex poisoned");
        let prefix = format!("{}__", ENV_PREFIX);

        let existing: Vec<(String, String)> = env::vars()
            .filter(|(key, _)| key.starts_with(&prefix))
            .collect();

        for (key, _) in &existing {
            env::remove_var(key);
        }

        for (key, value) in vars {
            env::set_var(key, value);
        }

        let result = panic::catch_unwind(test);

        for (key, _) in vars {
            env::remove_var(key);
        }

        for (key, value) in existing {
            env::set_var(key, value);
        }

        result.unwrap();
    }

    #[test]
    fn numeric_tokens_remain_strings() {
        with_control_plane_env(
            &[
                ("FLEDX_CP__REGISTRATION__TOKEN", "123456"),
                ("FLEDX_CP__OPERATOR__TOKENS", "1111,2222"),
                ("FLEDX_CP__TOKENS__PEPPER", "9999"),
            ],
            || {
                let cfg = load().expect("config loads");

                assert_eq!(cfg.registration.token, "123456");
                assert_eq!(
                    cfg.operator.tokens,
                    vec!["1111".to_string(), "2222".to_string()]
                );
                assert_eq!(cfg.tokens.pepper, "9999");
            },
        );
    }

    #[test]
    fn numeric_and_bool_env_values_still_parse() {
        with_control_plane_env(
            &[
                ("FLEDX_CP__SERVER__PORT", "9090"),
                ("FLEDX_CP__REGISTRATION__RATE_LIMIT_PER_MINUTE", "45"),
                ("FLEDX_CP__LIMITS__MAX_FIELD_LEN", "512"),
                ("FLEDX_CP__REACHABILITY__RESCHEDULE_ON_UNREACHABLE", "false"),
            ],
            || {
                let cfg = load().expect("config loads");

                assert_eq!(cfg.server.port, 9090);
                assert_eq!(cfg.registration.rate_limit_per_minute, 45);
                assert_eq!(cfg.limits.max_field_len, 512);
                assert!(!cfg.reachability.reschedule_on_unreachable);
            },
        );
    }

    #[test]
    fn feature_flags_default_and_env_overrides() {
        let cfg = load().expect("config loads");
        assert!(cfg.features.enforce_agent_compatibility);
        assert!(!cfg.features.migrations_dry_run_on_start);

        with_control_plane_env(
            &[
                ("FLEDX_CP__FEATURES__ENFORCE_AGENT_COMPATIBILITY", "false"),
                ("FLEDX_CP__FEATURES__MIGRATIONS_DRY_RUN_ON_START", "true"),
            ],
            || {
                let cfg = load().expect("config loads");
                assert!(!cfg.features.enforce_agent_compatibility);
                assert!(cfg.features.migrations_dry_run_on_start);
            },
        );
    }
}
