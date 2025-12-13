use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use crate::{
    config::{LimitsConfig, PortsConfig, VolumesConfig},
    error::AppError,
    persistence as db,
};
use common::api::{DeploymentHealth, HealthProbe, HealthProbeKind};
use uuid::Uuid;

use crate::error::ApiResult;
use common::api::DeploymentSpec;

pub const MAX_CONFIG_VALUE_LEN: usize = 4096;
pub const MAX_CONFIG_FILE_PATH_LEN: usize = 512;

pub fn normalize_inventory(
    arch: Option<String>,
    os: Option<String>,
    labels: Option<HashMap<String, String>>,
    capacity: Option<db::CapacityHints>,
    limits: &LimitsConfig,
) -> ApiResult<db::NodeInventoryUpdate> {
    let arch = normalize_opt_lower("arch", arch, limits.max_field_len)?;
    let os = normalize_opt_lower("os", os, limits.max_field_len)?;
    let labels = normalize_labels(labels, limits)?;
    let capacity = normalize_capacity(capacity, true)?;

    Ok(db::NodeInventoryUpdate {
        arch,
        os,
        labels,
        capacity,
        public_ip: None,
        public_host: None,
    })
}

pub fn normalize_public_ingress(
    public_ip: Option<String>,
    public_host: Option<String>,
    limits: &LimitsConfig,
) -> ApiResult<(Option<String>, Option<String>)> {
    let mut normalized_ip = None;
    if let Some(value) = public_ip {
        let trimmed = value.trim().to_string();
        validate_opt_str("public_ip", Some(&trimmed), limits.max_field_len)?;
        let parsed = trimmed
            .parse::<IpAddr>()
            .map_err(|_| AppError::bad_request("public_ip must be a valid IPv4 or IPv6 address"))?;
        normalized_ip = Some(parsed.to_string());
    }

    let mut normalized_host = None;
    if let Some(value) = public_host {
        let trimmed = value.trim();
        validate_opt_str("public_host", Some(trimmed), limits.max_field_len)?;
        if trimmed.chars().any(char::is_whitespace) {
            return Err(AppError::bad_request(
                "public_host cannot contain whitespace",
            ));
        }
        normalized_host = Some(trimmed.to_ascii_lowercase());
    }

    Ok((normalized_ip, normalized_host))
}

pub fn normalize_constraints(
    constraints: Option<db::PlacementConstraints>,
    limits: &LimitsConfig,
) -> ApiResult<Option<db::PlacementConstraints>> {
    let Some(mut constraints) = constraints else {
        return Ok(None);
    };

    constraints.arch =
        normalize_opt_lower("constraints.arch", constraints.arch, limits.max_field_len)?;
    constraints.os = normalize_opt_lower("constraints.os", constraints.os, limits.max_field_len)?;
    constraints.labels = normalize_labels(Some(constraints.labels), limits)?.unwrap_or_default();
    constraints.capacity = normalize_capacity(constraints.capacity, false)?;

    if constraints.arch.is_none()
        && constraints.os.is_none()
        && constraints.labels.is_empty()
        && constraints.capacity.is_none()
        && !constraints.requires_public_ip
    {
        return Ok(None);
    }

    Ok(Some(constraints))
}

pub fn normalize_opt_lower(
    field: &str,
    value: Option<String>,
    max_len: usize,
) -> ApiResult<Option<String>> {
    let value = value
        .map(|val| val.trim().to_string())
        .filter(|val| !val.is_empty());
    validate_opt_str(field, value.as_deref(), max_len)?;
    Ok(value.map(|val| val.to_ascii_lowercase()))
}

pub fn normalize_labels(
    labels: Option<HashMap<String, String>>,
    limits: &LimitsConfig,
) -> ApiResult<Option<HashMap<String, String>>> {
    let Some(labels) = labels else {
        return Ok(None);
    };

    let mut normalized = HashMap::new();
    for (key, value) in labels {
        let key_trimmed = key.trim();
        if key_trimmed.is_empty() {
            return Err(AppError::bad_request("label key cannot be empty"));
        }
        if key_trimmed.len() > limits.max_field_len {
            return Err(AppError::bad_request("label key too long"));
        }

        let value_trimmed = value.trim();
        if value_trimmed.is_empty() {
            return Err(AppError::bad_request("label value cannot be empty"));
        }
        if value_trimmed.len() > limits.max_field_len {
            return Err(AppError::bad_request("label value too long"));
        }

        let key_norm = key_trimmed.to_ascii_lowercase();
        if normalized
            .insert(key_norm.clone(), value_trimmed.to_string())
            .is_some()
        {
            return Err(AppError::bad_request(format!(
                "duplicate label key '{}'",
                key_norm
            )));
        }
    }

    Ok(Some(normalized))
}

pub fn normalize_capacity(
    capacity: Option<db::CapacityHints>,
    allow_empty: bool,
) -> ApiResult<Option<db::CapacityHints>> {
    let Some(capacity) = capacity else {
        return Ok(None);
    };

    if let Some(cpu) = capacity.cpu_millis {
        if cpu == 0 {
            return Err(AppError::bad_request(
                "cpu_millis must be greater than zero",
            ));
        }
    }
    if let Some(memory) = capacity.memory_bytes {
        if memory == 0 {
            return Err(AppError::bad_request(
                "memory_bytes must be greater than zero",
            ));
        }
    }

    if capacity.cpu_millis.is_none() && capacity.memory_bytes.is_none() && !allow_empty {
        return Ok(None);
    }

    Ok(Some(capacity))
}

pub(crate) fn validate_registration(
    req: &crate::services::nodes::RegistrationRequest,
    limits: &LimitsConfig,
) -> ApiResult<db::NodeInventoryUpdate> {
    validate_opt_str("name", req.name.as_deref(), limits.max_field_len)?;
    let mut inventory = normalize_inventory(
        req.arch.clone(),
        req.os.clone(),
        req.labels.clone(),
        req.capacity.clone(),
        limits,
    )?;
    let (public_ip, public_host) =
        normalize_public_ingress(req.public_ip.clone(), req.public_host.clone(), limits)?;
    inventory.public_ip = public_ip;
    inventory.public_host = public_host;
    Ok(inventory)
}

pub(crate) fn validate_heartbeat(
    req: &crate::services::nodes::HeartbeatRequest,
    limits: &LimitsConfig,
) -> ApiResult<Option<db::NodeInventoryUpdate>> {
    let mut total_metrics = 0usize;
    for inst in &req.containers {
        validate_opt_str(
            "container_id",
            inst.container_id.as_deref(),
            limits.max_field_len,
        )?;
        validate_opt_str("message", inst.message.as_deref(), limits.max_field_len)?;

        if limits.heartbeat_metrics_per_instance > 0
            && inst.metrics.len() > limits.heartbeat_metrics_per_instance
        {
            return Err(AppError::bad_request(format!(
                "metrics samples per instance exceed limit ({} > {})",
                inst.metrics.len(),
                limits.heartbeat_metrics_per_instance
            )));
        }

        for sample in &inst.metrics {
            if !sample.cpu_percent.is_finite() || sample.cpu_percent < 0.0 {
                return Err(AppError::bad_request(
                    "metrics.cpu_percent must be finite and non-negative",
                ));
            }

            ensure_within_i64("metrics.memory_bytes", sample.memory_bytes)?;
            ensure_within_i64("metrics.network_rx_bytes", sample.network_rx_bytes)?;
            ensure_within_i64("metrics.network_tx_bytes", sample.network_tx_bytes)?;

            if let Some(bytes) = sample.blk_read_bytes {
                ensure_within_i64("metrics.blk_read_bytes", bytes)?;
            }

            if let Some(bytes) = sample.blk_write_bytes {
                ensure_within_i64("metrics.blk_write_bytes", bytes)?;
            }
        }

        total_metrics += inst.metrics.len();
    }

    if limits.heartbeat_metrics_total > 0 && total_metrics > limits.heartbeat_metrics_total {
        return Err(AppError::bad_request(format!(
            "metrics samples across heartbeat exceed limit ({} > {})",
            total_metrics, limits.heartbeat_metrics_total
        )));
    }

    let inventory = req
        .inventory
        .clone()
        .map(|inv| normalize_inventory(inv.arch, inv.os, inv.labels, inv.capacity, limits))
        .transpose()?;
    let (public_ip, public_host) =
        normalize_public_ingress(req.public_ip.clone(), req.public_host.clone(), limits)?;

    let combined = match inventory {
        Some(mut inv) => {
            inv.public_ip = public_ip;
            inv.public_host = public_host;
            Some(inv)
        }
        None => {
            if public_ip.is_none() && public_host.is_none() {
                None
            } else {
                Some(db::NodeInventoryUpdate {
                    public_ip,
                    public_host,
                    ..Default::default()
                })
            }
        }
    };

    Ok(combined)
}

fn ensure_within_i64(field: &str, value: u64) -> ApiResult<()> {
    if value > i64::MAX as u64 {
        return Err(AppError::bad_request(format!(
            "{field} exceeds maximum supported value"
        )));
    }

    Ok(())
}

pub(crate) fn validate_deployment_spec(
    spec: &DeploymentSpec,
    limits: &LimitsConfig,
    port_cfg: &PortsConfig,
    vol_cfg: &VolumesConfig,
) -> ApiResult<()> {
    if let Some(replicas) = spec.replicas {
        if replicas == 0 {
            return Err(AppError::bad_request("replicas must be at least 1"));
        }
    }
    validate_opt_str("name", spec.name.as_deref(), limits.max_field_len)?;
    validate_required_str("image", &spec.image, limits.max_field_len)?;
    if let Some(command) = spec.command.as_ref() {
        for arg in command {
            validate_opt_str("command", Some(arg.as_str()), limits.max_field_len)?;
        }
    }

    if let Some(env) = spec.env.as_ref() {
        for (key, value) in env {
            validate_opt_str("env key", Some(key.as_str()), limits.max_field_len)?;
            if value.len() > limits.max_field_len {
                return Err(AppError::bad_request("env value too long"));
            }
        }
    }

    if let Some(secret_env) = spec.secret_env.as_ref() {
        validate_secret_env(secret_env, limits)?;
    }

    if let Some(secret_files) = spec.secret_files.as_ref() {
        validate_secret_files(secret_files, limits)?;
    }

    if let Some(ports) = spec.ports.as_ref() {
        validate_ports(ports, limits, port_cfg)?;
    }

    if spec.requires_public_ip
        && !spec
            .ports
            .as_deref()
            .map(|ports| ports.iter().any(|port| port.expose))
            .unwrap_or(false)
    {
        return Err(AppError::bad_request(
            "requires_public_ip requires at least one port with expose=true",
        ));
    }

    if let Some(volumes) = spec.volumes.as_ref() {
        validate_volumes(volumes, limits, vol_cfg)?;
    }

    Ok(())
}

pub fn validate_ports(
    ports: &[db::PortMapping],
    limits: &LimitsConfig,
    port_cfg: &PortsConfig,
) -> ApiResult<()> {
    for port in ports {
        if port.container_port == 0 {
            return Err(AppError::bad_request(
                "container_port must be between 1 and 65535",
            ));
        }
        if let Some(host_port) = port.host_port {
            if host_port == 0 {
                return Err(AppError::bad_request(
                    "host_port must be between 1 and 65535",
                ));
            }
        } else if !port_cfg.auto_assign {
            let message = if port.expose {
                "expose requires host_port when auto assignment is disabled"
            } else {
                "host_port is required when auto assignment is disabled"
            };
            return Err(AppError::bad_request(message));
        }

        validate_protocol(&port.protocol)?;
        validate_opt_str("host_ip", port.host_ip.as_deref(), limits.max_field_len)?;
    }

    Ok(())
}

pub fn validate_volumes(
    volumes: &[db::VolumeMount],
    limits: &LimitsConfig,
    vol_cfg: &VolumesConfig,
) -> ApiResult<()> {
    if vol_cfg.allowed_host_prefixes.is_empty() {
        return Err(AppError::bad_request(
            "volume mounts are disabled; configure volumes.allowed_host_prefixes",
        ));
    }

    for volume in volumes {
        let host_path = volume.host_path.trim();
        let container_path = volume.container_path.trim();

        if host_path.is_empty() {
            return Err(AppError::bad_request("host_path is required"));
        }

        if container_path.is_empty() {
            return Err(AppError::bad_request("container_path is required"));
        }

        if host_path.len() > limits.max_field_len || container_path.len() > limits.max_field_len {
            return Err(AppError::bad_request("volume paths too long"));
        }

        if !Path::new(host_path).is_absolute() {
            return Err(AppError::bad_request("host_path must be an absolute path"));
        }

        if !Path::new(container_path).is_absolute() {
            return Err(AppError::bad_request(
                "container_path must be an absolute path",
            ));
        }

        if !vol_cfg.is_allowed_host_path(host_path) {
            return Err(AppError::bad_request(
                "host_path is not allowed by volume configuration",
            ));
        }
    }

    Ok(())
}

pub fn normalize_volumes(
    volumes: Option<Vec<db::VolumeMount>>,
    limits: &LimitsConfig,
    vol_cfg: &VolumesConfig,
) -> ApiResult<Option<Vec<db::VolumeMount>>> {
    let Some(volumes) = volumes else {
        return Ok(None);
    };

    let mut normalized = Vec::with_capacity(volumes.len());
    for volume in volumes {
        let host_path = volume.host_path.trim().to_string();
        let container_path = volume.container_path.trim().to_string();

        normalized.push(db::VolumeMount {
            host_path,
            container_path,
            read_only: volume.read_only,
        });
    }

    validate_volumes(&normalized, limits, vol_cfg)?;

    Ok(Some(normalized))
}

pub fn normalize_health(
    health: Option<DeploymentHealth>,
    limits: &LimitsConfig,
) -> ApiResult<Option<DeploymentHealth>> {
    let Some(health) = health else {
        return Ok(None);
    };

    let mut normalized = DeploymentHealth {
        liveness: None,
        readiness: None,
    };

    if let Some(probe) = health.liveness {
        normalized.liveness = Some(normalize_health_probe(probe, limits)?);
    }
    if let Some(probe) = health.readiness {
        normalized.readiness = Some(normalize_health_probe(probe, limits)?);
    }

    if normalized.liveness.is_none() && normalized.readiness.is_none() {
        return Err(AppError::bad_request(
            "health configuration must define at least one probe",
        ));
    }

    Ok(Some(normalized))
}

fn normalize_health_probe(probe: HealthProbe, limits: &LimitsConfig) -> ApiResult<HealthProbe> {
    let kind = match probe.kind {
        HealthProbeKind::Http { port, path } => {
            validate_port("health.probe.port", port)?;
            let trimmed_path = path.trim().to_string();
            if trimmed_path.is_empty() {
                return Err(AppError::bad_request("health http path cannot be empty"));
            }
            if trimmed_path.len() > limits.max_field_len {
                return Err(AppError::bad_request("health http path too long"));
            }
            HealthProbeKind::Http {
                port,
                path: trimmed_path,
            }
        }
        HealthProbeKind::Tcp { port } => {
            validate_port("health.probe.port", port)?;
            HealthProbeKind::Tcp { port }
        }
        HealthProbeKind::Exec { command } => {
            if command.is_empty() {
                return Err(AppError::bad_request("health exec command cannot be empty"));
            }
            let mut normalized_command = Vec::with_capacity(command.len());
            for arg in command {
                let trimmed = arg.trim();
                if trimmed.is_empty() {
                    return Err(AppError::bad_request(
                        "health exec command arguments cannot be empty",
                    ));
                }
                if trimmed.len() > limits.max_field_len {
                    return Err(AppError::bad_request(
                        "health exec command argument too long",
                    ));
                }
                normalized_command.push(trimmed.to_string());
            }
            HealthProbeKind::Exec {
                command: normalized_command,
            }
        }
    };

    validate_positive_u64("health.interval_seconds", probe.interval_seconds)?;
    validate_positive_u64("health.timeout_seconds", probe.timeout_seconds)?;
    validate_positive_u32("health.failure_threshold", probe.failure_threshold)?;
    validate_positive_u64("health.start_period_seconds", probe.start_period_seconds)?;

    Ok(HealthProbe {
        kind,
        interval_seconds: probe.interval_seconds,
        timeout_seconds: probe.timeout_seconds,
        failure_threshold: probe.failure_threshold,
        start_period_seconds: probe.start_period_seconds,
    })
}

fn validate_port(field: &str, port: u16) -> ApiResult<()> {
    if port == 0 {
        Err(AppError::bad_request(format!(
            "{field} must be between 1 and 65535"
        )))
    } else {
        Ok(())
    }
}

fn validate_positive_u64(field: &str, value: Option<u64>) -> ApiResult<()> {
    if let Some(val) = value {
        if val == 0 {
            return Err(AppError::bad_request(format!(
                "{field} must be greater than zero"
            )));
        }
    }
    Ok(())
}

fn validate_positive_u32(field: &str, value: Option<u32>) -> ApiResult<()> {
    if let Some(val) = value {
        if val == 0 {
            return Err(AppError::bad_request(format!(
                "{field} must be greater than zero"
            )));
        }
    }
    Ok(())
}

pub fn validate_protocol(proto: &str) -> ApiResult<()> {
    let proto = proto.to_ascii_lowercase();
    if proto == "tcp" || proto == "udp" {
        return Ok(());
    }

    Err(AppError::bad_request("protocol must be tcp or udp"))
}

pub fn validate_required_str(field: &str, value: &str, max_len: usize) -> ApiResult<()> {
    validate_opt_str(field, Some(value), max_len)
}

pub fn validate_opt_str(field: &str, value: Option<&str>, max_len: usize) -> ApiResult<()> {
    if let Some(val) = value {
        if val.trim().is_empty() {
            return Err(AppError::bad_request(format!("{field} cannot be empty")));
        }
        if val.len() > max_len {
            return Err(AppError::bad_request(format!("{field} too long")));
        }
    }
    Ok(())
}

fn validate_secret_env(env: &[common::api::SecretEnv], limits: &LimitsConfig) -> ApiResult<()> {
    for entry in env {
        validate_required_str("secret_env name", &entry.name, limits.max_field_len)?;
        if entry.name.chars().any(char::is_whitespace) || entry.name.contains('=') {
            return Err(AppError::bad_request(
                "secret_env name cannot contain whitespace or '='",
            ));
        }
        validate_secret_name("secret_env secret", &entry.secret, limits.max_field_len)?;
    }
    Ok(())
}

fn validate_secret_files(
    files: &[common::api::SecretFile],
    limits: &LimitsConfig,
) -> ApiResult<()> {
    for entry in files {
        validate_required_str("secret_files path", &entry.path, limits.max_field_len)?;
        if !entry.path.starts_with('/') {
            return Err(AppError::bad_request(
                "secret_files path must be an absolute path",
            ));
        }
        if entry.path.contains(['\n', '\r']) {
            return Err(AppError::bad_request(
                "secret_files path cannot contain newlines",
            ));
        }
        validate_secret_name("secret_files secret", &entry.secret, limits.max_field_len)?;
    }
    Ok(())
}

fn validate_secret_name(field: &str, name: &str, max_len: usize) -> ApiResult<()> {
    validate_required_str(field, name, max_len)?;
    if name
        .chars()
        .any(|c| c == '/' || c == '\\' || c.is_whitespace())
    {
        return Err(AppError::bad_request(format!(
            "{field} cannot contain slashes or whitespace"
        )));
    }
    Ok(())
}

pub fn validate_config_name(name: &str, limits: &LimitsConfig) -> ApiResult<()> {
    validate_required_str("config name", name, limits.max_field_len)
}

pub fn validate_config_entries(
    entries: &[db::ConfigEntry],
    limits: &LimitsConfig,
) -> ApiResult<()> {
    let mut seen = HashSet::new();
    let mut has_secret_ref = false;
    let mut has_plain_value = false;

    for entry in entries {
        validate_required_str("config entry key", &entry.key, limits.max_field_len)?;
        if !seen.insert(entry.key.to_ascii_lowercase()) {
            return Err(AppError::bad_request("duplicate config entry key"));
        }

        match (&entry.value, &entry.secret_ref) {
            (Some(value), None) => {
                if value.trim().is_empty() {
                    return Err(AppError::bad_request("config entry value cannot be empty"));
                }
                if value.len() > MAX_CONFIG_VALUE_LEN {
                    return Err(AppError::bad_request("config entry value too long"));
                }
                has_plain_value = true;
            }
            (None, Some(secret_ref)) => {
                validate_secret_name("config entry secret_ref", secret_ref, limits.max_field_len)?;
                has_secret_ref = true;
            }
            _ => {
                return Err(AppError::bad_request(
                    "config entries must set exactly one of value or secret_ref",
                ));
            }
        }
    }

    if has_secret_ref && has_plain_value {
        return Err(AppError::bad_request(
            "config entries cannot mix plaintext values and secret refs",
        ));
    }

    Ok(())
}

pub fn validate_config_files(files: &[db::ConfigFileRef], limits: &LimitsConfig) -> ApiResult<()> {
    let mut seen = HashSet::new();

    for file in files {
        let path = file.path.trim();
        if path.is_empty() {
            return Err(AppError::bad_request("config file path cannot be empty"));
        }
        if path.len() > MAX_CONFIG_FILE_PATH_LEN {
            return Err(AppError::bad_request("config file path too long"));
        }
        if path.contains(['\n', '\r']) {
            return Err(AppError::bad_request(
                "config file path cannot contain newlines",
            ));
        }
        if !seen.insert(path.to_ascii_lowercase()) {
            return Err(AppError::bad_request("duplicate config file path"));
        }

        validate_required_str("config file_ref", &file.file_ref, limits.max_field_len)?;
    }

    Ok(())
}

#[allow(dead_code)]
pub fn _validate_uuid(id: &Uuid) -> ApiResult<()> {
    let _ = id;
    Ok(())
}

pub fn normalize_placement_hints(
    placement: Option<db::PlacementHints>,
    limits: &LimitsConfig,
    total_nodes: usize,
) -> ApiResult<Option<db::PlacementHints>> {
    let Some(mut placement) = placement else {
        return Ok(None);
    };

    placement.affinity = normalize_affinity(placement.affinity, limits)?;
    placement.anti_affinity = normalize_affinity(placement.anti_affinity, limits)?;

    if placement.anti_affinity.is_some() && total_nodes < 2 {
        return Err(AppError::bad_request(
            "anti_affinity requires at least two nodes",
        ));
    }

    if placement.affinity.is_none() && placement.anti_affinity.is_none() && !placement.spread {
        return Ok(None);
    }

    Ok(Some(placement))
}

fn normalize_affinity(
    affinity: Option<db::PlacementAffinity>,
    limits: &LimitsConfig,
) -> ApiResult<Option<db::PlacementAffinity>> {
    let Some(mut affinity) = affinity else {
        return Ok(None);
    };

    let mut seen = HashSet::new();
    affinity.node_ids.retain(|id| seen.insert(*id));
    affinity.labels = normalize_labels(Some(affinity.labels), limits)?.unwrap_or_default();

    if affinity.node_ids.is_empty() && affinity.labels.is_empty() {
        return Ok(None);
    }

    Ok(Some(affinity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::nodes::{HeartbeatRequest, RegistrationRequest};
    use common::api::NodeStatus;

    fn limits() -> LimitsConfig {
        LimitsConfig {
            registration_body_bytes: 0,
            heartbeat_body_bytes: 0,
            config_payload_bytes: 0,
            heartbeat_metrics_per_instance: 0,
            heartbeat_metrics_total: 0,
            resource_metrics_max_series: 0,
            max_field_len: 255,
            log_tail_limit: 0,
            log_tail_max_window_secs: 0,
            metrics_summary_limit: 0,
            metrics_summary_window_secs: 0,
        }
    }

    fn ports() -> PortsConfig {
        PortsConfig {
            auto_assign: true,
            range_start: 10000,
            range_end: 11000,
            public_host: None,
        }
    }

    fn volumes() -> VolumesConfig {
        VolumesConfig {
            allowed_host_prefixes: vec!["/data".into()],
        }
    }

    #[test]
    fn config_entries_disallow_mixed_secret_and_values() {
        let limits = limits();
        let entries = vec![
            db::ConfigEntry {
                key: "plain".into(),
                value: Some("value".into()),
                secret_ref: None,
            },
            db::ConfigEntry {
                key: "secret".into(),
                value: None,
                secret_ref: Some("ref".into()),
            },
        ];

        assert!(validate_config_entries(&entries, &limits).is_err());
    }

    #[test]
    fn config_entries_enforce_value_length() {
        let limits = limits();
        let entries = vec![db::ConfigEntry {
            key: "k".into(),
            value: Some("x".repeat(MAX_CONFIG_VALUE_LEN + 1)),
            secret_ref: None,
        }];

        assert!(validate_config_entries(&entries, &limits).is_err());
    }

    #[test]
    fn config_files_enforce_path_length() {
        let limits = limits();
        let files = vec![db::ConfigFileRef {
            path: "x".repeat(MAX_CONFIG_FILE_PATH_LEN + 1),
            file_ref: "ref".into(),
        }];

        assert!(validate_config_files(&files, &limits).is_err());
    }

    #[test]
    fn deployment_spec_rejects_zero_replicas() {
        let limits = limits();
        let spec = DeploymentSpec {
            name: None,
            image: "nginx:latest".into(),
            replicas: Some(0),
            command: None,
            env: None,
            secret_env: None,
            secret_files: None,
            ports: None,
            requires_public_ip: false,
            tunnel_only: false,
            volumes: None,
            constraints: None,
            placement: None,
            health: None,
            desired_state: None,
        };

        assert!(validate_deployment_spec(&spec, &limits, &ports(), &volumes()).is_err());
    }

    #[test]
    fn deployment_spec_allows_minimal_valid_payload() {
        let limits = limits();
        let spec = DeploymentSpec {
            name: Some("web".into()),
            image: "nginx:latest".into(),
            replicas: Some(1),
            command: None,
            env: None,
            secret_env: None,
            secret_files: None,
            ports: None,
            requires_public_ip: false,
            tunnel_only: false,
            volumes: None,
            constraints: None,
            placement: None,
            health: None,
            desired_state: None,
        };

        assert!(validate_deployment_spec(&spec, &limits, &ports(), &volumes()).is_ok());
    }

    #[test]
    fn deployment_spec_rejects_public_ingress_without_exposed_port() {
        let limits = limits();
        let spec = DeploymentSpec {
            name: Some("web".into()),
            image: "nginx:latest".into(),
            replicas: Some(1),
            command: None,
            env: None,
            secret_env: None,
            secret_files: None,
            ports: Some(vec![db::PortMapping {
                container_port: 8080,
                host_port: None,
                protocol: "tcp".into(),
                host_ip: None,
                expose: false,
                endpoint: None,
            }]),
            requires_public_ip: true,
            tunnel_only: false,
            volumes: None,
            constraints: None,
            placement: None,
            health: None,
            desired_state: None,
        };

        let result = validate_deployment_spec(&spec, &limits, &ports(), &volumes());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().message,
            "requires_public_ip requires at least one port with expose=true"
        );
    }

    #[test]
    fn deployment_spec_allows_public_ingress_with_exposed_port() {
        let limits = limits();
        let spec = DeploymentSpec {
            name: Some("web".into()),
            image: "nginx:latest".into(),
            replicas: Some(1),
            command: None,
            env: None,
            secret_env: None,
            secret_files: None,
            ports: Some(vec![db::PortMapping {
                container_port: 8080,
                host_port: None,
                protocol: "tcp".into(),
                host_ip: None,
                expose: true,
                endpoint: None,
            }]),
            requires_public_ip: true,
            tunnel_only: false,
            volumes: None,
            constraints: None,
            placement: None,
            health: None,
            desired_state: None,
        };

        assert!(validate_deployment_spec(&spec, &limits, &ports(), &volumes()).is_ok());
    }

    #[test]
    fn registration_rejects_invalid_public_ip() {
        let limits = limits();
        let req = RegistrationRequest {
            name: Some("node".into()),
            arch: None,
            os: None,
            labels: None,
            capacity: None,
            public_ip: Some("not-an-ip".into()),
            public_host: None,
        };

        assert!(validate_registration(&req, &limits).is_err());
    }

    #[test]
    fn registration_rejects_whitespace_public_host() {
        let limits = limits();
        let req = RegistrationRequest {
            name: Some("node".into()),
            arch: None,
            os: None,
            labels: None,
            capacity: None,
            public_ip: None,
            public_host: Some("  invalid host  ".into()),
        };

        assert!(validate_registration(&req, &limits).is_err());
    }

    #[test]
    fn heartbeat_rejects_invalid_public_ip() {
        let limits = limits();
        let req = HeartbeatRequest {
            node_status: NodeStatus::Ready,
            containers: Vec::new(),
            timestamp: None,
            inventory: None,
            public_ip: Some("123.456.789.0".into()),
            public_host: None,
        };

        assert!(validate_heartbeat(&req, &limits).is_err());
    }

    #[test]
    fn heartbeat_rejects_whitespace_public_host() {
        let limits = limits();
        let req = HeartbeatRequest {
            node_status: NodeStatus::Ready,
            containers: Vec::new(),
            timestamp: None,
            inventory: None,
            public_ip: None,
            public_host: Some("   ".into()),
        };

        assert!(validate_heartbeat(&req, &limits).is_err());
    }
}
