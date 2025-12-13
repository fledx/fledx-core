use anyhow::{self};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use common::api;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

use crate::view::format::format_uuid;
use crate::{DeployWatchArgs, StatusArgs, MAX_PAGE_LIMIT};

pub const CONFIG_MAX_FIELD_LEN: usize = 255;
pub const CONFIG_MAX_VALUE_LEN: usize = 4096;
pub const CONFIG_MAX_FILE_PATH_LEN: usize = 512;

pub fn validate_positive_u64(field: &str, value: Option<u64>) -> anyhow::Result<()> {
    if let Some(val) = value {
        if val == 0 {
            anyhow::bail!("{field} must be greater than zero");
        }
    }
    Ok(())
}

pub fn validate_positive_u32(field: &str, value: Option<u32>) -> anyhow::Result<()> {
    if let Some(val) = value {
        if val == 0 {
            anyhow::bail!("{field} must be greater than zero");
        }
    }
    Ok(())
}

pub fn expires_at_from_hours(
    expires_in_hours: Option<u64>,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    let Some(hours) = expires_in_hours else {
        return Ok(None);
    };
    if hours == 0 {
        anyhow::bail!("--expires-in-hours must be greater than zero");
    }
    let expiry = Utc::now()
        .checked_add_signed(ChronoDuration::hours(hours as i64))
        .ok_or_else(|| anyhow::anyhow!("expiry duration is too large"))?;
    Ok(Some(expiry))
}

pub fn validate_limit(limit: u32) -> anyhow::Result<()> {
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        anyhow::bail!("limit must be between 1 and {}", MAX_PAGE_LIMIT);
    }
    Ok(())
}

pub fn validate_replica_count(replicas: u32) -> anyhow::Result<()> {
    if replicas == 0 {
        anyhow::bail!("--replicas must be at least 1");
    }
    Ok(())
}

pub fn validate_command_args(args: &[String], flag_name: &str) -> anyhow::Result<()> {
    if args.iter().any(|arg| arg.trim().is_empty()) {
        anyhow::bail!("{flag_name} arguments cannot be empty");
    }
    Ok(())
}

pub fn validate_config_version_arg(version: Option<i64>) -> anyhow::Result<Option<i64>> {
    if let Some(v) = version {
        if v < 1 {
            anyhow::bail!("version must be at least 1");
        }
    }
    Ok(version)
}

pub fn unique_config_ids(ids: &[Uuid]) -> anyhow::Result<Vec<Uuid>> {
    let mut seen = HashSet::new();
    let mut ordered = Vec::with_capacity(ids.len());
    let mut duplicates = Vec::new();
    for id in ids {
        if !seen.insert(*id) {
            duplicates.push(format_uuid(*id, false));
        } else {
            ordered.push(*id);
        }
    }
    if !duplicates.is_empty() {
        eprintln!(
            "warning: ignoring duplicate --config-id values: {}",
            duplicates.join(", ")
        );
    }
    Ok(ordered)
}

pub fn validate_config_field(field: &str, value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{field} cannot be empty");
    }
    if value.len() > CONFIG_MAX_FIELD_LEN {
        anyhow::bail!("{field} too long (max {CONFIG_MAX_FIELD_LEN} characters)",);
    }
    Ok(())
}

pub fn validate_config_file_ref(file_ref: &str) -> anyhow::Result<()> {
    validate_config_field("config file_ref", file_ref)?;
    if file_ref.contains(['\n', '\r']) {
        anyhow::bail!("config file_ref cannot contain newlines");
    }
    Ok(())
}

pub fn validate_config_name_arg(name: &str) -> anyhow::Result<()> {
    validate_config_field("config name", name)
}

pub fn validate_config_entry_key(key: &str) -> anyhow::Result<()> {
    validate_config_field("config entry key", key)
}

pub fn validate_config_entry_value(value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("config entry value cannot be empty");
    }
    if value.len() > CONFIG_MAX_VALUE_LEN {
        anyhow::bail!("config entry value too long (max {CONFIG_MAX_VALUE_LEN} characters)");
    }
    Ok(())
}

pub fn validate_secret_ref(secret: &str) -> anyhow::Result<()> {
    validate_config_field("config entry secret_ref", secret)?;
    if secret
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '\\')
    {
        anyhow::bail!("config entry secret_ref cannot contain slashes or whitespace");
    }
    Ok(())
}

pub fn validate_config_file_path(path: &str) -> anyhow::Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("config file path cannot be empty");
    }
    if trimmed.len() > CONFIG_MAX_FILE_PATH_LEN {
        anyhow::bail!("config file path too long (max {CONFIG_MAX_FILE_PATH_LEN} characters)",);
    }
    if trimmed.contains(['\n', '\r']) {
        anyhow::bail!("config file path cannot contain newlines");
    }
    Ok(())
}

pub fn collect_plain_entries(
    vars: &[(String, String)],
    env_files: &[PathBuf],
) -> anyhow::Result<Vec<(String, String)>> {
    let mut entries = vars.to_vec();

    for path in env_files {
        let content = fs::read_to_string(path)
            .map_err(|err| anyhow::anyhow!("failed to read env file {}: {err}", path.display()))?;

        for (idx, raw_line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let line = trimmed
                .strip_prefix("export ")
                .map(str::trim_start)
                .unwrap_or(trimmed);

            let (key, value) = line.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "env file {} line {} must be in KEY=VALUE form",
                    path.display(),
                    line_no
                )
            })?;

            if key.trim().is_empty() {
                anyhow::bail!(
                    "env file {} line {} has an empty key",
                    path.display(),
                    line_no
                );
            }

            entries.push((key.to_string(), value.to_string()));
        }
    }

    Ok(entries)
}

pub fn config_entries_from_args(
    vars: &[(String, String)],
    env_files: &[PathBuf],
    secret_entries: &[(String, String)],
) -> anyhow::Result<Vec<api::ConfigEntry>> {
    if (!vars.is_empty() || !env_files.is_empty()) && !secret_entries.is_empty() {
        anyhow::bail!(
            "config entries cannot mix plaintext (--var/--from-env-file) and secret (--secret-entry) values",
        );
    }

    let mut plain_entries = collect_plain_entries(vars, env_files)?;
    let mut seen_keys: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(plain_entries.len() + secret_entries.len());

    for (key, value) in plain_entries.drain(..) {
        validate_config_entry_key(&key)?;
        validate_config_entry_value(&value)?;

        let normalized = key.to_ascii_lowercase();
        if !seen_keys.insert(normalized.clone()) {
            anyhow::bail!("duplicate config entry key: {key}");
        }

        out.push(api::ConfigEntry {
            key,
            value: Some(value),
            secret_ref: None,
        });
    }

    for (key, secret) in secret_entries {
        validate_config_entry_key(key)?;
        validate_secret_ref(secret)?;

        let normalized = key.to_ascii_lowercase();
        if !seen_keys.insert(normalized) {
            anyhow::bail!("duplicate config entry key: {key}");
        }

        out.push(api::ConfigEntry {
            key: key.clone(),
            value: None,
            secret_ref: Some(secret.clone()),
        });
    }

    Ok(out)
}

pub fn config_files_from_args(files: &[(String, String)]) -> anyhow::Result<Vec<api::ConfigFile>> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(files.len());

    for (path, file_ref) in files {
        validate_config_file_path(path)?;
        validate_config_file_ref(file_ref)?;

        let normalized = path.trim().to_ascii_lowercase();
        if !seen.insert(normalized) {
            anyhow::bail!("duplicate config file path: {path}");
        }

        out.push(api::ConfigFile {
            path: path.clone(),
            file_ref: file_ref.clone(),
        });
    }

    Ok(out)
}

pub fn ensure_unique_container_ports(ports: &[api::PortMapping]) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for port in ports {
        if !seen.insert(port.container_port) {
            anyhow::bail!(
                "duplicate container port {} in --port entries",
                port.container_port
            );
        }
    }
    Ok(())
}

pub fn validate_constraint_requirements(
    cpu_millis: Option<u32>,
    memory_bytes: Option<u64>,
) -> anyhow::Result<()> {
    validate_positive_u32("--require-cpu-millis", cpu_millis)?;
    validate_positive_u64("--require-memory-bytes", memory_bytes)?;
    Ok(())
}

pub fn validate_status_args(args: &StatusArgs) -> anyhow::Result<()> {
    if args.nodes_only && args.deploys_only {
        anyhow::bail!("--nodes-only and --deploys-only cannot both be set");
    }
    validate_limit(args.node_limit)?;
    validate_limit(args.deploy_limit)?;
    if args.watch && args.watch_interval == 0 {
        anyhow::bail!("watch interval must be greater than 0 seconds");
    }
    if args.watch && args.json {
        anyhow::bail!("--json is not supported with --watch");
    }
    Ok(())
}

pub fn validate_deploy_watch_args(args: &DeployWatchArgs) -> anyhow::Result<()> {
    validate_positive_u64("poll-interval", Some(args.poll_interval))?;
    if let Some(max_interval) = args.max_interval {
        validate_positive_u64("max-interval", Some(max_interval))?;
        if max_interval < args.poll_interval {
            anyhow::bail!("--max-interval cannot be less than --poll-interval");
        }
    }
    if let Some(max_runtime) = args.max_runtime {
        validate_positive_u64("max-runtime", Some(max_runtime))?;
    }
    validate_positive_u64("follow-logs-interval", Some(args.follow_logs_interval))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::api::PortMapping;

    #[test]
    fn validate_command_args_rejects_empty_values() {
        let err = validate_command_args(&["run".into(), "   ".into()], "--command").unwrap_err();
        assert!(err
            .to_string()
            .contains("--command arguments cannot be empty"));
    }

    #[test]
    fn config_files_from_args_rejects_newlines_in_ref() {
        let files = vec![("/etc/app/config.yml".into(), "ref\nextra".into())];
        let err = config_files_from_args(&files).unwrap_err();
        assert!(err
            .to_string()
            .contains("config file_ref cannot contain newlines"));
    }

    #[test]
    fn ensure_unique_container_ports_detects_duplicates() {
        let ports = vec![
            PortMapping {
                container_port: 80,
                host_port: Some(80),
                protocol: "tcp".into(),
                host_ip: None,
                expose: false,
                endpoint: None,
            },
            PortMapping {
                container_port: 80,
                host_port: Some(8080),
                protocol: "tcp".into(),
                host_ip: None,
                expose: false,
                endpoint: None,
            },
        ];
        assert!(ensure_unique_container_ports(&ports).is_err());
    }

    #[test]
    fn validate_constraint_requirements_needs_positive_values() {
        assert!(validate_constraint_requirements(Some(1), Some(1024)).is_ok());
        assert!(validate_constraint_requirements(Some(0), None).is_err());
        assert!(validate_constraint_requirements(None, Some(0)).is_err());
    }

    #[test]
    fn validate_limit_rejects_out_of_range() {
        assert!(validate_limit(0).is_err());
        assert!(validate_limit(MAX_PAGE_LIMIT + 1).is_err());
        assert!(validate_limit(1).is_ok());
    }

    #[test]
    fn validate_status_args_rejects_conflicts() {
        let base = StatusArgs {
            node_limit: crate::DEFAULT_PAGE_LIMIT,
            node_offset: 0,
            node_status: None,
            deploy_limit: crate::DEFAULT_PAGE_LIMIT,
            deploy_offset: 0,
            deploy_status: None,
            json: false,
            wide: false,
            watch: false,
            watch_interval: 2,
            nodes_only: false,
            deploys_only: false,
            no_color: false,
        };

        let mut both = base.clone();
        both.nodes_only = true;
        both.deploys_only = true;
        assert!(validate_status_args(&both).is_err());

        let mut bad_interval = base.clone();
        bad_interval.watch = true;
        bad_interval.watch_interval = 0;
        assert!(validate_status_args(&bad_interval).is_err());

        let mut ok = base.clone();
        ok.watch = true;
        ok.watch_interval = 1;
        assert!(validate_status_args(&ok).is_ok());

        let mut json_watch = base;
        json_watch.watch = true;
        json_watch.json = true;
        assert!(validate_status_args(&json_watch).is_err());
    }
}
