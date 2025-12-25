use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::Context;
use uuid::Uuid;

use crate::{api, config};

#[derive(Debug, Clone)]
pub(super) struct DeploymentContext {
    pub cfg: config::AppConfig,
    pub configs: Vec<api::ConfigDesired>,
    pub config_fingerprint: Option<String>,
}

impl DeploymentContext {
    pub fn has_configs(&self) -> bool {
        !self.configs.is_empty()
    }
}

#[derive(Default)]
pub(super) struct ConfigApplyOutcome {
    pub applied: usize,
    pub skipped: usize,
}

pub(super) fn apply_configs_to_spec(
    spec: &mut crate::runtime::ContainerSpec,
    ctx: &DeploymentContext,
    desired: &api::DeploymentDesired,
) -> anyhow::Result<ConfigApplyOutcome> {
    let mut outcome = ConfigApplyOutcome::default();
    if ctx.configs.is_empty() {
        return Ok(outcome);
    }

    let ordered = ordered_configs(&ctx.configs, ctx.cfg.node_id, desired.deployment_id);

    let mut config_env = HashMap::new();
    for config in &ordered {
        for entry in &config.entries {
            let value = resolve_config_entry(entry, &ctx.cfg.secrets_prefix)?;
            config_env.insert(entry.key.clone(), value);
        }
    }

    for (key, value) in config_env {
        if spec.env.iter().any(|(existing, _)| existing == &key) {
            outcome.skipped = outcome.skipped.saturating_add(1);
            continue;
        }
        spec.env.push((key, value));
        outcome.applied = outcome.applied.saturating_add(1);
    }

    let mut mounted_paths: HashSet<String> = spec
        .mounts
        .iter()
        .map(|m| m.container_path.clone())
        .collect();

    for config in &ordered {
        for file in &config.files {
            if mounted_paths.contains(&file.path) {
                outcome.skipped = outcome.skipped.saturating_add(1);
                continue;
            }

            let host_path = resolve_config_file_path(&ctx.cfg, file)?;
            spec.mounts.push(crate::runtime::FileMount {
                host_path,
                container_path: file.path.clone(),
                readonly: true,
            });
            mounted_paths.insert(file.path.clone());
            outcome.applied = outcome.applied.saturating_add(1);
        }
    }

    Ok(outcome)
}

fn ordered_configs(
    configs: &[api::ConfigDesired],
    node_id: Uuid,
    deployment_id: Uuid,
) -> Vec<api::ConfigDesired> {
    let mut node_configs = Vec::new();
    let mut deployment_configs = Vec::new();

    for cfg in configs {
        if cfg.attached_deployments.contains(&deployment_id) {
            deployment_configs.push(cfg.clone());
            continue;
        }
        if cfg.attached_nodes.contains(&node_id) {
            node_configs.push(cfg.clone());
        }
    }

    node_configs.sort_by_key(|c| c.metadata.name.clone());
    deployment_configs.sort_by_key(|c| c.metadata.name.clone());

    node_configs.into_iter().chain(deployment_configs).collect()
}

fn resolve_config_entry(entry: &api::ConfigEntry, secrets_prefix: &str) -> anyhow::Result<String> {
    if let Some(value) = entry.value.as_ref() {
        return Ok(value.clone());
    }

    let Some(secret) = entry.secret_ref.as_ref() else {
        anyhow::bail!(format!(
            "config entry {} missing value or secret_ref",
            entry.key
        ));
    };

    let trimmed_prefix = secrets_prefix.trim();
    if trimmed_prefix.is_empty() {
        anyhow::bail!("secrets_prefix is empty; set FLEDX_AGENT_SECRETS_PREFIX");
    }

    let env_key = format!("{}{}", trimmed_prefix, secret);
    match std::env::var(&env_key) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => anyhow::bail!(format!(
            "required secret {} missing (env var {} not set)",
            secret, env_key
        )),
        Err(err) => anyhow::bail!(format!(
            "failed to read secret {} from env {}: {}",
            secret, env_key, err
        )),
    }
}

fn resolve_config_file_path(
    cfg: &config::AppConfig,
    file: &api::ConfigFile,
) -> anyhow::Result<String> {
    let base = cfg.volume_data_dir.trim();
    if base.is_empty() {
        anyhow::bail!("volume_data_dir is empty; set FLEDX_AGENT_VOLUME_DATA_DIR");
    }

    let host_path = PathBuf::from(base).join("configs").join(&file.file_ref);
    let meta = std::fs::metadata(&host_path).with_context(|| {
        format!(
            "failed to read config file {} (ref {}) at {}",
            file.path,
            file.file_ref,
            host_path.display()
        )
    })?;
    if !meta.is_file() {
        anyhow::bail!(format!(
            "config file {} (ref {}) is not a file at {}",
            file.path,
            file.file_ref,
            host_path.display()
        ));
    }

    Ok(host_path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{ContainerSpec, FileMount};
    use crate::test_support::base_config;
    use chrono::Utc;
    use tempfile::tempdir;

    fn config_metadata(name: &str) -> api::ConfigMetadata {
        api::ConfigMetadata {
            config_id: Uuid::new_v4(),
            name: name.to_string(),
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn config_entry_value(key: &str, value: &str) -> api::ConfigEntry {
        api::ConfigEntry {
            key: key.to_string(),
            value: Some(value.to_string()),
            secret_ref: None,
        }
    }

    fn config_entry_secret(key: &str, secret: &str) -> api::ConfigEntry {
        api::ConfigEntry {
            key: key.to_string(),
            value: None,
            secret_ref: Some(secret.to_string()),
        }
    }

    fn config_file(path: &str, file_ref: &str) -> api::ConfigFile {
        api::ConfigFile {
            path: path.to_string(),
            file_ref: file_ref.to_string(),
        }
    }

    #[test]
    fn ordered_configs_sorts_node_then_deployment() {
        let node_id = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();
        let configs = vec![
            api::ConfigDesired {
                metadata: config_metadata("beta"),
                entries: Vec::new(),
                files: Vec::new(),
                attached_deployments: Vec::new(),
                attached_nodes: vec![node_id],
                checksum: None,
            },
            api::ConfigDesired {
                metadata: config_metadata("alpha"),
                entries: Vec::new(),
                files: Vec::new(),
                attached_deployments: Vec::new(),
                attached_nodes: vec![node_id],
                checksum: None,
            },
            api::ConfigDesired {
                metadata: config_metadata("gamma"),
                entries: Vec::new(),
                files: Vec::new(),
                attached_deployments: vec![deployment_id],
                attached_nodes: Vec::new(),
                checksum: None,
            },
        ];

        let ordered = ordered_configs(&configs, node_id, deployment_id);
        let names: Vec<String> = ordered
            .into_iter()
            .map(|config| config.metadata.name)
            .collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn resolve_config_entry_prefers_value() {
        let entry = config_entry_value("TOKEN", "abc");
        let value = resolve_config_entry(&entry, "PREFIX_").expect("value");
        assert_eq!(value, "abc");
    }

    #[test]
    fn resolve_config_entry_rejects_missing_value_and_secret() {
        let entry = api::ConfigEntry {
            key: "EMPTY".to_string(),
            value: None,
            secret_ref: None,
        };
        let err = resolve_config_entry(&entry, "PREFIX_").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("missing value or secret_ref"), "{msg}");
    }

    #[test]
    fn resolve_config_entry_reads_secret_env() {
        let secret = format!("SECRET_{}", Uuid::new_v4());
        let prefix = format!("TEST_SECRET_{}", Uuid::new_v4());
        let env_key = format!("{prefix}{secret}");
        // SAFETY: Test controls env mutations and runs in isolation.
        unsafe {
            std::env::set_var(&env_key, "shh");
        }

        let entry = config_entry_secret("TOKEN", &secret);
        let value = resolve_config_entry(&entry, &prefix).expect("secret");
        assert_eq!(value, "shh");

        // SAFETY: Test controls env mutations and runs in isolation.
        unsafe {
            std::env::remove_var(env_key);
        }
    }

    #[test]
    fn resolve_config_entry_rejects_empty_secret_prefix() {
        let entry = config_entry_secret("TOKEN", "value");
        let err = resolve_config_entry(&entry, "   ").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("secrets_prefix is empty"), "{msg}");
    }

    #[test]
    fn resolve_config_file_path_errors_when_missing_or_not_file() {
        let tmp = tempdir().expect("temp dir");
        let mut cfg = base_config();
        cfg.volume_data_dir = tmp.path().to_string_lossy().into_owned();

        let missing = config_file("/etc/app/config.yaml", "missing");
        let err = resolve_config_file_path(&cfg, &missing).expect_err("missing");
        let msg = err.to_string();
        assert!(msg.contains("failed to read config file"), "{msg}");

        let configs_dir = tmp.path().join("configs");
        std::fs::create_dir_all(&configs_dir).expect("configs dir");
        let dir_ref = configs_dir.join("dir-ref");
        std::fs::create_dir_all(&dir_ref).expect("dir ref");

        let non_file = config_file("/etc/app/dir.yaml", "dir-ref");
        let err = resolve_config_file_path(&cfg, &non_file).expect_err("not a file");
        let msg = err.to_string();
        assert!(msg.contains("is not a file"), "{msg}");
    }

    #[test]
    fn apply_configs_to_spec_applies_env_and_mounts() {
        let tmp = tempdir().expect("temp dir");
        let mut cfg = base_config();
        cfg.volume_data_dir = tmp.path().to_string_lossy().into_owned();

        let configs_dir = tmp.path().join("configs");
        std::fs::create_dir_all(&configs_dir).expect("configs dir");
        let file_ref = "config-ref";
        std::fs::write(configs_dir.join(file_ref), "config").expect("write file");

        let node_id = cfg.node_id;
        let deployment_id = Uuid::new_v4();
        let config = api::ConfigDesired {
            metadata: config_metadata("app"),
            entries: vec![
                config_entry_value("EXISTING", "old"),
                config_entry_value("NEW", "value"),
            ],
            files: vec![
                config_file("/etc/app/config.yaml", file_ref),
                config_file("/etc/app/dup.conf", "ignored-ref"),
            ],
            attached_deployments: Vec::new(),
            attached_nodes: vec![node_id],
            checksum: None,
        };

        let ctx = DeploymentContext {
            cfg,
            configs: vec![config],
            config_fingerprint: None,
        };

        let desired = api::DeploymentDesired {
            deployment_id,
            name: "app".to_string(),
            replica_number: 0,
            image: "example".to_string(),
            replicas: 1,
            command: None,
            env: None,
            secret_env: None,
            secret_files: None,
            ports: None,
            requires_public_ip: false,
            tunnel_only: false,
            placement: None,
            volumes: None,
            health: None,
            desired_state: api::DesiredState::Running,
            replica_generation: None,
            generation: 1,
        };

        let mut spec = ContainerSpec::new("example");
        spec.env.push(("EXISTING".to_string(), "keep".to_string()));
        spec.mounts.push(FileMount {
            host_path: "/tmp/dup".to_string(),
            container_path: "/etc/app/dup.conf".to_string(),
            readonly: true,
        });

        let outcome = apply_configs_to_spec(&mut spec, &ctx, &desired).expect("apply");
        assert_eq!(outcome.applied, 2);
        assert_eq!(outcome.skipped, 2);

        let env_value = spec
            .env
            .iter()
            .find(|(key, _)| key == "NEW")
            .map(|(_, value)| value.as_str());
        assert_eq!(env_value, Some("value"));

        assert!(
            spec.mounts
                .iter()
                .any(|mount| mount.container_path == "/etc/app/config.yaml")
        );
    }
}
