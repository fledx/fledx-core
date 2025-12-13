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
        anyhow::bail!("secrets_prefix is empty; set FLEDX_AGENT__SECRETS_PREFIX");
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
        anyhow::bail!("volume_data_dir is empty; set FLEDX_AGENT__VOLUME_DATA_DIR");
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
