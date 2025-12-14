use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::{
    api::{self, DeploymentHealth, HealthProbe, HealthProbeKind},
    config,
    runtime::FileMount,
};

pub(crate) fn validate_ports(ports: &[api::PortMapping]) -> Result<()> {
    for port in ports {
        if port.expose && port.host_port.is_none() {
            bail!(
                "exposed container port {} requires a host_port binding",
                port.container_port
            );
        }
    }

    Ok(())
}

pub(crate) fn validate_volume_mounts(
    volumes: &[api::VolumeMount],
    cfg: &config::AppConfig,
) -> Result<()> {
    if volumes.is_empty() {
        return Ok(());
    }

    if cfg.allowed_volume_prefixes.is_empty() {
        bail!("volume mounts are disabled; set FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES to enable");
    }

    let resolved_prefixes: Vec<PathBuf> = cfg
        .allowed_volume_prefixes
        .iter()
        .map(|p| {
            let path = Path::new(p);
            path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
        })
        .collect();

    for volume in volumes {
        let host_path = Path::new(&volume.host_path);
        if !host_path.is_absolute() {
            bail!("volume host_path must be absolute: {}", volume.host_path);
        }
        if !Path::new(&volume.container_path).is_absolute() {
            bail!(
                "volume container_path must be absolute: {}",
                volume.container_path
            );
        }
        let resolved_host = canonicalize_existing(host_path)?;
        let allowed = resolved_prefixes
            .iter()
            .any(|prefix| resolved_host.starts_with(prefix));
        if !allowed {
            bail!(
                "volume host path {} is outside allowed prefixes {:?}",
                resolved_host.display(),
                cfg.allowed_volume_prefixes
            );
        }
    }

    Ok(())
}

pub(crate) fn resolve_secret_env(
    entries: &[api::SecretEnv],
    prefix: &str,
) -> Result<Vec<(String, String)>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let trimmed_prefix = normalized_secrets_prefix(prefix)?;
    let mut resolved = Vec::with_capacity(entries.len());

    for entry in entries {
        let env_key = format!("{}{}", trimmed_prefix, entry.secret);
        match std::env::var(&env_key) {
            Ok(value) => resolved.push((entry.name.clone(), value)),
            Err(std::env::VarError::NotPresent) if entry.optional => continue,
            Err(std::env::VarError::NotPresent) => {
                bail!(
                    "required secret {} missing (env var {} not set)",
                    entry.secret,
                    env_key
                );
            }
            Err(err) => {
                bail!(
                    "failed to read secret {} from env {}: {}",
                    entry.secret,
                    env_key,
                    err
                );
            }
        }
    }

    Ok(resolved)
}

pub(crate) fn resolve_secret_files(
    entries: &[api::SecretFile],
    secrets_dir: &str,
) -> Result<Vec<FileMount>> {
    let mut mounts = Vec::new();
    if entries.is_empty() {
        return Ok(mounts);
    }

    let base = secrets_dir.trim();
    if base.is_empty() {
        bail!("secrets_dir is empty; set FLEDX_AGENT_SECRETS_DIR");
    }

    for entry in entries {
        let host_path = PathBuf::from(base).join(&entry.secret);
        match std::fs::metadata(&host_path) {
            Ok(meta) => {
                if !meta.is_file() {
                    if entry.optional {
                        continue;
                    }
                    bail!(
                        "required secret file {} is not a file at {}",
                        entry.secret,
                        host_path.display()
                    );
                }
            }
            Err(err) => {
                if entry.optional && err.kind() == std::io::ErrorKind::NotFound {
                    continue;
                }
                bail!(
                    "failed to read secret file {} at {}: {}",
                    entry.secret,
                    host_path.display(),
                    err
                );
            }
        }

        let mount = FileMount {
            host_path: host_path.to_string_lossy().into_owned(),
            container_path: entry.path.clone(),
            readonly: true,
        };
        mounts.push(mount);
    }

    Ok(mounts)
}

pub(crate) fn validate_health(health: &DeploymentHealth) -> Result<()> {
    let mut has_probe = false;

    if let Some(probe) = health.liveness.as_ref() {
        validate_probe("liveness", probe)?;
        has_probe = true;
    }

    if let Some(probe) = health.readiness.as_ref() {
        validate_probe("readiness", probe)?;
        has_probe = true;
    }

    if !has_probe {
        bail!("health configuration must define at least one probe");
    }

    Ok(())
}

fn validate_probe(role: &str, probe: &HealthProbe) -> Result<()> {
    match &probe.kind {
        HealthProbeKind::Http { port, path } => {
            validate_port(role, *port)?;
            if path.trim().is_empty() {
                bail!("{role} http path cannot be empty");
            }
        }
        HealthProbeKind::Tcp { port } => validate_port(role, *port)?,
        HealthProbeKind::Exec { command } => {
            if command.is_empty() {
                bail!("{role} exec command cannot be empty");
            }
            for arg in command {
                if arg.trim().is_empty() {
                    bail!("{role} exec arguments cannot be empty");
                }
            }
        }
    }

    if let Some(val) = probe.interval_seconds {
        if val == 0 {
            bail!("{role} interval_seconds must be greater than zero");
        }
    }

    if let Some(val) = probe.timeout_seconds {
        if val == 0 {
            bail!("{role} timeout_seconds must be greater than zero");
        }
    }

    if let Some(val) = probe.failure_threshold {
        if val == 0 {
            bail!("{role} failure_threshold must be greater than zero");
        }
    }

    if let Some(val) = probe.start_period_seconds {
        if val == 0 {
            bail!("{role} start_period_seconds must be greater than zero");
        }
    }

    Ok(())
}

fn validate_port(role: &str, port: u16) -> Result<()> {
    if port == 0 {
        bail!("{role} port must be between 1 and 65535");
    }
    Ok(())
}

fn canonicalize_existing(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        bail!("volume host path {} does not exist", path.display());
    }
    path.canonicalize()
        .with_context(|| format!("resolve host path {}", path.display()))
}

fn normalized_secrets_prefix(prefix: &str) -> Result<String> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        bail!("secrets_prefix is empty; set FLEDX_AGENT_SECRETS_PREFIX");
    }

    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_config;
    use tempfile::tempdir;

    #[test]
    fn validate_ports_requires_host_port_for_exposed_mapping() {
        let ports = vec![api::PortMapping {
            container_port: 8080,
            host_port: None,
            protocol: "tcp".into(),
            expose: true,
            host_ip: None,
            endpoint: None,
        }];

        let err = validate_ports(&ports).unwrap_err();
        assert!(err
            .to_string()
            .contains("exposed container port 8080 requires a host_port binding"));
    }

    #[test]
    fn volume_validation_respects_allowlist_and_paths() {
        let tmp = tempdir().expect("tmpdir");
        let allowed = tmp.path().canonicalize().unwrap();
        let mut cfg = base_config();
        cfg.allowed_volume_prefixes = vec![allowed.display().to_string()];

        let good = api::VolumeMount {
            host_path: allowed
                .join("nested/../data")
                .to_string_lossy()
                .into_owned(),
            container_path: "/data".into(),
            read_only: Some(false),
        };

        std::fs::create_dir_all(&good.host_path).expect("mkdirs");

        assert!(validate_volume_mounts(&[good], &cfg).is_ok());

        let bad = api::VolumeMount {
            host_path: "/etc/passwd".into(),
            container_path: "/data".into(),
            read_only: Some(false),
        };

        let err = validate_volume_mounts(&[bad], &cfg).unwrap_err();
        assert!(err.to_string().contains("outside allowed prefixes"));
    }

    #[test]
    fn resolve_secret_env_requires_present_values() {
        let entries = vec![api::SecretEnv {
            name: "TOKEN".into(),
            secret: "MY_SECRET".into(),
            optional: false,
        }];

        std::env::remove_var("FLEDX_SECRET_MY_SECRET");
        let err = resolve_secret_env(&entries, "FLEDX_SECRET_").unwrap_err();
        assert!(err
            .to_string()
            .contains("required secret MY_SECRET missing"));

        std::env::set_var("FLEDX_SECRET_MY_SECRET", "value");
        let resolved = resolve_secret_env(&entries, "FLEDX_SECRET_").expect("resolved env");
        assert_eq!(resolved, vec![("TOKEN".into(), "value".into())]);
    }

    #[test]
    fn resolve_secret_files_builds_mounts() {
        let dir = tempdir().expect("tempdir");
        let secret_path = dir.path().join("creds");
        std::fs::write(&secret_path, "ok").expect("write secret");

        let entries = vec![api::SecretFile {
            secret: "creds".into(),
            path: "/etc/creds".into(),
            optional: false,
        }];

        let mounts = resolve_secret_files(&entries, dir.path().to_str().unwrap()).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].container_path, "/etc/creds");
        assert!(mounts[0].readonly);
    }

    #[test]
    fn validate_health_rejects_empty_configuration() {
        let health = DeploymentHealth {
            liveness: None,
            readiness: None,
        };

        let err = validate_health(&health).unwrap_err();
        assert!(err
            .to_string()
            .contains("health configuration must define at least one probe"));
    }
}
