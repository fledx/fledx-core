use anyhow::{anyhow, Context};

use crate::{
    api, config,
    runtime::{
        self, ContainerSpec, DynContainerRuntime, PortMapping as RuntimePortMapping, PortProtocol,
    },
    state::ENDPOINTS_LABEL,
    validation,
};

use super::desired_replica_generation;

pub(super) fn to_container_spec(
    desired: &api::DeploymentDesired,
    container_name: &str,
    cfg: &config::AppConfig,
    endpoints: &[String],
) -> anyhow::Result<ContainerSpec> {
    let mut spec = ContainerSpec::new(desired.image.clone());
    spec.name = Some(container_name.to_string());
    spec.command = desired.command.clone();

    if let Some(env) = &desired.env {
        spec.env = env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    }

    if let Some(secret_env) = desired.secret_env.as_ref() {
        let resolved = validation::resolve_secret_env(secret_env, &cfg.secrets_prefix)?;
        for (name, value) in resolved {
            if let Some(pos) = spec.env.iter().position(|(k, _)| k == &name) {
                spec.env.remove(pos);
            }
            spec.env.push((name, value));
        }
    }

    if let Some(ports) = &desired.ports {
        spec.ports = ports.iter().map(to_runtime_port).collect();
    }

    if let Some(secret_files) = desired.secret_files.as_ref() {
        let mounts = validation::resolve_secret_files(secret_files, &cfg.secrets_dir)?;
        spec.mounts.extend(mounts);
    }

    if let Some(volumes) = desired.volumes.as_ref() {
        validation::validate_volume_mounts(volumes, cfg)?;
        for volume in volumes {
            spec.mounts.push(runtime::FileMount {
                host_path: volume.host_path.clone(),
                container_path: volume.container_path.clone(),
                readonly: volume.read_only.unwrap_or(false),
            });
        }
    }

    spec.labels.push((
        "fledx.deployment_id".into(),
        desired.deployment_id.to_string(),
    ));
    spec.labels.push((
        "fledx.replica_number".into(),
        desired.replica_number.to_string(),
    ));
    spec.labels.push((
        "fledx.generation".into(),
        desired_replica_generation(desired).to_string(),
    ));

    if !endpoints.is_empty() {
        let encoded =
            serde_json::to_string(endpoints).context("encode endpoint metadata for labels")?;
        spec.labels.push((ENDPOINTS_LABEL.into(), encoded));
    }

    Ok(spec)
}

pub(super) fn compute_exposed_endpoints(
    desired: &api::DeploymentDesired,
    cfg: &config::AppConfig,
) -> anyhow::Result<Vec<String>> {
    let mut endpoints = Vec::new();

    if let Some(ports) = &desired.ports {
        for port in ports {
            if !port.expose {
                continue;
            }

            let host_port = port.host_port.ok_or_else(|| {
                anyhow!(
                    "exposed container port {} requires a host_port binding",
                    port.container_port
                )
            })?;

            let host = endpoint_host(port, cfg)
                .or_else(|| {
                    port.host_ip
                        .as_deref()
                        .map(str::trim)
                        .filter(|trimmed| !trimmed.is_empty())
                        .map(|trimmed| trimmed.to_string())
                })
                .unwrap_or_else(|| "0.0.0.0".to_string());

            endpoints.push(format!("{host}:{host_port}"));
        }
    }

    Ok(endpoints)
}

pub(super) fn to_runtime_port(port: &api::PortMapping) -> RuntimePortMapping {
    let protocol = match port.protocol.to_ascii_lowercase().as_str() {
        "udp" => PortProtocol::Udp,
        _ => PortProtocol::Tcp,
    };
    let host_port = port.host_port.unwrap_or(port.container_port);

    RuntimePortMapping {
        container_port: port.container_port,
        host_port,
        protocol,
        host_ip: port.host_ip.clone(),
    }
}

pub(super) async fn stop_and_remove(
    runtime: &DynContainerRuntime,
    name: &str,
) -> anyhow::Result<()> {
    if let Err(err) = runtime.stop_container(name).await {
        if !matches!(err, runtime::ContainerRuntimeError::NotFound { .. }) {
            return Err(err.into());
        }
    }

    if let Err(err) = runtime.remove_container(name).await {
        if !matches!(err, runtime::ContainerRuntimeError::NotFound { .. }) {
            return Err(err.into());
        }
    }

    Ok(())
}

fn endpoint_host(port: &api::PortMapping, cfg: &config::AppConfig) -> Option<String> {
    trimmed_non_empty(cfg.public_host.as_deref())
        .or_else(|| trimmed_non_empty(cfg.public_ip.as_deref()))
        .or_else(|| trimmed_non_empty(port.host_ip.as_deref()))
}

fn trimmed_non_empty(value: Option<&str>) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
