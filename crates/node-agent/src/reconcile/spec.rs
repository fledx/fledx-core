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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_config;
    use std::collections::HashMap;

    fn base_desired() -> api::DeploymentDesired {
        api::DeploymentDesired {
            deployment_id: uuid::Uuid::new_v4(),
            name: "app".into(),
            replica_number: 0,
            image: "nginx:latest".into(),
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
        }
    }

    #[test]
    fn trimmed_non_empty_filters_whitespace() {
        assert_eq!(trimmed_non_empty(Some("  ")), None);
        assert_eq!(trimmed_non_empty(None), None);
        assert_eq!(trimmed_non_empty(Some(" ok ")), Some("ok".to_string()));
    }

    #[test]
    fn compute_exposed_endpoints_honors_host_precedence() {
        let mut cfg = base_config();
        cfg.public_host = Some("edge.example.com".into());
        let mut desired = base_desired();
        desired.ports = Some(vec![api::PortMapping {
            container_port: 80,
            host_port: Some(8080),
            protocol: "tcp".into(),
            host_ip: Some("127.0.0.1".into()),
            expose: true,
            endpoint: None,
        }]);

        let endpoints = compute_exposed_endpoints(&desired, &cfg).expect("endpoints");
        assert_eq!(endpoints, vec!["edge.example.com:8080".to_string()]);

        cfg.public_host = None;
        cfg.public_ip = Some("203.0.113.10".into());
        let endpoints = compute_exposed_endpoints(&desired, &cfg).expect("endpoints");
        assert_eq!(endpoints, vec!["203.0.113.10:8080".to_string()]);
    }

    #[test]
    fn compute_exposed_endpoints_errors_without_host_port() {
        let cfg = base_config();
        let mut desired = base_desired();
        desired.ports = Some(vec![api::PortMapping {
            container_port: 80,
            host_port: None,
            protocol: "tcp".into(),
            host_ip: None,
            expose: true,
            endpoint: None,
        }]);

        let err = compute_exposed_endpoints(&desired, &cfg).unwrap_err();
        assert!(err.to_string().contains("requires a host_port binding"));
    }

    #[test]
    fn to_runtime_port_defaults_host_and_protocol() {
        let port = api::PortMapping {
            container_port: 443,
            host_port: None,
            protocol: "udp".into(),
            host_ip: None,
            expose: false,
            endpoint: None,
        };
        let runtime = to_runtime_port(&port);
        assert_eq!(runtime.container_port, 443);
        assert_eq!(runtime.host_port, 443);
        assert_eq!(runtime.protocol, PortProtocol::Udp);
    }

    #[test]
    fn to_container_spec_applies_secret_env_and_labels() {
        let mut cfg = base_config();
        cfg.secrets_prefix = "FLEDX_SECRET_".into();

        std::env::set_var("FLEDX_SECRET_API_KEY", "secret");
        let mut desired = base_desired();
        desired.env = Some(HashMap::from([("API_KEY".into(), "plain".into())]));
        desired.secret_env = Some(vec![api::SecretEnv {
            name: "API_KEY".into(),
            secret: "API_KEY".into(),
            optional: false,
        }]);
        desired.replica_generation = Some(5);

        let endpoints = vec!["10.0.0.1:8080".to_string()];
        let spec =
            to_container_spec(&desired, "container-1", &cfg, &endpoints).expect("container spec");
        let env = spec.env.iter().find(|(k, _)| k == "API_KEY").unwrap();
        assert_eq!(env.1, "secret");
        assert!(spec
            .labels
            .iter()
            .any(|(k, v)| k == ENDPOINTS_LABEL && v.contains("10.0.0.1:8080")));
        assert!(spec
            .labels
            .iter()
            .any(|(k, v)| k == "fledx.generation" && v == "5"));
    }

    #[test]
    fn to_container_spec_errors_when_secret_missing() {
        let cfg = base_config();
        std::env::remove_var("FLEDX_SECRET_MISSING");
        let mut desired = base_desired();
        desired.secret_env = Some(vec![api::SecretEnv {
            name: "API_KEY".into(),
            secret: "MISSING".into(),
            optional: false,
        }]);

        let err = to_container_spec(&desired, "container-1", &cfg, &[]).expect_err("should fail");
        assert!(err.to_string().contains("required secret MISSING"));
    }
}
