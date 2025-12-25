use std::collections::HashMap;

use async_trait::async_trait;
use bollard::{
    errors::Error as DockerError,
    exec::{CreateExecOptions, StartExecOptions, StartExecResults},
    models::{ContainerCreateBody, HostConfig},
    query_parameters::{
        CreateContainerOptions, CreateImageOptions, InspectContainerOptions, ListContainersOptions,
        RemoveContainerOptions, StartContainerOptions, StatsOptionsBuilder, StopContainerOptions,
    },
    Docker,
};
use futures_util::{StreamExt, TryStreamExt};
use uuid::Uuid;

use crate::runtime::{
    helpers::{
        blkio_bytes, build_mounts, build_ports, calculate_cpu_percent, format_env, map_status,
        network_bytes,
    },
    ContainerDetails, ContainerResourceUsage, ContainerRuntime, ContainerRuntimeError,
    ContainerSpec, ExecResult, PortMapping, PortProtocol,
};

#[derive(Clone)]
pub struct DockerRuntime {
    docker: Docker,
}

impl DockerRuntime {
    pub fn connect() -> Result<Self, ContainerRuntimeError> {
        let docker =
            Docker::connect_with_defaults().map_err(|err| ContainerRuntimeError::Connection {
                context: "connect",
                source: err.into(),
            })?;
        Ok(Self { docker })
    }

    pub fn from_client(docker: Docker) -> Self {
        Self { docker }
    }
}

#[async_trait]
impl ContainerRuntime for DockerRuntime {
    async fn pull_image(&self, image: &str) -> Result<(), ContainerRuntimeError> {
        let mut stream = self.docker.create_image(
            Some(CreateImageOptions {
                from_image: Some(image.to_string()),
                ..Default::default()
            }),
            None,
            None,
        );

        while let Some(progress) = stream.next().await {
            progress.map_err(|err| {
                map_connection_or(err, "pull_image", |source| {
                    ContainerRuntimeError::PullImage {
                        image: image.to_string(),
                        source: source.into(),
                    }
                })
            })?;
        }

        Ok(())
    }

    async fn start_container(&self, spec: ContainerSpec) -> Result<String, ContainerRuntimeError> {
        self.pull_image(&spec.image).await?;

        let container_name = spec
            .name
            .unwrap_or_else(|| format!("fledx-agent-{}", Uuid::new_v4()));
        let env = format_env(&spec.env);

        let (port_bindings, exposed_ports) = build_ports(&spec.ports);
        let binds = build_mounts(&spec.mounts);

        let host_config = HostConfig {
            port_bindings,
            binds,
            ..Default::default()
        };

        let container_config = ContainerCreateBody {
            image: Some(spec.image.clone()),
            env,
            exposed_ports,
            host_config: Some(host_config),
            cmd: spec.command.clone(),
            labels: if spec.labels.is_empty() {
                None
            } else {
                Some(spec.labels.into_iter().collect())
            },
            ..Default::default()
        };

        let create_opts = CreateContainerOptions {
            name: Some(container_name.clone()),
            platform: String::new(),
        };

        let created = self
            .docker
            .create_container(Some(create_opts), container_config)
            .await
            .map_err(|err| {
                map_connection_or(err, "create_container", |source| {
                    ContainerRuntimeError::CreateContainer {
                        name: container_name.clone(),
                        source: source.into(),
                    }
                })
            })?;

        self.docker
            .start_container(&created.id, None::<StartContainerOptions>)
            .await
            .map_err(|err| map_start_error(err, &created.id, &spec.ports))?;

        Ok(created.id)
    }

    async fn exec_command(
        &self,
        container_id: &str,
        command: &[String],
    ) -> Result<ExecResult, ContainerRuntimeError> {
        let exec = self
            .docker
            .create_exec(
                container_id,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(command.to_vec()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|err| map_exec_error(err, container_id))?;

        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .map_err(|err| map_exec_error(err, container_id))?;

        let mut output = String::new();
        if let StartExecResults::Attached {
            output: mut stream, ..
        } = start
        {
            while let Some(log) = stream
                .try_next()
                .await
                .map_err(|err| map_exec_error(err, container_id))?
            {
                output.push_str(&log.to_string());
            }
        }

        let inspect = self
            .docker
            .inspect_exec(&exec.id)
            .await
            .map_err(|err| map_exec_error(err, container_id))?;

        Ok(ExecResult {
            exit_code: inspect.exit_code.unwrap_or_default(),
            output,
        })
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerDetails, ContainerRuntimeError> {
        let details = self
            .docker
            .inspect_container(id, None::<InspectContainerOptions>)
            .await
            .map_err(|err| {
                map_docker_error(err, id, "inspect_container", |id, source| {
                    ContainerRuntimeError::InspectContainer {
                        id,
                        source: source.into(),
                    }
                })
            })?;

        let status = map_status(details.state.as_ref());
        let name = details.name.map(|n| n.trim_start_matches('/').to_string());
        let id = details.id.unwrap_or_else(|| id.to_string());
        let labels = details.config.and_then(|c| c.labels);

        Ok(ContainerDetails {
            id,
            name,
            status,
            labels,
        })
    }

    async fn stop_container(&self, id: &str) -> Result<(), ContainerRuntimeError> {
        match self
            .docker
            .stop_container(
                id,
                Some(StopContainerOptions {
                    signal: None,
                    t: Some(10),
                }),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(err) if is_not_modified(&err) => Ok(()),
            Err(err) => Err(map_docker_error(err, id, "stop_container", |id, source| {
                ContainerRuntimeError::StopContainer {
                    id,
                    source: source.into(),
                }
            })),
        }
    }

    async fn remove_container(&self, id: &str) -> Result<(), ContainerRuntimeError> {
        self.docker
            .remove_container(
                id,
                Some(RemoveContainerOptions {
                    v: false,
                    force: true,
                    link: false,
                }),
            )
            .await
            .map_err(|err| {
                map_docker_error(err, id, "remove_container", |id, source| {
                    ContainerRuntimeError::RemoveContainer {
                        id,
                        source: source.into(),
                    }
                })
            })
    }

    async fn list_managed_containers(
        &self,
    ) -> Result<Vec<ContainerDetails>, ContainerRuntimeError> {
        let mut filters = HashMap::new();
        filters.insert("label".to_string(), vec!["fledx.deployment_id".to_string()]);

        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters: Some(filters),
                ..Default::default()
            }))
            .await
            .map_err(|err| {
                map_connection_or(err, "list_containers", |source| {
                    ContainerRuntimeError::ListContainers(source.into())
                })
            })?;

        let mut details = Vec::new();
        for id in containers.iter().filter_map(|c| c.id.as_ref()) {
            match self.inspect_container(id).await {
                Ok(info) => details.push(info),
                Err(ContainerRuntimeError::NotFound { .. }) => continue,
                Err(err) => return Err(err),
            }
        }

        Ok(details)
    }

    async fn container_stats(
        &self,
        id: &str,
    ) -> Result<ContainerResourceUsage, ContainerRuntimeError> {
        let mut stream = self
            .docker
            .stats(
                id,
                Some(
                    StatsOptionsBuilder::default()
                        .stream(false)
                        .one_shot(true)
                        .build(),
                ),
            )
            .take(1);

        let stats = stream
            .try_next()
            .await
            .map_err(|err| {
                map_docker_error(err, id, "container_stats", |id, source| {
                    ContainerRuntimeError::Stats {
                        id,
                        source: source.into(),
                    }
                })
            })?
            .ok_or_else(|| ContainerRuntimeError::NotFound { id: id.to_string() })?;

        let cpu_percent = calculate_cpu_percent(&stats).unwrap_or_default();
        let memory_bytes = stats
            .memory_stats
            .as_ref()
            .and_then(|mem| mem.usage)
            .unwrap_or_default();
        let network_rx_bytes = network_bytes(&stats, |net| net.rx_bytes);
        let network_tx_bytes = network_bytes(&stats, |net| net.tx_bytes);
        let blk_read_bytes = blkio_bytes(&stats, "read");
        let blk_write_bytes = blkio_bytes(&stats, "write");

        Ok(ContainerResourceUsage {
            collected_at: chrono::Utc::now(),
            cpu_percent,
            memory_bytes,
            network_rx_bytes,
            network_tx_bytes,
            blk_read_bytes,
            blk_write_bytes,
        })
    }
}

fn map_connection_or<F>(err: DockerError, context: &'static str, wrap: F) -> ContainerRuntimeError
where
    F: FnOnce(DockerError) -> ContainerRuntimeError,
{
    if is_connection_error(&err) {
        ContainerRuntimeError::Connection {
            context,
            source: err.into(),
        }
    } else {
        wrap(err)
    }
}

fn map_docker_error<F>(
    err: DockerError,
    id: &str,
    context: &'static str,
    wrap: F,
) -> ContainerRuntimeError
where
    F: FnOnce(String, DockerError) -> ContainerRuntimeError,
{
    if is_not_found(&err) {
        ContainerRuntimeError::NotFound { id: id.to_string() }
    } else if is_connection_error(&err) {
        ContainerRuntimeError::Connection {
            context,
            source: err.into(),
        }
    } else {
        wrap(id.to_string(), err)
    }
}

fn is_not_found(err: &DockerError) -> bool {
    matches!(
        err,
        DockerError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

fn is_not_modified(err: &DockerError) -> bool {
    matches!(
        err,
        DockerError::DockerResponseServerError {
            status_code: 304,
            ..
        }
    )
}

fn is_connection_error(err: &DockerError) -> bool {
    matches!(
        err,
        DockerError::IOError { .. }
            | DockerError::HyperResponseError { .. }
            | DockerError::RequestTimeoutError
            | DockerError::SocketNotFoundError(_)
    )
}

fn map_start_error(
    err: DockerError,
    container_id: &str,
    ports: &[PortMapping],
) -> ContainerRuntimeError {
    if let Some(conflict) = map_port_conflict(&err, ports) {
        return ContainerRuntimeError::PortConflict {
            id: container_id.to_string(),
            host_port: conflict.host_port,
            protocol: conflict.protocol,
            host_ip: conflict.host_ip.unwrap_or_else(|| "0.0.0.0".into()),
            source: err.into(),
        };
    }

    if is_connection_error(&err) {
        return ContainerRuntimeError::Connection {
            context: "start_container",
            source: err.into(),
        };
    }

    ContainerRuntimeError::StartContainer {
        id: container_id.to_string(),
        source: err.into(),
    }
}

fn map_exec_error(err: DockerError, container_id: &str) -> ContainerRuntimeError {
    if is_connection_error(&err) {
        ContainerRuntimeError::Connection {
            context: "exec_command",
            source: err.into(),
        }
    } else {
        ContainerRuntimeError::Exec {
            id: container_id.to_string(),
            source: err.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortConflictDetails {
    host_port: u16,
    protocol: PortProtocol,
    host_ip: Option<String>,
}

fn map_port_conflict(err: &DockerError, ports: &[PortMapping]) -> Option<PortConflictDetails> {
    if ports.is_empty() {
        return None;
    }

    let message = match err {
        DockerError::DockerResponseServerError { message, .. } => message,
        _ => return None,
    };

    let lower = message.to_ascii_lowercase();
    if !(lower.contains("port is already allocated")
        || lower.contains("address already in use")
        || lower.contains("ports are not available"))
    {
        return None;
    }

    let parsed = extract_host_binding(message);

    if let Some((ip, port, proto_hint)) = parsed {
        if let Some(matching) = find_matching_mapping(ports, ip.as_deref(), port, proto_hint) {
            return Some(matching);
        }
    }

    ports.first().map(|p| PortConflictDetails {
        host_port: p.host_port,
        protocol: p.protocol,
        host_ip: p.host_ip.clone(),
    })
}

fn find_matching_mapping(
    ports: &[PortMapping],
    ip: Option<&str>,
    port: u16,
    protocol: Option<PortProtocol>,
) -> Option<PortConflictDetails> {
    ports.iter().find_map(|mapping| {
        if mapping.host_port != port {
            return None;
        }

        if let Some(proto_hint) = protocol {
            if mapping.protocol != proto_hint {
                return None;
            }
        }

        if let Some(ip_hint) = ip {
            let mapping_ip = mapping.host_ip.as_deref().unwrap_or("0.0.0.0");
            if mapping_ip != ip_hint {
                return None;
            }
        }

        Some(PortConflictDetails {
            host_port: mapping.host_port,
            protocol: mapping.protocol,
            host_ip: mapping.host_ip.clone(),
        })
    })
}

fn extract_host_binding(message: &str) -> Option<(Option<String>, u16, Option<PortProtocol>)> {
    let lower = message.to_ascii_lowercase();
    let protocol_hint = if lower.contains("udp") {
        Some(PortProtocol::Udp)
    } else if lower.contains("tcp") {
        Some(PortProtocol::Tcp)
    } else {
        None
    };

    for token in message.split_whitespace() {
        if let Some((ip, port)) = parse_host_port_token(token) {
            return Some((ip, port, protocol_hint));
        }
    }

    None
}

fn parse_host_port_token(token: &str) -> Option<(Option<String>, u16)> {
    let cleaned = token.trim_matches(|c: char| !(c.is_ascii_digit() || c == '.' || c == ':'));
    if cleaned.is_empty() {
        return None;
    }

    let mut parts: Vec<&str> = cleaned.split(':').collect();
    while parts.last().is_some_and(|part| part.is_empty()) {
        parts.pop();
    }
    if parts.is_empty() {
        return None;
    }

    let port_part = parts.pop().unwrap_or_default();
    let port_str: String = port_part
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let port: u16 = port_str.parse().ok()?;

    if parts.is_empty() {
        return Some((None, port));
    }

    let ip = parts.join(":");
    if ip.is_empty() {
        Some((None, port))
    } else {
        Some((Some(ip), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_port_conflict_from_docker_error() {
        let ports = vec![
            PortMapping {
                container_port: 80,
                host_port: 8080,
                protocol: PortProtocol::Tcp,
                host_ip: Some("0.0.0.0".into()),
            },
            PortMapping {
                container_port: 53,
                host_port: 5353,
                protocol: PortProtocol::Udp,
                host_ip: Some("127.0.0.1".into()),
            },
        ];

        let err = bollard::errors::Error::DockerResponseServerError {
            status_code: 500,
            message: "driver failed programming external connectivity: Bind for 0.0.0.0:8080 failed: port is already allocated".into(),
        };

        let details = map_port_conflict(&err, &ports).expect("port conflict detected");
        assert_eq!(details.host_port, 8080);
        assert_eq!(details.protocol, PortProtocol::Tcp);
        assert_eq!(details.host_ip.as_deref(), Some("0.0.0.0"));
    }

    #[test]
    fn map_connection_or_wraps_connection_errors() {
        let err = DockerError::RequestTimeoutError;
        let mapped = map_connection_or(err, "pull_image", |source| {
            ContainerRuntimeError::PullImage {
                image: "img".into(),
                source: source.into(),
            }
        });
        match mapped {
            ContainerRuntimeError::Connection { context, .. } => {
                assert_eq!(context, "pull_image");
            }
            other => panic!("expected connection error, got {other:?}"),
        }
    }

    #[test]
    fn map_docker_error_handles_not_found_and_other() {
        let not_found = DockerError::DockerResponseServerError {
            status_code: 404,
            message: "missing".into(),
        };
        let mapped = map_docker_error(not_found, "id-1", "inspect", |id, source| {
            ContainerRuntimeError::InspectContainer {
                id,
                source: source.into(),
            }
        });
        match mapped {
            ContainerRuntimeError::NotFound { id } => assert_eq!(id, "id-1"),
            other => panic!("expected not found, got {other:?}"),
        }

        let other = DockerError::DockerResponseServerError {
            status_code: 500,
            message: "boom".into(),
        };
        let mapped = map_docker_error(other, "id-2", "inspect", |id, source| {
            ContainerRuntimeError::InspectContainer {
                id,
                source: source.into(),
            }
        });
        match mapped {
            ContainerRuntimeError::InspectContainer { id, .. } => assert_eq!(id, "id-2"),
            other => panic!("expected inspect error, got {other:?}"),
        }
    }

    #[test]
    fn map_start_error_reports_port_conflict_and_connection() {
        let ports = vec![PortMapping {
            container_port: 80,
            host_port: 8080,
            protocol: PortProtocol::Tcp,
            host_ip: Some("127.0.0.1".into()),
        }];
        let conflict = DockerError::DockerResponseServerError {
            status_code: 500,
            message: "Bind for 127.0.0.1:8080 failed: port is already allocated".into(),
        };
        match map_start_error(conflict, "id-3", &ports) {
            ContainerRuntimeError::PortConflict { host_port, .. } => assert_eq!(host_port, 8080),
            other => panic!("expected port conflict, got {other:?}"),
        }

        let conn = DockerError::RequestTimeoutError;
        match map_start_error(conn, "id-4", &ports) {
            ContainerRuntimeError::Connection { context, .. } => {
                assert_eq!(context, "start_container");
            }
            other => panic!("expected connection error, got {other:?}"),
        }
    }

    #[test]
    fn map_exec_error_distinguishes_connection() {
        let conn = DockerError::RequestTimeoutError;
        match map_exec_error(conn, "id-5") {
            ContainerRuntimeError::Connection { context, .. } => {
                assert_eq!(context, "exec_command");
            }
            other => panic!("expected connection error, got {other:?}"),
        }

        let other = DockerError::DockerResponseServerError {
            status_code: 500,
            message: "boom".into(),
        };
        match map_exec_error(other, "id-6") {
            ContainerRuntimeError::Exec { id, .. } => assert_eq!(id, "id-6"),
            other => panic!("expected exec error, got {other:?}"),
        }
    }

    #[test]
    fn extract_host_binding_parses_ip_port_and_protocol() {
        let msg = "Bind for 0.0.0.0:8080 failed: address already in use";
        let binding = extract_host_binding(msg).expect("binding");
        assert_eq!(binding.0.as_deref(), Some("0.0.0.0"));
        assert_eq!(binding.1, 8080);
        assert_eq!(binding.2, None);

        let msg =
            "Ports are not available: listen udp 127.0.0.1:5353: bind: address already in use";
        let binding = extract_host_binding(msg).expect("binding");
        assert_eq!(binding.0.as_deref(), Some("127.0.0.1"));
        assert_eq!(binding.1, 5353);
        assert_eq!(binding.2, Some(PortProtocol::Udp));
    }

    #[test]
    fn parse_host_port_token_handles_ip_and_port() {
        assert_eq!(
            parse_host_port_token("0.0.0.0:8080"),
            Some((Some("0.0.0.0".into()), 8080))
        );
        assert_eq!(parse_host_port_token(":9090"), Some((None, 9090)));
        assert_eq!(parse_host_port_token("8080"), Some((None, 8080)));
        assert_eq!(parse_host_port_token("bad"), None);
    }

    #[test]
    fn find_matching_mapping_honors_protocol_and_ip() {
        let ports = vec![
            PortMapping {
                container_port: 80,
                host_port: 8080,
                protocol: PortProtocol::Tcp,
                host_ip: Some("0.0.0.0".into()),
            },
            PortMapping {
                container_port: 53,
                host_port: 5353,
                protocol: PortProtocol::Udp,
                host_ip: Some("127.0.0.1".into()),
            },
        ];

        let found = find_matching_mapping(&ports, Some("127.0.0.1"), 5353, Some(PortProtocol::Udp))
            .expect("match");
        assert_eq!(found.host_port, 5353);
        assert_eq!(found.protocol, PortProtocol::Udp);

        let not_found = find_matching_mapping(&ports, Some("1.2.3.4"), 8080, None);
        assert!(not_found.is_none());
    }

    #[test]
    fn is_not_found_and_not_modified_detection() {
        let not_found = DockerError::DockerResponseServerError {
            status_code: 404,
            message: "missing".into(),
        };
        assert!(is_not_found(&not_found));
        assert!(!is_not_modified(&not_found));

        let not_modified = DockerError::DockerResponseServerError {
            status_code: 304,
            message: "unchanged".into(),
        };
        assert!(is_not_modified(&not_modified));
        assert!(!is_not_found(&not_modified));
    }

    #[test]
    fn is_connection_error_flags_expected_variants() {
        let io_err = DockerError::IOError {
            err: std::io::Error::other("io"),
        };
        assert!(is_connection_error(&io_err));

        let timeout = DockerError::RequestTimeoutError;
        assert!(is_connection_error(&timeout));

        let socket = DockerError::SocketNotFoundError("sock".into());
        assert!(is_connection_error(&socket));

        let other = DockerError::DockerResponseServerError {
            status_code: 500,
            message: "boom".into(),
        };
        assert!(!is_connection_error(&other));
    }

    #[test]
    fn map_port_conflict_parses_or_falls_back_to_first_mapping() {
        let ports = vec![
            PortMapping {
                container_port: 80,
                host_port: 8080,
                protocol: PortProtocol::Tcp,
                host_ip: Some("0.0.0.0".into()),
            },
            PortMapping {
                container_port: 53,
                host_port: 5353,
                protocol: PortProtocol::Udp,
                host_ip: Some("127.0.0.1".into()),
            },
        ];

        let err = DockerError::DockerResponseServerError {
            status_code: 500,
            message:
                "Ports are not available: listen udp 127.0.0.1:5353: bind: address already in use"
                    .into(),
        };
        let conflict = map_port_conflict(&err, &ports).expect("conflict");
        assert_eq!(conflict.host_port, 5353);
        assert_eq!(conflict.protocol, PortProtocol::Udp);
        assert_eq!(conflict.host_ip.as_deref(), Some("127.0.0.1"));

        let err = DockerError::DockerResponseServerError {
            status_code: 500,
            message: "port is already allocated".into(),
        };
        let conflict = map_port_conflict(&err, &ports).expect("fallback");
        assert_eq!(conflict.host_port, 8080);

        let err = DockerError::DockerResponseServerError {
            status_code: 500,
            message: "something else".into(),
        };
        assert!(map_port_conflict(&err, &ports).is_none());
        assert!(map_port_conflict(&err, &[]).is_none());
    }
}
