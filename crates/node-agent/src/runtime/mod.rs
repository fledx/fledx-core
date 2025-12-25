use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

pub mod docker;
pub mod helpers;

pub type DynContainerRuntime = Arc<dyn ContainerRuntime>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerStatus {
    Running,
    Exited { exit_code: Option<i64> },
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub exit_code: i64,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContainerResourceUsage {
    pub collected_at: DateTime<Utc>,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub blk_read_bytes: Option<u64>,
    pub blk_write_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerDetails {
    pub id: String,
    pub name: Option<String>,
    pub status: ContainerStatus,
    pub labels: Option<HashMap<String, String>>,
}

#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    async fn pull_image(&self, image: &str) -> Result<(), ContainerRuntimeError>;
    async fn start_container(&self, spec: ContainerSpec) -> Result<String, ContainerRuntimeError>;
    async fn inspect_container(&self, id: &str) -> Result<ContainerDetails, ContainerRuntimeError>;
    async fn stop_container(&self, id: &str) -> Result<(), ContainerRuntimeError>;
    async fn remove_container(&self, id: &str) -> Result<(), ContainerRuntimeError>;
    async fn list_managed_containers(&self)
    -> Result<Vec<ContainerDetails>, ContainerRuntimeError>;

    async fn container_stats(
        &self,
        id: &str,
    ) -> Result<ContainerResourceUsage, ContainerRuntimeError>;

    async fn exec_command(
        &self,
        container_id: &str,
        command: &[String],
    ) -> Result<ExecResult, ContainerRuntimeError>;
}

#[derive(Debug, Clone)]
pub struct ContainerSpec {
    pub image: String,
    pub name: Option<String>,
    pub env: Vec<(String, String)>,
    pub ports: Vec<PortMapping>,
    pub command: Option<Vec<String>>,
    pub labels: Vec<(String, String)>,
    pub mounts: Vec<FileMount>,
}

impl ContainerSpec {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            name: None,
            env: Vec::new(),
            ports: Vec::new(),
            command: None,
            labels: Vec::new(),
            mounts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMount {
    pub host_path: String,
    pub container_path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl PortProtocol {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            PortProtocol::Tcp => "tcp",
            PortProtocol::Udp => "udp",
        }
    }
}

impl std::fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: u16,
    pub protocol: PortProtocol,
    pub host_ip: Option<String>,
}

impl PortMapping {
    pub fn tcp(container_port: u16, host_port: u16) -> Self {
        Self {
            container_port,
            host_port,
            protocol: PortProtocol::Tcp,
            host_ip: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ContainerRuntimeError {
    #[error("failed to connect to runtime ({context}): {source}")]
    Connection {
        context: &'static str,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to pull image {image}: {source}")]
    PullImage {
        image: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to create container {name}: {source}")]
    CreateContainer {
        name: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("port conflict on {host_ip}:{host_port}/{protocol}")]
    PortConflict {
        id: String,
        host_port: u16,
        protocol: PortProtocol,
        host_ip: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to start container {id}: {source}")]
    StartContainer {
        id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to inspect container {id}: {source}")]
    InspectContainer {
        id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to stop container {id}: {source}")]
    StopContainer {
        id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to remove container {id}: {source}")]
    RemoveContainer {
        id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to exec command in container {id}: {source}")]
    Exec {
        id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to collect stats for container {id}: {source}")]
    Stats {
        id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to list containers: {0}")]
    ListContainers(#[source] anyhow::Error),
    #[error("container {id} not found")]
    NotFound { id: String },
}

impl ContainerRuntimeError {
    pub fn is_connection_error(&self) -> bool {
        matches!(self, ContainerRuntimeError::Connection { .. })
    }
}

pub use docker::DockerRuntime;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_spec_new_sets_defaults() {
        let spec = ContainerSpec::new("nginx:latest");
        assert_eq!(spec.image, "nginx:latest");
        assert!(spec.name.is_none());
        assert!(spec.env.is_empty());
        assert!(spec.ports.is_empty());
        assert!(spec.command.is_none());
        assert!(spec.labels.is_empty());
        assert!(spec.mounts.is_empty());
    }

    #[test]
    fn port_protocol_formats_as_expected() {
        assert_eq!(PortProtocol::Tcp.as_str(), "tcp");
        assert_eq!(PortProtocol::Udp.as_str(), "udp");
        assert_eq!(PortProtocol::Tcp.to_string(), "tcp");
        assert_eq!(PortProtocol::Udp.to_string(), "udp");
    }

    #[test]
    fn port_mapping_tcp_sets_protocol_and_ports() {
        let mapping = PortMapping::tcp(80, 8080);
        assert_eq!(mapping.container_port, 80);
        assert_eq!(mapping.host_port, 8080);
        assert_eq!(mapping.protocol, PortProtocol::Tcp);
        assert!(mapping.host_ip.is_none());
    }

    #[test]
    fn runtime_error_connection_classification() {
        let err = ContainerRuntimeError::Connection {
            context: "docker",
            source: anyhow::anyhow!("boom"),
        };
        assert!(err.is_connection_error());

        let err = ContainerRuntimeError::NotFound {
            id: "missing".into(),
        };
        assert!(!err.is_connection_error());
    }
}
