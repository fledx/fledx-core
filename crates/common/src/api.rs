//! Shared API DTOs used across control-plane, node-agent, and CLI.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// Desired deployment state (wire format uses lowercase values).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DesiredState {
    /// Run the deployment.
    Running,
    /// Keep the deployment stopped.
    Stopped,
}

impl DesiredState {
    /// Returns the canonical lowercase representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            DesiredState::Running => "running",
            DesiredState::Stopped => "stopped",
        }
    }
}

/// Deployment lifecycle state reported by the control-plane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentStatus {
    /// Deployment created, waiting to be scheduled.
    Pending,
    /// Deployment is being rolled out to the node.
    Deploying,
    /// Deployment is running.
    Running,
    /// Deployment is stopped.
    Stopped,
    /// Deployment failed to run.
    Failed,
}

impl DeploymentStatus {
    /// Returns the canonical lowercase representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            DeploymentStatus::Pending => "pending",
            DeploymentStatus::Deploying => "deploying",
            DeploymentStatus::Running => "running",
            DeploymentStatus::Stopped => "stopped",
            DeploymentStatus::Failed => "failed",
        }
    }
}

/// Node status reported to operators.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    /// Node is reachable and healthy.
    Ready,
    /// Node missed heartbeats.
    Unreachable,
    /// Node is in an error state.
    Error,
    /// Node registration is pending.
    Registering,
}

/// Instance state reported by agents.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InstanceState {
    /// Container is running.
    Running,
    /// Container start is pending or in progress.
    Pending,
    /// Container was stopped cleanly.
    Stopped,
    /// Container failed to start or crashed.
    Failed,
    /// Container state cannot be determined.
    Unknown,
}

/// CPU and memory hints attached to nodes and constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, ToSchema)]
pub struct CapacityHints {
    /// CPU in milli-cores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_millis: Option<u32>,
    /// Memory in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
}

/// Placement constraints for deployments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, ToSchema)]
pub struct PlacementConstraints {
    /// Required CPU architecture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Required operating system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Required node labels.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    /// Required capacity hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<CapacityHints>,
    /// Require nodes with a public IP for public ingress.
    #[serde(default, skip_serializing_if = "is_false")]
    #[schema(example = true)]
    pub requires_public_ip: bool,
}

/// Preferred co-location rules for deployments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlacementAffinity {
    /// Preferred node identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_ids: Vec<Uuid>,
    /// Preferred node labels.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Placement hints (best-effort).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlacementHints {
    /// Prefer running alongside specific nodes/labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<PlacementAffinity>,
    /// Prefer avoiding nodes/labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anti_affinity: Option<PlacementAffinity>,
    /// Prefer spreading replicas across nodes (best-effort).
    #[serde(default, skip_serializing_if = "is_false")]
    pub spread: bool,
}

/// Assignment of a single replica to a node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct ReplicaAssignment {
    /// Replica number (0-based).
    pub replica_number: u32,
    /// Node chosen for the replica.
    pub node_id: Uuid,
}

/// Reference to a secret injected as an environment variable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretEnv {
    /// Name of the environment variable inside the container.
    pub name: String,
    /// Name of the secret to resolve on the agent.
    pub secret: String,
    /// Whether the secret is optional (missing secrets are skipped).
    #[serde(default)]
    pub optional: bool,
}

/// Reference to a secret mounted as a file in the container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretFile {
    /// Target path inside the container.
    pub path: String,
    /// Name of the secret to resolve on the agent.
    pub secret: String,
    /// Whether the secret is optional (missing secrets are skipped).
    #[serde(default)]
    pub optional: bool,
}

/// Network port mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct PortMapping {
    /// Container port exposed by the workload.
    pub container_port: u16,
    /// Optional host port to bind to (auto-assigned when omitted).
    #[serde(default)]
    pub host_port: Option<u16>,
    /// Protocol for the port mapping (defaults to tcp).
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Optional host IP to bind to.
    #[serde(default)]
    pub host_ip: Option<String>,
    /// Whether the port should be exposed externally.
    #[serde(default)]
    pub expose: bool,
    /// Optional host:port endpoint for an exposed port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Volume mount from host to container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VolumeMount {
    /// Absolute path on the host.
    pub host_path: String,
    /// Absolute path inside the container.
    pub container_path: String,
    /// Optional read-only flag (default: read/write).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

/// Deployment specification accepted by the control-plane.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "name": "web-nginx",
    "image": "nginx:1.27-alpine",
    "replicas": 1,
    "ports": [{
        "container_port": 80,
        "host_port": 8080,
        "protocol": "tcp",
        "expose": true
    }],
    "requires_public_ip": true,
    "desired_state": "running"
}))]
#[serde(deny_unknown_fields)]
pub struct DeploymentSpec {
    /// Optional human-readable name; falls back to image.
    pub name: Option<String>,
    /// Container image reference.
    pub image: String,
    /// Number of desired replicas (default: 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,
    /// Optional entrypoint/command override.
    pub command: Option<Vec<String>>,
    /// Environment variables.
    pub env: Option<HashMap<String, String>>,
    /// Secret environment variable references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_env: Option<Vec<SecretEnv>>,
    /// Secret file references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_files: Option<Vec<SecretFile>>,
    /// Port mappings requested by the deployment.
    pub ports: Option<Vec<PortMapping>>,
    /// Whether the deployment requires public ingress.
    #[serde(default, skip_serializing_if = "is_false")]
    #[schema(default = false, example = true)]
    pub requires_public_ip: bool,
    /// Route traffic via the control-plane tunnel/relay instead of direct host:port.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tunnel_only: bool,
    /// Placement constraints for scheduling.
    #[serde(default)]
    pub constraints: Option<PlacementConstraints>,
    /// Placement hints (affinity/anti-affinity/spread).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<PlacementHints>,
    /// Desired state for the deployment; defaults to running.
    pub desired_state: Option<DesiredState>,
    /// Filesystem volumes to mount into the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<VolumeMount>>,
    /// Optional health check configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<DeploymentHealth>,
}

/// Health check configuration attached to deployments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentHealth {
    /// Liveness probe executed when the container is running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<HealthProbe>,
    /// Readiness probe executed before traffic is routed to the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<HealthProbe>,
}

/// Defines a single probe configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct HealthProbe {
    /// Probe implementation and associated fields.
    #[serde(flatten)]
    pub kind: HealthProbeKind,
    /// Interval between probe executions (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_seconds: Option<u64>,
    /// Timeout for each probe run (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    /// Fail threshold before marking the probe as failing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_threshold: Option<u32>,
    /// Optional delay before running probes after container start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_period_seconds: Option<u64>,
}

/// Supported health probe implementations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum HealthProbeKind {
    /// HTTP probe hitting a container port and path.
    Http {
        /// Container port to target.
        port: u16,
        /// HTTP path to request (must not be empty).
        path: String,
    },
    /// TCP probe dialing a container port.
    Tcp {
        /// Container port to target.
        port: u16,
    },
    /// Exec probe running commands inside the container.
    Exec {
        /// Commands executed for the probe.
        command: Vec<String>,
    },
}

/// Deployment update payload accepted by the control-plane.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentUpdate {
    /// New name (None means unchanged).
    pub name: Option<String>,
    /// New image (None means unchanged).
    pub image: Option<String>,
    /// New replica count (None means unchanged).
    pub replicas: Option<u32>,
    /// Replace command (Some(None) clears it).
    #[serde(default)]
    pub command: Option<Option<Vec<String>>>,
    /// Replace environment (Some(None) clears it).
    #[serde(default)]
    pub env: Option<Option<HashMap<String, String>>>,
    /// Replace secret env refs (Some(None) clears them).
    #[serde(default)]
    pub secret_env: Option<Option<Vec<SecretEnv>>>,
    /// Replace secret file refs (Some(None) clears them).
    #[serde(default)]
    pub secret_files: Option<Option<Vec<SecretFile>>>,
    /// Replace ports (Some(None) clears them).
    #[serde(default)]
    pub ports: Option<Option<Vec<PortMapping>>>,
    /// Set or clear the public ingress requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = true)]
    pub requires_public_ip: Option<bool>,
    /// Route traffic via the control-plane tunnel/relay instead of direct host:port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_only: Option<bool>,
    /// Replace constraints (Some(None) clears them).
    #[serde(default)]
    pub constraints: Option<Option<PlacementConstraints>>,
    /// Replace placement hints (Some(None) clears them).
    #[serde(default)]
    pub placement: Option<Option<PlacementHints>>,
    /// New desired state (None means unchanged).
    pub desired_state: Option<DesiredState>,
    /// Replace volumes (Some(None) clears them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Option<Vec<VolumeMount>>>,
    /// Replace health probes (Some(None) clears them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Option<DeploymentHealth>>,
}

/// Single desired deployment entry in the desired state response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct DeploymentDesired {
    /// Deployment identifier.
    pub deployment_id: Uuid,
    /// Deployment name.
    pub name: String,
    /// Replica number (0-based) assigned to this node.
    #[serde(default = "default_replica_number")]
    pub replica_number: u32,
    /// Container image.
    pub image: String,
    /// Number of desired replicas.
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Optional command.
    pub command: Option<Vec<String>>,
    /// Optional environment variables.
    pub env: Option<HashMap<String, String>>,
    /// Secret environment variable references.
    pub secret_env: Option<Vec<SecretEnv>>,
    /// Secret file references.
    pub secret_files: Option<Vec<SecretFile>>,
    /// Port mappings for the deployment.
    pub ports: Option<Vec<PortMapping>>,
    /// Whether the deployment requires public ingress.
    #[serde(default)]
    #[schema(example = true)]
    pub requires_public_ip: bool,
    /// Route traffic via the control-plane tunnel/relay instead of direct host:port.
    #[serde(default)]
    pub tunnel_only: bool,
    /// Placement hints (best-effort).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<PlacementHints>,
    /// Filesystem volumes to mount into the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<VolumeMount>>,
    /// Optional health probes shipped to the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<DeploymentHealth>,
    /// Desired state (running or stopped).
    pub desired_state: DesiredState,
    /// Generation number used for reconciliation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "replica_generation"
    )]
    pub replica_generation: Option<i64>,
    /// Generation number used for reconciliation (deployment-wide fallback).
    pub generation: i64,
}

/// Control-plane response containing desired deployments for a node.
///
/// Agents must check the compatibility window before applying desired state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct DesiredStateResponse {
    /// Control-plane version serving the response.
    pub control_plane_version: String,
    /// Minimum node-agent version supported by the control-plane. The default
    /// policy accepts agents from the previous minor through the next minor
    /// release (inclusive, any patch) unless overridden by control-plane
    /// configuration.
    pub min_supported_agent_version: String,
    /// Maximum node-agent version supported by the control-plane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_supported_agent_version: Option<String>,
    /// Optional URL with upgrade guidance for incompatible agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_url: Option<String>,
    /// Advertised tunnel endpoint for agents to reach the gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelEndpoint>,
    /// Desired deployments assigned to the node.
    pub deployments: Vec<DeploymentDesired>,
}

/// Health status reported by the node agent for a replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthStatus {
    /// Whether the last probe reported success.
    pub healthy: bool,
    /// Result string from the last probe run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probe_result: Option<String>,
    /// Optional reason for the last probe failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional error string from the last probe execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Timestamp of the last probe attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<DateTime<Utc>>,
}

/// Resource usage metrics collected for a replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ResourceMetricSample {
    /// Timestamp when the sample was collected.
    pub collected_at: DateTime<Utc>,
    /// CPU utilization percent (0-100, best-effort).
    pub cpu_percent: f64,
    /// Memory usage in bytes.
    pub memory_bytes: u64,
    /// Network bytes received.
    pub network_rx_bytes: u64,
    /// Network bytes transmitted.
    pub network_tx_bytes: u64,
    /// Block device bytes read (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blk_read_bytes: Option<u64>,
    /// Block device bytes written (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blk_write_bytes: Option<u64>,
}

/// Recent resource metrics for a single replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ReplicaResourceMetrics {
    /// Node hosting the replica.
    pub node_id: Uuid,
    /// Replica ordinal.
    pub replica_number: u32,
    /// Last time the control-plane heard from the replica.
    pub last_seen: DateTime<Utc>,
    /// Bounded set of recent samples.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<ResourceMetricSample>,
}

/// Response containing resource metrics for a deployment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct DeploymentMetricsResponse {
    /// Deployment identifier.
    pub deployment_id: Uuid,
    /// Deployment name.
    pub deployment: String,
    /// Window applied to the samples in seconds.
    pub window_secs: u64,
    /// Timestamp when the response was generated.
    pub as_of: DateTime<Utc>,
    /// Per-replica metrics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replicas: Vec<ReplicaResourceMetrics>,
}

/// Instance status reported by the node-agent during heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct InstanceStatus {
    /// Deployment identifier.
    pub deployment_id: Uuid,
    /// Replica ordinal within the deployment.
    #[serde(default)]
    pub replica_number: u32,
    /// Optional container identifier.
    pub container_id: Option<String>,
    /// Container state.
    pub state: InstanceState,
    /// Optional status message.
    pub message: Option<String>,
    /// Restart counter.
    pub restart_count: u32,
    /// Desired generation tracked by the agent.
    #[serde(default)]
    pub generation: i64,
    /// Last time the status changed according to the agent.
    pub last_updated: DateTime<Utc>,
    /// Reachable endpoints reported by the node agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Optional health status reported for the replica.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthStatus>,
    /// Recent resource usage samples (bounded by the agent).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<ResourceMetricSample>,
}

/// Instance status returned from control-plane status endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct InstanceStatusResponse {
    /// Deployment identifier.
    pub deployment_id: Uuid,
    /// Replica ordinal within the deployment.
    pub replica_number: u32,
    /// Optional container identifier.
    pub container_id: Option<String>,
    /// Container state.
    pub state: InstanceState,
    /// Optional status message.
    pub message: Option<String>,
    /// Restart counter.
    pub restart_count: u32,
    /// Desired generation tracked by the agent.
    pub generation: i64,
    /// Last time the status changed according to the agent.
    pub last_updated: DateTime<Utc>,
    /// Time of the last heartbeat observed by the control-plane.
    pub last_seen: DateTime<Utc>,
    /// Reachable endpoints reported by the node agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Optional health status reported for the replica.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthStatus>,
    /// Recent resource usage samples reported by the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<ResourceMetricSample>,
}

/// Control-plane response describing a deployment status.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeploymentStatusResponse {
    /// Deployment identifier.
    pub deployment_id: Uuid,
    /// Deployment name.
    pub name: String,
    /// Container image.
    pub image: String,
    /// Number of desired replicas.
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Optional command.
    pub command: Option<Vec<String>>,
    /// Optional environment variables.
    pub env: Option<HashMap<String, String>>,
    /// Secret environment variable references.
    pub secret_env: Option<Vec<SecretEnv>>,
    /// Secret file references.
    pub secret_files: Option<Vec<SecretFile>>,
    /// Port mappings (after allocation).
    pub ports: Option<Vec<PortMapping>>,
    /// Whether the deployment requires public ingress.
    pub requires_public_ip: bool,
    /// Route traffic via the control-plane tunnel/relay instead of direct host:port.
    #[serde(default)]
    pub tunnel_only: bool,
    /// Placement constraints.
    pub constraints: Option<PlacementConstraints>,
    /// Placement hints (best-effort).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<PlacementHints>,
    /// Filesystem volumes to mount into the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<VolumeMount>>,
    /// Health checks configured for the deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<DeploymentHealth>,
    /// Desired state (running or stopped).
    pub desired_state: DesiredState,
    /// Current deployment status.
    pub status: DeploymentStatus,
    /// Node assigned to run the deployment.
    pub assigned_node_id: Option<Uuid>,
    /// Nodes chosen for replicas (best-effort).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<ReplicaAssignment>,
    /// Generation number.
    pub generation: i64,
    /// Timestamp of the last status report from the node.
    pub last_reported: Option<DateTime<Utc>>,
    /// Instance status details, if available.
    pub instance: Option<InstanceStatusResponse>,
    /// Lightweight recent usage summary for the deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_summary: Option<UsageSummary>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Response returned when creating a deployment.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeploymentCreateResponse {
    /// Deployment identifier.
    pub deployment_id: Uuid,
    /// Node assigned to the deployment.
    pub assigned_node_id: Uuid,
    /// Nodes chosen for replicas (best-effort).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_node_ids: Vec<Uuid>,
    /// Number of replicas that could not be placed.
    #[serde(default)]
    pub unplaced_replicas: u32,
    /// Generation number for reconciliation.
    #[serde(default = "default_generation")]
    pub generation: i64,
}

/// Config entry containing either a plaintext value or secret reference.
///
/// All entries in a config must pick a single strategy: either every entry
/// uses plaintext `value` fields or every entry uses `secret_ref` fields (they
/// cannot be mixed).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigEntry {
    /// Entry key (unique per config).
    #[schema(example = "DATABASE_URL", min_length = 1, max_length = 255)]
    pub key: String,
    /// Plaintext value (mutually exclusive with secret_ref).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(
        example = "postgres://app:secret@db:5432/app",
        max_length = 4096,
        value_type = String
    )]
    pub value: Option<String>,
    /// Secret reference (mutually exclusive with value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "db-password", min_length = 1, max_length = 255)]
    pub secret_ref: Option<String>,
}

/// Reference to a file-backed config blob.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigFile {
    /// Target path for the config file.
    #[schema(example = "/etc/app/config.yaml", min_length = 1, max_length = 512)]
    pub path: String,
    /// Reference to the stored file content.
    #[schema(example = "config-blobs/app-v1", min_length = 1, max_length = 255)]
    pub file_ref: String,
}

/// Config metadata used across responses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigMetadata {
    /// Config identifier.
    pub config_id: Uuid,
    /// Config name (unique).
    pub name: String,
    /// Monotonic version for propagation.
    pub version: i64,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Request payload to create a config.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigCreateRequest {
    /// Config name (must be unique).
    #[schema(example = "app-config", min_length = 1, max_length = 255)]
    pub name: String,
    /// Optional version override (defaults to 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 1, minimum = 1)]
    pub version: Option<i64>,
    /// Key/value entries for the config.
    #[serde(default)]
    #[schema(example = json!([{
        "key": "DATABASE_URL",
        "value": "postgres://app:secret@db:5432/app"
    }]))]
    pub entries: Vec<ConfigEntry>,
    /// File references attached to the config.
    #[serde(default)]
    #[schema(example = json!([{
        "path": "/etc/app/config.yaml",
        "file_ref": "config-blobs/app-v1"
    }]))]
    pub files: Vec<ConfigFile>,
}

/// Request payload to update/replace a config.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigUpdateRequest {
    /// Optional new name (must stay unique).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "app-config-v2", min_length = 1, max_length = 255)]
    pub name: Option<String>,
    /// Optional explicit version (defaults to current + 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 2, minimum = 1)]
    pub version: Option<i64>,
    /// Replacement entries for the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = json!([{
        "key": "DATABASE_URL",
        "value": "postgres://app:secret@db:5432/app?sslmode=disable"
    }]))]
    pub entries: Option<Vec<ConfigEntry>>,
    /// Replacement files for the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = json!([{
        "path": "/etc/app/config.yaml",
        "file_ref": "config-blobs/app-v2"
    }]))]
    pub files: Option<Vec<ConfigFile>>,
}

/// Full config response with entries and files.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "metadata": {
        "config_id": "00000000-0000-0000-0000-00000000cafe",
        "name": "app-config",
        "version": 2,
        "created_at": "2025-01-10T12:00:00Z",
        "updated_at": "2025-02-11T15:30:00Z"
    },
    "entries": [
        { "key": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app" }
    ],
    "files": [
        { "path": "/etc/app/config.yaml", "file_ref": "config-blobs/app-v2" }
    ],
    "attached_deployments": ["00000000-0000-0000-0000-00000000beef"],
    "attached_nodes": ["00000000-0000-0000-0000-00000000babe"]
}))]
pub struct ConfigResponse {
    /// Config metadata.
    pub metadata: ConfigMetadata,
    /// Config entries.
    #[serde(default)]
    pub entries: Vec<ConfigEntry>,
    /// Config files.
    #[serde(default)]
    pub files: Vec<ConfigFile>,
    /// Deployments currently attached to the config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attached_deployments: Vec<Uuid>,
    /// Nodes currently attached to the config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attached_nodes: Vec<Uuid>,
}

/// Config summary for list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigSummary {
    /// Config metadata.
    pub metadata: ConfigMetadata,
    /// Number of key/value entries.
    pub entry_count: i64,
    /// Number of file references.
    pub file_count: i64,
}

/// Paginated config list response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigSummaryPage {
    /// Requested page size.
    pub limit: u32,
    /// Requested offset.
    pub offset: u32,
    /// Config summaries on this page.
    pub items: Vec<ConfigSummary>,
}

/// Attachment/ detachment response for configs.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "metadata": {
        "config_id": "00000000-0000-0000-0000-00000000cafe",
        "name": "app-config",
        "version": 2,
        "created_at": "2025-01-10T12:00:00Z",
        "updated_at": "2025-02-11T15:30:00Z"
    },
    "deployment_id": "00000000-0000-0000-0000-00000000beef",
    "node_id": null,
    "attached": true,
    "attached_at": "2025-02-12T08:00:00Z"
}))]
pub struct ConfigAttachmentResponse {
    /// Config metadata.
    pub metadata: ConfigMetadata,
    /// Attached deployment identifier (when applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<Uuid>,
    /// Attached node identifier (when applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<Uuid>,
    /// Whether the attachment exists after the operation.
    pub attached: bool,
    /// Timestamp when the attachment was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_at: Option<DateTime<Utc>>,
}

/// Config payload returned to node agents.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "metadata": {
        "config_id": "00000000-0000-0000-0000-00000000cafe",
        "name": "app-config",
        "version": 2,
        "created_at": "2025-01-10T12:00:00Z",
        "updated_at": "2025-02-11T15:30:00Z"
    },
    "entries": [
        { "key": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app" }
    ],
    "files": [
        { "path": "/etc/app/config.yaml", "file_ref": "config-blobs/app-v2" }
    ],
    "attached_deployments": ["00000000-0000-0000-0000-00000000beef"],
    "attached_nodes": ["00000000-0000-0000-0000-00000000babe"],
    "checksum": "7995c1ac84c543fa"
}))]
pub struct ConfigDesired {
    /// Config metadata including version and timestamps.
    pub metadata: ConfigMetadata,
    /// Key/value pairs defined on the config.
    #[serde(default)]
    pub entries: Vec<ConfigEntry>,
    /// File references defined on the config.
    #[serde(default)]
    pub files: Vec<ConfigFile>,
    /// Deployments that reference this config on the requesting node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attached_deployments: Vec<Uuid>,
    /// Nodes that reference this config (usually the requester only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attached_nodes: Vec<Uuid>,
    /// Integrity hash of the config content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

/// Service identity bundle delivered to node agents for mTLS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "identity": "service://tenant-a/payments",
    "cert_pem": "-----BEGIN CERTIFICATE-----...",
    "key_pem": "-----BEGIN PRIVATE KEY-----...",
    "ca_pem": "-----BEGIN CERTIFICATE-----CA...",
    "expires_at": "2025-03-01T12:00:00Z",
    "rotate_after": "2025-02-28T12:00:00Z"
}))]
pub struct ServiceIdentityBundle {
    /// Canonical identity string (URI or ref) used to name the bundle.
    pub identity: String,
    /// PEM-encoded end-entity certificate.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
    /// Optional PEM-encoded CA chain for peers/verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    /// Expiry time of the certificate (UTC) for observability/refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Suggested time to refresh before expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_after: Option<DateTime<Utc>>,
}

/// Response returned when agents fetch configs for a node.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "configs": [{
        "metadata": {
            "config_id": "00000000-0000-0000-0000-00000000cafe",
            "name": "app-config",
            "version": 2,
            "created_at": "2025-01-10T12:00:00Z",
            "updated_at": "2025-02-11T15:30:00Z"
        },
        "entries": [
            { "key": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app" }
        ],
        "files": [
            { "path": "/etc/app/config.yaml", "file_ref": "config-blobs/app-v2" }
        ],
        "attached_deployments": ["00000000-0000-0000-0000-00000000beef"],
        "attached_nodes": ["00000000-0000-0000-0000-00000000babe"],
        "checksum": "7995c1ac84c543fa"
    }]
}))]
pub struct NodeConfigResponse {
    /// Configs relevant to the requesting node.
    #[serde(default)]
    pub configs: Vec<ConfigDesired>,
    /// Service identity bundles provisioned for this node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_identities: Vec<ServiceIdentityBundle>,
}

/// Paginated list response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Page<T> {
    /// Requested page size.
    pub limit: u32,
    /// Requested offset.
    pub offset: u32,
    /// Items on this page.
    pub items: Vec<T>,
}

/// Paginated usage rollup response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UsageRollupPage {
    /// Requested page size.
    pub limit: u32,
    /// Requested offset.
    pub offset: u32,
    /// Aggregated resource usage rollups on this page.
    pub items: Vec<UsageRollup>,
}

/// Paginated node list response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeSummaryPage {
    /// Requested page size.
    pub limit: u32,
    /// Requested offset.
    pub offset: u32,
    /// Nodes on this page.
    pub items: Vec<NodeSummary>,
}

/// Paginated deployment list response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeploymentSummaryPage {
    /// Requested page size.
    pub limit: u32,
    /// Requested offset.
    pub offset: u32,
    /// Deployments on this page.
    pub items: Vec<DeploymentSummary>,
}

/// Paginated audit log response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditLogPage {
    /// Requested page size.
    pub limit: u32,
    /// Requested offset.
    pub offset: u32,
    /// Audit log entries on this page.
    pub items: Vec<AuditLogEntry>,
}

/// Ingress route object exposed via operator + consumer APIs.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "00000000-0000-0000-0000-00000000babe",
    "domain": "example.com",
    "path_prefix": "/api",
    "backend_id": "00000000-0000-0000-0000-00000000cafe",
    "tls_ref": "tls-example",
    "generation": 3,
    "created_at": "2025-02-12T12:00:00Z",
    "updated_at": "2025-02-12T12:10:00Z",
    "deleted_at": null
}))]
pub struct IngressRoute {
    /// Route identifier.
    pub id: Uuid,
    /// Fully-qualified domain name handled by the route.
    pub domain: String,
    /// Path prefix (must start with `/`).
    pub path_prefix: String,
    /// Deployment id to forward to.
    pub backend_id: Uuid,
    /// Optional TLS reference identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ref: Option<String>,
    /// Route traffic to backend via tunnel/relay instead of direct host:port.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tunnel_only: bool,
    /// Monotonic version used for watches.
    pub generation: i64,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
    /// Deletion timestamp when soft-deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Request body to create an ingress route.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "domain": "example.com",
    "path_prefix": "/",
    "backend_id": "00000000-0000-0000-0000-00000000cafe",
    "tls_ref": "edge-cert"
}))]
pub struct IngressRouteCreateRequest {
    /// Fully-qualified domain name.
    pub domain: String,
    /// Path prefix beginning with `/`.
    #[serde(default = "default_root_path")]
    pub path_prefix: String,
    /// Deployment id to forward to.
    pub backend_id: Uuid,
    /// Optional TLS reference identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ref: Option<String>,
    /// Route traffic via tunnel/relay instead of direct host:port.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tunnel_only: bool,
}

fn default_root_path() -> String {
    "/".to_string()
}

fn deserialize_nullable_string<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NullableVisitor;

    impl<'de> serde::de::Visitor<'de> for NullableVisitor {
        type Value = Option<Option<String>>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string, null, or nothing")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(None))
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = String::deserialize(deserializer)?;
            Ok(Some(Some(value)))
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(None))
        }
    }

    deserializer.deserialize_option(NullableVisitor)
}

/// Request body to update an ingress route.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IngressRouteUpdateRequest {
    /// Fully-qualified domain name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Path prefix beginning with `/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// Deployment id to forward to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<Uuid>,
    /// Optional TLS reference identifier (null clears).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_nullable_string"
    )]
    pub tls_ref: Option<Option<String>>,
    /// Route traffic via tunnel/relay instead of direct host:port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_only: Option<bool>,
}

/// Response returned when watching ingress routes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IngressRouteWatchResponse {
    /// Highest generation in the result set.
    pub max_generation: i64,
    /// Routes with generation greater than the provided cursor.
    pub items: Vec<IngressRoute>,
}

/// Paginated ingress route list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IngressRoutePage {
    /// Requested page size.
    pub limit: u32,
    /// Requested offset.
    pub offset: u32,
    /// Routes on this page.
    pub items: Vec<IngressRoute>,
}

/// Uploaded TLS certificate metadata (private key is never returned).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TlsCert {
    /// Unique certificate identifier.
    pub id: Uuid,
    /// Stable operator-provided reference used by ingress routes.
    pub reference: String,
    /// Friendly name for operators.
    pub name: String,
    /// Common name extracted from the leaf certificate, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Start of certificate validity window (UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    /// Expiry time of the certificate (UTC) for observability/refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    /// Expiry time of the certificate (UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Whole days remaining until expiry (floored; negative when expired).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_remaining: Option<i64>,
    /// When set the certificate can no longer be bound to routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Upload request for a TLS certificate and key pair.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "reference": "edge-cert",
    "name": "edge.example.com",
    "cert_pem": "-----BEGIN CERTIFICATE-----...",
    "key_pem": "-----BEGIN PRIVATE KEY-----..."
}))]
pub struct TlsCertCreateRequest {
    /// Unique reference used by ingress routes via `tls_ref`.
    pub reference: String,
    /// Friendly display name.
    pub name: String,
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// PEM-encoded private key for the certificate.
    pub key_pem: String,
}

/// Paginated TLS certificate list response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TlsCertPage {
    /// Requested page size.
    pub limit: u32,
    /// Requested offset.
    pub offset: u32,
    /// Returned certificates (PEM omitted).
    pub items: Vec<TlsCert>,
}

/// Node summary for list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "node_id": "00000000-0000-0000-0000-000000000042",
    "name": "edge-01",
    "status": "ready",
    "last_seen": "2025-12-10T18:42:00Z",
    "arch": "x86_64",
    "os": "linux",
    "public_ip": "203.0.113.10",
    "public_host": "edge-01.example.com",
    "labels": {
        "zone": "edge-west",
        "gpu": "false"
    },
    "capacity": {
        "cpu_millis": 2000,
        "memory_bytes": 8589934592u64
    }
}))]
pub struct NodeSummary {
    /// Node identifier.
    pub node_id: Uuid,
    /// Optional node name.
    pub name: Option<String>,
    /// Current status of the node.
    pub status: NodeStatus,
    /// Last heartbeat timestamp.
    pub last_seen: Option<DateTime<Utc>>,
    /// CPU architecture reported by the node.
    pub arch: Option<String>,
    /// Operating system reported by the node.
    pub os: Option<String>,
    /// Optional public IP reported by the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "203.0.113.10")]
    pub public_ip: Option<String>,
    /// Optional public host reported by the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "edge-01.example.com")]
    pub public_host: Option<String>,
    /// Node labels.
    pub labels: Option<HashMap<String, String>>,
    /// Optional capacity hints reported by the node.
    pub capacity: Option<CapacityHints>,
}

/// Deployment summary for list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeploymentSummary {
    /// Deployment identifier.
    pub deployment_id: Uuid,
    /// Deployment name.
    pub name: String,
    /// Container image.
    pub image: String,
    /// Number of desired replicas.
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Desired state (running or stopped).
    pub desired_state: DesiredState,
    /// Current deployment status.
    pub status: DeploymentStatus,
    /// Node assigned to run the deployment.
    pub assigned_node_id: Option<Uuid>,
    /// Route traffic via the control-plane tunnel/relay instead of direct host:port.
    #[serde(default)]
    pub tunnel_only: bool,
    /// Nodes chosen for replicas (best-effort).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<ReplicaAssignment>,
    /// Generation number.
    pub generation: i64,
    /// Placement hints (best-effort).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<PlacementHints>,
    /// Filesystem volumes to mount into the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<VolumeMount>>,
    /// Timestamp of the last status report from the node.
    pub last_reported: Option<DateTime<Utc>>,
}

/// Response describing a node and its instances.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "node_id": "00000000-0000-0000-0000-000000000042",
    "name": "edge-01",
    "status": "ready",
    "last_seen": "2025-12-10T18:42:00Z",
    "arch": "x86_64",
    "os": "linux",
    "public_ip": "203.0.113.10",
    "public_host": "edge-01.example.com",
    "labels": {
        "zone": "edge-west",
        "gpu": "false"
    },
    "capacity": {
        "cpu_millis": 2000,
        "memory_bytes": 8589934592u64
    },
    "instances": [],
    "usage_summary": null
}))]
pub struct NodeStatusResponse {
    /// Node identifier.
    pub node_id: Uuid,
    /// Optional node name.
    pub name: Option<String>,
    /// Current status of the node.
    pub status: NodeStatus,
    /// Last heartbeat timestamp.
    pub last_seen: Option<DateTime<Utc>>,
    /// CPU architecture reported by the node.
    pub arch: Option<String>,
    /// Operating system reported by the node.
    pub os: Option<String>,
    /// Optional public IP reported by the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "203.0.113.10")]
    pub public_ip: Option<String>,
    /// Optional public host reported by the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "edge-01.example.com")]
    pub public_host: Option<String>,
    /// Node labels.
    pub labels: Option<HashMap<String, String>>,
    /// Optional capacity hints reported by the node.
    pub capacity: Option<CapacityHints>,
    /// Instances running on the node.
    pub instances: Vec<InstanceStatusResponse>,
    /// Lightweight recent usage summary for the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_summary: Option<UsageSummary>,
}

/// Response returned when registering a node.
/// Advertised tunnel endpoint returned by the control-plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TunnelEndpoint {
    /// Hostname or IP where the gateway exposes the tunnel listener.
    #[schema(example = "tunnel.edge.example.com")]
    pub host: String,
    /// Port where the gateway exposes the tunnel listener.
    #[schema(example = 49423)]
    pub port: u16,
    /// Whether the tunnel listener expects TLS (HTTPS). Defaults to true.
    #[serde(default = "default_tunnel_use_tls")]
    #[schema(example = true)]
    pub use_tls: bool,
    /// Max seconds to wait for establishing the CONNECT tunnel.
    #[schema(example = 10)]
    pub connect_timeout_secs: u64,
    /// Heartbeat cadence expected by the gateway once connected.
    #[schema(example = 30)]
    pub heartbeat_interval_secs: u64,
    /// Time without heartbeats before the gateway closes the tunnel.
    #[schema(example = 90)]
    pub heartbeat_timeout_secs: u64,
    /// Header carrying the node bearer token during CONNECT.
    #[schema(example = "x-fledx-tunnel-token")]
    pub token_header: String,
}

const fn default_tunnel_use_tls() -> bool {
    true
}

/// Response returned when registering a node.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegistrationResponse {
    /// Node identifier.
    pub node_id: Uuid,
    /// Bearer token for the node.
    pub node_token: String,
    /// Advertised tunnel endpoint for private agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelEndpoint>,
}

/// Request to create a new token for a node (rotation).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenRotateRequest {
    /// Optional expiry timestamp for the token.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether to disable existing tokens for the subject.
    #[serde(default)]
    pub disable_existing: bool,
}

/// Request to create an operator token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenCreateRequest {
    /// Optional expiry timestamp for the token.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response returned when issuing a new token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    /// Token record identifier.
    pub token_id: Uuid,
    /// Plaintext token (only returned at creation time).
    pub token: String,
    /// Optional expiry timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response returned when disabling a token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TokenDisableResponse {
    /// Token record identifier.
    pub token_id: Uuid,
    /// Timestamp at which the token was disabled.
    pub disabled_at: DateTime<Utc>,
}

/// Audit log entry describing an operator action.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditLogEntry {
    /// Audit record identifier.
    pub id: Uuid,
    /// Action name (e.g., deployment.create).
    pub action: String,
    /// Type of resource the action targeted.
    pub resource_type: String,
    /// Optional resource identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    /// Operator token record identifier when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_token_id: Option<Uuid>,
    /// Hash of the operator token used (for env-configured tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_token_hash: Option<String>,
    /// Role associated with the operator token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_role: Option<String>,
    /// Scopes associated with the operator token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_scopes: Option<Vec<String>>,
    /// Request identifier associated with the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Outcome of the action (success|failure).
    pub status: String,
    /// Optional payload or error snippet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Timestamp when the entry was recorded.
    pub created_at: DateTime<Utc>,
}

/// Weighted-average resource usage over a rolling window.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
#[schema(example = json!({
    "window_start": "2025-02-03T04:00:00Z",
    "window_end": "2025-02-03T04:05:00Z",
    "samples": 12,
    "avg_cpu_percent": 18.4,
    "avg_memory_bytes": 241172480,
    "avg_network_rx_bytes": 16384,
    "avg_network_tx_bytes": 12288,
    "avg_blk_read_bytes": 4096,
    "avg_blk_write_bytes": 2048
}))]
pub struct UsageSummary {
    /// Beginning of the summarized window.
    pub window_start: DateTime<Utc>,
    /// End of the summarized window (usually now).
    pub window_end: DateTime<Utc>,
    /// Total usage samples contributing to the summary.
    pub samples: i64,
    /// Average CPU percent over the window.
    pub avg_cpu_percent: f64,
    /// Average memory usage in bytes.
    pub avg_memory_bytes: i64,
    /// Average network RX bytes per sample.
    pub avg_network_rx_bytes: i64,
    /// Average network TX bytes per sample.
    pub avg_network_tx_bytes: i64,
    /// Average block read bytes per sample (when reported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_blk_read_bytes: Option<i64>,
    /// Average block write bytes per sample (when reported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_blk_write_bytes: Option<i64>,
}

/// Minute-level usage rollup emitted by nodes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
#[schema(example = json!({
    "deployment_id": "00000000-0000-0000-0000-00000000cafe",
    "node_id": "00000000-0000-0000-0000-00000000beef",
    "replica_number": 0,
    "bucket_start": "2025-02-03T04:05:00Z",
    "samples": 2,
    "avg_cpu_percent": 12.3,
    "avg_memory_bytes": 230686720,
    "avg_network_rx_bytes": 10240,
    "avg_network_tx_bytes": 9216,
    "avg_blk_read_bytes": 4096,
    "avg_blk_write_bytes": 0
}))]
pub struct UsageRollup {
    /// Deployment identifier.
    pub deployment_id: Uuid,
    /// Node identifier.
    pub node_id: Uuid,
    /// Replica ordinal within the deployment.
    pub replica_number: i64,
    /// Start of the bucket (truncated to minute).
    pub bucket_start: DateTime<Utc>,
    /// Number of samples aggregated into the bucket.
    pub samples: i64,
    /// Average CPU percent for the bucket.
    pub avg_cpu_percent: f64,
    /// Average memory usage in bytes for the bucket.
    pub avg_memory_bytes: i64,
    /// Average network RX bytes for the bucket.
    pub avg_network_rx_bytes: i64,
    /// Average network TX bytes for the bucket.
    pub avg_network_tx_bytes: i64,
    /// Average block read bytes for the bucket, when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_blk_read_bytes: Option<i64>,
    /// Average block write bytes for the bucket, when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_blk_write_bytes: Option<i64>,
}

/// Individual metric sample returned in summaries.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetricSample {
    /// HTTP method as captured on the control-plane metric labels.
    pub method: String,
    /// Request path (labels may be templated).
    pub path: String,
    /// HTTP response status code observed.
    pub status: String,
    /// Counter value for the line.
    pub count: f64,
}

/// Snapshot of the top HTTP request metrics.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MetricsSummary {
    /// Requested page size.
    pub limit: u32,
    /// Reporting window (seconds) enforced by the control-plane.
    pub window_secs: u64,
    /// Timestamp when the snapshot was taken.
    pub as_of: DateTime<Utc>,
    /// Metric samples (sorted by count descending).
    #[serde(default)]
    pub items: Vec<MetricSample>,
}

fn default_generation() -> i64 {
    1
}

fn default_replicas() -> u32 {
    1
}

fn default_replica_number() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enum_as_str_is_lowercase() {
        assert_eq!(DesiredState::Running.as_str(), "running");
        assert_eq!(DesiredState::Stopped.as_str(), "stopped");
        assert_eq!(DeploymentStatus::Pending.as_str(), "pending");
        assert_eq!(DeploymentStatus::Deploying.as_str(), "deploying");
        assert_eq!(DeploymentStatus::Running.as_str(), "running");
        assert_eq!(DeploymentStatus::Stopped.as_str(), "stopped");
        assert_eq!(DeploymentStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn ingress_route_tls_ref_handles_nullability() {
        let missing: IngressRouteUpdateRequest =
            serde_json::from_value(json!({})).expect("deserialize update request without tls_ref");
        assert_eq!(missing.tls_ref, None);

        let null_value: IngressRouteUpdateRequest =
            serde_json::from_value(json!({"tls_ref": null}))
                .expect("deserialize update request with null tls_ref");
        assert_eq!(null_value.tls_ref, Some(None));

        let string_value: IngressRouteUpdateRequest =
            serde_json::from_value(json!({"tls_ref": "edge-cert"}))
                .expect("deserialize update request with string tls_ref");
        assert_eq!(string_value.tls_ref, Some(Some("edge-cert".to_string())));
    }

    #[test]
    fn defaulted_fields_apply_on_deserialize() {
        let port: PortMapping = serde_json::from_value(json!({"container_port": 8080}))
            .expect("deserialize port mapping");
        assert_eq!(port.protocol, "tcp");
        assert_eq!(port.host_port, None);
        assert_eq!(port.host_ip, None);
        assert!(!port.expose);

        let create: IngressRouteCreateRequest = serde_json::from_value(json!({
            "domain": "edge.example.com",
            "backend_id": "00000000-0000-0000-0000-000000000042"
        }))
        .expect("deserialize ingress create request");
        assert_eq!(create.path_prefix, "/");

        let tunnel: TunnelEndpoint = serde_json::from_value(json!({
            "host": "tunnel.edge.example.com",
            "port": 49423,
            "connect_timeout_secs": 10,
            "heartbeat_interval_secs": 30,
            "heartbeat_timeout_secs": 90,
            "token_header": "x-fledx-tunnel-token"
        }))
        .expect("deserialize tunnel endpoint");
        assert!(tunnel.use_tls);
    }

    #[test]
    fn placement_constraints_skip_requires_public_ip_when_false() {
        let constraints = PlacementConstraints {
            requires_public_ip: false,
            ..Default::default()
        };
        let value = serde_json::to_value(&constraints).expect("serialize");
        assert!(value.get("requires_public_ip").is_none());

        let constraints = PlacementConstraints {
            requires_public_ip: true,
            ..Default::default()
        };
        let value = serde_json::to_value(&constraints).expect("serialize");
        assert_eq!(value.get("requires_public_ip"), Some(&json!(true)));
    }

    #[test]
    fn placement_affinity_rejects_unknown_fields() {
        let result: Result<PlacementAffinity, _> =
            serde_json::from_value(json!({ "node_ids": [], "extra": "nope" }));
        assert!(result.is_err());
    }

    #[test]
    fn ingress_route_update_rejects_non_string_tls_ref() {
        let result: Result<IngressRouteUpdateRequest, _> =
            serde_json::from_value(json!({ "tls_ref": 42 }));
        assert!(result.is_err());
    }

    #[test]
    fn deployment_desired_defaults_replica_fields() {
        let desired: DeploymentDesired = serde_json::from_value(json!({
            "deployment_id": "00000000-0000-0000-0000-000000000042",
            "name": "edge-app",
            "image": "nginx:latest",
            "desired_state": "running",
            "generation": 5
        }))
        .expect("deserialize desired deployment");
        assert_eq!(desired.replicas, 1);
        assert_eq!(desired.replica_number, 0);
        assert!(!desired.requires_public_ip);
        assert!(!desired.tunnel_only);
    }
}
