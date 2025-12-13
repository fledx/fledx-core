use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use common::api;
use uuid::Uuid;

use super::common::{
    DeploymentStatusArg, DesiredStateArg, OutputFormatArgs, DEFAULT_DEPLOY_WATCH_INTERVAL_SECS,
    DEFAULT_LOG_FOLLOW_INTERVAL_SECS, DEFAULT_PAGE_LIMIT,
};

#[derive(Debug, Subcommand)]
pub enum DeployCommands {
    /// Create a new deployment.
    Create(DeployCreateArgs),
    /// Update an existing deployment.
    Update(DeployUpdateArgs),
    /// List deployments and their status.
    List(DeploymentListArgs),
    /// Show deployment status summaries.
    Status(DeploymentStatusArgs),
    /// Stop a running deployment (sets desired state to stopped).
    Stop(DeployStopArgs),
    /// Delete a deployment.
    Delete(DeployDeleteArgs),
    /// Tail observability logs for deployments and nodes.
    Logs(DeployLogsArgs),
    /// Watch a deployment status as it changes (optional logs).
    Watch(DeployWatchArgs),
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentListArgs {
    /// Maximum number of deployments to return (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub limit: u32,
    /// Offset into the deployment list for pagination.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    /// Optional status filter (pending|deploying|running|stopped|failed).
    #[arg(long = "status", value_enum)]
    pub status: Option<DeploymentStatusArg>,
    /// Output format for structured output (JSON/YAML); defaults to table.
    #[command(flatten)]
    pub output: OutputFormatArgs,
    /// Show image and last_reported columns in table output.
    #[arg(long)]
    pub wide: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentStatusArgs {
    /// Maximum number of deployments to return (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub limit: u32,
    /// Offset into the deployment list for pagination.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    /// Optional status filter (pending|deploying|running|stopped|failed).
    #[arg(long = "status", value_enum)]
    pub status: Option<DeploymentStatusArg>,
    /// Output format for structured output (JSON/YAML); defaults to table.
    #[command(flatten)]
    pub output: OutputFormatArgs,
    /// Show image and last_reported columns in table output.
    #[arg(long)]
    pub wide: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DeployLogsArgs {
    /// Maximum number of log entries to return (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub limit: u32,
    /// Offset into the log tail for pagination.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    /// Filter logs by resource type.
    #[arg(long = "resource-type")]
    pub resource_type: Option<String>,
    /// Filter logs by resource identifier.
    #[arg(long = "resource-id", value_parser = crate::parse_uuid)]
    pub resource_id: Option<Uuid>,
    /// Include entries recorded at or after this timestamp (RFC 3339).
    #[arg(long, value_parser = crate::parse_timestamp)]
    pub since: Option<DateTime<Utc>>,
    /// Include entries recorded before this timestamp (RFC 3339).
    #[arg(long, value_parser = crate::parse_timestamp)]
    pub until: Option<DateTime<Utc>>,
    /// Continuously poll for new entries.
    #[arg(long, default_value_t = false)]
    pub follow: bool,
    /// Poll interval in seconds when following.
    #[arg(long = "follow-interval", default_value_t = DEFAULT_LOG_FOLLOW_INTERVAL_SECS)]
    pub follow_interval: u64,
}

#[derive(Debug, Clone, Args)]
pub struct DeployWatchArgs {
    /// Identifier of the deployment to monitor.
    #[arg(long = "id", value_parser = crate::parse_uuid)]
    pub deployment_id: Uuid,
    /// Poll interval in seconds between status refreshes.
    #[arg(long = "poll-interval", default_value_t = DEFAULT_DEPLOY_WATCH_INTERVAL_SECS)]
    pub poll_interval: u64,
    /// Maximum interval in seconds when backing off after errors.
    #[arg(long = "max-interval")]
    pub max_interval: Option<u64>,
    /// Stop watching after this many seconds (default: unlimited).
    #[arg(long = "max-runtime")]
    pub max_runtime: Option<u64>,
    /// Tail deployment logs alongside status updates.
    #[arg(long = "follow-logs")]
    pub follow_logs: bool,
    /// Poll interval in seconds when following logs.
    #[arg(long = "follow-logs-interval", default_value_t = DEFAULT_LOG_FOLLOW_INTERVAL_SECS)]
    pub follow_logs_interval: u64,
}

#[derive(Debug, Clone, Args, Default)]
pub struct HealthSpecArgs {
    /// HTTP path for the health probe.
    #[arg(long = "health-http", value_name = "PATH")]
    pub http_path: Option<String>,
    /// TCP port for the health probe.
    #[arg(long = "health-tcp", value_name = "PORT")]
    pub tcp_port: Option<u16>,
    /// Exec command for the health probe (pass arguments after the flag).
    #[arg(
        long = "health-exec",
        value_name = "CMD",
        num_args = 1..,
        allow_hyphen_values = true
    )]
    pub exec_command: Vec<String>,
    /// Container port targeted by HTTP probes.
    #[arg(long = "health-port", value_name = "PORT")]
    pub health_port: Option<u16>,
    /// Seconds between probe executions.
    #[arg(long = "health-interval", value_name = "SECONDS")]
    pub interval: Option<u64>,
    /// Seconds before a probe run is considered failed.
    #[arg(long = "health-timeout", value_name = "SECONDS")]
    pub timeout: Option<u64>,
    /// Failures required before the probe is marked unhealthy.
    #[arg(long = "health-threshold", value_name = "COUNT")]
    pub failure_threshold: Option<u32>,
    /// Seconds to wait before starting probes after container start.
    #[arg(long = "health-start-period", value_name = "SECONDS")]
    pub start_period: Option<u64>,
    /// Configure the probe as readiness instead of liveness.
    #[arg(long)]
    pub readiness: bool,
}

#[derive(Debug, Clone, Args)]
pub struct HealthUpdateArgs {
    #[command(flatten)]
    pub spec: HealthSpecArgs,
    /// Clear any configured health probes.
    #[arg(long)]
    pub clear_health: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DeployCreateArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub image: String,
    /// Number of desired replicas (>=1).
    #[arg(long, default_value_t = 1)]
    pub replicas: u32,
    #[arg(long, num_args = 1.., allow_hyphen_values = true)]
    pub command: Option<Vec<String>>,
    /// Repeatable env vars in KEY=VALUE form.
    #[arg(long, value_parser = crate::parse_kv)]
    pub env: Option<Vec<(String, String)>>,
    /// Secret env refs in NAME=SECRET form (repeatable).
    #[arg(long = "secret-env", value_parser = crate::parse_secret_env)]
    pub secret_env: Vec<api::SecretEnv>,
    /// Optional secret env refs in NAME=SECRET form.
    #[arg(long = "secret-env-optional", value_parser = crate::parse_optional_secret_env)]
    pub secret_env_optional: Vec<api::SecretEnv>,
    /// Secret files to mount as /path=SECRET (repeatable).
    #[arg(long = "secret-file", value_parser = crate::parse_secret_file)]
    pub secret_files: Vec<api::SecretFile>,
    /// Optional secret files to mount as /path=SECRET.
    #[arg(
        long = "secret-file-optional",
        value_parser = crate::parse_optional_secret_file
    )]
    pub secret_files_optional: Vec<api::SecretFile>,
    /// Desired state for the deployment (running|stopped).
    #[arg(
        long = "desired-state",
        value_enum,
        default_value_t = DesiredStateArg::Running
    )]
    pub desired_state: DesiredStateArg,
    /// Port mappings: [host_ip:](host|auto):container[/protocol] or container[/protocol] (use host=auto or :container for control-plane assignment).
    #[arg(long = "port", value_parser = crate::parse_port)]
    pub ports: Vec<crate::PortMapping>,
    /// Container ports to expose externally (repeatable).
    #[arg(long = "expose-port", value_parser = crate::parse_port_num)]
    pub expose_ports: Vec<u16>,
    /// Preferred node ids for placement (repeatable).
    #[arg(long = "affinity-node", value_parser = crate::parse_uuid)]
    pub affinity_nodes: Vec<Uuid>,
    /// Preferred node labels for placement in KEY=VALUE form (repeatable).
    #[arg(long = "affinity-label", value_parser = crate::parse_kv)]
    pub affinity_labels: Option<Vec<(String, String)>>,
    /// Avoid placing on specific node ids (repeatable).
    #[arg(long = "anti-affinity-node", value_parser = crate::parse_uuid)]
    pub anti_affinity_nodes: Vec<Uuid>,
    /// Avoid placing on nodes with matching labels (repeatable).
    #[arg(long = "anti-affinity-label", value_parser = crate::parse_kv)]
    pub anti_affinity_labels: Option<Vec<(String, String)>>,
    /// Prefer spreading replicas across nodes (best-effort).
    #[arg(long = "spread")]
    pub spread: bool,
    /// Bind-mount a host path into the container: HOST_PATH:CONTAINER_PATH[:ro].
    #[arg(long = "volume", value_parser = crate::parse_volume)]
    pub volumes: Vec<api::VolumeMount>,
    #[command(flatten)]
    pub health: HealthSpecArgs,
    /// Required node architecture for placement (e.g., amd64, arm64).
    #[arg(long = "require-arch")]
    pub require_arch: Option<String>,
    /// Required node OS for placement (e.g., linux).
    #[arg(long = "require-os")]
    pub require_os: Option<String>,
    /// Required node labels in KEY=VALUE form (repeatable).
    #[arg(long = "require-label", value_parser = crate::parse_kv)]
    pub require_labels: Option<Vec<(String, String)>>,
    /// Minimum CPU in milli-cores for placement.
    #[arg(long = "require-cpu-millis")]
    pub require_cpu_millis: Option<u32>,
    /// Minimum memory in bytes for placement.
    #[arg(long = "require-memory-bytes")]
    pub require_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, Args)]
pub struct DeployUpdateArgs {
    #[arg(long = "id", value_parser = crate::parse_uuid)]
    pub deployment_id: Uuid,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub image: Option<String>,
    /// Update replica count (>=1).
    #[arg(long = "replicas")]
    pub replicas: Option<u32>,
    #[arg(long, num_args = 1.., allow_hyphen_values = true)]
    pub command: Option<Vec<String>>,
    /// Remove any previously set command.
    #[arg(long = "clear-command", default_value_t = false)]
    pub clear_command: bool,
    /// Replace env vars in KEY=VALUE form.
    #[arg(long = "env", value_parser = crate::parse_kv)]
    pub env: Option<Vec<(String, String)>>,
    /// Remove all env vars.
    #[arg(long = "clear-env", default_value_t = false)]
    pub clear_env: bool,
    /// Replace secret env refs in NAME=SECRET form.
    #[arg(long = "secret-env", value_parser = crate::parse_secret_env)]
    pub secret_env: Vec<api::SecretEnv>,
    /// Replace optional secret env refs in NAME=SECRET form.
    #[arg(long = "secret-env-optional", value_parser = crate::parse_optional_secret_env)]
    pub secret_env_optional: Vec<api::SecretEnv>,
    /// Clear all secret env refs.
    #[arg(long = "clear-secret-env", default_value_t = false)]
    pub clear_secret_env: bool,
    /// Replace secret file refs in /path=SECRET form.
    #[arg(long = "secret-file", value_parser = crate::parse_secret_file)]
    pub secret_files: Vec<api::SecretFile>,
    /// Replace optional secret file refs in /path=SECRET form.
    #[arg(long = "secret-file-optional", value_parser = crate::parse_optional_secret_file)]
    pub secret_files_optional: Vec<api::SecretFile>,
    /// Clear all secret file refs.
    #[arg(long = "clear-secret-files", default_value_t = false)]
    pub clear_secret_files: bool,
    /// Desired state for the deployment (running|stopped).
    #[arg(long = "desired-state", value_enum)]
    pub desired_state: Option<DesiredStateArg>,
    /// Replace port mappings: [host_ip:](host|auto):container[/protocol] or container[/protocol] (use host=auto or :container for control-plane assignment).
    #[arg(long = "port", value_parser = crate::parse_port)]
    pub ports: Vec<crate::PortMapping>,
    /// Container ports to expose externally (repeatable).
    #[arg(long = "expose-port", value_parser = crate::parse_port_num)]
    pub expose_ports: Vec<u16>,
    /// Remove all port mappings.
    #[arg(long = "clear-ports", default_value_t = false)]
    pub clear_ports: bool,
    /// Preferred node ids for placement (repeatable).
    #[arg(long = "affinity-node", value_parser = crate::parse_uuid)]
    pub affinity_nodes: Vec<Uuid>,
    /// Preferred node labels for placement in KEY=VALUE form (repeatable).
    #[arg(long = "affinity-label", value_parser = crate::parse_kv)]
    pub affinity_labels: Option<Vec<(String, String)>>,
    /// Avoid placing on specific node ids (repeatable).
    #[arg(long = "anti-affinity-node", value_parser = crate::parse_uuid)]
    pub anti_affinity_nodes: Vec<Uuid>,
    /// Avoid placing on nodes with matching labels (repeatable).
    #[arg(long = "anti-affinity-label", value_parser = crate::parse_kv)]
    pub anti_affinity_labels: Option<Vec<(String, String)>>,
    /// Prefer spreading replicas across nodes (best-effort).
    #[arg(long = "spread")]
    pub spread: bool,
    /// Bind-mount a host path into the container: HOST_PATH:CONTAINER_PATH[:ro].
    #[arg(long = "volume", value_parser = crate::parse_volume)]
    pub volumes: Vec<api::VolumeMount>,
    /// Required node architecture for placement (e.g., amd64, arm64).
    #[arg(long = "require-arch")]
    pub require_arch: Option<String>,
    /// Required node OS for placement (e.g., linux).
    #[arg(long = "require-os")]
    pub require_os: Option<String>,
    /// Required node labels in KEY=VALUE form (repeatable).
    #[arg(long = "require-label", value_parser = crate::parse_kv)]
    pub require_labels: Option<Vec<(String, String)>>,
    /// Minimum CPU in milli-cores for placement.
    #[arg(long = "require-cpu-millis")]
    pub require_cpu_millis: Option<u32>,
    /// Minimum memory in bytes for placement.
    #[arg(long = "require-memory-bytes")]
    pub require_memory_bytes: Option<u64>,
    /// Clear all placement constraints.
    #[arg(long = "clear-constraints", default_value_t = false)]
    pub clear_constraints: bool,
    /// Clear placement hints (affinity/anti-affinity/spread).
    #[arg(long = "clear-placement", default_value_t = false)]
    pub clear_placement: bool,
    /// Clear all configured volumes.
    #[arg(long = "clear-volumes", default_value_t = false)]
    pub clear_volumes: bool,
    #[command(flatten)]
    pub health: HealthUpdateArgs,
}

#[derive(Debug, Clone, Args)]
pub struct DeployStatusArgs {
    #[arg(long = "id", value_parser = crate::parse_uuid)]
    pub deployment_id: Uuid,
    /// Emit JSON instead of the default text output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DeployStopArgs {
    #[arg(long = "id", value_parser = crate::parse_uuid)]
    pub deployment_id: Uuid,
}

#[derive(Debug, Clone, Args)]
pub struct DeployDeleteArgs {
    #[arg(long = "id", value_parser = crate::parse_uuid)]
    pub deployment_id: Uuid,
}
