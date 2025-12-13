use super::common::{NodeStatusArg, OutputFormatArgs, DEFAULT_PAGE_LIMIT};
use clap::{Args, Subcommand};

#[derive(Debug, Clone, Args)]
pub struct NodeRegisterArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub arch: Option<String>,
    #[arg(long)]
    pub os: Option<String>,
    /// Node label in KEY=VALUE form (repeatable).
    #[arg(long = "label", value_parser = crate::parse_kv)]
    pub labels: Option<Vec<(String, String)>>,
    /// Optional capacity hint for CPU in milli-cores.
    #[arg(long = "capacity-cpu-millis")]
    pub capacity_cpu_millis: Option<u32>,
    /// Optional capacity hint for memory in bytes.
    #[arg(long = "capacity-memory-bytes")]
    pub capacity_memory_bytes: Option<u64>,
}

#[derive(Debug, Subcommand)]
pub enum NodeCommands {
    /// Register a new edge node with the control plane.
    Register(NodeRegisterArgs),
    /// List nodes with status and inventory details.
    List(NodeListArgs),
    /// Show node status summaries.
    Status(NodeStatusArgs),
}

#[derive(Debug, Clone, Args)]
pub struct NodeListArgs {
    /// Maximum number of nodes to return (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub limit: u32,
    /// Offset into the node list for pagination.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    /// Optional status filter (ready|unreachable|error|registering).
    #[arg(long = "status", value_enum)]
    pub status: Option<NodeStatusArg>,
    /// Output format for structured output (JSON/YAML); defaults to table.
    #[command(flatten)]
    pub output: OutputFormatArgs,
    /// Show labels and capacity columns in table output.
    #[arg(long)]
    pub wide: bool,
}

#[derive(Debug, Clone, Args)]
pub struct NodeStatusArgs {
    /// Maximum number of nodes to return (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub limit: u32,
    /// Offset into the node list for pagination.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    /// Optional status filter (ready|unreachable|error|registering).
    #[arg(long = "status", value_enum)]
    pub status: Option<NodeStatusArg>,
    /// Output format for structured output (JSON/YAML); defaults to table.
    #[command(flatten)]
    pub output: OutputFormatArgs,
    /// Show labels and capacity columns in table output.
    #[arg(long)]
    pub wide: bool,
}
