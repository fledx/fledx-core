use clap::Args;

use super::common::{DEFAULT_PAGE_LIMIT, DeploymentStatusArg, NodeStatusArg};

#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    /// Maximum number of nodes to return (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub node_limit: u32,
    /// Offset into the node list for pagination.
    #[arg(long, default_value_t = 0)]
    pub node_offset: u32,
    /// Optional status filter for nodes.
    #[arg(long = "node-status", value_enum)]
    pub node_status: Option<NodeStatusArg>,
    /// Maximum number of deployments to return (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub deploy_limit: u32,
    /// Offset into the deployment list for pagination.
    #[arg(long, default_value_t = 0)]
    pub deploy_offset: u32,
    /// Optional status filter for deployments.
    #[arg(long = "deploy-status", value_enum)]
    pub deploy_status: Option<DeploymentStatusArg>,
    /// Emit JSON instead of tables.
    #[arg(long)]
    pub json: bool,
    /// Show extra columns for nodes (labels/capacity) and deployments (image/last_reported).
    #[arg(long)]
    pub wide: bool,
    /// Refresh continuously.
    #[arg(long, default_value_t = false)]
    pub watch: bool,
    /// Watch refresh interval in seconds.
    #[arg(long = "watch-interval", default_value_t = 2)]
    pub watch_interval: u64,
    /// Only show node status (skips deployments).
    #[arg(long)]
    pub nodes_only: bool,
    /// Only show deployment status (skips nodes).
    #[arg(long)]
    pub deploys_only: bool,
    /// Disable ANSI colors even if stdout is a TTY.
    #[arg(long)]
    pub no_color: bool,
}
