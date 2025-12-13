use chrono::Duration as ChronoDuration;
use clap::{Args, Subcommand};
use uuid::Uuid;

use super::common::{OutputFormatArgs, DEFAULT_PAGE_LIMIT};

#[derive(Debug, Subcommand)]
pub enum UsageCommands {
    /// List recent resource usage rollups.
    List(UsageListArgs),
}

#[derive(Debug, Clone, Args)]
pub struct UsageListArgs {
    /// Deployment identifier to filter usage (required if --node is absent).
    #[arg(long = "deployment", value_parser = crate::parse_uuid)]
    pub deployment_id: Option<Uuid>,
    /// Node identifier to filter usage (required if --deployment is absent).
    #[arg(long = "node", value_parser = crate::parse_uuid)]
    pub node_id: Option<Uuid>,
    /// Replica number to filter usage.
    #[arg(long = "replica")]
    pub replica_number: Option<u32>,
    /// Maximum number of usage rows to return (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub limit: u32,
    /// Offset into the usage list for pagination.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    /// Look back over this window (supports s, m, h, d suffixes).
    #[arg(long = "range", value_parser = crate::parse_duration_arg, default_value = "15m")]
    pub range: ChronoDuration,
    /// Output format for structured output (JSON/YAML); defaults to table.
    #[command(flatten)]
    pub output: OutputFormatArgs,
}
