use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum MetricsCommands {
    /// Show aggregated HTTP metrics.
    Show(MetricsShowArgs),
}

#[derive(Debug, Clone, Args)]
pub struct MetricsShowArgs {
    /// Maximum number of metrics entries to return (1-100).
    #[arg(long)]
    pub limit: Option<u32>,
    /// Emit JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}
