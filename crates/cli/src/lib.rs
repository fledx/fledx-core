pub mod api;
pub mod args;
pub mod commands;
pub mod parse;
pub mod validate;
mod version;
pub mod view;
pub mod watch;

pub use api::OperatorApi;
pub use args::*;
pub use commands::CommandContext;
pub use parse::*;
pub use validate::*;

pub type PortMapping = ::common::api::PortMapping;

use clap::Parser;

use crate::commands::completions::generate_completions;
use crate::commands::configs::handle_configs;
use crate::commands::deploy::handle_deploy_commands;
use crate::commands::metrics::handle_metrics;
use crate::commands::nodes::handle_nodes;
use crate::commands::status::handle_status;
use crate::commands::usage::handle_usage;

/// Shared async entrypoint used by the CLI binaries.
pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run_parsed(cli).await
}

/// Execute the CLI given a pre-parsed argument struct.
pub async fn run_parsed(cli: Cli) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let Cli {
        globals:
            GlobalArgs {
                control_plane_url,
                operator_token,
                operator_header,
                registration_token,
            },
        command,
    } = cli;

    let base = control_plane_url.trim_end_matches('/').to_string();
    let ctx = CommandContext::new(
        client.clone(),
        base.clone(),
        operator_header,
        operator_token,
    );

    match command {
        Commands::Status(args) => handle_status(&ctx, args).await?,
        Commands::Nodes { command } => handle_nodes(&ctx, registration_token, command).await?,
        Commands::Deployments { command } => handle_deploy_commands(&ctx, *command).await?,
        Commands::Configs { command } => handle_configs(&ctx, command).await?,
        Commands::Metrics { command } => handle_metrics(&ctx, command).await?,
        Commands::Usage { command } => handle_usage(&ctx, command).await?,
        Commands::Completions { shell } => generate_completions(shell),
    }

    Ok(())
}
