pub mod api;
pub mod args;
pub mod commands;
pub mod parse;
pub mod validate;
mod version;
pub mod view;
pub mod watch;
#[cfg(feature = "bootstrap")]
#[path = "bootstrap/mod.rs"]
mod bootstrap_flow;
#[cfg(feature = "bootstrap")]
mod profile_store;
#[cfg(test)]
mod test_support;

pub use api::OperatorApi;
pub use args::*;
pub use commands::CommandContext;
pub use parse::*;
pub use validate::*;

pub type PortMapping = ::common::api::PortMapping;

#[cfg(not(feature = "bootstrap"))]
use clap::Parser;
#[cfg(feature = "bootstrap")]
use clap::{CommandFactory, FromArgMatches};
#[cfg(feature = "bootstrap")]
use clap::parser::ValueSource;

use crate::commands::completions::generate_completions;
use crate::commands::configs::handle_configs;
use crate::commands::deploy::handle_deploy_commands;
use crate::commands::metrics::handle_metrics;
use crate::commands::nodes::handle_nodes;
use crate::commands::status::handle_status;
use crate::commands::usage::handle_usage;
#[cfg(feature = "bootstrap")]
use crate::commands::bootstrap::handle_bootstrap;
#[cfg(feature = "bootstrap")]
use crate::commands::profiles::handle_profiles;
#[cfg(feature = "bootstrap")]
use crate::profile_store::ProfileStore;

/// Shared async entrypoint used by the CLI binaries.
pub async fn run() -> anyhow::Result<()> {
    #[cfg(feature = "bootstrap")]
    {
        let matches = Cli::command().get_matches();
        let mut cli = Cli::from_arg_matches(&matches)?;

        let mut store = ProfileStore::load()?;
        let selected_profile = resolve_profile_name(&cli.profile, &store);
        apply_profile_overrides(&matches, &cli.command, &selected_profile, &store, &mut cli.globals)?;

        if store.default_profile.is_none() && selected_profile.is_some() {
            store.default_profile = selected_profile.clone();
            store.save()?;
        }

        cli.profile = selected_profile;
        return run_parsed(cli).await;
    }

    #[cfg(not(feature = "bootstrap"))]
    {
        let cli = Cli::parse();
        run_parsed(cli).await
    }
}

/// Execute the CLI given a pre-parsed argument struct.
pub async fn run_parsed(cli: Cli) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    #[cfg(feature = "bootstrap")]
    let selected_profile = cli.profile.clone();

    let globals = cli.globals.clone();
    let registration_token = globals.registration_token.clone();
    let base = globals.control_plane_url.trim_end_matches('/').to_string();
    let ctx = CommandContext::new(
        client.clone(),
        base.clone(),
        globals.operator_header.clone(),
        globals.operator_token.clone(),
    );
    let command = cli.command;

    match command {
        Commands::Status(args) => handle_status(&ctx, args).await?,
        Commands::Nodes { command } => handle_nodes(&ctx, registration_token, command).await?,
        Commands::Deployments { command } => handle_deploy_commands(&ctx, *command).await?,
        Commands::Configs { command } => handle_configs(&ctx, command).await?,
        Commands::Metrics { command } => handle_metrics(&ctx, command).await?,
        Commands::Usage { command } => handle_usage(&ctx, command).await?,
        Commands::Completions { shell } => generate_completions(shell),
        #[cfg(feature = "bootstrap")]
        Commands::Bootstrap { command } => {
            handle_bootstrap(client, selected_profile, &globals, command).await?
        }
        #[cfg(feature = "bootstrap")]
        Commands::Profile { command } => handle_profiles(selected_profile, command)?,
    }

    Ok(())
}

#[cfg(feature = "bootstrap")]
fn resolve_profile_name(cli_profile: &Option<String>, store: &ProfileStore) -> Option<String> {
    cli_profile.clone().or_else(|| store.default_profile.clone())
}

#[cfg(feature = "bootstrap")]
fn apply_profile_overrides(
    matches: &clap::ArgMatches,
    command: &Commands,
    selected_profile: &Option<String>,
    store: &ProfileStore,
    globals: &mut GlobalArgs,
) -> anyhow::Result<()> {
    let Some(name) = selected_profile.as_deref() else {
        return Ok(());
    };

    let profile = match store.profiles.get(name) {
        Some(profile) => profile,
        None => {
            let allow_missing = matches!(
                command,
                Commands::Bootstrap { .. } | Commands::Profile { .. }
            );
            if allow_missing {
                return Ok(());
            }
            anyhow::bail!("profile '{}' not found (create it via `fledx profile set`)", name);
        }
    };

    if matches.value_source("control_plane_url") == Some(ValueSource::DefaultValue) {
        if let Some(url) = profile.control_plane_url.clone() {
            globals.control_plane_url = url;
        }
    }

    if matches.value_source("operator_header") == Some(ValueSource::DefaultValue) {
        if let Some(header) = profile.operator_header.clone() {
            globals.operator_header = header;
        }
    }

    if matches.value_source("operator_token").is_none() {
        if let Some(token) = profile.operator_token.clone() {
            globals.operator_token = Some(token);
        }
    }

    if matches.value_source("registration_token").is_none() {
        if let Some(token) = profile.registration_token.clone() {
            globals.registration_token = Some(token);
        }
    }

    Ok(())
}
