pub mod api;
pub mod args;
#[cfg(feature = "bootstrap")]
#[path = "bootstrap/mod.rs"]
mod bootstrap_flow;
pub mod commands;
pub mod parse;
#[cfg(feature = "bootstrap")]
mod profile_store;
#[cfg(test)]
mod test_support;
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

#[cfg(feature = "bootstrap")]
use clap::parser::ValueSource;
#[cfg(not(feature = "bootstrap"))]
use clap::Parser;
#[cfg(feature = "bootstrap")]
use clap::{CommandFactory, FromArgMatches};

#[cfg(feature = "bootstrap")]
use crate::commands::bootstrap::handle_bootstrap;
use crate::commands::completions::generate_completions;
use crate::commands::configs::handle_configs;
use crate::commands::deploy::handle_deploy_commands;
use crate::commands::metrics::handle_metrics;
use crate::commands::nodes::handle_nodes;
#[cfg(feature = "bootstrap")]
use crate::commands::profiles::handle_profiles;
use crate::commands::status::handle_status;
use crate::commands::usage::handle_usage;
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
        apply_profile_overrides(
            &matches,
            &cli.command,
            &selected_profile,
            &store,
            &mut cli.globals,
        )?;

        maybe_persist_default_profile(&mut store, &selected_profile)?;

        cli.profile = selected_profile;
        run_parsed(cli).await
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
    cli_profile
        .clone()
        .or_else(|| store.default_profile.clone())
}

#[cfg(feature = "bootstrap")]
fn maybe_persist_default_profile(
    store: &mut ProfileStore,
    selected_profile: &Option<String>,
) -> anyhow::Result<()> {
    if store.default_profile.is_some() {
        return Ok(());
    }

    let Some(name) = selected_profile.as_deref() else {
        return Ok(());
    };

    if !store.profiles.contains_key(name) {
        // The profile may be created later (e.g. bootstrap cp), but we should not
        // persist a default_profile that points at a non-existent entry.
        return Ok(());
    }

    store.default_profile = Some(name.to_string());
    store.save()?;
    Ok(())
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
            anyhow::bail!(
                "profile '{}' not found (create it via `fledx profile set`)",
                name
            );
        }
    };

    // Precedence: CLI flags > env vars > profile > defaults.
    if profile_can_override(matches, "control_plane_url") {
        if let Some(url) = profile.control_plane_url.clone() {
            globals.control_plane_url = url;
        }
    }

    if profile_can_override(matches, "operator_header") {
        if let Some(header) = profile.operator_header.clone() {
            globals.operator_header = header;
        }
    }

    if profile_can_override(matches, "operator_token") {
        if let Some(token) = profile.operator_token.clone() {
            globals.operator_token = Some(token);
        }
    }

    if profile_can_override(matches, "registration_token") {
        if let Some(token) = profile.registration_token.clone() {
            globals.registration_token = Some(token);
        }
    }

    Ok(())
}

#[cfg(feature = "bootstrap")]
fn profile_can_override(matches: &clap::ArgMatches, arg_id: &str) -> bool {
    matches!(
        matches.value_source(arg_id),
        None | Some(ValueSource::DefaultValue)
    )
}

#[cfg(all(test, feature = "bootstrap"))]
mod profile_override_tests {
    use super::*;
    use clap::CommandFactory;

    fn store_with_default_profile() -> ProfileStore {
        let mut store = ProfileStore {
            default_profile: Some("default".into()),
            ..Default::default()
        };
        store.profiles.insert(
            "default".into(),
            crate::profile_store::Profile {
                control_plane_url: Some("http://profile.example:8080".to_string()),
                operator_header: Some("x-profile-operator-token".to_string()),
                operator_token: Some("op".to_string()),
                registration_token: Some("reg".to_string()),
            },
        );
        store
    }

    #[test]
    fn profile_overrides_defaults_and_missing_values() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        std::env::remove_var("FLEDX_CLI_CONTROL_PLANE_URL");
        std::env::remove_var("FLEDX_CLI_OPERATOR_HEADER");
        std::env::remove_var("FLEDX_CLI_OPERATOR_TOKEN");
        std::env::remove_var("FLEDX_CLI_REGISTRATION_TOKEN");

        let store = store_with_default_profile();
        let selected_profile = Some("default".to_string());

        let matches = Cli::command().get_matches_from(["fledx", "profile", "list"]);
        let cli = Cli::from_arg_matches(&matches).expect("parse");
        let Cli {
            mut globals,
            command,
            profile: _,
        } = cli;

        apply_profile_overrides(&matches, &command, &selected_profile, &store, &mut globals)
            .expect("apply");

        assert_eq!(globals.control_plane_url, "http://profile.example:8080");
        assert_eq!(globals.operator_header, "x-profile-operator-token");
        assert_eq!(globals.operator_token.as_deref(), Some("op"));
        assert_eq!(globals.registration_token.as_deref(), Some("reg"));
    }

    #[test]
    fn profile_does_not_override_cli_flags() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        std::env::remove_var("FLEDX_CLI_CONTROL_PLANE_URL");
        std::env::remove_var("FLEDX_CLI_OPERATOR_HEADER");
        std::env::remove_var("FLEDX_CLI_OPERATOR_TOKEN");
        std::env::remove_var("FLEDX_CLI_REGISTRATION_TOKEN");

        let store = store_with_default_profile();
        let selected_profile = Some("default".to_string());

        let matches = Cli::command().get_matches_from([
            "fledx",
            "--control-plane-url",
            "http://cli.example:8080",
            "--operator-header",
            "x-cli-operator-token",
            "--operator-token",
            "cli-op",
            "--registration-token",
            "cli-reg",
            "profile",
            "list",
        ]);
        let cli = Cli::from_arg_matches(&matches).expect("parse");
        let Cli {
            mut globals,
            command,
            profile: _,
        } = cli;

        apply_profile_overrides(&matches, &command, &selected_profile, &store, &mut globals)
            .expect("apply");

        assert_eq!(globals.control_plane_url, "http://cli.example:8080");
        assert_eq!(globals.operator_header, "x-cli-operator-token");
        assert_eq!(globals.operator_token.as_deref(), Some("cli-op"));
        assert_eq!(globals.registration_token.as_deref(), Some("cli-reg"));
    }

    #[test]
    fn profile_does_not_override_env_vars() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        std::env::set_var("FLEDX_CLI_CONTROL_PLANE_URL", "http://env.example:8080");
        std::env::set_var("FLEDX_CLI_OPERATOR_HEADER", "x-env-operator-token");
        std::env::set_var("FLEDX_CLI_OPERATOR_TOKEN", "env-op");
        std::env::set_var("FLEDX_CLI_REGISTRATION_TOKEN", "env-reg");

        let store = store_with_default_profile();
        let selected_profile = Some("default".to_string());

        let matches = Cli::command().get_matches_from(["fledx", "profile", "list"]);
        let cli = Cli::from_arg_matches(&matches).expect("parse");
        let Cli {
            mut globals,
            command,
            profile: _,
        } = cli;

        apply_profile_overrides(&matches, &command, &selected_profile, &store, &mut globals)
            .expect("apply");

        assert_eq!(globals.control_plane_url, "http://env.example:8080");
        assert_eq!(globals.operator_header, "x-env-operator-token");
        assert_eq!(globals.operator_token.as_deref(), Some("env-op"));
        assert_eq!(globals.registration_token.as_deref(), Some("env-reg"));

        std::env::remove_var("FLEDX_CLI_CONTROL_PLANE_URL");
        std::env::remove_var("FLEDX_CLI_OPERATOR_HEADER");
        std::env::remove_var("FLEDX_CLI_OPERATOR_TOKEN");
        std::env::remove_var("FLEDX_CLI_REGISTRATION_TOKEN");
    }

    #[test]
    fn default_profile_is_not_persisted_for_missing_profile() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::env::remove_var("HOME");

        let mut store = ProfileStore::default();
        maybe_persist_default_profile(&mut store, &Some("missing".to_string())).expect("persist");

        assert!(store.default_profile.is_none());
        assert!(!ProfileStore::path().expect("path").exists());
    }

    #[test]
    fn default_profile_is_persisted_for_existing_profile() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::env::remove_var("HOME");

        let mut store = ProfileStore::default();
        store
            .profiles
            .insert("prod".to_string(), crate::profile_store::Profile::default());

        maybe_persist_default_profile(&mut store, &Some("prod".to_string())).expect("persist");

        assert_eq!(store.default_profile.as_deref(), Some("prod"));
        assert!(ProfileStore::path().expect("path").exists());
    }
}
