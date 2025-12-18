use clap::{Args, Parser, Subcommand};
use uuid::Uuid;

use crate::version;

#[cfg(feature = "bootstrap")]
pub mod bootstrap;
pub mod common;
pub mod deploy;
pub mod metrics;
pub mod nodes;
#[cfg(feature = "bootstrap")]
pub mod profiles;
pub mod status;
pub mod usage;

#[cfg(feature = "bootstrap")]
pub use bootstrap::*;
pub use common::*;
pub use deploy::*;
pub use metrics::*;
pub use nodes::*;
#[cfg(feature = "bootstrap")]
pub use profiles::*;
pub use status::*;
pub use usage::*;

#[derive(Debug, Parser)]
#[command(
    name = "fledx",
    version = version::VERSION,
    long_version = version::FULL_VERSION,
    about = "fledx - Distributed Edge Hosting CLI"
)]
pub struct Cli {
    /// Name of the local CLI profile to use (from ~/.config/fledx/config.toml).
    #[cfg(feature = "bootstrap")]
    #[arg(long, global = true)]
    pub profile: Option<String>,

    #[command(flatten)]
    pub globals: GlobalArgs,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Args)]
pub struct GlobalArgs {
    /// Control-plane base URL, e.g. http://127.0.0.1:49421
    #[arg(
        long,
        env = "FLEDX_CLI_CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:49421"
    )]
    pub control_plane_url: String,

    /// Optional bearer token for control-plane admin endpoints.
    #[arg(
        long = "operator-token",
        env = "FLEDX_CLI_OPERATOR_TOKEN",
        visible_alias = "token"
    )]
    pub operator_token: Option<String>,

    /// Header name used for operator token auth (default: authorization).
    #[arg(
        long = "operator-header",
        env = "FLEDX_CLI_OPERATOR_HEADER",
        default_value = "authorization"
    )]
    pub operator_header: String,

    /// Registration token required by the control plane for node enrollment.
    #[arg(long, env = "FLEDX_CLI_REGISTRATION_TOKEN", global = true)]
    pub registration_token: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Show combined status for nodes and deployments (supports --watch).
    Status(StatusArgs),
    /// Node management commands.
    Nodes {
        #[command(subcommand)]
        command: NodeCommands,
    },
    /// Deployment management commands.
    Deployments {
        #[command(subcommand)]
        command: Box<DeployCommands>,
    },
    /// Config management commands.
    Configs {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Observability metrics commands.
    Metrics {
        #[command(subcommand)]
        command: MetricsCommands,
    },
    /// Resource usage commands.
    Usage {
        #[command(subcommand)]
        command: UsageCommands,
    },
    /// Generate shell completions for the CLI.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: CompletionShell,
    },

    /// Bootstrap (install + configure) control-plane and agents.
    #[cfg(feature = "bootstrap")]
    Bootstrap {
        #[command(flatten)]
        args: BootstrapRootArgs,
        #[command(subcommand)]
        command: Box<BootstrapCommands>,
    },

    /// Local CLI profile management.
    #[cfg(feature = "bootstrap")]
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// List configs.
    List(ConfigListArgs),
    /// Show a single config with entries and files.
    Show(ConfigShowArgs),
    /// Create a new config.
    Create(ConfigCreateArgs),
    /// Update or replace a config.
    Update(ConfigUpdateArgs),
    /// Delete a config.
    Delete(ConfigDeleteArgs),
    /// Attach a config to a deployment or node.
    #[command(subcommand)]
    Attach(ConfigAttachCommands),
    /// Detach a config from a deployment or node.
    #[command(subcommand)]
    Detach(ConfigDetachCommands),
}

#[derive(Debug, Subcommand)]
pub enum ConfigAttachCommands {
    /// Attach one or more configs to a deployment.
    Deployment(ConfigAttachDeploymentArgs),
    /// Attach one or more configs to a node.
    Node(ConfigAttachNodeArgs),
}

#[derive(Debug, Subcommand)]
pub enum ConfigDetachCommands {
    /// Detach one or more configs from a deployment.
    Deployment(ConfigAttachDeploymentArgs),
    /// Detach one or more configs from a node.
    Node(ConfigAttachNodeArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ConfigListArgs {
    /// Page size (1-100).
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT)]
    pub limit: u32,
    /// Pagination offset.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    /// Output format for structured output (JSON/YAML); defaults to table.
    #[command(flatten)]
    pub output: OutputFormatArgs,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigShowArgs {
    /// Config identifier.
    #[arg(long = "id", value_parser = crate::parse_uuid)]
    pub config_id: Uuid,
    /// Output format for structured output (JSON/YAML); defaults to table.
    #[command(flatten)]
    pub output: OutputFormatArgs,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigCreateArgs {
    /// Config name (must be unique).
    #[arg(long)]
    pub name: String,
    /// Optional version (defaults to 1).
    #[arg(long)]
    pub version: Option<i64>,
    /// Plaintext entries in KEY=VALUE form (repeatable).
    #[arg(
        long = "var",
        visible_alias = "entry",
        value_parser = crate::parse_kv,
        value_name = "KEY=VALUE"
    )]
    pub vars: Vec<(String, String)>,
    /// Plaintext entries loaded from an env file (repeatable).
    #[arg(long = "from-env-file", value_name = "PATH")]
    pub env_files: Vec<std::path::PathBuf>,
    /// Secret-backed entries in KEY=SECRET form (repeatable).
    #[arg(
        long = "secret-entry",
        visible_alias = "secret-var",
        value_parser = crate::parse_kv
    )]
    pub secret_entries: Vec<(String, String)>,
    /// File references in PATH=REF form (repeatable).
    #[arg(long = "file", value_parser = crate::parse_kv)]
    pub files: Vec<(String, String)>,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigUpdateArgs {
    /// Config identifier.
    #[arg(long = "id", value_parser = crate::parse_uuid)]
    pub config_id: Uuid,
    /// Optional new name (must remain unique).
    #[arg(long)]
    pub name: Option<String>,
    /// Optional explicit version (defaults to current + 1).
    #[arg(long)]
    pub version: Option<i64>,
    /// Plaintext entries in KEY=VALUE form (repeatable).
    #[arg(
        long = "var",
        visible_alias = "entry",
        value_parser = crate::parse_kv,
        value_name = "KEY=VALUE"
    )]
    pub vars: Vec<(String, String)>,
    /// Plaintext entries loaded from an env file (repeatable).
    #[arg(long = "from-env-file", value_name = "PATH")]
    pub env_files: Vec<std::path::PathBuf>,
    /// Secret-backed entries in KEY=SECRET form (repeatable).
    #[arg(
        long = "secret-entry",
        visible_alias = "secret-var",
        value_parser = crate::parse_kv
    )]
    pub secret_entries: Vec<(String, String)>,
    /// File references in PATH=REF form (repeatable).
    #[arg(long = "file", value_parser = crate::parse_kv)]
    pub files: Vec<(String, String)>,
    /// Replace existing entries with an empty set.
    #[arg(long = "clear-entries", default_value_t = false)]
    pub clear_entries: bool,
    /// Replace existing files with an empty set.
    #[arg(long = "clear-files", default_value_t = false)]
    pub clear_files: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigDeleteArgs {
    /// Config identifier.
    #[arg(long = "id", value_parser = crate::parse_uuid)]
    pub config_id: Uuid,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigAttachDeploymentArgs {
    /// One or more config identifiers.
    #[arg(
        long = "config-id",
        value_parser = crate::parse_uuid,
        num_args = 1..,
        value_delimiter = ','
    )]
    pub config_ids: Vec<Uuid>,
    /// Deployment identifier.
    #[arg(long = "deployment-id", value_parser = crate::parse_uuid)]
    pub deployment_id: Uuid,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigAttachNodeArgs {
    /// One or more config identifiers.
    #[arg(
        long = "config-id",
        value_parser = crate::parse_uuid,
        num_args = 1..,
        value_delimiter = ','
    )]
    pub config_ids: Vec<Uuid>,
    /// Node identifier.
    #[arg(long = "node-id", value_parser = crate::parse_uuid)]
    pub node_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration as ChronoDuration, Utc};

    #[test]
    fn parses_node_list_args() {
        let cli = Cli::try_parse_from([
            "fledx", "nodes", "list", "--limit", "10", "--offset", "5", "--status", "ready",
            "--json",
        ])
        .unwrap();

        match cli.command {
            Commands::Nodes {
                command: NodeCommands::List(args),
            } => {
                assert_eq!(args.limit, 10);
                assert_eq!(args.offset, 5);
                assert_eq!(args.status, Some(NodeStatusArg::Ready));
                assert_eq!(args.output.mode(), OutputMode::Json);
                assert!(!args.wide);
            }
            _ => panic!("expected nodes list command"),
        }
    }

    #[test]
    fn parses_node_status_args() {
        let cli = Cli::try_parse_from([
            "fledx", "nodes", "status", "--limit", "3", "--offset", "1", "--status", "error",
            "--yaml", "--wide",
        ])
        .unwrap();

        match cli.command {
            Commands::Nodes {
                command: NodeCommands::Status(args),
            } => {
                assert_eq!(args.limit, 3);
                assert_eq!(args.offset, 1);
                assert_eq!(args.status, Some(NodeStatusArg::Error));
                assert_eq!(args.output.mode(), OutputMode::Yaml);
                assert!(args.wide);
            }
            _ => panic!("expected nodes status command"),
        }
    }

    #[test]
    fn parses_deployment_list_args() {
        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "list",
            "--status",
            "running",
            "--wide",
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::List(args) => {
                assert_eq!(args.limit, DEFAULT_PAGE_LIMIT);
                assert_eq!(args.offset, 0);
                assert_eq!(args.status, Some(DeploymentStatusArg::Running));
                assert_eq!(args.output.mode(), OutputMode::Table);
                assert!(args.wide);
            }
            _ => panic!("expected deployments list command"),
        }
    }

    #[test]
    fn parses_deploy_status_args() {
        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "status",
            "--status",
            "running",
            "--yaml",
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::Status(args) => {
                assert_eq!(args.output.mode(), OutputMode::Yaml);
                assert_eq!(args.status, Some(DeploymentStatusArg::Running));
            }
            _ => panic!("expected deployments status command"),
        }
    }

    #[test]
    fn parses_deploy_logs_args() {
        let deploy_id = Uuid::new_v4();
        let timestamp = "2025-12-07T12:00:00Z";
        let id_str = deploy_id.to_string();
        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "logs",
            "--limit",
            "12",
            "--offset",
            "2",
            "--resource-type",
            "deployment",
            "--resource-id",
            &id_str,
            "--since",
            timestamp,
            "--follow",
            "--follow-interval",
            "4",
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::Logs(args) => {
                assert_eq!(args.limit, 12);
                assert_eq!(args.offset, 2);
                assert_eq!(args.resource_type.as_deref(), Some("deployment"));
                assert_eq!(args.resource_id, Some(deploy_id));
                let expected_since = DateTime::parse_from_rfc3339(timestamp)
                    .unwrap()
                    .with_timezone(&Utc);
                assert_eq!(args.since, Some(expected_since));
                assert!(args.follow);
                assert_eq!(args.follow_interval, 4);
            }
            _ => panic!("expected deployments logs command"),
        }
    }

    #[test]
    fn parses_deploy_watch_args() {
        let deploy_id = Uuid::new_v4();
        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "watch",
            "--id",
            &deploy_id.to_string(),
            "--poll-interval",
            "3",
            "--max-interval",
            "10",
            "--max-runtime",
            "20",
            "--follow-logs",
            "--follow-logs-interval",
            "5",
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::Watch(args) => {
                assert_eq!(args.deployment_id, deploy_id);
                assert_eq!(args.poll_interval, 3);
                assert_eq!(args.max_interval, Some(10));
                assert_eq!(args.max_runtime, Some(20));
                assert!(args.follow_logs);
                assert_eq!(args.follow_logs_interval, 5);
            }
            _ => panic!("expected deployments watch command"),
        }
    }

    #[test]
    fn parses_metrics_show_args() {
        let cli =
            Cli::try_parse_from(["fledx", "metrics", "show", "--limit", "5", "--json"]).unwrap();

        match cli.command {
            Commands::Metrics {
                command: MetricsCommands::Show(args),
            } => {
                assert_eq!(args.limit, Some(5));
                assert!(args.json);
            }
            _ => panic!("expected metrics command"),
        }
    }

    #[test]
    fn parses_usage_list_args() {
        let deployment = Uuid::new_v4();
        let node = Uuid::new_v4();
        let cli = Cli::try_parse_from([
            "fledx",
            "usage",
            "list",
            "--deployment",
            &deployment.to_string(),
            "--node",
            &node.to_string(),
            "--replica",
            "1",
            "--limit",
            "20",
            "--offset",
            "5",
            "--range",
            "30m",
            "--json",
        ])
        .unwrap();

        match cli.command {
            Commands::Usage {
                command: UsageCommands::List(args),
            } => {
                assert_eq!(args.deployment_id, Some(deployment));
                assert_eq!(args.node_id, Some(node));
                assert_eq!(args.replica_number, Some(1));
                assert_eq!(args.limit, 20);
                assert_eq!(args.offset, 5);
                assert_eq!(args.range, ChronoDuration::minutes(30));
                assert_eq!(args.output.mode(), OutputMode::Json);
            }
            _ => panic!("expected usage list command"),
        }
    }

    #[test]
    fn parses_status_args() {
        let cli = Cli::try_parse_from([
            "fledx",
            "status",
            "--node-limit",
            "5",
            "--node-status",
            "ready",
            "--deploy-limit",
            "10",
            "--deploy-status",
            "running",
            "--json",
            "--wide",
        ])
        .unwrap();

        match cli.command {
            Commands::Status(args) => {
                assert_eq!(args.node_limit, 5);
                assert_eq!(args.node_status, Some(NodeStatusArg::Ready));
                assert_eq!(args.deploy_limit, 10);
                assert_eq!(args.deploy_status, Some(DeploymentStatusArg::Running));
                assert!(args.json);
                assert!(args.wide);
            }
            _ => panic!("expected status command"),
        }
    }

    #[test]
    fn parses_deploy_create_with_replicas_and_placement() {
        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "create",
            "--name",
            "app",
            "--image",
            "nginx",
            "--replicas",
            "3",
            "--affinity-node",
            Uuid::nil().to_string().as_str(),
            "--anti-affinity-node",
            Uuid::from_u128(2).to_string().as_str(),
            "--spread",
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::Create(args) => {
                assert_eq!(args.name.as_deref(), Some("app"));
                assert_eq!(args.image, "nginx");
                assert_eq!(args.replicas, 3);
                assert_eq!(args.affinity_nodes.len(), 1);
                assert_eq!(args.anti_affinity_nodes.len(), 1);
                assert!(args.spread);
            }
            _ => panic!("expected deployments create"),
        }
    }

    #[test]
    fn parses_deploy_create_with_volume() {
        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "create",
            "--image",
            "nginx",
            "--volume",
            "/data/app:/var/app:ro",
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::Create(args) => {
                assert_eq!(args.volumes.len(), 1);
                assert_eq!(args.volumes[0].host_path, "/data/app");
                assert_eq!(args.volumes[0].container_path, "/var/app");
                assert_eq!(args.volumes[0].read_only, Some(true));
            }
            _ => panic!("expected deployments create"),
        }
    }

    #[test]
    fn parses_deploy_update_with_replicas_and_placement() {
        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "update",
            "--id",
            Uuid::nil().to_string().as_str(),
            "--replicas",
            "4",
            "--spread",
            "--affinity-node",
            Uuid::from_u128(3).to_string().as_str(),
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::Update(args) => {
                assert_eq!(args.deployment_id, Uuid::nil());
                assert_eq!(args.replicas, Some(4));
                assert!(args.spread);
                assert_eq!(args.affinity_nodes.len(), 1);
            }
            _ => panic!("expected deployments update"),
        }
    }

    #[test]
    fn parses_deploy_update_with_volumes_and_clear_flag() {
        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "update",
            "--id",
            Uuid::nil().to_string().as_str(),
            "--volume",
            "/data/app:/var/app",
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::Update(args) => {
                assert_eq!(args.deployment_id, Uuid::nil());
                assert_eq!(args.volumes.len(), 1);
                assert!(!args.clear_volumes);
            }
            _ => panic!("expected deployments update"),
        }

        let cli = Cli::try_parse_from([
            "fledx",
            "deployments",
            "update",
            "--id",
            Uuid::nil().to_string().as_str(),
            "--clear-volumes",
        ])
        .unwrap();

        let Commands::Deployments { command } = cli.command else {
            panic!("expected deployments command");
        };
        match *command {
            DeployCommands::Update(args) => assert!(args.clear_volumes),
            _ => panic!("expected deployments update"),
        }
    }

    #[test]
    fn parses_status_watch_args() {
        let cli = Cli::try_parse_from([
            "fledx",
            "status",
            "--watch",
            "--watch-interval",
            "3",
            "--nodes-only",
            "--no-color",
        ])
        .unwrap();

        match cli.command {
            Commands::Status(args) => {
                assert!(args.watch);
                assert_eq!(args.watch_interval, 3);
                assert!(args.nodes_only);
                assert!(args.no_color);
            }
            _ => panic!("expected status watch command"),
        }
    }
}
