use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SshHostKeyChecking {
    /// Accept unknown host keys and add them to known_hosts (TOFU).
    ///
    /// WARNING: vulnerable to MITM on the first connection.
    AcceptNew,
    /// Require the host key to already exist in known_hosts.
    ///
    /// This is the recommended policy for production deployments.
    Strict,
    /// Disable host key checking (insecure).
    Off,
}

#[derive(Debug, Clone, Args)]
pub struct BootstrapRootArgs {
    /// Override the GitHub owner/org for bootstrap release assets.
    ///
    /// This applies to both `bootstrap cp` and `bootstrap agent` unless the
    /// subcommand sets `--repo` or `--repo-owner`.
    #[arg(
        long = "repo-owner",
        env = "FLEDX_BOOTSTRAP_REPO_OWNER",
        value_name = "OWNER"
    )]
    pub repo_owner: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum BootstrapCommands {
    /// Install + configure the control-plane (local or via SSH).
    Cp(BootstrapCpArgs),
    /// Install + configure a node agent via SSH and auto-enroll it.
    Agent(BootstrapAgentArgs),
}

#[derive(Debug, Args)]
pub struct BootstrapCpArgs {
    /// Hostname or IP that must be reachable by agents.
    ///
    /// This value is used when generating agent configuration.
    #[arg(long = "cp-hostname", value_name = "HOST")]
    pub cp_hostname: String,

    /// SSH target host to install the control-plane on (user@host or host).
    ///
    /// If omitted, installs locally.
    #[arg(long = "ssh-host", visible_alias = "host", value_name = "HOST")]
    pub ssh_host: Option<String>,

    /// SSH username (overrides user@host if provided).
    #[arg(long = "ssh-user", value_name = "USER")]
    pub ssh_user: Option<String>,

    /// SSH port.
    #[arg(long = "ssh-port", default_value_t = 22)]
    pub ssh_port: u16,

    /// SSH identity file (private key).
    #[arg(long = "ssh-identity-file", value_name = "PATH")]
    pub ssh_identity_file: Option<PathBuf>,

    /// Allow interactive SSH auth (password prompts, host key prompts).
    ///
    /// Default uses `BatchMode=yes` to avoid hanging on prompts.
    #[arg(long = "ssh-interactive", default_value_t = false)]
    pub ssh_interactive: bool,

    /// SSH connection timeout (seconds).
    #[arg(long = "ssh-connect-timeout-secs", default_value_t = 10)]
    pub ssh_connect_timeout_secs: u16,

    /// SSH host key checking policy (defaults to `strict`).
    #[arg(long = "ssh-host-key-checking", value_enum, default_value_t = SshHostKeyChecking::Strict)]
    pub ssh_host_key_checking: SshHostKeyChecking,

    /// Control-plane version to install (defaults to latest release; supports `latest`).
    #[arg(long = "version", value_name = "VERSION")]
    pub version: Option<String>,

    /// Override the GitHub repo used for control-plane release assets.
    ///
    /// Defaults to the distribution configured by the CLI binary (core vs enterprise).
    #[arg(
        long = "repo",
        env = "FLEDX_BOOTSTRAP_CP_REPO",
        value_name = "OWNER/REPO"
    )]
    pub repo: Option<String>,

    /// Override only the GitHub owner/org for control-plane release assets.
    ///
    /// This keeps the default repo name from the distribution spec.
    /// Example: `--repo-owner myorg` + default `fledx/fledx-enterprise`
    /// becomes `myorg/fledx-enterprise`.
    #[arg(
        long = "repo-owner",
        env = "FLEDX_BOOTSTRAP_CP_REPO_OWNER",
        value_name = "OWNER"
    )]
    pub repo_owner: Option<String>,

    /// Override the control-plane archive name using a template.
    ///
    /// Supported placeholders: `{version}`, `{arch}`.
    #[arg(
        long = "archive-template",
        env = "FLEDX_BOOTSTRAP_CP_ARCHIVE_TEMPLATE",
        value_name = "TEMPLATE"
    )]
    pub archive_template: Option<String>,

    /// Directory to install binaries into.
    #[arg(
        long = "bin-dir",
        default_value = "/usr/local/bin",
        value_name = "PATH"
    )]
    pub bin_dir: PathBuf,

    /// Directory to write config/env files into.
    #[arg(long = "config-dir", default_value = "/etc/fledx", value_name = "PATH")]
    pub config_dir: PathBuf,

    /// Directory to store persistent data into.
    #[arg(
        long = "data-dir",
        default_value = "/var/lib/fledx",
        value_name = "PATH"
    )]
    pub data_dir: PathBuf,

    /// Control-plane HTTP server port.
    #[arg(long = "server-port", default_value_t = 49421)]
    pub server_port: u16,

    /// Control-plane tunnel listener port.
    #[arg(long = "tunnel-port", default_value_t = 49423)]
    pub tunnel_port: u16,

    /// Dedicated system user to run the control-plane service as.
    #[arg(long = "service-user", default_value = "fledx-cp")]
    pub service_user: String,

    /// Tokens pepper used to hash stored tokens (defaults to random).
    #[arg(long = "tokens-pepper", value_name = "VALUE")]
    pub tokens_pepper: Option<String>,

    /// Allow interactive sudo (prompts for password). Default uses `sudo -n`.
    #[arg(long = "sudo-interactive", default_value_t = false)]
    pub sudo_interactive: bool,

    /// Allow installing unsigned release assets (SHA256 only).
    ///
    /// WARNING: This weakens the supply-chain trust model and should only be
    /// used for local/dev builds or legacy releases without signatures.
    #[arg(long = "insecure-allow-unsigned", default_value_t = false)]
    pub insecure_allow_unsigned: bool,

    /// Do not wait for services to become ready after starting them.
    #[arg(long = "no-wait", default_value_t = false)]
    pub no_wait: bool,

    /// Maximum seconds to wait for readiness checks.
    #[arg(long = "wait-timeout-secs", default_value_t = 120)]
    pub wait_timeout_secs: u64,
}

#[derive(Debug, Args)]
pub struct BootstrapAgentArgs {
    /// SSH target host to install the agent on (user@host or host).
    #[arg(long = "ssh-host", visible_alias = "host", value_name = "HOST")]
    pub ssh_host: String,

    /// SSH username (overrides user@host if provided).
    #[arg(long = "ssh-user", value_name = "USER")]
    pub ssh_user: Option<String>,

    /// SSH port.
    #[arg(long = "ssh-port", default_value_t = 22)]
    pub ssh_port: u16,

    /// SSH identity file (private key).
    #[arg(long = "ssh-identity-file", value_name = "PATH")]
    pub ssh_identity_file: Option<PathBuf>,

    /// Allow interactive SSH auth (password prompts, host key prompts).
    ///
    /// Default uses `BatchMode=yes` to avoid hanging on prompts.
    #[arg(long = "ssh-interactive", default_value_t = false)]
    pub ssh_interactive: bool,

    /// SSH connection timeout (seconds).
    #[arg(long = "ssh-connect-timeout-secs", default_value_t = 10)]
    pub ssh_connect_timeout_secs: u16,

    /// SSH host key checking policy (defaults to `strict`).
    #[arg(long = "ssh-host-key-checking", value_enum, default_value_t = SshHostKeyChecking::Strict)]
    pub ssh_host_key_checking: SshHostKeyChecking,

    /// Node name to register (defaults to ssh host).
    #[arg(long = "name", value_name = "NAME")]
    pub name: Option<String>,

    /// Agent version to install.
    ///
    /// Defaults to the control-plane version (queried from `GET /health`).
    /// Use `latest` to install the latest core release.
    #[arg(long = "version", value_name = "VERSION")]
    pub version: Option<String>,

    /// Override the GitHub repo used for agent release assets.
    ///
    /// Defaults to the distribution configured by the CLI binary (core vs enterprise).
    #[arg(
        long = "repo",
        env = "FLEDX_BOOTSTRAP_AGENT_REPO",
        value_name = "OWNER/REPO"
    )]
    pub repo: Option<String>,

    /// Override only the GitHub owner/org for agent release assets.
    ///
    /// This keeps the default repo name from the distribution spec.
    /// Example: `--repo-owner myorg` + default `fledx/fledx-core`
    /// becomes `myorg/fledx-core`.
    #[arg(
        long = "repo-owner",
        env = "FLEDX_BOOTSTRAP_AGENT_REPO_OWNER",
        value_name = "OWNER"
    )]
    pub repo_owner: Option<String>,

    /// Override the agent archive name using a template.
    ///
    /// Supported placeholders: `{version}`, `{arch}`.
    #[arg(
        long = "archive-template",
        env = "FLEDX_BOOTSTRAP_AGENT_ARCHIVE_TEMPLATE",
        value_name = "TEMPLATE"
    )]
    pub archive_template: Option<String>,

    /// Directory to install binaries into.
    #[arg(
        long = "bin-dir",
        default_value = "/usr/local/bin",
        value_name = "PATH"
    )]
    pub bin_dir: PathBuf,

    /// Binary install path (overrides --bin-dir).
    #[arg(long = "install-path", value_name = "PATH")]
    pub install_path: Option<PathBuf>,

    /// Directory to write config/env files into.
    #[arg(long = "config-dir", default_value = "/etc/fledx", value_name = "PATH")]
    pub config_dir: PathBuf,

    /// Directory to store persistent data into.
    #[arg(
        long = "data-dir",
        default_value = "/var/lib/fledx",
        value_name = "PATH"
    )]
    pub data_dir: PathBuf,

    /// Dedicated system user to run the agent service as.
    #[arg(long = "service-user", default_value = "fledx-agent")]
    pub service_user: String,

    /// Do not add the service user to the Docker socket group.
    ///
    /// By default, bootstrap will add the agent service user to the group that
    /// owns `/var/run/docker.sock` on the target host. On most systems this is
    /// effectively root-equivalent access.
    ///
    /// Use this flag if you manage Docker socket permissions yourself.
    #[arg(long = "no-docker-group", default_value_t = false)]
    pub no_docker_group: bool,

    /// Node label in KEY=VALUE form (repeatable).
    #[arg(long = "label", visible_alias = "labels", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,

    /// Capacity hint: CPU milli-cores (forwarded during enrollment).
    #[arg(long = "capacity-cpu-millis", value_name = "MILLIS")]
    pub capacity_cpu_millis: Option<u32>,

    /// Capacity hint: memory bytes (forwarded during enrollment).
    #[arg(long = "capacity-memory-bytes", value_name = "BYTES")]
    pub capacity_memory_bytes: Option<u64>,

    /// Allow interactive sudo (prompts for password). Default uses `sudo -n`.
    #[arg(long = "sudo-interactive", default_value_t = false)]
    pub sudo_interactive: bool,

    /// Allow installing unsigned release assets (SHA256 only).
    ///
    /// WARNING: This weakens the supply-chain trust model and should only be
    /// used for local/dev builds or legacy releases without signatures.
    #[arg(long = "insecure-allow-unsigned", default_value_t = false)]
    pub insecure_allow_unsigned: bool,

    /// Do not wait for services to become ready after starting them.
    #[arg(long = "no-wait", default_value_t = false)]
    pub no_wait: bool,

    /// Maximum seconds to wait for readiness checks.
    #[arg(long = "wait-timeout-secs", default_value_t = 120)]
    pub wait_timeout_secs: u64,
}
