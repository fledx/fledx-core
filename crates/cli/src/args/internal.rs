use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum InternalCommands {
    /// Report whether release signing keys are configured.
    #[command(name = "release-signing-keys", hide = true)]
    ReleaseSigningKeys {
        /// Output JSON for machine checks.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}
