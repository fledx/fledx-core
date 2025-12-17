use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    /// List configured profiles.
    List,
    /// Show a single profile (defaults to the selected/default profile).
    Show(ProfileShowArgs),
    /// Create or update a profile.
    Set(ProfileSetArgs),
    /// Set the default profile name.
    SetDefault(ProfileSetDefaultArgs),
}

#[derive(Debug, Args)]
pub struct ProfileShowArgs {
    /// Profile name (defaults to selected/default profile).
    #[arg(long = "name", value_name = "NAME")]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct ProfileSetDefaultArgs {
    /// Profile name to set as default.
    #[arg(long = "name", value_name = "NAME")]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct ProfileSetArgs {
    /// Profile name to create/update.
    #[arg(long = "name", value_name = "NAME")]
    pub name: String,

    /// Control-plane base URL, e.g. http://127.0.0.1:49421
    #[arg(long = "control-plane-url", value_name = "URL")]
    pub control_plane_url: Option<String>,

    /// Header name used for operator token auth (default: authorization).
    #[arg(long = "operator-header", value_name = "HEADER")]
    pub operator_header: Option<String>,

    /// Bearer token for control-plane operator endpoints.
    #[arg(long = "operator-token", value_name = "TOKEN")]
    pub operator_token: Option<String>,

    /// Registration token required by the control plane for node enrollment.
    #[arg(long = "registration-token", value_name = "TOKEN")]
    pub registration_token: Option<String>,
}
