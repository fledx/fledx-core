use clap::{Args, ValueEnum};
use common::api::DesiredState;

pub const DEFAULT_PAGE_LIMIT: u32 = 50;
pub const MAX_PAGE_LIMIT: u32 = 100;
pub const DEFAULT_LOG_FOLLOW_INTERVAL_SECS: u64 = 2;
pub const DEFAULT_DEPLOY_WATCH_INTERVAL_SECS: u64 = 2;
pub const DEFAULT_DEPLOY_WATCH_MAX_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Args)]
pub struct OutputFormatArgs {
    /// Emit JSON instead of a table.
    #[arg(long, conflicts_with = "yaml")]
    pub json: bool,
    /// Emit YAML instead of a table.
    #[arg(long, conflicts_with = "json")]
    pub yaml: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OutputMode {
    Table,
    Json,
    Yaml,
}

impl OutputFormatArgs {
    pub fn mode(&self) -> OutputMode {
        if self.json {
            OutputMode::Json
        } else if self.yaml {
            OutputMode::Yaml
        } else {
            OutputMode::Table
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum DesiredStateArg {
    Running,
    Stopped,
}

impl From<DesiredStateArg> for DesiredState {
    fn from(state: DesiredStateArg) -> Self {
        match state {
            DesiredStateArg::Running => DesiredState::Running,
            DesiredStateArg::Stopped => DesiredState::Stopped,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum CompletionShell {
    Bash,
    Fish,
    Zsh,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum NodeStatusArg {
    Ready,
    Unreachable,
    Error,
    Registering,
}

impl NodeStatusArg {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeStatusArg::Ready => "ready",
            NodeStatusArg::Unreachable => "unreachable",
            NodeStatusArg::Error => "error",
            NodeStatusArg::Registering => "registering",
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum DeploymentStatusArg {
    Pending,
    Deploying,
    Running,
    Stopped,
    Failed,
}

impl DeploymentStatusArg {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeploymentStatusArg::Pending => "pending",
            DeploymentStatusArg::Deploying => "deploying",
            DeploymentStatusArg::Running => "running",
            DeploymentStatusArg::Stopped => "stopped",
            DeploymentStatusArg::Failed => "failed",
        }
    }
}
