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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_format_mode_prefers_json_then_yaml() {
        let args = OutputFormatArgs {
            json: true,
            yaml: false,
        };
        assert_eq!(args.mode(), OutputMode::Json);

        let args = OutputFormatArgs {
            json: false,
            yaml: true,
        };
        assert_eq!(args.mode(), OutputMode::Yaml);

        let args = OutputFormatArgs {
            json: false,
            yaml: false,
        };
        assert_eq!(args.mode(), OutputMode::Table);
    }

    #[test]
    fn desired_state_arg_converts_to_api() {
        let state: DesiredState = DesiredStateArg::Running.into();
        assert_eq!(state, DesiredState::Running);
        let state: DesiredState = DesiredStateArg::Stopped.into();
        assert_eq!(state, DesiredState::Stopped);
    }

    #[test]
    fn status_args_render_expected_strings() {
        assert_eq!(NodeStatusArg::Ready.as_str(), "ready");
        assert_eq!(NodeStatusArg::Unreachable.as_str(), "unreachable");
        assert_eq!(NodeStatusArg::Error.as_str(), "error");
        assert_eq!(NodeStatusArg::Registering.as_str(), "registering");

        assert_eq!(DeploymentStatusArg::Pending.as_str(), "pending");
        assert_eq!(DeploymentStatusArg::Deploying.as_str(), "deploying");
        assert_eq!(DeploymentStatusArg::Running.as_str(), "running");
        assert_eq!(DeploymentStatusArg::Stopped.as_str(), "stopped");
        assert_eq!(DeploymentStatusArg::Failed.as_str(), "failed");
    }
}
