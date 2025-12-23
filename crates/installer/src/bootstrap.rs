use std::path::Path;
use std::process::Command;

use anyhow::Context;

const GITHUB_USER_AGENT: &str = "fledx-installer";

mod ssh;
pub use ssh::*;

mod github;
pub use github::*;

mod archive;
pub use archive::*;

mod tokens;
pub use tokens::*;

mod systemd;
pub use systemd::{
    install_agent_ssh, install_agent_ssh_with_ca, install_cp_local, install_cp_local_with_tls,
    install_cp_ssh, install_cp_ssh_with_tls, render_agent_env, render_agent_unit,
    render_agent_unit_with_docker_service, systemd_escape_environment_file_path,
    systemd_escape_environment_file_value, systemd_quote_env_value, systemd_quote_unit_path,
    systemd_quote_unit_value, wait_for_systemd_active, wait_for_systemd_active_local,
    wait_for_systemd_active_ssh, AgentCaCert, AgentEnvInputs, AgentInstallSettings,
    AgentUnitInputs, ControlPlaneInstallSettings, ControlPlaneTlsAssets,
};

fn sh_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn sh_quote_path(path: &Path) -> String {
    sh_quote(&path.as_os_str().to_string_lossy())
}

fn looks_like_noninteractive_sudo_failure(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    if !lower.contains("sudo") {
        return false;
    }

    lower.contains("a password is required")
        || lower.contains("no tty present")
        || lower.contains("a terminal is required")
        || lower.contains("askpass")
        || lower.contains("must have a tty")
}

struct CommandOutput {
    stdout: String,
    stderr: String,
    status: std::process::ExitStatus,
}

fn run_capture(mut cmd: Command) -> anyhow::Result<CommandOutput> {
    let output = cmd
        .output()
        .with_context(|| format!("failed to run {:?}", cmd))?;
    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        status: output.status,
    })
}
