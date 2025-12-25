use std::path::Path;
use std::process::Command;

use anyhow::Context;

const GITHUB_USER_AGENT: &str = "fledx-installer";

#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    AgentCaCert, AgentEnvInputs, AgentInstallSettings, AgentUnitInputs,
    ControlPlaneInstallSettings, ControlPlaneTlsAssets, install_agent_ssh,
    install_agent_ssh_with_ca, install_cp_local, install_cp_local_with_tls, install_cp_ssh,
    install_cp_ssh_with_tls, render_agent_env, render_agent_unit,
    render_agent_unit_with_docker_service, systemd_escape_environment_file_path,
    systemd_escape_environment_file_value, systemd_quote_env_value, systemd_quote_unit_path,
    systemd_quote_unit_value, wait_for_systemd_active, wait_for_systemd_active_local,
    wait_for_systemd_active_ssh,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_handles_empty_and_quotes() {
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("simple"), "'simple'");
        assert_eq!(sh_quote("we're"), "'we'\"'\"'re'");
    }

    #[test]
    fn sh_quote_path_wraps_display() {
        let path = Path::new("/tmp/with space/file.txt");
        assert_eq!(sh_quote_path(path), "'/tmp/with space/file.txt'");
    }

    #[test]
    fn noninteractive_sudo_failure_detection_matches_expected_patterns() {
        assert!(looks_like_noninteractive_sudo_failure(
            "sudo: a password is required"
        ));
        assert!(looks_like_noninteractive_sudo_failure(
            "sudo: no tty present and no askpass program specified"
        ));
        assert!(!looks_like_noninteractive_sudo_failure("permission denied"));
    }

    #[test]
    fn run_capture_returns_stdout_and_status() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("printf 'hello'; exit 7");
        let output = run_capture(cmd).expect("run");
        assert_eq!(output.stdout, "hello");
        assert!(!output.status.success());
    }

    #[test]
    fn run_capture_surfaces_missing_command() {
        let cmd = Command::new("definitely-not-a-command-12345");
        let err = match run_capture(cmd) {
            Ok(_) => panic!("expected missing command error"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("failed to run"), "{msg}");
    }
}
