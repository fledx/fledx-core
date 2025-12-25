use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::Context;
use tokio::time::{sleep, Instant};

use super::{looks_like_noninteractive_sudo_failure, run_capture, sh_quote, sh_quote_path};
use super::{InstallTarget, SshTarget, SudoMode};

fn normalize_unit_name(unit: &str) -> String {
    let trimmed = unit.trim();
    if trimmed.is_empty() {
        return trimmed.to_string();
    }
    if trimmed.contains('.') {
        return trimmed.to_string();
    }
    format!("{trimmed}.service")
}

fn parse_systemctl_is_active_output(output: &str) -> String {
    // `systemctl is-active` returns one token like:
    // active, inactive, failed, activating, deactivating, reloading, unknown.
    //
    // Some SSH targets prepend banners/MOTD text to stdout, so we scan tokens
    // and pick the last recognized state.
    const STATES: [&str; 7] = [
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "reloading",
        "unknown",
    ];

    for token in output.split_whitespace().rev() {
        let token = token.trim().to_ascii_lowercase();
        if STATES.iter().any(|s| *s == token) {
            return token;
        }
    }

    output.trim().to_string()
}

pub async fn wait_for_systemd_active(
    target: &InstallTarget,
    service: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    match target {
        InstallTarget::Local => wait_for_systemd_active_local(service, timeout).await,
        InstallTarget::Ssh(ssh) => wait_for_systemd_active_ssh(ssh, service, timeout).await,
    }
}

pub async fn wait_for_systemd_active_local(service: &str, timeout: Duration) -> anyhow::Result<()> {
    eprintln!(
        "waiting for systemd service active: {service} (timeout {}s)",
        timeout.as_secs()
    );
    let start = Instant::now();
    loop {
        let state = systemd_state_local(service)
            .with_context(|| format!("failed to query systemd state for {}", service))?;
        if state == "active" {
            return Ok(());
        }
        if state == "failed" {
            let debug = systemd_debug_bundle_local(service);
            anyhow::bail!("systemd service {service} entered 'failed' state.\n\n{debug}");
        }
        if start.elapsed() >= timeout {
            let debug = systemd_debug_bundle_local(service);
            anyhow::bail!(
                "timed out waiting for systemd service {service} to become active.\n\n{debug}"
            );
        }
        sleep(Duration::from_millis(500)).await;
    }
}

pub async fn wait_for_systemd_active_ssh(
    ssh: &SshTarget,
    service: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    eprintln!(
        "waiting for systemd service active on {}: {service} (timeout {}s)",
        ssh.destination(),
        timeout.as_secs()
    );
    let start = Instant::now();
    loop {
        let state = systemd_state_ssh(ssh, service)
            .with_context(|| format!("failed to query systemd state for {}", service))?;
        if state == "active" {
            return Ok(());
        }
        if state == "failed" {
            let debug = systemd_debug_bundle_ssh(ssh, service)
                .unwrap_or_else(|e| format!("failed to collect systemd debug bundle: {e:#}"));
            anyhow::bail!(
                "systemd service {service} entered 'failed' state on {}.\n\n{debug}",
                ssh.destination()
            );
        }
        if start.elapsed() >= timeout {
            let debug = systemd_debug_bundle_ssh(ssh, service)
                .unwrap_or_else(|e| format!("failed to collect systemd debug bundle: {e:#}"));
            anyhow::bail!(
                "timed out waiting for systemd service {service} to become active on {}.\n\n{debug}",
                ssh.destination()
            );
        }
        sleep(Duration::from_millis(500)).await;
    }
}

fn systemd_state_local(service: &str) -> anyhow::Result<String> {
    let unit = normalize_unit_name(service);
    let mut cmd = Command::new("systemctl");
    cmd.arg("is-active").arg("--quiet").arg("--").arg(&unit);
    let output = run_capture(cmd)?;
    if output.status.success() {
        return Ok("active".to_string());
    }

    let mut cmd = Command::new("systemctl");
    cmd.arg("is-failed").arg("--quiet").arg("--").arg(&unit);
    let output = run_capture(cmd)?;
    if output.status.success() {
        return Ok("failed".to_string());
    }

    let mut cmd = Command::new("systemctl");
    cmd.arg("is-active").arg("--").arg(&unit);
    let output = run_capture(cmd)?;
    Ok(parse_systemctl_is_active_output(&format!(
        "{}\n{}",
        output.stdout, output.stderr
    )))
}

fn systemd_state_ssh(ssh: &SshTarget, service: &str) -> anyhow::Result<String> {
    let unit = normalize_unit_name(service);
    let output = systemctl_capture_ssh(
        ssh,
        &[
            OsString::from("is-active"),
            OsString::from("--quiet"),
            OsString::from("--"),
            OsString::from(&unit),
        ],
    )?;
    if output.status.success() {
        return Ok("active".to_string());
    }

    let output = systemctl_capture_ssh(
        ssh,
        &[
            OsString::from("is-failed"),
            OsString::from("--quiet"),
            OsString::from("--"),
            OsString::from(&unit),
        ],
    )?;
    if output.status.success() {
        return Ok("failed".to_string());
    }

    let output = systemctl_capture_ssh(
        ssh,
        &[
            OsString::from("is-active"),
            OsString::from("--"),
            OsString::from(&unit),
        ],
    )?;
    Ok(parse_systemctl_is_active_output(&format!(
        "{}\n{}",
        output.stdout, output.stderr
    )))
}

fn systemctl_capture_ssh(
    ssh: &SshTarget,
    args: &[OsString],
) -> anyhow::Result<super::ssh::CapturedOutput> {
    let output = ssh.run_capture_command("systemctl", args)?;
    if !should_retry_systemctl_with_sudo(&output.stderr) {
        return Ok(output);
    }

    let mut sudo_args = Vec::with_capacity(args.len() + 2);
    sudo_args.push(OsString::from("-n"));
    sudo_args.push(OsString::from("systemctl"));
    sudo_args.extend_from_slice(args);
    ssh.run_capture_command("sudo", &sudo_args)
}

fn should_retry_systemctl_with_sudo(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("failed to connect to bus")
        || lowered.contains("permission denied")
        || lowered.contains("access denied")
}

fn systemd_debug_bundle_local(service: &str) -> String {
    let unit = normalize_unit_name(service);
    let mut out = String::new();
    let _ = writeln!(&mut out, "systemctl is-active:");
    let _ = writeln!(
        &mut out,
        "{}",
        systemd_state_local(&unit).unwrap_or_else(|e| e.to_string())
    );

    let _ = writeln!(&mut out, "\nsystemctl status:");
    let _ = writeln!(
        &mut out,
        "{}",
        systemd_status_local(&unit).unwrap_or_else(|e| e.to_string())
    );

    let _ = writeln!(&mut out, "\njournalctl (sudo -n, optional, last 10 lines):");
    let _ = writeln!(
        &mut out,
        "{}",
        systemd_journal_local(&unit).unwrap_or_else(|e| e.to_string())
    );

    redact_debug_bundle(&out)
}

fn systemd_status_local(service: &str) -> anyhow::Result<String> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("status")
        .arg("--no-pager")
        .arg("-l")
        .arg("-n")
        .arg("100")
        .arg("--")
        .arg(service);
    let output = run_capture(cmd)?;
    Ok(format!(
        "exit: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        output.stdout.trim_end(),
        output.stderr.trim_end()
    ))
}

fn systemd_journal_local(service: &str) -> anyhow::Result<String> {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .arg("journalctl")
        .arg("-u")
        .arg(service)
        .arg("-n")
        .arg("10")
        .arg("--no-pager");

    let output = match run_capture(cmd) {
        Ok(output) => output,
        Err(e) => return Ok(format!("skipped (failed to run sudo -n journalctl): {e:#}")),
    };

    if !output.status.success() && looks_like_noninteractive_sudo_failure(&output.stderr) {
        return Ok("skipped (sudo -n not permitted)".to_string());
    }

    Ok(format!(
        "exit: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        output.stdout.trim_end(),
        output.stderr.trim_end()
    ))
}

fn systemd_debug_bundle_ssh(ssh: &SshTarget, service: &str) -> anyhow::Result<String> {
    // Best-effort bundle that never fails the SSH command.
    //
    // For `journalctl` we only try `sudo -n` (non-interactive) access, because
    // prompting for a password here would be surprising and can hang.
    let unit = normalize_unit_name(service);
    let service_q = sh_quote(&unit);
    let script = format!(
        "\
echo 'systemctl is-active:'
systemctl is-active -- {service} 2>&1 || true
echo
echo 'systemctl status:'
systemctl status --no-pager -l -n 100 -- {service} 2>&1 || true
echo
echo 'journalctl (sudo -n, optional, last 10 lines):'
if sudo -n true 2>/dev/null; then
  sudo -n journalctl -u {service} -n 10 --no-pager 2>&1 || true
else
  echo 'skipped (sudo -n not permitted)'
fi
true
",
        service = service_q
    );
    let raw = ssh.run_output(&script).with_context(|| {
        format!(
            "failed to collect systemd debug bundle on {}",
            ssh.destination()
        )
    })?;
    Ok(redact_debug_bundle(&raw))
}

fn redact_debug_bundle(bundle: &str) -> String {
    // The debug bundle can include journal entries. In failure modes, systemd
    // may log the contents of problematic `EnvironmentFile=` lines (including
    // tokens). Best-effort redact known secret-bearing values.
    //
    // Keep this simple and dependency-free: operate line-by-line and scrub
    // common patterns.
    const ENV_VARS: [&str; 4] = [
        "FLEDX_CP_REGISTRATION_TOKEN",
        "FLEDX_CP_OPERATOR_TOKENS",
        "FLEDX_CP_TOKENS_PEPPER",
        "FLEDX_AGENT_NODE_TOKEN",
    ];

    let mut out = String::with_capacity(bundle.len());
    for line in bundle.lines() {
        let mut redacted = line.to_string();

        for name in ENV_VARS {
            let needle = format!("{name}=");
            if let Some(idx) = redacted.find(&needle) {
                let value_start = idx + needle.len();
                let rest = redacted[value_start..].trim_start();
                let replacement = if rest.starts_with('"') {
                    "\"<redacted>\""
                } else {
                    "<redacted>"
                };

                redacted.truncate(value_start);
                redacted.push_str(replacement);
            }
        }

        redacted = redact_bearer_tokens(&redacted);

        out.push_str(&redacted);
        out.push('\n');
    }
    out
}

fn redact_bearer_tokens(line: &str) -> String {
    fn redact_with_prefix(mut line: &str, prefix: &str) -> String {
        let mut out = String::with_capacity(line.len());
        while let Some(idx) = line.find(prefix) {
            out.push_str(&line[..idx]);
            out.push_str(prefix);
            out.push_str("<redacted>");

            let after = &line[idx + prefix.len()..];
            let token_end = after
                .find(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == ',')
                .unwrap_or(after.len());
            line = &after[token_end..];
        }
        out.push_str(line);
        out
    }

    // Common header patterns we may see in logs.
    let line = redact_with_prefix(line, "Bearer ");
    redact_with_prefix(&line, "bearer ")
}

pub fn render_agent_env(input: &AgentEnvInputs) -> String {
    let AgentEnvInputs {
        control_plane_url,
        node_id,
        node_token,
        allow_insecure_http,
        ca_cert_path,
        volume_dir,
        tunnel_host,
        tunnel,
    } = input;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "FLEDX_AGENT_CONTROL_PLANE_URL={}",
        systemd_quote_env_value(control_plane_url)
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_NODE_ID={}",
        systemd_quote_env_value(&node_id.to_string())
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_NODE_TOKEN={}",
        systemd_quote_env_value(node_token)
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES={}",
        systemd_quote_env_value(&volume_dir.display().to_string())
    );
    if *allow_insecure_http {
        let _ = writeln!(
            out,
            "FLEDX_AGENT_ALLOW_INSECURE_HTTP={}",
            systemd_quote_env_value("true")
        );
    }
    if let Some(path) = ca_cert_path.as_deref() {
        let _ = writeln!(
            out,
            "FLEDX_AGENT_CA_CERT_PATH={}",
            systemd_quote_env_value(path)
        );
    }

    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_ENDPOINT_HOST={}",
        systemd_quote_env_value(tunnel_host)
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_ENDPOINT_PORT={}",
        systemd_quote_env_value(&tunnel.port.to_string())
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_USE_TLS={}",
        systemd_quote_env_value(&tunnel.use_tls.to_string())
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_CONNECT_TIMEOUT_SECS={}",
        systemd_quote_env_value(&tunnel.connect_timeout_secs.to_string())
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_HEARTBEAT_INTERVAL_SECS={}",
        systemd_quote_env_value(&tunnel.heartbeat_interval_secs.to_string())
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_HEARTBEAT_TIMEOUT_SECS={}",
        systemd_quote_env_value(&tunnel.heartbeat_timeout_secs.to_string())
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_TOKEN_HEADER={}",
        systemd_quote_env_value(&tunnel.token_header)
    );
    let _ = writeln!(out, "RUST_LOG={}", systemd_quote_env_value("info"));
    out
}

pub struct AgentEnvInputs {
    pub control_plane_url: String,
    pub node_id: uuid::Uuid,
    pub node_token: String,
    pub allow_insecure_http: bool,
    pub ca_cert_path: Option<String>,
    pub volume_dir: PathBuf,
    pub tunnel_host: String,
    pub tunnel: common::api::TunnelEndpoint,
}

const DEFAULT_DOCKER_SERVICE: &str = "docker.service";

pub fn render_agent_unit(input: &AgentUnitInputs) -> String {
    render_agent_unit_with_docker_service(input, Some(DEFAULT_DOCKER_SERVICE))
}

pub fn render_agent_unit_with_docker_service(
    input: &AgentUnitInputs,
    docker_service: Option<&str>,
) -> String {
    let AgentUnitInputs {
        service_user,
        env_path,
        bin_path,
    } = input;

    let env_path_escaped = systemd_escape_environment_file_path(env_path);
    let bin_path_escaped = systemd_quote_unit_path(bin_path);
    let docker_service = docker_service
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_unit_name);
    let after_line = match docker_service.as_deref() {
        Some(service) => format!("After=network-online.target {service}"),
        None => "After=network-online.target".to_string(),
    };
    let requires_line = docker_service
        .as_deref()
        .map(|service| format!("Requires={service}\n"))
        .unwrap_or_default();

    format!(
        "\
[Unit]
Description=Distributed Edge Hosting Node Agent
{after_line}
{requires_line}Wants=network-online.target

[Service]
User={service_user}
EnvironmentFile={env_path}
ExecStart={bin_path}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
",
        env_path = env_path_escaped,
        bin_path = bin_path_escaped,
    )
}

pub struct AgentUnitInputs {
    pub service_user: String,
    pub env_path: PathBuf,
    pub bin_path: PathBuf,
}

pub struct ControlPlaneInstallSettings {
    pub bin_dir: PathBuf,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub service_user: String,
    pub sudo_interactive: bool,
}

pub struct ControlPlaneTlsAssets {
    pub ca_cert_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_cert_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

fn cp_env_with_tls(env: &str, tls_assets: Option<&ControlPlaneTlsAssets>) -> String {
    let Some(tls) = tls_assets else {
        return env.to_string();
    };

    let mut out = String::new();
    for line in env.lines() {
        let trimmed = line.trim_start();
        let is_tls_line = trimmed.starts_with("FLEDX_CP_SERVER_TLS_ENABLED=")
            || trimmed.starts_with("FLEDX_CP_SERVER_TLS_CERT_PATH=")
            || trimmed.starts_with("FLEDX_CP_SERVER_TLS_KEY_PATH=");
        if !is_tls_line {
            out.push_str(line);
            out.push('\n');
        }
    }

    let enabled = systemd_quote_env_value("true");
    let cert_path = systemd_quote_env_value(&tls.cert_path.to_string_lossy());
    let key_path = systemd_quote_env_value(&tls.key_path.to_string_lossy());
    out.push_str(&format!("FLEDX_CP_SERVER_TLS_ENABLED={enabled}\n"));
    out.push_str(&format!("FLEDX_CP_SERVER_TLS_CERT_PATH={cert_path}\n"));
    out.push_str(&format!("FLEDX_CP_SERVER_TLS_KEY_PATH={key_path}\n"));
    out
}

pub fn install_cp_local(
    bin: &Path,
    env: &str,
    unit: &str,
    settings: &ControlPlaneInstallSettings,
) -> anyhow::Result<()> {
    install_cp_local_with_tls(bin, env, unit, settings, None)
}

pub fn install_cp_local_with_tls(
    bin: &Path,
    env: &str,
    unit: &str,
    settings: &ControlPlaneInstallSettings,
    tls_assets: Option<&ControlPlaneTlsAssets>,
) -> anyhow::Result<()> {
    validate_linux_username(&settings.service_user)?;
    let sudo = SudoMode::root(settings.sudo_interactive);

    if !local_user_exists(&settings.service_user)? {
        sudo_run_cmd(
            sudo,
            "useradd",
            vec![
                OsString::from("-r"),
                OsString::from("-s"),
                OsString::from("/bin/false"),
                OsString::from(settings.service_user.clone()),
            ],
        )?;
    }

    sudo_run_cmd(
        sudo,
        "install",
        vec![
            OsString::from("-d"),
            OsString::from("-o"),
            OsString::from("root"),
            OsString::from("-g"),
            OsString::from("root"),
            settings.bin_dir.clone().into_os_string(),
        ],
    )?;

    sudo_run_cmd(
        sudo,
        "install",
        vec![
            OsString::from("-d"),
            OsString::from("-o"),
            OsString::from("root"),
            OsString::from("-g"),
            OsString::from("root"),
            settings.config_dir.clone().into_os_string(),
        ],
    )?;

    let cp_dir = settings.data_dir.join("cp");
    sudo_run_cmd(
        sudo,
        "install",
        vec![
            OsString::from("-d"),
            OsString::from("-o"),
            OsString::from(settings.service_user.clone()),
            OsString::from("-g"),
            OsString::from(settings.service_user.clone()),
            cp_dir.into_os_string(),
        ],
    )?;

    let bin_path = settings.bin_dir.join("fledx-cp");
    sudo_run_cmd(
        sudo,
        "install",
        vec![
            OsString::from("-m"),
            OsString::from("0755"),
            bin.as_os_str().to_os_string(),
            bin_path.into_os_string(),
        ],
    )?;

    let env_tmp = tempfile::NamedTempFile::new()?;
    let env = cp_env_with_tls(env, tls_assets);
    fs::write(env_tmp.path(), env)?;
    let env_path = settings.config_dir.join("fledx-cp.env");
    sudo_run_cmd(
        sudo,
        "install",
        vec![
            OsString::from("-m"),
            OsString::from("0600"),
            env_tmp.path().as_os_str().to_os_string(),
            env_path.into_os_string(),
        ],
    )?;

    if let Some(tls) = tls_assets {
        let tls_dir = tls.ca_cert_path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "TLS CA path must include a parent directory: {}",
                tls.ca_cert_path.display()
            )
        })?;
        sudo_run_cmd(
            sudo,
            "install",
            vec![
                OsString::from("-d"),
                OsString::from("-o"),
                OsString::from("root"),
                OsString::from("-g"),
                OsString::from("root"),
                tls_dir.as_os_str().to_os_string(),
            ],
        )?;

        let ca_tmp = tempfile::NamedTempFile::new()?;
        fs::write(ca_tmp.path(), &tls.ca_cert_pem)?;
        sudo_run_cmd(
            sudo,
            "install",
            vec![
                OsString::from("-m"),
                OsString::from("0644"),
                ca_tmp.path().as_os_str().to_os_string(),
                tls.ca_cert_path.clone().into_os_string(),
            ],
        )?;

        let cert_tmp = tempfile::NamedTempFile::new()?;
        fs::write(cert_tmp.path(), &tls.cert_pem)?;
        sudo_run_cmd(
            sudo,
            "install",
            vec![
                OsString::from("-m"),
                OsString::from("0644"),
                OsString::from("-o"),
                OsString::from(settings.service_user.clone()),
                OsString::from("-g"),
                OsString::from(settings.service_user.clone()),
                cert_tmp.path().as_os_str().to_os_string(),
                tls.cert_path.clone().into_os_string(),
            ],
        )?;

        let key_tmp = tempfile::NamedTempFile::new()?;
        fs::write(key_tmp.path(), &tls.key_pem)?;
        sudo_run_cmd(
            sudo,
            "install",
            vec![
                OsString::from("-m"),
                OsString::from("0600"),
                OsString::from("-o"),
                OsString::from(settings.service_user.clone()),
                OsString::from("-g"),
                OsString::from(settings.service_user.clone()),
                key_tmp.path().as_os_str().to_os_string(),
                tls.key_path.clone().into_os_string(),
            ],
        )?;
    }

    let unit_tmp = tempfile::NamedTempFile::new()?;
    fs::write(unit_tmp.path(), unit)?;
    sudo_run_cmd(
        sudo,
        "install",
        vec![
            OsString::from("-m"),
            OsString::from("0644"),
            unit_tmp.path().as_os_str().to_os_string(),
            OsString::from("/etc/systemd/system/fledx-cp.service"),
        ],
    )?;

    sudo_run_cmd(sudo, "systemctl", vec![OsString::from("daemon-reload")])?;
    sudo_run_cmd(
        sudo,
        "systemctl",
        vec![
            OsString::from("enable"),
            OsString::from("--now"),
            OsString::from("fledx-cp"),
        ],
    )?;
    Ok(())
}

pub fn install_cp_ssh(
    ssh: &SshTarget,
    bin: &Path,
    env: &str,
    unit: &str,
    settings: &ControlPlaneInstallSettings,
) -> anyhow::Result<()> {
    install_cp_ssh_with_tls(ssh, bin, env, unit, settings, None)
}

pub fn install_cp_ssh_with_tls(
    ssh: &SshTarget,
    bin: &Path,
    env: &str,
    unit: &str,
    settings: &ControlPlaneInstallSettings,
    tls_assets: Option<&ControlPlaneTlsAssets>,
) -> anyhow::Result<()> {
    let sudo = SudoMode::root(settings.sudo_interactive);
    validate_linux_username(&settings.service_user)?;
    let remote_dir = ssh.mktemp_dir("fledx-bootstrap-cp")?;

    let local_dir = tempfile::tempdir()?;
    let local_bin = local_dir.path().join("fledx-cp");
    fs::copy(bin, &local_bin)?;

    let local_env = local_dir.path().join("fledx-cp.env");
    let env = cp_env_with_tls(env, tls_assets);
    write_file_with_mode(&local_env, &env, 0o600)?;

    let local_unit = local_dir.path().join("fledx-cp.service");
    write_file_with_mode(&local_unit, unit, 0o644)?;

    if let Some(tls) = tls_assets {
        let local_ca = local_dir.path().join("fledx-cp-ca.pem");
        write_file_with_mode(&local_ca, &tls.ca_cert_pem, 0o644)?;
        ssh.upload_file(
            &local_ca,
            &PathBuf::from(format!("{remote_dir}/fledx-cp-ca.pem")),
        )?;

        let local_cert = local_dir.path().join("fledx-cp-cert.pem");
        write_file_with_mode(&local_cert, &tls.cert_pem, 0o644)?;
        ssh.upload_file(
            &local_cert,
            &PathBuf::from(format!("{remote_dir}/fledx-cp-cert.pem")),
        )?;

        let local_key = local_dir.path().join("fledx-cp-key.pem");
        write_file_with_mode(&local_key, &tls.key_pem, 0o600)?;
        ssh.upload_file(
            &local_key,
            &PathBuf::from(format!("{remote_dir}/fledx-cp-key.pem")),
        )?;
    }

    // IMPORTANT: Do not execute multi-line scripts via `ssh host sh -c <script>`.
    // Some SSH configurations inject banners/motd text, and multi-line payloads
    // can be split by the remote shell in surprising ways (leading to parts of
    // the install running without sudo).
    //
    // Upload the script as a file and execute it via `sh <path>` under sudo.
    let local_script = local_dir.path().join("install-cp.sh");
    let tls_install = if let Some(tls) = tls_assets {
        let tls_dir = tls.ca_cert_path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "TLS CA path must include a parent directory: {}",
                tls.ca_cert_path.display()
            )
        })?;
        let tls_dir_q = sh_quote_path(tls_dir);
        let ca_path_q = sh_quote_path(&tls.ca_cert_path);
        let cert_path_q = sh_quote_path(&tls.cert_path);
        let key_path_q = sh_quote_path(&tls.key_path);
        let service_user_q = sh_quote(&settings.service_user);
        format!(
            "\
install -d -o root -g root {tls_dir}
install -m 0644 \"$REMOTE_DIR/fledx-cp-ca.pem\" {ca_path}
install -m 0644 -o {service_user} -g {service_user} \"$REMOTE_DIR/fledx-cp-cert.pem\" {cert_path}
install -m 0600 -o {service_user} -g {service_user} \"$REMOTE_DIR/fledx-cp-key.pem\" {key_path}
",
            tls_dir = tls_dir_q,
            ca_path = ca_path_q,
            cert_path = cert_path_q,
            key_path = key_path_q,
            service_user = service_user_q,
        )
    } else {
        String::new()
    };
    let script = render_cp_install_script(settings, &remote_dir, &tls_install);
    write_file_with_mode(&local_script, &script, 0o700)?;

    ssh.upload_file(&local_bin, &PathBuf::from(format!("{remote_dir}/fledx-cp")))?;
    ssh.upload_file(
        &local_env,
        &PathBuf::from(format!("{remote_dir}/fledx-cp.env")),
    )?;
    ssh.upload_file(
        &local_unit,
        &PathBuf::from(format!("{remote_dir}/fledx-cp.service")),
    )?;

    let remote_script = PathBuf::from(format!("{remote_dir}/install-cp.sh"));
    ssh.upload_file(&local_script, &remote_script)?;
    // Run the uploaded script directly to avoid `sh -c` argument-boundary
    // issues that can drop into an interactive shell when a TTY is allocated.
    ssh.run_command(sudo, "sh", &[remote_script.as_os_str().to_os_string()])?;
    Ok(())
}

fn render_cp_install_script(
    settings: &ControlPlaneInstallSettings,
    remote_dir: &str,
    tls_install: &str,
) -> String {
    let env_path = settings.config_dir.join("fledx-cp.env");
    let bin_path = settings.bin_dir.join("fledx-cp");
    let cp_dir = settings.data_dir.join("cp");

    let remote_dir_q = sh_quote(remote_dir);
    let service_user_q = sh_quote(&settings.service_user);
    let bin_dir_q = sh_quote_path(&settings.bin_dir);
    let config_dir_q = sh_quote_path(&settings.config_dir);
    let cp_dir_q = sh_quote_path(&cp_dir);
    let bin_path_q = sh_quote_path(&bin_path);
    let env_path_q = sh_quote_path(&env_path);

    format!(
        "\
set -eu

REMOTE_DIR={remote_dir}
SERVICE_USER={service_user}
BIN_DIR={bin_dir}
CONFIG_DIR={config_dir}
CP_DIR={cp_dir}
BIN_PATH={bin_path}
ENV_PATH={env_path}

cleanup() {{
  rm -rf -- \"$REMOTE_DIR\"
}}
trap cleanup EXIT

useradd -r -s /bin/false \"$SERVICE_USER\" 2>/dev/null || true
install -d -o root -g root \"$BIN_DIR\"
install -d -o root -g root \"$CONFIG_DIR\"
install -d -o \"$SERVICE_USER\" -g \"$SERVICE_USER\" \"$CP_DIR\"
{tls_install}\
install -m 0755 \"$REMOTE_DIR/fledx-cp\" \"$BIN_PATH\"
install -m 0600 \"$REMOTE_DIR/fledx-cp.env\" \"$ENV_PATH\"
install -m 0644 \"$REMOTE_DIR/fledx-cp.service\" /etc/systemd/system/fledx-cp.service
systemctl daemon-reload
systemctl enable --now fledx-cp
# Ensure an already-running unit picks up the new env/unit/binary.
systemctl restart fledx-cp
",
        remote_dir = remote_dir_q,
        service_user = service_user_q,
        bin_dir = bin_dir_q,
        config_dir = config_dir_q,
        cp_dir = cp_dir_q,
        bin_path = bin_path_q,
        env_path = env_path_q,
        tls_install = tls_install,
    )
}

pub struct AgentInstallSettings {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub service_user: String,
    pub sudo_interactive: bool,
    /// Whether to add the agent service user to the group that owns
    /// `/var/run/docker.sock` on the target host.
    ///
    /// On most systems, access to the Docker daemon via the socket is
    /// effectively root-equivalent.
    pub add_to_docker_socket_group: bool,
}

pub struct AgentCaCert {
    pub cert_pem: String,
    pub cert_path: PathBuf,
}

pub fn install_agent_ssh(
    ssh: &SshTarget,
    bin: &Path,
    env: &str,
    unit: &str,
    settings: &AgentInstallSettings,
    bin_path: &Path,
) -> anyhow::Result<()> {
    install_agent_ssh_with_ca(ssh, bin, env, unit, settings, bin_path, None)
}

pub fn install_agent_ssh_with_ca(
    ssh: &SshTarget,
    bin: &Path,
    env: &str,
    unit: &str,
    settings: &AgentInstallSettings,
    bin_path: &Path,
    ca_cert: Option<&AgentCaCert>,
) -> anyhow::Result<()> {
    let sudo = SudoMode::root(settings.sudo_interactive);
    validate_linux_username(&settings.service_user)?;
    let remote_dir = ssh.mktemp_dir("fledx-bootstrap-agent")?;

    let local_dir = tempfile::tempdir()?;
    let local_bin = local_dir.path().join("fledx-agent");
    fs::copy(bin, &local_bin)?;

    let local_env = local_dir.path().join("fledx-agent.env");
    write_file_with_mode(&local_env, env, 0o600)?;

    let local_unit = local_dir.path().join("fledx-agent.service");
    write_file_with_mode(&local_unit, unit, 0o644)?;

    let local_script = local_dir.path().join("install-agent.sh");
    let ca_install = if let Some(ca_cert) = ca_cert {
        let ca_dir = ca_cert.cert_path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "CA cert path must include a parent directory: {}",
                ca_cert.cert_path.display()
            )
        })?;
        let ca_dir_q = sh_quote_path(ca_dir);
        let ca_path_q = sh_quote_path(&ca_cert.cert_path);
        format!(
            "\
install -d -o root -g root {ca_dir}
install -m 0644 \"$REMOTE_DIR/fledx-agent-ca.pem\" {ca_path}
",
            ca_dir = ca_dir_q,
            ca_path = ca_path_q,
        )
    } else {
        String::new()
    };
    let script = render_agent_install_script(settings, &remote_dir, bin_path, &ca_install);
    write_file_with_mode(&local_script, &script, 0o700)?;

    ssh.upload_file(
        &local_bin,
        &PathBuf::from(format!("{remote_dir}/fledx-agent")),
    )?;
    ssh.upload_file(
        &local_env,
        &PathBuf::from(format!("{remote_dir}/fledx-agent.env")),
    )?;
    ssh.upload_file(
        &local_unit,
        &PathBuf::from(format!("{remote_dir}/fledx-agent.service")),
    )?;
    if let Some(ca_cert) = ca_cert {
        let local_ca = local_dir.path().join("fledx-agent-ca.pem");
        write_file_with_mode(&local_ca, &ca_cert.cert_pem, 0o644)?;
        ssh.upload_file(
            &local_ca,
            &PathBuf::from(format!("{remote_dir}/fledx-agent-ca.pem")),
        )?;
    }

    let remote_script = PathBuf::from(format!("{remote_dir}/install-agent.sh"));
    ssh.upload_file(&local_script, &remote_script)?;
    // Run the uploaded script directly to avoid `sh -c` argument-boundary
    // issues that can drop into an interactive shell when a TTY is allocated.
    ssh.run_command(sudo, "sh", &[remote_script.as_os_str().to_os_string()])?;
    Ok(())
}

fn render_agent_install_script(
    settings: &AgentInstallSettings,
    remote_dir: &str,
    bin_path: &Path,
    ca_install: &str,
) -> String {
    let env_path = settings.config_dir.join("fledx-agent.env");
    let bin_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
    let agent_dir = settings.data_dir.join("agent");
    let volumes_dir = settings.data_dir.join("volumes");

    let add_to_docker_socket_group = if settings.add_to_docker_socket_group {
        "1"
    } else {
        "0"
    };

    let remote_dir_q = sh_quote(remote_dir);
    let service_user_q = sh_quote(&settings.service_user);
    let bin_dir_q = sh_quote_path(bin_dir);
    let config_dir_q = sh_quote_path(&settings.config_dir);
    let agent_dir_q = sh_quote_path(&agent_dir);
    let volumes_dir_q = sh_quote_path(&volumes_dir);
    let bin_path_q = sh_quote_path(bin_path);
    let env_path_q = sh_quote_path(&env_path);

    format!(
        "\
set -eu

REMOTE_DIR={remote_dir}
SERVICE_USER={service_user}
BIN_DIR={bin_dir}
	CONFIG_DIR={config_dir}
	AGENT_DIR={agent_dir}
	VOLUMES_DIR={volumes_dir}
	BIN_PATH={bin_path}
	ENV_PATH={env_path}
	ADD_DOCKER_SOCKET_GROUP={add_to_docker_socket_group}

	cleanup() {{
	  rm -rf -- \"$REMOTE_DIR\"
	}}
	trap cleanup EXIT

	if [ ! -S /var/run/docker.sock ]; then
	  echo \"docker socket not found at /var/run/docker.sock\" >&2
	  exit 1
	fi

	useradd -r -s /bin/false \"$SERVICE_USER\" 2>/dev/null || true

	if [ \"$ADD_DOCKER_SOCKET_GROUP\" = \"1\" ]; then
	  docker_group=$(stat -c '%G' /var/run/docker.sock)
	  if [ -z \"$docker_group\" ]; then
	    echo \"failed to determine docker socket group\" >&2
	    exit 1
	  fi

	  usermod -a -G \"$docker_group\" \"$SERVICE_USER\"
	fi

install -d -o root -g root \"$BIN_DIR\"
install -d -o root -g root \"$CONFIG_DIR\"
install -d -o \"$SERVICE_USER\" -g \"$SERVICE_USER\" \"$AGENT_DIR\"
install -d -o \"$SERVICE_USER\" -g \"$SERVICE_USER\" \"$VOLUMES_DIR\"
{ca_install}\
install -m 0755 \"$REMOTE_DIR/fledx-agent\" \"$BIN_PATH\"
install -m 0600 \"$REMOTE_DIR/fledx-agent.env\" \"$ENV_PATH\"
install -m 0644 \"$REMOTE_DIR/fledx-agent.service\" /etc/systemd/system/fledx-agent.service
systemctl daemon-reload
systemctl enable --now fledx-agent
# Ensure an already-running unit picks up the new env/unit/binary.
systemctl restart fledx-agent
",
        remote_dir = remote_dir_q,
        service_user = service_user_q,
        bin_dir = bin_dir_q,
        config_dir = config_dir_q,
        agent_dir = agent_dir_q,
        volumes_dir = volumes_dir_q,
        bin_path = bin_path_q,
        env_path = env_path_q,
        add_to_docker_socket_group = add_to_docker_socket_group,
        ca_install = ca_install,
    )
}

fn validate_linux_username(value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("service user must not be empty");
    }
    if value.len() > 32 {
        anyhow::bail!("service user '{}' is too long (max 32 characters)", value);
    }

    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        anyhow::bail!("service user must not be empty");
    };

    if !matches!(first, 'a'..='z' | '_') {
        anyhow::bail!(
            "invalid service user '{}': must start with [a-z_] (ASCII lowercase)",
            value
        );
    }

    for ch in chars {
        if !matches!(ch, 'a'..='z' | '0'..='9' | '_' | '-') {
            anyhow::bail!(
                "invalid service user '{}': unsupported character '{}'",
                value,
                ch
            );
        }
    }

    Ok(())
}

fn local_user_exists(user: &str) -> anyhow::Result<bool> {
    let mut cmd = Command::new("id");
    cmd.arg("-u").arg(user);
    let output = run_capture(cmd)?;
    Ok(output.status.success())
}

#[cfg(unix)]
fn write_file_with_mode(path: &Path, contents: &str, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_with_mode(path: &Path, contents: &str, _mode: u32) -> anyhow::Result<()> {
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn sudo_run_cmd(sudo: SudoMode, program: &str, args: Vec<OsString>) -> anyhow::Result<()> {
    let mut cmd = Command::new("sudo");
    if !sudo.interactive {
        cmd.arg("-n");
    }
    cmd.arg(program);
    cmd.args(args);
    let output = run_capture(cmd)?;
    if output.status.success() {
        return Ok(());
    }

    if !sudo.interactive && looks_like_noninteractive_sudo_failure(&output.stderr) {
        anyhow::bail!(
            "sudo failed in non-interactive mode.\n\
Hint: rerun with `--sudo-interactive` or configure passwordless sudo \
(NOPASSWD) for this user.\n\
\nstdout:\n{}\n\
stderr:\n{}",
            output.stdout.trim_end(),
            output.stderr.trim_end()
        );
    }

    anyhow::bail!(
        "command failed (status {}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        output.stdout.trim_end(),
        output.stderr.trim_end()
    );
}

pub fn systemd_quote_unit_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub fn systemd_quote_unit_path(path: &Path) -> String {
    systemd_quote_unit_value(&path.as_os_str().to_string_lossy())
}

/// Escape a path for use in `EnvironmentFile=` inside systemd unit files.
///
/// `EnvironmentFile=` does **not** accept quoting with double quotes.
/// If the value is written as `"path"`, systemd treats the leading `"` as part
/// of the path and will ignore it as non-absolute.
///
/// We still escape `%` to avoid systemd specifier expansion, and we escape
/// whitespace using `\\xNN` so paths containing spaces remain a single token.
pub fn systemd_escape_environment_file_path(path: &Path) -> String {
    systemd_escape_environment_file_value(&path.as_os_str().to_string_lossy())
}

pub fn systemd_escape_environment_file_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '%' => out.push_str("%%"),
            ' ' => out.push_str("\\x20"),
            '\t' => out.push_str("\\x09"),
            '\n' => out.push_str("\\x0a"),
            '\r' => out.push_str("\\x0d"),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn systemd_quote_env_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::super::ENV_LOCK;
    use super::*;
    use std::env;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("set perms");
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: String) -> Self {
            let prev = env::var(key).ok();
            env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }

    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let script = format!("#!/bin/sh\n{body}\n");
        fs::write(&path, script).expect("write script");
        make_executable(&path);
        path
    }

    fn with_fake_commands<F, R>(scripts: &[(&str, &str)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempdir().expect("tempdir");
        for (name, body) in scripts {
            let _ = write_script(dir.path(), name, body);
        }
        let old_path = env::var("PATH").unwrap_or_default();
        let _path_guard =
            EnvVarGuard::set("PATH", format!("{}:{}", dir.path().display(), old_path));
        f()
    }

    #[test]
    fn systemd_quote_unit_value_escapes_percent() {
        assert_eq!(
            systemd_quote_unit_value("/opt/fledx/%h/bin"),
            "\"/opt/fledx/%%h/bin\""
        );
    }

    #[test]
    fn systemd_escape_environment_file_value_does_not_quote_and_escapes() {
        assert_eq!(
            systemd_escape_environment_file_value("/etc/fledx dir/fledx%agent.env"),
            "/etc/fledx\\x20dir/fledx%%agent.env"
        );
    }

    #[test]
    fn systemd_escape_environment_file_path_escapes_whitespace() {
        let escaped =
            systemd_escape_environment_file_path(Path::new("/etc/fledx dir/fledx\tagent.env"));
        assert_eq!(escaped, "/etc/fledx\\x20dir/fledx\\x09agent.env");
    }

    #[test]
    fn systemd_quote_env_value_escapes_quotes_and_backslashes() {
        assert_eq!(systemd_quote_env_value("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn redact_debug_bundle_redacts_known_env_vars() {
        let raw = "\
ok
FLEDX_AGENT_NODE_TOKEN=\"deadbeef\"
FLEDX_CP_REGISTRATION_TOKEN=deadbeef
";

        let redacted = redact_debug_bundle(raw);
        assert!(redacted.contains("FLEDX_AGENT_NODE_TOKEN=\"<redacted>\""));
        assert!(redacted.contains("FLEDX_CP_REGISTRATION_TOKEN=<redacted>"));
        assert!(!redacted.contains("deadbeef"));
    }

    #[test]
    fn redact_debug_bundle_redacts_bearer_tokens() {
        let raw = "\
authorization: Bearer abcdef
authorization: bearer qwerty
";
        let redacted = redact_debug_bundle(raw);
        assert!(redacted.contains("authorization: Bearer <redacted>"));
        assert!(redacted.contains("authorization: bearer <redacted>"));
        assert!(!redacted.contains("abcdef"));
        assert!(!redacted.contains("qwerty"));
    }

    #[test]
    fn render_agent_unit_quotes_paths_for_systemd() {
        let unit = render_agent_unit(&AgentUnitInputs {
            service_user: "fledx-agent".to_string(),
            env_path: PathBuf::from("/etc/fledx dir/fledx%agent.env"),
            bin_path: PathBuf::from("/usr/local/bin dir/fledx-agent"),
        });

        assert!(unit.contains("EnvironmentFile=/etc/fledx\\x20dir/fledx%%agent.env"));
        assert!(unit.contains("ExecStart=\"/usr/local/bin dir/fledx-agent\""));
    }

    #[test]
    fn render_agent_unit_omits_docker_service_when_disabled() {
        let unit = render_agent_unit_with_docker_service(
            &AgentUnitInputs {
                service_user: "fledx-agent".to_string(),
                env_path: PathBuf::from("/etc/fledx/fledx-agent.env"),
                bin_path: PathBuf::from("/usr/local/bin/fledx-agent"),
            },
            None,
        );

        assert!(unit.contains("After=network-online.target"));
        assert!(!unit.contains("docker.service"));
        assert!(!unit.contains("Requires="));
    }

    #[test]
    fn render_agent_unit_normalizes_docker_service_name() {
        let unit = render_agent_unit_with_docker_service(
            &AgentUnitInputs {
                service_user: "fledx-agent".to_string(),
                env_path: PathBuf::from("/etc/fledx/fledx-agent.env"),
                bin_path: PathBuf::from("/usr/local/bin/fledx-agent"),
            },
            Some("containerd"),
        );

        assert!(unit.contains("After=network-online.target containerd.service"));
        assert!(unit.contains("Requires=containerd.service"));
    }

    #[test]
    fn render_agent_env_quotes_values_for_systemd_env_file() {
        let env = render_agent_env(&AgentEnvInputs {
            control_plane_url: "http://localhost:49421".to_string(),
            node_id: uuid::Uuid::nil(),
            node_token: "deadbeef".to_string(),
            allow_insecure_http: true,
            ca_cert_path: Some("/etc/fledx/tls/ca.pem".to_string()),
            volume_dir: PathBuf::from("/var/lib/fledx/volumes dir"),
            tunnel_host: "localhost".to_string(),
            tunnel: common::api::TunnelEndpoint {
                host: "localhost".to_string(),
                port: 1234,
                use_tls: false,
                connect_timeout_secs: 5,
                heartbeat_interval_secs: 5,
                heartbeat_timeout_secs: 15,
                token_header: "X-Fledx-Tunnel-Token".to_string(),
            },
        });

        assert!(env.contains("FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES=\"/var/lib/fledx/volumes dir\""));
        assert!(env.contains("FLEDX_AGENT_ALLOW_INSECURE_HTTP=\"true\""));
        assert!(env.contains("FLEDX_AGENT_CA_CERT_PATH=\"/etc/fledx/tls/ca.pem\""));
    }

    #[test]
    fn normalize_unit_name_appends_service_suffix() {
        assert_eq!(normalize_unit_name("fledx-agent"), "fledx-agent.service");
        assert_eq!(
            normalize_unit_name("fledx-agent.service"),
            "fledx-agent.service"
        );
    }

    #[test]
    fn parse_systemctl_is_active_output_prefers_last_known_token() {
        assert_eq!(parse_systemctl_is_active_output("active\n"), "active");
        assert_eq!(
            parse_systemctl_is_active_output("Welcome!\nactive\n"),
            "active"
        );
        assert_eq!(
            parse_systemctl_is_active_output("active\nsome banner"),
            "active"
        );
    }

    #[test]
    fn cp_env_with_tls_adds_tls_settings() {
        let tls = ControlPlaneTlsAssets {
            ca_cert_pem: "ca".to_string(),
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            ca_cert_path: PathBuf::from("/etc/fledx/tls/ca.pem"),
            cert_path: PathBuf::from("/etc/fledx/tls/cert.pem"),
            key_path: PathBuf::from("/etc/fledx/tls/key.pem"),
        };
        let env = cp_env_with_tls("FLEDX_CP_SERVER_HOST=0.0.0.0\n", Some(&tls));
        assert!(env.contains("FLEDX_CP_SERVER_TLS_ENABLED=\"true\""));
        assert!(env.contains("FLEDX_CP_SERVER_TLS_CERT_PATH=\"/etc/fledx/tls/cert.pem\""));
        assert!(env.contains("FLEDX_CP_SERVER_TLS_KEY_PATH=\"/etc/fledx/tls/key.pem\""));
    }

    #[test]
    fn cp_env_with_tls_overrides_existing_tls_settings() {
        let tls = ControlPlaneTlsAssets {
            ca_cert_pem: "ca".to_string(),
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            ca_cert_path: PathBuf::from("/etc/fledx/tls/ca.pem"),
            cert_path: PathBuf::from("/etc/fledx/tls/cert.pem"),
            key_path: PathBuf::from("/etc/fledx/tls/key.pem"),
        };
        let env = cp_env_with_tls(
            "FLEDX_CP_SERVER_TLS_ENABLED=\"false\"\nFLEDX_CP_SERVER_TLS_CERT_PATH=\"/tmp/old.pem\"\n",
            Some(&tls),
        );
        assert!(!env.contains("/tmp/old.pem"));
        assert!(env.contains("FLEDX_CP_SERVER_TLS_ENABLED=\"true\""));
        assert!(env.contains("FLEDX_CP_SERVER_TLS_CERT_PATH=\"/etc/fledx/tls/cert.pem\""));
    }

    #[test]
    fn render_cp_install_script_restarts_service() {
        let settings = ControlPlaneInstallSettings {
            bin_dir: PathBuf::from("/usr/local/bin"),
            config_dir: PathBuf::from("/etc/fledx"),
            data_dir: PathBuf::from("/var/lib/fledx"),
            service_user: "fledx-cp".to_string(),
            sudo_interactive: false,
        };
        let script = render_cp_install_script(&settings, "/tmp/fledx-bootstrap-cp.ABCDEF", "");
        assert!(script.contains("systemctl enable --now fledx-cp"));
        assert!(script.contains("systemctl restart fledx-cp"));
    }

    #[test]
    fn render_agent_install_script_restarts_service() {
        let settings = AgentInstallSettings {
            config_dir: PathBuf::from("/etc/fledx"),
            data_dir: PathBuf::from("/var/lib/fledx"),
            service_user: "fledx-agent".to_string(),
            sudo_interactive: false,
            add_to_docker_socket_group: false,
        };
        let script = render_agent_install_script(
            &settings,
            "/tmp/fledx-bootstrap-agent.ABCDEF",
            Path::new("/usr/local/bin/fledx-agent"),
            "",
        );
        assert!(script.contains("systemctl enable --now fledx-agent"));
        assert!(script.contains("systemctl restart fledx-agent"));
    }

    #[test]
    fn render_cp_install_script_includes_tls_section() {
        let settings = ControlPlaneInstallSettings {
            bin_dir: PathBuf::from("/usr/local/bin"),
            config_dir: PathBuf::from("/etc/fledx"),
            data_dir: PathBuf::from("/var/lib/fledx"),
            service_user: "fledx-cp".to_string(),
            sudo_interactive: false,
        };
        let tls_install = "install -d -o root -g root /etc/fledx/tls\n";
        let script =
            render_cp_install_script(&settings, "/tmp/fledx-bootstrap-cp.ABCDEF", tls_install);
        assert!(script.contains(tls_install));
        assert!(script.contains("install -m 0644"));
    }

    #[test]
    fn render_agent_install_script_includes_ca_install() {
        let settings = AgentInstallSettings {
            config_dir: PathBuf::from("/etc/fledx"),
            data_dir: PathBuf::from("/var/lib/fledx"),
            service_user: "fledx-agent".to_string(),
            sudo_interactive: false,
            add_to_docker_socket_group: true,
        };
        let script = render_agent_install_script(
            &settings,
            "/tmp/fledx-bootstrap-agent.ABCDEF",
            Path::new("/usr/local/bin/fledx-agent"),
            "install -m 0644 /tmp/ca.pem /etc/fledx/ca.pem\n",
        );
        assert!(script.contains("ADD_DOCKER_SOCKET_GROUP=1"));
        assert!(script.contains("install -m 0644 /tmp/ca.pem /etc/fledx/ca.pem"));
    }

    #[test]
    fn systemd_state_local_reports_active_failed_and_inactive() {
        const SYSTEMCTL: &str = r#"
case "$1" in
  is-active)
    if [ "$2" = "--quiet" ]; then
      exit "${FAKE_SYSTEMCTL_IS_ACTIVE_QUIET_EXIT:-3}"
    fi
    printf "%s" "${FAKE_SYSTEMCTL_IS_ACTIVE_OUTPUT:-inactive}"
    exit "${FAKE_SYSTEMCTL_IS_ACTIVE_EXIT:-3}"
    ;;
  is-failed)
    exit "${FAKE_SYSTEMCTL_IS_FAILED_EXIT:-3}"
    ;;
esac
exit 3
"#;

        with_fake_commands(&[("systemctl", SYSTEMCTL)], || {
            let _active_guard = EnvVarGuard::set("FAKE_SYSTEMCTL_IS_ACTIVE_QUIET_EXIT", "0".into());
            let state = systemd_state_local("fledx-agent").expect("active");
            assert_eq!(state, "active");
        });

        with_fake_commands(&[("systemctl", SYSTEMCTL)], || {
            let _active_guard = EnvVarGuard::set("FAKE_SYSTEMCTL_IS_ACTIVE_QUIET_EXIT", "3".into());
            let _failed_guard = EnvVarGuard::set("FAKE_SYSTEMCTL_IS_FAILED_EXIT", "0".into());
            let state = systemd_state_local("fledx-agent").expect("failed");
            assert_eq!(state, "failed");
        });

        with_fake_commands(&[("systemctl", SYSTEMCTL)], || {
            let _active_guard = EnvVarGuard::set("FAKE_SYSTEMCTL_IS_ACTIVE_QUIET_EXIT", "3".into());
            let _failed_guard = EnvVarGuard::set("FAKE_SYSTEMCTL_IS_FAILED_EXIT", "3".into());
            let _output_guard =
                EnvVarGuard::set("FAKE_SYSTEMCTL_IS_ACTIVE_OUTPUT", "inactive\n".into());
            let state = systemd_state_local("fledx-agent").expect("inactive");
            assert_eq!(state, "inactive");
        });
    }

    #[test]
    fn systemd_status_and_journal_local_format_output() {
        const SYSTEMCTL: &str = r#"
if [ "$1" = "status" ]; then
  printf "%s" "${FAKE_SYSTEMCTL_STATUS_OUT:-}"
  printf "%s" "${FAKE_SYSTEMCTL_STATUS_ERR:-}" 1>&2
  exit "${FAKE_SYSTEMCTL_STATUS_EXIT:-0}"
fi
exit 0
"#;
        const SUDO: &str = r#"
cat >/dev/null
printf "%s" "${FAKE_SUDO_STDOUT:-}"
printf "%s" "${FAKE_SUDO_STDERR:-}" 1>&2
exit "${FAKE_SUDO_EXIT:-0}"
"#;

        with_fake_commands(&[("systemctl", SYSTEMCTL), ("sudo", SUDO)], || {
            let _status_out = EnvVarGuard::set("FAKE_SYSTEMCTL_STATUS_OUT", "status ok".into());
            let _status_err = EnvVarGuard::set("FAKE_SYSTEMCTL_STATUS_ERR", "warn".into());
            let _status_exit = EnvVarGuard::set("FAKE_SYSTEMCTL_STATUS_EXIT", "1".into());
            let status = systemd_status_local("fledx-cp").expect("status");
            assert!(status.contains("exit status: 1"));
            assert!(status.contains("status ok"));
            assert!(status.contains("warn"));

            let _sudo_out = EnvVarGuard::set("FAKE_SUDO_STDOUT", "journal ok".into());
            let _sudo_exit = EnvVarGuard::set("FAKE_SUDO_EXIT", "0".into());
            let journal = systemd_journal_local("fledx-cp").expect("journal");
            assert!(journal.contains("journal ok"));
        });
    }

    #[test]
    fn systemd_journal_local_skips_when_sudo_not_permitted() {
        const SUDO: &str = r#"
printf "%s" "sudo: a password is required" 1>&2
exit 1
"#;
        with_fake_commands(&[("sudo", SUDO)], || {
            let journal = systemd_journal_local("fledx-cp").expect("journal");
            assert!(journal.contains("skipped (sudo -n not permitted)"));
        });
    }

    #[test]
    fn systemd_debug_bundle_local_redacts_sensitive_data() {
        const SYSTEMCTL: &str = r#"
case "$1" in
  is-active)
    exit 0
    ;;
  status)
    printf "%s" "FLEDX_CP_REGISTRATION_TOKEN=secret\nauthorization: Bearer token\n"
    exit 0
    ;;
esac
exit 0
"#;
        const SUDO: &str = r#"
printf "%s" "authorization: bearer secret\n"
exit 0
"#;
        with_fake_commands(&[("systemctl", SYSTEMCTL), ("sudo", SUDO)], || {
            let bundle = systemd_debug_bundle_local("fledx-cp");
            assert!(bundle.contains("systemctl is-active:"));
            assert!(bundle.contains("<redacted>"));
            assert!(!bundle.contains("secret"));
        });
    }

    #[test]
    fn validate_linux_username_accepts_valid_and_rejects_invalid() {
        validate_linux_username("fledx_agent").expect("valid");
        let err = validate_linux_username("1bad").expect_err("invalid");
        assert!(err.to_string().contains("must start"));
    }

    #[test]
    fn install_cp_local_with_tls_uses_sudo_commands() {
        const SUDO: &str = r#"
cat >/dev/null
exit 0
"#;
        const ID: &str = r#"
exit "${FAKE_ID_EXIT:-1}"
"#;
        with_fake_commands(&[("sudo", SUDO), ("id", ID)], || {
            let _id_exit = EnvVarGuard::set("FAKE_ID_EXIT", "1".into());
            let dir = tempdir().expect("tempdir");
            let bin = dir.path().join("fledx-cp");
            fs::write(&bin, "bin").expect("write bin");

            let settings = ControlPlaneInstallSettings {
                bin_dir: dir.path().join("bin"),
                config_dir: dir.path().join("etc"),
                data_dir: dir.path().join("data"),
                service_user: "svcuser".to_string(),
                sudo_interactive: false,
            };
            let tls = ControlPlaneTlsAssets {
                ca_cert_pem: "ca".to_string(),
                cert_pem: "cert".to_string(),
                key_pem: "key".to_string(),
                ca_cert_path: dir.path().join("tls/ca.pem"),
                cert_path: dir.path().join("tls/cert.pem"),
                key_path: dir.path().join("tls/key.pem"),
            };
            install_cp_local_with_tls(&bin, "ENV=1\n", "UNIT", &settings, Some(&tls))
                .expect("install");
        });
    }

    #[test]
    fn install_cp_ssh_with_tls_uses_fake_ssh() {
        const SSH: &str = r#"
cat >/dev/null
if [ -n "$FAKE_SSH_STDOUT" ]; then printf "%s" "$FAKE_SSH_STDOUT"; fi
if [ -n "$FAKE_SSH_STDERR" ]; then printf "%s" "$FAKE_SSH_STDERR" 1>&2; fi
exit "${FAKE_SSH_EXIT:-0}"
"#;
        with_fake_commands(&[("ssh", SSH)], || {
            let _stdout_guard =
                EnvVarGuard::set("FAKE_SSH_STDOUT", "/tmp/fledx-bootstrap-cp.ABCDEF\n".into());
            let _exit_guard = EnvVarGuard::set("FAKE_SSH_EXIT", "0".into());
            let ssh = SshTarget::from_user_at_host("example.com", None, 22, None);
            let dir = tempdir().expect("tempdir");
            let bin = dir.path().join("fledx-cp");
            fs::write(&bin, "bin").expect("write bin");

            let settings = ControlPlaneInstallSettings {
                bin_dir: dir.path().join("bin"),
                config_dir: dir.path().join("etc"),
                data_dir: dir.path().join("data"),
                service_user: "svcuser".to_string(),
                sudo_interactive: false,
            };
            let tls = ControlPlaneTlsAssets {
                ca_cert_pem: "ca".to_string(),
                cert_pem: "cert".to_string(),
                key_pem: "key".to_string(),
                ca_cert_path: dir.path().join("tls/ca.pem"),
                cert_path: dir.path().join("tls/cert.pem"),
                key_path: dir.path().join("tls/key.pem"),
            };

            install_cp_ssh_with_tls(&ssh, &bin, "ENV=1\n", "UNIT", &settings, Some(&tls))
                .expect("install");
        });
    }

    #[test]
    fn install_agent_ssh_with_ca_uses_fake_ssh() {
        const SSH: &str = r#"
cat >/dev/null
if [ -n "$FAKE_SSH_STDOUT" ]; then printf "%s" "$FAKE_SSH_STDOUT"; fi
if [ -n "$FAKE_SSH_STDERR" ]; then printf "%s" "$FAKE_SSH_STDERR" 1>&2; fi
exit "${FAKE_SSH_EXIT:-0}"
"#;
        with_fake_commands(&[("ssh", SSH)], || {
            let _stdout_guard = EnvVarGuard::set(
                "FAKE_SSH_STDOUT",
                "/tmp/fledx-bootstrap-agent.ABCDEF\n".into(),
            );
            let _exit_guard = EnvVarGuard::set("FAKE_SSH_EXIT", "0".into());
            let ssh = SshTarget::from_user_at_host("example.com", None, 22, None);
            let dir = tempdir().expect("tempdir");
            let bin = dir.path().join("fledx-agent");
            fs::write(&bin, "bin").expect("write bin");

            let settings = AgentInstallSettings {
                config_dir: dir.path().join("etc"),
                data_dir: dir.path().join("data"),
                service_user: "svcuser".to_string(),
                sudo_interactive: false,
                add_to_docker_socket_group: false,
            };
            let ca = AgentCaCert {
                cert_pem: "ca".to_string(),
                cert_path: dir.path().join("tls/ca.pem"),
            };

            install_agent_ssh_with_ca(
                &ssh,
                &bin,
                "ENV=1\n",
                "UNIT",
                &settings,
                Path::new("/usr/local/bin/fledx-agent"),
                Some(&ca),
            )
            .expect("install");
        });
    }

    #[test]
    fn sudo_run_cmd_reports_noninteractive_failure() {
        const SUDO: &str = r#"
printf "%s" "sudo: a password is required" 1>&2
exit 1
"#;
        with_fake_commands(&[("sudo", SUDO)], || {
            let err = sudo_run_cmd(SudoMode::root(false), "true", vec![OsString::from("arg")])
                .expect_err("should fail");
            assert!(err
                .to_string()
                .contains("sudo failed in non-interactive mode"));
        });
    }
}
