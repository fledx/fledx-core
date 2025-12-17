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
        if start.elapsed() >= timeout {
            anyhow::bail!("timed out waiting for systemd service {service} to become active");
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
        if start.elapsed() >= timeout {
            anyhow::bail!(
                "timed out waiting for systemd service {service} to become active on {}",
                ssh.destination()
            );
        }
        sleep(Duration::from_millis(500)).await;
    }
}

fn systemd_state_local(service: &str) -> anyhow::Result<String> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("is-active").arg(service);
    let output = run_capture(cmd)?;
    Ok(output.stdout.trim().to_string())
}

fn systemd_state_ssh(ssh: &SshTarget, service: &str) -> anyhow::Result<String> {
    ssh.run_output(&format!("systemctl is-active -- {}", sh_quote(service)))
}

pub fn render_agent_env(input: &AgentEnvInputs) -> String {
    let AgentEnvInputs {
        control_plane_url,
        node_id,
        node_token,
        allow_insecure_http,
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
    pub volume_dir: PathBuf,
    pub tunnel_host: String,
    pub tunnel: common::api::TunnelEndpoint,
}

pub fn render_agent_unit(input: &AgentUnitInputs) -> String {
    let AgentUnitInputs {
        service_user,
        env_path,
        bin_path,
    } = input;

    let env_path_escaped = systemd_escape_environment_file_path(env_path);
    let bin_path_escaped = systemd_quote_unit_path(bin_path);

    format!(
        "\
[Unit]
Description=Distributed Edge Hosting Node Agent
After=network-online.target docker.service
Requires=docker.service
Wants=network-online.target

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
        bin_path = bin_path_escaped
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

pub fn install_cp_local(
    bin: &Path,
    env: &str,
    unit: &str,
    settings: &ControlPlaneInstallSettings,
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
    let sudo = SudoMode::root(settings.sudo_interactive);
    validate_linux_username(&settings.service_user)?;
    let remote_dir = ssh.run_output("umask 077; mktemp -d -t fledx-bootstrap-cp.XXXXXXXXXX")?;

    let local_dir = tempfile::tempdir()?;
    let local_bin = local_dir.path().join("fledx-cp");
    fs::copy(bin, &local_bin)?;

    let local_env = local_dir.path().join("fledx-cp.env");
    write_file_with_mode(&local_env, env, 0o600)?;

    let local_unit = local_dir.path().join("fledx-cp.service");
    write_file_with_mode(&local_unit, unit, 0o644)?;

    // IMPORTANT: Do not execute multi-line scripts via `ssh host sh -c <script>`.
    // Some SSH configurations inject banners/motd text, and multi-line payloads
    // can be split by the remote shell in surprising ways (leading to parts of
    // the install running without sudo).
    //
    // Upload the script as a file and execute it via `sh <path>` under sudo.
    let local_script = local_dir.path().join("install-cp.sh");
    let script = render_cp_install_script(settings, &remote_dir);
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
    ssh.run(sudo, &format!("sh {}", sh_quote_path(&remote_script)))?;
    Ok(())
}

fn render_cp_install_script(settings: &ControlPlaneInstallSettings, remote_dir: &str) -> String {
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
install -m 0755 \"$REMOTE_DIR/fledx-cp\" \"$BIN_PATH\"
install -m 0600 \"$REMOTE_DIR/fledx-cp.env\" \"$ENV_PATH\"
install -m 0644 \"$REMOTE_DIR/fledx-cp.service\" /etc/systemd/system/fledx-cp.service
systemctl daemon-reload
systemctl enable --now fledx-cp
",
        remote_dir = remote_dir_q,
        service_user = service_user_q,
        bin_dir = bin_dir_q,
        config_dir = config_dir_q,
        cp_dir = cp_dir_q,
        bin_path = bin_path_q,
        env_path = env_path_q,
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

pub fn install_agent_ssh(
    ssh: &SshTarget,
    bin: &Path,
    env: &str,
    unit: &str,
    settings: &AgentInstallSettings,
    bin_path: &Path,
) -> anyhow::Result<()> {
    let sudo = SudoMode::root(settings.sudo_interactive);
    validate_linux_username(&settings.service_user)?;
    let remote_dir = ssh.run_output("umask 077; mktemp -d -t fledx-bootstrap-agent.XXXXXXXXXX")?;

    let local_dir = tempfile::tempdir()?;
    let local_bin = local_dir.path().join("fledx-agent");
    fs::copy(bin, &local_bin)?;

    let local_env = local_dir.path().join("fledx-agent.env");
    write_file_with_mode(&local_env, env, 0o600)?;

    let local_unit = local_dir.path().join("fledx-agent.service");
    write_file_with_mode(&local_unit, unit, 0o644)?;

    let local_script = local_dir.path().join("install-agent.sh");
    let script = render_agent_install_script(settings, &remote_dir, bin_path);
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

    let remote_script = PathBuf::from(format!("{remote_dir}/install-agent.sh"));
    ssh.upload_file(&local_script, &remote_script)?;
    ssh.run(sudo, &format!("sh {}", sh_quote_path(&remote_script)))?;
    Ok(())
}

fn render_agent_install_script(
    settings: &AgentInstallSettings,
    remote_dir: &str,
    bin_path: &Path,
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
install -m 0755 \"$REMOTE_DIR/fledx-agent\" \"$BIN_PATH\"
install -m 0600 \"$REMOTE_DIR/fledx-agent.env\" \"$ENV_PATH\"
install -m 0644 \"$REMOTE_DIR/fledx-agent.service\" /etc/systemd/system/fledx-agent.service
systemctl daemon-reload
systemctl enable --now fledx-agent
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
    use super::*;

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
    fn systemd_quote_env_value_escapes_quotes_and_backslashes() {
        assert_eq!(systemd_quote_env_value("a\"b\\c"), "\"a\\\"b\\\\c\"");
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
    fn render_agent_env_quotes_values_for_systemd_env_file() {
        let env = render_agent_env(&AgentEnvInputs {
            control_plane_url: "http://localhost:8080".to_string(),
            node_id: uuid::Uuid::nil(),
            node_token: "deadbeef".to_string(),
            allow_insecure_http: true,
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
    }
}
