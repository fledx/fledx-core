use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::Context;
use flate2::read::GzDecoder;
use rand::TryRngCore;
use serde::Deserialize;
use sha2::Digest;
use tokio::time::{sleep, Instant};

const GITHUB_USER_AGENT: &str = "fledx-installer";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxArch {
    X86_64,
    Aarch64,
}

impl LinuxArch {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    pub fn from_uname(value: &str) -> anyhow::Result<Self> {
        let normalized = value.trim();
        match normalized {
            "x86_64" | "amd64" => Ok(Self::X86_64),
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            other => anyhow::bail!("unsupported arch '{}'; supported: x86_64, aarch64", other),
        }
    }

    pub fn detect_local() -> anyhow::Result<Self> {
        Self::from_uname(std::env::consts::ARCH)
    }
}

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub user: Option<String>,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
}

impl SshTarget {
    pub fn from_user_at_host(
        raw_host: &str,
        user_override: Option<String>,
        port: u16,
        identity_file: Option<PathBuf>,
    ) -> Self {
        let (user_from_host, host) = match raw_host.split_once('@') {
            Some((user, host)) => (Some(user.to_string()), host.to_string()),
            None => (None, raw_host.to_string()),
        };
        let user = user_override.or(user_from_host);
        Self {
            host,
            user,
            port,
            identity_file,
        }
    }

    pub fn destination(&self) -> String {
        match &self.user {
            Some(user) => format!("{user}@{}", self.host),
            None => self.host.clone(),
        }
    }

    fn ssh_base(&self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.arg("-p").arg(self.port.to_string());
        if let Some(key) = &self.identity_file {
            cmd.arg("-i").arg(key);
        }
        cmd.arg(self.destination());
        cmd
    }

    fn scp_base(&self) -> Command {
        let mut cmd = Command::new("scp");
        cmd.arg("-P").arg(self.port.to_string());
        if let Some(key) = &self.identity_file {
            cmd.arg("-i").arg(key);
        }
        cmd
    }

    pub fn run(&self, sudo: SudoMode, script: &str) -> anyhow::Result<()> {
        let mut cmd = self.ssh_base();
        if sudo.interactive {
            cmd.arg("-tt");
        }

        if sudo.required {
            cmd.arg("sudo");
            if !sudo.interactive {
                cmd.arg("-n");
            }
        }

        cmd.arg("sh").arg("-c").arg(script);
        let output = run_capture(cmd)?;
        if output.status.success() {
            return Ok(());
        }

        if sudo.required && !sudo.interactive && looks_like_noninteractive_sudo_failure(&output.stderr)
        {
            anyhow::bail!(
                "sudo failed in non-interactive mode on {}.\n\
Hint: rerun with `--sudo-interactive` or configure passwordless sudo \
(NOPASSWD) for this user.\n\
\nstdout:\n{}\n\
stderr:\n{}",
                self.destination(),
                output.stdout.trim_end(),
                output.stderr.trim_end()
            );
        }

        anyhow::bail!(
            "command failed on {} (status {}):\nstdout:\n{}\nstderr:\n{}",
            self.destination(),
            output.status,
            output.stdout.trim_end(),
            output.stderr.trim_end()
        );
    }

    pub fn run_output(&self, script: &str) -> anyhow::Result<String> {
        let mut cmd = self.ssh_base();
        cmd.arg("sh").arg("-c").arg(script);
        run_checked(cmd)
    }

    pub fn upload_file(&self, local: &Path, remote: &Path) -> anyhow::Result<()> {
        let mut cmd = self.scp_base();
        cmd.arg(local);
        cmd.arg(format!("{}:{}", self.destination(), remote.display()));
        run_checked(cmd).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SudoMode {
    pub required: bool,
    pub interactive: bool,
}

impl SudoMode {
    pub fn root(interactive: bool) -> Self {
        Self {
            required: true,
            interactive,
        }
    }
}

#[derive(Debug, Clone)]
pub enum InstallTarget {
    Local,
    Ssh(SshTarget),
}

impl InstallTarget {
    pub fn detect_arch(&self, sudo_interactive: bool) -> anyhow::Result<LinuxArch> {
        match self {
            InstallTarget::Local => LinuxArch::detect_local(),
            InstallTarget::Ssh(ssh) => {
                let uname = ssh.run_output("uname -m")?;
                let arch = LinuxArch::from_uname(&uname)
                    .with_context(|| format!("failed to parse remote arch from uname: {}", uname))?;
                ssh.run(SudoMode::root(sudo_interactive), "true")
                    .context("remote sudo check failed")?;
                Ok(arch)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
}

pub async fn fetch_release(
    client: &reqwest::Client,
    repo: &str,
    version: Option<&str>,
) -> anyhow::Result<GitHubRelease> {
    let url = release_api_url(repo, version);
    let res = client
        .get(&url)
        .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
        .send()
        .await
        .with_context(|| format!("failed to fetch GitHub release metadata: {url}"))?;
    let res = res
        .error_for_status()
        .with_context(|| format!("GitHub release request failed: {url}"))?;
    Ok(res.json().await?)
}

pub fn release_api_url(repo: &str, version: Option<&str>) -> String {
    match version.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("latest") => {
            format!("https://api.github.com/repos/{repo}/releases/latest")
        }
        Some(v) => {
            let normalized = v.trim_start_matches('v');
            format!("https://api.github.com/repos/{repo}/releases/tags/v{normalized}")
        }
        None => format!("https://api.github.com/repos/{repo}/releases/latest"),
    }
}

pub async fn download_asset(
    client: &reqwest::Client,
    repo: &str,
    release: &GitHubRelease,
    name: &str,
    dest: &Path,
) -> anyhow::Result<()> {
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| {
            let available = release
                .assets
                .iter()
                .map(|a| a.name.as_str())
                .take(12)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!(
                "release asset not found: {} (repo {} tag {}; available: {})",
                name,
                repo,
                release.tag_name,
                available
            )
        })?;

    let bytes = client
        .get(&asset.browser_download_url)
        .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
        .send()
        .await
        .with_context(|| {
            format!(
                "failed to download {}@{} asset {} from {}",
                repo, release.tag_name, name, asset.browser_download_url
            )
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "failed to download {}@{} asset {} from {}",
                repo, release.tag_name, name, asset.browser_download_url
            )
        })?
        .bytes()
        .await
        .with_context(|| {
            format!(
                "failed to read {}@{} asset {} download body from {}",
                repo, release.tag_name, name, asset.browser_download_url
            )
        })?;

    fs::write(dest, &bytes).with_context(|| {
        format!(
            "failed to write downloaded {}@{} asset {} to {}",
            repo,
            release.tag_name,
            name,
            dest.display()
        )
    })?;
    Ok(())
}

pub fn normalize_version(tag: &str) -> String {
    tag.trim().trim_start_matches('v').to_string()
}

pub fn parse_sha256_file(path: &Path) -> anyhow::Result<String> {
    let raw = fs::read_to_string(path)?;
    let hash = raw
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid sha256 file: {}", path.display()))?;
    Ok(hash.to_string())
}

pub fn verify_sha256(
    repo: &str,
    tag: &str,
    asset: &str,
    archive: &Path,
    sha_file: &Path,
) -> anyhow::Result<()> {
    let expected = parse_sha256_file(sha_file).with_context(|| {
        format!(
            "failed to parse sha256 file for {}@{} asset {}: {}",
            repo,
            tag,
            asset,
            sha_file.display()
        )
    })?;
    let actual = sha256_hex(archive).with_context(|| {
        format!(
            "failed to compute sha256 for {}@{} asset {}: {}",
            repo,
            tag,
            asset,
            archive.display()
        )
    })?;
    if expected != actual {
        anyhow::bail!(
            "checksum mismatch for {}@{} asset {} ({}): expected {}, got {}",
            repo,
            tag,
            asset,
            archive.display(),
            expected,
            actual
        );
    }
    Ok(())
}

pub fn sha256_hex(path: &Path) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn extract_single_file(
    archive_path: &Path,
    bin_name: &str,
    out_dir: &Path,
) -> anyhow::Result<PathBuf> {
    let tar_gz = fs::File::open(archive_path)?;
    let gz = GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(gz);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if file_name == bin_name {
            let dest = out_dir.join(bin_name);
            entry.unpack(&dest)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))?;
            }
            return Ok(dest);
        }
    }

    anyhow::bail!(
        "archive {} did not contain expected binary '{}'",
        archive_path.display(),
        bin_name
    )
}

pub fn generate_master_key_hex() -> String {
    let mut bytes = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut bytes).expect("os rng failure");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn generate_token_hex(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut bytes).expect("os rng failure");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn resolve_ipv4_host(value: &str) -> anyhow::Result<String> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Ok(v4.to_string()),
            IpAddr::V6(_) => {
                anyhow::bail!("IPv6 is not supported for --cp-hostname; use an IPv4 address")
            }
        };
    }

    let mut addrs = (value, 0)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve hostname '{}'", value))?;
    let ip = addrs
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| anyhow::anyhow!("hostname '{}' did not resolve to an IPv4 address", value))?;
    Ok(ip.to_string())
}

pub fn extract_host_from_url(url: &str) -> anyhow::Result<String> {
    let parsed = reqwest::Url::parse(url).context("invalid control-plane URL")?;
    parsed
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("control-plane URL must include a host"))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlPlaneHealthResponse {
    pub control_plane_version: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub tunnel_statuses: Vec<ControlPlaneTunnelStatus>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlPlaneTunnelStatus {
    pub node_id: uuid::Uuid,
    pub status: String,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_heartbeat_secs: Option<u64>,
}

pub fn health_url(base_url: &str) -> String {
    format!("{}/health", base_url.trim_end_matches('/'))
}

pub async fn fetch_control_plane_version(
    client: &reqwest::Client,
    base_url: &str,
) -> anyhow::Result<String> {
    let parsed = fetch_control_plane_health(client, base_url).await?;
    let version = parsed
        .control_plane_version
        .or(parsed.version)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "control-plane health response missing version fields: {}",
                health_url(base_url)
            )
        })?;
    Ok(normalize_version(&version))
}

pub async fn fetch_control_plane_health(
    client: &reqwest::Client,
    base_url: &str,
) -> anyhow::Result<ControlPlaneHealthResponse> {
    let url = health_url(base_url);
    let res = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to query control-plane health: {url}"))?;
    let status = res.status();
    let body = res
        .text()
        .await
        .with_context(|| format!("failed to read control-plane health response body: {url}"))?;
    if !status.is_success() {
        anyhow::bail!(
            "control-plane health request failed (status {}): {}",
            status,
            body.trim()
        );
    }

    let parsed: ControlPlaneHealthResponse = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse control-plane health response: {url}"))?;
    Ok(parsed)
}

pub async fn wait_for_node_tunnel_connected(
    client: &reqwest::Client,
    base_url: &str,
    node_id: uuid::Uuid,
    timeout: Duration,
) -> anyhow::Result<()> {
    let url = health_url(base_url);
    eprintln!(
        "waiting for agent tunnel connection: node {} via {} (timeout {}s)",
        node_id,
        url,
        timeout.as_secs()
    );
    let start = Instant::now();
    let mut last_log = Instant::now();
    let mut attempt: u32 = 0;

    loop {
        attempt = attempt.saturating_add(1);
        match fetch_control_plane_health(client, base_url).await {
            Ok(health) => match health.tunnel_statuses.iter().find(|s| s.node_id == node_id) {
                Some(status) if status.status == "connected" => return Ok(()),
                Some(status) => {
                    if last_log.elapsed() >= Duration::from_secs(5) {
                        let details = status.last_error.as_deref().unwrap_or("no error reported");
                        eprintln!(
                            "agent not connected yet (attempt {attempt}): status={} last_heartbeat_secs={:?} last_error={details}",
                            status.status,
                            status.last_heartbeat_secs
                        );
                        last_log = Instant::now();
                    }
                }
                None => {
                    if last_log.elapsed() >= Duration::from_secs(5) {
                        eprintln!(
                            "agent not connected yet (attempt {attempt}): node not present in /health tunnel_statuses"
                        );
                        last_log = Instant::now();
                    }
                }
            },
            Err(err) => {
                if last_log.elapsed() >= Duration::from_secs(5) {
                    eprintln!("agent connectivity check not ready yet (attempt {attempt}): {err}");
                    last_log = Instant::now();
                }
            }
        }

        if start.elapsed() >= timeout {
            anyhow::bail!(
                "timed out waiting for agent tunnel connection: node {node_id} via {url}"
            );
        }

        let sleep_ms = (200u64 * attempt as u64).clamp(200, 2_000);
        sleep(Duration::from_millis(sleep_ms)).await;
    }
}

pub async fn wait_for_http_ok(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    eprintln!("waiting for health check: {url} (timeout {}s)", timeout.as_secs());
    let start = Instant::now();
    let mut last_log = Instant::now();
    let mut attempt: u32 = 0;

    loop {
        attempt = attempt.saturating_add(1);
        let res = client.get(url).send().await;
        match res {
            Ok(res) if res.status().is_success() => return Ok(()),
            Ok(res) => {
                if last_log.elapsed() >= Duration::from_secs(5) {
                    eprintln!(
                        "health check not ready yet (attempt {attempt}): status {}",
                        res.status()
                    );
                    last_log = Instant::now();
                }
            }
            Err(err) => {
                if last_log.elapsed() >= Duration::from_secs(5) {
                    eprintln!("health check not ready yet (attempt {attempt}): {err}");
                    last_log = Instant::now();
                }
            }
        }

        if start.elapsed() >= timeout {
            anyhow::bail!("timed out waiting for control-plane health: {url}");
        }

        let sleep_ms = (200u64 * attempt as u64).clamp(200, 2_000);
        sleep(Duration::from_millis(sleep_ms)).await;
    }
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
    ssh.run_output(&format!("systemctl is-active {service}"))
}

pub async fn register_node(
    client: &reqwest::Client,
    base: &str,
    registration_token: &str,
    name: &str,
    arch: &str,
    os: &str,
    labels: Option<HashMap<String, String>>,
    capacity: Option<common::api::CapacityHints>,
    agent_version: &str,
) -> anyhow::Result<(uuid::Uuid, String, common::api::TunnelEndpoint)> {
    let base = base.trim_end_matches('/');
    let url = format!("{base}/api/v1/nodes/register");
    let payload = serde_json::json!({
        "name": name,
        "arch": arch,
        "os": os,
        "labels": labels,
        "capacity": capacity,
    });

    let res = client
        .post(url)
        .header("x-agent-version", agent_version)
        .bearer_auth(registration_token)
        .json(&payload)
        .send()
        .await?;
    let res = res
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("node registration failed: {}", e))?;

    let body: common::api::RegistrationResponse = res.json().await?;
    let tunnel = body
        .tunnel
        .ok_or_else(|| anyhow::anyhow!("control-plane did not return a tunnel endpoint"))?;
    Ok((body.node_id, body.node_token, tunnel))
}

pub fn parse_labels(values: &[String]) -> anyhow::Result<Option<HashMap<String, String>>> {
    if values.is_empty() {
        return Ok(None);
    }

    let mut out = HashMap::new();
    for raw in values {
        let (key, value) = parse_label(raw)?;
        if out.insert(key.clone(), value).is_some() {
            anyhow::bail!("duplicate label key: {}", key);
        }
    }
    Ok(Some(out))
}

pub fn parse_label(raw: &str) -> anyhow::Result<(String, String)> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("invalid label '{}': expected KEY=VALUE", raw))?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() {
        anyhow::bail!("invalid label '{}': key is empty", raw);
    }
    if value.is_empty() {
        anyhow::bail!("invalid label '{}': value is empty", raw);
    }
    Ok((key.to_string(), value.to_string()))
}

pub fn capacity_from_args(
    cpu_millis: Option<u32>,
    memory_bytes: Option<u64>,
) -> Option<common::api::CapacityHints> {
    if cpu_millis.is_none() && memory_bytes.is_none() {
        None
    } else {
        Some(common::api::CapacityHints {
            cpu_millis,
            memory_bytes,
        })
    }
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
    let _ = writeln!(out, "FLEDX_AGENT_CONTROL_PLANE_URL={control_plane_url}");
    let _ = writeln!(out, "FLEDX_AGENT_NODE_ID={node_id}");
    let _ = writeln!(out, "FLEDX_AGENT_NODE_TOKEN={node_token}");
    let _ = writeln!(
        out,
        "FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES={}",
        volume_dir.display()
    );
    if *allow_insecure_http {
        let _ = writeln!(out, "FLEDX_AGENT_ALLOW_INSECURE_HTTP=true");
    }

    let _ = writeln!(out, "FLEDX_AGENT_TUNNEL_ENDPOINT_HOST={tunnel_host}");
    let _ = writeln!(out, "FLEDX_AGENT_TUNNEL_ENDPOINT_PORT={}", tunnel.port);
    let _ = writeln!(out, "FLEDX_AGENT_TUNNEL_USE_TLS={}", tunnel.use_tls);
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_CONNECT_TIMEOUT_SECS={}",
        tunnel.connect_timeout_secs
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_HEARTBEAT_INTERVAL_SECS={}",
        tunnel.heartbeat_interval_secs
    );
    let _ = writeln!(
        out,
        "FLEDX_AGENT_TUNNEL_HEARTBEAT_TIMEOUT_SECS={}",
        tunnel.heartbeat_timeout_secs
    );
    let _ = writeln!(out, "FLEDX_AGENT_TUNNEL_TOKEN_HEADER={}", tunnel.token_header);
    let _ = writeln!(out, "RUST_LOG=info");
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

    format!(
        "\
[Unit]
Description=Distributed Edge Hosting Node Agent
After=network-online.target docker.service
Requires=docker.service
Wants=network-online.target

[Service]
User={service_user}
EnvironmentFile={}
ExecStart={}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
",
        env_path.display(),
        bin_path.display()
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

pub fn install_cp_local(bin: &Path, env: &str, unit: &str, settings: &ControlPlaneInstallSettings) -> anyhow::Result<()> {
    let sudo = SudoMode::root(settings.sudo_interactive);

    sudo_run(
        sudo,
        &format!(
            "useradd -r -s /bin/false {} 2>/dev/null || true",
            settings.service_user
        ),
    )?;

    sudo_run(
        sudo,
        &format!(
            "install -d -o root -g root {}",
            settings.bin_dir.display()
        ),
    )?;

    sudo_run(
        sudo,
        &format!(
            "install -d -o root -g root {}",
            settings.config_dir.display()
        ),
    )?;

    let cp_dir = settings.data_dir.join("cp");
    sudo_run(
        sudo,
        &format!(
            "install -d -o {u} -g {u} {}",
            cp_dir.display(),
            u = settings.service_user
        ),
    )?;

    sudo_run(
        sudo,
        &format!(
            "install -m 0755 {} {}/fledx-cp",
            bin.display(),
            settings.bin_dir.display()
        ),
    )?;

    let env_tmp = tempfile::NamedTempFile::new()?;
    fs::write(env_tmp.path(), env)?;
    sudo_run(
        sudo,
        &format!(
            "install -m 0600 {} {}/fledx-cp.env",
            env_tmp.path().display(),
            settings.config_dir.display()
        ),
    )?;

    let unit_tmp = tempfile::NamedTempFile::new()?;
    fs::write(unit_tmp.path(), unit)?;
    sudo_run(
        sudo,
        &format!(
            "install -m 0644 {} /etc/systemd/system/fledx-cp.service",
            unit_tmp.path().display()
        ),
    )?;

    sudo_run(sudo, "systemctl daemon-reload")?;
    sudo_run(sudo, "systemctl enable --now fledx-cp")?;
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
    let remote_dir = format!("/tmp/fledx-bootstrap-cp-{}", generate_token_hex(4));
    ssh.run(SudoMode { required: false, interactive: false }, &format!("mkdir -p {remote_dir}"))?;

    let local_dir = tempfile::tempdir()?;
    let local_bin = local_dir.path().join("fledx-cp");
    fs::copy(bin, &local_bin)?;

    let local_env = local_dir.path().join("fledx-cp.env");
    fs::write(&local_env, env)?;

    let local_unit = local_dir.path().join("fledx-cp.service");
    fs::write(&local_unit, unit)?;

    let local_script = local_dir.path().join("install.sh");
    fs::write(
        &local_script,
        render_cp_install_script(settings, &remote_dir),
    )?;

    ssh.upload_file(&local_bin, &PathBuf::from(format!("{remote_dir}/fledx-cp")))?;
    ssh.upload_file(&local_env, &PathBuf::from(format!("{remote_dir}/fledx-cp.env")))?;
    ssh.upload_file(
        &local_unit,
        &PathBuf::from(format!("{remote_dir}/fledx-cp.service")),
    )?;
    ssh.upload_file(&local_script, &PathBuf::from(format!("{remote_dir}/install.sh")))?;

    ssh.run(sudo, &format!("sh {remote_dir}/install.sh"))?;
    Ok(())
}

fn render_cp_install_script(settings: &ControlPlaneInstallSettings, remote_dir: &str) -> String {
    let env_path = settings.config_dir.join("fledx-cp.env");
    let bin_path = settings.bin_dir.join("fledx-cp");
    format!(
        "\
set -eu

useradd -r -s /bin/false {user} 2>/dev/null || true
install -d -o root -g root {bin_dir}
install -d -o root -g root {config_dir}
install -d -o {user} -g {user} {data_dir}/cp
install -m 0755 {remote_dir}/fledx-cp {bin_path}
install -m 0600 {remote_dir}/fledx-cp.env {env_path}
install -m 0644 {remote_dir}/fledx-cp.service /etc/systemd/system/fledx-cp.service
systemctl daemon-reload
systemctl enable --now fledx-cp
rm -rf {remote_dir}
",
        user = settings.service_user,
        bin_dir = settings.bin_dir.display(),
        config_dir = settings.config_dir.display(),
        data_dir = settings.data_dir.display(),
        remote_dir = remote_dir,
        bin_path = bin_path.display(),
        env_path = env_path.display(),
    )
}

pub struct AgentInstallSettings {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub service_user: String,
    pub sudo_interactive: bool,
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
    let remote_dir = format!("/tmp/fledx-bootstrap-agent-{}", generate_token_hex(4));
    ssh.run(SudoMode { required: false, interactive: false }, &format!("mkdir -p {remote_dir}"))?;

    let local_dir = tempfile::tempdir()?;
    let local_bin = local_dir.path().join("fledx-agent");
    fs::copy(bin, &local_bin)?;

    let local_env = local_dir.path().join("fledx-agent.env");
    fs::write(&local_env, env)?;

    let local_unit = local_dir.path().join("fledx-agent.service");
    fs::write(&local_unit, unit)?;

    let local_script = local_dir.path().join("install.sh");
    fs::write(
        &local_script,
        render_agent_install_script(settings, &remote_dir, bin_path),
    )?;

    ssh.upload_file(&local_bin, &PathBuf::from(format!("{remote_dir}/fledx-agent")))?;
    ssh.upload_file(
        &local_env,
        &PathBuf::from(format!("{remote_dir}/fledx-agent.env")),
    )?;
    ssh.upload_file(
        &local_unit,
        &PathBuf::from(format!("{remote_dir}/fledx-agent.service")),
    )?;
    ssh.upload_file(&local_script, &PathBuf::from(format!("{remote_dir}/install.sh")))?;

    ssh.run(sudo, &format!("sh {remote_dir}/install.sh"))?;
    Ok(())
}

fn render_agent_install_script(settings: &AgentInstallSettings, remote_dir: &str, bin_path: &Path) -> String {
    let env_path = settings.config_dir.join("fledx-agent.env");
    let bin_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
    let volumes_dir = settings.data_dir.join("volumes");

    format!(
        "\
set -eu

if [ ! -S /var/run/docker.sock ]; then
  echo \"docker socket not found at /var/run/docker.sock\" >&2
  exit 1
fi

docker_group=$(stat -c '%G' /var/run/docker.sock)
if [ -z \"$docker_group\" ]; then
  echo \"failed to determine docker socket group\" >&2
  exit 1
fi

useradd -r -s /bin/false {user} 2>/dev/null || true
usermod -a -G \"$docker_group\" {user}

install -d -o root -g root {bin_dir}
install -d -o root -g root {config_dir}
install -d -o {user} -g {user} {data_dir}/agent
install -d -o {user} -g {user} {volumes_dir}
install -m 0755 {remote_dir}/fledx-agent {bin_path}
install -m 0600 {remote_dir}/fledx-agent.env {env_path}
install -m 0644 {remote_dir}/fledx-agent.service /etc/systemd/system/fledx-agent.service
systemctl daemon-reload
systemctl enable --now fledx-agent
rm -rf {remote_dir}
",
        user = settings.service_user,
        bin_dir = bin_dir.display(),
        config_dir = settings.config_dir.display(),
        data_dir = settings.data_dir.display(),
        volumes_dir = volumes_dir.display(),
        remote_dir = remote_dir,
        bin_path = bin_path.display(),
        env_path = env_path.display(),
    )
}

fn sudo_run(sudo: SudoMode, script: &str) -> anyhow::Result<()> {
    let mut cmd = Command::new("sudo");
    if !sudo.interactive {
        cmd.arg("-n");
    }
    cmd.arg("sh").arg("-c").arg(script);
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

fn run_checked(mut cmd: Command) -> anyhow::Result<String> {
    let output = cmd.output().with_context(|| format!("failed to run {:?}", cmd))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "command failed (status {}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            stdout.trim_end(),
            stderr.trim_end()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
    let output = cmd.output().with_context(|| format!("failed to run {:?}", cmd))?;
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
    fn ssh_target_parses_user_at_host() {
        let target = SshTarget::from_user_at_host("alice@example.com", None, 22, None);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.user.as_deref(), Some("alice"));
    }

    #[test]
    fn ssh_target_user_override_wins() {
        let target =
            SshTarget::from_user_at_host("alice@example.com", Some("bob".into()), 22, None);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.user.as_deref(), Some("bob"));
    }

    #[test]
    fn linux_arch_maps_common_uname_values() {
        assert_eq!(LinuxArch::from_uname("x86_64").unwrap().as_str(), "x86_64");
        assert_eq!(LinuxArch::from_uname("amd64").unwrap().as_str(), "x86_64");
        assert_eq!(LinuxArch::from_uname("aarch64").unwrap().as_str(), "aarch64");
        assert_eq!(LinuxArch::from_uname("arm64").unwrap().as_str(), "aarch64");
    }

    #[test]
    fn linux_arch_rejects_unknown_values() {
        let err = LinuxArch::from_uname("i686").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("unsupported arch"), "{msg}");
        assert!(msg.contains("i686"), "{msg}");
        assert!(msg.contains("x86_64"), "{msg}");
        assert!(msg.contains("aarch64"), "{msg}");
    }

    #[test]
    fn release_api_url_defaults_to_latest() {
        let url = release_api_url("fledx/fledx-core", None);
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/latest"
        );
    }

    #[test]
    fn release_api_url_accepts_latest_flag() {
        let url = release_api_url("fledx/fledx-core", Some("latest"));
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/latest"
        );

        let url = release_api_url("fledx/fledx-core", Some("Latest"));
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/latest"
        );
    }

    #[test]
    fn release_api_url_strips_v_prefix() {
        let url = release_api_url("fledx/fledx-core", Some("v0.3.0"));
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/tags/v0.3.0"
        );
    }

    #[test]
    fn release_api_url_adds_v_prefix() {
        let url = release_api_url("fledx/fledx-core", Some("0.3.0"));
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/tags/v0.3.0"
        );
    }

    #[test]
    fn parse_label_rejects_missing_separator() {
        let err = parse_label("foo").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("expected KEY=VALUE"), "{msg}");
    }

    #[test]
    fn parse_label_trims_and_parses() {
        let (key, value) = parse_label("  region = eu-west  ").expect("parse");
        assert_eq!(key, "region");
        assert_eq!(value, "eu-west");
    }

    #[test]
    fn parse_labels_rejects_duplicate_keys() {
        let err = parse_labels(&["a=1".to_string(), "a=2".to_string()]).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("duplicate label key"), "{msg}");
    }

    #[test]
    fn parse_sha256_file_reads_first_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("asset.tar.gz.sha256");
        fs::write(&path, "abc123  asset.tar.gz\n").expect("write");

        let parsed = parse_sha256_file(&path).expect("parse");
        assert_eq!(parsed, "abc123");
    }

    #[test]
    fn verify_sha256_succeeds_for_matching_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("asset.tar.gz");
        fs::write(&archive, b"hello").expect("write archive");
        let actual = sha256_hex(&archive).expect("hash");

        let sha_file = dir.path().join("asset.tar.gz.sha256");
        fs::write(&sha_file, format!("{actual}  asset.tar.gz\n")).expect("write sha");

        verify_sha256(
            "fledx/fledx-core",
            "v0.3.0",
            "asset.tar.gz",
            &archive,
            &sha_file,
        )
        .expect("verify");
    }

    #[test]
    fn verify_sha256_errors_with_context_on_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("asset.tar.gz");
        fs::write(&archive, b"hello").expect("write archive");
        let actual = sha256_hex(&archive).expect("hash");

        let sha_file = dir.path().join("asset.tar.gz.sha256");
        fs::write(&sha_file, "deadbeef  asset.tar.gz\n").expect("write sha");

        let err = verify_sha256(
            "fledx/fledx-core",
            "v0.3.0",
            "asset.tar.gz",
            &archive,
            &sha_file,
        )
        .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("checksum mismatch"), "{msg}");
        assert!(msg.contains("fledx/fledx-core"), "{msg}");
        assert!(msg.contains("v0.3.0"), "{msg}");
        assert!(msg.contains("asset.tar.gz"), "{msg}");
        assert!(msg.contains("deadbeef"), "{msg}");
        assert!(msg.contains(&actual), "{msg}");
    }
}
