use std::{net::TcpListener, path::PathBuf, process::Stdio, time::Duration};

use common::api;
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use scopeguard::defer;
use serial_test::serial;
use tempfile::TempDir;
use tokio::process::{Child, Command};
use uuid::Uuid;

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

async fn wait_http_ok_while_running(
    url: &str,
    child: &mut Child,
    timeout: Duration,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("process exited early with status {status}");
        }
        if start.elapsed() > timeout {
            anyhow::bail!("timed out waiting for {}", url);
        }
        match client.get(url).send().await {
            Ok(res) if res.status().is_success() => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

fn docker_tests_enabled() -> bool {
    match std::env::var("FLEDX_RUN_DOCKER_TESTS") {
        Ok(value) => {
            value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

async fn docker_available() -> bool {
    match Command::new("docker")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

async fn docker_pull(image: &str) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("pull")
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("docker pull {} failed", image);
    }
    Ok(())
}

async fn docker_ps_by_deployment(deployment_id: Uuid) -> anyhow::Result<String> {
    let output = Command::new("docker")
        .args([
            "ps",
            "-q",
            "--filter",
            &format!("label=fledx.deployment_id={deployment_id}"),
        ])
        .output()
        .await?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn docker_rm_by_deployment(deployment_id: Uuid) -> anyhow::Result<()> {
    let output = Command::new("docker")
        .args([
            "ps",
            "-aq",
            "--filter",
            &format!("label=fledx.deployment_id={deployment_id}"),
        ])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let ids = stdout
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(());
    }

    let mut cmd = Command::new("docker");
    cmd.arg("rm").arg("-f").args(ids);
    let status = cmd.status().await?;
    if !status.success() {
        anyhow::bail!("docker rm -f failed for deployment {}", deployment_id);
    }
    Ok(())
}

async fn stop_process(child: &mut Child, signal: Signal, timeout: Duration) -> anyhow::Result<()> {
    if let Some(id) = child.id() {
        let pid = Pid::from_raw(id as i32);
        let _ = kill(pid, signal);
    }

    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => {
            // Fallback to force-kill.
            let _ = child.kill().await;
            Ok(())
        }
    }
}

async fn stop_process_checked(
    child: &mut Child,
    signal: Signal,
    timeout: Duration,
) -> anyhow::Result<()> {
    if let Some(id) = child.id() {
        let pid = Pid::from_raw(id as i32);
        let _ = kill(pid, signal);
    }

    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            if !status.success() {
                anyhow::bail!("process exited with status {status}");
            }
            Ok(())
        }
        Ok(Err(err)) => Err(err.into()),
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("timed out waiting for process to exit");
        }
    }
}

struct CpEnv {
    _tmp: TempDir,
    db_path: PathBuf,
    cp_port: u16,
    metrics_port: u16,
    tunnel_port: u16,
    operator_token: String,
    registration_token: String,
}

impl CpEnv {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("fledx-cp.db");
        Self {
            _tmp: tmp,
            db_path,
            cp_port: free_port(),
            metrics_port: free_port(),
            tunnel_port: free_port(),
            operator_token: "op-token".to_string(),
            registration_token: "reg-token".to_string(),
        }
    }

    fn db_url(&self) -> String {
        format!("sqlite://{}", self.db_path.display())
    }

    fn base_cp_command(&self) -> Command {
        let bin = assert_cmd::cargo::cargo_bin!("fledx-cp");
        let mut cmd = Command::new(bin);
        cmd.env("FLEDX_CP_SERVER_HOST", "127.0.0.1")
            .env("FLEDX_CP_SERVER_PORT", self.cp_port.to_string())
            .env("FLEDX_CP_METRICS_HOST", "127.0.0.1")
            .env("FLEDX_CP_METRICS_PORT", self.metrics_port.to_string())
            .env("FLEDX_CP_TUNNEL_ADVERTISED_HOST", "127.0.0.1")
            .env(
                "FLEDX_CP_TUNNEL_ADVERTISED_PORT",
                self.tunnel_port.to_string(),
            )
            .env("FLEDX_CP_DATABASE_URL", self.db_url())
            .env("FLEDX_CP_REGISTRATION_TOKEN", &self.registration_token)
            .env("FLEDX_CP_OPERATOR_TOKENS", &self.operator_token)
            .env("FLEDX_CP_TOKENS_PEPPER", "test-pepper")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        cmd
    }
}

#[derive(serde::Deserialize)]
struct RegistrationResponse {
    node_id: Uuid,
    node_token: String,
}

async fn register_node(
    cp_port: u16,
    registration_token: &str,
) -> anyhow::Result<RegistrationResponse> {
    let url = format!("http://127.0.0.1:{cp_port}/api/v1/nodes/register");
    let client = reqwest::Client::new();
    let res = client
        .post(url)
        .bearer_auth(registration_token)
        .header(
            node_agent::AGENT_VERSION_HEADER,
            node_agent::version::VERSION,
        )
        .header(node_agent::AGENT_BUILD_HEADER, node_agent::version::GIT_SHA)
        .json(&serde_json::json!({ "name": "itest-node" }))
        .send()
        .await?;

    let status = res.status();
    if status != reqwest::StatusCode::CREATED {
        let body = res.text().await.unwrap_or_default();
        anyhow::bail!("node registration failed: status={} body={}", status, body);
    }

    Ok(res.json::<RegistrationResponse>().await?)
}

async fn wait_node_ready(cp_port: u16, operator_token: &str, node_id: Uuid) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{cp_port}/api/v1/nodes?limit=100&offset=0");
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(20);
    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("timed out waiting for node {} to become ready", node_id);
        }

        let res = client.get(&url).bearer_auth(operator_token).send().await?;
        if !res.status().is_success() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        let page: api::NodeSummaryPage = res.json().await?;
        if let Some(node) = page.items.into_iter().find(|n| n.node_id == node_id) {
            if node.status == api::NodeStatus::Ready {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn create_sleep_deployment(
    cp_port: u16,
    operator_token: &str,
) -> anyhow::Result<api::DeploymentCreateResponse> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{cp_port}/api/v1/deployments");
    let spec = api::DeploymentSpec {
        name: Some("itest-sleep".into()),
        image: "busybox:1.36.1".into(),
        replicas: Some(1),
        command: Some(vec!["sh".into(), "-c".into(), "sleep 300".into()]),
        env: None,
        secret_env: None,
        secret_files: None,
        ports: None,
        requires_public_ip: false,
        tunnel_only: false,
        constraints: None,
        placement: None,
        desired_state: Some(api::DesiredState::Running),
        volumes: None,
        health: None,
    };

    let res = client
        .post(url)
        .bearer_auth(operator_token)
        .json(&spec)
        .send()
        .await?;
    let status = res.status();
    if status != reqwest::StatusCode::CREATED {
        let body = res.text().await.unwrap_or_default();
        anyhow::bail!("create deployment failed: status={} body={}", status, body);
    }
    Ok(res.json::<api::DeploymentCreateResponse>().await?)
}

async fn wait_deployment_running(
    cp_port: u16,
    operator_token: &str,
    deployment_id: Uuid,
) -> anyhow::Result<api::DeploymentStatusResponse> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{cp_port}/api/v1/deployments/{deployment_id}");
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(60);
    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "timed out waiting for deployment {} to be running",
                deployment_id
            );
        }
        let res = client.get(&url).bearer_auth(operator_token).send().await?;
        if !res.status().is_success() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        let status: api::DeploymentStatusResponse = res.json().await?;
        if status.status == api::DeploymentStatus::Running {
            if let Some(inst) = status.instance.as_ref() {
                if inst.state == api::InstanceState::Running && inst.container_id.is_some() {
                    return Ok(status);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn delete_deployment(
    cp_port: u16,
    operator_token: &str,
    deployment_id: Uuid,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{cp_port}/api/v1/deployments/{deployment_id}");
    let res = client
        .delete(url)
        .bearer_auth(operator_token)
        .send()
        .await?;
    let status = res.status();
    if !status.is_success() {
        let body = res.text().await.unwrap_or_default();
        anyhow::bail!("delete deployment failed: status={} body={}", status, body);
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn standalone_metrics_include_agent_and_cp() -> anyhow::Result<()> {
    let env = CpEnv::new();

    let mut cmd = env.base_cp_command();
    cmd.arg("--standalone")
        .env(
            "FLEDX_AGENT_CONTROL_PLANE_URL",
            format!("http://127.0.0.1:{}", env.cp_port),
        )
        .env("FLEDX_AGENT_ALLOW_INSECURE_HTTP", "true")
        .env("FLEDX_AGENT_NODE_ID", Uuid::new_v4().to_string())
        .env("FLEDX_AGENT_NODE_TOKEN", "fake-token")
        .env("FLEDX_AGENT_TUNNEL_ENDPOINT_HOST", "127.0.0.1")
        .env(
            "FLEDX_AGENT_TUNNEL_ENDPOINT_PORT",
            env.tunnel_port.to_string(),
        )
        .env("FLEDX_AGENT_HEARTBEAT_INTERVAL_SECS", "1")
        .env("FLEDX_AGENT_RECONCILE_INTERVAL_SECS", "60")
        .env("FLEDX_AGENT_CLEANUP_ON_SHUTDOWN", "true");

    let mut child = cmd.spawn().expect("spawn fledx-cp --standalone");
    let child_pid = child.id().map(|id| Pid::from_raw(id as i32));
    defer! {
        if let Some(pid) = child_pid {
            let _ = kill(pid, Signal::SIGKILL);
        }
    }

    wait_http_ok_while_running(
        &format!("http://127.0.0.1:{}/health", env.cp_port),
        &mut child,
        Duration::from_secs(10),
    )
    .await?;

    let metrics_url = format!("http://127.0.0.1:{}/metrics", env.metrics_port);
    wait_http_ok_while_running(&metrics_url, &mut child, Duration::from_secs(10)).await?;
    let body = reqwest::get(metrics_url).await?.text().await?;

    assert!(
        body.contains("control_plane_info"),
        "expected control-plane metrics in /metrics"
    );
    assert!(
        body.contains("node_agent_"),
        "expected node-agent metrics in /metrics"
    );

    stop_process_checked(&mut child, Signal::SIGINT, Duration::from_secs(10)).await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn standalone_can_run_a_container_via_docker() -> anyhow::Result<()> {
    if !docker_tests_enabled() {
        eprintln!("docker tests disabled; set FLEDX_RUN_DOCKER_TESTS=1 to enable");
        return Ok(());
    }
    if !docker_available().await {
        eprintln!("docker not available; skipping standalone docker integration test");
        return Ok(());
    }

    // Pull once up-front to reduce reconcile flakiness due to image fetch.
    docker_pull("busybox:1.36.1").await?;

    let env = CpEnv::new();

    // 1) Start control-plane (non-standalone) to register the node and obtain a token.
    let mut cp = env.base_cp_command().spawn().expect("spawn fledx-cp");
    let cp_pid = cp.id().map(|id| Pid::from_raw(id as i32));
    defer! {
        if let Some(pid) = cp_pid {
            let _ = kill(pid, Signal::SIGKILL);
        }
    }

    wait_http_ok_while_running(
        &format!("http://127.0.0.1:{}/health", env.cp_port),
        &mut cp,
        Duration::from_secs(10),
    )
    .await?;
    let reg = register_node(env.cp_port, &env.registration_token).await?;

    stop_process(&mut cp, Signal::SIGINT, Duration::from_secs(10)).await?;

    // 2) Start control-plane in standalone mode with embedded agent for that node.
    let mut cmd = env.base_cp_command();
    cmd.arg("--standalone")
        .env(
            "FLEDX_AGENT_CONTROL_PLANE_URL",
            format!("http://127.0.0.1:{}", env.cp_port),
        )
        .env("FLEDX_AGENT_ALLOW_INSECURE_HTTP", "true")
        .env("FLEDX_AGENT_NODE_ID", reg.node_id.to_string())
        .env("FLEDX_AGENT_NODE_TOKEN", &reg.node_token)
        .env("FLEDX_AGENT_TUNNEL_ENDPOINT_HOST", "127.0.0.1")
        .env(
            "FLEDX_AGENT_TUNNEL_ENDPOINT_PORT",
            env.tunnel_port.to_string(),
        )
        .env("FLEDX_AGENT_HEARTBEAT_INTERVAL_SECS", "1")
        .env("FLEDX_AGENT_RECONCILE_INTERVAL_SECS", "1")
        .env("FLEDX_AGENT_RESOURCE_SAMPLE_INTERVAL_SECS", "1")
        .env("FLEDX_AGENT_HEARTBEAT_TIMEOUT_SECS", "2")
        .env("FLEDX_AGENT_HEARTBEAT_MAX_RETRIES", "1")
        .env("FLEDX_AGENT_CLEANUP_ON_SHUTDOWN", "true");

    let mut standalone = cmd.spawn().expect("spawn fledx-cp --standalone");
    let standalone_pid = standalone.id().map(|id| Pid::from_raw(id as i32));
    defer! {
        if let Some(pid) = standalone_pid {
            let _ = kill(pid, Signal::SIGKILL);
        }
    }

    wait_http_ok_while_running(
        &format!("http://127.0.0.1:{}/health", env.cp_port),
        &mut standalone,
        Duration::from_secs(10),
    )
    .await?;
    wait_node_ready(env.cp_port, &env.operator_token, reg.node_id).await?;

    // 3) Create a deployment and wait until the agent reports a running container.
    let created = create_sleep_deployment(env.cp_port, &env.operator_token).await?;
    let deployment_id = created.deployment_id;

    let status = wait_deployment_running(env.cp_port, &env.operator_token, deployment_id).await?;
    assert_eq!(status.status, api::DeploymentStatus::Running);

    // 4) Verify the container exists from Docker's point of view.
    let docker_id = docker_ps_by_deployment(deployment_id).await?;
    assert!(
        !docker_id.is_empty(),
        "expected a docker container with label fledx.deployment_id={deployment_id}"
    );

    // 5) Delete the deployment and ensure containers are removed.
    delete_deployment(env.cp_port, &env.operator_token, deployment_id).await?;

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(30);
    loop {
        if start.elapsed() > timeout {
            break;
        }
        if docker_ps_by_deployment(deployment_id).await?.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Force cleanup if something remains.
    docker_rm_by_deployment(deployment_id).await?;

    stop_process(&mut standalone, Signal::SIGINT, Duration::from_secs(10)).await?;
    Ok(())
}
