use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use node_agent::api;
use node_agent::build_client;
use node_agent::config;
use node_agent::heartbeat::heartbeat_loop;
use node_agent::reconcile::reconcile_loop;
use node_agent::runtime::{
    ContainerDetails, ContainerResourceUsage, ContainerRuntime, ContainerRuntimeError,
    ContainerSpec, ContainerStatus, DockerRuntime, DynContainerRuntime, ExecResult,
};
use node_agent::state::{self, ReplicaKey};
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::{watch, Mutex};
use tokio::time::sleep;
use tracing::{info, warn};
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriterExt};
use tracing_subscriber::{util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;

#[tokio::test]
async fn chaos_smoke_noop() -> anyhow::Result<()> {
    if env::var("FLEDX_CHAOS_SMOKE").ok().as_deref() != Some("1") {
        eprintln!("skipping chaos smoke no-op (set FLEDX_CHAOS_SMOKE=1 to run)");
        return Ok(());
    }

    // No side effects; presence of env flag is enough to prove wiring.

    Ok(())
}

#[derive(Clone)]
struct HeartbeatRecord {
    received_at: Instant,
    containers: Vec<api::InstanceStatus>,
}

struct TestState {
    desired: api::DesiredStateResponse,
    heartbeats: Mutex<Vec<HeartbeatRecord>>,
}

struct TestControlPlane {
    addr: SocketAddr,
    state: Arc<TestState>,
    handle: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: Option<watch::Sender<bool>>,
}

impl TestControlPlane {
    async fn start(desired: api::DesiredStateResponse) -> anyhow::Result<Self> {
        let state = Arc::new(TestState {
            desired,
            heartbeats: Mutex::new(Vec::new()),
        });

        let (listener, addr) = Self::bind_listener(None).await?;
        let router = Self::router(state.clone());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = Some(Self::spawn_server(listener, router, shutdown_rx));

        Ok(Self {
            addr,
            state,
            handle,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    fn router(state: Arc<TestState>) -> Router {
        Router::new()
            .route(
                "/api/v1/nodes/{node_id}/desired-state",
                get(desired_handler),
            )
            .route(
                "/api/v1/nodes/{node_id}/heartbeats",
                post(heartbeat_handler),
            )
            .with_state(state)
    }

    async fn bind_listener(port: Option<u16>) -> anyhow::Result<(TcpListener, SocketAddr)> {
        let mut attempts = 0;
        loop {
            let target =
                SocketAddr::from(("127.0.0.1".parse::<std::net::IpAddr>()?, port.unwrap_or(0)));

            match TcpListener::bind(target).await {
                Ok(listener) => {
                    let addr = listener.local_addr()?;
                    return Ok((listener, addr));
                }
                Err(err) if err.kind() == ErrorKind::AddrInUse && attempts < 5 => {
                    attempts += 1;
                    sleep(Duration::from_millis(50)).await;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    fn spawn_server(
        listener: TcpListener,
        router: Router,
        mut shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let server = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = shutdown.changed().await;
            });

            let _ = server.await;
        })
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn heartbeat_count(&self) -> usize {
        let guard = self.state.heartbeats.lock().await;
        guard.len()
    }

    fn socket_addr(&self) -> SocketAddr {
        self.addr
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }

        Ok(())
    }

    async fn restart(&mut self) -> anyhow::Result<()> {
        self.stop().await?;

        let (listener, addr) = Self::bind_listener(Some(self.addr.port())).await?;
        self.addr = addr;
        let router = Self::router(self.state.clone());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        self.handle = Some(Self::spawn_server(listener, router, shutdown_rx));

        Ok(())
    }

    async fn wait_for_running(
        &self,
        start_idx: usize,
        deployment_id: Uuid,
        generation: i64,
        timeout: Duration,
    ) -> anyhow::Result<HeartbeatRecord> {
        let deadline = Instant::now() + timeout;

        loop {
            {
                let guard = self.state.heartbeats.lock().await;
                if let Some(record) = guard.iter().skip(start_idx).find(|record| {
                    record.containers.iter().any(|container| {
                        container.deployment_id == deployment_id
                            && container.state == api::InstanceState::Running
                            && container.generation == generation
                    })
                }) {
                    return Ok(record.clone());
                }
            }

            if Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for running heartbeat");
            }

            sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for TestControlPlane {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

struct PartitionProxy {
    addr: SocketAddr,
    blocked: Arc<AtomicBool>,
    attempts: Arc<Mutex<Vec<Instant>>>,
    active: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: Option<watch::Sender<bool>>,
}

impl PartitionProxy {
    async fn start(target: SocketAddr) -> anyhow::Result<Self> {
        let blocked = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(Mutex::new(Vec::new()));

        let (listener, addr) = TestControlPlane::bind_listener(None).await?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = Some(Self::spawn(
            listener,
            target,
            blocked.clone(),
            attempts.clone(),
            active.clone(),
            shutdown_rx,
        ));

        Ok(Self {
            addr,
            blocked,
            attempts,
            active,
            handle,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn block(&self) {
        self.blocked.store(true, Ordering::SeqCst);
        self.abort_active().await;
    }

    fn unblock(&self) {
        self.blocked.store(false, Ordering::SeqCst);
    }

    async fn blocked_attempts(&self) -> Vec<Instant> {
        let guard = self.attempts.lock().await;
        guard.clone()
    }

    async fn abort_active(&self) {
        let mut guard = self.active.lock().await;
        for handle in guard.drain(..) {
            handle.abort();
        }
    }

    fn spawn(
        listener: TcpListener,
        target: SocketAddr,
        blocked: Arc<AtomicBool>,
        attempts: Arc<Mutex<Vec<Instant>>>,
        active: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok((mut inbound, _)) => {
                                let blocked = blocked.clone();
                                let attempts = attempts.clone();

                                let active_handles = active.clone();
                                let task = tokio::spawn(async move {
                                    if blocked.load(Ordering::SeqCst) {
                                        {
                                            let mut guard = attempts.lock().await;
                                            let now = Instant::now();
                                            let debounce = Duration::from_millis(100);
                                            let should_record = guard
                                                .last()
                                                .map(|prev| now.duration_since(*prev) >= debounce)
                                                .unwrap_or(true);
                                            if should_record {
                                                guard.push(now);
                                            }
                                        }

                                        let _ = inbound.shutdown().await;
                                        return;
                                    }

                                    match TcpStream::connect(target).await {
                                        Ok(mut outbound) => {
                                            if let Err(err) = copy_bidirectional(&mut inbound, &mut outbound).await {
                                                warn!(?err, "proxy stream forwarding failed");
                                            }
                                        }
                                        Err(err) => {
                                            warn!(?err, "proxy could not reach target");
                                            let _ = inbound.shutdown().await;
                                        }
                                    }
                                });

                                {
                                    let mut guard = active_handles.lock().await;
                                    guard.push(task);
                                }
                            }
                            Err(err) => {
                                warn!(?err, "proxy failed to accept connection");
                                break;
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        break;
                    }
                }
            }
        })
    }
}

impl Drop for PartitionProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        if let Ok(mut guard) = self.active.try_lock() {
            for handle in guard.drain(..) {
                handle.abort();
            }
        }

        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

async fn desired_handler(
    State(state): State<Arc<TestState>>,
    Path(_): Path<Uuid>,
) -> Json<api::DesiredStateResponse> {
    Json(state.desired.clone())
}

async fn heartbeat_handler(
    State(state): State<Arc<TestState>>,
    Path(_): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> StatusCode {
    let containers_value = body
        .get("containers")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let containers: Vec<api::InstanceStatus> =
        serde_json::from_value(containers_value).unwrap_or_default();

    let record = HeartbeatRecord {
        received_at: Instant::now(),
        containers,
    };

    let mut guard = state.heartbeats.lock().await;
    guard.push(record);

    StatusCode::OK
}

fn artifact_dir() -> Option<PathBuf> {
    env::var("CHAOS_ARTIFACT_DIR").ok().map(PathBuf::from)
}

fn init_tracing() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let writer: BoxMakeWriter = if let Some(dir) = artifact_dir() {
            let path = dir.join("control-plane-chaos.log");
            match File::create(&path) {
                Ok(file) => BoxMakeWriter::new(std::io::stdout.and(file)),
                Err(err) => {
                    eprintln!("failed to open {:?} for chaos logs: {err}", path);
                    BoxMakeWriter::new(std::io::stdout)
                }
            }
        } else {
            BoxMakeWriter::new(std::io::stdout)
        };

        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(writer)
            .finish()
            .try_init();
    });
}

fn write_json_artifact(name: &str, value: serde_json::Value) {
    if let Some(dir) = artifact_dir() {
        if let Err(err) = fs::create_dir_all(&dir) {
            eprintln!("could not create CHAOS_ARTIFACT_DIR {:?}: {err}", dir);
            return;
        }

        let path = dir.join(name);
        match serde_json::to_vec_pretty(&value) {
            Ok(bytes) => {
                if let Err(err) = fs::write(&path, bytes) {
                    eprintln!("failed to write chaos artifact {:?}: {err}", path);
                }
            }
            Err(err) => eprintln!("failed to serialize chaos artifact {}: {err}", name),
        }
    }
}

fn test_base_config() -> config::AppConfig {
    config::AppConfig {
        control_plane_url: "http://localhost:8080".into(),
        node_id: Uuid::nil(),
        node_token: "t".into(),
        secrets_dir: "/var/run/secrets".into(),
        secrets_prefix: "FLEDX_SECRET_".into(),
        heartbeat_interval_secs: 1,
        heartbeat_timeout_secs: 1,
        heartbeat_max_retries: 2,
        heartbeat_backoff_ms: 10,
        heartbeat_max_metrics: 10,
        reconcile_interval_secs: 1,
        docker_reconnect_backoff_ms: 10,
        docker_reconnect_backoff_max_ms: 20,
        restart_backoff_ms: 10,
        restart_backoff_max_ms: 20,
        restart_failure_limit: 3,
        resource_sample_interval_secs: 1,
        resource_sample_window: 5,
        resource_sample_max_concurrency: 2,
        resource_sample_backoff_ms: 10,
        resource_sample_backoff_max_ms: 20,
        allow_insecure_http: true,
        tls_insecure_skip_verify: false,
        ca_cert_path: None,
        service_identity_dir: "/var/lib/fledx/service-identities".into(),
        metrics_host: "127.0.0.1".into(),
        metrics_port: 0,
        arch: env::consts::ARCH.into(),
        os: env::consts::OS.into(),
        tunnel: config::TunnelConfig::default(),
        tunnel_routes: Vec::new(),
        public_host: None,
        public_ip: None,
        gateway: config::GatewayConfig::default(),
        allowed_volume_prefixes: vec!["/tmp".into()],
        volume_data_dir: "/var/lib/fledx".into(),
        labels: HashMap::new(),
        capacity_cpu_millis: None,
        capacity_memory_bytes: None,
        force_empty_labels: false,
        force_empty_capacity: false,
        cleanup_on_shutdown: false,
    }
}

#[derive(Clone, Default)]
struct InMemoryRuntime {
    containers: Arc<Mutex<HashMap<String, ContainerDetails>>>,
}

#[async_trait]
impl ContainerRuntime for InMemoryRuntime {
    async fn pull_image(&self, _image: &str) -> Result<(), ContainerRuntimeError> {
        Ok(())
    }

    async fn start_container(&self, spec: ContainerSpec) -> Result<String, ContainerRuntimeError> {
        let id = spec
            .name
            .clone()
            .unwrap_or_else(|| format!("mock-{}", Uuid::new_v4()));
        let labels = if spec.labels.is_empty() {
            None
        } else {
            Some(spec.labels.into_iter().collect())
        };
        let details = ContainerDetails {
            id: id.clone(),
            name: Some(id.clone()),
            status: ContainerStatus::Running,
            labels,
        };
        let mut guard = self.containers.lock().await;
        guard.insert(id.clone(), details);
        Ok(id)
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerDetails, ContainerRuntimeError> {
        let guard = self.containers.lock().await;
        guard
            .get(id)
            .cloned()
            .ok_or(ContainerRuntimeError::NotFound { id: id.to_string() })
    }

    async fn stop_container(&self, id: &str) -> Result<(), ContainerRuntimeError> {
        let mut guard = self.containers.lock().await;
        match guard.get_mut(id) {
            Some(container) => {
                container.status = ContainerStatus::Exited { exit_code: Some(0) };
                Ok(())
            }
            None => Err(ContainerRuntimeError::NotFound { id: id.to_string() }),
        }
    }

    async fn remove_container(&self, id: &str) -> Result<(), ContainerRuntimeError> {
        let mut guard = self.containers.lock().await;
        if guard.remove(id).is_some() {
            Ok(())
        } else {
            Err(ContainerRuntimeError::NotFound { id: id.to_string() })
        }
    }

    async fn list_managed_containers(
        &self,
    ) -> Result<Vec<ContainerDetails>, ContainerRuntimeError> {
        let guard = self.containers.lock().await;
        Ok(guard.values().cloned().collect())
    }

    async fn container_stats(
        &self,
        id: &str,
    ) -> Result<ContainerResourceUsage, ContainerRuntimeError> {
        Err(ContainerRuntimeError::NotFound { id: id.to_string() })
    }

    async fn exec_command(
        &self,
        _container_id: &str,
        _command: &[String],
    ) -> Result<ExecResult, ContainerRuntimeError> {
        Ok(ExecResult {
            exit_code: 0,
            output: String::new(),
        })
    }
}

fn build_agent_state(
    runtime: DynContainerRuntime,
    control_plane_url: String,
    node_id: Uuid,
) -> state::SharedState {
    let mut cfg = test_base_config();
    cfg.control_plane_url = control_plane_url;
    cfg.node_id = node_id;
    cfg.node_token = "test-token".into();
    cfg.heartbeat_interval_secs = 1;
    cfg.heartbeat_timeout_secs = 2;
    cfg.reconcile_interval_secs = 1;
    cfg.metrics_port = 0;

    let client = build_client(&cfg).expect("client");
    let factory: state::RuntimeFactory = {
        let runtime = runtime.clone();
        Arc::new(move || Ok(runtime.clone()))
    };

    state::new_state(cfg, client, factory, Some(runtime))
}

fn start_agent(
    state: state::SharedState,
) -> (
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let hb_state = state.clone();
    let rc_state = state.clone();
    let heartbeat = tokio::spawn({
        let hb_shutdown = shutdown_rx.clone();
        async move {
            let _ = heartbeat_loop(hb_state, hb_shutdown).await;
        }
    });
    let reconcile = tokio::spawn(async move {
        let _ = reconcile_loop(rc_state, shutdown_rx).await;
    });

    (shutdown_tx, heartbeat, reconcile)
}

struct DockerEnvGuard {
    prev_host: Option<String>,
    prev_tls_verify: Option<String>,
    prev_cert_path: Option<String>,
    prev_certdir: Option<String>,
}

impl DockerEnvGuard {
    fn apply(endpoint: &str) -> Self {
        let prev_host = env::var("DOCKER_HOST").ok();
        let prev_tls_verify = env::var("DOCKER_TLS_VERIFY").ok();
        let prev_cert_path = env::var("DOCKER_CERT_PATH").ok();
        let prev_certdir = env::var("DOCKER_TLS_CERTDIR").ok();

        env::set_var("DOCKER_HOST", endpoint);
        env::set_var("DOCKER_TLS_VERIFY", "0");
        env::remove_var("DOCKER_CERT_PATH");
        env::remove_var("DOCKER_TLS_CERTDIR");

        Self {
            prev_host,
            prev_tls_verify,
            prev_cert_path,
            prev_certdir,
        }
    }
}

impl Drop for DockerEnvGuard {
    fn drop(&mut self) {
        match &self.prev_host {
            Some(value) => env::set_var("DOCKER_HOST", value),
            None => env::remove_var("DOCKER_HOST"),
        }

        match &self.prev_tls_verify {
            Some(value) => env::set_var("DOCKER_TLS_VERIFY", value),
            None => env::remove_var("DOCKER_TLS_VERIFY"),
        }

        match &self.prev_cert_path {
            Some(value) => env::set_var("DOCKER_CERT_PATH", value),
            None => env::remove_var("DOCKER_CERT_PATH"),
        }

        match &self.prev_certdir {
            Some(value) => env::set_var("DOCKER_TLS_CERTDIR", value),
            None => env::remove_var("DOCKER_TLS_CERTDIR"),
        }
    }
}

struct DindCleanup {
    name: String,
}

impl Drop for DindCleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .arg("rm")
            .arg("-f")
            .arg(&self.name)
            .env_remove("DOCKER_HOST")
            .env_remove("DOCKER_TLS_VERIFY")
            .env_remove("DOCKER_CERT_PATH")
            .env_remove("DOCKER_TLS_CERTDIR")
            .output();
    }
}

async fn run_host_docker(args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("docker")
        .args(args)
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH")
        .env_remove("DOCKER_TLS_CERTDIR")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .context("run docker command")?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }

    anyhow::bail!(
        "docker command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn can_run_privileged_docker() -> bool {
    // Quick probe to detect environments where --privileged is blocked,
    // so we can skip the slow dind startup early.
    run_host_docker(&["run", "--rm", "--privileged", "busybox:1.36.1", "true"])
        .await
        .is_ok()
}

async fn free_local_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

async fn start_dind(name: &str, host_port: u16) -> anyhow::Result<()> {
    let _ = run_host_docker(&["rm", "-f", name]).await;

    run_host_docker(&["pull", "docker:24-dind"])
        .await
        .context("pull dind image")?;

    let port_flag = format!("{}:2375", host_port);
    run_host_docker(&[
        "run",
        "-d",
        "--privileged",
        "--name",
        name,
        "-p",
        &port_flag,
        "-e",
        "DOCKER_TLS_CERTDIR=",
        "-e",
        "DOCKER_DRIVER=vfs",
        "docker:24-dind",
        "--host=tcp://0.0.0.0:2375",
        "--host=unix:///var/run/docker.sock",
    ])
    .await
    .context("start dind container")?;

    Ok(())
}

async fn wait_for_dind_ready(port: u16, timeout: Duration) -> anyhow::Result<Instant> {
    let deadline = Instant::now() + timeout;
    let host = format!("tcp://127.0.0.1:{port}");

    loop {
        let attempt = Command::new("docker")
            .args(["-H", &host, "info"])
            .env("DOCKER_TLS_VERIFY", "0")
            .env_remove("DOCKER_CERT_PATH")
            .env_remove("DOCKER_TLS_CERTDIR")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        if matches!(attempt, Ok(status) if status.success()) {
            return Ok(Instant::now());
        }

        if Instant::now() >= deadline {
            anyhow::bail!("dind did not become ready in time");
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn restart_dind(name: &str) -> anyhow::Result<()> {
    run_host_docker(&["restart", name])
        .await
        .context("restart dind container")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_restart_recovers_containers_and_status() -> anyhow::Result<()> {
    if env::var("FLEDX_RUN_CHAOS").ok().as_deref() != Some("1") {
        eprintln!("skipping chaos restart test (set FLEDX_RUN_CHAOS=1 to run)");
        return Ok(());
    }

    let _ = tracing_subscriber::fmt::try_init();

    let deployment_id = Uuid::new_v4();
    let desired = api::DeploymentDesired {
        deployment_id,
        name: "chaos-demo".into(),
        replica_number: 0,
        image: "demo:1".into(),
        replicas: 1,
        command: None,
        env: None,
        secret_env: None,
        secret_files: None,
        ports: None,
        requires_public_ip: false,
        tunnel_only: false,
        placement: None,
        volumes: None,
        health: None,
        desired_state: api::DesiredState::Running,
        replica_generation: Some(1),
        generation: 1,
    };

    let desired_response = api::DesiredStateResponse {
        control_plane_version: "1.2.3".into(),
        min_supported_agent_version: "0.0.1".into(),
        max_supported_agent_version: Some("9.9.9".into()),
        upgrade_url: None,
        tunnel: None,
        deployments: vec![desired.clone()],
    };

    let control_plane = TestControlPlane::start(desired_response).await?;
    let runtime: DynContainerRuntime = Arc::new(InMemoryRuntime::default());
    let node_id = Uuid::new_v4();

    let state = build_agent_state(runtime.clone(), control_plane.url(), node_id);
    let (shutdown_tx, hb_handle, rc_handle) = start_agent(state.clone());

    let first = control_plane
        .wait_for_running(
            0,
            deployment_id,
            desired.replica_generation.unwrap_or(desired.generation),
            Duration::from_secs(8),
        )
        .await?;
    info!(
        elapsed_ms = first.received_at.elapsed().as_millis(),
        "agent reported running before crash"
    );

    shutdown_tx.send(true).ok();
    let _ = hb_handle.await;
    let _ = rc_handle.await;

    let pre_restart_heartbeats = control_plane.heartbeat_count().await;
    let restart_started = Instant::now();

    let restarted_state = build_agent_state(runtime.clone(), control_plane.url(), node_id);
    let (shutdown_tx2, hb_handle2, rc_handle2) = start_agent(restarted_state.clone());

    let recovered = control_plane
        .wait_for_running(
            pre_restart_heartbeats,
            deployment_id,
            desired.replica_generation.unwrap_or(desired.generation),
            Duration::from_secs(8),
        )
        .await?;
    let recovery_time = recovered.received_at.duration_since(restart_started);
    info!(?recovery_time, "agent recovered after restart");

    let threshold = Duration::from_secs(5);
    assert!(
        recovery_time <= threshold,
        "recovery took {:?}, over threshold {:?}",
        recovery_time,
        threshold
    );

    {
        let guard = restarted_state.managed_read().await;
        let key = ReplicaKey::new(deployment_id, 0);
        let entry = guard
            .managed
            .get(&key)
            .expect("managed entry after restart");
        assert_eq!(entry.state, api::InstanceState::Running);
        assert_eq!(entry.generation, 1);
    }

    let containers = runtime.list_managed_containers().await?;
    assert_eq!(containers.len(), 1, "container should remain running");
    assert!(matches!(containers[0].status, ContainerStatus::Running));

    shutdown_tx2.send(true).ok();
    let _ = hb_handle2.await;
    let _ = rc_handle2.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_control_plane_downtime_recovers_agent() -> anyhow::Result<()> {
    if env::var("FLEDX_RUN_CHAOS").ok().as_deref() != Some("1") {
        eprintln!("skipping control-plane chaos test (set FLEDX_RUN_CHAOS=1 to run)");
        return Ok(());
    }

    init_tracing();

    let deployment_id = Uuid::new_v4();
    let desired = api::DeploymentDesired {
        deployment_id,
        name: "chaos-control-plane".into(),
        replica_number: 0,
        image: "demo:1".into(),
        replicas: 1,
        command: None,
        env: None,
        secret_env: None,
        secret_files: None,
        ports: None,
        requires_public_ip: false,
        tunnel_only: false,
        placement: None,
        volumes: None,
        health: None,
        desired_state: api::DesiredState::Running,
        replica_generation: Some(1),
        generation: 1,
    };

    let desired_response = api::DesiredStateResponse {
        control_plane_version: "1.2.3".into(),
        min_supported_agent_version: "0.0.1".into(),
        max_supported_agent_version: Some("9.9.9".into()),
        upgrade_url: None,
        tunnel: None,
        deployments: vec![desired.clone()],
    };

    let mut control_plane = TestControlPlane::start(desired_response).await?;
    let runtime: DynContainerRuntime = Arc::new(InMemoryRuntime::default());
    let node_id = Uuid::new_v4();

    let state = build_agent_state(runtime.clone(), control_plane.url(), node_id);
    let (shutdown_tx, hb_handle, rc_handle) = start_agent(state.clone());

    let replica_generation = desired.replica_generation.unwrap_or(desired.generation);
    let running = control_plane
        .wait_for_running(
            0,
            deployment_id,
            replica_generation,
            Duration::from_secs(12),
        )
        .await?;
    info!(
        elapsed_ms = running.received_at.elapsed().as_millis(),
        "agent reported running before control-plane outage"
    );

    let pre_outage_heartbeats = control_plane.heartbeat_count().await;
    let containers_before = runtime.list_managed_containers().await?;
    assert_eq!(containers_before.len(), 1, "one container before outage");
    assert!(matches!(
        containers_before[0].status,
        ContainerStatus::Running
    ));

    let downtime_started = Instant::now();
    control_plane.stop().await?;
    info!(
        heartbeats_recorded = pre_outage_heartbeats,
        "control-plane taken offline for chaos test"
    );

    let post_stop_heartbeats = control_plane.heartbeat_count().await;
    sleep(Duration::from_secs(3)).await;

    let during_outage = control_plane.heartbeat_count().await;
    assert_eq!(
        during_outage, post_stop_heartbeats,
        "heartbeats should pause while control-plane is down"
    );

    let containers_during = runtime.list_managed_containers().await?;
    assert_eq!(
        containers_during.len(),
        1,
        "container should stay alive during control-plane downtime"
    );
    assert!(matches!(
        containers_during[0].status,
        ContainerStatus::Running
    ));

    control_plane.restart().await?;
    let control_plane_back_at = Instant::now();
    info!("control-plane listener restarted");

    let recovered = control_plane
        .wait_for_running(
            pre_outage_heartbeats,
            deployment_id,
            replica_generation,
            Duration::from_secs(20),
        )
        .await?;

    let recovery_time = recovered.received_at.duration_since(control_plane_back_at);
    let total_gap = recovered.received_at.duration_since(downtime_started);
    let recovery_threshold = Duration::from_secs(10);

    write_json_artifact(
        "control-plane-downtime.json",
        serde_json::json!({
            "test": "chaos_control_plane_downtime_recovers_agent",
            "recovery_ms": recovery_time.as_millis(),
            "total_outage_ms": total_gap.as_millis(),
            "heartbeats_before": pre_outage_heartbeats,
            "heartbeats_after": control_plane.heartbeat_count().await,
        }),
    );

    info!(
        recovery_ms = recovery_time.as_millis(),
        total_outage_ms = total_gap.as_millis(),
        "control-plane outage recovery timings"
    );

    assert!(
        recovery_time <= recovery_threshold,
        "recovery took {:?}, over threshold {:?}",
        recovery_time,
        recovery_threshold
    );

    {
        let guard = state.managed_read().await;
        let key = ReplicaKey::new(deployment_id, 0);
        let entry = guard
            .managed
            .get(&key)
            .expect("managed entry after control-plane return");
        assert_eq!(entry.state, api::InstanceState::Running);
        assert_eq!(entry.generation, replica_generation);
    }

    let containers_after = runtime.list_managed_containers().await?;
    assert_eq!(containers_after.len(), 1, "container should remain running");
    assert!(matches!(
        containers_after[0].status,
        ContainerStatus::Running
    ));

    shutdown_tx.send(true).ok();
    let _ = hb_handle.await;
    let _ = rc_handle.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_network_partition_recovers_control_plane_link() -> anyhow::Result<()> {
    if env::var("FLEDX_RUN_CHAOS").ok().as_deref() != Some("1") {
        eprintln!("skipping network-partition chaos test (set FLEDX_RUN_CHAOS=1 to run)");
        return Ok(());
    }

    init_tracing();

    let deployment_id = Uuid::new_v4();
    let desired = api::DeploymentDesired {
        deployment_id,
        name: "chaos-network-partition".into(),
        replica_number: 0,
        image: "demo:1".into(),
        replicas: 1,
        command: None,
        env: None,
        secret_env: None,
        secret_files: None,
        ports: None,
        requires_public_ip: false,
        tunnel_only: false,
        placement: None,
        volumes: None,
        health: None,
        desired_state: api::DesiredState::Running,
        replica_generation: Some(1),
        generation: 1,
    };

    let desired_response = api::DesiredStateResponse {
        control_plane_version: "1.2.3".into(),
        min_supported_agent_version: "0.0.1".into(),
        max_supported_agent_version: Some("9.9.9".into()),
        upgrade_url: None,
        tunnel: None,
        deployments: vec![desired.clone()],
    };

    let control_plane = TestControlPlane::start(desired_response).await?;
    let proxy = PartitionProxy::start(control_plane.socket_addr()).await?;
    let runtime: DynContainerRuntime = Arc::new(InMemoryRuntime::default());
    let node_id = Uuid::new_v4();

    let mut cfg = test_base_config();
    cfg.control_plane_url = proxy.url();
    cfg.node_id = node_id;
    cfg.node_token = "chaos-token".into();
    cfg.heartbeat_interval_secs = 1;
    cfg.heartbeat_timeout_secs = 1;
    cfg.heartbeat_max_retries = 3;
    cfg.heartbeat_backoff_ms = 250;
    cfg.reconcile_interval_secs = 1;
    cfg.metrics_port = 0;

    let client = build_client(&cfg).context("build client")?;
    let factory: state::RuntimeFactory = {
        let runtime = runtime.clone();
        Arc::new(move || Ok(runtime.clone()))
    };
    let state = state::new_state(cfg, client, factory, Some(runtime.clone()));
    let (shutdown_tx, hb_handle, rc_handle) = start_agent(state.clone());

    let replica_generation = desired.replica_generation.unwrap_or(desired.generation);
    let first = control_plane
        .wait_for_running(
            0,
            deployment_id,
            replica_generation,
            Duration::from_secs(20),
        )
        .await?;
    info!(
        elapsed_ms = first.received_at.elapsed().as_millis(),
        "agent reported running before network partition"
    );

    let pre_partition_heartbeats = control_plane.heartbeat_count().await;
    let containers_before = runtime.list_managed_containers().await?;
    assert_eq!(containers_before.len(), 1, "one container before partition");
    assert!(matches!(
        containers_before[0].status,
        ContainerStatus::Running
    ));

    proxy.block().await;
    let partition_started = Instant::now();
    sleep(Duration::from_secs(3)).await;

    let during_partition_heartbeats = control_plane.heartbeat_count().await;
    assert_eq!(
        during_partition_heartbeats, pre_partition_heartbeats,
        "heartbeats should stall while partitioned"
    );

    let blocked_attempts = proxy.blocked_attempts().await;
    assert!(
        !blocked_attempts.is_empty(),
        "agent should attempt heartbeats during partition"
    );

    let partition_secs = partition_started.elapsed().as_secs_f64().max(0.1);
    let attempt_rate = blocked_attempts.len() as f64 / partition_secs;
    let min_gap = blocked_attempts
        .windows(2)
        .map(|pair| pair[1].duration_since(pair[0]))
        .min()
        .unwrap_or(Duration::from_millis(0));

    info!(
        attempts = blocked_attempts.len(),
        attempt_rate_per_sec = attempt_rate,
        min_gap_ms = min_gap.as_millis(),
        "blocked heartbeat attempts captured during partition"
    );

    assert!(
        attempt_rate <= 15.0,
        "heartbeat retries should back off (rate {:.2} too high)",
        attempt_rate
    );
    assert!(
        min_gap >= Duration::from_millis(80) || blocked_attempts.len() == 1,
        "heartbeat retries should not hot-loop (min gap {:?})",
        min_gap
    );

    proxy.unblock();
    let partition_cleared_at = Instant::now();

    let recovered = control_plane
        .wait_for_running(
            during_partition_heartbeats,
            deployment_id,
            replica_generation,
            Duration::from_secs(20),
        )
        .await?;

    let recovery_time = recovered.received_at.duration_since(partition_cleared_at);
    let partition_duration = recovered.received_at.duration_since(partition_started);
    let recovery_threshold = Duration::from_secs(8);

    write_json_artifact(
        "control-plane-partition.json",
        serde_json::json!({
            "test": "chaos_network_partition_recovers_control_plane_link",
            "blocked_attempts": blocked_attempts.len(),
            "attempt_rate_per_sec": attempt_rate,
            "min_gap_ms": min_gap.as_millis(),
            "partition_ms": partition_duration.as_millis(),
            "recovery_ms": recovery_time.as_millis(),
        }),
    );

    info!(
        recovery_ms = recovery_time.as_millis(),
        total_gap_ms = partition_duration.as_millis(),
        "network partition recovery timings"
    );

    assert!(
        recovery_time <= recovery_threshold,
        "recovery took {:?}, over threshold {:?}",
        recovery_time,
        recovery_threshold
    );

    {
        let guard = state.managed_read().await;
        let key = ReplicaKey::new(deployment_id, 0);
        let entry = guard
            .managed
            .get(&key)
            .expect("managed entry after partition");
        assert_eq!(entry.state, api::InstanceState::Running);
        assert_eq!(entry.generation, replica_generation);
        assert_eq!(guard.managed.len(), 1, "no duplicate deployments managed");
    }

    let containers_after = runtime.list_managed_containers().await?;
    assert_eq!(
        containers_after.len(),
        1,
        "no duplicate containers after partition"
    );
    assert!(matches!(
        containers_after[0].status,
        ContainerStatus::Running
    ));

    shutdown_tx.send(true).ok();
    let _ = hb_handle.await;
    let _ = rc_handle.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_docker_restart_recovers_runtime() -> anyhow::Result<()> {
    if env::var("FLEDX_RUN_CHAOS").ok().as_deref() != Some("1") {
        eprintln!("skipping docker chaos test (set FLEDX_RUN_CHAOS=1 to run)");
        return Ok(());
    }

    let _ = tracing_subscriber::fmt::try_init();

    if let Err(err) = run_host_docker(&["info"]).await {
        eprintln!("skipping docker chaos test (docker unavailable): {err}");
        return Ok(());
    }

    if !can_run_privileged_docker().await {
        eprintln!("skipping docker chaos test (privileged containers blocked)");
        return Ok(());
    }

    let dind_port = free_local_port().await?;
    let dind_name = format!("fledx-chaos-dind-{}", Uuid::new_v4());
    let _cleanup = DindCleanup {
        name: dind_name.clone(),
    };

    let dind_launch = Instant::now();
    start_dind(&dind_name, dind_port).await?;
    let ready_at = match wait_for_dind_ready(dind_port, Duration::from_secs(55)).await {
        Ok(ts) => ts,
        Err(err) => {
            eprintln!("skipping docker chaos test (dind not ready): {err}");
            return Ok(());
        }
    };
    info!(
        port = dind_port,
        since_launch_ms = ready_at.duration_since(dind_launch).as_millis(),
        "dind is ready for chaos"
    );

    let _docker_env = DockerEnvGuard::apply(&format!("tcp://127.0.0.1:{dind_port}"));
    let runtime_factory: state::RuntimeFactory = Arc::new(|| {
        let rt = DockerRuntime::connect()?;
        Ok(Arc::new(rt) as DynContainerRuntime)
    });

    let deployment_id = Uuid::new_v4();
    let deployment_label = deployment_id.to_string();
    let desired = api::DeploymentDesired {
        deployment_id,
        name: "chaos-docker".into(),
        replica_number: 0,
        image: "nginx:1.25-alpine".into(),
        replicas: 1,
        command: None,
        env: None,
        secret_env: None,
        secret_files: None,
        ports: None,
        requires_public_ip: false,
        tunnel_only: false,
        placement: None,
        volumes: None,
        health: None,
        desired_state: api::DesiredState::Running,
        replica_generation: Some(1),
        generation: 1,
    };

    let desired_response = api::DesiredStateResponse {
        control_plane_version: "1.2.3".into(),
        min_supported_agent_version: "0.0.1".into(),
        max_supported_agent_version: Some("9.9.9".into()),
        upgrade_url: None,
        tunnel: None,
        deployments: vec![desired.clone()],
    };

    let control_plane = TestControlPlane::start(desired_response).await?;
    let node_id = Uuid::new_v4();

    let mut cfg = test_base_config();
    cfg.control_plane_url = control_plane.url();
    cfg.node_id = node_id;
    cfg.node_token = "chaos-token".into();
    cfg.heartbeat_interval_secs = 1;
    cfg.heartbeat_timeout_secs = 2;
    cfg.reconcile_interval_secs = 1;
    cfg.docker_reconnect_backoff_ms = 100;
    cfg.docker_reconnect_backoff_max_ms = 1_000;
    cfg.restart_backoff_ms = 100;
    cfg.restart_backoff_max_ms = 1_000;
    cfg.metrics_port = 0;

    let client = build_client(&cfg).context("build client")?;
    let state = state::new_state(cfg, client, runtime_factory, None);
    let (shutdown_tx, hb_handle, rc_handle) = start_agent(state.clone());

    let replica_generation = desired.replica_generation.unwrap_or(desired.generation);
    let generation_label = replica_generation.to_string();
    let first = control_plane
        .wait_for_running(
            0,
            deployment_id,
            replica_generation,
            Duration::from_secs(60),
        )
        .await?;
    info!(
        elapsed_ms = first.received_at.elapsed().as_millis(),
        "agent reported running before docker restart"
    );

    let pre_restart_heartbeats = control_plane.heartbeat_count().await;
    let restart_started = Instant::now();
    restart_dind(&dind_name).await?;
    let docker_back_at = match wait_for_dind_ready(dind_port, Duration::from_secs(55)).await {
        Ok(ts) => ts,
        Err(err) => {
            eprintln!("skipping docker chaos test after restart (dind not ready): {err}");
            return Ok(());
        }
    };

    let daemon_gap = docker_back_at.duration_since(restart_started);
    info!(
        downtime_ms = daemon_gap.as_millis(),
        "docker daemon restarted"
    );

    let recovered = control_plane
        .wait_for_running(
            pre_restart_heartbeats,
            deployment_id,
            replica_generation,
            Duration::from_secs(60),
        )
        .await?;

    let reconcile_gap = recovered.received_at.duration_since(docker_back_at);
    let total_gap = recovered.received_at.duration_since(restart_started);

    let daemon_threshold = Duration::from_secs(30);
    let reconcile_threshold = Duration::from_secs(20);

    info!(
        daemon_ms = daemon_gap.as_millis(),
        reconcile_ms = reconcile_gap.as_millis(),
        total_ms = total_gap.as_millis(),
        "docker restart recovery timings"
    );

    assert!(
        daemon_gap <= daemon_threshold,
        "docker restart took {:?}, over threshold {:?}",
        daemon_gap,
        daemon_threshold
    );

    assert!(
        reconcile_gap <= reconcile_threshold,
        "reconcile after docker restart took {:?}, over threshold {:?}",
        reconcile_gap,
        reconcile_threshold
    );

    let runtime = DockerRuntime::connect().context("connect to runtime after restart")?;
    let containers = runtime.list_managed_containers().await?;
    let managed: Vec<_> = containers
        .into_iter()
        .filter(|details| {
            let Some(labels) = details.labels.as_ref() else {
                return false;
            };

            labels
                .get("fledx.deployment_id")
                .map(|id| id == &deployment_label)
                .unwrap_or(false)
                && labels
                    .get("fledx.generation")
                    .map(|gen| gen == &generation_label)
                    .unwrap_or(false)
        })
        .collect();

    assert_eq!(managed.len(), 1, "expected exactly one managed container");
    let container = &managed[0];
    assert!(
        matches!(container.status, ContainerStatus::Running),
        "managed container not running: {:?}",
        container.status
    );

    shutdown_tx.send(true).ok();
    let _ = hb_handle.await;
    let _ = rc_handle.await;

    Ok(())
}
