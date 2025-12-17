use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    api, build_client, config,
    cp_client::CpResponse,
    runtime::{self, ContainerDetails, ContainerRuntime, ContainerRuntimeError, ContainerSpec},
    services::{
        heartbeat::{HeartbeatClient, HeartbeatPayload},
        reconcile::DesiredStateClient,
    },
    state::{self, RuntimeFactory, SharedState},
    version,
};

pub(crate) fn base_config() -> config::AppConfig {
    config::AppConfig {
        control_plane_url: "http://localhost:49421".into(),
        node_id: Uuid::new_v4(),
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
        arch: std::env::consts::ARCH.into(),
        os: std::env::consts::OS.into(),
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

#[tokio::test]
async fn build_client_sets_agent_headers() {
    let cfg = base_config();
    let client = build_client(&cfg).expect("client");
    let server = httpmock::MockServer::start_async().await;

    let mock = server
        .mock_async(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/check")
                .header(crate::AGENT_VERSION_HEADER, version::VERSION)
                .header(crate::AGENT_BUILD_HEADER, version::GIT_SHA);
            then.status(200);
        })
        .await;

    let res = client
        .get(server.url("/check"))
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(res.status(), reqwest::StatusCode::OK);
    mock.assert_async().await;
}

#[derive(Clone)]
pub(crate) enum DesiredReply {
    Ok(api::DesiredStateResponse),
    Err(String),
}

#[derive(Clone)]
pub(crate) struct FakeCpClient {
    request_id: String,
    desired: Arc<StdMutex<DesiredReply>>,
    heartbeat_result: Arc<StdMutex<Result<(), String>>>,
    sent_heartbeats: Arc<StdMutex<Vec<HeartbeatPayload>>>,
}

impl Default for FakeCpClient {
    fn default() -> Self {
        Self {
            request_id: "test-request".into(),
            desired: Arc::new(StdMutex::new(DesiredReply::Ok(api::DesiredStateResponse {
                control_plane_version: "test".into(),
                min_supported_agent_version: "0.0.0".into(),
                max_supported_agent_version: None,
                upgrade_url: None,
                tunnel: None,
                deployments: Vec::new(),
            }))),
            heartbeat_result: Arc::new(StdMutex::new(Ok(()))),
            sent_heartbeats: Arc::new(StdMutex::new(Vec::new())),
        }
    }
}

impl FakeCpClient {
    pub(crate) fn with_desired(desired: api::DesiredStateResponse) -> Self {
        let mut client = Self::default();
        client.set_desired(desired);
        client
    }

    pub(crate) fn with_request_id(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            ..Self::default()
        }
    }

    pub(crate) fn set_desired(&mut self, desired: api::DesiredStateResponse) {
        let mut guard = self.desired.lock().expect("lock desired");
        *guard = DesiredReply::Ok(desired);
    }

    pub(crate) fn set_desired_error(&self, message: impl Into<String>) {
        let mut guard = self.desired.lock().expect("lock desired");
        *guard = DesiredReply::Err(message.into());
    }

    pub(crate) fn set_heartbeat_error(&self, message: impl Into<String>) {
        let mut guard = self.heartbeat_result.lock().expect("lock heartbeat");
        *guard = Err(message.into());
    }

    pub(crate) fn sent_heartbeats(&self) -> Vec<HeartbeatPayload> {
        self.sent_heartbeats
            .lock()
            .expect("lock heartbeats")
            .clone()
    }
}

#[async_trait]
impl DesiredStateClient for FakeCpClient {
    async fn fetch_desired_state(
        &self,
        _state: &SharedState,
    ) -> anyhow::Result<CpResponse<api::DesiredStateResponse>> {
        let desired = self.desired.lock().expect("lock desired").clone();
        match desired {
            DesiredReply::Ok(body) => Ok(CpResponse {
                body,
                request_id: self.request_id.clone(),
            }),
            DesiredReply::Err(message) => Err(anyhow::anyhow!(message)),
        }
    }
}

#[async_trait]
impl HeartbeatClient for FakeCpClient {
    async fn send_heartbeat<P: serde::Serialize + Sync>(
        &self,
        _state: &SharedState,
        payload: &P,
    ) -> anyhow::Result<CpResponse<()>> {
        if let Ok(payload) =
            serde_json::to_value(payload).and_then(serde_json::from_value::<HeartbeatPayload>)
        {
            self.sent_heartbeats
                .lock()
                .expect("lock heartbeats")
                .push(payload);
        }

        let result = self
            .heartbeat_result
            .lock()
            .expect("lock heartbeat")
            .clone();
        match result {
            Ok(()) => Ok(CpResponse {
                body: (),
                request_id: self.request_id.clone(),
            }),
            Err(message) => Err(anyhow::anyhow!(message)),
        }
    }

    fn request_id(&self) -> &str {
        &self.request_id
    }
}

pub(crate) fn state_with_runtime_and_config(
    runtime: runtime::DynContainerRuntime,
    cfg: config::AppConfig,
) -> SharedState {
    let client = build_client(&cfg).expect("client");
    let runtime_factory: RuntimeFactory = {
        let runtime = runtime.clone();
        Arc::new(move || Ok(runtime.clone()))
    };

    state::new_state(cfg, client, runtime_factory, Some(runtime))
}

#[derive(Default, Clone)]
pub(crate) struct MockRuntime {
    pub(crate) containers: Arc<StdMutex<HashMap<String, ContainerDetails>>>,
    start_actions: Arc<StdMutex<VecDeque<StartAction>>>,
    start_calls: Arc<AtomicUsize>,
    exec_actions: Arc<StdMutex<VecDeque<ExecAction>>>,
    exec_calls: Arc<AtomicUsize>,
    stats_actions: Arc<StdMutex<StatsActionQueue>>,
    stats_calls: Arc<AtomicUsize>,
    last_started: Arc<StdMutex<Vec<ContainerSpec>>>,
}

type StatsActionQueue =
    HashMap<String, VecDeque<Result<runtime::ContainerResourceUsage, ContainerRuntimeError>>>;

pub(crate) enum StartAction {
    Ok(runtime::ContainerStatus),
    Err(ContainerRuntimeError),
}

pub(crate) enum ExecAction {
    Ok { exit_code: i64, output: String },
    Err(ContainerRuntimeError),
}

impl MockRuntime {
    pub(crate) fn with_containers(containers: Vec<ContainerDetails>) -> Self {
        Self {
            containers: Arc::new(StdMutex::new(
                containers.into_iter().map(|c| (c.id.clone(), c)).collect(),
            )),
            ..Default::default()
        }
    }

    pub(crate) fn with_start_actions(actions: Vec<StartAction>) -> Self {
        Self {
            start_actions: Arc::new(StdMutex::new(actions.into())),
            ..Default::default()
        }
    }

    pub(crate) fn with_exec_actions(actions: Vec<ExecAction>) -> Self {
        Self {
            exec_actions: Arc::new(StdMutex::new(actions.into())),
            ..Default::default()
        }
    }

    pub(crate) fn insert_container(
        &self,
        spec: ContainerSpec,
        status: runtime::ContainerStatus,
    ) -> String {
        let name = spec
            .name
            .clone()
            .unwrap_or_else(|| format!("mock-{}", Uuid::new_v4()));
        let labels = if spec.labels.is_empty() {
            None
        } else {
            Some(spec.labels.into_iter().collect())
        };

        let details = ContainerDetails {
            id: name.clone(),
            name: Some(name.clone()),
            status,
            labels,
        };
        let mut guard = self.containers.lock().expect("lock");
        guard.insert(name.clone(), details);
        name
    }

    pub(crate) fn start_calls(&self) -> usize {
        self.start_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn exec_calls(&self) -> usize {
        self.exec_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn stats_calls(&self) -> usize {
        self.stats_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn last_started(&self) -> Vec<ContainerSpec> {
        self.last_started.lock().expect("lock").clone()
    }

    pub(crate) fn set_stats(
        &self,
        container_id: &str,
        samples: Vec<Result<runtime::ContainerResourceUsage, ContainerRuntimeError>>,
    ) {
        let mut guard = self.stats_actions.lock().expect("lock");
        guard.insert(container_id.to_string(), samples.into());
    }
}

#[async_trait]
impl ContainerRuntime for MockRuntime {
    async fn pull_image(&self, _image: &str) -> Result<(), ContainerRuntimeError> {
        Ok(())
    }

    async fn start_container(&self, spec: ContainerSpec) -> Result<String, ContainerRuntimeError> {
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        self.last_started.lock().expect("lock").push(spec.clone());
        if let Some(action) = self.start_actions.lock().expect("lock").pop_front() {
            return match action {
                StartAction::Err(err) => Err(err),
                StartAction::Ok(status) => Ok(self.insert_container(spec, status)),
            };
        }

        Ok(self.insert_container(spec, runtime::ContainerStatus::Running))
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerDetails, ContainerRuntimeError> {
        let guard = self.containers.lock().expect("lock");
        guard
            .get(id)
            .cloned()
            .ok_or(ContainerRuntimeError::NotFound { id: id.to_string() })
    }

    async fn stop_container(&self, id: &str) -> Result<(), ContainerRuntimeError> {
        let mut guard = self.containers.lock().expect("lock");
        match guard.get_mut(id) {
            Some(container) => {
                container.status = runtime::ContainerStatus::Exited { exit_code: Some(0) };
                Ok(())
            }
            None => Err(ContainerRuntimeError::NotFound { id: id.to_string() }),
        }
    }

    async fn remove_container(&self, id: &str) -> Result<(), ContainerRuntimeError> {
        let mut guard = self.containers.lock().expect("lock");
        if guard.remove(id).is_some() {
            Ok(())
        } else {
            Err(ContainerRuntimeError::NotFound { id: id.to_string() })
        }
    }

    async fn list_managed_containers(
        &self,
    ) -> Result<Vec<ContainerDetails>, ContainerRuntimeError> {
        let guard = self.containers.lock().expect("lock");
        Ok(guard.values().cloned().collect())
    }

    async fn container_stats(
        &self,
        id: &str,
    ) -> Result<runtime::ContainerResourceUsage, ContainerRuntimeError> {
        self.stats_calls.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.stats_actions.lock().expect("lock");
        if let Some(queue) = guard.get_mut(id) {
            if let Some(result) = queue.pop_front() {
                return result;
            }
        }

        Err(ContainerRuntimeError::NotFound { id: id.to_string() })
    }

    async fn exec_command(
        &self,
        _container_id: &str,
        _command: &[String],
    ) -> Result<runtime::ExecResult, ContainerRuntimeError> {
        self.exec_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(action) = self.exec_actions.lock().expect("lock").pop_front() {
            match action {
                ExecAction::Ok { exit_code, output } => {
                    Ok(runtime::ExecResult { exit_code, output })
                }
                ExecAction::Err(err) => Err(err),
            }
        } else {
            Ok(runtime::ExecResult {
                exit_code: 0,
                output: String::new(),
            })
        }
    }
}

pub(crate) fn make_test_state(
    base_url: String,
    node_id: Uuid,
    timeout_secs: u64,
    max_retries: u32,
    backoff_ms: u64,
) -> SharedState {
    let mut cfg = base_config();
    cfg.control_plane_url = base_url;
    cfg.node_id = node_id;
    cfg.heartbeat_timeout_secs = timeout_secs;
    cfg.heartbeat_max_retries = max_retries;
    cfg.heartbeat_backoff_ms = backoff_ms;
    cfg.metrics_port = 0;

    let client = build_client(&cfg).expect("client");
    let runtime_factory: RuntimeFactory = Arc::new(|| {
        Err(ContainerRuntimeError::Connection {
            context: "factory",
            source: anyhow::anyhow!("test-only connection failure"),
        })
    });

    SharedState::new(cfg, client, runtime_factory, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::ContainerRuntimeError;

    #[tokio::test]
    async fn mock_runtime_exec_actions_report_errors_and_counts() {
        let runtime = MockRuntime::with_exec_actions(vec![ExecAction::Err(
            ContainerRuntimeError::NotFound {
                id: "missing".into(),
            },
        )]);

        let result = runtime.exec_command("container-id", &[]).await;
        assert!(matches!(
            result,
            Err(ContainerRuntimeError::NotFound { id }) if id == "missing"
        ));
        assert_eq!(runtime.exec_calls(), 1);
    }
}
