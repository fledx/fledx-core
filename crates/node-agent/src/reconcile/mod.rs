use crate::{
    api::{self, InstanceState},
    runtime, services,
    state::{self, ReplicaKey, SharedState},
};
use tokio::sync::watch;

pub(crate) mod adoption;
pub(crate) mod apply;
pub(crate) mod backoff;
pub(crate) mod cleanup;
pub(crate) mod config_apply;
pub(crate) mod desired_fetch;
pub(crate) mod spec;

pub async fn reconcile_loop(
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let interval_secs = {
        let guard = state.lock().await;
        guard.cfg.reconcile_interval_secs
    };
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                let client = crate::cp_client::ControlPlaneClient::new(&state).await;
                let _ = services::reconcile::reconcile_tick(&state, &client).await;
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    Applied,
    FetchError,
    RuntimeUnavailable,
}

impl ReconcileOutcome {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            ReconcileOutcome::Applied => "success",
            ReconcileOutcome::FetchError => "fetch_error",
            ReconcileOutcome::RuntimeUnavailable => "runtime_unavailable",
        }
    }
}

pub(crate) fn replica_key(desired: &api::DeploymentDesired) -> ReplicaKey {
    ReplicaKey::new(desired.deployment_id, desired.replica_number)
}

pub(crate) fn desired_replica_generation(desired: &api::DeploymentDesired) -> i64 {
    desired.replica_generation.unwrap_or(desired.generation)
}

pub(crate) fn container_name(key: &ReplicaKey) -> String {
    format!("fledx-agent-{}-{}", key.deployment_id, key.replica_number)
}

pub(crate) fn instance_state_from_status(status: &runtime::ContainerStatus) -> InstanceState {
    match status {
        runtime::ContainerStatus::Running => InstanceState::Running,
        runtime::ContainerStatus::Exited { exit_code } => {
            if exit_code.unwrap_or_default() == 0 {
                InstanceState::Stopped
            } else {
                InstanceState::Failed
            }
        }
        runtime::ContainerStatus::Unknown(_) => InstanceState::Unknown,
    }
}

pub(crate) fn instance_message(status: &runtime::ContainerStatus) -> Option<String> {
    match status {
        runtime::ContainerStatus::Running => None,
        runtime::ContainerStatus::Exited { exit_code } => {
            exit_code.map(|code| format!("container exited with code {}", code))
        }
        runtime::ContainerStatus::Unknown(msg) => Some(msg.clone()),
    }
}

pub(crate) fn parse_endpoints_label(
    labels: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    labels
        .get(state::ENDPOINTS_LABEL)
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .unwrap_or_default()
}
