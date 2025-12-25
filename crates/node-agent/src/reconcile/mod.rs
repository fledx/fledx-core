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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{DeploymentDesired, DesiredState};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn reconcile_outcome_labels_are_stable() {
        assert_eq!(ReconcileOutcome::Applied.label(), "success");
        assert_eq!(ReconcileOutcome::FetchError.label(), "fetch_error");
        assert_eq!(
            ReconcileOutcome::RuntimeUnavailable.label(),
            "runtime_unavailable"
        );
    }

    #[test]
    fn replica_key_and_container_name_format() {
        let deployment_id = Uuid::from_u128(1);
        let desired = DeploymentDesired {
            deployment_id,
            name: "svc".into(),
            replica_number: 2,
            image: "nginx".into(),
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
            desired_state: DesiredState::Running,
            replica_generation: None,
            generation: 5,
        };
        let key = replica_key(&desired);
        assert_eq!(key.deployment_id, deployment_id);
        assert_eq!(key.replica_number, 2);
        assert_eq!(
            container_name(&key),
            format!("fledx-agent-{}-{}", deployment_id, 2)
        );
    }

    #[test]
    fn desired_replica_generation_prefers_override() {
        let deployment_id = Uuid::from_u128(2);
        let mut desired = DeploymentDesired {
            deployment_id,
            name: "svc".into(),
            replica_number: 0,
            image: "nginx".into(),
            replicas: 2,
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
            desired_state: DesiredState::Running,
            replica_generation: None,
            generation: 7,
        };
        assert_eq!(desired_replica_generation(&desired), 7);
        desired.replica_generation = Some(9);
        assert_eq!(desired_replica_generation(&desired), 9);
    }

    #[test]
    fn instance_state_from_status_maps_variants() {
        assert_eq!(
            instance_state_from_status(&runtime::ContainerStatus::Running),
            InstanceState::Running
        );
        assert_eq!(
            instance_state_from_status(&runtime::ContainerStatus::Exited { exit_code: Some(0) }),
            InstanceState::Stopped
        );
        assert_eq!(
            instance_state_from_status(&runtime::ContainerStatus::Exited { exit_code: Some(2) }),
            InstanceState::Failed
        );
        assert_eq!(
            instance_state_from_status(&runtime::ContainerStatus::Unknown("x".into())),
            InstanceState::Unknown
        );
    }

    #[test]
    fn instance_message_formats_exit_codes_and_unknown() {
        assert_eq!(
            instance_message(&runtime::ContainerStatus::Exited { exit_code: Some(1) }).as_deref(),
            Some("container exited with code 1")
        );
        assert_eq!(
            instance_message(&runtime::ContainerStatus::Unknown("oops".into())).as_deref(),
            Some("oops")
        );
        assert!(instance_message(&runtime::ContainerStatus::Running).is_none());
    }

    #[test]
    fn parse_endpoints_label_handles_missing_and_invalid() {
        let mut labels = HashMap::new();
        assert!(parse_endpoints_label(&labels).is_empty());

        labels.insert(state::ENDPOINTS_LABEL.to_string(), "not json".into());
        assert!(parse_endpoints_label(&labels).is_empty());

        labels.insert(
            state::ENDPOINTS_LABEL.to_string(),
            serde_json::to_string(&vec!["a".to_string(), "b".to_string()]).unwrap(),
        );
        let parsed = parse_endpoints_label(&labels);
        assert_eq!(parsed, vec!["a".to_string(), "b".to_string()]);
    }
}
