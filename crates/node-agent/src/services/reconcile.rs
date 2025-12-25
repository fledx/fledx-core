use std::collections::HashSet;
use std::time::Instant;

use async_trait::async_trait;
use tracing::{error, warn};

use crate::{
    api,
    cp_client::{ControlPlaneClient, CpResponse},
    reconcile::{ReconcileOutcome, adoption, apply, cleanup, desired_fetch, replica_key},
    runtime,
    state::{self, ReplicaKey, SharedState, ensure_runtime},
    telemetry,
};

#[async_trait]
pub trait DesiredStateClient: Send + Sync {
    async fn fetch_desired_state(
        &self,
        state: &SharedState,
    ) -> anyhow::Result<CpResponse<api::DesiredStateResponse>>;
}

#[async_trait]
impl DesiredStateClient for ControlPlaneClient {
    async fn fetch_desired_state(
        &self,
        state: &SharedState,
    ) -> anyhow::Result<CpResponse<api::DesiredStateResponse>> {
        ControlPlaneClient::fetch_desired_state(self, state).await
    }
}

pub async fn reconcile_tick<C: DesiredStateClient>(
    state: &SharedState,
    client: &C,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let outcome = reconcile_once(state, client).await;

    match outcome {
        Ok(outcome) => {
            telemetry::record_reconcile_result(outcome.label());
            telemetry::record_reconcile_duration(outcome.label(), started.elapsed());
        }
        Err(err) => {
            error!(?err, "reconcile iteration failed");
            telemetry::record_reconcile_result("error");
            telemetry::record_reconcile_duration("error", started.elapsed());
        }
    }

    Ok(())
}

async fn reconcile_once<C: DesiredStateClient>(
    state: &SharedState,
    client: &C,
) -> anyhow::Result<ReconcileOutcome> {
    let initial_request_id = state::ensure_request_id(state).await;

    let desired = match desired_fetch::fetch_desired_state_with_client(
        state,
        client,
        initial_request_id.clone(),
    )
    .await
    {
        Ok(resp) => resp,
        Err(err) => {
            error!(?err, "failed to fetch desired state");
            return Ok(ReconcileOutcome::FetchError);
        }
    };

    let request_id = state::ensure_request_id(state).await;
    let span = tracing::info_span!("reconcile", %request_id);
    let _span_guard = span.enter();

    telemetry::record_reconcile_queue_len(desired.deployments.len());

    let runtime = {
        let mut guard = state.lock().await;
        match ensure_runtime(&mut guard) {
            Ok(rt) => Some(rt),
            Err(err) => {
                warn!(?err, "docker runtime unavailable, skipping reconcile tick");
                None
            }
        }
    };

    let runtime_unavailable = runtime.is_none();

    let desired_keys: HashSet<ReplicaKey> = desired.deployments.iter().map(replica_key).collect();

    if let Some(rt) = runtime.clone() {
        if let Err(err) = adoption::maybe_adopt_existing(state, rt.clone()).await {
            warn!(?err, "failed to adopt existing containers");
        }

        for deployment in desired.deployments {
            if let Err(err) = apply::apply_deployment(state, deployment, rt.clone()).await {
                error!(?err, "failed to apply desired deployment");
                if err
                    .downcast_ref::<runtime::ContainerRuntimeError>()
                    .map(|e| e.is_connection_error())
                    .unwrap_or(false)
                {
                    break;
                }
            }
        }
    }

    cleanup::cleanup_removed(state, &desired_keys, runtime).await?;

    let managed_count = {
        let store = state.managed_read().await;
        store.managed.len()
    };
    telemetry::record_managed_deployments(managed_count);

    if runtime_unavailable {
        Ok(ReconcileOutcome::RuntimeUnavailable)
    } else {
        Ok(ReconcileOutcome::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api, runtime,
        state::{self, RuntimeFactory},
        test_support::{FakeCpClient, MockRuntime, base_config, state_with_runtime_and_config},
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn reconcile_once_adopts_and_preserves_running_containers() {
        let deployment_id = Uuid::new_v4();
        let key = ReplicaKey::new(deployment_id, 0);
        let mut labels = std::collections::HashMap::new();
        labels.insert("fledx.deployment_id".into(), deployment_id.to_string());
        labels.insert("fledx.replica_number".into(), "0".into());
        labels.insert("fledx.generation".into(), "1".into());

        let container = runtime::ContainerDetails {
            id: "c1".into(),
            name: Some("c1".into()),
            status: runtime::ContainerStatus::Running,
            labels: Some(labels),
        };

        let mock = MockRuntime::with_containers(vec![container]);
        let runtime: runtime::DynContainerRuntime = std::sync::Arc::new(mock);
        let state = state_with_runtime_and_config(runtime, base_config());

        let desired = api::DeploymentDesired {
            deployment_id,
            name: "example/image:1".into(),
            replica_number: 0,
            image: "example/image:1".into(),
            replicas: 1,
            command: None,
            env: None,
            secret_env: None,
            secret_files: None,
            ports: None,
            volumes: None,
            requires_public_ip: false,
            tunnel_only: false,
            placement: None,
            health: None,
            desired_state: api::DesiredState::Running,
            replica_generation: Some(1),
            generation: 1,
        };

        let response = api::DesiredStateResponse {
            control_plane_version: "test".into(),
            min_supported_agent_version: "0.0.0".into(),
            max_supported_agent_version: None,
            upgrade_url: None,
            tunnel: None,
            deployments: vec![desired],
        };
        let client = FakeCpClient::with_desired(response);

        let outcome = reconcile_once(&state, &client)
            .await
            .expect("reconcile succeeds");
        assert_eq!(outcome, ReconcileOutcome::Applied);

        let managed = state.managed_read().await;
        let entry = managed.managed.get(&key).expect("managed entry");
        assert_eq!(entry.state, api::InstanceState::Running);
        drop(managed);

        let app = state.lock().await;
        assert!(!app.needs_adoption, "adoption flag should be cleared");
    }

    #[tokio::test]
    async fn reconcile_once_reports_runtime_unavailable_when_factory_fails() {
        let cfg = base_config();
        let client = reqwest::Client::new();
        let runtime_factory: RuntimeFactory = std::sync::Arc::new(|| {
            Err(runtime::ContainerRuntimeError::Connection {
                context: "test",
                source: anyhow::anyhow!("down"),
            })
        });
        let state = state::new_state(cfg, client, runtime_factory, None);
        let cp_client = FakeCpClient::default();

        let outcome = reconcile_once(&state, &cp_client)
            .await
            .expect("reconcile completes");
        assert_eq!(outcome, ReconcileOutcome::RuntimeUnavailable);

        let managed = state.managed_read().await;
        assert!(managed.managed.is_empty());
    }

    #[tokio::test]
    async fn reconcile_once_returns_fetch_error_on_client_failure() {
        let runtime: runtime::DynContainerRuntime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, base_config());
        let client = FakeCpClient::default();
        client.set_desired_error("nope");

        let outcome = reconcile_once(&state, &client)
            .await
            .expect("reconcile completes");
        assert_eq!(outcome, ReconcileOutcome::FetchError);
    }
}
