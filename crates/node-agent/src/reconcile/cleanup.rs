use std::collections::HashSet;

use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    runtime::{ContainerRuntimeError, DynContainerRuntime},
    state::{ReplicaKey, SharedState, ensure_runtime, record_runtime_error},
};

use super::container_name;

pub(crate) async fn cleanup_removed(
    state: &SharedState,
    desired_ids: &HashSet<ReplicaKey>,
    runtime: Option<DynContainerRuntime>,
) -> anyhow::Result<()> {
    let mut to_remove: Vec<ReplicaKey> = {
        let store = state.managed_read().await;
        store
            .managed
            .keys()
            .filter(|id| !desired_ids.contains(id))
            .cloned()
            .collect()
    };

    let runtime = match runtime {
        Some(rt) => rt,
        None => {
            let mut guard = state.lock().await;
            match ensure_runtime(&mut guard) {
                Ok(rt) => rt,
                Err(err) => {
                    warn!(
                        ?err,
                        "docker runtime unavailable, skipping cleanup of removed deployments"
                    );
                    return Ok(());
                }
            }
        }
    };

    let stray_containers = runtime
        .list_managed_containers()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|details| {
            let labels = details.labels.as_ref()?;
            let deployment_id = labels
                .get("fledx.deployment_id")
                .and_then(|id| Uuid::parse_str(id).ok())?;
            let replica_number = labels
                .get("fledx.replica_number")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or_default();
            let key = ReplicaKey::new(deployment_id, replica_number);
            if desired_ids.contains(&key) {
                return None;
            }
            let name = details.name.clone().unwrap_or_else(|| container_name(&key));
            Some((key, name))
        })
        .collect::<Vec<_>>();

    for (key, _) in &stray_containers {
        if !to_remove.contains(key) {
            to_remove.push(*key);
        }
    }

    if to_remove.is_empty() {
        return Ok(());
    }

    for key in to_remove {
        let name = container_name(&key);
        match stop_and_remove(&runtime, &name).await {
            Ok(_) => {
                let mut store = state.managed_write().await;
                store.managed.remove(&key);
            }
            Err(err)
                if matches!(
                    err.downcast_ref::<ContainerRuntimeError>(),
                    Some(ContainerRuntimeError::NotFound { .. })
                ) =>
            {
                let mut store = state.managed_write().await;
                store.managed.remove(&key);
            }
            Err(err) => {
                if let Some(cre) = err.downcast_ref::<ContainerRuntimeError>() {
                    record_runtime_error(state, cre).await;
                }
                error!(
                    ?err,
                    %name,
                    "failed to remove container for removed deployment; will retry"
                );
            }
        }
    }

    for (key, name) in stray_containers {
        let _ = stop_and_remove(&runtime, &name).await;
        let mut store = state.managed_write().await;
        store.managed.remove(&key);
    }

    Ok(())
}

pub(super) async fn stop_and_remove(
    runtime: &DynContainerRuntime,
    name: &str,
) -> anyhow::Result<()> {
    if let Err(err) = runtime.stop_container(name).await
        && !matches!(err, ContainerRuntimeError::NotFound { .. })
    {
        return Err(err.into());
    }

    if let Err(err) = runtime.remove_container(name).await
        && !matches!(err, ContainerRuntimeError::NotFound { .. })
    {
        return Err(err.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api, runtime, state,
        test_support::{MockRuntime, base_config, state_with_runtime_and_config},
    };
    use chrono::Utc;

    #[tokio::test]
    async fn cleanup_removed_purges_managed_containers() {
        let deployment_id = Uuid::new_v4();
        let key = ReplicaKey::new(deployment_id, 0);
        let name = container_name(&key);
        let mut labels = std::collections::HashMap::new();
        labels.insert("fledx.deployment_id".into(), deployment_id.to_string());
        labels.insert("fledx.replica_number".into(), "0".into());
        labels.insert("fledx.generation".into(), "1".into());

        let container = runtime::ContainerDetails {
            id: name.clone(),
            name: Some(name.clone()),
            status: runtime::ContainerStatus::Running,
            labels: Some(labels),
        };

        let mock = MockRuntime::with_containers(vec![container]);
        let runtime: DynContainerRuntime = std::sync::Arc::new(mock.clone());
        let state = state_with_runtime_and_config(runtime.clone(), base_config());
        {
            let mut guard = state.managed_write().await;
            guard.managed.insert(
                key,
                state::ManagedDeployment {
                    container_id: Some(name.clone()),
                    state: api::InstanceState::Running,
                    message: None,
                    restart_count: 0,
                    consecutive_failures: 0,
                    backoff_until: None,
                    generation: 1,
                    last_updated: Utc::now(),
                    endpoints: Vec::new(),
                    health: None,
                    health_config: None,
                    ports: None,
                    liveness_probe_state: state::ProbeState::default(),
                    readiness_probe_state: state::ProbeState::default(),
                    last_started_at: None,
                    failed_probe: None,
                },
            );
        }

        let desired_ids: HashSet<ReplicaKey> = HashSet::new();
        cleanup_removed(&state, &desired_ids, Some(runtime))
            .await
            .expect("cleanup");

        let guard = state.managed_read().await;
        assert!(guard.managed.is_empty(), "managed set should be cleared");
        let containers = mock.containers.lock().expect("lock");
        assert!(
            containers.is_empty(),
            "containers should be removed for missing deployments"
        );
    }

    #[tokio::test]
    async fn stop_and_remove_ignores_missing_container() {
        let mock = MockRuntime::default();
        let runtime: DynContainerRuntime = std::sync::Arc::new(mock);

        stop_and_remove(&runtime, "missing")
            .await
            .expect("should ignore not found");
    }
}
