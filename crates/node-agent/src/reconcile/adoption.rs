use tracing::warn;
use uuid::Uuid;

use crate::{
    runtime::DynContainerRuntime,
    state::{self, ManagedDeployment, ReplicaKey, SharedState},
};

use super::{instance_message, instance_state_from_status, parse_endpoints_label};

pub(crate) async fn maybe_adopt_existing(
    state: &SharedState,
    runtime: DynContainerRuntime,
) -> anyhow::Result<()> {
    let should_adopt = {
        let guard = state.lock().await;
        guard.needs_adoption
    };

    if !should_adopt {
        return Ok(());
    }

    let containers = match runtime.list_managed_containers().await {
        Ok(list) => list,
        Err(err) => {
            state::record_runtime_error(state, &err).await;
            return Err(err.into());
        }
    };

    let mut store = state.managed_write().await;
    let mut adopted = 0usize;
    for details in containers {
        let Some(labels) = details.labels.as_ref() else {
            continue;
        };
        let Some(id_raw) = labels.get("fledx.deployment_id") else {
            continue;
        };
        let deployment_id = match Uuid::parse_str(id_raw) {
            Ok(id) => id,
            Err(_) => {
                warn!(deployment_id = %id_raw, "invalid deployment_id label on container; skipping");
                continue;
            }
        };
        let replica_number = labels
            .get("fledx.replica_number")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or_default();
        let generation = labels
            .get("fledx.generation")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);

        let key = ReplicaKey::new(deployment_id, replica_number);
        let mut entry = store
            .managed
            .get(&key)
            .cloned()
            .unwrap_or_else(|| ManagedDeployment::new(generation));
        entry.reset_for_generation(generation);
        entry.consecutive_failures = 0;
        entry.backoff_until = None;

        let state_value = instance_state_from_status(&details.status);
        let message = instance_message(&details.status);
        entry.mark_state(Some(details.id.clone()), state_value, message);
        entry.endpoints = parse_endpoints_label(labels);

        store.managed.insert(key, entry);
        adopted += 1;
    }

    {
        let mut app = state.lock().await;
        app.needs_adoption = false;
    }
    tracing::info!(adopted, "adopted existing managed containers");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api, runtime,
        test_support::{MockRuntime, base_config, state_with_runtime_and_config},
    };

    #[tokio::test]
    async fn adopts_existing_containers_and_clears_needs_flag() {
        let deployment_id = Uuid::new_v4();
        let key = ReplicaKey::new(deployment_id, 0);

        let mut labels = std::collections::HashMap::new();
        labels.insert("fledx.deployment_id".into(), deployment_id.to_string());
        labels.insert("fledx.replica_number".into(), "0".into());
        labels.insert("fledx.generation".into(), "1".into());
        labels.insert(
            state::ENDPOINTS_LABEL.to_string(),
            serde_json::to_string(&vec!["http://127.0.0.1:8080".to_string()]).unwrap(),
        );

        let container = runtime::ContainerDetails {
            id: "c1".into(),
            name: Some("c1".into()),
            status: runtime::ContainerStatus::Running,
            labels: Some(labels),
        };

        let mock = MockRuntime::with_containers(vec![container]);
        let runtime: DynContainerRuntime = std::sync::Arc::new(mock);
        let state = state_with_runtime_and_config(runtime.clone(), base_config());

        maybe_adopt_existing(&state, runtime.clone())
            .await
            .expect("adoption succeeds");

        let guard = state.managed_read().await;
        let managed = guard.managed.get(&key).expect("managed entry");
        assert_eq!(managed.state, api::InstanceState::Running);
        assert_eq!(managed.consecutive_failures, 0);
        assert!(managed.backoff_until.is_none());
        assert_eq!(managed.endpoints, vec!["http://127.0.0.1:8080"]);
        drop(guard);

        let app = state.lock().await;
        assert!(!app.needs_adoption, "needs_adoption flag should be cleared");
    }
}
