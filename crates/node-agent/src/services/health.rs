use anyhow::Result;
use reqwest::Client;
use tracing::warn;

use crate::{
    health::{apply_probe_results, run_health_for_work, uses_exec_probe, HealthCheckWork},
    runtime::DynContainerRuntime,
    state::{self, SharedState},
};

pub async fn health_tick(state: &SharedState, http_client: &Client) -> Result<()> {
    let now = chrono::Utc::now();
    let mut work_items = Vec::new();
    let mut needs_exec = false;

    {
        let store = state.managed_read().await;
        for (key, entry) in store.managed.iter() {
            if entry.container_id.is_none() || entry.state != crate::api::InstanceState::Running {
                continue;
            }
            let health_config = match entry.health_config.clone() {
                Some(cfg) => cfg,
                None => continue,
            };
            let container_id = entry.container_id.clone().unwrap();
            if uses_exec_probe(&health_config) {
                needs_exec = true;
            }

            work_items.push(HealthCheckWork {
                key: *key,
                container_id,
                health_config,
                ports: entry.ports.clone(),
                liveness_state: entry.liveness_probe_state.clone(),
                readiness_state: entry.readiness_probe_state.clone(),
                last_started_at: entry.last_started_at,
                failed_probe: entry.failed_probe,
                failure_reason: None,
            });
        }
    }

    let cfg = {
        let guard = state.lock().await;
        guard.cfg.clone()
    };

    let runtime: Option<DynContainerRuntime> = if needs_exec {
        let mut guard = state.lock().await;
        match state::ensure_runtime(&mut guard) {
            Ok(rt) => Some(rt),
            Err(err) => {
                warn!(?err, "docker runtime unavailable for health probes");
                guard.runtime.clone()
            }
        }
    } else {
        let guard = state.lock().await;
        guard.runtime.clone()
    };

    for mut work in work_items {
        if let Err(err) =
            run_health_for_work(&cfg, runtime.clone(), &mut work, http_client, now).await
        {
            warn!(
                error = ?err,
                deployment_id = %work.key.deployment_id,
                replica_number = work.key.replica_number,
                "health probe execution failed"
            );
        }
        apply_probe_results(state, work, &cfg).await;
    }

    Ok(())
}
