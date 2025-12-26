use anyhow::Result;
use reqwest::Client;
use tracing::warn;

use crate::{
    health::{HealthCheckWork, apply_probe_results, run_health_for_work, uses_exec_probe},
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{DeploymentHealth, HealthProbe, HealthProbeKind, InstanceState, PortMapping},
        runtime::ContainerRuntimeError,
        state::{ManagedDeployment, ProbeRole, ReplicaKey, RuntimeFactory},
        test_support::base_config,
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use httpmock::{Method::GET, MockServer};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn health_tick_skips_runtime_factory_without_exec_probe() {
        let server = MockServer::start();
        let path = "/healthz";
        let _mock = server.mock(|when, then| {
            when.method(GET).path(path);
            then.status(200);
        });

        let calls = Arc::new(AtomicUsize::new(0));
        let runtime_factory: RuntimeFactory = {
            let calls = Arc::clone(&calls);
            Arc::new(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(ContainerRuntimeError::Connection {
                    context: "test",
                    source: anyhow::anyhow!("down"),
                })
            })
        };

        let state = state::new_state(base_config(), Client::new(), runtime_factory, None);
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut guard = state.managed_write().await;
            let mut entry = ManagedDeployment::new(1);
            entry.container_id = Some("container".into());
            entry.state = InstanceState::Running;
            entry.health_config = Some(DeploymentHealth {
                liveness: Some(HealthProbe {
                    kind: HealthProbeKind::Http {
                        port: 8080,
                        path: path.to_string(),
                    },
                    interval_seconds: Some(1),
                    timeout_seconds: Some(1),
                    failure_threshold: Some(1),
                    start_period_seconds: Some(0),
                }),
                readiness: None,
            });
            entry.ports = Some(vec![PortMapping {
                container_port: 8080,
                host_port: Some(server.port()),
                protocol: "tcp".into(),
                host_ip: Some("127.0.0.1".into()),
                expose: false,
                endpoint: None,
            }]);
            entry.last_started_at = Some(Utc::now() - ChronoDuration::seconds(5));
            guard.managed.insert(key, entry);
        }

        health_tick(&state, &Client::new()).await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let guard = state.managed_read().await;
        let entry = guard.managed.get(&key).expect("entry");
        let health = entry.health.as_ref().expect("health");
        assert!(health.healthy);
    }

    #[tokio::test]
    async fn health_tick_attempts_exec_probe_when_runtime_unavailable() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime_factory: RuntimeFactory = {
            let calls = Arc::clone(&calls);
            Arc::new(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(ContainerRuntimeError::Connection {
                    context: "test",
                    source: anyhow::anyhow!("down"),
                })
            })
        };

        let state = state::new_state(base_config(), Client::new(), runtime_factory, None);
        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut guard = state.managed_write().await;
            let mut entry = ManagedDeployment::new(1);
            entry.container_id = Some("container".into());
            entry.state = InstanceState::Running;
            entry.health_config = Some(DeploymentHealth {
                liveness: Some(HealthProbe {
                    kind: HealthProbeKind::Exec {
                        command: vec!["/bin/check".into()],
                    },
                    interval_seconds: Some(1),
                    timeout_seconds: Some(1),
                    failure_threshold: Some(1),
                    start_period_seconds: Some(0),
                }),
                readiness: None,
            });
            entry.last_started_at = Some(Utc::now() - ChronoDuration::seconds(1));
            guard.managed.insert(key, entry);
        }

        health_tick(&state, &Client::new()).await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let guard = state.managed_read().await;
        let entry = guard.managed.get(&key).expect("entry");
        assert_eq!(entry.state, InstanceState::Failed);
        assert_eq!(entry.failed_probe, Some(ProbeRole::Liveness));
        assert!(entry.backoff_until.is_some());
        assert_eq!(entry.restart_count, 1);
        let health = entry.health.as_ref().expect("health");
        assert!(!health.healthy);
        assert_eq!(
            health.last_error.as_deref(),
            Some("docker runtime unavailable")
        );
    }
}
