use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::Result;
use futures_util::stream::StreamExt;
use tokio::sync::watch;
use tokio::time;
use tracing::{debug, warn};

use crate::api::InstanceState;
use crate::runtime::{ContainerResourceUsage, ContainerRuntimeError, DynContainerRuntime};
use crate::state::{self, ReplicaKey, SharedState};
use crate::telemetry;

const MIN_WINDOW: usize = 1;

#[derive(Debug, Clone)]
struct BackoffEntry {
    attempts: u32,
    ready_at: Instant,
}

pub async fn resource_sampler_loop(
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let (interval, max_samples, max_concurrency, backoff_base, backoff_max) = {
        let guard = state.lock().await;
        (
            Duration::from_secs(guard.cfg.resource_sample_interval_secs.max(1)),
            guard.cfg.resource_sample_window.max(MIN_WINDOW),
            guard.cfg.resource_sample_max_concurrency.max(1),
            Duration::from_millis(guard.cfg.resource_sample_backoff_ms.max(1)),
            Duration::from_millis(
                guard
                    .cfg
                    .resource_sample_backoff_max_ms
                    .max(guard.cfg.resource_sample_backoff_ms.max(1)),
            ),
        )
    };

    let mut ticker = time::interval(interval);
    let mut backoff: HashMap<String, BackoffEntry> = HashMap::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = ticker.tick() => {
                if let Err(err) = sample_once(
                    &state,
                    &mut backoff,
                    max_samples,
                    max_concurrency,
                    backoff_base,
                    backoff_max,
                ).await {
                    warn!(?err, "resource sampler iteration failed");
                }
            }
        }
    }

    Ok(())
}

async fn sample_once(
    state: &SharedState,
    backoff: &mut HashMap<String, BackoffEntry>,
    max_samples: usize,
    max_concurrency: usize,
    backoff_base: Duration,
    backoff_max: Duration,
) -> Result<()> {
    let runtime = match state.acquire_runtime().await {
        Ok(rt) => rt,
        Err(err) => {
            warn!(?err, "resource sampler cannot connect to docker runtime");
            return Ok(());
        }
    };

    let targets: Vec<_> = {
        let store = state.managed_read().await;
        store
            .managed
            .iter()
            .filter_map(|(key, managed)| {
                if managed.state == InstanceState::Running {
                    managed.container_id.as_ref().map(|id| (*key, id.clone()))
                } else {
                    None
                }
            })
            .collect()
    };

    {
        let mut store = state.managed_write().await;
        store
            .resource_samples
            .retain(|key, _| targets.iter().any(|(k, _)| k == key));
    }

    if targets.is_empty() {
        prune_backoff(backoff, &[]);
        return Ok(());
    }

    prune_backoff(backoff, &targets);

    let samples = collect_samples(
        state,
        runtime,
        targets,
        backoff,
        max_concurrency,
        backoff_base,
        backoff_max,
    )
    .await?;

    if samples.is_empty() {
        return Ok(());
    }

    let max_samples = max_samples.max(MIN_WINDOW);
    let mut store = state.managed_write().await;
    for (key, container_id, sample) in samples {
        let entry = store.resource_samples.entry(key).or_default();
        entry.push_back(sample.clone());
        if entry.len() > max_samples {
            let drop_count = entry.len() - max_samples;
            for _ in 0..drop_count {
                entry.pop_front();
            }
        }

        telemetry::record_resource_sample(&container_id, &sample);
    }

    Ok(())
}

async fn collect_samples(
    state: &SharedState,
    runtime: DynContainerRuntime,
    targets: Vec<(ReplicaKey, String)>,
    backoff: &mut HashMap<String, BackoffEntry>,
    max_concurrency: usize,
    backoff_base: Duration,
    backoff_max: Duration,
) -> Result<Vec<(ReplicaKey, String, ContainerResourceUsage)>> {
    let now = Instant::now();
    let mut work = Vec::new();
    for (key, id) in targets {
        if matches!(backoff.get(&id), Some(entry) if entry.ready_at > now) {
            continue;
        }
        work.push((key, id));
    }

    let mut tasks = futures_util::stream::iter(work.into_iter().map(|(key, id)| {
        let runtime = runtime.clone();
        async move {
            let res = runtime.container_stats(&id).await;
            (key, id, res)
        }
    }))
    .buffer_unordered(max_concurrency.max(1));

    let mut samples = Vec::new();

    while let Some((key, id, result)) = tasks.next().await {
        match result {
            Ok(sample) => {
                backoff.remove(&id);
                samples.push((key, id, sample));
            }
            Err(err) => {
                handle_sample_error(state, backoff, &id, err, backoff_base, backoff_max).await;
            }
        }
    }

    Ok(samples)
}

async fn handle_sample_error(
    state: &SharedState,
    backoff: &mut HashMap<String, BackoffEntry>,
    container_id: &str,
    err: ContainerRuntimeError,
    backoff_base: Duration,
    backoff_max: Duration,
) {
    if err.is_connection_error() {
        state::record_runtime_error(state, &err).await;
    } else {
        let attempts = backoff
            .get(container_id)
            .map(|entry| entry.attempts.saturating_add(1))
            .unwrap_or(1);
        let delay = state::backoff_with_jitter(backoff_base, backoff_max, attempts);
        backoff.insert(
            container_id.to_string(),
            BackoffEntry {
                attempts,
                ready_at: Instant::now() + delay,
            },
        );
        debug!(
            container_id = %container_id,
            attempts,
            backoff_ms = delay.as_millis(),
            "resource sampler backing off after error"
        );
    }

    warn!(
        container_id = %container_id,
        error = %err,
        "resource sampler failed to collect stats"
    );
}

fn prune_backoff(backoff: &mut HashMap<String, BackoffEntry>, targets: &[(ReplicaKey, String)]) {
    let active: HashSet<&String> = targets.iter().map(|(_, id)| id).collect();
    backoff.retain(|id, _| active.contains(id));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ManagedDeployment, ReplicaKey};
    use crate::test_support::{MockRuntime, base_config, state_with_runtime_and_config};
    use chrono::Utc;
    use std::collections::VecDeque;
    use uuid::Uuid;

    fn sample(cpu: f64) -> ContainerResourceUsage {
        ContainerResourceUsage {
            collected_at: Utc::now(),
            cpu_percent: cpu,
            memory_bytes: 128,
            network_rx_bytes: 10,
            network_tx_bytes: 20,
            blk_read_bytes: Some(5),
            blk_write_bytes: Some(7),
        }
    }

    #[tokio::test]
    async fn collects_and_trims_samples() {
        let runtime = std::sync::Arc::new(MockRuntime::default());
        let mut cfg = base_config();
        cfg.resource_sample_window = 1;
        let state = state_with_runtime_and_config(runtime.clone(), cfg);

        let container_id = "c1".to_string();
        runtime.set_stats(&container_id, vec![Ok(sample(1.0)), Ok(sample(2.0))]);

        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut store = state.managed_write().await;
            let mut managed = ManagedDeployment::new(1);
            managed.mark_running(Some(container_id.clone()));
            store.managed.insert(key, managed);
        }

        let mut backoff = HashMap::new();
        sample_once(
            &state,
            &mut backoff,
            1,
            2,
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        sample_once(
            &state,
            &mut backoff,
            1,
            2,
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .await
        .unwrap();

        let samples = {
            let store = state.managed_read().await;
            store
                .resource_samples
                .get(&key)
                .cloned()
                .unwrap_or_default()
        };

        assert_eq!(samples.len(), 1, "window should trim older samples");
        assert_eq!(samples.back().unwrap().cpu_percent, 2.0);
    }

    #[tokio::test]
    async fn backs_off_after_error() {
        let runtime = std::sync::Arc::new(MockRuntime::default());
        let cfg = base_config();
        let state = state_with_runtime_and_config(runtime.clone(), cfg);

        let container_id = "c2".to_string();
        runtime.set_stats(
            &container_id,
            vec![
                Err(ContainerRuntimeError::NotFound {
                    id: container_id.clone(),
                }),
                Ok(sample(3.0)),
            ],
        );

        let key = ReplicaKey::new(Uuid::new_v4(), 1);
        {
            let mut store = state.managed_write().await;
            let mut managed = ManagedDeployment::new(1);
            managed.mark_running(Some(container_id.clone()));
            store.managed.insert(key, managed);
        }

        let mut backoff = HashMap::new();
        sample_once(
            &state,
            &mut backoff,
            5,
            2,
            Duration::from_millis(50),
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        assert!(backoff.contains_key(&container_id));
        assert_eq!(runtime.stats_calls(), 1, "first attempt should call stats");

        sample_once(
            &state,
            &mut backoff,
            5,
            2,
            Duration::from_millis(50),
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert_eq!(runtime.stats_calls(), 1, "backoff should skip calls");

        if let Some(entry) = backoff.get_mut(&container_id) {
            entry.ready_at = Instant::now();
        }

        sample_once(
            &state,
            &mut backoff,
            5,
            2,
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        assert_eq!(
            runtime.stats_calls(),
            2,
            "backoff expiry should allow retry"
        );

        let samples = {
            let store = state.managed_read().await;
            store
                .resource_samples
                .get(&key)
                .cloned()
                .unwrap_or_default()
        };

        assert_eq!(samples.len(), 1);
        assert_eq!(samples.front().unwrap().cpu_percent, 3.0);
    }

    #[tokio::test]
    async fn prunes_samples_for_non_running_targets() {
        let runtime = std::sync::Arc::new(MockRuntime::default());
        let cfg = base_config();
        let state = state_with_runtime_and_config(runtime, cfg);

        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut store = state.managed_write().await;
            let mut queue = VecDeque::new();
            queue.push_back(sample(1.0));
            store.resource_samples.insert(key, queue);
        }

        let mut backoff = HashMap::new();
        sample_once(
            &state,
            &mut backoff,
            5,
            2,
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .await
        .unwrap();

        let store = state.managed_read().await;
        assert!(
            store.resource_samples.is_empty(),
            "stale samples should be cleared when no running replicas remain"
        );
    }

    #[tokio::test]
    async fn connection_errors_clear_runtime_without_container_backoff() {
        let runtime = std::sync::Arc::new(MockRuntime::default());
        let cfg = base_config();
        let state = state_with_runtime_and_config(runtime.clone(), cfg);

        let container_id = "conn-err".to_string();
        runtime.set_stats(
            &container_id,
            vec![Err(ContainerRuntimeError::Connection {
                context: "stats",
                source: anyhow::anyhow!("down"),
            })],
        );

        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        {
            let mut store = state.managed_write().await;
            let mut managed = ManagedDeployment::new(1);
            managed.mark_running(Some(container_id.clone()));
            store.managed.insert(key, managed);
        }

        let mut backoff = HashMap::new();
        sample_once(
            &state,
            &mut backoff,
            5,
            1,
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .await
        .unwrap();

        assert!(!backoff.contains_key(&container_id));
        let guard = state.lock().await;
        assert!(guard.runtime.is_none());
        assert!(guard.runtime_backoff_attempts >= 1);
        assert!(guard.runtime_backoff_until.is_some());
        assert!(guard.needs_adoption);
    }

    #[test]
    fn prune_backoff_removes_stale_entries() {
        let mut backoff = HashMap::new();
        backoff.insert(
            "keep".to_string(),
            BackoffEntry {
                attempts: 1,
                ready_at: Instant::now(),
            },
        );
        backoff.insert(
            "drop".to_string(),
            BackoffEntry {
                attempts: 2,
                ready_at: Instant::now(),
            },
        );

        let key = ReplicaKey::new(Uuid::new_v4(), 0);
        let targets = vec![(key, "keep".to_string())];
        prune_backoff(&mut backoff, &targets);

        assert!(backoff.contains_key("keep"));
        assert!(!backoff.contains_key("drop"));
    }
}
