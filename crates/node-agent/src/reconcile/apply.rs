use tracing::info;

use crate::{
    api::{self, InstanceState},
    runtime::{self, DynContainerRuntime},
    state::{
        self, load_managed_entry, record_runtime_error, save_managed_entry, ReplicaKey, SharedState,
    },
    telemetry, validation,
};

use super::{
    backoff,
    config_apply::{apply_configs_to_spec, DeploymentContext},
    container_name, desired_replica_generation, instance_message, instance_state_from_status,
    replica_key, spec,
};

pub(crate) async fn apply_deployment(
    state: &SharedState,
    desired: api::DeploymentDesired,
    runtime: DynContainerRuntime,
) -> anyhow::Result<()> {
    info!(
        deployment_id = %desired.deployment_id,
        replica_number = desired.replica_number,
        image = %desired.image,
        desired_state = ?desired.desired_state,
        generation = desired_replica_generation(&desired),
        "applying deployment"
    );

    let context = build_deployment_context(state, &desired).await;

    let key = replica_key(&desired);
    let container_name = container_name(&key);

    match desired.desired_state {
        api::DesiredState::Running => {
            reconcile_running(state, desired, runtime, key, container_name, &context).await?;
        }
        api::DesiredState::Stopped => {
            reconcile_stopped(state, desired, runtime, key, container_name).await?;
        }
    }

    Ok(())
}

async fn reconcile_running(
    state: &SharedState,
    desired: api::DeploymentDesired,
    runtime: DynContainerRuntime,
    key: ReplicaKey,
    container_name: String,
    ctx: &DeploymentContext,
) -> anyhow::Result<()> {
    let desired_generation = desired_replica_generation(&desired);
    let cfg = ctx.cfg.clone();

    if let Some(ports) = desired.ports.as_deref() {
        validation::validate_ports(ports)?;
    }
    if let Some(health) = desired.health.as_ref() {
        validation::validate_health(health)?;
    }

    let mut managed = load_managed_entry(state, key, desired_generation).await;
    managed.health_config = desired.health.clone();
    managed.ports = desired.ports.clone();

    let inspected = runtime.inspect_container(&container_name).await;

    let mut needs_start = false;

    match inspected {
        Ok(details) => {
            let current_gen = details
                .labels
                .as_ref()
                .and_then(|labels| labels.get("fledx.generation"))
                .and_then(|v| v.parse::<i64>().ok());
            let running = matches!(details.status, runtime::ContainerStatus::Running);
            let config_label = details
                .labels
                .as_ref()
                .and_then(|labels| labels.get(state::CONFIG_FINGERPRINT_LABEL))
                .cloned();
            let configs_match = ctx.config_fingerprint.as_deref() == config_label.as_deref();
            if current_gen == Some(desired_generation) && running {
                if managed.failed_probe == Some(state::ProbeRole::Liveness) {
                    if let Err(err) = spec::stop_and_remove(&runtime, &container_name).await {
                        if let Some(cre) = err.downcast_ref::<runtime::ContainerRuntimeError>() {
                            record_runtime_error(state, cre).await;
                        }
                        return Err(err);
                    }
                    managed.failed_probe = None;
                    needs_start = true;
                } else if configs_match {
                    managed.refresh_running(Some(details.id));
                    if ctx.has_configs() {
                        telemetry::record_config_apply("skipped");
                    }
                } else {
                    if let Err(err) = spec::stop_and_remove(&runtime, &container_name).await {
                        if let Some(cre) = err.downcast_ref::<runtime::ContainerRuntimeError>() {
                            record_runtime_error(state, cre).await;
                        }
                        return Err(err);
                    }
                    managed.restart_count = managed.restart_count.saturating_add(1);
                    managed.container_id = None;
                    needs_start = true;
                }
            } else {
                if let Err(err) = spec::stop_and_remove(&runtime, &container_name).await {
                    if let Some(cre) = err.downcast_ref::<runtime::ContainerRuntimeError>() {
                        record_runtime_error(state, cre).await;
                    }
                    return Err(err);
                }
                managed.restart_count = managed.restart_count.saturating_add(1);
                managed.container_id = None;
                if !running {
                    let msg = super::instance_message(&details.status);
                    backoff::apply(&cfg, &mut managed, None, msg);
                } else {
                    managed.consecutive_failures = 0;
                    managed.backoff_until = None;
                    managed.message = None;
                }
                needs_start = true;
            }
        }
        Err(runtime::ContainerRuntimeError::NotFound { .. }) => needs_start = true,
        Err(err) => {
            record_runtime_error(state, &err).await;
            return Err(err.into());
        }
    }

    if needs_start {
        if managed.consecutive_failures >= cfg.restart_failure_limit {
            managed.mark_state(
                None,
                InstanceState::Failed,
                Some(format!(
                    "restart limit reached after {} failures",
                    managed.consecutive_failures
                )),
            );
            save_managed_entry(state, key, managed).await;
            return Ok(());
        }

        if let Some(remaining) = backoff::remaining(&managed) {
            let msg = managed.message.clone().unwrap_or_else(|| {
                format!(
                    "restart backoff, next attempt in {}s",
                    remaining.num_seconds().max(1)
                )
            });
            managed.mark_state(None, InstanceState::Failed, Some(msg));
            save_managed_entry(state, key, managed).await;
            return Ok(());
        }

        let start_kind = if managed.restart_count > 0 {
            "restart"
        } else {
            "start"
        };
        let endpoints = match spec::compute_exposed_endpoints(&desired, &cfg) {
            Ok(list) => list,
            Err(err) => {
                let msg = err.to_string();
                managed.restart_count = managed.restart_count.saturating_add(1);
                telemetry::record_container_start(start_kind, "failed");
                backoff::apply(&cfg, &mut managed, None, Some(msg));
                save_managed_entry(state, key, managed).await;
                return Err(err);
            }
        };
        managed.endpoints = endpoints.clone();
        let mut spec = match spec::to_container_spec(&desired, &container_name, &cfg, &endpoints) {
            Ok(spec) => spec,
            Err(err) => {
                managed.restart_count = managed.restart_count.saturating_add(1);
                telemetry::record_container_start(start_kind, "failed");
                backoff::apply(&cfg, &mut managed, None, Some(err.to_string()));
                save_managed_entry(state, key, managed).await;
                return Err(err);
            }
        };
        if let Some(fp) = ctx.config_fingerprint.as_ref() {
            spec.labels
                .push((state::CONFIG_FINGERPRINT_LABEL.to_string(), fp.clone()));
        }
        let config_outcome =
            apply_configs_to_spec(&mut spec, ctx, &desired).inspect_err(|_err| {
                if ctx.has_configs() {
                    telemetry::record_config_apply("failed");
                }
            })?;
        match runtime.start_container(spec).await {
            Ok(container_id) => {
                managed.restart_count = managed.restart_count.saturating_add(1);
                telemetry::record_container_start(start_kind, "success");
                if ctx.has_configs()
                    && (ctx.config_fingerprint.is_some() || config_outcome.applied > 0)
                {
                    telemetry::record_config_apply("applied");
                }
                match runtime.inspect_container(&container_id).await {
                    Ok(details) => {
                        let state_value = instance_state_from_status(&details.status);
                        let message = instance_message(&details.status);
                        match state_value {
                            InstanceState::Running => managed.mark_running(Some(details.id)),
                            InstanceState::Failed => {
                                backoff::apply(&cfg, &mut managed, Some(details.id), message);
                            }
                            other => managed.mark_state(Some(details.id), other, message),
                        }
                    }
                    Err(err) => {
                        record_runtime_error(state, &err).await;
                        return Err(err.into());
                    }
                }
            }
            Err(err) => {
                let msg = match &err {
                    runtime::ContainerRuntimeError::PortConflict {
                        host_port,
                        protocol,
                        host_ip,
                        ..
                    } => Some(format!(
                        "port conflict on {}:{}/{}; free the port and retry",
                        host_ip, host_port, protocol
                    )),
                    _ => Some(format!("failed to start: {}", err)),
                };
                managed.restart_count = managed.restart_count.saturating_add(1);
                backoff::apply(&cfg, &mut managed, None, msg);
                telemetry::record_container_start(start_kind, "failed");
                if ctx.has_configs() {
                    telemetry::record_config_apply("failed");
                }
                record_runtime_error(state, &err).await;
                save_managed_entry(state, key, managed).await;
                return Err(err.into());
            }
        }
    }

    save_managed_entry(state, key, managed).await;

    Ok(())
}

async fn reconcile_stopped(
    state: &SharedState,
    desired: api::DeploymentDesired,
    runtime: DynContainerRuntime,
    key: ReplicaKey,
    container_name: String,
) -> anyhow::Result<()> {
    let mut managed = load_managed_entry(state, key, desired_replica_generation(&desired)).await;

    if let Err(err) = spec::stop_and_remove(&runtime, &container_name).await {
        if let Some(cre) = err.downcast_ref::<runtime::ContainerRuntimeError>() {
            record_runtime_error(state, cre).await;
        }
    }

    managed.consecutive_failures = 0;
    managed.backoff_until = None;
    managed.mark_state(None, InstanceState::Stopped, None);
    save_managed_entry(state, key, managed).await;

    Ok(())
}

async fn build_deployment_context(
    state: &SharedState,
    desired: &api::DeploymentDesired,
) -> DeploymentContext {
    let guard = state.lock().await;
    let configs = crate::configs::select_configs_for_deployment(
        &guard.configs,
        guard.cfg.node_id,
        desired.deployment_id,
    );
    let fingerprint = crate::configs::config_fingerprint(&configs);
    DeploymentContext {
        cfg: guard.cfg.clone(),
        configs,
        config_fingerprint: fingerprint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api, runtime,
        test_support::{base_config, state_with_runtime_and_config, MockRuntime, StartAction},
    };
    use chrono::Utc;
    use uuid::Uuid;

    #[tokio::test]
    async fn restart_backoff_prevents_thrash() {
        let mut cfg = base_config();
        cfg.restart_backoff_ms = 50;
        cfg.restart_backoff_max_ms = 50;

        let start_error = runtime::ContainerRuntimeError::StartContainer {
            id: "fail".into(),
            source: anyhow::anyhow!("boom"),
        };

        let mock = std::sync::Arc::new(MockRuntime::with_start_actions(vec![
            StartAction::Err(start_error),
            StartAction::Ok(runtime::ContainerStatus::Running),
        ]));
        let runtime: DynContainerRuntime = mock.clone();
        let state = state_with_runtime_and_config(runtime.clone(), cfg);
        let deployment_id = Uuid::new_v4();
        let key = ReplicaKey::new(deployment_id, 0);
        let desired = api::DeploymentDesired {
            deployment_id,
            name: "example/image:1".into(),
            replica_number: key.replica_number,
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

        let first = apply_deployment(&state, desired.clone(), runtime.clone()).await;
        assert!(first.is_err(), "first start should fail");

        {
            let guard = state.managed_read().await;
            let entry = guard.managed.get(&key).expect("entry");
            assert_eq!(entry.state, InstanceState::Failed);
            assert_eq!(entry.consecutive_failures, 1);
            assert!(entry.backoff_until.is_some());
            assert_eq!(mock.start_calls(), 1);
        }

        let second = apply_deployment(&state, desired.clone(), runtime.clone()).await;
        assert!(
            second.is_ok(),
            "backoff path should short-circuit without error"
        );
        {
            let guard = state.managed_read().await;
            let entry = guard.managed.get(&key).expect("entry");
            assert_eq!(mock.start_calls(), 1);
            assert_eq!(entry.state, InstanceState::Failed);
        }

        {
            let mut guard = state.managed_write().await;
            if let Some(entry) = guard.managed.get_mut(&key) {
                entry.backoff_until = Some(Utc::now() - chrono::Duration::seconds(1));
            }
        }

        let third = apply_deployment(&state, desired, runtime.clone()).await;
        assert!(
            third.is_ok(),
            "should recover after backoff and successful start"
        );
        {
            let guard = state.managed_read().await;
            let entry = guard.managed.get(&key).expect("entry");
            assert_eq!(mock.start_calls(), 2);
            assert_eq!(entry.state, InstanceState::Running);
            assert_eq!(entry.consecutive_failures, 0);
        }
    }

    #[tokio::test]
    async fn config_reload_respects_local_env_precedence() {
        let deployment_id = Uuid::new_v4();
        let mock = MockRuntime::default();
        let runtime: DynContainerRuntime = std::sync::Arc::new(mock.clone());
        let state = state_with_runtime_and_config(runtime.clone(), base_config());

        let config_id = Uuid::new_v4();
        let config = api::ConfigDesired {
            metadata: api::ConfigMetadata {
                config_id,
                name: "cfg".into(),
                version: 1,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            entries: vec![
                api::ConfigEntry {
                    key: "SHARED".into(),
                    value: Some("from-config".into()),
                    secret_ref: None,
                },
                api::ConfigEntry {
                    key: "CONFIG_ONLY".into(),
                    value: Some("yes".into()),
                    secret_ref: None,
                },
            ],
            files: Vec::new(),
            attached_deployments: vec![deployment_id],
            attached_nodes: Vec::new(),
            checksum: Some("sum".into()),
        };

        {
            let mut guard = state.lock().await;
            guard.configs.insert(config_id, config);
        }

        let desired = api::DeploymentDesired {
            deployment_id,
            name: "example/image:1".into(),
            replica_number: 0,
            image: "example/image:1".into(),
            replicas: 1,
            command: None,
            env: Some(std::collections::HashMap::from([(
                "SHARED".into(),
                "from-deploy".into(),
            )])),
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

        apply_deployment(&state, desired, runtime.clone())
            .await
            .expect("deployment starts");

        let started = mock.last_started();
        let spec = started.last().expect("captured spec");

        let env_value = |key: &str| {
            spec.env
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        };

        assert_eq!(env_value("SHARED"), Some("from-deploy".into()));
        assert_eq!(env_value("CONFIG_ONLY"), Some("yes".into()));
    }
}
