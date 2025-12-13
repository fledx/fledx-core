use chrono::Utc;
use uuid::Uuid;

use crate::app_state::AppState;
use crate::error::{ApiResult, AppError};
use crate::http::{self, DeploymentFields};
use crate::persistence::{self as db, deployments, logs, nodes, ports, usage};
use crate::validation;

pub type DeploymentSpec = common::api::DeploymentSpec;
pub type DeploymentUpdate = crate::http::DeploymentUpdate;
pub type DeploymentStatusResponse = crate::http::DeploymentStatusResponse;
pub type DeploymentSummary = crate::http::DeploymentSummary;
pub type DeploymentMetricsResponse = crate::http::DeploymentMetricsResponse;
pub type UsageRollupResponse = crate::http::UsageRollupResponse;

pub struct DeploymentCreateResult {
    pub deployment_id: Uuid,
    pub assigned_node_id: Uuid,
    pub assigned_node_ids: Vec<Uuid>,
    pub unplaced_replicas: u32,
    pub generation: i64,
}

pub async fn create_deployment(
    state: &AppState,
    deployment_id: Uuid,
    spec: DeploymentSpec,
) -> ApiResult<DeploymentCreateResult> {
    let replicas = spec.replicas.unwrap_or(1);
    let total_nodes = nodes::count_nodes(&state.db).await?;
    validation::validate_deployment_spec(&spec, &state.limits, &state.ports, &state.volumes)?;
    let health = validation::normalize_health(spec.health.clone(), &state.limits)?;
    let ports = crate::http::normalize_ports(spec.ports.clone(), &state.ports, None);
    let volumes =
        validation::normalize_volumes(spec.volumes.clone(), &state.limits, &state.volumes)?;
    let mut constraints =
        validation::normalize_constraints(spec.constraints.clone(), &state.limits)?;
    if spec.requires_public_ip {
        constraints
            .get_or_insert_with(Default::default)
            .requires_public_ip = true;
    }
    let placement =
        validation::normalize_placement_hints(spec.placement.clone(), &state.limits, total_nodes)?;
    let desired_state = spec
        .desired_state
        .map(crate::http::to_db_desired_state)
        .unwrap_or(db::DesiredState::Running);
    let mut resolved_ports = ports.clone();
    let assignments: Vec<db::NewDeploymentAssignment>;
    let unplaced_replicas: u32;

    if desired_state == db::DesiredState::Running {
        let decision = state
            .scheduler
            .schedule_replicas(
                replicas,
                constraints.as_ref(),
                placement.as_ref(),
                ports.as_deref(),
                deployment_id,
                Some(deployment_id),
                Some(&crate::http::port_allocation_config(&state.ports)),
            )
            .await?;
        crate::http::record_replica_schedule_decision("create", &decision);
        if decision.compatible_nodes == 0 {
            return Err(crate::http::no_compatible_nodes_error_replicas(
                &decision,
                spec.requires_public_ip,
            ));
        }
        assignments = crate::http::assignments_from_decision(&decision);
        if assignments.is_empty() {
            return Err(crate::http::no_ready_nodes_error_replicas(&decision));
        }
        resolved_ports =
            crate::http::deployment_ports_for_storage(replicas, &assignments, resolved_ports);
        unplaced_replicas = decision.unplaced_replicas;
    } else {
        let decision = state
            .scheduler
            .schedule_replicas(
                replicas,
                constraints.as_ref(),
                placement.as_ref(),
                ports.as_deref(),
                deployment_id,
                Some(deployment_id),
                None,
            )
            .await?;
        crate::http::record_replica_schedule_decision("create", &decision);
        if decision.compatible_nodes == 0 {
            return Err(crate::http::no_compatible_nodes_error_replicas(
                &decision,
                spec.requires_public_ip,
            ));
        }
        assignments = crate::http::assignments_from_decision(&decision);
        if assignments.is_empty() {
            return Err(crate::http::no_ready_nodes_error_replicas(&decision));
        }
        resolved_ports =
            crate::http::deployment_ports_for_storage(replicas, &assignments, resolved_ports);
        unplaced_replicas = decision.unplaced_replicas;
    }

    if unplaced_replicas > 0 {
        ::tracing::warn!(
            deployment_id = %deployment_id,
            placed = assignments.len(),
            unplaced = unplaced_replicas,
            "not all replicas could be scheduled"
        );
    }

    let name = spec
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| spec.image.clone());
    let image = spec.image.trim().to_string();
    let assigned_node_id = assignments
        .first()
        .map(|a| a.node_id)
        .expect("assignments not empty");

    let new_dep = db::NewDeployment {
        id: deployment_id,
        name,
        image,
        replicas: replicas as i64,
        command: spec.command,
        env: spec.env,
        secret_env: spec.secret_env,
        secret_files: spec.secret_files,
        volumes,
        ports: resolved_ports.clone(),
        requires_public_ip: spec.requires_public_ip,
        tunnel_only: spec.tunnel_only,
        constraints,
        placement,
        health,
        desired_state,
        assigned_node_id: Some(assigned_node_id),
        status: db::DeploymentStatus::Pending,
        generation: 1,
        assignments: assignments.clone(),
    };

    let created = deployments::create_deployment(&state.db, new_dep)
        .await
        .map_err(http::map_port_error)?;

    Ok(DeploymentCreateResult {
        deployment_id: created.id,
        assigned_node_id,
        assigned_node_ids: assignments.iter().map(|a| a.node_id).collect(),
        unplaced_replicas,
        generation: created.generation,
    })
}

pub async fn update_deployment(
    state: &AppState,
    deployment_id: Uuid,
    update: DeploymentUpdate,
) -> ApiResult<DeploymentStatusResponse> {
    if update.name.is_none()
        && update.image.is_none()
        && update.replicas.is_none()
        && update.command.is_none()
        && update.env.is_none()
        && update.secret_env.is_none()
        && update.secret_files.is_none()
        && update.ports.is_none()
        && update.constraints.is_none()
        && update.placement.is_none()
        && update.desired_state.is_none()
        && update.volumes.is_none()
        && update.health.is_none()
        && update.tunnel_only.is_none()
    {
        return Err(AppError::bad_request("no fields to update"));
    }

    let deployment = deployments::get_deployment(&state.db, deployment_id)
        .await?
        .ok_or_else(|| AppError::not_found("deployment not found"))?;
    let existing_assignments =
        deployments::list_assignments_for_deployment(&state.db, deployment_id).await?;
    let DeploymentFields {
        replicas: existing_replicas,
        command: existing_command,
        env: existing_env,
        secret_env: existing_secret_env,
        secret_files: existing_secret_files,
        volumes: existing_volumes,
        ports: existing_ports,
        requires_public_ip: existing_requires_public_ip,
        tunnel_only: existing_tunnel_only,
        constraints: existing_constraints,
        placement: existing_placement,
        health: existing_health,
    } = crate::http::deserialize_deployment_fields(&deployment, &state.ports)?;
    let current_health = existing_health.clone();
    let current_replicas = existing_replicas;
    let current_command = existing_command.clone();
    let current_env = existing_env.clone();
    let current_secret_env = existing_secret_env.clone();
    let current_secret_files = existing_secret_files.clone();
    let current_volumes = existing_volumes.clone();
    let current_ports = existing_ports.clone();
    let current_constraints = existing_constraints.clone();
    let current_placement = existing_placement.clone();

    let total_nodes = nodes::count_nodes(&state.db).await?;

    if let Some(name) = update.name.as_ref() {
        if name.trim().is_empty() {
            return Err(AppError::bad_request("name cannot be empty"));
        }
    }

    let name = update
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| deployment.name.clone());

    let image = match update.image.as_ref() {
        Some(img) => {
            let trimmed = img.trim();
            if trimmed.is_empty() {
                return Err(AppError::bad_request("image cannot be empty"));
            }
            trimmed.to_string()
        }
        None => deployment.image.clone(),
    };

    let replicas = match update.replicas {
        Some(value) => {
            if value == 0 {
                return Err(AppError::bad_request("replicas must be at least 1"));
            }
            value as i64
        }
        None => current_replicas,
    };

    let command = match update.command {
        Some(cmd) => cmd,
        None => existing_command,
    };
    let env = match update.env {
        Some(env) => env,
        None => existing_env,
    };
    let secret_env = match update.secret_env {
        Some(env) => env,
        None => existing_secret_env,
    };
    let secret_files = match update.secret_files {
        Some(files) => files,
        None => existing_secret_files,
    };
    let volumes = match update.volumes {
        Some(volumes) => validation::normalize_volumes(volumes, &state.limits, &state.volumes)?,
        None => existing_volumes,
    };
    let ports = match update.ports {
        Some(ports) => crate::http::normalize_ports(ports, &state.ports, existing_ports.as_deref()),
        None => existing_ports,
    };
    let mut constraints = match update.constraints {
        Some(constraints) => validation::normalize_constraints(constraints, &state.limits)?,
        None => existing_constraints,
    };
    let placement = match update.placement {
        Some(placement) => {
            validation::normalize_placement_hints(placement, &state.limits, total_nodes)?
        }
        None => existing_placement,
    };
    let requires_public_ip = update
        .requires_public_ip
        .unwrap_or(existing_requires_public_ip);
    let tunnel_only = update.tunnel_only.unwrap_or(existing_tunnel_only);
    let desired_state = update
        .desired_state
        .map(crate::http::to_db_desired_state)
        .unwrap_or(deployment.desired_state);
    let health = match update.health {
        Some(Some(config)) => validation::normalize_health(Some(config), &state.limits)?,
        Some(None) => None,
        None => current_health.clone(),
    };

    if requires_public_ip {
        constraints
            .get_or_insert_with(Default::default)
            .requires_public_ip = true;
    }

    let merged_spec = DeploymentSpec {
        name: Some(name.clone()),
        image: image.clone(),
        replicas: Some(replicas as u32),
        command: command.clone(),
        env: env.clone(),
        secret_env: secret_env.clone(),
        secret_files: secret_files.clone(),
        ports: ports.clone(),
        volumes: volumes.clone(),
        constraints: constraints.clone(),
        placement: placement.clone(),
        health: health.clone(),
        requires_public_ip,
        tunnel_only,
        desired_state: Some(crate::http::to_api_desired_state(desired_state)),
    };
    validation::validate_deployment_spec(
        &merged_spec,
        &state.limits,
        &state.ports,
        &state.volumes,
    )?;

    let replica_count = replicas.max(1) as u32;
    let mut resolved_ports = ports.clone();
    let mut new_assignments = crate::http::assignments_from_records(&existing_assignments);
    let mut unplaced_replicas = 0;

    if desired_state == db::DesiredState::Running {
        let decision = state
            .scheduler
            .schedule_replicas(
                replica_count,
                constraints.as_ref(),
                placement.as_ref(),
                ports.as_deref(),
                deployment_id,
                Some(deployment_id),
                Some(&crate::http::port_allocation_config(&state.ports)),
            )
            .await?;
        crate::http::record_replica_schedule_decision("update", &decision);
        if decision.compatible_nodes == 0 {
            return Err(crate::http::no_compatible_nodes_error_replicas(
                &decision,
                requires_public_ip,
            ));
        }
        new_assignments = crate::http::assignments_from_decision(&decision);
        if new_assignments.is_empty() {
            return Err(crate::http::no_ready_nodes_error_replicas(&decision));
        }
        resolved_ports = crate::http::deployment_ports_for_storage(
            replica_count,
            &new_assignments,
            resolved_ports,
        );
        unplaced_replicas = decision.unplaced_replicas;
    } else {
        resolved_ports = crate::http::deployment_ports_for_storage(
            replica_count,
            &new_assignments,
            resolved_ports,
        );
    }

    if unplaced_replicas > 0 {
        ::tracing::warn!(
            deployment_id = %deployment_id,
            placed = new_assignments.len(),
            unplaced = unplaced_replicas,
            "not all replicas could be scheduled"
        );
    }

    let assignment_changed =
        crate::http::assignments_changed(&existing_assignments, &new_assignments);
    let spec_changed_base = image != deployment.image
        || replicas != current_replicas
        || command != current_command
        || env != current_env
        || secret_env != current_secret_env
        || secret_files != current_secret_files
        || volumes != current_volumes
        || constraints != current_constraints
        || placement != current_placement
        || health != current_health
        || requires_public_ip != existing_requires_public_ip
        || tunnel_only != existing_tunnel_only;
    let spec_changed = spec_changed_base || resolved_ports != current_ports || assignment_changed;

    let generation = if spec_changed || assignment_changed {
        deployment.generation + 1
    } else {
        deployment.generation
    };

    let status = match desired_state {
        db::DesiredState::Running => {
            if spec_changed
                || assignment_changed
                || deployment.desired_state == db::DesiredState::Stopped
                || unplaced_replicas > 0
            {
                db::DeploymentStatus::Pending
            } else {
                deployment.status
            }
        }
        db::DesiredState::Stopped => db::DeploymentStatus::Stopped,
    };

    let mut tx = state.db.begin().await.map_err(http::map_service_error)?;
    let updated_rows = deployments::update_deployment_tx(
        &mut tx,
        db::UpdatedDeployment {
            id: deployment_id,
            name,
            image,
            replicas,
            command,
            env,
            secret_env,
            secret_files,
            volumes,
            ports: resolved_ports.clone(),
            requires_public_ip,
            tunnel_only,
            constraints,
            placement,
            health,
            desired_state,
            assigned_node_id: new_assignments.first().map(|a| a.node_id),
            status,
            generation,
        },
    )
    .await?;

    if updated_rows == 0 {
        return Err(AppError::not_found("deployment not found"));
    }

    deployments::replace_deployment_assignments_tx(&mut tx, deployment_id, &new_assignments)
        .await?;

    ports::replace_port_reservations(&mut tx, deployment_id, &new_assignments, desired_state)
        .await
        .map_err(crate::http::map_port_error)?;
    tx.commit().await.map_err(http::map_service_error)?;

    let updated = deployments::get_deployment(&state.db, deployment_id)
        .await?
        .ok_or_else(|| AppError::not_found("deployment not found"))?;

    let resp = crate::http::build_deployment_response(state, updated).await?;
    Ok(resp)
}

pub async fn deployment_status(
    state: &AppState,
    deployment_id: Uuid,
) -> ApiResult<DeploymentStatusResponse> {
    let deployment = deployments::get_deployment(&state.db, deployment_id)
        .await?
        .ok_or_else(|| AppError::not_found("deployment not found"))?;
    let resp = crate::http::build_deployment_response(state, deployment).await?;
    Ok(resp)
}

pub async fn list_deployments(
    state: &AppState,
    status_filter: Option<db::DeploymentStatus>,
    limit: u32,
    offset: u32,
) -> ApiResult<Vec<DeploymentSummary>> {
    let deployments_rows =
        deployments::list_deployments_paged(&state.db, status_filter, limit, offset).await?;
    let mut items = Vec::with_capacity(deployments_rows.len());
    for row in deployments_rows {
        let assignments = deployments::list_assignments_for_deployment(&state.db, row.id).await?;
        items.push(crate::http::to_deployment_summary(row, assignments));
    }
    Ok(items)
}

pub async fn deployment_metrics(
    state: &AppState,
    deployment_id: Uuid,
) -> ApiResult<DeploymentMetricsResponse> {
    let deployment = deployments::get_deployment(&state.db, deployment_id)
        .await?
        .ok_or_else(|| AppError::not_found("deployment not found"))?;

    let records = logs::list_instance_statuses_for_deployment(&state.db, deployment_id).await?;
    let cutoff = if state.retention.instance_metrics_secs > 0 {
        Some(Utc::now() - chrono::Duration::seconds(state.retention.instance_metrics_secs as i64))
    } else {
        None
    };

    let replicas: Vec<crate::http::ReplicaResourceMetrics> = records
        .into_iter()
        .map(|record| {
            let mut metrics = record.metrics.map(|m| m.0).unwrap_or_default();
            if let Some(cutoff) = cutoff {
                metrics.retain(|sample| sample.collected_at >= cutoff);
            }
            metrics.sort_by_key(|m| m.collected_at);
            metrics.dedup_by_key(|m| m.collected_at);

            crate::http::ReplicaResourceMetrics {
                node_id: record.node_id,
                replica_number: record.replica_number as u32,
                last_seen: record.last_seen,
                metrics,
            }
        })
        .collect();

    Ok(DeploymentMetricsResponse {
        deployment_id,
        deployment: deployment.name,
        window_secs: state.retention.instance_metrics_secs,
        as_of: Utc::now(),
        replicas,
    })
}

pub async fn list_usage_rollups(
    state: &AppState,
    filters: db::UsageRollupFilters,
    limit: u32,
    offset: u32,
) -> ApiResult<Vec<UsageRollupResponse>> {
    let rollups = usage::list_usage_rollups(&state.db, filters, limit, offset).await?;
    Ok(rollups
        .into_iter()
        .map(|row| UsageRollupResponse {
            deployment_id: row.deployment_id,
            node_id: row.node_id,
            replica_number: row.replica_number,
            bucket_start: row.bucket_start,
            samples: row.samples,
            avg_cpu_percent: row.avg_cpu_percent,
            avg_memory_bytes: row.avg_memory_bytes,
            avg_network_rx_bytes: row.avg_network_rx_bytes,
            avg_network_tx_bytes: row.avg_network_tx_bytes,
            avg_blk_read_bytes: row.avg_blk_read_bytes,
            avg_blk_write_bytes: row.avg_blk_write_bytes,
        })
        .collect())
}
