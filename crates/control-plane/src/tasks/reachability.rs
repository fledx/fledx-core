use std::collections::HashSet;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use crate::app_state::AppState;
use crate::audit::{AuditContext, AuditStatus};
use crate::config::PortsConfig;
use crate::http::{
    assignments_changed, assignments_from_decision, deployment_ports_for_storage,
    deserialize_deployment_fields, port_allocation_config, record_replica_schedule_decision,
    DeploymentFields,
};
use crate::persistence as db;
use crate::persistence::{
    deployments as deployment_store, nodes as node_store, ports as port_store,
};
use crate::scheduler;
use crate::telemetry;
use crate::Result;

#[derive(Debug, Default)]
pub struct ReachabilityReport {
    pub marked_unreachable: usize,
    pub rescheduled: usize,
    pub marked_pending: usize,
}

#[derive(Debug, Default)]
struct RescheduleReport {
    rescheduled: usize,
    marked_pending: usize,
}

pub async fn reachability_loop(state: AppState) {
    let stale_duration = Duration::from_secs(state.reachability.heartbeat_stale_secs.max(1));
    let sweep_interval = Duration::from_secs(state.reachability.sweep_interval_secs.max(1));
    let mut interval = tokio::time::interval(sweep_interval);

    loop {
        interval.tick().await;
        if let Err(err) = run_reachability_sweep_with_audit(
            &state.db,
            &state.scheduler,
            stale_duration,
            state.reachability.reschedule_on_unreachable,
            &state.ports,
            Some(&state),
        )
        .await
        {
            warn!(?err, "reachability sweep failed");
        }
    }
}

pub async fn run_reachability_sweep(
    db: &db::Db,
    scheduler: &scheduler::RoundRobinScheduler,
    stale_duration: Duration,
    reschedule_on_unreachable: bool,
    ports: &PortsConfig,
) -> Result<ReachabilityReport> {
    run_reachability_sweep_with_audit(
        db,
        scheduler,
        stale_duration,
        reschedule_on_unreachable,
        ports,
        None,
    )
    .await
}

async fn run_reachability_sweep_with_audit(
    db: &db::Db,
    scheduler: &scheduler::RoundRobinScheduler,
    stale_duration: Duration,
    reschedule_on_unreachable: bool,
    ports: &PortsConfig,
    audit_state: Option<&AppState>,
) -> Result<ReachabilityReport> {
    let cutoff = Utc::now()
        - ChronoDuration::from_std(stale_duration)
            .unwrap_or_else(|_| ChronoDuration::seconds(stale_duration.as_secs() as i64));
    let stale_nodes = node_store::find_stale_ready_nodes(db, cutoff).await?;
    let mut report = ReachabilityReport::default();
    for node in &stale_nodes {
        let updated = node_store::mark_node_unreachable_if_stale(db, node.id, cutoff).await?;
        if updated > 0 {
            report.marked_unreachable += 1;
            warn!(
                node_id = %node.id,
                last_seen = ?node.last_seen,
                "marking node unreachable after missed heartbeats"
            );
            if let Some(state) = audit_state {
                record_node_unreachable_audit(state, node).await;
            }
        }
    }

    if reschedule_on_unreachable {
        let reschedule_report = reschedule_deployments(db, scheduler, ports, audit_state).await?;
        report.rescheduled = reschedule_report.rescheduled;
        report.marked_pending = reschedule_report.marked_pending;
    }

    Ok(report)
}

async fn reschedule_deployments(
    db: &db::Db,
    scheduler: &scheduler::RoundRobinScheduler,
    port_cfg: &PortsConfig,
    audit_state: Option<&AppState>,
) -> Result<RescheduleReport> {
    let nodes = node_store::list_nodes(db).await?;
    let unreachable: HashSet<_> = nodes
        .iter()
        .filter(|n| n.status == db::NodeStatus::Unreachable)
        .map(|n| n.id)
        .collect();

    let mut deployment_ids: HashSet<Uuid> = HashSet::new();
    for node_id in &unreachable {
        let assignments = deployment_store::list_assignments_for_node(db, *node_id).await?;
        for assignment in assignments {
            deployment_ids.insert(assignment.deployment_id);
        }
    }

    let under_assigned = deployment_store::list_under_assigned_deployments(db).await?;
    for dep in &under_assigned {
        deployment_ids.insert(dep.id);
    }

    if deployment_ids.is_empty() {
        return Ok(RescheduleReport::default());
    }

    let mut report = RescheduleReport::default();

    for deployment_id in deployment_ids {
        let Some(deployment) = deployment_store::get_deployment(db, deployment_id).await? else {
            continue;
        };
        if deployment.desired_state != db::DesiredState::Running {
            continue;
        }

        let DeploymentFields {
            replicas,
            command,
            env,
            secret_env,
            secret_files,
            volumes,
            ports,
            requires_public_ip,
            tunnel_only: _,
            constraints,
            placement,
            health: existing_health,
        } = deserialize_deployment_fields(&deployment, port_cfg)?;

        let replica_count = replicas.max(1) as u32;
        let current_assignments =
            deployment_store::list_assignments_for_deployment(db, deployment.id).await?;
        let mut constraints = constraints;
        if requires_public_ip {
            constraints
                .get_or_insert_with(Default::default)
                .requires_public_ip = true;
        }

        let decision = scheduler
            .schedule_replicas(
                replica_count,
                constraints.as_ref(),
                placement.as_ref(),
                ports.as_deref(),
                deployment.id,
                Some(deployment.id),
                Some(&port_allocation_config(port_cfg)),
            )
            .await?;
        record_replica_schedule_decision("reschedule", &decision);

        if decision.compatible_nodes == 0 {
            warn!(
                deployment_id = %deployment.id,
                "marking deployment pending; no compatible nodes for placement or ports"
            );
            report.marked_pending += 1;
        }

        let new_assignments = assignments_from_decision(&decision);
        let pending_failure = decision.compatible_nodes == 0
            || decision.unplaced_replicas > 0
            || new_assignments.is_empty();
        let assignment_changed = assignments_changed(&current_assignments, &new_assignments);
        let resolved_ports =
            deployment_ports_for_storage(replica_count, &new_assignments, ports.clone());
        let generation = if assignment_changed {
            deployment.generation + 1
        } else {
            deployment.generation
        };

        let status =
            if assignment_changed || decision.unplaced_replicas > 0 || new_assignments.is_empty() {
                db::DeploymentStatus::Pending
            } else {
                deployment.status
            };

        let mut tx = db.begin().await?;
        deployment_store::update_deployment_tx(
            &mut tx,
            db::UpdatedDeployment {
                id: deployment.id,
                name: deployment.name.clone(),
                image: deployment.image.clone(),
                replicas,
                command: command.clone(),
                env: env.clone(),
                secret_env: secret_env.clone(),
                secret_files: secret_files.clone(),
                volumes: volumes.clone(),
                ports: resolved_ports.clone(),
                requires_public_ip: deployment.requires_public_ip,
                tunnel_only: deployment.tunnel_only,
                constraints: constraints.clone(),
                placement: placement.clone(),
                health: existing_health.clone(),
                desired_state: deployment.desired_state,
                assigned_node_id: new_assignments.first().map(|a| a.node_id),
                status,
                generation,
            },
        )
        .await?;
        deployment_store::replace_deployment_assignments_tx(
            &mut tx,
            deployment.id,
            &new_assignments,
        )
        .await?;
        port_store::replace_port_reservations(
            &mut tx,
            deployment.id,
            &new_assignments,
            deployment.desired_state,
        )
        .await?;
        tx.commit().await?;

        if new_assignments.is_empty() || decision.unplaced_replicas > 0 {
            report.marked_pending += 1;
        } else if assignment_changed {
            report.rescheduled += 1;
        }

        if assignment_changed {
            if let Some(state) = audit_state {
                let reason = if current_assignments
                    .iter()
                    .any(|assignment| unreachable.contains(&assignment.node_id))
                {
                    "node_unreachable"
                } else {
                    "under_assigned"
                };
                let status = if pending_failure {
                    AuditStatus::Failure
                } else {
                    AuditStatus::Success
                };
                record_deployment_reschedule_audit(
                    state,
                    deployment.id,
                    reason,
                    &current_assignments,
                    &new_assignments,
                    status,
                )
                .await;
            }
        }
    }

    Ok(report)
}

async fn record_node_unreachable_audit(state: &AppState, node: &db::NodeRecord) {
    let payload = json!({
        "reason": "heartbeat_timeout",
        "last_seen": node.last_seen,
    })
    .to_string();
    telemetry::record_audit_log(
        state,
        "node.unreachable",
        "node",
        AuditStatus::Success,
        AuditContext {
            resource_id: Some(node.id),
            actor: None,
            request_id: None,
            payload: Some(payload),
        },
    )
    .await;
}

async fn record_deployment_reschedule_audit(
    state: &AppState,
    deployment_id: Uuid,
    reason: &str,
    previous: &[db::DeploymentAssignmentRecord],
    next: &[db::NewDeploymentAssignment],
    status: AuditStatus,
) {
    let from: Vec<_> = previous
        .iter()
        .map(|assignment| {
            json!({
                "replica_number": assignment.replica_number,
                "node_id": assignment.node_id,
            })
        })
        .collect();
    let to: Vec<_> = next
        .iter()
        .map(|assignment| {
            json!({
                "replica_number": assignment.replica_number,
                "node_id": assignment.node_id,
            })
        })
        .collect();
    let payload = json!({
        "reason": reason,
        "from": from,
        "to": to,
    })
    .to_string();
    telemetry::record_audit_log(
        state,
        "deployment.reschedule",
        "deployment",
        status,
        AuditContext {
            resource_id: Some(deployment_id),
            actor: None,
            request_id: None,
            payload: Some(payload),
        },
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PortsConfig;
    use crate::persistence::{deployments, migrations, nodes};

    #[tokio::test]
    async fn sweep_marks_stale_nodes_and_reschedules() {
        let db = migrations::init_pool("sqlite::memory:")
            .await
            .expect("db init");
        migrations::run_migrations(&db).await.expect("migrations");
        let scheduler = scheduler::RoundRobinScheduler::new(db.clone());
        let ports = PortsConfig {
            auto_assign: false,
            range_start: 30000,
            range_end: 40000,
            public_host: None,
        };
        let now = Utc::now();

        let ready_node = nodes::create_node(
            &db,
            nodes::NewNode {
                id: Uuid::new_v4(),
                name: Some("ready".into()),
                token_hash: "ready-hash".into(),
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: Some(now),
                status: nodes::NodeStatus::Ready,
            },
        )
        .await
        .expect("ready node");

        let stale_node = nodes::create_node(
            &db,
            nodes::NewNode {
                id: Uuid::new_v4(),
                name: Some("stale".into()),
                token_hash: "stale-hash".into(),
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: Some(now - ChronoDuration::seconds(120)),
                status: nodes::NodeStatus::Ready,
            },
        )
        .await
        .expect("stale node");

        let deployment_id = Uuid::new_v4();
        deployments::create_deployment(
            &db,
            deployments::NewDeployment {
                id: deployment_id,
                name: "resched".into(),
                image: "img:1".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: deployments::DesiredState::Running,
                assigned_node_id: Some(stale_node.id),
                status: deployments::DeploymentStatus::Running,
                generation: 1,
                assignments: vec![deployments::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id: stale_node.id,
                    ports: None,
                }],
            },
        )
        .await
        .expect("deployment");

        let report = run_reachability_sweep(&db, &scheduler, Duration::from_secs(60), true, &ports)
            .await
            .expect("sweep");

        assert_eq!(report.marked_unreachable, 1);
        assert_eq!(report.rescheduled, 1);

        let stale_after = nodes::get_node(&db, stale_node.id)
            .await
            .expect("fetch stale node")
            .expect("stale node missing");
        assert_eq!(stale_after.status, nodes::NodeStatus::Unreachable);

        let assignments = deployments::list_assignments_for_deployment(&db, deployment_id)
            .await
            .expect("list assignments");
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].node_id, ready_node.id);

        let deployment = deployments::get_deployment(&db, deployment_id)
            .await
            .expect("fetch deployment")
            .expect("deployment missing");
        assert_eq!(deployment.status, deployments::DeploymentStatus::Pending);
    }
}
