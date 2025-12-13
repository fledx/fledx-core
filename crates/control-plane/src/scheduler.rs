use std::sync::Arc;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::persistence::{
    self, nodes, ports, NodeRecord, NodeStatus, PlacementConstraints, PlacementHints,
    PortAllocationConfig, PortAllocationError, PortMapping, PortReservationConflict,
};

#[derive(Clone)]
pub struct RoundRobinScheduler {
    db: persistence::Db,
    last_assigned: Arc<Mutex<Option<Uuid>>>,
}

#[derive(Debug, Clone)]
pub struct ScheduleDecision {
    pub node_id: Option<Uuid>,
    pub ready_nodes: usize,
    pub compatible_nodes: usize,
    pub total_nodes: usize,
    pub port_conflicted_nodes: usize,
    pub port_conflicts: Vec<PortReservationConflict>,
    pub allocated_ports: Option<Vec<PortMapping>>,
    pub allocation_error: Option<PortAllocationError>,
}

#[derive(Debug, Clone)]
pub struct ReplicaPlacement {
    pub replica_number: u32,
    pub node_id: Uuid,
    pub resolved_ports: Option<Vec<PortMapping>>,
}

#[derive(Debug, Clone)]
pub struct ReplicaScheduleDecision {
    pub placements: Vec<ReplicaPlacement>,
    pub ready_nodes: usize,
    pub compatible_nodes: usize,
    pub total_nodes: usize,
    pub port_conflicted_nodes: usize,
    pub port_conflicts: Vec<PortReservationConflict>,
    pub allocation_errors: Vec<PortAllocationError>,
    pub anti_affinity_filtered: usize,
    pub unplaced_replicas: u32,
}

#[derive(Debug, Clone)]
struct Candidate {
    node: NodeRecord,
    resolved_ports: Option<Vec<PortMapping>>,
}

impl RoundRobinScheduler {
    pub fn new(db: persistence::Db) -> Self {
        Self {
            db,
            last_assigned: Arc::new(Mutex::new(None)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn schedule_replicas(
        &self,
        replicas: u32,
        constraints: Option<&PlacementConstraints>,
        placement: Option<&PlacementHints>,
        ports: Option<&[PortMapping]>,
        deployment_id: Uuid,
        ignore_deployment: Option<Uuid>,
        port_config: Option<&PortAllocationConfig>,
    ) -> anyhow::Result<ReplicaScheduleDecision> {
        let nodes = nodes::list_nodes(&self.db).await?;
        let total_nodes = nodes.len();
        let mut port_conflicts = Vec::new();
        let mut allocation_errors = Vec::new();
        let mut candidates = Vec::new();

        for node in nodes {
            if !node_matches_constraints(&node, constraints) {
                continue;
            }

            let resolved_ports = match (ports, port_config) {
                (Some(ports), Some(cfg)) => {
                    match ports::allocate_host_ports_for_node(
                        &self.db,
                        node.id,
                        deployment_id,
                        ports,
                        ignore_deployment,
                        cfg,
                    )
                    .await
                    {
                        Ok(resolved) => Some(resolved),
                        Err(err) => {
                            if let Some(alloc_err) = err.downcast_ref::<PortAllocationError>() {
                                match alloc_err {
                                    PortAllocationError::Conflict(conflict) => {
                                        port_conflicts.push(conflict.clone());
                                    }
                                    other => allocation_errors.push(other.clone()),
                                }
                                continue;
                            }
                            return Err(err);
                        }
                    }
                }
                (Some(ports), None) => {
                    if let Some(conflict) = ports::find_port_conflict_for_node(
                        &self.db,
                        node.id,
                        ports,
                        ignore_deployment,
                    )
                    .await?
                    {
                        port_conflicts.push(conflict);
                        continue;
                    }
                    Some(ports.to_vec())
                }
                (None, _) => None,
            };

            candidates.push(Candidate {
                node,
                resolved_ports,
            });
        }

        let compatible_nodes = candidates.len();
        let mut ready_candidates: Vec<_> = candidates
            .into_iter()
            .filter(|c| c.node.status == NodeStatus::Ready)
            .collect();
        let ready_nodes = ready_candidates.len();

        // Ensure deterministic ordering even when nodes share the same created_at
        // timestamp (common in fast test setups).
        ready_candidates.sort_by(|a, b| {
            a.node
                .created_at
                .cmp(&b.node.created_at)
                .then_with(|| a.node.name.cmp(&b.node.name))
                .then_with(|| a.node.id.cmp(&b.node.id))
        });

        if ready_candidates.is_empty() {
            return Ok(ReplicaScheduleDecision {
                placements: Vec::new(),
                ready_nodes,
                compatible_nodes,
                total_nodes,
                port_conflicted_nodes: port_conflicts.len(),
                port_conflicts,
                allocation_errors,
                anti_affinity_filtered: 0,
                unplaced_replicas: replicas,
            });
        }

        let mut preferred = Vec::new();
        let mut avoided = Vec::new();
        for candidate in ready_candidates {
            if matches_anti_affinity(&candidate.node, placement) {
                avoided.push(candidate);
            } else {
                preferred.push(candidate);
            }
        }

        let anti_affinity_filtered = avoided.len();

        preferred.sort_by(|a, b| {
            let a_affinity = matches_affinity(&a.node, placement);
            let b_affinity = matches_affinity(&b.node, placement);
            b_affinity.cmp(&a_affinity)
        });
        avoided.sort_by(|a, b| {
            let a_affinity = matches_affinity(&a.node, placement);
            let b_affinity = matches_affinity(&b.node, placement);
            b_affinity.cmp(&a_affinity)
        });

        let mut ordered = preferred;
        if ordered.len() < replicas as usize {
            ordered.append(&mut avoided);
        }

        if replicas <= 1 {
            let last_assigned = { *self.last_assigned.lock().await };
            rotate_from_last(&mut ordered, last_assigned);
        }

        let mut placements = Vec::new();
        for candidate in ordered.into_iter().take(replicas as usize) {
            placements.push(ReplicaPlacement {
                replica_number: placements.len() as u32,
                node_id: candidate.node.id,
                resolved_ports: candidate.resolved_ports,
            });
        }

        let unplaced_replicas = replicas.saturating_sub(placements.len() as u32);

        if let Some(last) = placements.last() {
            let mut guard = self.last_assigned.lock().await;
            *guard = Some(last.node_id);
        }

        Ok(ReplicaScheduleDecision {
            placements,
            ready_nodes,
            compatible_nodes,
            total_nodes,
            port_conflicted_nodes: port_conflicts.len(),
            port_conflicts,
            allocation_errors,
            anti_affinity_filtered,
            unplaced_replicas,
        })
    }

    pub async fn select_node(
        &self,
        constraints: Option<&PlacementConstraints>,
        ports: Option<&[PortMapping]>,
        ignore_deployment: Option<Uuid>,
    ) -> anyhow::Result<ScheduleDecision> {
        let deployment_id = ignore_deployment.unwrap_or_else(Uuid::new_v4);
        let decision = self
            .schedule_replicas(
                1,
                constraints,
                None,
                ports,
                deployment_id,
                ignore_deployment,
                None,
            )
            .await?;
        let placement = decision.placements.first().cloned();
        Ok(ScheduleDecision {
            node_id: placement.as_ref().map(|p| p.node_id),
            ready_nodes: decision.ready_nodes,
            compatible_nodes: decision.compatible_nodes,
            total_nodes: decision.total_nodes,
            port_conflicted_nodes: decision.port_conflicted_nodes,
            port_conflicts: decision.port_conflicts,
            allocated_ports: placement.and_then(|p| p.resolved_ports),
            allocation_error: decision.allocation_errors.first().cloned(),
        })
    }

    pub async fn select_node_with_port_allocation(
        &self,
        constraints: Option<&PlacementConstraints>,
        ports: Option<&[PortMapping]>,
        deployment_id: Uuid,
        ignore_deployment: Option<Uuid>,
        port_config: &PortAllocationConfig,
    ) -> anyhow::Result<ScheduleDecision> {
        let decision = self
            .schedule_replicas(
                1,
                constraints,
                None,
                ports,
                deployment_id,
                ignore_deployment,
                Some(port_config),
            )
            .await?;
        let placement = decision.placements.first().cloned();
        Ok(ScheduleDecision {
            node_id: placement.as_ref().map(|p| p.node_id),
            ready_nodes: decision.ready_nodes,
            compatible_nodes: decision.compatible_nodes,
            total_nodes: decision.total_nodes,
            port_conflicted_nodes: decision.port_conflicted_nodes,
            port_conflicts: decision.port_conflicts,
            allocated_ports: placement.and_then(|p| p.resolved_ports),
            allocation_error: decision.allocation_errors.first().cloned(),
        })
    }
}

pub(crate) fn node_matches_constraints(
    node: &NodeRecord,
    constraints: Option<&PlacementConstraints>,
) -> bool {
    let Some(constraints) = constraints else {
        return true;
    };

    if constraints.requires_public_ip && node.public_ip.is_none() {
        return false;
    }

    if let Some(required_arch) = constraints.arch.as_ref() {
        if node
            .arch
            .as_ref()
            .map(|arch| arch.eq_ignore_ascii_case(required_arch))
            != Some(true)
        {
            return false;
        }
    }

    if let Some(required_os) = constraints.os.as_ref() {
        if node
            .os
            .as_ref()
            .map(|os| os.eq_ignore_ascii_case(required_os))
            != Some(true)
        {
            return false;
        }
    }

    if !constraints.labels.is_empty() {
        let Some(node_labels) = node.labels.as_ref().map(|labels| &labels.0) else {
            return false;
        };
        for (key, value) in &constraints.labels {
            match node_labels.get(key) {
                Some(candidate) if candidate == value => {}
                _ => return false,
            }
        }
    }

    if let Some(required_capacity) = constraints.capacity.as_ref() {
        let Some(node_capacity) = node.capacity.as_ref().map(|cap| &cap.0) else {
            return false;
        };
        if let Some(req_cpu) = required_capacity.cpu_millis {
            if node_capacity.cpu_millis.unwrap_or(0) < req_cpu {
                return false;
            }
        }
        if let Some(req_mem) = required_capacity.memory_bytes {
            if node_capacity.memory_bytes.unwrap_or(0) < req_mem {
                return false;
            }
        }
    }

    true
}

fn rotate_from_last(candidates: &mut [Candidate], last_assigned: Option<Uuid>) {
    if candidates.is_empty() {
        return;
    }

    if let Some(last) = last_assigned {
        if let Some(pos) = candidates.iter().position(|c| c.node.id == last) {
            let len = candidates.len();
            let shift = (pos + 1) % len;
            candidates.rotate_left(shift);
        }
    }
}

fn matches_affinity(node: &NodeRecord, placement: Option<&PlacementHints>) -> bool {
    let Some(hints) = placement else {
        return false;
    };

    let Some(affinity) = hints.affinity.as_ref() else {
        return false;
    };

    affinity.node_ids.contains(&node.id) || labels_match(node, &affinity.labels)
}

fn matches_anti_affinity(node: &NodeRecord, placement: Option<&PlacementHints>) -> bool {
    let Some(hints) = placement else {
        return false;
    };

    let Some(anti) = hints.anti_affinity.as_ref() else {
        return false;
    };

    anti.node_ids.contains(&node.id) || labels_match(node, &anti.labels)
}

fn labels_match(node: &NodeRecord, required: &std::collections::HashMap<String, String>) -> bool {
    if required.is_empty() {
        return false;
    }
    let Some(labels) = node.labels.as_ref().map(|l| &l.0) else {
        return false;
    };

    required
        .iter()
        .all(|(key, value)| labels.get(key).map(|candidate| candidate == value) == Some(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::NewNode;
    use crate::persistence::PlacementAffinity;
    use crate::persistence::{migrations, nodes, ports};

    async fn setup_db() -> persistence::Db {
        let pool = migrations::init_pool("sqlite::memory:").await.unwrap();
        migrations::run_migrations(&pool).await.unwrap();
        pool
    }

    fn ready_node(
        name: &str,
        labels: Option<std::collections::HashMap<String, String>>,
    ) -> NewNode {
        NewNode {
            id: Uuid::new_v4(),
            name: Some(name.into()),
            token_hash: format!("{name}-token"),
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels,
            capacity: None,
            last_seen: None,
            status: NodeStatus::Ready,
        }
    }

    fn ready_public_node(
        name: &str,
        labels: Option<std::collections::HashMap<String, String>>,
    ) -> NewNode {
        let mut node = ready_node(name, labels);
        node.public_ip = Some("203.0.113.10".into());
        node
    }

    #[tokio::test]
    async fn schedules_multiple_replicas_across_ready_nodes() {
        let db = setup_db().await;
        let scheduler = RoundRobinScheduler::new(db.clone());
        nodes::create_node(&db, ready_node("a", None))
            .await
            .unwrap();
        nodes::create_node(&db, ready_node("b", None))
            .await
            .unwrap();
        nodes::create_node(&db, ready_node("c", None))
            .await
            .unwrap();

        let decision = scheduler
            .schedule_replicas(
                2,
                None,
                None,
                None,
                Uuid::new_v4(),
                None,
                Some(&ports::PortAllocationConfig {
                    enable_auto_assign: true,
                    range_start: 20000,
                    range_end: 20010,
                }),
            )
            .await
            .unwrap();

        assert_eq!(decision.unplaced_replicas, 0);
        assert_eq!(decision.placements.len(), 2);
        let unique: std::collections::HashSet<_> =
            decision.placements.iter().map(|p| p.node_id).collect();
        assert_eq!(unique.len(), 2);
    }

    #[tokio::test]
    async fn honors_anti_affinity_labels() {
        let db = setup_db().await;
        let scheduler = RoundRobinScheduler::new(db.clone());
        let mut labels_a = std::collections::HashMap::new();
        labels_a.insert("rack".into(), "a".into());
        let mut labels_b = std::collections::HashMap::new();
        labels_b.insert("rack".into(), "b".into());

        let node_a = nodes::create_node(&db, ready_node("a", Some(labels_a)))
            .await
            .unwrap();
        let node_b = nodes::create_node(&db, ready_node("b", Some(labels_b)))
            .await
            .unwrap();

        let placement = PlacementHints {
            affinity: None,
            anti_affinity: Some(PlacementAffinity {
                node_ids: vec![],
                labels: std::iter::once(("rack".into(), "a".into()))
                    .collect::<std::collections::HashMap<_, _>>(),
            }),
            spread: true,
        };

        let decision = scheduler
            .schedule_replicas(
                1,
                None,
                Some(&placement),
                None,
                Uuid::new_v4(),
                None,
                Some(&ports::PortAllocationConfig {
                    enable_auto_assign: true,
                    range_start: 20000,
                    range_end: 20010,
                }),
            )
            .await
            .unwrap();

        assert_eq!(decision.unplaced_replicas, 0);
        let placed = decision
            .placements
            .first()
            .expect("placement missing")
            .node_id;
        assert_eq!(placed, node_b.id);
        assert_ne!(placed, node_a.id);
    }

    #[tokio::test]
    async fn reports_unplaced_when_nodes_insufficient() {
        let db = setup_db().await;
        let scheduler = RoundRobinScheduler::new(db.clone());
        let node = nodes::create_node(&db, ready_node("solo", None))
            .await
            .unwrap();

        let decision = scheduler
            .schedule_replicas(
                2,
                None,
                None,
                None,
                Uuid::new_v4(),
                None,
                Some(&ports::PortAllocationConfig {
                    enable_auto_assign: true,
                    range_start: 20000,
                    range_end: 20010,
                }),
            )
            .await
            .unwrap();

        assert_eq!(decision.placements.len(), 1);
        assert_eq!(decision.placements[0].node_id, node.id);
        assert_eq!(decision.unplaced_replicas, 1);
    }

    #[tokio::test]
    async fn requires_public_ip_filters_private_nodes() {
        let db = setup_db().await;
        let scheduler = RoundRobinScheduler::new(db.clone());
        let private = nodes::create_node(&db, ready_node("private", None))
            .await
            .unwrap();
        let public = nodes::create_node(&db, ready_public_node("public", None))
            .await
            .unwrap();

        let constraints = PlacementConstraints {
            requires_public_ip: true,
            ..Default::default()
        };

        let decision = scheduler
            .schedule_replicas(
                1,
                Some(&constraints),
                None,
                None,
                Uuid::new_v4(),
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(decision.compatible_nodes, 1);
        assert_eq!(decision.ready_nodes, 1);
        assert_eq!(decision.total_nodes, 2);
        assert_eq!(decision.unplaced_replicas, 0);
        let placed = decision
            .placements
            .first()
            .expect("expected placement")
            .node_id;
        assert_eq!(placed, public.id);
        assert_ne!(placed, private.id);
    }

    #[tokio::test]
    async fn requires_public_ip_reports_no_public_nodes() {
        let db = setup_db().await;
        let scheduler = RoundRobinScheduler::new(db.clone());
        nodes::create_node(&db, ready_node("private-a", None))
            .await
            .unwrap();
        nodes::create_node(&db, ready_node("private-b", None))
            .await
            .unwrap();

        let constraints = PlacementConstraints {
            requires_public_ip: true,
            ..Default::default()
        };

        let decision = scheduler
            .schedule_replicas(
                1,
                Some(&constraints),
                None,
                None,
                Uuid::new_v4(),
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(decision.compatible_nodes, 0);
        assert_eq!(decision.ready_nodes, 0);
        assert_eq!(decision.total_nodes, 2);
        assert_eq!(decision.unplaced_replicas, 1);
        assert!(decision.placements.is_empty());
    }
}
