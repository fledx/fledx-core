use ::common::api::{DeploymentSummary, ReplicaAssignment};
use ratatui::{
    layout::Constraint,
    style::{Modifier, Style},
    widgets::{Cell, Row},
};
use std::collections::HashMap;
use uuid::Uuid;

use super::{
    format::{
        color_deployment_status, deployment_status_color, deployment_status_label,
        format_attached_configs, format_optional_uuid, format_placement_hint, format_timestamp,
        format_uuid,
    },
    status::status_cell,
    table::render_table,
    AttachedConfigInfo,
};

pub fn render_deployments_table(
    deployments: &[DeploymentSummary],
    deployment_configs: &HashMap<Uuid, Vec<AttachedConfigInfo>>,
    wide: bool,
    short_ids: bool,
    colorize: bool,
) -> String {
    let mut headers = vec![
        "ID",
        "NAME",
        "STATUS",
        "DESIRED",
        "CONFIGS",
        "GENERATION",
        "ASSIGNED_NODE",
    ];
    if wide {
        headers.insert(2, "REPLICAS");
        headers.push("ASSIGNMENTS");
        headers.push("IMAGE");
        headers.push("PLACEMENT");
        headers.push("LAST_REPORTED");
    }

    let mut rows = Vec::with_capacity(deployments.len());
    for deployment in deployments {
        let mut row = vec![
            format_uuid(deployment.deployment_id, short_ids),
            deployment.name.clone(),
            color_deployment_status(deployment.status, colorize),
            deployment.desired_state.as_str().to_string(),
            format_attached_configs(
                deployment_configs
                    .get(&deployment.deployment_id)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
                short_ids,
            ),
            deployment.generation.to_string(),
            format_optional_uuid(deployment.assigned_node_id, short_ids),
        ];
        if wide {
            row.insert(2, deployment.replicas.to_string());
            row.push(format_assignments(
                &deployment.assignments,
                deployment.assigned_node_id,
                short_ids,
            ));
            row.push(deployment.image.clone());
            row.push(format_placement_hint(&deployment.placement, short_ids));
            row.push(format_timestamp(deployment.last_reported));
        }

        rows.push(row);
    }

    render_table(&headers, &rows)
}

pub fn format_assignments(
    assignments: &[ReplicaAssignment],
    assigned_node_id: Option<Uuid>,
    short_ids: bool,
) -> String {
    if assignments.is_empty() {
        return format_optional_uuid(assigned_node_id, short_ids);
    }

    let mut parts: Vec<String> = assignments
        .iter()
        .map(|a| {
            format!(
                "r{}={}",
                a.replica_number,
                format_uuid(a.node_id, short_ids)
            )
        })
        .collect();
    parts.sort();
    parts.join(",")
}

pub fn deployment_table_rows(
    deployments: &[DeploymentSummary],
    deployment_configs: &HashMap<Uuid, Vec<AttachedConfigInfo>>,
    wide: bool,
    short_ids: bool,
    colorize: bool,
) -> Vec<Row<'static>> {
    deployments
        .iter()
        .map(|deployment| {
            let mut cells = vec![
                Cell::from(format_uuid(deployment.deployment_id, short_ids)),
                Cell::from(deployment.name.clone()),
                status_cell(
                    deployment_status_label(deployment.status),
                    deployment_status_color(deployment.status, colorize),
                ),
                Cell::from(deployment.desired_state.as_str().to_string()),
                Cell::from(format_attached_configs(
                    deployment_configs
                        .get(&deployment.deployment_id)
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]),
                    short_ids,
                )),
                Cell::from(deployment.generation.to_string()),
                Cell::from(format_optional_uuid(deployment.assigned_node_id, short_ids)),
            ];
            if wide {
                cells.insert(2, Cell::from(deployment.replicas.to_string()));
                cells.push(Cell::from(format_assignments(
                    &deployment.assignments,
                    deployment.assigned_node_id,
                    short_ids,
                )));
                cells.push(Cell::from(deployment.image.clone()));
                cells.push(Cell::from(format_placement_hint(
                    &deployment.placement,
                    short_ids,
                )));
                cells.push(Cell::from(format_timestamp(deployment.last_reported)));
            }
            Row::new(cells)
        })
        .collect()
}

pub fn deployment_table_header(wide: bool) -> Row<'static> {
    let mut headers = vec![
        Cell::from("ID"),
        Cell::from("NAME"),
        Cell::from("STATUS"),
        Cell::from("DESIRED"),
        Cell::from("CONFIGS"),
        Cell::from("GENERATION"),
        Cell::from("ASSIGNED_NODE"),
    ];
    if wide {
        headers.insert(2, Cell::from("REPLICAS"));
        headers.push(Cell::from("ASSIGNMENTS"));
        headers.push(Cell::from("IMAGE"));
        headers.push(Cell::from("PLACEMENT"));
        headers.push(Cell::from("LAST_REPORTED"));
    }
    Row::new(headers).style(Style::default().add_modifier(Modifier::BOLD))
}

pub fn deployment_table_constraints(wide: bool) -> Vec<Constraint> {
    let mut cols = vec![
        Constraint::Length(10),
        Constraint::Length(16),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Percentage(28),
        Constraint::Length(10),
        Constraint::Length(14),
    ];
    if wide {
        cols.insert(2, Constraint::Length(10));
        cols.push(Constraint::Percentage(25));
        cols.push(Constraint::Length(24));
        cols.push(Constraint::Length(22));
        cols.push(Constraint::Length(22));
    }
    cols
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use common::api::{DeploymentStatus, DeploymentSummary, DesiredState};
    use std::collections::HashMap;

    #[test]
    fn renders_deployments_table_includes_status_and_assignment() {
        let deployment_id = Uuid::from_u128(1);
        let node_id = Uuid::from_u128(2);
        let deployments = vec![DeploymentSummary {
            deployment_id,
            name: "app".to_string(),
            image: "nginx:alpine".to_string(),
            replicas: 2,
            desired_state: DesiredState::Running,
            status: DeploymentStatus::Deploying,
            assigned_node_id: Some(node_id),
            assignments: vec![
                ReplicaAssignment {
                    replica_number: 0,
                    node_id,
                },
                ReplicaAssignment {
                    replica_number: 1,
                    node_id,
                },
            ],
            generation: 3,
            tunnel_only: false,
            placement: None,
            volumes: None,
            last_reported: Some(chrono::Utc.with_ymd_and_hms(2024, 5, 6, 7, 8, 9).unwrap()),
        }];

        let output = render_deployments_table(&deployments, &HashMap::new(), true, false, false);
        assert!(output.contains(&deployment_id.to_string()));
        assert!(output.contains("deploying"));
        assert!(output.contains("running"));
        assert!(output.contains("r0=") && output.contains("r1="));
        assert!(output.contains("3"));
        assert!(output.contains("nginx:alpine"));
    }

    #[test]
    fn renders_deployments_table_short_ids_assignments() {
        let deployments = vec![DeploymentSummary {
            deployment_id: Uuid::from_u128(1),
            name: "app".to_string(),
            image: "nginx:alpine".to_string(),
            replicas: 2,
            desired_state: DesiredState::Running,
            status: DeploymentStatus::Running,
            assigned_node_id: None,
            assignments: vec![
                ReplicaAssignment {
                    replica_number: 0,
                    node_id: Uuid::from_u128(2),
                },
                ReplicaAssignment {
                    replica_number: 1,
                    node_id: Uuid::from_u128(3),
                },
            ],
            generation: 1,
            tunnel_only: false,
            placement: None,
            volumes: None,
            last_reported: None,
        }];

        let output = render_deployments_table(&deployments, &HashMap::new(), true, true, false);
        assert!(output.contains("r0="));
        assert!(output.contains("r1="));
        assert!(output.contains("running"));
    }
}
