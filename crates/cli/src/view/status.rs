use ::common::api::{DeploymentSummary, NodeSummary, Page};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    prelude::*,
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Paragraph, Table},
    Frame,
};
use serde::Serialize;

use super::{
    deployments::{
        deployment_table_constraints, deployment_table_header, deployment_table_rows,
        render_deployments_table,
    },
    format::{color_deployment_status, color_node_status},
    nodes::{node_table_constraints, node_table_header, node_table_rows, render_nodes_table},
    AttachedConfigInfo, ConfigAttachmentLookup,
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeStatusCounts {
    pub ready: usize,
    pub unreachable: usize,
    pub error: usize,
    pub registering: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DeploymentStatusCounts {
    pub pending: usize,
    pub deploying: usize,
    pub running: usize,
    pub stopped: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusSummary {
    pub nodes: NodeStatusCounts,
    pub deployments: DeploymentStatusCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatusView {
    #[serde(flatten)]
    pub node: NodeSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configs: Vec<AttachedConfigInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentStatusView {
    #[serde(flatten)]
    pub deployment: DeploymentSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configs: Vec<AttachedConfigInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusOutputView {
    pub summary: StatusSummary,
    pub nodes: Page<NodeStatusView>,
    pub deployments: Page<DeploymentStatusView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusOutput {
    pub summary: StatusSummary,
    pub nodes: Page<NodeSummary>,
    pub deployments: Page<DeploymentSummary>,
    #[serde(flatten)]
    pub attachments: ConfigAttachmentLookup,
}

pub fn status_output_view(output: &StatusOutput) -> StatusOutputView {
    let nodes = Page {
        limit: output.nodes.limit,
        offset: output.nodes.offset,
        items: output
            .nodes
            .items
            .iter()
            .map(|node| NodeStatusView {
                node: node.clone(),
                configs: output
                    .attachments
                    .node_configs
                    .get(&node.node_id)
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect(),
    };

    let deployments = Page {
        limit: output.deployments.limit,
        offset: output.deployments.offset,
        items: output
            .deployments
            .items
            .iter()
            .map(|deployment| DeploymentStatusView {
                deployment: deployment.clone(),
                configs: output
                    .attachments
                    .deployment_configs
                    .get(&deployment.deployment_id)
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect(),
    };

    StatusOutputView {
        summary: output.summary.clone(),
        nodes,
        deployments,
    }
}

pub fn compute_summary(nodes: &[NodeSummary], deployments: &[DeploymentSummary]) -> StatusSummary {
    let mut node_counts = NodeStatusCounts {
        ready: 0,
        unreachable: 0,
        error: 0,
        registering: 0,
    };
    for node in nodes {
        match node.status {
            common::api::NodeStatus::Ready => node_counts.ready += 1,
            common::api::NodeStatus::Unreachable => node_counts.unreachable += 1,
            common::api::NodeStatus::Error => node_counts.error += 1,
            common::api::NodeStatus::Registering => node_counts.registering += 1,
        }
    }

    let mut deploy_counts = DeploymentStatusCounts {
        pending: 0,
        deploying: 0,
        running: 0,
        stopped: 0,
        failed: 0,
    };
    for deployment in deployments {
        match deployment.status {
            common::api::DeploymentStatus::Pending => deploy_counts.pending += 1,
            common::api::DeploymentStatus::Deploying => deploy_counts.deploying += 1,
            common::api::DeploymentStatus::Running => deploy_counts.running += 1,
            common::api::DeploymentStatus::Stopped => deploy_counts.stopped += 1,
            common::api::DeploymentStatus::Failed => deploy_counts.failed += 1,
        }
    }

    StatusSummary {
        nodes: node_counts,
        deployments: deploy_counts,
    }
}

pub fn render_summary(
    summary: &StatusSummary,
    colorize: bool,
    include_nodes: bool,
    include_deploys: bool,
) -> String {
    let mut parts = Vec::new();
    if include_nodes {
        parts.push(format!(
            "Nodes: {}={} {}={} {}={} {}={}",
            color_node_status(common::api::NodeStatus::Ready, colorize),
            summary.nodes.ready,
            color_node_status(common::api::NodeStatus::Unreachable, colorize),
            summary.nodes.unreachable,
            color_node_status(common::api::NodeStatus::Error, colorize),
            summary.nodes.error,
            color_node_status(common::api::NodeStatus::Registering, colorize),
            summary.nodes.registering
        ));
    }

    if include_deploys {
        parts.push(format!(
            "Deployments: {}={} {}={} {}={} {}={} {}={}",
            color_deployment_status(common::api::DeploymentStatus::Running, colorize),
            summary.deployments.running,
            color_deployment_status(common::api::DeploymentStatus::Stopped, colorize),
            summary.deployments.stopped,
            color_deployment_status(common::api::DeploymentStatus::Failed, colorize),
            summary.deployments.failed,
            color_deployment_status(common::api::DeploymentStatus::Pending, colorize),
            summary.deployments.pending,
            color_deployment_status(common::api::DeploymentStatus::Deploying, colorize),
            summary.deployments.deploying
        ));
    }

    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ratatui::{backend::TestBackend, Terminal};
    use uuid::Uuid;

    #[test]
    fn computes_summary_counts() {
        let nodes = vec![
            NodeSummary {
                node_id: Uuid::from_u128(10),
                name: None,
                status: common::api::NodeStatus::Ready,
                last_seen: None,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
            },
            NodeSummary {
                node_id: Uuid::from_u128(11),
                name: None,
                status: common::api::NodeStatus::Unreachable,
                last_seen: None,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
            },
        ];
        let deployments = vec![
            DeploymentSummary {
                deployment_id: Uuid::from_u128(1),
                name: "api".into(),
                image: "nginx".into(),
                replicas: 1,
                desired_state: common::api::DesiredState::Running,
                status: common::api::DeploymentStatus::Running,
                assigned_node_id: None,
                assignments: vec![],
                generation: 1,
                tunnel_only: false,
                placement: None,
                volumes: None,
                last_reported: None,
            },
            DeploymentSummary {
                deployment_id: Uuid::from_u128(2),
                name: "worker".into(),
                image: "busybox".into(),
                replicas: 1,
                desired_state: common::api::DesiredState::Running,
                status: common::api::DeploymentStatus::Failed,
                assigned_node_id: None,
                assignments: vec![],
                generation: 1,
                tunnel_only: false,
                placement: None,
                volumes: None,
                last_reported: None,
            },
        ];

        let summary = compute_summary(&nodes, &deployments);
        assert_eq!(
            summary,
            StatusSummary {
                nodes: NodeStatusCounts {
                    ready: 1,
                    unreachable: 1,
                    error: 0,
                    registering: 0,
                },
                deployments: DeploymentStatusCounts {
                    pending: 0,
                    deploying: 0,
                    running: 1,
                    stopped: 0,
                    failed: 1,
                }
            }
        );

        let rendered = render_summary(&summary, false, true, true);
        assert!(rendered.contains("Nodes: ready=1"));
        assert!(rendered.contains("Deployments: running=1"));
    }

    #[test]
    fn status_output_json_structure() {
        let nodes = Page {
            limit: 1,
            offset: 0,
            items: vec![NodeSummary {
                node_id: Uuid::from_u128(100),
                name: Some("edge-1".into()),
                status: common::api::NodeStatus::Ready,
                last_seen: None,
                arch: Some("amd64".into()),
                os: Some("linux".into()),
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
            }],
        };
        let deployments = Page {
            limit: 1,
            offset: 0,
            items: vec![DeploymentSummary {
                deployment_id: Uuid::from_u128(200),
                name: "api".into(),
                image: "nginx".into(),
                replicas: 1,
                desired_state: common::api::DesiredState::Running,
                status: common::api::DeploymentStatus::Running,
                assigned_node_id: None,
                assignments: vec![],
                generation: 1,
                tunnel_only: false,
                placement: None,
                volumes: None,
                last_reported: None,
            }],
        };
        let summary = compute_summary(&nodes.items, &deployments.items);
        let mut attachments = ConfigAttachmentLookup::default();
        let cfg = AttachedConfigInfo {
            config_id: Uuid::from_u128(300),
            name: "app-config".into(),
            version: 2,
            updated_at: chrono::Utc.with_ymd_and_hms(2024, 2, 1, 0, 0, 0).unwrap(),
        };
        attachments
            .node_configs
            .insert(nodes.items[0].node_id, vec![cfg.clone()]);
        attachments
            .deployment_configs
            .insert(deployments.items[0].deployment_id, vec![cfg.clone()]);
        let output = StatusOutput {
            summary,
            nodes,
            deployments,
            attachments,
        };

        let json = crate::view::to_pretty_json(&status_output_view(&output)).unwrap();
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"nodes\""));
        assert!(json.contains("\"deployments\""));
        assert!(json.contains("edge-1"));
        assert!(json.contains("nginx"));
        assert!(json.contains("app-config"));
        assert!(json.contains("version"));
    }

    #[test]
    fn render_summary_colorizes_when_enabled() {
        let summary = StatusSummary {
            nodes: NodeStatusCounts {
                ready: 1,
                unreachable: 0,
                error: 0,
                registering: 0,
            },
            deployments: DeploymentStatusCounts {
                pending: 0,
                deploying: 0,
                running: 1,
                stopped: 0,
                failed: 0,
            },
        };
        let rendered = render_summary(&summary, true, true, true);
        assert!(rendered.contains("\u{1b}[32mready"));
        assert!(rendered.contains("\u{1b}[32mrunning"));
    }

    #[test]
    fn render_summary_respects_filters() {
        let summary = StatusSummary {
            nodes: NodeStatusCounts {
                ready: 2,
                unreachable: 1,
                error: 0,
                registering: 0,
            },
            deployments: DeploymentStatusCounts {
                pending: 0,
                deploying: 0,
                running: 5,
                stopped: 0,
                failed: 0,
            },
        };

        let nodes_only = render_summary(&summary, false, true, false);
        assert!(nodes_only.contains("Nodes:"));
        assert!(!nodes_only.contains("Deployments:"));

        let deploys_only = render_summary(&summary, false, false, true);
        assert!(!deploys_only.contains("Nodes:"));
        assert!(deploys_only.contains("Deployments:"));
    }

    fn base_status_output() -> StatusOutput {
        let nodes = Page {
            limit: 1,
            offset: 0,
            items: vec![NodeSummary {
                node_id: Uuid::from_u128(10),
                name: Some("edge-1".into()),
                status: common::api::NodeStatus::Ready,
                last_seen: None,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
            }],
        };
        let deployments = Page {
            limit: 1,
            offset: 0,
            items: vec![DeploymentSummary {
                deployment_id: Uuid::from_u128(20),
                name: "api".into(),
                image: "nginx".into(),
                replicas: 1,
                desired_state: common::api::DesiredState::Running,
                status: common::api::DeploymentStatus::Running,
                assigned_node_id: None,
                assignments: vec![],
                generation: 1,
                tunnel_only: false,
                placement: None,
                volumes: None,
                last_reported: None,
            }],
        };
        let summary = compute_summary(&nodes.items, &deployments.items);
        StatusOutput {
            summary,
            nodes,
            deployments,
            attachments: ConfigAttachmentLookup::default(),
        }
    }

    #[test]
    fn render_status_view_respects_include_flags() {
        let output = base_status_output();
        let nodes_only = render_status_view(&output, false, false, false, true, false);
        assert!(nodes_only.contains("Nodes:"));
        assert!(!nodes_only.contains("Deployments:"));

        let deploys_only = render_status_view(&output, false, false, false, false, true);
        assert!(!deploys_only.contains("Nodes:"));
        assert!(deploys_only.contains("Deployments:"));
    }

    #[test]
    fn status_cell_applies_color_when_provided() {
        let plain = status_cell("ok", None);
        let colored = status_cell("ok", Some(Color::Red));
        assert_eq!(plain, Cell::from("ok".to_string()));
        assert_eq!(
            colored,
            Cell::from("ok".to_string()).style(Style::default().fg(Color::Red))
        );
    }

    #[test]
    fn render_status_frame_renders_error_banner() {
        let output = base_status_output();
        let backend = TestBackend::new(80, 6);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|f| {
                render_status_frame(
                    f,
                    &output,
                    StatusRenderFlags {
                        include_nodes: false,
                        include_deploys: false,
                        wide: false,
                        colorize: false,
                        short_ids: false,
                    },
                    Some("boom"),
                );
            })
            .expect("draw");

        let buffer = terminal.backend().buffer();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
            content.push('\n');
        }
        assert!(content.contains("Error: boom"));
    }
}

pub fn render_status_view(
    output: &StatusOutput,
    wide: bool,
    colorize: bool,
    short_ids: bool,
    include_nodes: bool,
    include_deploys: bool,
) -> String {
    let mut parts = vec![render_summary(
        &output.summary,
        colorize,
        include_nodes,
        include_deploys,
    )];

    if include_nodes {
        parts.push(String::new());
        parts.push("Nodes:".to_string());
        parts.push(render_nodes_table(
            &output.nodes.items,
            &output.attachments.node_configs,
            wide,
            short_ids,
            colorize,
        ));
    }

    if include_deploys {
        parts.push(String::new());
        parts.push("Deployments:".to_string());
        parts.push(render_deployments_table(
            &output.deployments.items,
            &output.attachments.deployment_configs,
            wide,
            short_ids,
            colorize,
        ));
    }

    parts.join("\n")
}

#[derive(Copy, Clone)]
pub struct StatusRenderFlags {
    pub include_nodes: bool,
    pub include_deploys: bool,
    pub wide: bool,
    pub colorize: bool,
    pub short_ids: bool,
}

pub fn status_cell(text: &str, color: Option<Color>) -> Cell<'static> {
    match color {
        Some(color) => Cell::from(text.to_string()).style(Style::default().fg(color)),
        None => Cell::from(text.to_string()),
    }
}

pub fn render_status_frame(
    frame: &mut Frame,
    output: &StatusOutput,
    flags: StatusRenderFlags,
    error: Option<&str>,
) {
    let mut constraints = Vec::new();
    constraints.push(Constraint::Length(if error.is_some() { 3 } else { 2 }));
    if flags.include_nodes {
        constraints.push(Constraint::Min(6));
    }
    if flags.include_deploys {
        constraints.push(Constraint::Min(6));
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    let header_lines = if let Some(err) = error {
        vec![
            Line::from(render_summary(
                &output.summary,
                flags.colorize,
                flags.include_nodes,
                flags.include_deploys,
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("Error: {err}"),
                Style::default().fg(Color::Red),
            )),
        ]
    } else {
        vec![Line::from(render_summary(
            &output.summary,
            flags.colorize,
            flags.include_nodes,
            flags.include_deploys,
        ))]
    };

    let header = Paragraph::new(header_lines).block(Block::default().borders(Borders::NONE));
    frame.render_widget(header, chunks[0]);
    let mut chunk_idx = 1;

    if flags.include_nodes {
        let rows = node_table_rows(
            &output.nodes.items,
            &output.attachments.node_configs,
            flags.wide,
            flags.short_ids,
            flags.colorize,
        );
        let table = Table::new(rows, node_table_constraints(flags.wide))
            .header(node_table_header(flags.wide))
            .block(Block::default().borders(Borders::ALL).title("Nodes"));
        frame.render_widget(table, chunks[chunk_idx]);
        chunk_idx += 1;
    }

    if flags.include_deploys {
        let rows = deployment_table_rows(
            &output.deployments.items,
            &output.attachments.deployment_configs,
            flags.wide,
            flags.short_ids,
            flags.colorize,
        );
        let table = Table::new(rows, deployment_table_constraints(flags.wide))
            .header(deployment_table_header(flags.wide))
            .block(Block::default().borders(Borders::ALL).title("Deployments"));
        frame.render_widget(table, chunks[chunk_idx]);
    }
}
