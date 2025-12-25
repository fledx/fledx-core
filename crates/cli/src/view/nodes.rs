use ::common::api::NodeSummary;
use ratatui::{
    layout::Constraint,
    style::{Modifier, Style},
    widgets::{Cell, Row},
};
use std::collections::HashMap;
use uuid::Uuid;

use super::{
    AttachedConfigInfo,
    format::{
        color_node_status, format_attached_configs, format_capacity, format_labels,
        format_optional_str, format_timestamp, format_uuid, node_status_color, node_status_label,
    },
    status::status_cell,
    table::render_table,
};

pub fn render_nodes_table(
    nodes: &[NodeSummary],
    node_configs: &HashMap<Uuid, Vec<AttachedConfigInfo>>,
    wide: bool,
    short_ids: bool,
    colorize: bool,
) -> String {
    let mut headers = vec!["ID", "NAME", "STATUS", "LAST_SEEN", "CONFIGS"];
    if wide {
        headers.push("ARCH");
        headers.push("OS");
        headers.push("LABELS");
        headers.push("CAPACITY");
    }

    let mut rows = Vec::with_capacity(nodes.len());
    for node in nodes {
        let mut row = vec![
            format_uuid(node.node_id, short_ids),
            format_optional_str(node.name.as_deref()),
            color_node_status(node.status, colorize),
            format_timestamp(node.last_seen),
            format_attached_configs(
                node_configs
                    .get(&node.node_id)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
                short_ids,
            ),
        ];

        if wide {
            row.push(format_optional_str(node.arch.as_deref()));
            row.push(format_optional_str(node.os.as_deref()));
            row.push(format_labels(&node.labels));
            row.push(format_capacity(node.capacity.as_ref()));
        }
        rows.push(row);
    }

    render_table(&headers, &rows)
}

pub fn node_table_rows(
    nodes: &[NodeSummary],
    node_configs: &HashMap<Uuid, Vec<AttachedConfigInfo>>,
    wide: bool,
    short_ids: bool,
    colorize: bool,
) -> Vec<Row<'static>> {
    nodes
        .iter()
        .map(|node| {
            let mut cells = vec![
                Cell::from(format_uuid(node.node_id, short_ids)),
                Cell::from(format_optional_str(node.name.as_deref())),
                status_cell(
                    node_status_label(node.status),
                    node_status_color(node.status, colorize),
                ),
                Cell::from(format_timestamp(node.last_seen)),
                Cell::from(format_attached_configs(
                    node_configs
                        .get(&node.node_id)
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]),
                    short_ids,
                )),
            ];
            if wide {
                cells.push(Cell::from(format_optional_str(node.arch.as_deref())));
                cells.push(Cell::from(format_optional_str(node.os.as_deref())));
                cells.push(Cell::from(format_labels(&node.labels)));
                cells.push(Cell::from(format_capacity(node.capacity.as_ref())));
            }
            Row::new(cells)
        })
        .collect()
}

pub fn node_table_header(wide: bool) -> Row<'static> {
    let mut headers = vec![
        Cell::from("ID"),
        Cell::from("NAME"),
        Cell::from("STATUS"),
        Cell::from("LAST_SEEN"),
        Cell::from("CONFIGS"),
    ];
    if wide {
        headers.push(Cell::from("ARCH"));
        headers.push(Cell::from("OS"));
        headers.push(Cell::from("LABELS"));
        headers.push(Cell::from("CAPACITY"));
    }
    Row::new(headers).style(Style::default().add_modifier(Modifier::BOLD))
}

pub fn node_table_constraints(wide: bool) -> Vec<Constraint> {
    let mut cols = vec![
        Constraint::Length(10),
        Constraint::Length(16),
        Constraint::Length(14),
        Constraint::Length(22),
        Constraint::Percentage(30),
    ];
    if wide {
        cols.push(Constraint::Length(10));
        cols.push(Constraint::Length(10));
        cols.push(Constraint::Percentage(30));
        cols.push(Constraint::Length(16));
    }
    cols
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn base_node(node_id: Uuid) -> NodeSummary {
        NodeSummary {
            node_id,
            name: None,
            status: common::api::NodeStatus::Ready,
            last_seen: None,
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
        }
    }

    #[test]
    fn renders_nodes_table_includes_labels_and_capacity() {
        let mut labels = HashMap::new();
        labels.insert("region".to_string(), "eu-west".to_string());
        labels.insert("role".to_string(), "edge".to_string());
        let nodes = vec![NodeSummary {
            node_id: Uuid::nil(),
            name: Some("edge-1".to_string()),
            status: common::api::NodeStatus::Ready,
            last_seen: Some(chrono::Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap()),
            arch: Some("amd64".to_string()),
            os: Some("linux".to_string()),
            public_ip: None,
            public_host: None,
            labels: Some(labels),
            capacity: Some(common::api::CapacityHints {
                cpu_millis: Some(750),
                memory_bytes: Some(1024 * 1024 * 1024),
            }),
        }];

        let output = render_nodes_table(&nodes, &HashMap::new(), true, false, false);
        assert!(output.contains("edge-1"));
        assert!(output.contains("ready"));
        assert!(output.contains("region=eu-west"));
        assert!(output.contains("role=edge"));
        assert!(output.contains("cpu=750m"));
        assert!(output.contains("mem=1Gi"));
    }

    #[test]
    fn renders_short_ids_when_requested() {
        let node_id = Uuid::from_u128(0xabcdef);
        let nodes = vec![NodeSummary {
            node_id,
            name: Some("shorty".into()),
            status: common::api::NodeStatus::Ready,
            last_seen: None,
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
        }];
        let output = render_nodes_table(&nodes, &HashMap::new(), false, true, true);
        assert!(output.contains(&node_id.simple().to_string()[..8]));
        assert!(!output.contains(&node_id.to_string()));
    }

    #[test]
    fn renders_nodes_table_narrow_omits_labels_and_capacity() {
        let mut labels = HashMap::new();
        labels.insert("region".to_string(), "eu-west".to_string());
        let mut node = base_node(Uuid::from_u128(1));
        node.labels = Some(labels);
        node.capacity = Some(common::api::CapacityHints {
            cpu_millis: Some(500),
            memory_bytes: Some(256 * 1024 * 1024),
        });

        let output = render_nodes_table(&[node], &HashMap::new(), false, false, false);
        assert!(!output.contains("region=eu-west"));
        assert!(!output.contains("cpu=500m"));
    }

    #[test]
    fn node_table_constraints_wide_increases_columns() {
        let narrow = node_table_constraints(false);
        let wide = node_table_constraints(true);
        assert!(wide.len() > narrow.len());
    }

    #[test]
    fn node_table_rows_len_matches_nodes() {
        let nodes = vec![base_node(Uuid::from_u128(1)), base_node(Uuid::from_u128(2))];
        let narrow_rows = node_table_rows(&nodes, &HashMap::new(), false, false, false);
        let wide_rows = node_table_rows(&nodes, &HashMap::new(), true, false, false);
        assert_eq!(narrow_rows.len(), nodes.len());
        assert_eq!(wide_rows.len(), nodes.len());
    }
}
