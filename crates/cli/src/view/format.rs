use ::common::api::{
    CapacityHints, DeploymentStatus, NodeStatus, PlacementAffinity, PlacementHints,
};
use chrono::{DateTime, SecondsFormat, Utc};
use ratatui::style::Color;
use uuid::Uuid;

use super::AttachedConfigInfo;

pub fn node_status_label(status: NodeStatus) -> &'static str {
    match status {
        NodeStatus::Ready => "ready",
        NodeStatus::Unreachable => "unreachable",
        NodeStatus::Error => "error",
        NodeStatus::Registering => "registering",
    }
}

pub fn deployment_status_label(status: DeploymentStatus) -> &'static str {
    status.as_str()
}

pub fn colorize(text: &str, code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

pub fn color_node_status(status: NodeStatus, enabled: bool) -> String {
    let label = node_status_label(status);
    match status {
        NodeStatus::Ready => colorize(label, "32", enabled),
        NodeStatus::Unreachable => colorize(label, "33", enabled),
        NodeStatus::Error => colorize(label, "31", enabled),
        NodeStatus::Registering => colorize(label, "36", enabled),
    }
}

pub fn color_deployment_status(status: DeploymentStatus, enabled: bool) -> String {
    let label = deployment_status_label(status);
    match status {
        DeploymentStatus::Running => colorize(label, "32", enabled),
        DeploymentStatus::Deploying => colorize(label, "33", enabled),
        DeploymentStatus::Pending => colorize(label, "36", enabled),
        DeploymentStatus::Stopped => colorize(label, "34", enabled),
        DeploymentStatus::Failed => colorize(label, "31", enabled),
    }
}

pub fn node_status_color(status: NodeStatus, enabled: bool) -> Option<Color> {
    if !enabled {
        return None;
    }
    let color = match status {
        NodeStatus::Ready => Color::Green,
        NodeStatus::Unreachable => Color::Yellow,
        NodeStatus::Error => Color::Red,
        NodeStatus::Registering => Color::Cyan,
    };
    Some(color)
}

pub fn deployment_status_color(status: DeploymentStatus, enabled: bool) -> Option<Color> {
    if !enabled {
        return None;
    }
    let color = match status {
        DeploymentStatus::Running => Color::Green,
        DeploymentStatus::Deploying => Color::Yellow,
        DeploymentStatus::Pending => Color::Cyan,
        DeploymentStatus::Stopped => Color::Blue,
        DeploymentStatus::Failed => Color::Red,
    };
    Some(color)
}

pub fn format_optional_str(value: Option<&str>) -> String {
    match value {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => "-".to_string(),
    }
}

pub fn format_timestamp(ts: Option<DateTime<Utc>>) -> String {
    ts.map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| "-".to_string())
}

pub fn format_redacted() -> String {
    "[redacted]".to_string()
}

pub fn format_uuid(id: Uuid, short: bool) -> String {
    if short {
        id.simple().to_string()[..8].to_string()
    } else {
        id.to_string()
    }
}

pub fn format_optional_uuid(value: Option<Uuid>, short: bool) -> String {
    value
        .map(|id| format_uuid(id, short))
        .unwrap_or_else(|| "-".to_string())
}

pub fn format_labels(labels: &Option<std::collections::HashMap<String, String>>) -> String {
    match labels {
        Some(map) if !map.is_empty() => {
            let mut parts: Vec<String> = map.iter().map(|(k, v)| format!("{k}={v}")).collect();
            parts.sort();
            parts.join(",")
        }
        _ => "-".to_string(),
    }
}

pub fn format_capacity(capacity: Option<&CapacityHints>) -> String {
    match capacity {
        Some(caps) => {
            let mut parts = Vec::new();
            if let Some(cpu) = caps.cpu_millis {
                parts.push(format!("cpu={}m", cpu));
            }
            if let Some(memory) = caps.memory_bytes {
                parts.push(format!("mem={}", format_bytes(memory)));
            }
            if parts.is_empty() {
                "-".to_string()
            } else {
                parts.join(" ")
            }
        }
        None => "-".to_string(),
    }
}

pub fn format_affinity_details(affinity: &PlacementAffinity, short_ids: bool) -> String {
    let mut parts = Vec::new();
    if !affinity.node_ids.is_empty() {
        let nodes = affinity
            .node_ids
            .iter()
            .map(|id| format_uuid(*id, short_ids))
            .collect::<Vec<_>>()
            .join(",");
        parts.push(format!("nodes={nodes}"));
    }
    if !affinity.labels.is_empty() {
        parts.push(format!(
            "labels={}",
            format_labels(&Some(affinity.labels.clone()))
        ));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

pub fn format_placement_hint(placement: &Option<PlacementHints>, short_ids: bool) -> String {
    let Some(placement) = placement else {
        return "-".to_string();
    };

    let mut parts = Vec::new();
    if let Some(affinity) = &placement.affinity {
        parts.push(format!(
            "aff({})",
            format_affinity_details(affinity, short_ids)
        ));
    }
    if let Some(anti) = &placement.anti_affinity {
        parts.push(format!(
            "anti({})",
            format_affinity_details(anti, short_ids)
        ));
    }
    if placement.spread {
        parts.push("spread".to_string());
    }

    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes.is_multiple_of(GIB) {
        format!("{}Gi", bytes / GIB)
    } else if bytes.is_multiple_of(MIB) {
        format!("{}Mi", bytes / MIB)
    } else if bytes.is_multiple_of(KIB) {
        format!("{}Ki", bytes / KIB)
    } else {
        format!("{}B", bytes)
    }
}

pub fn format_bytes_i64(value: i64) -> String {
    if value <= 0 {
        return "0B".to_string();
    }
    format_bytes(value as u64)
}

pub fn format_metric_count(value: f64) -> String {
    if !value.is_finite() {
        return value.to_string();
    }
    let fraction = (value - value.trunc()).abs();
    if fraction < 1e-6 {
        format!("{:.0}", value)
    } else {
        format!("{:.2}", value)
    }
}

pub fn format_cpu_percent(value: f64) -> String {
    if !value.is_finite() {
        return value.to_string();
    }
    let rounded = value.round();
    if (value - rounded).abs() < 0.05 {
        format!("{:.0}%", rounded)
    } else {
        format!("{:.1}%", value)
    }
}

pub fn format_attached_configs(configs: &[AttachedConfigInfo], short_ids: bool) -> String {
    if configs.is_empty() {
        return "-".to_string();
    }

    configs
        .iter()
        .map(|cfg| {
            format!(
                "{}@v{} [{} | {}]",
                cfg.name,
                cfg.version,
                format_uuid(cfg.config_id, short_ids),
                format_timestamp(Some(cfg.updated_at))
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_cpu_percent_rounds_expected() {
        assert_eq!(format_cpu_percent(10.02), "10%");
        assert_eq!(format_cpu_percent(10.26), "10.3%");
        assert_eq!(format_cpu_percent(f64::NAN), "NaN");
    }

    #[test]
    fn format_bytes_i64_clamps_non_positive() {
        assert_eq!(format_bytes_i64(-5), "0B");
        assert_eq!(format_bytes_i64(0), "0B");
        assert_eq!(format_bytes_i64(2048), "2Ki");
        assert_eq!(format_bytes_i64(1536), "1536B");
    }
}
