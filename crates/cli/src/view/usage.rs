use ::common::api::{Page, UsageRollup};

use super::format::{format_bytes_i64, format_cpu_percent, format_timestamp, format_uuid};
use super::table::render_table;
use crate::OutputMode;
use crate::view::{to_pretty_json, to_pretty_yaml};

pub fn render_usage_table(rollups: &[UsageRollup]) -> String {
    let headers = [
        "TIME",
        "DEPLOYMENT",
        "NODE",
        "REPLICA",
        "CPU",
        "MEM",
        "RX",
        "TX",
    ];
    let rows = rollups
        .iter()
        .map(|rollup| {
            vec![
                format_timestamp(Some(rollup.bucket_start)),
                format_uuid(rollup.deployment_id, true),
                format_uuid(rollup.node_id, true),
                rollup.replica_number.to_string(),
                format_cpu_percent(rollup.avg_cpu_percent),
                format_bytes_i64(rollup.avg_memory_bytes),
                format_bytes_i64(rollup.avg_network_rx_bytes),
                format_bytes_i64(rollup.avg_network_tx_bytes),
            ]
        })
        .collect::<Vec<_>>();

    render_table(&headers, &rows)
}

pub fn format_usage_output(
    page: &Page<UsageRollup>,
    mode: OutputMode,
    filters: &str,
) -> anyhow::Result<String> {
    match mode {
        OutputMode::Table => Ok(if page.items.is_empty() {
            format!("no usage data found for {}", filters)
        } else {
            render_usage_table(&page.items)
        }),
        OutputMode::Json => Ok(to_pretty_json(page)?),
        OutputMode::Yaml => Ok(to_pretty_yaml(page)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    #[test]
    fn renders_usage_table_with_units() {
        let rollups = vec![UsageRollup {
            deployment_id: Uuid::from_u128(1),
            node_id: Uuid::from_u128(2),
            replica_number: 0,
            bucket_start: Utc.with_ymd_and_hms(2024, 2, 3, 4, 5, 6).unwrap(),
            samples: 3,
            avg_cpu_percent: 55.5,
            avg_memory_bytes: 512 * 1024 * 1024,
            avg_network_rx_bytes: 1024,
            avg_network_tx_bytes: 2048,
            avg_blk_read_bytes: None,
            avg_blk_write_bytes: None,
        }];

        let output = render_usage_table(&rollups);
        assert!(output.contains("TIME"));
        assert!(output.contains("DEPLOYMENT"));
        assert!(output.contains("55.5%"));
        assert!(output.contains("512Mi"));
        assert!(output.contains("1Ki"));
        assert!(output.contains("2Ki"));
    }

    #[test]
    fn usage_json_includes_rollups() {
        let rollup = UsageRollup {
            deployment_id: Uuid::from_u128(3),
            node_id: Uuid::from_u128(4),
            replica_number: 1,
            bucket_start: Utc.with_ymd_and_hms(2024, 6, 1, 1, 1, 1).unwrap(),
            samples: 5,
            avg_cpu_percent: 12.0,
            avg_memory_bytes: 256 * 1024 * 1024,
            avg_network_rx_bytes: 512,
            avg_network_tx_bytes: 1024,
            avg_blk_read_bytes: None,
            avg_blk_write_bytes: None,
        };
        let page = Page {
            limit: 10,
            offset: 0,
            items: vec![rollup],
        };

        let json = to_pretty_json(&page).unwrap();
        assert!(json.contains("avg_cpu_percent"));
        assert!(json.contains("deployment_id"));
        assert!(json.contains("avg_memory_bytes"));
        assert!(json.contains("268435456"));
    }

    #[test]
    fn usage_output_reports_empty_state_in_table_mode() {
        let page: Page<UsageRollup> = Page {
            limit: 5,
            offset: 0,
            items: Vec::new(),
        };

        let output = format_usage_output(&page, OutputMode::Table, "deployment=abcd").unwrap();
        assert_eq!(output, "no usage data found for deployment=abcd");
    }

    #[test]
    fn usage_output_serializes_json_mode() {
        let rollup = UsageRollup {
            deployment_id: Uuid::from_u128(9),
            node_id: Uuid::from_u128(8),
            replica_number: 1,
            bucket_start: Utc.with_ymd_and_hms(2024, 7, 1, 0, 0, 0).unwrap(),
            samples: 2,
            avg_cpu_percent: 4.5,
            avg_memory_bytes: 1024,
            avg_network_rx_bytes: 2048,
            avg_network_tx_bytes: 4096,
            avg_blk_read_bytes: Some(512),
            avg_blk_write_bytes: None,
        };
        let page = Page {
            limit: 1,
            offset: 0,
            items: vec![rollup.clone()],
        };

        let output = format_usage_output(&page, OutputMode::Json, "deployment=abcd").unwrap();
        assert!(output.contains(&rollup.deployment_id.to_string()));
        assert!(output.contains("avg_blk_read_bytes"));
        assert!(output.contains("4.5"));
    }
}
