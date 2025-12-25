use std::collections::HashMap;

use bollard::models::{
    ContainerNetworkStats, ContainerState, ContainerStateStatusEnum, ContainerStatsResponse,
    PortBinding, PortMap,
};

use crate::runtime::{ContainerStatus, FileMount, PortMapping};

pub(crate) type ExposedPorts = HashMap<String, HashMap<(), ()>>;

pub(crate) fn format_env(env: &[(String, String)]) -> Option<Vec<String>> {
    if env.is_empty() {
        None
    } else {
        Some(env.iter().map(|(k, v)| format!("{k}={v}")).collect())
    }
}

pub(crate) fn build_mounts(mounts: &[FileMount]) -> Option<Vec<String>> {
    if mounts.is_empty() {
        None
    } else {
        Some(
            mounts
                .iter()
                .map(|mount| {
                    let mode = if mount.readonly { "ro" } else { "rw" };
                    format!("{}:{}:{}", mount.host_path, mount.container_path, mode)
                })
                .collect(),
        )
    }
}

pub(crate) fn build_ports(ports: &[PortMapping]) -> (Option<PortMap>, Option<ExposedPorts>) {
    if ports.is_empty() {
        return (None, None);
    }

    let mut port_bindings: PortMap = HashMap::new();
    let mut exposed_ports: HashMap<String, HashMap<(), ()>> = HashMap::new();

    for mapping in ports {
        let key = format!("{}/{}", mapping.container_port, mapping.protocol.as_str());
        exposed_ports.entry(key.clone()).or_default();

        let entry = port_bindings.entry(key).or_insert_with(|| Some(Vec::new()));
        if let Some(bindings) = entry.as_mut() {
            bindings.push(PortBinding {
                host_ip: mapping.host_ip.clone(),
                host_port: Some(mapping.host_port.to_string()),
            });
        }
    }

    (Some(port_bindings), Some(exposed_ports))
}

pub(crate) fn map_status(state: Option<&ContainerState>) -> ContainerStatus {
    if let Some(state) = state {
        match state.status.as_ref() {
            Some(ContainerStateStatusEnum::RUNNING) => ContainerStatus::Running,
            Some(ContainerStateStatusEnum::EXITED) => ContainerStatus::Exited {
                exit_code: state.exit_code,
            },
            Some(other) => ContainerStatus::Unknown(other.to_string()),
            None => ContainerStatus::Unknown("unknown".into()),
        }
    } else {
        ContainerStatus::Unknown("unknown".into())
    }
}

pub(crate) fn calculate_cpu_percent(stats: &ContainerStatsResponse) -> Option<f64> {
    let cpu = stats.cpu_stats.as_ref()?;
    let pre = stats.precpu_stats.as_ref()?;

    let cpu_total = cpu.cpu_usage.as_ref()?.total_usage?;
    let pre_total = pre.cpu_usage.as_ref()?.total_usage?;
    let cpu_delta = cpu_total.saturating_sub(pre_total);

    let system_delta = cpu
        .system_cpu_usage
        .unwrap_or_default()
        .saturating_sub(pre.system_cpu_usage.unwrap_or_default());

    if cpu_delta == 0 || system_delta == 0 {
        return None;
    }

    let cpu_count = cpu
        .online_cpus
        .or_else(|| {
            cpu.cpu_usage
                .as_ref()?
                .percpu_usage
                .as_ref()
                .map(|v| v.len() as u32)
        })
        .unwrap_or(1);

    Some((cpu_delta as f64 / system_delta as f64) * cpu_count as f64 * 100.0)
}

pub(crate) fn network_bytes(
    stats: &ContainerStatsResponse,
    selector: impl Fn(&ContainerNetworkStats) -> Option<u64>,
) -> u64 {
    stats
        .networks
        .as_ref()
        .map(|map| map.values().filter_map(selector).sum())
        .unwrap_or_default()
}

pub(crate) fn blkio_bytes(stats: &ContainerStatsResponse, op: &str) -> Option<u64> {
    let entries = stats
        .blkio_stats
        .as_ref()?
        .io_service_bytes_recursive
        .as_ref()?;

    let op_lower = op.to_ascii_lowercase();
    let total: u64 = entries
        .iter()
        .filter(|entry| {
            entry
                .op
                .as_deref()
                .map(|value| value.to_ascii_lowercase() == op_lower)
                .unwrap_or(false)
        })
        .filter_map(|entry| entry.value)
        .sum();

    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::PortProtocol;
    use bollard::models::{
        ContainerBlkioStatEntry, ContainerBlkioStats, ContainerCpuStats, ContainerCpuUsage,
        ContainerNetworkStats,
    };
    use std::collections::HashMap;

    #[test]
    fn port_map_builds_expected_keys() {
        let mappings = vec![
            PortMapping {
                container_port: 80,
                host_port: 8080,
                protocol: PortProtocol::Tcp,
                host_ip: Some("127.0.0.1".into()),
            },
            PortMapping {
                container_port: 53,
                host_port: 5353,
                protocol: PortProtocol::Udp,
                host_ip: None,
            },
        ];

        let (bindings, exposed) = build_ports(&mappings);

        let bindings = bindings.expect("bindings");
        let exposed = exposed.expect("exposed");

        assert!(bindings.contains_key("80/tcp"));
        assert!(bindings.contains_key("53/udp"));
        assert!(exposed.contains_key("80/tcp"));
        assert!(exposed.contains_key("53/udp"));
    }

    #[test]
    fn format_env_returns_none_for_empty() {
        assert_eq!(format_env(&[]), None);
    }

    #[test]
    fn format_env_formats_key_value_pairs() {
        let env = vec![("API_KEY".to_string(), "secret".to_string())];
        let rendered = format_env(&env).expect("formatted env");
        assert_eq!(rendered, vec!["API_KEY=secret".to_string()]);
    }

    #[test]
    fn build_mounts_returns_none_for_empty() {
        assert_eq!(build_mounts(&[]), None);
    }

    #[test]
    fn build_mounts_formats_rw_and_ro() {
        let mounts = vec![
            FileMount {
                host_path: "/host/data".to_string(),
                container_path: "/data".to_string(),
                readonly: false,
            },
            FileMount {
                host_path: "/host/config".to_string(),
                container_path: "/config".to_string(),
                readonly: true,
            },
        ];

        let rendered = build_mounts(&mounts).expect("mounts");
        assert_eq!(
            rendered,
            vec![
                "/host/data:/data:rw".to_string(),
                "/host/config:/config:ro".to_string()
            ]
        );
    }

    #[test]
    fn map_status_handles_running_and_exited() {
        let running = ContainerState {
            status: Some(ContainerStateStatusEnum::RUNNING),
            ..Default::default()
        };
        assert_eq!(map_status(Some(&running)), ContainerStatus::Running);

        let exited = ContainerState {
            status: Some(ContainerStateStatusEnum::EXITED),
            exit_code: Some(137),
            ..Default::default()
        };
        assert_eq!(
            map_status(Some(&exited)),
            ContainerStatus::Exited {
                exit_code: Some(137)
            }
        );
    }

    #[test]
    fn map_status_falls_back_to_unknown() {
        let paused = ContainerState {
            status: Some(ContainerStateStatusEnum::PAUSED),
            ..Default::default()
        };
        assert_eq!(
            map_status(Some(&paused)),
            ContainerStatus::Unknown("paused".into())
        );

        let missing_status = ContainerState {
            status: None,
            ..Default::default()
        };
        assert_eq!(
            map_status(Some(&missing_status)),
            ContainerStatus::Unknown("unknown".into())
        );
        assert_eq!(map_status(None), ContainerStatus::Unknown("unknown".into()));
    }

    fn stats_with_cpu(
        cpu_total: u64,
        pre_total: u64,
        system_total: u64,
        pre_system_total: u64,
        online_cpus: Option<u32>,
        percpu_len: Option<usize>,
    ) -> ContainerStatsResponse {
        let percpu_usage = percpu_len.map(|len| vec![0_u64; len]);
        ContainerStatsResponse {
            cpu_stats: Some(ContainerCpuStats {
                cpu_usage: Some(ContainerCpuUsage {
                    total_usage: Some(cpu_total),
                    percpu_usage,
                    ..Default::default()
                }),
                system_cpu_usage: Some(system_total),
                online_cpus,
                ..Default::default()
            }),
            precpu_stats: Some(ContainerCpuStats {
                cpu_usage: Some(ContainerCpuUsage {
                    total_usage: Some(pre_total),
                    ..Default::default()
                }),
                system_cpu_usage: Some(pre_system_total),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn calculate_cpu_percent_uses_online_cpus_when_set() {
        let stats = stats_with_cpu(2000, 1000, 10_000, 9_000, Some(2), None);
        let percent = calculate_cpu_percent(&stats).expect("cpu percent");
        assert!((percent - 200.0).abs() < 0.0001);
    }

    #[test]
    fn calculate_cpu_percent_falls_back_to_percpu_len() {
        let stats = stats_with_cpu(2000, 1000, 10_000, 9_000, None, Some(4));
        let percent = calculate_cpu_percent(&stats).expect("cpu percent");
        assert!((percent - 400.0).abs() < 0.0001);
    }

    #[test]
    fn calculate_cpu_percent_returns_none_when_deltas_zero() {
        let stats = stats_with_cpu(1000, 1000, 10_000, 9_000, Some(2), None);
        assert_eq!(calculate_cpu_percent(&stats), None);

        let empty = ContainerStatsResponse::default();
        assert_eq!(calculate_cpu_percent(&empty), None);
    }

    #[test]
    fn network_bytes_sums_selected_fields() {
        let mut networks = HashMap::new();
        networks.insert(
            "eth0".to_string(),
            ContainerNetworkStats {
                rx_bytes: Some(100),
                tx_bytes: Some(200),
                ..Default::default()
            },
        );
        networks.insert(
            "eth1".to_string(),
            ContainerNetworkStats {
                rx_bytes: Some(50),
                tx_bytes: None,
                ..Default::default()
            },
        );

        let stats = ContainerStatsResponse {
            networks: Some(networks),
            ..Default::default()
        };

        assert_eq!(network_bytes(&stats, |net| net.rx_bytes), 150);
        assert_eq!(network_bytes(&stats, |net| net.tx_bytes), 200);
    }

    #[test]
    fn network_bytes_returns_zero_for_missing_stats() {
        let stats = ContainerStatsResponse::default();
        assert_eq!(network_bytes(&stats, |net| net.rx_bytes), 0);
    }

    #[test]
    fn blkio_bytes_filters_ops_case_insensitively() {
        let stats = ContainerStatsResponse {
            blkio_stats: Some(ContainerBlkioStats {
                io_service_bytes_recursive: Some(vec![
                    ContainerBlkioStatEntry {
                        op: Some("Read".to_string()),
                        value: Some(12),
                        ..Default::default()
                    },
                    ContainerBlkioStatEntry {
                        op: Some("write".to_string()),
                        value: Some(7),
                        ..Default::default()
                    },
                    ContainerBlkioStatEntry {
                        op: None,
                        value: Some(99),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(blkio_bytes(&stats, "read"), Some(12));
        assert_eq!(blkio_bytes(&stats, "WRITE"), Some(7));
    }

    #[test]
    fn blkio_bytes_returns_none_when_missing_stats() {
        let stats = ContainerStatsResponse::default();
        assert_eq!(blkio_bytes(&stats, "read"), None);
    }
}
