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
}
