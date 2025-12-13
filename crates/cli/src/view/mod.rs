pub mod deployments;
pub mod format;
pub mod logs;
pub mod metrics;
pub mod nodes;
pub mod status;
pub mod table;
pub mod usage;

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct AttachedConfigInfo {
    pub config_id: Uuid,
    pub name: String,
    pub version: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ConfigAttachmentLookup {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub node_configs: HashMap<Uuid, Vec<AttachedConfigInfo>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub deployment_configs: HashMap<Uuid, Vec<AttachedConfigInfo>>,
}

pub fn to_pretty_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

pub fn to_pretty_yaml<T: Serialize>(value: &T) -> anyhow::Result<String> {
    Ok(serde_yaml::to_string(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::common::api::{DeploymentStatus, DeploymentSummary, DesiredState, Page};

    #[test]
    fn pretty_json_round_trips_page() {
        let deployments = vec![DeploymentSummary {
            deployment_id: Uuid::from_u128(3),
            name: "api".to_string(),
            image: "busybox".to_string(),
            replicas: 1,
            desired_state: DesiredState::Stopped,
            status: DeploymentStatus::Stopped,
            assigned_node_id: None,
            assignments: vec![],
            generation: 1,
            tunnel_only: false,
            placement: None,
            volumes: None,
            last_reported: None,
        }];
        let page = Page {
            limit: 10,
            offset: 0,
            items: deployments,
        };

        let json = to_pretty_json(&page).unwrap();
        assert!(json.contains("\"limit\": 10"));
        assert!(json.contains("\"items\""));
        assert!(json.contains("busybox"));
    }

    #[test]
    fn pretty_yaml_round_trips_page() {
        let deployments = vec![DeploymentSummary {
            deployment_id: Uuid::from_u128(3),
            name: "api".to_string(),
            image: "busybox".to_string(),
            replicas: 1,
            desired_state: DesiredState::Stopped,
            status: DeploymentStatus::Stopped,
            assigned_node_id: None,
            assignments: vec![],
            generation: 1,
            tunnel_only: false,
            placement: None,
            volumes: None,
            last_reported: None,
        }];
        let page = Page {
            limit: 10,
            offset: 0,
            items: deployments,
        };

        let yaml = to_pretty_yaml(&page).unwrap();
        assert!(yaml.contains("limit: 10"));
        assert!(yaml.contains("items:"));
        assert!(yaml.contains("busybox"));
    }
}
