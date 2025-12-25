use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use reqwest::header::ETAG;
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{info, warn};
use uuid::Uuid;

use crate::api::{ConfigDesired, ServiceIdentityBundle};
use crate::compat;
use crate::cp_client::ControlPlaneClient;
use crate::state::{self, SharedState};
use crate::telemetry;
use crate::SERVICE_IDENTITY_FINGERPRINT_HEADER;

const CONFIG_BACKOFF_BASE_MS: u64 = 500;
const CONFIG_BACKOFF_MAX_MS: u64 = 30_000;

pub async fn config_sync_loop(
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let interval_secs = {
        let guard = state.lock().await;
        guard.cfg.reconcile_interval_secs
    };
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                if let Err(err) = refresh_configs(&state).await {
                    warn!(?err, "config sync failed");
                }
            }
        }
    }

    Ok(())
}

pub async fn refresh_configs(state: &SharedState) -> anyhow::Result<()> {
    compat::enforce(state, "configs").await?;

    let (etag, identities_fp, backoff_until, attempts) = {
        let guard = state.lock().await;
        (
            guard.configs_etag.clone(),
            guard.service_identities_fingerprint.clone(),
            guard.configs_backoff_until,
            guard.configs_backoff_attempts,
        )
    };

    if let Some(until) = backoff_until {
        if until > std::time::Instant::now() {
            return Ok(());
        }
    }

    let client = ControlPlaneClient::new(state).await;
    let response = match client
        .fetch_configs(state, etag.as_deref(), identities_fp.as_deref())
        .await
    {
        Ok(res) => res,
        Err(err) => {
            let fetch_label = if err.downcast_ref::<compat::CompatError>().is_some() {
                "compat_error"
            } else {
                "error"
            };
            telemetry::record_config_fetch(fetch_label);
            apply_config_backoff(state, attempts + 1).await;
            return Err(err);
        }
    };

    let status = response.status;
    let request_id = response.request_id.clone();
    let headers = response.headers.clone();

    if status == StatusCode::NOT_MODIFIED {
        telemetry::record_config_fetch("not_modified");
        reset_config_backoff(state).await;
        return Ok(());
    }

    if !status.is_success() {
        apply_config_backoff(state, attempts + 1).await;
        telemetry::record_config_fetch("error");
        anyhow::bail!("config request failed with status {status}");
    }

    let payload = response
        .payload
        .context("config response payload missing")?;
    let config_count = payload.configs.len();
    store_configs(state, payload.configs, headers.get(ETAG)).await?;

    if let Some(fingerprint) = headers
        .get(SERVICE_IDENTITY_FINGERPRINT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    {
        store_service_identities(state, payload.service_identities, Some(fingerprint)).await;
    } else {
        store_service_identities(state, payload.service_identities, None).await;
    }
    telemetry::record_config_fetch("success");
    reset_config_backoff(state).await;
    info!(%request_id, configs = %config_count, "refreshed node configs");

    Ok(())
}

async fn store_configs(
    state: &SharedState,
    configs: Vec<ConfigDesired>,
    etag_header: Option<&reqwest::header::HeaderValue>,
) -> anyhow::Result<()> {
    let mut guard = state.lock().await;
    let mut map = HashMap::with_capacity(configs.len());
    for config in configs {
        map.insert(config.metadata.config_id, config);
    }
    guard.configs = map;
    guard.configs_etag = etag_header
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    Ok(())
}

async fn store_service_identities(
    state: &SharedState,
    identities: Vec<ServiceIdentityBundle>,
    fingerprint: Option<String>,
) {
    state::set_service_identities(state, identities, fingerprint).await;
}

async fn apply_config_backoff(state: &SharedState, attempts: u32) {
    let backoff = state::backoff_with_jitter(
        Duration::from_millis(CONFIG_BACKOFF_BASE_MS),
        Duration::from_millis(CONFIG_BACKOFF_MAX_MS),
        attempts,
    );
    let mut guard = state.lock().await;
    guard.configs_backoff_attempts = attempts;
    guard.configs_backoff_until = Some(std::time::Instant::now() + backoff);
}

async fn reset_config_backoff(state: &SharedState) {
    let mut guard = state.lock().await;
    guard.configs_backoff_attempts = 0;
    guard.configs_backoff_until = None;
}

pub fn select_configs_for_deployment(
    configs: &HashMap<Uuid, ConfigDesired>,
    node_id: Uuid,
    deployment_id: Uuid,
) -> Vec<ConfigDesired> {
    let mut selected: Vec<ConfigDesired> = configs
        .values()
        .filter(|cfg| {
            cfg.attached_deployments.contains(&deployment_id)
                || cfg.attached_nodes.contains(&node_id)
        })
        .cloned()
        .collect();

    selected.sort_by_key(|cfg| cfg.metadata.name.clone());
    selected
}

pub fn config_fingerprint(configs: &[ConfigDesired]) -> Option<String> {
    if configs.is_empty() {
        return None;
    }

    let mut sorted = configs.to_vec();
    sorted.sort_by_key(|cfg| cfg.metadata.config_id);

    let mut hasher = Sha256::new();
    for config in sorted {
        hasher.update(config.metadata.config_id.as_bytes());
        hasher.update(config.metadata.version.to_le_bytes());
        if let Some(cs) = config.checksum.as_ref() {
            hasher.update(cs.as_bytes());
        }
    }

    Some(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ConfigEntry, ConfigMetadata, NodeConfigResponse};
    use crate::runtime::DynContainerRuntime;
    use crate::telemetry;
    use crate::test_support::{base_config, state_with_runtime_and_config, MockRuntime};
    use chrono::Utc;
    use httpmock::{Method::GET, MockServer};
    use std::collections::HashMap;

    fn sample_config(node_id: Uuid, version: i64) -> ConfigDesired {
        ConfigDesired {
            metadata: ConfigMetadata {
                config_id: Uuid::new_v4(),
                name: format!("cfg-{version}"),
                version,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            entries: vec![ConfigEntry {
                key: "FROM_CONFIG".into(),
                value: Some("yes".into()),
                secret_ref: None,
            }],
            files: Vec::new(),
            attached_deployments: Vec::new(),
            attached_nodes: vec![node_id],
            checksum: Some(format!("sum-{version}")),
        }
    }

    #[tokio::test]
    async fn refresh_configs_uses_etag_and_caches_payload() {
        telemetry::init_metrics_recorder();

        let server = MockServer::start_async().await;
        let node_id = Uuid::new_v4();
        let mut cfg = base_config();
        cfg.control_plane_url = server.url("");
        cfg.node_id = node_id;

        let runtime: DynContainerRuntime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, cfg.clone());

        let config = sample_config(node_id, 1);
        let path = format!("/api/v1/nodes/{}/configs", node_id);

        let first = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(path.clone())
                    .header("authorization", "Bearer t");
                then.status(200)
                    .header(ETAG.as_str(), "v1")
                    .header(compat::CONTROL_PLANE_VERSION_HEADER, "1.2.3")
                    .header(compat::CONTROL_PLANE_COMPAT_MIN_HEADER, "0.0.0")
                    .header(compat::CONTROL_PLANE_COMPAT_MAX_HEADER, "9.9.9")
                    .json_body_obj(&NodeConfigResponse {
                        configs: vec![config.clone()],
                        service_identities: Vec::new(),
                    });
            })
            .await;

        refresh_configs(&state)
            .await
            .expect("initial fetch succeeds");
        first.assert_async().await;
        first.delete_async().await;

        {
            let guard = state.lock().await;
            assert_eq!(guard.configs_etag.as_deref(), Some("v1"));
            assert_eq!(guard.configs.len(), 1);
            let stored = guard
                .configs
                .get(&config.metadata.config_id)
                .expect("config stored");
            assert_eq!(stored.metadata.version, 1);
        }

        let second = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(path.clone())
                    .header("if-none-match", "v1");
                then.status(304)
                    .header(ETAG.as_str(), "v1")
                    .header(compat::CONTROL_PLANE_COMPAT_MIN_HEADER, "0.0.0")
                    .header(compat::CONTROL_PLANE_COMPAT_MAX_HEADER, "9.9.9");
            })
            .await;

        refresh_configs(&state).await.expect("handles not-modified");
        second.assert_async().await;
    }

    #[tokio::test]
    async fn refresh_configs_applies_backoff_on_payload_limit() {
        telemetry::init_metrics_recorder();

        let server = MockServer::start_async().await;
        let node_id = Uuid::new_v4();
        let mut cfg = base_config();
        cfg.control_plane_url = server.url("");
        cfg.node_id = node_id;

        let runtime: DynContainerRuntime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, cfg.clone());

        let existing = sample_config(node_id, 1);
        {
            let mut guard = state.lock().await;
            guard
                .configs
                .insert(existing.metadata.config_id, existing.clone());
        }

        let path = format!("/api/v1/nodes/{}/configs", node_id);
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(path.clone());
                then.status(413)
                    .body("config payload exceeds 10 bytes limit");
            })
            .await;

        let err = refresh_configs(&state)
            .await
            .expect_err("payload limit should surface as error");
        mock.assert_async().await;
        assert!(format!("{err:?}").contains("status 413"));

        {
            let guard = state.lock().await;
            assert_eq!(guard.configs_backoff_attempts, 1);
            assert!(guard.configs_backoff_until.is_some());
            assert!(guard.configs.contains_key(&existing.metadata.config_id));
        }
    }

    #[tokio::test]
    async fn refresh_configs_handles_auth_error_without_crash() {
        telemetry::init_metrics_recorder();

        let server = MockServer::start_async().await;
        let node_id = Uuid::new_v4();
        let mut cfg = base_config();
        cfg.control_plane_url = server.url("");
        cfg.node_id = node_id;

        let runtime: DynContainerRuntime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, cfg);

        let path = format!("/api/v1/nodes/{}/configs", node_id);
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(path.clone());
                then.status(401).body("unauthorized");
            })
            .await;

        let err = refresh_configs(&state)
            .await
            .expect_err("auth error should propagate");
        mock.assert_async().await;
        assert!(err.to_string().contains("status 401"));

        {
            let guard = state.lock().await;
            assert_eq!(guard.configs_backoff_attempts, 1);
            assert!(guard.configs_backoff_until.is_some());
        }
    }

    #[test]
    fn select_configs_for_deployment_filters_and_sorts() {
        let node_id = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();

        let mut by_deployment = sample_config(node_id, 1);
        by_deployment.metadata.name = "b-config".to_string();
        by_deployment.attached_nodes.clear();
        by_deployment.attached_deployments.push(deployment_id);

        let mut by_node = sample_config(node_id, 2);
        by_node.metadata.name = "a-config".to_string();

        let unrelated = sample_config(Uuid::new_v4(), 3);

        let mut configs = HashMap::new();
        configs.insert(by_deployment.metadata.config_id, by_deployment.clone());
        configs.insert(by_node.metadata.config_id, by_node.clone());
        configs.insert(unrelated.metadata.config_id, unrelated);

        let selected = select_configs_for_deployment(&configs, node_id, deployment_id);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].metadata.name, "a-config");
        assert_eq!(selected[1].metadata.name, "b-config");
    }

    #[test]
    fn config_fingerprint_is_stable_and_sensitive_to_changes() {
        let node_id = Uuid::new_v4();
        let mut first = sample_config(node_id, 1);
        first.metadata.config_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let mut second = sample_config(node_id, 2);
        second.metadata.config_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();

        let hash_a = config_fingerprint(&[first.clone(), second.clone()]).expect("hash");
        let hash_b = config_fingerprint(&[second.clone(), first.clone()]).expect("hash");
        assert_eq!(hash_a, hash_b);

        let mut changed = second.clone();
        changed.metadata.version += 1;
        let hash_c = config_fingerprint(&[first, changed]).expect("hash");
        assert_ne!(hash_a, hash_c);

        assert_eq!(config_fingerprint(&[]), None);
    }
}
