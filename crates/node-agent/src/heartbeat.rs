use std::time::Duration;

use tokio::sync::watch;
use tracing::warn;

use crate::{config, state::SharedState};
use crate::{cp_client::ControlPlaneClient, services};

pub async fn heartbeat_loop(
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let interval_secs = {
        let guard = state.lock().await;
        guard.cfg.heartbeat_interval_secs
    };
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                let client = ControlPlaneClient::new(&state).await;
                if let Err(err) = services::heartbeat::heartbeat_with_retry(&state, client, shutdown.clone()).await {
                    if *shutdown.borrow() {
                        break;
                    }
                    warn!(?err, "heartbeat failed");
                }
            }
        }
    }

    Ok(())
}

pub fn heartbeat_url(cfg: &config::AppConfig) -> String {
    crate::cp_client::heartbeat_url(cfg)
}

pub use crate::services::heartbeat::build_inventory_payload;

#[cfg(test)]
pub(crate) async fn heartbeat_with_retry(
    state: &SharedState,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = ControlPlaneClient::new(state).await;
    services::heartbeat::heartbeat_with_retry(state, client, shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compat::{self, CompatError},
        runtime::ContainerResourceUsage,
        state::{ManagedDeployment, ReplicaKey},
        test_support::{base_config, make_test_state},
        validate_control_plane_url, version,
    };
    use chrono::Utc;
    use httpmock::Method::POST;
    use httpmock::MockServer;
    use std::collections::VecDeque;
    use tokio::sync::watch;
    use tokio::time::{sleep, timeout, Duration as TokioDuration};
    use uuid::Uuid;

    #[test]
    fn heartbeat_url_trims_trailing_slash() {
        let mut cfg = base_config();
        cfg.control_plane_url = "http://localhost:8080/".into();
        cfg.node_id = Uuid::nil();

        let url = heartbeat_url(&cfg);
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/nodes/00000000-0000-0000-0000-000000000000/heartbeats"
        );
    }

    #[test]
    fn reject_http_when_not_allowed() {
        let mut cfg = base_config();
        cfg.control_plane_url = "http://localhost:8080".into();
        cfg.node_id = Uuid::nil();
        cfg.allow_insecure_http = false;

        let err = validate_control_plane_url(&cfg).unwrap_err();
        assert!(
            err.to_string()
                .contains("insecure control-plane URL not allowed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn allow_http_when_explicitly_enabled() {
        let mut cfg = base_config();
        cfg.control_plane_url = "http://localhost:8080".into();
        cfg.node_id = Uuid::nil();
        cfg.allow_insecure_http = true;

        assert!(validate_control_plane_url(&cfg).is_ok());
    }

    #[test]
    fn allow_https_by_default() {
        let mut cfg = base_config();
        cfg.control_plane_url = "https://localhost:8443".into();
        cfg.node_id = Uuid::nil();
        cfg.allow_insecure_http = false;

        assert!(validate_control_plane_url(&cfg).is_ok());
    }

    #[test]
    fn inventory_omits_defaults() {
        let cfg = base_config();
        let payload = build_inventory_payload(&cfg);
        let value = serde_json::to_value(payload).expect("serialize");

        assert_eq!(value.get("labels"), None, "labels should be omitted");
        assert_eq!(value.get("capacity"), None, "capacity should be omitted");
        assert_eq!(
            value.get("arch"),
            Some(&serde_json::Value::String(std::env::consts::ARCH.into()))
        );
        assert_eq!(
            value.get("os"),
            Some(&serde_json::Value::String(std::env::consts::OS.into()))
        );
    }

    #[test]
    fn inventory_allows_clearing_when_forced() {
        let mut cfg = base_config();
        cfg.force_empty_labels = true;
        cfg.force_empty_capacity = true;
        let payload = build_inventory_payload(&cfg);
        let value = serde_json::to_value(payload).expect("serialize");

        assert_eq!(
            value.get("labels"),
            Some(&serde_json::Value::Object(Default::default()))
        );
        assert_eq!(
            value.get("capacity"),
            Some(&serde_json::Value::Object(Default::default()))
        );
    }

    #[tokio::test]
    async fn heartbeat_respects_timeout() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/heartbeats", node_id);

        let _mock = server.mock(|when, then| {
            when.method(POST).path(path.clone());
            then.status(200).delay(Duration::from_millis(1500));
        });

        let state = make_test_state(server.url(""), node_id, 1, 1, 100);
        let (_tx, rx) = watch::channel(false);

        let start = std::time::Instant::now();
        let res = heartbeat_with_retry(&state, rx).await;
        let elapsed = start.elapsed();

        assert!(res.is_err(), "expected timeout error");
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout path should return promptly"
        );
    }

    #[tokio::test]
    async fn heartbeat_cancels_on_shutdown() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/heartbeats", node_id);

        let _mock = server.mock(|when, then| {
            when.method(POST).path(path.clone());
            then.status(200).delay(Duration::from_secs(5));
        });

        let state = make_test_state(server.url(""), node_id, 1, 3, 2000);
        let (tx, rx) = watch::channel(false);

        tokio::spawn(async move {
            sleep(TokioDuration::from_millis(100)).await;
            let _ = tx.send(true);
        });

        let res = timeout(
            TokioDuration::from_secs(2),
            heartbeat_with_retry(&state, rx),
        )
        .await;
        assert!(
            res.is_ok(),
            "heartbeat future did not complete after shutdown"
        );
        assert!(
            res.unwrap().is_err(),
            "shutdown should cancel heartbeat retries"
        );
    }

    #[tokio::test]
    async fn heartbeat_succeeds() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/heartbeats", node_id);

        let mock = server.mock(|when, then| {
            when.method(POST).path(path.clone());
            then.status(200);
        });

        let state = make_test_state(server.url(""), node_id, 5, 2, 50);
        let (_tx, rx) = watch::channel(false);

        let res = heartbeat_with_retry(&state, rx).await;
        assert!(res.is_ok(), "heartbeat should succeed");
        assert_eq!(mock.calls(), 1);
    }

    #[tokio::test]
    async fn heartbeat_sends_resource_metrics_payload() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/heartbeats", node_id);

        let hb_mock = server.mock(|when, then| {
            when.method(POST)
                .path(path.clone())
                .body_matches(r#""metrics":\["#)
                .body_matches(r#""cpu_percent":7\.5"#);
            then.status(200);
        });

        let state = make_test_state(server.url(""), node_id, 5, 1, 50);
        {
            let mut guard = state.managed_write().await;
            let key = ReplicaKey::new(Uuid::new_v4(), 0);
            let mut deployment = ManagedDeployment::new(1);
            deployment.mark_running(Some("c-metrics".into()));
            guard.managed.insert(key, deployment);

            let mut queue = VecDeque::new();
            queue.push_back(ContainerResourceUsage {
                collected_at: Utc::now(),
                cpu_percent: 7.5,
                memory_bytes: 64,
                network_rx_bytes: 1,
                network_tx_bytes: 2,
                blk_read_bytes: Some(3),
                blk_write_bytes: Some(4),
            });
            guard.resource_samples.insert(key, queue);
        }

        let (_tx, rx) = watch::channel(false);
        let res = heartbeat_with_retry(&state, rx).await;

        assert!(res.is_ok(), "heartbeat with metrics should succeed");
        hb_mock.assert();
    }

    #[tokio::test]
    async fn heartbeat_records_compat_headers() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/heartbeats", node_id);

        let _mock = server.mock(|when, then| {
            when.method(POST).path(path.clone());
            then.status(200)
                .header(compat::CONTROL_PLANE_VERSION_HEADER, "1.2.3")
                .header(compat::CONTROL_PLANE_COMPAT_MIN_HEADER, "1.0.0")
                .header(compat::CONTROL_PLANE_COMPAT_MAX_HEADER, "2.0.0")
                .header(
                    compat::CONTROL_PLANE_COMPAT_UPGRADE_URL_HEADER,
                    "https://upgrade",
                );
        });

        let state = make_test_state(server.url(""), node_id, 5, 2, 50);
        let (_tx, rx) = watch::channel(false);

        let res = heartbeat_with_retry(&state, rx).await;
        assert!(res.is_ok(), "heartbeat should succeed");

        let snapshot = {
            let guard = state.lock().await;
            guard.compat.snapshot.clone()
        }
        .expect("snapshot");

        assert_eq!(
            snapshot.control_plane_version,
            semver::Version::new(1, 2, 3)
        );
        assert_eq!(snapshot.min_supported, semver::Version::new(1, 0, 0));
        assert_eq!(snapshot.max_supported, semver::Version::new(2, 0, 0));
        assert_eq!(snapshot.upgrade_url.as_deref(), Some("https://upgrade"));
    }

    #[tokio::test]
    async fn heartbeat_stops_on_incompatible_window() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/heartbeats", node_id);

        let payload = compat::AgentVersionError {
            error: compat::UNSUPPORTED_AGENT_ERROR.into(),
            agent_version: version::VERSION.into(),
            min_supported: "99.0.0".into(),
            max_supported: "99.0.0".into(),
            upgrade_url: "https://upgrade".into(),
        };

        let mock = server.mock(|when, then| {
            when.method(POST).path(path.clone());
            then.status(426)
                .header(compat::CONTROL_PLANE_VERSION_HEADER, "99.0.0")
                .header(compat::CONTROL_PLANE_COMPAT_MIN_HEADER, "99.0.0")
                .header(compat::CONTROL_PLANE_COMPAT_MAX_HEADER, "99.0.0")
                .json_body_obj(&payload);
        });

        let state = make_test_state(server.url(""), node_id, 1, 1, 10);
        let (_tx, rx) = watch::channel(false);

        let res = heartbeat_with_retry(&state, rx).await;
        assert!(res.is_err(), "incompatible heartbeat should fail fast");
        assert!(res.unwrap_err().downcast_ref::<CompatError>().is_some());
        assert_eq!(
            mock.calls(),
            1,
            "heartbeat should not retry on compat errors"
        );

        let guard = state.lock().await;
        assert!(
            guard.compat.last_error.is_some(),
            "compat error should be recorded"
        );
    }

    #[tokio::test]
    async fn heartbeat_aborts_if_shutdown_already_set() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();

        let mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200);
        });

        let state = make_test_state(server.url(""), node_id, 5, 3, 200);
        let (tx, rx) = watch::channel(false);
        let _ = tx.send(true);

        let start = std::time::Instant::now();
        let res = heartbeat_with_retry(&state, rx).await;
        let elapsed = start.elapsed();

        assert!(res.is_err(), "expected shutdown error");
        assert!(
            elapsed < Duration::from_millis(200),
            "should abort immediately"
        );
        assert_eq!(
            mock.calls(),
            0,
            "no heartbeat should be sent after shutdown"
        );
    }
}
