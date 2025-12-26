use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use reqwest::header::HeaderMap;
use semver::Version;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    api,
    state::{self, SharedState},
    telemetry, version,
};

pub const CONTROL_PLANE_VERSION_HEADER: &str = "x-control-plane-version";
pub const CONTROL_PLANE_COMPAT_MIN_HEADER: &str = "x-agent-compat-min";
pub const CONTROL_PLANE_COMPAT_MAX_HEADER: &str = "x-agent-compat-max";
pub const CONTROL_PLANE_COMPAT_UPGRADE_URL_HEADER: &str = "x-agent-compat-upgrade-url";
pub const UNSUPPORTED_AGENT_ERROR: &str = "unsupported_agent_version";

#[cfg(not(test))]
const COMPAT_BACKOFF_BASE_MS: u64 = 1_000;
#[cfg(test)]
const COMPAT_BACKOFF_BASE_MS: u64 = 25;

#[cfg(not(test))]
const COMPAT_BACKOFF_MAX_MS: u64 = 30_000;
#[cfg(test)]
const COMPAT_BACKOFF_MAX_MS: u64 = 250;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentVersionError {
    pub error: String,
    pub agent_version: String,
    pub min_supported: String,
    pub max_supported: String,
    pub upgrade_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatSnapshot {
    pub control_plane_version: Version,
    pub min_supported: Version,
    pub max_supported: Version,
    pub upgrade_url: Option<String>,
}

impl CompatSnapshot {
    pub fn supports(&self, agent: &Version) -> bool {
        agent >= &self.min_supported && agent <= &self.max_supported
    }

    fn from_parts(
        cp_version: &str,
        min: Option<&str>,
        max: Option<&str>,
        upgrade_url: Option<&str>,
    ) -> Result<Self> {
        let cp = Version::parse(cp_version).context("parse control-plane version")?;

        let min_supported = match min {
            Some(raw) if !raw.trim().is_empty() => {
                Version::parse(raw).context("parse min agent version")?
            }
            _ => default_min_supported(&cp),
        };

        let max_supported = match max {
            Some(raw) if !raw.trim().is_empty() => {
                Version::parse(raw).context("parse max agent version")?
            }
            _ => default_max_supported(&cp),
        };

        let upgrade_url = upgrade_url
            .map(|url| url.trim())
            .filter(|url| !url.is_empty())
            .map(ToString::to_string);

        Ok(Self {
            control_plane_version: cp,
            min_supported,
            max_supported,
            upgrade_url,
        })
    }
}

fn default_min_supported(cp: &Version) -> Version {
    Version::new(cp.major, cp.minor.saturating_sub(1), 0)
}

fn default_max_supported(cp: &Version) -> Version {
    Version::new(cp.major, cp.minor.saturating_add(1), 999_999)
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CompatError {
    #[error(
        "agent version {agent_version} unsupported; control-plane window {min_supported}..={max_supported}"
    )]
    Incompatible {
        agent_version: String,
        min_supported: String,
        max_supported: String,
        upgrade_url: Option<String>,
    },
}

impl From<AgentVersionError> for CompatError {
    fn from(value: AgentVersionError) -> Self {
        CompatError::Incompatible {
            agent_version: value.agent_version,
            min_supported: value.min_supported,
            max_supported: value.max_supported,
            upgrade_url: Some(value.upgrade_url).filter(|v| !v.is_empty()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompatState {
    pub snapshot: Option<CompatSnapshot>,
    pub last_error: Option<String>,
    pub backoff_attempts: u32,
    pub backoff_until: Option<Instant>,
    logged_once: bool,
}

impl CompatState {
    fn agent_version() -> Result<Version> {
        Version::parse(version::VERSION).context("parse agent version")
    }

    fn apply_snapshot(&mut self, snapshot: CompatSnapshot) {
        let changed = self
            .snapshot
            .as_ref()
            .map(|prev| prev != &snapshot)
            .unwrap_or(true);
        if changed {
            self.backoff_attempts = 0;
            self.backoff_until = None;
        }

        let agent_version = match Self::agent_version() {
            Ok(v) => v,
            Err(err) => {
                warn!(?err, "agent version missing or invalid");
                self.snapshot = Some(snapshot);
                return;
            }
        };

        let supported = snapshot.supports(&agent_version);
        self.snapshot = Some(snapshot.clone());

        if supported {
            self.clear_error();
        } else {
            let message = mismatch_message(&snapshot, &agent_version);
            self.last_error = Some(message.clone());
            telemetry::record_compatibility_status(self.last_error.as_deref());
        }

        if !self.logged_once {
            info!(
                control_plane_version = %snapshot.control_plane_version,
                min_supported_agent_version = %snapshot.min_supported,
                max_supported_agent_version = %snapshot.max_supported,
                upgrade_url = snapshot.upgrade_url.as_deref().unwrap_or(""),
                "control-plane compatibility window fetched"
            );
            self.logged_once = true;
        }
    }

    fn clear_error(&mut self) {
        self.last_error = None;
        self.backoff_attempts = 0;
        self.backoff_until = None;
        telemetry::record_compatibility_status(None);
    }

    fn schedule_backoff(&mut self) -> Duration {
        self.backoff_attempts = self.backoff_attempts.saturating_add(1);
        let base = Duration::from_millis(COMPAT_BACKOFF_BASE_MS);
        let max = Duration::from_millis(COMPAT_BACKOFF_MAX_MS);
        let duration = state::backoff_with_jitter(base, max, self.backoff_attempts);
        self.backoff_until = Some(Instant::now() + duration);
        duration
    }
}

fn mismatch_message(snapshot: &CompatSnapshot, agent_version: &Version) -> String {
    let upgrade = snapshot
        .upgrade_url
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|url| format!("; upgrade via {url}"))
        .unwrap_or_default();

    format!(
        "agent version {} unsupported by control-plane {}; supported window {}..={}{upgrade}",
        agent_version,
        snapshot.control_plane_version,
        snapshot.min_supported,
        snapshot.max_supported
    )
}

pub async fn update_from_headers(state: &SharedState, headers: &HeaderMap) -> Result<()> {
    let cp_version = headers
        .get(CONTROL_PLANE_VERSION_HEADER)
        .and_then(|value| value.to_str().ok());

    if let Some(cp_version) = cp_version {
        let snapshot = CompatSnapshot::from_parts(
            cp_version,
            headers
                .get(CONTROL_PLANE_COMPAT_MIN_HEADER)
                .and_then(|v| v.to_str().ok()),
            headers
                .get(CONTROL_PLANE_COMPAT_MAX_HEADER)
                .and_then(|v| v.to_str().ok()),
            headers
                .get(CONTROL_PLANE_COMPAT_UPGRADE_URL_HEADER)
                .and_then(|v| v.to_str().ok()),
        )?;

        let mut guard = state.lock().await;
        guard.compat.apply_snapshot(snapshot);
    }

    Ok(())
}

pub async fn update_from_desired_state(
    state: &SharedState,
    desired: &api::DesiredStateResponse,
) -> Result<()> {
    let snapshot = CompatSnapshot::from_parts(
        &desired.control_plane_version,
        Some(desired.min_supported_agent_version.as_str()),
        desired.max_supported_agent_version.as_deref(),
        desired.upgrade_url.as_deref(),
    )?;

    let mut guard = state.lock().await;
    guard.compat.apply_snapshot(snapshot);
    Ok(())
}

pub async fn update_from_error_payload(
    state: &SharedState,
    payload: &AgentVersionError,
    headers: &HeaderMap,
) -> Result<()> {
    let cp_version = headers
        .get(CONTROL_PLANE_VERSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(version::VERSION);

    let snapshot = CompatSnapshot::from_parts(
        cp_version,
        Some(payload.min_supported.as_str()),
        Some(payload.max_supported.as_str()),
        Some(payload.upgrade_url.as_str()),
    )?;

    let mut guard = state.lock().await;
    guard.compat.apply_snapshot(snapshot);
    Ok(())
}

pub async fn handle_error_response(
    state: &SharedState,
    headers: &HeaderMap,
    body: &str,
) -> Result<Option<CompatError>> {
    if let Err(err) = update_from_headers(state, headers).await {
        warn!(?err, "failed to parse compatibility headers");
    }

    if let Ok(payload) = serde_json::from_str::<AgentVersionError>(body)
        && payload.error == UNSUPPORTED_AGENT_ERROR
    {
        update_from_error_payload(state, &payload, headers)
            .await
            .ok();
        return Ok(Some(payload.into()));
    }

    Ok(None)
}

pub async fn enforce(state: &SharedState, operation: &str) -> Result<()> {
    let (snapshot, backoff_until) = {
        let guard = state.lock().await;
        (guard.compat.snapshot.clone(), guard.compat.backoff_until)
    };

    if let Some(until) = backoff_until {
        let now = Instant::now();
        if until > now {
            tokio::time::sleep(until - now).await;
        }
    }

    let snapshot = match snapshot {
        Some(value) => value,
        None => return Ok(()),
    };

    let agent_version = CompatState::agent_version()?;

    if snapshot.supports(&agent_version) {
        let mut guard = state.lock().await;
        guard.compat.clear_error();
        return Ok(());
    }

    let mut guard = state.lock().await;
    let backoff = guard.compat.schedule_backoff();
    let message = mismatch_message(&snapshot, &agent_version);
    guard.compat.last_error = Some(message.clone());
    telemetry::record_compatibility_status(guard.compat.last_error.as_deref());
    drop(guard);

    warn!(
        operation,
        cp_version = %snapshot.control_plane_version,
        min_supported = %snapshot.min_supported,
        max_supported = %snapshot.max_supported,
        upgrade_url = snapshot.upgrade_url.as_deref().unwrap_or(""),
        agent_version = %agent_version,
        backoff_ms = backoff.as_millis(),
        "agent/control-plane compatibility mismatch"
    );

    tokio::time::sleep(backoff).await;

    Err(CompatError::Incompatible {
        agent_version: agent_version.to_string(),
        min_supported: snapshot.min_supported.to_string(),
        max_supported: snapshot.max_supported.to_string(),
        upgrade_url: snapshot.upgrade_url.clone(),
    }
    .into())
}

pub async fn prime_control_plane_info(state: &SharedState) -> Result<()> {
    let (client, url) = {
        let guard = state.lock().await;
        (
            guard.client.clone(),
            guard
                .cfg
                .control_plane_url
                .trim_end_matches('/')
                .to_string(),
        )
    };

    let health_url = format!("{url}/health");
    let res = match client.get(health_url.clone()).send().await {
        Ok(res) => res,
        Err(err) => {
            warn!(?err, url = %health_url, "failed to fetch control-plane health for compatibility");
            return Ok(());
        }
    };

    let status = res.status();
    let headers = res.headers().clone();
    let body = match res.text().await {
        Ok(text) => text,
        Err(err) => {
            warn!(?err, url = %health_url, "failed to read health response body");
            return Ok(());
        }
    };

    if !status.is_success() {
        warn!(%status, body = %body, "health endpoint returned error during compatibility prime");
        return Ok(());
    }

    if let Err(err) = update_from_headers(state, &headers).await {
        warn!(
            ?err,
            "failed to parse compatibility headers from health response"
        );
    }

    #[derive(Deserialize)]
    struct HealthPayload {
        control_plane_version: String,
        min_supported_agent_version: String,
        max_supported_agent_version: String,
    }

    match serde_json::from_str::<HealthPayload>(&body) {
        Ok(payload) => {
            let snapshot = CompatSnapshot::from_parts(
                &payload.control_plane_version,
                Some(payload.min_supported_agent_version.as_str()),
                Some(payload.max_supported_agent_version.as_str()),
                None,
            )?;

            let mut guard = state.lock().await;
            guard.compat.apply_snapshot(snapshot);
        }
        Err(err) => {
            warn!(
                ?err,
                "failed to decode health response for compatibility prime"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_test_state;
    use reqwest::header::{HeaderMap, HeaderValue};
    use uuid::Uuid;

    #[test]
    fn snapshot_parses_and_applies_defaults() {
        let snapshot = CompatSnapshot::from_parts("1.2.3", None, None, None).expect("snapshot");
        assert_eq!(snapshot.min_supported, Version::new(1, 1, 0));
        assert_eq!(snapshot.max_supported, Version::new(1, 3, 999_999));
    }

    #[test]
    fn mismatch_message_includes_window() {
        let snapshot = CompatSnapshot::from_parts(
            "1.2.3",
            Some("1.2.0"),
            Some("1.2.2"),
            Some("https://upgrade"),
        )
        .expect("snapshot");
        let msg = mismatch_message(&snapshot, &Version::new(1, 2, 5));
        assert!(msg.contains("upgrade"));
        assert!(msg.contains("1.2.2"));
    }

    #[test]
    fn backoff_grows_with_attempts() {
        let mut state = CompatState::default();
        let first = state.schedule_backoff();
        let second = state.schedule_backoff();
        assert!(second >= first);
        assert!(state.backoff_attempts >= 2);
    }

    #[test]
    fn snapshot_supports_inclusive_bounds() {
        let snapshot =
            CompatSnapshot::from_parts("1.2.3", Some("1.2.0"), Some("1.2.3"), None).unwrap();
        assert!(snapshot.supports(&Version::new(1, 2, 0)));
        assert!(snapshot.supports(&Version::new(1, 2, 3)));
        assert!(!snapshot.supports(&Version::new(1, 1, 9)));
    }

    #[test]
    fn snapshot_trims_upgrade_url() {
        let snapshot = CompatSnapshot::from_parts(
            "1.2.3",
            Some("1.0.0"),
            Some("2.0.0"),
            Some("  https://upgrade.example  "),
        )
        .expect("snapshot");
        assert_eq!(
            snapshot.upgrade_url.as_deref(),
            Some("https://upgrade.example")
        );
    }

    #[test]
    fn compat_error_filters_empty_upgrade_url() {
        let err = CompatError::from(AgentVersionError {
            error: "unsupported_agent_version".into(),
            agent_version: "1.0.0".into(),
            min_supported: "1.0.0".into(),
            max_supported: "1.0.0".into(),
            upgrade_url: "".into(),
        });
        match err {
            CompatError::Incompatible { upgrade_url, .. } => assert!(upgrade_url.is_none()),
        }
    }

    #[tokio::test]
    async fn update_from_headers_applies_snapshot() {
        let state = make_test_state("http://localhost:49421".into(), Uuid::new_v4(), 1, 1, 1);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTROL_PLANE_VERSION_HEADER,
            HeaderValue::from_static("1.2.3"),
        );
        headers.insert(
            CONTROL_PLANE_COMPAT_MIN_HEADER,
            HeaderValue::from_static("1.0.0"),
        );
        headers.insert(
            CONTROL_PLANE_COMPAT_MAX_HEADER,
            HeaderValue::from_static("2.0.0"),
        );
        headers.insert(
            CONTROL_PLANE_COMPAT_UPGRADE_URL_HEADER,
            HeaderValue::from_static(" https://upgrade.example "),
        );

        update_from_headers(&state, &headers).await.expect("update");

        let guard = state.lock().await;
        let snapshot = guard.compat.snapshot.as_ref().expect("snapshot");
        assert_eq!(snapshot.control_plane_version, Version::new(1, 2, 3));
        assert_eq!(snapshot.min_supported, Version::new(1, 0, 0));
        assert_eq!(snapshot.max_supported, Version::new(2, 0, 0));
        assert_eq!(
            snapshot.upgrade_url.as_deref(),
            Some("https://upgrade.example")
        );
    }

    #[tokio::test]
    async fn update_from_headers_ignores_missing_version() {
        let state = make_test_state("http://localhost:49421".into(), Uuid::new_v4(), 1, 1, 1);
        let headers = HeaderMap::new();
        update_from_headers(&state, &headers).await.expect("update");

        let guard = state.lock().await;
        assert!(guard.compat.snapshot.is_none());
    }

    #[tokio::test]
    async fn handle_error_response_returns_incompatible() {
        let state = make_test_state("http://localhost:49421".into(), Uuid::new_v4(), 1, 1, 1);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTROL_PLANE_VERSION_HEADER,
            HeaderValue::from_static("2.1.0"),
        );
        let body = serde_json::json!({
            "error": UNSUPPORTED_AGENT_ERROR,
            "agent_version": "0.1.0",
            "min_supported": "2.0.0",
            "max_supported": "2.0.1",
            "upgrade_url": "https://upgrade.example"
        })
        .to_string();

        let err = handle_error_response(&state, &headers, &body)
            .await
            .expect("handle")
            .expect("compat error");

        match err {
            CompatError::Incompatible { min_supported, .. } => {
                assert_eq!(min_supported, "2.0.0");
            }
        }

        let guard = state.lock().await;
        let snapshot = guard.compat.snapshot.as_ref().expect("snapshot");
        assert_eq!(snapshot.control_plane_version, Version::new(2, 1, 0));
    }

    #[tokio::test]
    async fn handle_error_response_ignores_invalid_body() {
        let state = make_test_state("http://localhost:49421".into(), Uuid::new_v4(), 1, 1, 1);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTROL_PLANE_VERSION_HEADER,
            HeaderValue::from_static("1.2.3"),
        );

        let result = handle_error_response(&state, &headers, "not-json")
            .await
            .expect("handle");
        assert!(result.is_none());

        let guard = state.lock().await;
        let snapshot = guard.compat.snapshot.as_ref().expect("snapshot");
        assert_eq!(snapshot.control_plane_version, Version::new(1, 2, 3));
    }

    #[tokio::test]
    async fn enforce_allows_supported_snapshot() {
        let state = make_test_state("http://localhost:49421".into(), Uuid::new_v4(), 1, 1, 1);
        let agent = Version::parse(version::VERSION).expect("agent version");
        let snapshot = CompatSnapshot {
            control_plane_version: agent.clone(),
            min_supported: Version::new(0, 0, 0),
            max_supported: Version::new(agent.major.saturating_add(1), 0, 0),
            upgrade_url: None,
        };

        {
            let mut guard = state.lock().await;
            guard.compat.apply_snapshot(snapshot);
        }

        enforce(&state, "test").await.expect("supported");
        let guard = state.lock().await;
        assert!(guard.compat.last_error.is_none());
    }

    #[tokio::test]
    async fn enforce_returns_error_when_incompatible() {
        let state = make_test_state("http://localhost:49421".into(), Uuid::new_v4(), 1, 1, 1);
        let agent = Version::parse(version::VERSION).expect("agent version");
        let min_minor = agent.minor.saturating_add(1);
        let snapshot = CompatSnapshot {
            control_plane_version: agent.clone(),
            min_supported: Version::new(agent.major, min_minor, 0),
            max_supported: Version::new(agent.major, min_minor, 0),
            upgrade_url: None,
        };
        {
            let mut guard = state.lock().await;
            guard.compat.apply_snapshot(snapshot);
        }

        let err = enforce(&state, "test").await.expect_err("incompatible");
        assert!(err.to_string().contains("unsupported"));

        let guard = state.lock().await;
        assert!(guard.compat.backoff_attempts >= 1);
        assert!(guard.compat.last_error.is_some());
    }
}
