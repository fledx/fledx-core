use anyhow::Context;
use reqwest::{StatusCode, header::HeaderMap};
use tracing::warn;

use crate::{
    REQUEST_ID_HEADER, SERVICE_IDENTITY_FINGERPRINT_HEADER,
    api::{self, NodeConfigResponse},
    compat, config,
    state::{self, SharedState},
};

#[derive(Debug)]
pub struct CpResponse<T> {
    pub body: T,
    pub request_id: String,
}

#[derive(Debug)]
pub struct ConfigResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub request_id: String,
    pub payload: Option<NodeConfigResponse>,
}

#[derive(Clone)]
pub struct ControlPlaneClient {
    cfg: config::AppConfig,
    client: reqwest::Client,
    request_id: String,
}

impl ControlPlaneClient {
    pub async fn new(state: &SharedState) -> Self {
        let request_id = state::ensure_request_id(state).await;
        Self::with_request_id(state, request_id).await
    }

    pub async fn with_request_id(state: &SharedState, request_id: String) -> Self {
        state::set_request_id(state, request_id.clone()).await;
        let (cfg, client) = {
            let guard = state.lock().await;
            (guard.cfg.clone(), guard.client.clone())
        };

        Self {
            cfg,
            client,
            request_id,
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub async fn fetch_desired_state(
        &self,
        state: &SharedState,
    ) -> anyhow::Result<CpResponse<api::DesiredStateResponse>> {
        let url = desired_state_url(&self.cfg);
        let res = self
            .client
            .get(url)
            .bearer_auth(&self.cfg.node_token)
            .header(REQUEST_ID_HEADER, &self.request_id)
            .send()
            .await
            .map_err(|err| {
                warn!(request_id = %self.request_id, ?err, "desired state request failed");
                err
            })?;

        let status = res.status();
        let headers = res.headers().clone();
        let canonical_request_id = state::update_request_id_from_headers(state, &headers).await;

        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();

            if let Some(err) = compat::handle_error_response(state, &headers, &body).await? {
                warn!(%canonical_request_id, %status, error = %body, "desired state blocked by compatibility");
                return Err(err.into());
            }

            warn!(
                %canonical_request_id,
                %status,
                "desired state request returned error"
            );
            anyhow::bail!("desired state request failed: {status}, body: {body}");
        }

        let body = res.json::<api::DesiredStateResponse>().await?;
        compat::update_from_headers(state, &headers).await?;
        compat::update_from_desired_state(state, &body).await?;
        if let Some(tunnel) = &body.tunnel {
            state::set_tunnel_endpoint(state, tunnel.clone()).await;
        }

        Ok(CpResponse {
            body,
            request_id: canonical_request_id,
        })
    }

    pub async fn send_heartbeat<P: serde::Serialize>(
        &self,
        state: &SharedState,
        payload: &P,
    ) -> anyhow::Result<CpResponse<()>> {
        let url = heartbeat_url(&self.cfg);
        let res = self
            .client
            .post(url)
            .bearer_auth(&self.cfg.node_token)
            .header(REQUEST_ID_HEADER, &self.request_id)
            .json(payload)
            .send()
            .await
            .map_err(|err| {
                warn!(request_id = %self.request_id, ?err, "heartbeat request failed");
                err
            })?;

        let status = res.status();
        let headers = res.headers().clone();
        let canonical_request_id = state::update_request_id_from_headers(state, &headers).await;

        if status != StatusCode::OK {
            let body = res.text().await.unwrap_or_default();

            if let Some(err) = compat::handle_error_response(state, &headers, &body).await? {
                warn!(%canonical_request_id, %status, error = %body, "heartbeat blocked by compatibility");
                return Err(err.into());
            }

            warn!(%canonical_request_id, %status, "heartbeat failed");
            anyhow::bail!("heartbeat failed: status {status}, body: {body}");
        }

        compat::update_from_headers(state, &headers).await?;

        Ok(CpResponse {
            body: (),
            request_id: canonical_request_id,
        })
    }

    pub async fn fetch_configs(
        &self,
        state: &SharedState,
        etag: Option<&str>,
        service_identity_fingerprint: Option<&str>,
    ) -> anyhow::Result<ConfigResponse> {
        let url = configs_url(&self.cfg);
        let mut request = self
            .client
            .get(url)
            .bearer_auth(&self.cfg.node_token)
            .header(REQUEST_ID_HEADER, &self.request_id);

        if let Some(tag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, tag);
        }

        if let Some(fp) = service_identity_fingerprint {
            request = request.header(SERVICE_IDENTITY_FINGERPRINT_HEADER, fp);
        }

        let res = request.send().await.map_err(|err| {
            warn!(request_id = %self.request_id, ?err, "config request failed");
            err
        })?;

        let status = res.status();
        let headers = res.headers().clone();
        let canonical_request_id = state::update_request_id_from_headers(state, &headers).await;

        if status == StatusCode::NOT_MODIFIED {
            compat::update_from_headers(state, &headers).await?;
            return Ok(ConfigResponse {
                status,
                headers,
                request_id: canonical_request_id,
                payload: None,
            });
        }

        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();

            if let Some(err) = compat::handle_error_response(state, &headers, &body).await? {
                warn!(%canonical_request_id, %status, error = %body, "config request blocked by compatibility");
                return Err(err.into());
            }

            warn!(%canonical_request_id, %status, error = %body, "config request failed");
            anyhow::bail!("config request failed: status {status}, body: {body}");
        }

        let payload = res
            .json::<NodeConfigResponse>()
            .await
            .context("decode node configs")?;

        compat::update_from_headers(state, &headers).await?;

        Ok(ConfigResponse {
            status,
            headers,
            request_id: canonical_request_id,
            payload: Some(payload),
        })
    }
}

fn desired_state_url(cfg: &config::AppConfig) -> String {
    let base = cfg.control_plane_url.trim_end_matches('/');
    format!("{}/api/v1/nodes/{}/desired-state", base, cfg.node_id)
}

pub(crate) fn heartbeat_url(cfg: &config::AppConfig) -> String {
    let base = cfg.control_plane_url.trim_end_matches('/');
    format!("{}/api/v1/nodes/{}/heartbeats", base, cfg.node_id)
}

fn configs_url(cfg: &config::AppConfig) -> String {
    let base = cfg.control_plane_url.trim_end_matches('/');
    format!("{}/api/v1/nodes/{}/configs", base, cfg.node_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SERVICE_IDENTITY_FINGERPRINT_HEADER, state, test_support::make_test_state};
    use httpmock::{Method::GET, MockServer};
    use uuid::Uuid;

    #[tokio::test]
    async fn fetch_desired_state_updates_traceparent_request_id() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/desired-state", node_id);
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

        let response = api::DesiredStateResponse {
            control_plane_version: "1.2.3".into(),
            min_supported_agent_version: "1.0.0".into(),
            max_supported_agent_version: None,
            upgrade_url: None,
            tunnel: None,
            deployments: vec![],
        };

        let _mock = server.mock(|when, then| {
            when.method(GET)
                .path(path.clone())
                .header(REQUEST_ID_HEADER, "seed-request");
            then.status(200)
                .header(crate::TRACEPARENT_HEADER, traceparent)
                .json_body_obj(&response);
        });

        let state = make_test_state(server.url(""), node_id, 5, 2, 50);
        state::set_request_id(&state, "seed-request".into()).await;

        let client = ControlPlaneClient::with_request_id(&state, "seed-request".into()).await;

        let res = client
            .fetch_desired_state(&state)
            .await
            .expect("desired state succeeds");
        assert!(res.body.deployments.is_empty());

        let stored = state::current_request_id(&state)
            .await
            .expect("request id stored");
        assert_eq!(stored, "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[tokio::test]
    async fn fetch_configs_includes_etag_and_fingerprint_headers() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/configs", node_id);

        let config = api::ConfigDesired {
            metadata: api::ConfigMetadata {
                config_id: Uuid::new_v4(),
                name: "cfg".into(),
                version: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            entries: Vec::new(),
            files: Vec::new(),
            attached_deployments: Vec::new(),
            attached_nodes: vec![node_id],
            checksum: None,
        };

        let response = api::NodeConfigResponse {
            configs: vec![config.clone()],
            service_identities: Vec::new(),
        };

        let _mock = server.mock(|when, then| {
            when.method(GET)
                .path(path.clone())
                .header(REQUEST_ID_HEADER, "seed-request")
                .header("if-none-match", "etag-1")
                .header(SERVICE_IDENTITY_FINGERPRINT_HEADER, "fp-1");
            then.status(200).json_body_obj(&response);
        });

        let state = make_test_state(server.url(""), node_id, 5, 2, 50);
        state::set_request_id(&state, "seed-request".into()).await;
        let client = ControlPlaneClient::with_request_id(&state, "seed-request".into()).await;

        let res = client
            .fetch_configs(&state, Some("etag-1"), Some("fp-1"))
            .await
            .expect("config fetch succeeds");

        assert_eq!(res.status, StatusCode::OK);
        let payload = res.payload.expect("payload present");
        assert_eq!(payload.configs.len(), 1);
        assert_eq!(payload.configs[0].metadata.name, "cfg");
    }

    #[tokio::test]
    async fn fetch_configs_returns_not_modified_payload_none() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/configs", node_id);
        let traceparent = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01";

        let _mock = server.mock(|when, then| {
            when.method(GET)
                .path(path.clone())
                .header(REQUEST_ID_HEADER, "seed-request")
                .header("if-none-match", "etag-2");
            then.status(304)
                .header(crate::TRACEPARENT_HEADER, traceparent);
        });

        let state = make_test_state(server.url(""), node_id, 5, 2, 50);
        state::set_request_id(&state, "seed-request".into()).await;
        let client = ControlPlaneClient::with_request_id(&state, "seed-request".into()).await;

        let res = client
            .fetch_configs(&state, Some("etag-2"), None)
            .await
            .expect("not modified is ok");

        assert_eq!(res.status, StatusCode::NOT_MODIFIED);
        assert!(res.payload.is_none());

        let stored = state::current_request_id(&state)
            .await
            .expect("request id stored");
        assert_eq!(stored, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }

    #[tokio::test]
    async fn fetch_configs_reports_error_on_failure_status() {
        let server = MockServer::start();
        let node_id = Uuid::new_v4();
        let path = format!("/api/v1/nodes/{}/configs", node_id);

        let _mock = server.mock(|when, then| {
            when.method(GET)
                .path(path.clone())
                .header(REQUEST_ID_HEADER, "seed-request");
            then.status(500).body("boom");
        });

        let state = make_test_state(server.url(""), node_id, 5, 2, 50);
        state::set_request_id(&state, "seed-request".into()).await;
        let client = ControlPlaneClient::with_request_id(&state, "seed-request".into()).await;

        let err = client
            .fetch_configs(&state, None, None)
            .await
            .expect_err("fetch should fail");

        assert!(err.to_string().contains("config request failed"));
    }
}
