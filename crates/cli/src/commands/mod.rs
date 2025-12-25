use crate::api::{OperatorApi, SessionTokenCache};
use anyhow::Context;
use std::sync::Arc;

#[cfg(feature = "bootstrap")]
pub mod bootstrap;
pub mod completions;
pub mod configs;
pub mod deploy;
#[cfg(feature = "bootstrap")]
pub mod internal;
pub mod metrics;
pub mod nodes;
#[cfg(feature = "bootstrap")]
pub mod profiles;
pub mod status;
pub mod usage;

#[derive(Clone)]
pub struct CommandContext {
    pub client: reqwest::Client,
    pub base: String,
    pub operator_header: String,
    pub operator_token: Option<String>,
    pub session_cache: Option<Arc<SessionTokenCache>>,
}

impl CommandContext {
    pub fn new(
        client: reqwest::Client,
        base: String,
        operator_header: String,
        operator_token: Option<String>,
    ) -> Self {
        Self {
            client,
            base,
            operator_header,
            operator_token,
            session_cache: None,
        }
    }

    pub fn new_with_session(
        client: reqwest::Client,
        base: String,
        operator_header: String,
        operator_token: Option<String>,
        session_cache: Arc<SessionTokenCache>,
    ) -> Self {
        Self {
            client,
            base,
            operator_header,
            operator_token,
            session_cache: Some(session_cache),
        }
    }

    pub fn operator_api(&self) -> anyhow::Result<OperatorApi> {
        if let Some(cache) = &self.session_cache {
            return Ok(OperatorApi::new_with_session(
                self.client.clone(),
                self.base.clone(),
                self.operator_header.clone(),
                cache.clone(),
            ));
        }
        let token = resolve_operator_token(&self.operator_token)?;
        Ok(make_operator_api(
            &self.client,
            &self.base,
            &self.operator_header,
            &token,
        ))
    }
}

pub fn build_client(ca_cert_path: &Option<String>) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();

    if let Some(path) = ca_cert_path.as_deref() {
        let pem = std::fs::read(path).with_context(|| format!("read CA certificate: {path}"))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .context("parse CA certificate PEM for CLI client")?;
        builder = builder.add_root_certificate(cert);
    }

    builder.build().context("build CLI HTTP client")
}

fn resolve_operator_token(operator_token: &Option<String>) -> anyhow::Result<String> {
    operator_token.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "operator token is required; pass --operator-token or set FLEDX_CLI_OPERATOR_TOKEN"
        )
    })
}

fn make_operator_api(
    client: &reqwest::Client,
    base: &str,
    operator_header: &str,
    operator_token: &str,
) -> OperatorApi {
    OperatorApi::new(
        client.clone(),
        base.to_string(),
        operator_header.to_string(),
        operator_token.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::SessionTokenConfig;
    use std::sync::Arc;

    #[test]
    fn resolve_operator_token_returns_error_when_missing() {
        let err = resolve_operator_token(&None).expect_err("should fail");
        assert!(err.to_string().contains("operator token is required"));
    }

    #[test]
    fn resolve_operator_token_returns_value() {
        let token = resolve_operator_token(&Some("token-123".to_string())).expect("token");
        assert_eq!(token, "token-123");
    }

    #[test]
    fn build_client_errors_on_missing_ca_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.pem");
        let err = build_client(&Some(missing.display().to_string())).expect_err("should fail");
        assert!(
            err.to_string()
                .contains(&format!("read CA certificate: {}", missing.display()))
        );
    }

    #[test]
    fn build_client_errors_on_invalid_ca_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("invalid.pem");
        let invalid_pem = b"-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----\n";
        std::fs::write(&path, invalid_pem).expect("write");
        let err = build_client(&Some(path.display().to_string())).expect_err("should fail");
        let message = err.to_string();
        assert!(
            message.contains("parse CA certificate PEM for CLI client")
                || message.contains("build CLI HTTP client"),
            "{message}"
        );
    }

    #[test]
    fn operator_api_uses_static_token_when_no_session_cache() {
        let ctx = CommandContext::new(
            reqwest::Client::new(),
            "http://example".to_string(),
            "authorization".to_string(),
            Some("token".to_string()),
        );
        let api = ctx.operator_api().expect("api");
        let req = api
            .apply_auth(reqwest::Client::new().get("http://example"))
            .expect("apply auth");
        let req = req.build().expect("build");
        let header = req.headers().get("authorization").expect("header");
        assert_eq!(header.to_str().expect("value"), "Bearer token");
    }

    #[test]
    fn operator_api_uses_session_cache_when_present() {
        let cache = SessionTokenCache::new(
            reqwest::Client::new(),
            "http://example",
            "authorization",
            "token",
            "fp",
            SessionTokenConfig::default(),
        )
        .expect("cache");
        let ctx = CommandContext::new_with_session(
            reqwest::Client::new(),
            "http://example".to_string(),
            "authorization".to_string(),
            None,
            Arc::new(cache),
        );
        let api = ctx.operator_api().expect("api");
        let err = api
            .apply_auth(reqwest::Client::new().get("http://example"))
            .expect_err("session auth should fail");
        assert!(
            err.to_string()
                .contains("session-auth requires async request path")
        );
    }
}
