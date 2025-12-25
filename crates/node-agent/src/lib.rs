use anyhow::Context;
use reqwest::header::{HeaderMap, HeaderValue};
use tracing::warn;

pub mod api;
pub mod compat;
pub mod config;
pub mod configs;
pub mod cp_client;
pub mod health;
pub mod heartbeat;
pub mod reconcile;
pub mod runner;
pub mod runtime;
pub mod sampler;
pub mod services;
pub mod state;
pub mod telemetry;
pub mod validation;
pub mod version;

#[cfg(test)]
pub mod test_support;

pub const REQUEST_ID_HEADER: &str = "x-request-id";
pub const TRACEPARENT_HEADER: &str = "traceparent";
pub const AGENT_VERSION_HEADER: &str = "x-agent-version";
pub const AGENT_BUILD_HEADER: &str = "x-agent-build";
/// Fingerprint header used to avoid re-sending unchanged service identity bundles.
pub const SERVICE_IDENTITY_FINGERPRINT_HEADER: &str = "x-fledx-service-identities-fingerprint";

pub fn validate_control_plane_url(cfg: &config::AppConfig) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(&cfg.control_plane_url)?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if cfg.allow_insecure_http => {
            warn!(
                cp = %cfg.control_plane_url,
                "insecure HTTP control-plane URL in use; traffic will be unencrypted"
            );
            Ok(())
        }
        "http" => anyhow::bail!(
            "insecure control-plane URL not allowed: {}; set allow_insecure_http=true to override",
            cfg.control_plane_url
        ),
        other => anyhow::bail!("unsupported URL scheme: {}", other),
    }
}

pub fn build_client(cfg: &config::AppConfig) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();

    builder = builder.default_headers(build_agent_headers()?);

    if let Some(ca_path) = cfg.ca_cert_path.as_ref() {
        let pem = std::fs::read(ca_path)
            .map_err(|err| anyhow::anyhow!("failed to read ca_cert_path {}: {}", ca_path, err))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|err| anyhow::anyhow!("invalid certificate in {}: {}", ca_path, err))?;
        builder = builder.add_root_certificate(cert);
    }

    if cfg.tls_insecure_skip_verify {
        warn!("TLS certificate verification is disabled; use only for development");
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder.build().map_err(Into::into)
}

fn build_agent_headers() -> anyhow::Result<HeaderMap> {
    if version::VERSION.trim().is_empty() {
        anyhow::bail!("agent version metadata missing; refusing to start");
    }
    if version::GIT_SHA.trim().is_empty() || version::GIT_SHA == "unknown" {
        anyhow::bail!("agent build metadata missing; refusing to start");
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        AGENT_VERSION_HEADER,
        HeaderValue::from_str(version::VERSION).context("invalid agent version header value")?,
    );
    headers.insert(
        AGENT_BUILD_HEADER,
        HeaderValue::from_str(version::GIT_SHA).context("invalid agent build header value")?,
    );

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_config;
    use uuid::Uuid;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("node-agent-{}-{}", name, Uuid::new_v4()));
        path
    }

    #[test]
    fn validate_control_plane_url_accepts_https() {
        let mut cfg = base_config();
        cfg.control_plane_url = "https://control.example".into();
        cfg.allow_insecure_http = false;

        validate_control_plane_url(&cfg).expect("https should be allowed");
    }

    #[test]
    fn validate_control_plane_url_allows_http_when_insecure_enabled() {
        let mut cfg = base_config();
        cfg.control_plane_url = "http://control.example".into();
        cfg.allow_insecure_http = true;

        validate_control_plane_url(&cfg).expect("http allowed when insecure flag is set");
    }

    #[test]
    fn validate_control_plane_url_rejects_http_when_disallowed() {
        let mut cfg = base_config();
        cfg.control_plane_url = "http://control.example".into();
        cfg.allow_insecure_http = false;

        let err = validate_control_plane_url(&cfg).expect_err("http should be rejected");
        assert!(
            err.to_string()
                .contains("insecure control-plane URL not allowed")
        );
    }

    #[test]
    fn validate_control_plane_url_rejects_unknown_scheme() {
        let mut cfg = base_config();
        cfg.control_plane_url = "ftp://control.example".into();

        let err = validate_control_plane_url(&cfg).expect_err("unsupported scheme");
        assert!(err.to_string().contains("unsupported URL scheme"));
    }

    #[test]
    fn build_client_allows_insecure_tls_toggle() {
        let mut cfg = base_config();
        cfg.tls_insecure_skip_verify = true;

        build_client(&cfg).expect("client should build");
    }

    #[test]
    fn build_client_errors_on_missing_ca_file() {
        let mut cfg = base_config();
        cfg.ca_cert_path = Some("/no/such/ca.pem".into());

        let err = build_client(&cfg).expect_err("missing CA file");
        assert!(err.to_string().contains("failed to read ca_cert_path"));
    }

    #[test]
    fn build_client_errors_on_invalid_ca_file() {
        let mut cfg = base_config();
        let path = temp_path("bad-ca.pem");
        let invalid_pem = b"-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n";
        std::fs::write(&path, invalid_pem).expect("write temp file");
        cfg.ca_cert_path = Some(path.to_string_lossy().to_string());

        let err = build_client(&cfg).expect_err("invalid CA file");
        let message = err.to_string();
        assert!(
            !message.contains("failed to read ca_cert_path"),
            "expected parse error, got: {message}"
        );

        let _ = std::fs::remove_file(path);
    }
}
