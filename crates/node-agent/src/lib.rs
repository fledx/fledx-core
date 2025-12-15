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
