use crate::api::OperatorApi;
use anyhow::Context;

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
        }
    }

    pub fn operator_api(&self) -> anyhow::Result<OperatorApi> {
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
