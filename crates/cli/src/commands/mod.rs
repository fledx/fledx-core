use crate::api::OperatorApi;

pub mod completions;
pub mod configs;
pub mod deploy;
pub mod metrics;
pub mod nodes;
pub mod status;
pub mod usage;
#[cfg(feature = "bootstrap")]
pub mod bootstrap;
#[cfg(feature = "bootstrap")]
pub mod profiles;

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
