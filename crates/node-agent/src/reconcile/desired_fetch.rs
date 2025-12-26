use tracing::info;

use crate::{api, services::reconcile::DesiredStateClient, state};

pub(crate) async fn fetch_desired_state_with_client<C: DesiredStateClient>(
    state: &state::SharedState,
    client: &C,
    _request_id: String,
) -> anyhow::Result<api::DesiredStateResponse> {
    let response = client.fetch_desired_state(state).await?;
    let body = response.body;
    info!(
        request_id = %response.request_id,
        deployments = body.deployments.len(),
        "fetched desired state"
    );
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api,
        runtime::ContainerRuntimeError,
        state::RuntimeFactory,
        test_support::{FakeCpClient, base_config},
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn fetch_desired_state_returns_body() -> anyhow::Result<()> {
        let deployment = api::DeploymentDesired {
            deployment_id: Uuid::new_v4(),
            name: "example/app:1".into(),
            replica_number: 0,
            image: "example/app:1".into(),
            replicas: 1,
            command: None,
            env: None,
            secret_env: None,
            secret_files: None,
            ports: None,
            volumes: None,
            requires_public_ip: false,
            tunnel_only: false,
            placement: None,
            health: None,
            desired_state: api::DesiredState::Running,
            replica_generation: Some(1),
            generation: 1,
        };

        let response = api::DesiredStateResponse {
            control_plane_version: "test".into(),
            min_supported_agent_version: "0.0.0".into(),
            max_supported_agent_version: None,
            upgrade_url: None,
            tunnel: None,
            deployments: vec![deployment.clone()],
        };

        let client = FakeCpClient::with_desired(response.clone());
        let runtime_factory: RuntimeFactory = std::sync::Arc::new(|| {
            Err(ContainerRuntimeError::Connection {
                context: "test",
                source: anyhow::anyhow!("down"),
            })
        });
        let state = state::new_state(base_config(), reqwest::Client::new(), runtime_factory, None);

        let result = fetch_desired_state_with_client(&state, &client, "request".into()).await?;

        assert_eq!(result, response);
        Ok(())
    }

    #[tokio::test]
    async fn fetch_desired_state_propagates_errors() {
        let client = FakeCpClient::default();
        client.set_desired_error("boom");
        let runtime_factory: RuntimeFactory = std::sync::Arc::new(|| {
            Err(ContainerRuntimeError::Connection {
                context: "test",
                source: anyhow::anyhow!("down"),
            })
        });
        let state = state::new_state(base_config(), reqwest::Client::new(), runtime_factory, None);

        let err = fetch_desired_state_with_client(&state, &client, "request".into())
            .await
            .expect_err("expected error");

        assert_eq!(err.to_string(), "boom");
    }
}
