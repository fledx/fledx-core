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
