use super::*;

pub fn router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/api/v1/deployments",
            axum::routing::get(list_deployments).post(create_deployment),
        )
        .route(
            "/api/v1/deployments/{deployment_id}",
            axum::routing::get(deployment_status)
                .patch(update_deployment)
                .delete(delete_deployment),
        )
        .route(
            "/api/v1/deployments/{deployment_id}/metrics",
            axum::routing::get(deployment_metrics),
        )
        .route(
            "/api/v1/configs",
            axum::routing::get(list_configs).post(create_config),
        )
        .route(
            "/api/v1/configs/{config_id}",
            axum::routing::get(get_config)
                .put(update_config)
                .delete(delete_config),
        )
        .route(
            "/api/v1/configs/{config_id}/deployments/{deployment_id}",
            axum::routing::post(attach_config_to_deployment).delete(detach_config_from_deployment),
        )
        .route_layer(middleware::from_fn_with_state(state, require_operator_auth))
}
