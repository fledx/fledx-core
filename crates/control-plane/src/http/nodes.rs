use super::*;

pub fn router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/v1/nodes/{node_id}", axum::routing::get(node_status))
        .route("/api/v1/nodes", axum::routing::get(list_nodes))
        .route(
            "/api/v1/configs/{config_id}/nodes/{node_id}",
            axum::routing::post(attach_config_to_node).delete(detach_config_from_node),
        )
        .route_layer(middleware::from_fn_with_state(state, require_operator_auth))
}
