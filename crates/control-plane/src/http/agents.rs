use super::*;
use tower_http::limit::RequestBodyLimitLayer;

pub fn router(state: AppState) -> Router<AppState> {
    let reg_limit = state.limits.registration_body_bytes;
    let hb_limit = state.limits.heartbeat_body_bytes;

    Router::<AppState>::new()
        .route(
            "/api/v1/nodes/register",
            axum::routing::post(register_node)
                .layer(RequestBodyLimitLayer::new(reg_limit as usize)),
        )
        .route(
            "/api/v1/nodes/{node_id}/heartbeats",
            axum::routing::post(heartbeat).layer(RequestBodyLimitLayer::new(hb_limit as usize)),
        )
        .route(
            "/api/v1/nodes/{node_id}/desired-state",
            axum::routing::get(desired_state),
        )
        .route(
            "/api/v1/nodes/{node_id}/configs",
            axum::routing::get(node_configs),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_agent_compatibility,
        ))
}
