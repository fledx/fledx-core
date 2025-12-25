use super::*;
use axum::{middleware, routing::get};

pub fn api_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/metrics",
            get(metrics).route_layer(middleware::from_fn_with_state(state, require_operator_auth)),
        )
        .route("/health", get(healthz))
}

pub fn metrics_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new().route(
        "/metrics",
        get(metrics).route_layer(middleware::from_fn_with_state(state, require_operator_auth)),
    )
}
