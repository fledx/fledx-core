use super::*;
use axum::routing::get;

pub fn api_router() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/metrics", get(metrics))
        .route("/health", get(healthz))
}

pub fn metrics_router() -> Router<AppState> {
    Router::<AppState>::new().route("/metrics", get(metrics))
}
