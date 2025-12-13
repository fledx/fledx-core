use super::*;
use axum::routing::get;

pub fn router() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/metrics", get(metrics))
        .route("/health", get(healthz))
}
