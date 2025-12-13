use super::*;

pub fn router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/api/v1/metrics/summary",
            axum::routing::get(metrics_summary),
        )
        .route("/api/v1/usage", axum::routing::get(list_usage_rollups))
        .route_layer(middleware::from_fn_with_state(state, require_operator_auth))
}
