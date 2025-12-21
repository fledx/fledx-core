use super::*;
use tower_http::limit::RequestBodyLimitLayer;

async fn require_agent_rate_limit(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> ApiResult<Response> {
    if let Some(limiter) = &state.agent_limiter {
        let mut limiter = limiter.lock().await;
        let decision = limiter.acquire();
        if !decision.allowed {
            return Err(AppError::too_many_requests("agent rate limit exceeded")
                .with_headers(decision.headers()));
        }
    }

    Ok(next.run(req).await)
}

pub fn router(state: AppState) -> Router<AppState> {
    let reg_limit = state.limits.registration_body_bytes;
    let hb_limit = state.limits.heartbeat_body_bytes;

    let registration = Router::<AppState>::new().route(
        "/api/v1/nodes/register",
        axum::routing::post(register_node).layer(RequestBodyLimitLayer::new(reg_limit as usize)),
    );

    let agent_routes = Router::<AppState>::new()
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
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_agent_rate_limit,
        ));

    Router::<AppState>::new()
        .merge(registration)
        .merge(agent_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_agent_compatibility,
        ))
}
