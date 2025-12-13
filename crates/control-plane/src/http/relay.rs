use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::{
    body::{self, Body},
    extract::{Path, State},
    http::{HeaderName, HeaderValue, Request, StatusCode},
    response::IntoResponse,
    routing::any,
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use metrics::{counter, histogram};
use serde::Serialize;
use tracing::warn;
use uuid::Uuid;

use crate::{app_state::AppState, tunnel::ForwardError};

const RELAY_TIMEOUT_SECS: u64 = 30;
const RELAY_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Serialize)]
struct RelayError {
    error: &'static str,
    message: String,
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/relay/{node_id}/{*path}", any(relay_handler))
        .with_state(state)
}

async fn relay_handler(
    State(state): State<AppState>,
    Path((node_id, _path)): Path<(Uuid, String)>,
    req: Request<Body>,
) -> impl IntoResponse {
    let forward_path =
        extract_forward_path(node_id, req.uri().path_and_query().map(|pq| pq.as_str()));
    let method = req.method().as_str().to_string();
    let headers = flatten_headers(req.headers());
    let start = Instant::now();

    let body_bytes = match body::to_bytes(req.into_body(), RELAY_BODY_LIMIT_BYTES).await {
        Ok(bytes) => bytes,
        Err(err) => {
            state.relay_health.record_error("invalid_body").await;
            counter!(
                "control_plane_relay_requests_total",
                "node_id" => node_id.to_string(),
                "result" => "invalid_body"
            )
            .increment(1);
            histogram!(
                "control_plane_relay_request_duration_seconds",
                "node_id" => node_id.to_string(),
                "result" => "invalid_body"
            )
            .record(start.elapsed().as_secs_f64());
            return relay_error(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                format!("failed to read body: {}", err),
            );
        }
    };

    let timeout = Duration::from_secs(RELAY_TIMEOUT_SECS);
    let result = state
        .tunnel_registry
        .forward_request(
            node_id,
            method,
            forward_path,
            headers,
            body_bytes.to_vec(),
            timeout,
        )
        .await;

    let (result_label, response) = match result {
        Ok(response) => {
            state.relay_health.record_success().await;
            ("ok", build_http_response(response))
        }
        Err(err) => {
            let (label, response) = map_forward_error(err);
            state.relay_health.record_error(label).await;
            (label, response)
        }
    };

    counter!(
        "control_plane_relay_requests_total",
        "node_id" => node_id.to_string(),
        "result" => result_label.to_string()
    )
    .increment(1);
    histogram!(
        "control_plane_relay_request_duration_seconds",
        "node_id" => node_id.to_string(),
        "result" => result_label.to_string()
    )
    .record(start.elapsed().as_secs_f64());

    response
}

fn extract_forward_path(node_id: Uuid, path_and_query: Option<&str>) -> String {
    let prefix = format!("/relay/{}", node_id);
    let remainder = path_and_query
        .and_then(|pq| pq.strip_prefix(&prefix))
        .unwrap_or("");

    if remainder.is_empty() {
        "/".to_string()
    } else {
        remainder.to_string()
    }
}

fn flatten_headers(map: &axum::http::HeaderMap) -> HashMap<String, String> {
    map.iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect()
}

fn build_http_response(response: crate::tunnel::ForwardResponse) -> axum::response::Response {
    let mut builder = axum::response::Response::builder();
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    builder = builder.status(status);

    for (key, value) in response.headers.iter() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(key.to_ascii_lowercase().as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(name, value);
        } else {
            warn!(header = key, "skipping invalid header from tunnel response");
        }
    }

    let body = match general_purpose::STANDARD.decode(response.body_b64) {
        Ok(bytes) => Body::from(bytes),
        Err(err) => {
            return relay_error(
                StatusCode::BAD_GATEWAY,
                "invalid_response_body",
                format!("failed to decode response body: {}", err),
            );
        }
    };

    builder.body(body).unwrap_or_else(|err| {
        relay_error(
            StatusCode::BAD_GATEWAY,
            "response_build_failed",
            err.to_string(),
        )
    })
}

fn map_forward_error(err: ForwardError) -> (&'static str, axum::response::Response) {
    match err {
        ForwardError::NoTunnel => (
            "tunnel_unavailable",
            relay_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tunnel_unavailable",
                "no active tunnel for node".to_string(),
            ),
        ),
        ForwardError::Overloaded => (
            "tunnel_overloaded",
            relay_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "tunnel_overloaded",
                "tunnel is at capacity".to_string(),
            ),
        ),
        ForwardError::Timeout => (
            "tunnel_timeout",
            relay_error(
                StatusCode::GATEWAY_TIMEOUT,
                "tunnel_timeout",
                "no response before timeout".to_string(),
            ),
        ),
        ForwardError::ChannelClosed => (
            "tunnel_closed",
            relay_error(
                StatusCode::BAD_GATEWAY,
                "tunnel_closed",
                "tunnel closed unexpectedly".to_string(),
            ),
        ),
        ForwardError::Other(message) => (
            "tunnel_error",
            relay_error(StatusCode::BAD_GATEWAY, "tunnel_error", message),
        ),
    }
}

fn relay_error(
    status: StatusCode,
    code: &'static str,
    message: String,
) -> axum::response::Response {
    let body = Json(RelayError {
        error: code,
        message,
    });
    (status, body).into_response()
}
