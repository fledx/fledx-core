use axum::http::HeaderMap;

use crate::app_state::AppState;

/// Convenience wrapper used by handlers to attach compatibility headers.
pub fn add_headers(state: &AppState, headers: &mut HeaderMap) {
    crate::http::add_compatibility_headers(state, headers);
}
