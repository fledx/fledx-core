use axum::{extract::Extension, http::Request};
use metrics::counter;
use sqlx::Error as SqlxError;
use tower_http::request_id::RequestId;
use tracing::warn;

use crate::app_state::AppState;
use crate::audit::{AuditContext, AuditStatus};

pub(crate) fn request_id_from_extension(
    request_id: Option<Extension<RequestId>>,
) -> Option<String> {
    request_id.and_then(|id| request_id_value(&id))
}

pub(crate) fn request_id_from_request<B>(req: &Request<B>) -> Option<String> {
    req.extensions()
        .get::<RequestId>()
        .and_then(request_id_value)
}

fn request_id_value(id: &RequestId) -> Option<String> {
    id.header_value()
        .to_str()
        .ok()
        .map(|value| value.to_string())
}

pub async fn record_audit_log(
    state: &AppState,
    action: &str,
    resource_type: &str,
    status: AuditStatus,
    context: AuditContext<'_>,
) {
    if let Err(err) = crate::audit::record(state, action, resource_type, status, context).await {
        warn!(?err, "failed to record audit log");
    }
}

pub(crate) fn record_internal_error_metrics(err: &anyhow::Error) {
    counter!("control_plane_internal_errors_total").increment(1);
    if let Some(db_err) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<SqlxError>())
    {
        let kind = match db_err {
            SqlxError::RowNotFound => "row_not_found",
            SqlxError::Database(_) => "database",
            SqlxError::Io(_) => "io",
            SqlxError::Tls(_) => "tls",
            _ => "other",
        };
        counter!("control_plane_db_errors_total", "kind" => kind).increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn request_id_from_request_returns_value() {
        let mut req = Request::new(());
        req.extensions_mut()
            .insert(RequestId::new(HeaderValue::from_static("req-123")));

        assert_eq!(request_id_from_request(&req), Some("req-123".to_string()));
    }

    #[test]
    fn request_id_from_request_returns_none_when_missing() {
        let req = Request::new(());
        assert!(request_id_from_request(&req).is_none());
    }

    #[test]
    fn request_id_from_request_returns_none_for_invalid_header_value() {
        let invalid = HeaderValue::from_bytes(&[0xFF]).expect("header value allows opaque bytes");
        let mut req = Request::new(());
        req.extensions_mut().insert(RequestId::new(invalid));

        assert!(request_id_from_request(&req).is_none());
    }

    #[test]
    fn request_id_from_extension_handles_present_and_missing() {
        let ext = Extension(RequestId::new(HeaderValue::from_static("req-456")));
        assert_eq!(
            request_id_from_extension(Some(ext)),
            Some("req-456".to_string())
        );
        assert!(request_id_from_extension(None).is_none());
    }
}
