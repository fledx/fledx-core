use axum::{Json, response::IntoResponse};

use crate::error::AppError;

pub(crate) fn map_service_error<E>(err: E) -> AppError
where
    E: Into<anyhow::Error>,
{
    err.into().into()
}

pub(crate) fn into_response(err: AppError) -> axum::response::Response {
    let body = Json(serde_json::json!({
        "error": err.message,
        "code": err.code,
    }));
    let mut response = (err.status, body).into_response();
    if let Some(headers) = err.headers.as_deref() {
        for (name, value) in headers.iter() {
            response.headers_mut().insert(name.clone(), value.clone());
        }
    }
    response
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        into_response(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde_json::json;

    #[test]
    fn map_service_error_round_trips_into_app_error() {
        let err = map_service_error(anyhow::anyhow!("boom"));
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, "internal_error");
        assert_eq!(err.message, "internal server error");
    }

    #[tokio::test]
    async fn into_response_exposes_code_and_message() {
        let app_error = AppError {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: "nope".into(),
            headers: None,
        };
        let response = into_response(app_error);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload, json!({"error": "nope", "code": "bad_request"}));
    }
}
