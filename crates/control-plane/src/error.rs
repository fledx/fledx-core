use tracing::error;

/// Application error type for HTTP handlers.
#[derive(Debug)]
pub struct AppError {
    pub status: axum::http::StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub type ApiResult<T> = std::result::Result<T, AppError>;

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: msg.into(),
        }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: msg.into(),
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "forbidden",
            message: msg.into(),
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::NOT_FOUND,
            code: "not_found",
            message: msg.into(),
        }
    }

    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            code: "service_unavailable",
            message: msg.into(),
        }
    }

    pub fn payload_too_large(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: msg.into(),
        }
    }

    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: msg.into(),
        }
    }

    pub fn internal(msg: &str) -> Self {
        Self {
            status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: msg.to_string(),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        crate::telemetry::record_internal_error_metrics(&err);
        error!(?err, "internal error");
        AppError::internal("internal server error")
    }
}
