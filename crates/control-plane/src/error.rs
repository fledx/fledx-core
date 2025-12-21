use axum::http::HeaderMap;
use sqlx::{error::DatabaseError, Error as SqlxError};
use tracing::error;

/// Application error type for HTTP handlers.
#[derive(Debug)]
pub struct AppError {
    pub status: axum::http::StatusCode,
    pub code: &'static str,
    pub message: String,
    pub headers: Option<Box<HeaderMap>>,
}

pub type ApiResult<T> = std::result::Result<T, AppError>;

const DB_UNAVAILABLE_MESSAGE: &str = "database temporarily unavailable";

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: msg.into(),
            headers: None,
        }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: msg.into(),
            headers: None,
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "forbidden",
            message: msg.into(),
            headers: None,
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::NOT_FOUND,
            code: "not_found",
            message: msg.into(),
            headers: None,
        }
    }

    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            code: "service_unavailable",
            message: msg.into(),
            headers: None,
        }
    }

    pub fn payload_too_large(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: msg.into(),
            headers: None,
        }
    }

    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: msg.into(),
            headers: None,
        }
    }

    pub fn internal(msg: &str) -> Self {
        Self {
            status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: msg.to_string(),
            headers: None,
        }
    }

    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = Some(Box::new(headers));
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DbErrorKind {
    UniqueViolation,
    ForeignKeyViolation,
    NotNullViolation,
    CheckViolation,
    SerializationFailure,
    Deadlock,
    Busy,
}

fn map_anyhow_error(err: &anyhow::Error) -> Option<AppError> {
    let sqlx_err = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<SqlxError>())?;
    map_sqlx_error(sqlx_err)
}

fn map_sqlx_error(err: &SqlxError) -> Option<AppError> {
    match err {
        SqlxError::RowNotFound => Some(AppError::not_found("resource not found")),
        SqlxError::Database(db_err) => map_database_error(db_err.as_ref()),
        SqlxError::PoolTimedOut | SqlxError::PoolClosed => {
            Some(AppError::service_unavailable(DB_UNAVAILABLE_MESSAGE))
        }
        SqlxError::Io(_) | SqlxError::Tls(_) => {
            Some(AppError::service_unavailable(DB_UNAVAILABLE_MESSAGE))
        }
        _ => None,
    }
}

fn map_database_error(err: &dyn DatabaseError) -> Option<AppError> {
    let kind = classify_db_error(err.code().as_deref(), err.message())?;
    match kind {
        DbErrorKind::UniqueViolation => Some(AppError::bad_request("resource already exists")),
        DbErrorKind::ForeignKeyViolation => Some(AppError::bad_request("invalid reference")),
        DbErrorKind::NotNullViolation => Some(AppError::bad_request("missing required field")),
        DbErrorKind::CheckViolation => Some(AppError::bad_request("invalid request")),
        DbErrorKind::SerializationFailure | DbErrorKind::Deadlock | DbErrorKind::Busy => {
            Some(AppError::service_unavailable(DB_UNAVAILABLE_MESSAGE))
        }
    }
}

fn classify_db_error(code: Option<&str>, message: &str) -> Option<DbErrorKind> {
    let code = code.unwrap_or_default();
    let message = message.to_ascii_lowercase();

    if matches!(code, "23505" | "2067" | "1555")
        || message.contains("unique constraint")
        || message.contains("duplicate key")
    {
        return Some(DbErrorKind::UniqueViolation);
    }

    if matches!(code, "23503" | "787") || message.contains("foreign key constraint") {
        return Some(DbErrorKind::ForeignKeyViolation);
    }

    if code == "23502" || message.contains("not null constraint") {
        return Some(DbErrorKind::NotNullViolation);
    }

    if code == "23514" || message.contains("check constraint") {
        return Some(DbErrorKind::CheckViolation);
    }

    if code == "40001" || message.contains("serialization failure") {
        return Some(DbErrorKind::SerializationFailure);
    }

    if code == "40P01" || message.contains("deadlock") {
        return Some(DbErrorKind::Deadlock);
    }

    if message.contains("database is locked") || message.contains("database is busy") {
        return Some(DbErrorKind::Busy);
    }

    None
}

pub fn is_unique_violation(err: &anyhow::Error) -> bool {
    let Some(sqlx_err) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<SqlxError>())
    else {
        return false;
    };

    match sqlx_err {
        SqlxError::Database(db_err) => matches!(
            classify_db_error(db_err.code().as_deref(), db_err.message()),
            Some(DbErrorKind::UniqueViolation)
        ),
        _ => false,
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        if let Some(mapped) = map_anyhow_error(&err) {
            if mapped.status.is_server_error() {
                crate::telemetry::record_internal_error_metrics(&err);
                error!(?err, "internal error");
            }
            return mapped;
        }

        crate::telemetry::record_internal_error_metrics(&err);
        error!(?err, "internal error");
        AppError::internal("internal server error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn classify_db_error_detects_unique_constraints() {
        assert_eq!(
            classify_db_error(
                Some("23505"),
                "duplicate key value violates unique constraint"
            ),
            Some(DbErrorKind::UniqueViolation)
        );
        assert_eq!(
            classify_db_error(None, "UNIQUE constraint failed: tls_certs.ref"),
            Some(DbErrorKind::UniqueViolation)
        );
    }

    #[test]
    fn classify_db_error_detects_foreign_key_constraints() {
        assert_eq!(
            classify_db_error(None, "FOREIGN KEY constraint failed"),
            Some(DbErrorKind::ForeignKeyViolation)
        );
    }

    #[test]
    fn classify_db_error_detects_not_null_constraints() {
        assert_eq!(
            classify_db_error(None, "NOT NULL constraint failed: configs.name"),
            Some(DbErrorKind::NotNullViolation)
        );
    }

    #[test]
    fn classify_db_error_detects_check_constraints() {
        assert_eq!(
            classify_db_error(None, "CHECK constraint failed"),
            Some(DbErrorKind::CheckViolation)
        );
    }

    #[test]
    fn classify_db_error_detects_retryable_db_failures() {
        assert_eq!(
            classify_db_error(Some("40001"), "serialization failure"),
            Some(DbErrorKind::SerializationFailure)
        );
        assert_eq!(
            classify_db_error(Some("40P01"), "deadlock detected"),
            Some(DbErrorKind::Deadlock)
        );
        assert_eq!(
            classify_db_error(None, "database is locked"),
            Some(DbErrorKind::Busy)
        );
    }

    #[test]
    fn row_not_found_maps_to_not_found_app_error() {
        let err = AppError::from(anyhow::Error::new(SqlxError::RowNotFound));
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.code, "not_found");
        assert_eq!(err.message, "resource not found");
    }
}
