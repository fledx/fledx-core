use axum::http::HeaderMap;
use sqlx::{Error as SqlxError, error::DatabaseError};
use std::fmt;
use tracing::error;

/// Application error type for HTTP handlers.
#[derive(Debug, Clone)]
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

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}

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
        let err = match err.downcast::<AppError>() {
            Ok(app_err) => return app_err,
            Err(err) => err,
        };
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
    use sqlx::error::ErrorKind;
    use std::borrow::Cow;
    use std::error::Error as StdError;
    use std::fmt;

    #[derive(Debug)]
    struct FakeDbError {
        code: Option<String>,
        message: String,
    }

    impl FakeDbError {
        fn new(code: Option<&str>, message: &str) -> Self {
            Self {
                code: code.map(str::to_string),
                message: message.to_string(),
            }
        }
    }

    impl fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl StdError for FakeDbError {}

    impl DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            &self.message
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.as_deref().map(Cow::Borrowed)
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

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

    #[test]
    fn pool_timeout_maps_to_service_unavailable() {
        let err = AppError::from(anyhow::Error::new(SqlxError::PoolTimedOut));
        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code, "service_unavailable");
        assert_eq!(err.message, DB_UNAVAILABLE_MESSAGE);
    }

    #[test]
    fn database_unique_violation_maps_to_bad_request() {
        let db_err = FakeDbError::new(Some("23505"), "duplicate key value");
        let err = AppError::from(anyhow::Error::new(SqlxError::Database(Box::new(db_err))));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "bad_request");
        assert_eq!(err.message, "resource already exists");
    }

    #[test]
    fn database_not_null_violation_maps_to_bad_request() {
        let db_err = FakeDbError::new(Some("23502"), "NOT NULL constraint failed");
        let err = AppError::from(anyhow::Error::new(SqlxError::Database(Box::new(db_err))));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "bad_request");
        assert_eq!(err.message, "missing required field");
    }

    #[test]
    fn map_database_error_returns_none_for_unclassified() {
        let db_err = FakeDbError::new(Some("99999"), "some other error");
        assert!(map_database_error(&db_err).is_none());
    }

    #[test]
    fn io_error_maps_to_service_unavailable() {
        let io_err = std::io::Error::other("boom");
        let err = AppError::from(anyhow::Error::new(SqlxError::Io(io_err)));
        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code, "service_unavailable");
        assert_eq!(err.message, DB_UNAVAILABLE_MESSAGE);
    }

    #[test]
    fn with_headers_includes_header_map() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "value".parse().expect("header value"));
        let err = AppError::bad_request("oops").with_headers(headers);
        let stored = err.headers.expect("headers");
        assert_eq!(
            stored.get("x-test").and_then(|value| value.to_str().ok()),
            Some("value")
        );
    }

    #[test]
    fn is_unique_violation_detects_database_error() {
        let db_err = FakeDbError::new(Some("23505"), "duplicate key value");
        let err = anyhow::Error::new(SqlxError::Database(Box::new(db_err)));
        assert!(is_unique_violation(&err));
    }

    #[test]
    fn is_unique_violation_returns_false_for_non_database_error() {
        let err = anyhow::Error::new(SqlxError::RowNotFound);
        assert!(!is_unique_violation(&err));
    }

    #[test]
    fn unknown_errors_map_to_internal() {
        let err = AppError::from(anyhow::anyhow!("boom"));
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, "internal_error");
        assert_eq!(err.message, "internal server error");
    }

    #[test]
    fn app_error_round_trips_through_anyhow() {
        let mut headers = HeaderMap::new();
        headers.insert("x-rate-limit", "10".parse().expect("header value"));
        let err = AppError::too_many_requests("rate limited").with_headers(headers);
        let mapped = AppError::from(anyhow::Error::new(err));
        assert_eq!(mapped.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(mapped.code, "rate_limited");
        assert_eq!(mapped.message, "rate limited");
        assert_eq!(
            mapped
                .headers
                .as_deref()
                .and_then(|stored| stored.get("x-rate-limit"))
                .and_then(|value| value.to_str().ok()),
            Some("10")
        );
    }

    #[test]
    fn app_error_from_anyhow_without_app_error_is_internal() {
        let err = AppError::from(anyhow::anyhow!("still bad"));
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, "internal_error");
        assert_eq!(err.message, "internal server error");
    }
}
