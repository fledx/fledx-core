use axum::http::{header::RETRY_AFTER, HeaderMap, HeaderName, HeaderValue};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: usize,
    pub remaining: usize,
    pub reset_after: Duration,
    pub retry_after: Option<Duration>,
}

impl RateLimitDecision {
    pub fn allowed(limit: usize, remaining: usize, reset_after: Duration) -> Self {
        Self {
            allowed: true,
            limit,
            remaining,
            reset_after,
            retry_after: None,
        }
    }

    pub fn limited(limit: usize, reset_after: Duration) -> Self {
        Self {
            allowed: false,
            limit,
            remaining: 0,
            reset_after,
            retry_after: Some(reset_after),
        }
    }

    pub fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if self.limit == 0 {
            return headers;
        }

        headers.insert(
            HeaderName::from_static("x-ratelimit-limit"),
            header_value(self.limit as u64),
        );
        headers.insert(
            HeaderName::from_static("x-ratelimit-remaining"),
            header_value(self.remaining as u64),
        );
        headers.insert(
            HeaderName::from_static("x-ratelimit-reset"),
            header_value(duration_to_seconds(self.reset_after)),
        );
        if let Some(retry_after) = self.retry_after {
            headers.insert(RETRY_AFTER, header_value(duration_to_seconds(retry_after)));
        }

        headers
    }
}

fn header_value(value: u64) -> HeaderValue {
    HeaderValue::from_str(&value.to_string()).expect("valid header value")
}

fn duration_to_seconds(duration: Duration) -> u64 {
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();
    let mut rounded = if nanos == 0 { secs } else { secs + 1 };
    if rounded == 0 {
        rounded = 1;
    }
    rounded
}
