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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_headers_include_limits_and_reset() {
        let decision = RateLimitDecision::allowed(10, 4, Duration::from_secs(30));
        let headers = decision.headers();

        assert_eq!(
            headers.get("x-ratelimit-limit").unwrap(),
            "10",
            "limit header should be set"
        );
        assert_eq!(
            headers.get("x-ratelimit-remaining").unwrap(),
            "4",
            "remaining header should be set"
        );
        assert_eq!(
            headers.get("x-ratelimit-reset").unwrap(),
            "30",
            "reset header should reflect seconds"
        );
        assert!(
            headers.get(RETRY_AFTER).is_none(),
            "retry-after should not be present when allowed"
        );
    }

    #[test]
    fn limited_headers_include_retry_after() {
        let decision = RateLimitDecision::limited(5, Duration::from_millis(1500));
        let headers = decision.headers();

        assert_eq!(headers.get("x-ratelimit-limit").unwrap(), "5");
        assert_eq!(headers.get("x-ratelimit-remaining").unwrap(), "0");
        assert_eq!(headers.get("x-ratelimit-reset").unwrap(), "2");
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "2");
    }

    #[test]
    fn zero_limit_yields_no_headers() {
        let decision = RateLimitDecision::allowed(0, 0, Duration::from_secs(10));
        let headers = decision.headers();

        assert!(headers.is_empty(), "zero limit should omit headers");
    }
}
