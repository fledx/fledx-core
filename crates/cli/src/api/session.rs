use crate::api::{CLIENT_FINGERPRINT_HEADER, render_control_plane_error};
use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderName, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type ExchangeFn =
    Arc<dyn Fn() -> BoxFuture<Result<SessionToken, SessionExchangeError>> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct SessionTokenConfig {
    pub refresh_before: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
}

impl Default for SessionTokenConfig {
    fn default() -> Self {
        Self {
            refresh_before: Duration::from_secs(5 * 60),
            backoff_base: Duration::from_secs(5),
            backoff_max: Duration::from_secs(60),
        }
    }
}

#[derive(Clone)]
pub struct SessionTokenCache {
    exchange: ExchangeFn,
    client_fingerprint: String,
    config: SessionTokenConfig,
    state: Arc<Mutex<SessionState>>,
    notify: Arc<Notify>,
}

impl SessionTokenCache {
    pub fn new(
        client: Client,
        base: impl Into<String>,
        operator_header: impl Into<String>,
        operator_token: impl Into<String>,
        client_fingerprint: impl Into<String>,
        config: SessionTokenConfig,
    ) -> anyhow::Result<Self> {
        let base = base.into();
        let operator_header = operator_header.into();
        let operator_token = operator_token.into();
        let client_fingerprint = client_fingerprint.into();
        if client_fingerprint.trim().is_empty() {
            anyhow::bail!("client fingerprint is required for operator sessions");
        }

        let header = HeaderName::from_bytes(operator_header.as_bytes()).map_err(|err| {
            anyhow::anyhow!(
                "invalid operator header name '{}': {}",
                operator_header,
                err
            )
        })?;

        let exchange_fingerprint = client_fingerprint.clone();
        let exchange: ExchangeFn = Arc::new(move || {
            let client = client.clone();
            let base = base.clone();
            let header = header.clone();
            let operator_token = operator_token.clone();
            let client_fingerprint = exchange_fingerprint.clone();
            Box::pin(async move {
                exchange_session_token(&client, &base, header, &operator_token, &client_fingerprint)
                    .await
            })
        });

        Ok(Self::new_with_exchange(
            exchange,
            client_fingerprint,
            config,
        ))
    }

    pub(crate) fn new_with_exchange(
        exchange: ExchangeFn,
        client_fingerprint: String,
        config: SessionTokenConfig,
    ) -> Self {
        Self {
            exchange,
            client_fingerprint,
            config,
            state: Arc::new(Mutex::new(SessionState::default())),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn client_fingerprint(&self) -> &str {
        &self.client_fingerprint
    }

    pub async fn token(&self) -> Result<String> {
        loop {
            let fallback = {
                let mut state = self.state.lock().await;
                if let Some(token) = &state.token {
                    if !token_needs_refresh(token, &self.config) {
                        return Ok(token.value.clone());
                    }
                    if let Some(until) = state.backoff_until
                        && Instant::now() < until
                        && !token_expired(token)
                    {
                        return Ok(token.value.clone());
                    }
                }

                if state.refreshing {
                    let notified = self.notify.notified();
                    drop(state);
                    notified.await;
                    continue;
                }

                if let Some(until) = state.backoff_until
                    && Instant::now() < until
                {
                    let message = state
                        .last_error
                        .clone()
                        .unwrap_or_else(|| "session exchange backoff active".to_string());
                    return Err(anyhow::anyhow!(message));
                }

                let fallback = state.token.clone().filter(|token| !token_expired(token));
                state.refreshing = true;
                fallback
            };

            let outcome = (self.exchange)().await;
            let mut state = self.state.lock().await;
            state.refreshing = false;

            match outcome {
                Ok(token) => {
                    state.token = Some(token.clone());
                    state.backoff_until = None;
                    state.backoff_delay = None;
                    state.last_error = None;
                    self.notify.notify_waiters();
                    return Ok(token.value);
                }
                Err(err) => {
                    let message = err.message();
                    let delay = next_backoff_delay(&state, &self.config, err.retry_after());
                    state.backoff_delay = Some(delay);
                    state.backoff_until = Some(Instant::now() + delay);
                    state.last_error = Some(message.clone());
                    self.notify.notify_waiters();
                    if let Some(token) = fallback {
                        return Ok(token.value);
                    }
                    return Err(anyhow::anyhow!(message));
                }
            }
        }
    }

    pub async fn invalidate(&self) {
        let mut state = self.state.lock().await;
        state.token = None;
        state.backoff_until = None;
        state.backoff_delay = None;
        state.last_error = None;
        self.notify.notify_waiters();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SessionToken {
    value: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct SessionState {
    token: Option<SessionToken>,
    refreshing: bool,
    backoff_until: Option<Instant>,
    backoff_delay: Option<Duration>,
    last_error: Option<String>,
}

#[derive(Debug)]
pub(crate) enum SessionExchangeError {
    RateLimited {
        retry_after: Duration,
        message: String,
    },
    Failed(anyhow::Error),
}

impl SessionExchangeError {
    fn retry_after(&self) -> Option<Duration> {
        match self {
            SessionExchangeError::RateLimited { retry_after, .. } => Some(*retry_after),
            SessionExchangeError::Failed(_) => None,
        }
    }

    fn message(&self) -> String {
        match self {
            SessionExchangeError::RateLimited { message, .. } => message.clone(),
            SessionExchangeError::Failed(err) => err.to_string(),
        }
    }
}

async fn exchange_session_token(
    client: &Client,
    base: &str,
    operator_header: HeaderName,
    operator_token: &str,
    client_fingerprint: &str,
) -> Result<SessionToken, SessionExchangeError> {
    let url = format!("{}/api/v1/operator/sessions", base.trim_end_matches('/'));
    let req = client
        .post(url)
        .header(operator_header, format!("Bearer {}", operator_token))
        .header(CLIENT_FINGERPRINT_HEADER, client_fingerprint);
    let res = req
        .send()
        .await
        .map_err(|err| SessionExchangeError::Failed(err.into()))?;
    let status = res.status();

    if status.is_success() {
        let body = res
            .json::<common::api::TokenResponse>()
            .await
            .map_err(|err| SessionExchangeError::Failed(err.into()))?;
        let expires_at = body.expires_at.ok_or_else(|| {
            SessionExchangeError::Failed(anyhow::anyhow!(
                "operator session response missing expires_at"
            ))
        })?;
        return Ok(SessionToken {
            value: body.token,
            expires_at,
        });
    }

    let retry_after = retry_after_from_headers(res.headers());
    let body = res.text().await.unwrap_or_default();
    let message = render_control_plane_error(status, &body);
    if status == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = retry_after.unwrap_or_else(|| Duration::from_secs(30));
        return Err(SessionExchangeError::RateLimited {
            retry_after,
            message,
        });
    }

    Err(SessionExchangeError::Failed(anyhow::anyhow!(message)))
}

fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    if let Some(value) = headers.get(RETRY_AFTER)
        && let Ok(raw) = value.to_str()
        && let Ok(seconds) = raw.parse::<u64>()
    {
        return Some(Duration::from_secs(seconds.max(1)));
    }
    if let Some(value) = headers.get("x-ratelimit-reset")
        && let Ok(raw) = value.to_str()
        && let Ok(seconds) = raw.parse::<u64>()
    {
        return Some(Duration::from_secs(seconds.max(1)));
    }
    None
}

fn token_needs_refresh(token: &SessionToken, config: &SessionTokenConfig) -> bool {
    if token_expired(token) {
        return true;
    }
    if config.refresh_before.is_zero() {
        return false;
    }
    let Ok(refresh_before) = chrono::Duration::from_std(config.refresh_before) else {
        return false;
    };
    let remaining = token.expires_at - Utc::now();
    remaining <= refresh_before
}

fn token_expired(token: &SessionToken) -> bool {
    token.expires_at <= Utc::now()
}

fn next_backoff_delay(
    state: &SessionState,
    config: &SessionTokenConfig,
    retry_after: Option<Duration>,
) -> Duration {
    if let Some(delay) = retry_after {
        return delay.max(Duration::from_secs(1));
    }
    let base = config.backoff_base.max(Duration::from_secs(1));
    let delay = match state.backoff_delay {
        None => base,
        Some(prev) => prev.saturating_mul(2),
    };
    delay.min(config.backoff_max.max(base))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn session_cache_reuses_token_when_valid() {
        let calls = Arc::new(AtomicUsize::new(0));
        let exchange_calls = calls.clone();
        let exchange: ExchangeFn = Arc::new(move || {
            let exchange_calls = exchange_calls.clone();
            Box::pin(async move {
                exchange_calls.fetch_add(1, Ordering::SeqCst);
                Ok(SessionToken {
                    value: "session-1".to_string(),
                    expires_at: Utc::now() + chrono::Duration::minutes(10),
                })
            })
        });

        let cache = SessionTokenCache::new_with_exchange(
            exchange,
            "host=test;user=test".to_string(),
            SessionTokenConfig::default(),
        );
        let first = cache.token().await.expect("token");
        let second = cache.token().await.expect("token");
        assert_eq!(first, "session-1");
        assert_eq!(second, "session-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn session_cache_backoff_on_rate_limit() {
        let calls = Arc::new(AtomicUsize::new(0));
        let exchange_calls = calls.clone();
        let exchange: ExchangeFn = Arc::new(move || {
            let exchange_calls = exchange_calls.clone();
            Box::pin(async move {
                exchange_calls.fetch_add(1, Ordering::SeqCst);
                Err(SessionExchangeError::RateLimited {
                    retry_after: Duration::from_secs(30),
                    message: "rate limited".to_string(),
                })
            })
        });

        let cache = SessionTokenCache::new_with_exchange(
            exchange,
            "host=test;user=test".to_string(),
            SessionTokenConfig::default(),
        );
        let err = cache.token().await.unwrap_err();
        assert!(err.to_string().contains("rate limited"));
        let err = cache.token().await.unwrap_err();
        assert!(err.to_string().contains("rate limited"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn session_cache_falls_back_when_refresh_fails() {
        let calls = Arc::new(AtomicUsize::new(0));
        let exchange_calls = calls.clone();
        let exchange: ExchangeFn = Arc::new(move || {
            let exchange_calls = exchange_calls.clone();
            Box::pin(async move {
                let call = exchange_calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    Ok(SessionToken {
                        value: "session-1".to_string(),
                        expires_at: Utc::now() + chrono::Duration::minutes(1),
                    })
                } else {
                    Err(SessionExchangeError::Failed(anyhow::anyhow!("boom")))
                }
            })
        });

        let cache = SessionTokenCache::new_with_exchange(
            exchange,
            "host=test;user=test".to_string(),
            SessionTokenConfig::default(),
        );
        let first = cache.token().await.expect("token");
        let second = cache.token().await.expect("fallback");
        let third = cache.token().await.expect("backoff fallback");
        assert_eq!(first, "session-1");
        assert_eq!(second, "session-1");
        assert_eq!(third, "session-1");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retry_after_from_headers_prefers_retry_after_and_clamps() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("0"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("45"));
        let delay = retry_after_from_headers(&headers).expect("delay");
        assert_eq!(delay, Duration::from_secs(1));
    }

    #[test]
    fn retry_after_from_headers_uses_x_ratelimit_reset_when_retry_after_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("nope"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("12"));
        let delay = retry_after_from_headers(&headers).expect("delay");
        assert_eq!(delay, Duration::from_secs(12));
    }

    #[test]
    fn retry_after_from_headers_returns_none_when_unparseable() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("nope"));
        let delay = retry_after_from_headers(&headers);
        assert!(delay.is_none());
    }

    #[test]
    fn token_needs_refresh_handles_expired_and_refresh_window() {
        let config = SessionTokenConfig::default();
        let expired = SessionToken {
            value: "expired".to_string(),
            expires_at: Utc::now() - chrono::Duration::minutes(1),
        };
        assert!(token_needs_refresh(&expired, &config));

        let near_expiry = SessionToken {
            value: "near".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
        };
        assert!(token_needs_refresh(&near_expiry, &config));

        let far_expiry = SessionToken {
            value: "far".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(30),
        };
        assert!(!token_needs_refresh(&far_expiry, &config));
    }

    #[test]
    fn token_needs_refresh_respects_zero_refresh_before() {
        let config = SessionTokenConfig {
            refresh_before: Duration::ZERO,
            ..SessionTokenConfig::default()
        };
        let token = SessionToken {
            value: "valid".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        };
        assert!(!token_needs_refresh(&token, &config));
    }

    #[test]
    fn next_backoff_delay_uses_retry_after_minimum() {
        let state = SessionState::default();
        let config = SessionTokenConfig::default();
        let delay = next_backoff_delay(&state, &config, Some(Duration::ZERO));
        assert_eq!(delay, Duration::from_secs(1));
    }

    #[test]
    fn next_backoff_delay_doubles_and_caps() {
        let state = SessionState {
            backoff_delay: Some(Duration::from_secs(4)),
            ..SessionState::default()
        };
        let config = SessionTokenConfig {
            backoff_base: Duration::from_secs(2),
            backoff_max: Duration::from_secs(5),
            refresh_before: Duration::from_secs(0),
        };
        let delay = next_backoff_delay(&state, &config, None);
        assert_eq!(delay, Duration::from_secs(5));
    }
}
