use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    auth::OperatorIdentity,
    compat::AgentCompatibility,
    config::{
        AuditExportConfig, LimitsConfig, PortsConfig, ReachabilityConfig, RetentionConfig,
        TunnelConfig, VolumesConfig,
    },
    error::ApiResult,
    metrics::MetricsHistory,
    persistence,
    rate_limit::RateLimitDecision,
    scheduler,
};
use axum::body::Body;
use axum::http::HeaderName;
use axum::http::Request;
use metrics_exporter_prometheus::PrometheusHandle;
use subtle::ConstantTimeEq;

/// Shared application state passed into handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: persistence::Db,
    pub scheduler: scheduler::RoundRobinScheduler,
    pub registration_token: String,
    pub operator_auth: OperatorAuth,
    /// Pluggable validator for operator bearer tokens (env-only by default).
    pub operator_token_validator: OperatorTokenValidator,
    /// Optional authorizer for operator requests (RBAC enforcement).
    pub operator_authorizer: Option<OperatorAuthorizer>,
    pub registration_limiter: Option<RegistrationLimiterRef>,
    pub operator_limiter: Option<RegistrationLimiterRef>,
    /// Optional limiter for authenticated agent endpoints (heartbeats/configs/desired-state).
    pub agent_limiter: Option<RegistrationLimiterRef>,
    pub token_pepper: String,
    pub limits: LimitsConfig,
    pub retention: RetentionConfig,
    pub audit_export: AuditExportConfig,
    pub audit_redactor: Arc<crate::audit::AuditRedactor>,
    pub reachability: ReachabilityConfig,
    pub ports: PortsConfig,
    pub volumes: VolumesConfig,
    pub tunnel: TunnelConfig,
    pub metrics_handle: PrometheusHandle,
    pub metrics_history: MetricsHistory,
    pub tunnel_registry: crate::tunnel::TunnelRegistry,
    pub relay_health: crate::tunnel::RelayHealthState,
    pub agent_compat: AgentCompatibility,
    pub schema: persistence::MigrationSnapshot,
    pub enforce_agent_compatibility: bool,
    pub pem_key: Option<[u8; 32]>,
    pub audit_sink: Option<Arc<dyn crate::audit::AuditSink>>,
}

/// Operator authentication configuration.
#[derive(Clone)]
pub struct OperatorAuth {
    pub tokens: Vec<String>,
    pub header_name: HeaderName,
    pub env_policy: EnvTokenPolicy,
}

impl OperatorAuth {
    pub fn is_env_token(&self, candidate: &str) -> bool {
        if self.env_policy.is_disabled() {
            return false;
        }
        self.tokens.iter().any(|token| {
            if token.len() != candidate.len() {
                return false;
            }
            token.as_bytes().ct_eq(candidate.as_bytes()).into()
        })
    }
}

/// Runtime policy for environment-provided operator tokens.
#[derive(Clone)]
pub struct EnvTokenPolicy {
    warn_on_use: bool,
    disable_after_first_success: bool,
    disabled: Arc<AtomicBool>,
}

impl EnvTokenPolicy {
    pub fn new(warn_on_use: bool, disable_after_first_success: bool) -> Self {
        Self {
            warn_on_use,
            disable_after_first_success,
            disabled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn from_config(cfg: &crate::config::OperatorEnvConfig) -> Self {
        Self::new(cfg.warn_on_use, cfg.disable_after_first_success)
    }

    pub fn should_warn(&self) -> bool {
        self.warn_on_use
    }

    pub fn disable_after_first_success(&self) -> bool {
        self.disable_after_first_success
    }

    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Relaxed)
    }

    /// Returns true when this call disabled env tokens.
    pub fn disable(&self) -> bool {
        self.disabled
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

impl Default for EnvTokenPolicy {
    fn default() -> Self {
        Self::new(true, false)
    }
}

/// Callback used to validate operator bearer tokens.
pub type OperatorTokenValidator = Arc<
    dyn for<'a> Fn(
            &'a AppState,
            &'a str,
        ) -> Pin<
            Box<
                dyn Future<Output = crate::Result<Option<crate::auth::OperatorIdentity>>>
                    + Send
                    + 'a,
            >,
        > + Send
        + Sync,
>;

/// Callback used to authorize operator requests after token validation.
pub type OperatorAuthorizer =
    Arc<dyn for<'a> Fn(&'a Request<Body>, &'a OperatorIdentity) -> ApiResult<()> + Send + Sync>;

/// Interface for registration rate limiting.
///
/// Custom implementations can be injected via `BuildHooks::registration_limiter` to
/// control node registration frequency. The control plane also provides a built-in
/// `SlidingWindowRegistrationLimiter` that can be enabled via configuration.
pub trait RegistrationLimiter: Send + Sync + 'static {
    fn acquire(&mut self) -> RateLimitDecision;
}

/// Convenience alias for sharing the limiter through state.
pub type RegistrationLimiterRef = Arc<tokio::sync::Mutex<dyn RegistrationLimiter>>;

#[allow(dead_code)]
fn _assert_app_state_bounds() {
    fn assert_bounds<T: Clone + Send + Sync + 'static>() {}
    assert_bounds::<AppState>();
}

/// No-op limiter that allows all registration attempts.
///
/// This is used by default when rate limiting is disabled (config: `rate_limit_per_minute = 0`).
/// For production deployments, consider using `SlidingWindowRegistrationLimiter` or a custom
/// implementation to prevent registration abuse.
#[derive(Debug, Default)]
pub struct NoopRegistrationLimiter;

impl RegistrationLimiter for NoopRegistrationLimiter {
    fn acquire(&mut self) -> RateLimitDecision {
        RateLimitDecision::allowed(0, 0, Duration::ZERO)
    }
}

/// Simple sliding-window limiter driven by configuration.
#[derive(Debug)]
pub struct SlidingWindowRegistrationLimiter {
    capacity: usize,
    window: Duration,
    events: VecDeque<Instant>,
}

impl SlidingWindowRegistrationLimiter {
    pub fn per_minute(capacity: u32) -> Self {
        Self {
            capacity: capacity.max(1) as usize,
            window: Duration::from_secs(60),
            events: VecDeque::new(),
        }
    }
}

impl RegistrationLimiter for SlidingWindowRegistrationLimiter {
    fn acquire(&mut self) -> RateLimitDecision {
        let now = Instant::now();
        while let Some(front) = self.events.front() {
            if now.duration_since(*front) > self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }

        if self.events.len() >= self.capacity {
            let reset_after = self
                .events
                .front()
                .map(|front| self.window.saturating_sub(now.duration_since(*front)))
                .unwrap_or(self.window);
            return RateLimitDecision::limited(self.capacity, reset_after);
        }

        self.events.push_back(now);
        let remaining = self.capacity.saturating_sub(self.events.len());
        let reset_after = self
            .events
            .front()
            .map(|front| self.window.saturating_sub(now.duration_since(*front)))
            .unwrap_or(self.window);
        RateLimitDecision::allowed(self.capacity, remaining, reset_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_auth_checks_exact_tokens() {
        let auth = OperatorAuth {
            tokens: vec!["secret-token".to_string()],
            header_name: HeaderName::from_static("authorization"),
            env_policy: EnvTokenPolicy::default(),
        };

        assert!(auth.is_env_token("secret-token"));
        assert!(!auth.is_env_token("secret-token-2"));
        assert!(!auth.is_env_token("SECRET-TOKEN"));
    }

    #[test]
    fn noop_registration_limiter_allows_without_limits() {
        let mut limiter = NoopRegistrationLimiter;
        let decision = limiter.acquire();

        assert!(decision.allowed);
        assert_eq!(decision.limit, 0);
        assert_eq!(decision.remaining, 0);
    }

    #[test]
    fn sliding_window_limiter_enforces_capacity() {
        let mut limiter = SlidingWindowRegistrationLimiter::per_minute(2);

        let first = limiter.acquire();
        assert!(first.allowed);
        assert_eq!(first.limit, 2);
        assert_eq!(first.remaining, 1);

        let second = limiter.acquire();
        assert!(second.allowed);
        assert_eq!(second.remaining, 0);

        let third = limiter.acquire();
        assert!(!third.allowed);
        assert_eq!(third.limit, 2);
        assert_eq!(third.remaining, 0);
        assert!(third.retry_after.is_some());
    }
}
