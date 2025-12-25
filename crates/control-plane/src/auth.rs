use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, HeaderName, Request},
    middleware::Next,
};

use crate::{
    app_state::AppState,
    audit::{self, AuditActor, AuditStatus},
    error::{ApiResult, AppError},
    rbac::{default_scopes_for_role, OperatorRole},
    telemetry,
    tokens::legacy_hash,
};
use tracing::{info, warn};
use uuid::Uuid;

pub async fn require_operator_auth(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> ApiResult<axum::response::Response> {
    let request_id = telemetry::request_id_from_request(&req);
    let path = format!("{} {}", req.method(), req.uri().path());
    let token = match extract_bearer_from_header(
        req.headers(),
        &state.operator_auth.header_name,
        "operator authorization header",
    ) {
        Ok(token) => token,
        Err(err) => {
            log_auth_failure(
                state.clone(),
                request_id.clone(),
                path.clone(),
                err.message.clone(),
            )
            .await;
            return Err(err);
        }
    };

    let identity = match (state.operator_token_validator)(&state, &token)
        .await
        .map_err(AppError::from)?
    {
        Some(identity) => identity,
        None => {
            log_auth_failure(
                state.clone(),
                request_id.clone(),
                path,
                "invalid operator token".to_string(),
            )
            .await;
            return Err(AppError::forbidden("invalid operator token"));
        }
    };
    if let OperatorIdentity::EnvToken { .. } = &identity {
        let actor = identity.to_audit_actor();
        let policy = &state.operator_auth.env_policy;
        if policy.should_warn() {
            warn!(
                request_id = request_id.as_deref(),
                path = %path,
                "environment operator token used; intended for bootstrap only"
            );
            telemetry::record_audit_log(
                &state,
                "auth.env_token_used",
                "operator",
                AuditStatus::Success,
                audit::AuditContext {
                    resource_id: None,
                    actor: Some(&actor),
                    request_id: request_id.as_deref(),
                    payload: Some("environment operator token accepted".to_string()),
                },
            )
            .await;
        }
        if policy.disable_after_first_success() && policy.disable() {
            info!(
                request_id = request_id.as_deref(),
                path = %path,
                "environment operator tokens disabled after first successful use"
            );
            telemetry::record_audit_log(
                &state,
                "auth.env_token_disabled",
                "operator",
                AuditStatus::Success,
                audit::AuditContext {
                    resource_id: None,
                    actor: Some(&actor),
                    request_id: request_id.as_deref(),
                    payload: Some("environment operator tokens disabled".to_string()),
                },
            )
            .await;
        }
    }

    if let Some(authorizer) = &state.operator_authorizer {
        if let Err(err) = (authorizer)(&req, &identity) {
            let actor = identity.to_audit_actor();
            log_authz_failure(
                state.clone(),
                request_id.clone(),
                path.clone(),
                actor,
                err.message.clone(),
            )
            .await;
            return Err(err);
        }
    }

    if let Some(limiter) = &state.operator_limiter {
        let mut limiter = limiter.lock().await;
        let decision = limiter.acquire();
        if !decision.allowed {
            return Err(AppError::too_many_requests("operator rate limit exceeded")
                .with_headers(decision.headers()));
        }
    }

    req.extensions_mut().insert(identity);
    Ok(next.run(req).await)
}

pub async fn env_only_operator_token_validator(
    state: &AppState,
    token: &str,
) -> crate::Result<Option<OperatorIdentity>> {
    let token_hash = legacy_hash(token);
    if state.operator_auth.is_env_token(token) {
        let role = OperatorRole::Admin;
        let scopes = default_scopes_for_role(role);
        return Ok(Some(OperatorIdentity::EnvToken {
            token_hash,
            role,
            scopes,
        }));
    }

    Ok(None)
}

pub fn extract_bearer(headers: &HeaderMap) -> ApiResult<String> {
    extract_bearer_from_header(headers, &AUTHORIZATION, "authorization header")
}

pub fn extract_bearer_from_header(
    headers: &HeaderMap,
    header: &HeaderName,
    context: &str,
) -> ApiResult<String> {
    let value = headers
        .get(header)
        .ok_or_else(|| AppError::unauthorized(format!("missing {context}")))?;

    let value = value
        .to_str()
        .map_err(|_| AppError::unauthorized(format!("invalid {context}")))?;

    let prefix = "Bearer ";
    if !value.starts_with(prefix) {
        return Err(AppError::unauthorized(format!("invalid {context} scheme")));
    }

    Ok(value[prefix.len()..].to_string())
}

#[derive(Clone, Debug)]
pub enum OperatorIdentity {
    EnvToken {
        token_hash: String,
        role: OperatorRole,
        scopes: Vec<String>,
    },
    DbToken {
        id: Uuid,
        token_hash: String,
        role: OperatorRole,
        scopes: Vec<String>,
    },
}

impl OperatorIdentity {
    pub fn token_id(&self) -> Option<Uuid> {
        match self {
            OperatorIdentity::EnvToken { .. } => None,
            OperatorIdentity::DbToken { id, .. } => Some(*id),
        }
    }

    pub fn token_hash(&self) -> &str {
        match self {
            OperatorIdentity::EnvToken { token_hash, .. }
            | OperatorIdentity::DbToken { token_hash, .. } => token_hash,
        }
    }

    pub fn role(&self) -> OperatorRole {
        match self {
            OperatorIdentity::EnvToken { role, .. } => *role,
            OperatorIdentity::DbToken { role, .. } => *role,
        }
    }

    pub fn scopes(&self) -> &[String] {
        match self {
            OperatorIdentity::EnvToken { scopes, .. } => scopes,
            OperatorIdentity::DbToken { scopes, .. } => scopes,
        }
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes().iter().any(|candidate| candidate == scope)
    }

    pub fn to_audit_actor(&self) -> AuditActor {
        AuditActor::new(
            self.token_id(),
            Some(self.token_hash().to_string()),
            Some(self.role().as_str().to_string()),
            Some(self.scopes().to_vec()),
        )
    }
}

async fn log_auth_failure(
    state: AppState,
    request_id: Option<String>,
    path: String,
    reason: String,
) {
    let payload = format!("{path}: {reason}");
    telemetry::record_audit_log(
        &state,
        "auth",
        "auth",
        AuditStatus::Failure,
        audit::AuditContext {
            resource_id: None,
            actor: None,
            request_id: request_id.as_deref(),
            payload: Some(payload),
        },
    )
    .await;
}

async fn log_authz_failure(
    state: AppState,
    request_id: Option<String>,
    path: String,
    actor: AuditActor,
    reason: String,
) {
    let payload = format!("{path}: {reason}");
    telemetry::record_audit_log(
        &state,
        "authz",
        "authz",
        AuditStatus::Failure,
        audit::AuditContext {
            resource_id: None,
            actor: Some(&actor),
            request_id: request_id.as_deref(),
            payload: Some(payload),
        },
    )
    .await;
}
