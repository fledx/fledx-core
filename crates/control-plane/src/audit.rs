use crate::app_state::AppState;
use futures_util::future::BoxFuture;
use uuid::Uuid;

const MAX_PAYLOAD_LEN: usize = 2048;

#[derive(Debug, Clone)]
pub struct AuditActor {
    pub token_id: Option<Uuid>,
    pub token_hash: Option<String>,
}

impl AuditActor {
    pub fn new(token_id: Option<Uuid>, token_hash: Option<String>) -> Self {
        Self {
            token_id,
            token_hash,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AuditStatus {
    Success,
    Failure,
}

#[derive(Debug, Clone)]
pub struct AuditContext<'a> {
    pub resource_id: Option<Uuid>,
    pub actor: Option<&'a AuditActor>,
    pub request_id: Option<&'a str>,
    pub payload: Option<String>,
}

/// Sink trait for custom audit log implementations.
///
/// Custom implementations can be injected via `BuildHooks::make_audit_sink` to persist
/// audit logs to external systems (databases, SIEM, etc.). The default build uses
/// `NoopAuditSink` which discards all audit events.
pub trait AuditSink: Send + Sync + 'static {
    fn record<'a>(
        &'a self,
        action: &'a str,
        resource_type: &'a str,
        status: AuditStatus,
        context: AuditContext<'a>,
    ) -> BoxFuture<'a, crate::Result<()>>;
}

/// No-op audit sink that discards all events.
///
/// This is the default implementation used when no custom audit sink is configured.
/// To enable audit logging, implement `AuditSink` and inject it via `BuildHooks`.
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record<'a>(
        &'a self,
        _action: &'a str,
        _resource_type: &'a str,
        _status: AuditStatus,
        _context: AuditContext<'a>,
    ) -> BoxFuture<'a, crate::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl AuditStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditStatus::Success => "success",
            AuditStatus::Failure => "failure",
        }
    }
}

pub async fn record(
    state: &AppState,
    action: impl Into<String>,
    resource_type: impl Into<String>,
    status: AuditStatus,
    context: AuditContext<'_>,
) -> crate::Result<()> {
    let payload = context.payload.map(|value| truncate_payload(&value));

    if let Some(sink) = &state.audit_sink {
        sink.record(
            &action.into(),
            &resource_type.into(),
            status,
            AuditContext { payload, ..context },
        )
        .await?;
    }

    Ok(())
}

pub fn truncate_payload(payload: &str) -> String {
    let trimmed = payload.trim();
    let mut out = String::with_capacity(trimmed.len().min(MAX_PAYLOAD_LEN));
    for (idx, ch) in trimmed.chars().enumerate() {
        if idx == MAX_PAYLOAD_LEN {
            out.push_str("...<truncated>");
            return out;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_payload_handles_multibyte_characters() {
        let input = "🔥".repeat(MAX_PAYLOAD_LEN + 10);
        let truncated = truncate_payload(&input);
        assert!(truncated.ends_with("...<truncated>"));
        assert_eq!(truncated.chars().count(), MAX_PAYLOAD_LEN + 14);
        assert!(truncated.starts_with(&"🔥".repeat(MAX_PAYLOAD_LEN)));
    }
}
