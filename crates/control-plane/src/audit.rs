use crate::app_state::AppState;
use futures_util::future::BoxFuture;
use serde_json::Value;
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

#[derive(Debug, Clone)]
pub struct AuditRedactor {
    enabled: bool,
    redact_keys: Vec<String>,
    value_markers: Vec<String>,
}

impl AuditRedactor {
    pub fn new(config: &crate::config::AuditRedactionConfig) -> Self {
        let redact_keys = config
            .keys
            .iter()
            .map(|key| key.to_ascii_lowercase())
            .collect();
        let value_markers = config
            .value_markers
            .iter()
            .map(|marker| marker.to_ascii_lowercase())
            .collect();
        Self {
            enabled: config.enabled,
            redact_keys,
            value_markers,
        }
    }

    pub fn redact_payload(&self, payload: &str) -> String {
        if !self.enabled {
            return payload.trim().to_string();
        }

        match serde_json::from_str::<Value>(payload) {
            Ok(value) => {
                let redacted = self.redact_value(value);
                serde_json::to_string(&redacted).unwrap_or_else(|_| self.redact_text(payload))
            }
            Err(_) => self.redact_text(payload),
        }
    }

    fn redact_value(&self, value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut redacted = serde_json::Map::with_capacity(map.len());
                for (key, value) in map {
                    if self.is_sensitive_key(&key) {
                        redacted.insert(key, Value::String("<redacted>".to_string()));
                    } else {
                        redacted.insert(key, self.redact_value(value));
                    }
                }
                Value::Object(redacted)
            }
            Value::Array(items) => {
                Value::Array(items.into_iter().map(|v| self.redact_value(v)).collect())
            }
            Value::String(value) => Value::String(self.redact_text(&value)),
            other => other,
        }
    }

    fn is_sensitive_key(&self, key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        self.redact_keys.iter().any(|needle| lower.contains(needle))
    }

    fn redact_text(&self, input: &str) -> String {
        if self.contains_value_marker(input) {
            return "<redacted>".to_string();
        }

        let mut out = input.trim().to_string();
        out = redact_private_key_blocks(&out);
        out = redact_bearer_tokens(&out);
        out = self.redact_key_value_pairs(&out);
        out
    }

    fn redact_key_value_pairs(&self, input: &str) -> String {
        let mut out = input.to_string();
        for key in &self.redact_keys {
            out = redact_key_value_pair(&out, key);
        }
        out
    }

    fn contains_value_marker(&self, input: &str) -> bool {
        let lower = input.to_ascii_lowercase();
        self.value_markers
            .iter()
            .any(|marker| lower.contains(marker))
    }
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
    let payload = context
        .payload
        .map(|value| truncate_payload(&state.audit_redactor.redact_payload(&value)));

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

fn redact_private_key_blocks(input: &str) -> String {
    const BLOCKS: [&str; 4] = [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ];
    let mut out = input.to_string();
    for block in BLOCKS {
        let begin = format!("-----BEGIN {block}-----");
        let end = format!("-----END {block}-----");
        out = redact_between_markers(&out, &begin, &end);
    }
    out
}

fn redact_between_markers(input: &str, begin: &str, end: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start_idx) = rest.find(begin) {
        let after_begin = &rest[start_idx + begin.len()..];
        if let Some(end_idx) = after_begin.find(end) {
            let end_pos = start_idx + begin.len() + end_idx + end.len();
            out.push_str(&rest[..start_idx]);
            out.push_str("<redacted>");
            rest = &rest[end_pos..];
        } else {
            break;
        }
    }
    out.push_str(rest);
    out
}

fn redact_bearer_tokens(line: &str) -> String {
    fn redact_with_prefix(mut line: &str, prefix: &str) -> String {
        let mut out = String::with_capacity(line.len());
        while let Some(idx) = line.find(prefix) {
            out.push_str(&line[..idx]);
            out.push_str(prefix);
            out.push_str("<redacted>");

            let after = &line[idx + prefix.len()..];
            let token_end = after
                .find(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == ',')
                .unwrap_or(after.len());
            line = &after[token_end..];
        }
        out.push_str(line);
        out
    }

    let line = redact_with_prefix(line, "Bearer ");
    redact_with_prefix(&line, "bearer ")
}

fn redact_key_value_pair(input: &str, key: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(found) = lower[cursor..].find(&key_lower) {
        let start = cursor + found;
        if start > 0 {
            let prev = lower.as_bytes()[start - 1] as char;
            if prev.is_ascii_alphanumeric() || prev == '_' {
                cursor = start + key_lower.len();
                continue;
            }
        }

        let mut pos = start + key_lower.len();
        let bytes = input.as_bytes();
        while pos < input.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= input.len() || (bytes[pos] != b'=' && bytes[pos] != b':') {
            cursor = start + key_lower.len();
            continue;
        }
        pos += 1;
        while pos < input.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= input.len() {
            break;
        }

        let (value_start, value_end) = match bytes[pos] {
            b'"' | b'\'' => {
                let quote = bytes[pos];
                let mut end = pos + 1;
                while end < input.len() {
                    if bytes[end] == quote {
                        end += 1;
                        break;
                    }
                    end += 1;
                }
                (pos, end)
            }
            _ => {
                let mut end = pos;
                while end < input.len() {
                    let ch = bytes[end];
                    if ch.is_ascii_whitespace() || ch == b',' || ch == b';' {
                        break;
                    }
                    end += 1;
                }
                (pos, end)
            }
        };

        out.push_str(&input[cursor..value_start]);
        out.push_str("<redacted>");
        cursor = value_end;
    }

    out.push_str(&input[cursor..]);
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

    fn default_redactor() -> AuditRedactor {
        AuditRedactor::new(&crate::config::AuditRedactionConfig::default())
    }

    #[test]
    fn redacts_sensitive_json_keys() {
        let redactor = default_redactor();
        let payload = r#"{"token":"abc","nested":{"secret":"def","ok":"value"},"list":[{"private_key":"pem"}]}"#;
        let redacted = redactor.redact_payload(payload);
        let value: Value = serde_json::from_str(&redacted).expect("json");
        assert_eq!(value["token"], Value::String("<redacted>".to_string()));
        assert_eq!(
            value["nested"]["secret"],
            Value::String("<redacted>".to_string())
        );
        assert_eq!(value["nested"]["ok"], Value::String("value".to_string()));
        assert_eq!(
            value["list"][0]["private_key"],
            Value::String("<redacted>".to_string())
        );
    }

    #[test]
    fn redacts_bearer_tokens_in_text() {
        let redactor = default_redactor();
        let payload = "Authorization: Bearer abc123";
        let redacted = redactor.redact_payload(payload);
        assert!(redacted.contains("Bearer <redacted>"));
        assert!(!redacted.contains("abc123"));
    }

    #[test]
    fn redacts_private_key_markers() {
        let redactor = default_redactor();
        let payload = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
        let redacted = redactor.redact_payload(payload);
        assert_eq!(redacted, "<redacted>");
    }
}
