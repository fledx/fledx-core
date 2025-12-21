use ::common::api::AuditLogEntry;

use super::{
    format::{format_redacted, format_timestamp, format_uuid},
    table::render_table,
};

pub fn render_audit_logs_table(logs: &[AuditLogEntry]) -> String {
    let headers = vec![
        "TIME",
        "ACTION",
        "RESOURCE",
        "STATUS",
        "REQUEST_ID",
        "ACTOR",
        "DETAIL",
    ];
    let mut rows = Vec::with_capacity(logs.len());
    for entry in logs {
        let resource = log_entry_resource(entry);
        let actor = match (
            entry.operator_token_id,
            entry.operator_token_hash.as_deref(),
        ) {
            (Some(id), _) => format_uuid(id, true),
            (_, Some(hash)) => hash.to_string(),
            _ => "-".to_string(),
        };
        let detail = log_entry_detail(entry);
        rows.push(vec![
            format_timestamp(Some(entry.created_at)),
            entry.action.clone(),
            resource,
            entry.status.clone(),
            entry.request_id.clone().unwrap_or_else(|| "-".to_string()),
            actor,
            detail,
        ]);
    }

    render_table(&headers, &rows)
}

pub fn truncate_detail(detail: &str) -> String {
    let cleaned = detail.replace('\n', " ");
    const MAX_LEN: usize = 80;
    let mut out = String::with_capacity(cleaned.len().min(MAX_LEN));
    for (idx, ch) in cleaned.chars().enumerate() {
        if idx == MAX_LEN {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

pub fn format_log_entry_line(entry: &AuditLogEntry) -> String {
    let resource = log_entry_resource(entry);
    let detail = log_entry_detail(entry);
    let request_id = entry.request_id.as_deref().unwrap_or("-");
    format!(
        "{} {} {} {} request_id={} detail={}",
        format_timestamp(Some(entry.created_at)),
        entry.status,
        entry.action,
        resource,
        request_id,
        detail
    )
}

fn log_entry_resource(entry: &AuditLogEntry) -> String {
    match entry.resource_id {
        Some(_) => format!("{} {}", entry.resource_type, format_redacted()),
        None => entry.resource_type.clone(),
    }
}

fn log_entry_detail(entry: &AuditLogEntry) -> String {
    entry
        .payload
        .as_deref()
        .map(truncate_detail)
        .unwrap_or_else(|| "-".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn truncate_detail_handles_multibyte_characters() {
        let input = "🔥".repeat(90);
        let truncated = truncate_detail(&input);
        assert!(truncated.ends_with("..."));
        assert_eq!(truncated.chars().count(), 83);
        assert!(truncated.starts_with(&"🔥".repeat(80)));
    }

    #[test]
    fn format_log_entry_line_includes_request_id() {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            action: "deployment.update".into(),
            resource_type: "deployment".into(),
            resource_id: Some(Uuid::new_v4()),
            operator_token_id: None,
            operator_token_hash: None,
            operator_role: None,
            operator_scopes: None,
            request_id: Some("req-123".into()),
            status: "success".into(),
            payload: Some("payload detail".into()),
            created_at: Utc::now(),
        };

        let line = format_log_entry_line(&entry);
        assert!(line.contains("req-123"));
        assert!(line.contains("deployment"));
        assert!(line.contains("success"));
    }
}
