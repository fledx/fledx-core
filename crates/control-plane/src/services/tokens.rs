use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::app_state::AppState;
use crate::error::{ApiResult, AppError};
use crate::persistence::{nodes, tokens};
use crate::rbac::OperatorRole;
use crate::tokens::{generate_token, hash_token};

#[derive(Clone, Debug)]
pub struct RotateNodeTokenRequest {
    pub node_id: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    pub disable_existing: bool,
}

#[derive(Clone, Debug)]
pub struct CreateOperatorTokenRequest {
    pub expires_at: Option<DateTime<Utc>>,
    pub role: OperatorRole,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct TokenWithValue {
    pub token_id: Uuid,
    pub token: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct DisabledToken {
    pub token_id: Uuid,
    pub disabled_at: DateTime<Utc>,
}

pub async fn rotate_node_token(
    state: &AppState,
    req: RotateNodeTokenRequest,
) -> ApiResult<TokenWithValue> {
    if let Some(expires_at) = req.expires_at
        && expires_at <= Utc::now()
    {
        return Err(AppError::bad_request("expires_at must be in the future"));
    }

    let node_exists = nodes::get_node(&state.db, req.node_id).await?;
    if node_exists.is_none() {
        return Err(AppError::not_found("node not found"));
    }

    let token = generate_token();
    let token_hash = hash_token(&token, &state.token_pepper)?;
    let token_record =
        tokens::create_node_token(&state.db, req.node_id, token_hash.clone(), req.expires_at)
            .await?;
    if req.disable_existing {
        tokens::disable_other_node_tokens(&state.db, req.node_id, token_record.id).await?;
    }
    let _ = nodes::update_node_token_hash(&state.db, req.node_id, token_hash).await?;

    Ok(TokenWithValue {
        token_id: token_record.id,
        token,
        expires_at: token_record.expires_at,
    })
}

pub async fn create_operator_token(
    state: &AppState,
    _req: CreateOperatorTokenRequest,
) -> ApiResult<TokenWithValue> {
    let _ = state;
    Err(AppError::not_found(
        "database-backed operator tokens not available in this build",
    ))
}

pub async fn disable_operator_token(state: &AppState, _token_id: Uuid) -> ApiResult<DisabledToken> {
    let _ = state;
    Err(AppError::not_found(
        "database-backed operator tokens not available in this build",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{nodes as node_store, tokens as token_store};
    use crate::services::test_support::setup_state;
    use crate::tokens::{TokenMatch, hash_token, match_token};
    use axum::http::StatusCode;

    fn new_node(id: Uuid, token_hash: String) -> node_store::NewNode {
        node_store::NewNode {
            id,
            name: Some("node".into()),
            token_hash,
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
            last_seen: None,
            status: node_store::NodeStatus::Ready,
        }
    }

    #[tokio::test]
    async fn rotate_node_token_disables_existing_tokens() {
        let state = setup_state().await;
        let node_id = Uuid::new_v4();
        let node = new_node(node_id, "seed".into());
        node_store::create_node(&state.db, node)
            .await
            .expect("node");

        let old_hash = hash_token("old", &state.token_pepper).expect("hash");
        token_store::create_node_token(&state.db, node_id, old_hash, None)
            .await
            .expect("old token");

        let req = RotateNodeTokenRequest {
            node_id,
            expires_at: None,
            disable_existing: true,
        };
        let token = rotate_node_token(&state, req).await.expect("rotate");

        let active = token_store::list_active_node_tokens(&state.db, node_id)
            .await
            .expect("active");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, token.token_id);
        let matched =
            match_token(&token.token, &active[0].token_hash, &state.token_pepper).expect("match");
        assert!(matches!(matched, Some(TokenMatch::Argon2)));
    }

    #[tokio::test]
    async fn rotate_node_token_requires_existing_node() {
        let state = setup_state().await;
        let req = RotateNodeTokenRequest {
            node_id: Uuid::new_v4(),
            expires_at: None,
            disable_existing: false,
        };
        let err = rotate_node_token(&state, req)
            .await
            .expect_err("missing node");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_operator_token_reports_unavailable() {
        let state = setup_state().await;
        let req = CreateOperatorTokenRequest {
            expires_at: None,
            role: OperatorRole::ReadOnly,
            scopes: Vec::new(),
        };
        let err = create_operator_token(&state, req)
            .await
            .expect_err("unavailable");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn disable_operator_token_reports_unavailable() {
        let state = setup_state().await;
        let err = disable_operator_token(&state, Uuid::new_v4())
            .await
            .expect_err("unavailable");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }
}
