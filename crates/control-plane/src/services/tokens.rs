use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::app_state::AppState;
use crate::error::{ApiResult, AppError};
use crate::persistence::{nodes, tokens};
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
    if let Some(expires_at) = req.expires_at {
        if expires_at <= Utc::now() {
            return Err(AppError::bad_request("expires_at must be in the future"));
        }
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
