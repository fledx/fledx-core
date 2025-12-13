use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::Db;
use crate::Result;

#[derive(Debug, Clone, FromRow)]
pub struct NodeTokenRecord {
    pub id: Uuid,
    pub node_id: Uuid,
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

pub async fn get_node_token(pool: &Db, id: Uuid) -> Result<Option<NodeTokenRecord>> {
    let record = sqlx::query_as::<_, NodeTokenRecord>(
        r#"
        SELECT
            id,
            node_id,
            token_hash,
            created_at,
            expires_at,
            disabled_at,
            last_used_at
        FROM node_tokens
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

pub async fn create_node_token(
    pool: &Db,
    node_id: Uuid,
    token_hash: String,
    expires_at: Option<DateTime<Utc>>,
) -> Result<NodeTokenRecord> {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO node_tokens (
            id,
            node_id,
            token_hash,
            created_at,
            expires_at
        )
        VALUES (?1, ?2, ?3, datetime('now'), ?4)
        "#,
    )
    .bind(id)
    .bind(node_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(pool)
    .await?;

    get_node_token(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("node token insert did not return row"))
}

pub async fn list_active_node_tokens(pool: &Db, node_id: Uuid) -> Result<Vec<NodeTokenRecord>> {
    let records = sqlx::query_as::<_, NodeTokenRecord>(
        r#"
        SELECT
            id,
            node_id,
            token_hash,
            created_at,
            expires_at,
            disabled_at,
            last_used_at
        FROM node_tokens
        WHERE node_id = ?1
          AND disabled_at IS NULL
          AND (expires_at IS NULL OR expires_at > datetime('now'))
        ORDER BY created_at DESC
        "#,
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn disable_node_token(pool: &Db, token_id: Uuid) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE node_tokens
        SET disabled_at = COALESCE(disabled_at, datetime('now'))
        WHERE id = ?1
          AND disabled_at IS NULL
        "#,
    )
    .bind(token_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn node_tokens_exist(pool: &Db, node_id: Uuid) -> Result<bool> {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(1) as count
        FROM node_tokens
        WHERE node_id = ?1
        "#,
    )
    .bind(node_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0 > 0)
}

pub async fn disable_other_node_tokens(pool: &Db, node_id: Uuid, keep: Uuid) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE node_tokens
        SET disabled_at = datetime('now')
        WHERE node_id = ?1
          AND id != ?2
          AND disabled_at IS NULL
        "#,
    )
    .bind(node_id)
    .bind(keep)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn touch_node_token_last_used(pool: &Db, id: Uuid) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE node_tokens
        SET last_used_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn update_node_token_record_hash(
    pool: &Db,
    token_id: Uuid,
    token_hash: String,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE node_tokens
        SET token_hash = ?2, last_used_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(token_id)
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}
