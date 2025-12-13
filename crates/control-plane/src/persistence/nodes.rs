use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{FromRow, QueryBuilder};
use uuid::Uuid;

use super::{CapacityHints, Db};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum NodeStatus {
    Ready,
    Unreachable,
    Error,
    Registering,
}

#[derive(Debug, Clone, FromRow)]
pub struct NodeRecord {
    pub id: Uuid,
    pub name: Option<String>,
    pub token_hash: String,
    pub arch: Option<String>,
    pub os: Option<String>,
    pub public_ip: Option<String>,
    pub public_host: Option<String>,
    #[sqlx(rename = "labels_json")]
    pub labels: Option<Json<HashMap<String, String>>>,
    #[sqlx(rename = "capacity_json")]
    pub capacity: Option<Json<CapacityHints>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub status: NodeStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct NodeInventoryUpdate {
    pub arch: Option<String>,
    pub os: Option<String>,
    pub labels: Option<HashMap<String, String>>,
    pub capacity: Option<CapacityHints>,
    pub public_ip: Option<String>,
    pub public_host: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewNode {
    pub id: Uuid,
    pub name: Option<String>,
    pub token_hash: String,
    pub arch: Option<String>,
    pub os: Option<String>,
    pub public_ip: Option<String>,
    pub public_host: Option<String>,
    pub labels: Option<HashMap<String, String>>,
    pub capacity: Option<CapacityHints>,
    pub last_seen: Option<DateTime<Utc>>,
    pub status: NodeStatus,
}

impl NewNode {
    #[allow(dead_code)]
    pub fn new(token_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: None,
            token_hash,
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
            last_seen: None,
            status: NodeStatus::Registering,
        }
    }
}

pub async fn create_node(pool: &Db, new_node: NewNode) -> Result<NodeRecord> {
    let id = new_node.id;
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        INSERT INTO nodes (
            id,
            name,
            token_hash,
            arch,
            os,
            public_ip,
            public_host,
            labels_json,
            capacity_json,
            last_seen,
            status
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(id)
    .bind(&new_node.name)
    .bind(&new_node.token_hash)
    .bind(&new_node.arch)
    .bind(&new_node.os)
    .bind(&new_node.public_ip)
    .bind(&new_node.public_host)
    .bind(new_node.labels.map(Json))
    .bind(new_node.capacity.map(Json))
    .bind(new_node.last_seen)
    .bind(new_node.status)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO node_tokens (
            id,
            node_id,
            token_hash,
            created_at
        )
        VALUES (?1, ?2, ?3, datetime('now'))
        "#,
    )
    .bind(id)
    .bind(id)
    .bind(&new_node.token_hash)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    get_node(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("node insert did not return row"))
}

pub async fn get_node(pool: &Db, id: Uuid) -> Result<Option<NodeRecord>> {
    let record = sqlx::query_as::<_, NodeRecord>(
        r#"
        SELECT
            id,
            name,
            token_hash,
            arch,
            os,
            public_ip,
            public_host,
            labels_json,
            capacity_json,
            last_seen,
            status,
            created_at,
            updated_at
        FROM nodes
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

pub async fn update_node_token_hash(pool: &Db, id: Uuid, token_hash: String) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE nodes
        SET token_hash = ?2, updated_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

#[allow(dead_code)]
pub async fn update_node_status(
    pool: &Db,
    id: Uuid,
    status: NodeStatus,
    last_seen: Option<DateTime<Utc>>,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE nodes
        SET status = ?2, last_seen = ?3, updated_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(last_seen)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn mark_node_unreachable_if_stale(
    pool: &Db,
    id: Uuid,
    stale_before: DateTime<Utc>,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE nodes
        SET status = ?3, updated_at = datetime('now')
        WHERE id = ?1
          AND status = ?2
          AND last_seen IS NOT NULL
          AND last_seen < ?4
        "#,
    )
    .bind(id)
    .bind(NodeStatus::Ready)
    .bind(NodeStatus::Unreachable)
    .bind(stale_before)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn find_stale_ready_nodes(
    pool: &Db,
    stale_before: DateTime<Utc>,
) -> Result<Vec<NodeRecord>> {
    let records = sqlx::query_as::<_, NodeRecord>(
        r#"
        SELECT
            id,
            name,
            token_hash,
            arch,
            os,
            public_ip,
            public_host,
            labels_json,
            capacity_json,
            last_seen,
            status,
            created_at,
            updated_at
        FROM nodes
        WHERE status = ?1 AND last_seen IS NOT NULL AND last_seen < ?2
        ORDER BY last_seen ASC
        "#,
    )
    .bind(NodeStatus::Ready)
    .bind(stale_before)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn list_nodes(pool: &Db) -> Result<Vec<NodeRecord>> {
    let records = sqlx::query_as::<_, NodeRecord>(
        r#"
        SELECT
            id,
            name,
            token_hash,
            arch,
            os,
            public_ip,
            public_host,
            labels_json,
            capacity_json,
            last_seen,
            status,
            created_at,
            updated_at
        FROM nodes
        ORDER BY created_at ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn count_nodes(pool: &Db) -> Result<usize> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM nodes
        "#,
    )
    .fetch_one(pool)
    .await?;

    Ok(count.max(0) as usize)
}

pub async fn list_nodes_paged(
    pool: &Db,
    status: Option<NodeStatus>,
    limit: u32,
    offset: u32,
) -> Result<Vec<NodeRecord>> {
    let mut qb = QueryBuilder::<sqlx::Sqlite>::new(
        r#"
        SELECT
            id,
            name,
            token_hash,
            arch,
            os,
            public_ip,
            public_host,
            labels_json,
            capacity_json,
            last_seen,
            status,
            created_at,
            updated_at
        FROM nodes
        "#,
    );

    if status.is_some() {
        qb.push(" WHERE status = ");
        qb.push_bind(status);
    }

    qb.push(" ORDER BY created_at ASC LIMIT ");
    qb.push_bind(limit as i64);
    qb.push(" OFFSET ");
    qb.push_bind(offset as i64);

    let query = qb.build_query_as::<NodeRecord>();
    let records = query.fetch_all(pool).await?;
    Ok(records)
}
