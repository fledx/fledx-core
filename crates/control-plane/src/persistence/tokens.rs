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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{NewNode, NodeStatus, migrations, nodes};
    use chrono::TimeZone;
    use std::collections::HashSet;

    async fn setup_db() -> Db {
        let pool = migrations::init_pool("sqlite::memory:").await.unwrap();
        migrations::run_migrations(&pool).await.unwrap();
        pool
    }

    fn new_node(name: &str) -> NewNode {
        NewNode {
            id: Uuid::new_v4(),
            name: Some(name.into()),
            token_hash: format!("{name}-token"),
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
            last_seen: None,
            status: NodeStatus::Ready,
        }
    }

    #[tokio::test]
    async fn create_node_token_roundtrip() {
        let db = setup_db().await;
        let node = nodes::create_node(&db, new_node("alpha")).await.unwrap();
        let expires_at = Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();

        let record = create_node_token(&db, node.id, "hash-1".to_string(), Some(expires_at))
            .await
            .unwrap();

        assert_eq!(record.node_id, node.id);
        assert_eq!(record.token_hash, "hash-1");
        assert_eq!(record.expires_at, Some(expires_at));
        assert!(record.disabled_at.is_none());
        assert!(record.last_used_at.is_none());

        let fetched = get_node_token(&db, record.id)
            .await
            .unwrap()
            .expect("token");
        assert_eq!(fetched.id, record.id);
    }

    #[tokio::test]
    async fn list_active_node_tokens_filters_expired() {
        let db = setup_db().await;
        let node = nodes::create_node(&db, new_node("beta")).await.unwrap();
        let expired_at = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
        let active_at = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap();

        let expired = create_node_token(&db, node.id, "expired".into(), Some(expired_at))
            .await
            .unwrap();
        let active = create_node_token(&db, node.id, "active".into(), Some(active_at))
            .await
            .unwrap();

        let records = list_active_node_tokens(&db, node.id).await.unwrap();
        let ids: HashSet<Uuid> = records.iter().map(|record| record.id).collect();
        assert!(ids.contains(&active.id));
        assert!(!ids.contains(&expired.id));
    }

    #[tokio::test]
    async fn disable_node_token_is_idempotent() {
        let db = setup_db().await;
        let node = nodes::create_node(&db, new_node("gamma")).await.unwrap();
        let record = create_node_token(&db, node.id, "hash".into(), None)
            .await
            .unwrap();

        let affected = disable_node_token(&db, record.id).await.unwrap();
        assert_eq!(affected, 1);
        let affected_again = disable_node_token(&db, record.id).await.unwrap();
        assert_eq!(affected_again, 0);

        let records = list_active_node_tokens(&db, node.id).await.unwrap();
        assert!(!records.iter().any(|entry| entry.id == record.id));
    }

    #[tokio::test]
    async fn disable_other_node_tokens_keeps_expected_token() {
        let db = setup_db().await;
        let node = nodes::create_node(&db, new_node("delta")).await.unwrap();
        let first = create_node_token(&db, node.id, "hash-1".into(), None)
            .await
            .unwrap();
        let keep = create_node_token(&db, node.id, "hash-2".into(), None)
            .await
            .unwrap();

        let affected = disable_other_node_tokens(&db, node.id, keep.id)
            .await
            .unwrap();
        assert!(affected >= 1);

        let records = list_active_node_tokens(&db, node.id).await.unwrap();
        let ids: Vec<Uuid> = records.iter().map(|record| record.id).collect();
        assert_eq!(ids, vec![keep.id]);
        assert!(!ids.contains(&first.id));
    }

    #[tokio::test]
    async fn touch_node_token_last_used_sets_value() {
        let db = setup_db().await;
        let node = nodes::create_node(&db, new_node("epsilon")).await.unwrap();
        let record = create_node_token(&db, node.id, "hash".into(), None)
            .await
            .unwrap();
        assert!(record.last_used_at.is_none());

        let affected = touch_node_token_last_used(&db, record.id).await.unwrap();
        assert_eq!(affected, 1);
        let updated = get_node_token(&db, record.id)
            .await
            .unwrap()
            .expect("token");
        assert!(updated.last_used_at.is_some());
    }

    #[tokio::test]
    async fn update_node_token_record_hash_updates_and_touches() {
        let db = setup_db().await;
        let node = nodes::create_node(&db, new_node("zeta")).await.unwrap();
        let record = create_node_token(&db, node.id, "old".into(), None)
            .await
            .unwrap();

        let affected = update_node_token_record_hash(&db, record.id, "new-hash".into())
            .await
            .unwrap();
        assert_eq!(affected, 1);

        let updated = get_node_token(&db, record.id)
            .await
            .unwrap()
            .expect("token");
        assert_eq!(updated.token_hash, "new-hash");
        assert!(updated.last_used_at.is_some());
    }

    #[tokio::test]
    async fn node_tokens_exist_reports_presence() {
        let db = setup_db().await;
        let missing_node = Uuid::new_v4();
        let exists = node_tokens_exist(&db, missing_node).await.unwrap();
        assert!(!exists);

        let node = nodes::create_node(&db, new_node("eta")).await.unwrap();
        let exists = node_tokens_exist(&db, node.id).await.unwrap();
        assert!(exists);
    }
}
