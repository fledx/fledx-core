use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::FromRow;
use sqlx::types::Json;
use uuid::Uuid;

use super::{
    Db, HealthStatus, NodeInventoryUpdate, ResourceMetricSample, nodes::NodeStatus, usage,
};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum InstanceState {
    Running,
    Pending,
    Stopped,
    Failed,
    Unknown,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct InstanceStatusRecord {
    pub node_id: Uuid,
    pub deployment_id: Uuid,
    pub replica_number: i64,
    pub generation: i64,
    pub container_id: Option<String>,
    pub state: InstanceState,
    pub message: Option<String>,
    pub restart_count: i64,
    pub last_updated: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[sqlx(rename = "endpoints_json")]
    pub endpoints: Option<Json<Vec<String>>>,
    #[sqlx(rename = "health_json")]
    pub health: Option<Json<HealthStatus>>,
    #[sqlx(rename = "metrics_json")]
    pub metrics: Option<Json<Vec<ResourceMetricSample>>>,
}

#[derive(Debug, Clone)]
pub struct InstanceStatusUpsert {
    pub deployment_id: Uuid,
    pub replica_number: i64,
    pub generation: i64,
    pub container_id: Option<String>,
    pub state: InstanceState,
    pub message: Option<String>,
    pub restart_count: i64,
    pub last_updated: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub endpoints: Vec<String>,
    pub health: Option<HealthStatus>,
    pub metrics: Vec<ResourceMetricSample>,
}

pub struct RecordHeartbeatParams<'a> {
    pub node_id: Uuid,
    pub status: NodeStatus,
    pub last_seen: DateTime<Utc>,
    pub instances: &'a [InstanceStatusUpsert],
    pub retention: Duration,
    pub inventory: Option<NodeInventoryUpdate>,
    pub usage_rollups: &'a [usage::UsageRollup],
}

pub async fn record_heartbeat(pool: &Db, params: RecordHeartbeatParams<'_>) -> Result<()> {
    let RecordHeartbeatParams {
        node_id,
        status,
        last_seen,
        instances,
        retention,
        inventory,
        usage_rollups,
    } = params;
    let mut tx = pool.begin().await?;

    let inv_arch = inventory.as_ref().and_then(|inv| inv.arch.as_ref());
    let inv_os = inventory.as_ref().and_then(|inv| inv.os.as_ref());
    let inv_public_ip = inventory.as_ref().and_then(|inv| inv.public_ip.as_ref());
    let inv_public_host = inventory.as_ref().and_then(|inv| inv.public_host.as_ref());
    let inv_labels = inventory.as_ref().and_then(|inv| inv.labels.as_ref());
    let inv_capacity = inventory.as_ref().and_then(|inv| inv.capacity.as_ref());

    sqlx::query(
        r#"
        UPDATE nodes
        SET status = ?2,
            last_seen = ?3,
            arch = COALESCE(?4, arch),
            os = COALESCE(?5, os),
            public_ip = COALESCE(?6, public_ip),
            public_host = COALESCE(?7, public_host),
            labels_json = COALESCE(?8, labels_json),
            capacity_json = COALESCE(?9, capacity_json),
            updated_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(node_id)
    .bind(status)
    .bind(last_seen)
    .bind(inv_arch)
    .bind(inv_os)
    .bind(inv_public_ip)
    .bind(inv_public_host)
    .bind(inv_labels.map(Json))
    .bind(inv_capacity.map(Json))
    .execute(tx.as_mut())
    .await?;

    for inst in instances {
        sqlx::query(
            r#"
            INSERT INTO instance_statuses (
                node_id,
                deployment_id,
                replica_number,
                generation,
                container_id,
                state,
                message,
                restart_count,
                last_updated,
                last_seen,
                endpoints_json,
                health_json,
                metrics_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ON CONFLICT(node_id, deployment_id, replica_number) DO UPDATE SET
                generation = excluded.generation,
                container_id = excluded.container_id,
                state = excluded.state,
                message = excluded.message,
                restart_count = excluded.restart_count,
                last_updated = excluded.last_updated,
                last_seen = excluded.last_seen,
                endpoints_json = excluded.endpoints_json,
                health_json = excluded.health_json,
                metrics_json = excluded.metrics_json,
                updated_at = datetime('now')
            "#,
        )
        .bind(node_id)
        .bind(inst.deployment_id)
        .bind(inst.replica_number)
        .bind(inst.generation)
        .bind(&inst.container_id)
        .bind(inst.state)
        .bind(&inst.message)
        .bind(inst.restart_count)
        .bind(inst.last_updated)
        .bind(inst.last_seen)
        .bind(Json(inst.endpoints.clone()))
        .bind(inst.health.as_ref().map(Json))
        .bind(Json(inst.metrics.clone()))
        .execute(tx.as_mut())
        .await?;
    }

    sqlx::query(
        r#"
        DELETE FROM instance_statuses
        WHERE node_id = ?1 AND last_seen < ?2
        "#,
    )
    .bind(node_id)
    .bind(last_seen)
    .execute(tx.as_mut())
    .await?;

    let cutoff_delta =
        ChronoDuration::from_std(retention).unwrap_or_else(|_| ChronoDuration::zero());
    let cutoff = last_seen - cutoff_delta;
    sqlx::query(
        r#"
        DELETE FROM instance_statuses
        WHERE last_seen < ?1
        "#,
    )
    .bind(cutoff)
    .execute(tx.as_mut())
    .await?;

    if !usage_rollups.is_empty() {
        usage::upsert_usage_rollups(tx.as_mut(), usage_rollups).await?;
    }

    tx.commit().await?;
    Ok(())
}

pub async fn list_instance_statuses_for_node(
    pool: &Db,
    node_id: Uuid,
) -> Result<Vec<InstanceStatusRecord>> {
    let records = sqlx::query_as::<_, InstanceStatusRecord>(
        r#"
        SELECT
            node_id,
            deployment_id,
            replica_number,
            generation,
            container_id,
            state,
            message,
            restart_count,
            last_updated,
            last_seen,
            created_at,
            updated_at,
            endpoints_json,
            health_json,
            metrics_json
        FROM instance_statuses
        WHERE node_id = ?1
        ORDER BY deployment_id ASC, replica_number ASC
        "#,
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn list_instance_statuses_for_deployment(
    pool: &Db,
    deployment_id: Uuid,
) -> Result<Vec<InstanceStatusRecord>> {
    let records = sqlx::query_as::<_, InstanceStatusRecord>(
        r#"
        SELECT
            node_id,
            deployment_id,
            replica_number,
            generation,
            container_id,
            state,
            message,
            restart_count,
            last_updated,
            last_seen,
            created_at,
            updated_at,
            endpoints_json,
            health_json,
            metrics_json
        FROM instance_statuses
        WHERE deployment_id = ?1
        ORDER BY last_seen DESC
        "#,
    )
    .bind(deployment_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn get_instance_status_for_deployment(
    pool: &Db,
    deployment_id: Uuid,
    node_id: Option<Uuid>,
) -> Result<Option<InstanceStatusRecord>> {
    let Some(node_id) = node_id else {
        return Ok(None);
    };

    let record = sqlx::query_as::<_, InstanceStatusRecord>(
        r#"
        SELECT
            node_id,
            deployment_id,
            replica_number,
            generation,
            container_id,
            state,
            message,
            restart_count,
            last_updated,
            last_seen,
            created_at,
            updated_at,
            endpoints_json,
            health_json,
            metrics_json
        FROM instance_statuses
        WHERE deployment_id = ?1 AND node_id = ?2
        ORDER BY last_seen DESC
        LIMIT 1
        "#,
    )
    .bind(deployment_id)
    .bind(node_id)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}
