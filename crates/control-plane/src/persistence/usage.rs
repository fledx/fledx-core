use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::{FromRow, QueryBuilder};
use uuid::Uuid;

use super::Db;
use crate::Result;

#[derive(Debug, Clone)]
pub struct UsageRollup {
    pub deployment_id: Uuid,
    pub node_id: Uuid,
    pub replica_number: i64,
    pub bucket_start: DateTime<Utc>,
    pub samples: i64,
    pub avg_cpu_percent: f64,
    pub avg_memory_bytes: i64,
    pub avg_network_rx_bytes: i64,
    pub avg_network_tx_bytes: i64,
    pub avg_blk_read_bytes: Option<i64>,
    pub avg_blk_write_bytes: Option<i64>,
}

#[derive(Debug, Clone, FromRow)]
pub struct UsageRollupRecord {
    pub deployment_id: Uuid,
    pub node_id: Uuid,
    pub replica_number: i64,
    pub bucket_start: DateTime<Utc>,
    pub samples: i64,
    pub avg_cpu_percent: f64,
    pub avg_memory_bytes: i64,
    pub avg_network_rx_bytes: i64,
    pub avg_network_tx_bytes: i64,
    pub avg_blk_read_bytes: Option<i64>,
    pub avg_blk_write_bytes: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct UsageRollupFilters {
    pub deployment_id: Option<Uuid>,
    pub node_id: Option<Uuid>,
    pub replica_number: Option<i64>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct UsageSummaryFilters {
    pub deployment_id: Option<Uuid>,
    pub node_id: Option<Uuid>,
    pub replica_number: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct UsageSummary {
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub samples: i64,
    pub avg_cpu_percent: f64,
    pub avg_memory_bytes: i64,
    pub avg_network_rx_bytes: i64,
    pub avg_network_tx_bytes: i64,
    pub avg_blk_read_bytes: Option<i64>,
    pub avg_blk_write_bytes: Option<i64>,
}

pub async fn prune_usage_rollups(pool: &Db, cutoff: DateTime<Utc>) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM deployment_usage_rollups
        WHERE bucket_start < ?1
        "#,
    )
    .bind(cutoff)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn list_usage_rollups(
    pool: &Db,
    filters: UsageRollupFilters,
    limit: u32,
    offset: u32,
) -> Result<Vec<UsageRollupRecord>> {
    let mut qb = QueryBuilder::new(
        r#"
        SELECT
            deployment_id,
            node_id,
            replica_number,
            bucket_start,
            samples,
            avg_cpu_percent,
            avg_memory_bytes,
            avg_network_rx_bytes,
            avg_network_tx_bytes,
            avg_blk_read_bytes,
            avg_blk_write_bytes
        FROM deployment_usage_rollups
        "#,
    );

    let mut has_where = false;
    if let Some(deployment_id) = filters.deployment_id {
        qb.push(" WHERE deployment_id = ").push_bind(deployment_id);
        has_where = true;
    }
    if let Some(node_id) = filters.node_id {
        qb.push(if has_where {
            " AND node_id = "
        } else {
            " WHERE node_id = "
        })
        .push_bind(node_id);
        has_where = true;
    }
    if let Some(replica_number) = filters.replica_number {
        qb.push(if has_where {
            " AND replica_number = "
        } else {
            " WHERE replica_number = "
        })
        .push_bind(replica_number);
        has_where = true;
    }
    if let Some(since) = filters.since {
        qb.push(if has_where {
            " AND bucket_start >= "
        } else {
            " WHERE bucket_start >= "
        })
        .push_bind(since);
        has_where = true;
    }
    if let Some(until) = filters.until {
        qb.push(if has_where {
            " AND bucket_start <= "
        } else {
            " WHERE bucket_start <= "
        })
        .push_bind(until);
    }

    qb.push(" ORDER BY bucket_start DESC, deployment_id, node_id, replica_number ");
    qb.push(" LIMIT ").push_bind(limit as i64);
    qb.push(" OFFSET ").push_bind(offset as i64);

    let rows = qb
        .build_query_as::<UsageRollupRecord>()
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub(crate) async fn upsert_usage_rollups(
    conn: &mut sqlx::SqliteConnection,
    rollups: &[UsageRollup],
) -> Result<u64> {
    let mut qb = QueryBuilder::new(
        r#"
        INSERT INTO deployment_usage_rollups (
            deployment_id,
            node_id,
            replica_number,
            bucket_start,
            samples,
            avg_cpu_percent,
            avg_memory_bytes,
            avg_network_rx_bytes,
            avg_network_tx_bytes,
            avg_blk_read_bytes,
            avg_blk_write_bytes
        )
        "#,
    );

    qb.push_values(rollups, |mut b, rollup| {
        b.push_bind(rollup.deployment_id)
            .push_bind(rollup.node_id)
            .push_bind(rollup.replica_number)
            .push_bind(rollup.bucket_start)
            .push_bind(rollup.samples)
            .push_bind(rollup.avg_cpu_percent)
            .push_bind(rollup.avg_memory_bytes)
            .push_bind(rollup.avg_network_rx_bytes)
            .push_bind(rollup.avg_network_tx_bytes)
            .push_bind(rollup.avg_blk_read_bytes)
            .push_bind(rollup.avg_blk_write_bytes);
    });

    qb.push(
        r#"
        ON CONFLICT(deployment_id, node_id, replica_number, bucket_start) DO UPDATE SET
            samples = deployment_usage_rollups.samples + excluded.samples,
            avg_cpu_percent = (
                deployment_usage_rollups.avg_cpu_percent * deployment_usage_rollups.samples +
                excluded.avg_cpu_percent * excluded.samples
            ) / (deployment_usage_rollups.samples + excluded.samples),
            avg_memory_bytes = (
                deployment_usage_rollups.avg_memory_bytes * deployment_usage_rollups.samples +
                excluded.avg_memory_bytes * excluded.samples
            ) / (deployment_usage_rollups.samples + excluded.samples),
            avg_network_rx_bytes = (
                deployment_usage_rollups.avg_network_rx_bytes * deployment_usage_rollups.samples +
                excluded.avg_network_rx_bytes * excluded.samples
            ) / (deployment_usage_rollups.samples + excluded.samples),
            avg_network_tx_bytes = (
                deployment_usage_rollups.avg_network_tx_bytes * deployment_usage_rollups.samples +
                excluded.avg_network_tx_bytes * excluded.samples
            ) / (deployment_usage_rollups.samples + excluded.samples),
            avg_blk_read_bytes = CASE
                WHEN deployment_usage_rollups.avg_blk_read_bytes IS NULL AND excluded.avg_blk_read_bytes IS NULL THEN NULL
                ELSE (
                    COALESCE(deployment_usage_rollups.avg_blk_read_bytes, 0) * deployment_usage_rollups.samples +
                    COALESCE(excluded.avg_blk_read_bytes, 0) * excluded.samples
                ) / (deployment_usage_rollups.samples + excluded.samples)
            END,
            avg_blk_write_bytes = CASE
                WHEN deployment_usage_rollups.avg_blk_write_bytes IS NULL AND excluded.avg_blk_write_bytes IS NULL THEN NULL
                ELSE (
                    COALESCE(deployment_usage_rollups.avg_blk_write_bytes, 0) * deployment_usage_rollups.samples +
                    COALESCE(excluded.avg_blk_write_bytes, 0) * excluded.samples
                ) / (deployment_usage_rollups.samples + excluded.samples)
            END,
            updated_at = datetime('now')
        "#,
    );

    let res = qb.build().execute(conn).await?;
    Ok(res.rows_affected())
}

pub async fn summarize_usage_rollups(
    pool: &Db,
    filters: UsageSummaryFilters,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Result<Option<UsageSummary>> {
    let query_window_end = window_end + ChronoDuration::seconds(60);

    #[derive(FromRow)]
    struct UsageSummaryRow {
        total_samples: Option<i64>,
        sum_cpu: Option<f64>,
        sum_memory: Option<i64>,
        sum_rx: Option<i64>,
        sum_tx: Option<i64>,
        sum_blk_read: Option<i64>,
        blk_read_samples: Option<i64>,
        sum_blk_write: Option<i64>,
        blk_write_samples: Option<i64>,
        min_bucket: Option<DateTime<Utc>>,
        max_bucket: Option<DateTime<Utc>>,
    }

    let mut qb = QueryBuilder::new(
        r#"
        SELECT
            SUM(samples) AS total_samples,
            SUM(avg_cpu_percent * samples) AS sum_cpu,
            SUM(avg_memory_bytes * samples) AS sum_memory,
            SUM(avg_network_rx_bytes * samples) AS sum_rx,
            SUM(avg_network_tx_bytes * samples) AS sum_tx,
            SUM(CASE WHEN avg_blk_read_bytes IS NOT NULL THEN avg_blk_read_bytes * samples END) AS sum_blk_read,
            SUM(CASE WHEN avg_blk_read_bytes IS NOT NULL THEN samples END) AS blk_read_samples,
            SUM(CASE WHEN avg_blk_write_bytes IS NOT NULL THEN avg_blk_write_bytes * samples END) AS sum_blk_write,
            SUM(CASE WHEN avg_blk_write_bytes IS NOT NULL THEN samples END) AS blk_write_samples,
            MIN(bucket_start) AS min_bucket,
            MAX(bucket_start) AS max_bucket
        FROM deployment_usage_rollups
        "#,
    );

    qb.push(" WHERE bucket_start >= ").push_bind(window_start);
    qb.push(" AND bucket_start <= ").push_bind(query_window_end);
    if let Some(deployment_id) = filters.deployment_id {
        qb.push(" AND deployment_id = ").push_bind(deployment_id);
    }
    if let Some(node_id) = filters.node_id {
        qb.push(" AND node_id = ").push_bind(node_id);
    }
    if let Some(replica_number) = filters.replica_number {
        qb.push(" AND replica_number = ").push_bind(replica_number);
    }

    let row = qb
        .build_query_as::<UsageSummaryRow>()
        .fetch_one(pool)
        .await?;

    let samples = row.total_samples.unwrap_or(0);
    if samples == 0 {
        return Ok(None);
    }

    let avg_cpu_percent = row.sum_cpu.unwrap_or(0.0) / samples as f64;
    let avg_memory_bytes = row.sum_memory.unwrap_or(0) / samples;
    let avg_network_rx_bytes = row.sum_rx.unwrap_or(0) / samples;
    let avg_network_tx_bytes = row.sum_tx.unwrap_or(0) / samples;
    let avg_blk_read_bytes = match (row.sum_blk_read, row.blk_read_samples) {
        (Some(sum), Some(count)) if count > 0 => Some(sum / count),
        _ => None,
    };
    let avg_blk_write_bytes = match (row.sum_blk_write, row.blk_write_samples) {
        (Some(sum), Some(count)) if count > 0 => Some(sum / count),
        _ => None,
    };

    Ok(Some(UsageSummary {
        window_start: row.min_bucket.unwrap_or(window_start),
        window_end: row.max_bucket.unwrap_or(window_end),
        samples,
        avg_cpu_percent,
        avg_memory_bytes,
        avg_network_rx_bytes,
        avg_network_tx_bytes,
        avg_blk_read_bytes,
        avg_blk_write_bytes,
    }))
}
