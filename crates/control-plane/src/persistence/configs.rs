use chrono::{DateTime, Utc};
use sqlx::{FromRow, Sqlite, Transaction};
use uuid::Uuid;

use super::Db;
use crate::Result;

#[derive(Debug, Clone)]
pub struct ConfigEntry {
    pub key: String,
    pub value: Option<String>,
    pub secret_ref: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConfigFileRef {
    pub path: String,
    pub file_ref: String,
}

#[derive(Debug, Clone)]
pub struct NewConfig {
    pub id: Uuid,
    pub name: String,
    pub version: i64,
    pub entries: Vec<ConfigEntry>,
    pub files: Vec<ConfigFileRef>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ConfigRecord {
    pub id: Uuid,
    pub name: String,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ConfigListRow {
    pub id: Uuid,
    pub name: String,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub entry_count: i64,
    pub file_count: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct ConfigEntryRecord {
    pub config_id: Uuid,
    pub key: String,
    pub value: Option<String>,
    pub secret_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ConfigFileRecord {
    pub config_id: Uuid,
    pub path: String,
    pub file_ref: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_config(pool: &Db, new_config: NewConfig) -> Result<ConfigRecord> {
    let mut tx = pool.begin().await?;
    create_config_tx(&mut tx, &new_config).await?;
    tx.commit().await?;

    get_config(pool, new_config.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("config insert did not return row"))
}

pub async fn list_configs(pool: &Db, limit: u32, offset: u32) -> Result<Vec<ConfigListRow>> {
    let rows = sqlx::query_as::<_, ConfigListRow>(
        r#"
        SELECT
            c.id,
            c.name,
            c.version,
            c.created_at,
            c.updated_at,
            (SELECT COUNT(*) FROM config_entries e WHERE e.config_id = c.id) AS entry_count,
            (SELECT COUNT(*) FROM config_files f WHERE f.config_id = c.id) AS file_count
        FROM configs c
        ORDER BY c.updated_at DESC, c.name ASC
        LIMIT ?1 OFFSET ?2
        "#,
    )
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn get_config_by_name(pool: &Db, name: &str) -> Result<Option<ConfigRecord>> {
    let record = sqlx::query_as::<_, ConfigRecord>(
        r#"
        SELECT id, name, version, created_at, updated_at
        FROM configs
        WHERE name = ?1
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

async fn create_config_tx(tx: &mut Transaction<'_, Sqlite>, new_config: &NewConfig) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO configs (id, name, version)
        VALUES (?1, ?2, ?3)
        "#,
    )
    .bind(new_config.id)
    .bind(&new_config.name)
    .bind(new_config.version)
    .execute(tx.as_mut())
    .await?;

    insert_config_entries_tx(tx, new_config.id, &new_config.entries).await?;
    insert_config_files_tx(tx, new_config.id, &new_config.files).await?;

    Ok(())
}

pub async fn replace_config_data(
    pool: &Db,
    config_id: Uuid,
    name: &str,
    version: i64,
    entries: &[ConfigEntry],
    files: &[ConfigFileRef],
) -> Result<ConfigRecord> {
    let mut tx = pool.begin().await?;
    let updated = sqlx::query(
        r#"
        UPDATE configs
        SET name = ?2,
            version = ?3,
            updated_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(config_id)
    .bind(name)
    .bind(version)
    .execute(tx.as_mut())
    .await?;

    if updated.rows_affected() == 0 {
        anyhow::bail!("config not found for update");
    }

    sqlx::query(
        r#"
        DELETE FROM config_entries WHERE config_id = ?1
        "#,
    )
    .bind(config_id)
    .execute(tx.as_mut())
    .await?;

    sqlx::query(
        r#"
        DELETE FROM config_files WHERE config_id = ?1
        "#,
    )
    .bind(config_id)
    .execute(tx.as_mut())
    .await?;

    insert_config_entries_tx(&mut tx, config_id, entries).await?;
    insert_config_files_tx(&mut tx, config_id, files).await?;

    tx.commit().await?;

    get_config(pool, config_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("config missing after update"))
}

pub async fn get_config(pool: &Db, id: Uuid) -> Result<Option<ConfigRecord>> {
    let record = sqlx::query_as::<_, ConfigRecord>(
        r#"
        SELECT id, name, version, created_at, updated_at
        FROM configs
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

pub async fn delete_config(pool: &Db, id: Uuid) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM configs
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn deployments_for_config(pool: &Db, config_id: Uuid) -> Result<Vec<Uuid>> {
    let rows = sqlx::query_as::<_, (Uuid,)>(
        r#"
        SELECT deployment_id FROM config_deployments WHERE config_id = ?1
        ORDER BY deployment_id
        "#,
    )
    .bind(config_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn nodes_for_config(pool: &Db, config_id: Uuid) -> Result<Vec<Uuid>> {
    let rows = sqlx::query_as::<_, (Uuid,)>(
        r#"
        SELECT node_id FROM config_nodes WHERE config_id = ?1
        ORDER BY node_id
        "#,
    )
    .bind(config_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn config_deployment_attachment(
    pool: &Db,
    config_id: Uuid,
    deployment_id: Uuid,
) -> Result<Option<DateTime<Utc>>> {
    let row = sqlx::query_as::<_, (DateTime<Utc>,)>(
        r#"
        SELECT attached_at FROM config_deployments
        WHERE config_id = ?1 AND deployment_id = ?2
        "#,
    )
    .bind(config_id)
    .bind(deployment_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(ts,)| ts))
}

pub async fn config_node_attachment(
    pool: &Db,
    config_id: Uuid,
    node_id: Uuid,
) -> Result<Option<DateTime<Utc>>> {
    let row = sqlx::query_as::<_, (DateTime<Utc>,)>(
        r#"
        SELECT attached_at FROM config_nodes
        WHERE config_id = ?1 AND node_id = ?2
        "#,
    )
    .bind(config_id)
    .bind(node_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(ts,)| ts))
}

pub async fn list_config_entries(pool: &Db, config_id: Uuid) -> Result<Vec<ConfigEntryRecord>> {
    let rows = sqlx::query_as::<_, ConfigEntryRecord>(
        r#"
        SELECT config_id, key, value, secret_ref, created_at, updated_at
        FROM config_entries
        WHERE config_id = ?1
        ORDER BY key
        "#,
    )
    .bind(config_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn list_config_files(pool: &Db, config_id: Uuid) -> Result<Vec<ConfigFileRecord>> {
    let rows = sqlx::query_as::<_, ConfigFileRecord>(
        r#"
        SELECT config_id, path, file_ref, created_at, updated_at
        FROM config_files
        WHERE config_id = ?1
        ORDER BY path
        "#,
    )
    .bind(config_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn attach_config_to_deployment(
    pool: &Db,
    config_id: Uuid,
    deployment_id: Uuid,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        INSERT OR IGNORE INTO config_deployments (config_id, deployment_id)
        VALUES (?1, ?2)
        "#,
    )
    .bind(config_id)
    .bind(deployment_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn attach_config_to_node(pool: &Db, config_id: Uuid, node_id: Uuid) -> Result<u64> {
    let result = sqlx::query(
        r#"
        INSERT OR IGNORE INTO config_nodes (config_id, node_id)
        VALUES (?1, ?2)
        "#,
    )
    .bind(config_id)
    .bind(node_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn detach_config_from_deployment(
    pool: &Db,
    config_id: Uuid,
    deployment_id: Uuid,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM config_deployments
        WHERE config_id = ?1 AND deployment_id = ?2
        "#,
    )
    .bind(config_id)
    .bind(deployment_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn detach_config_from_node(pool: &Db, config_id: Uuid, node_id: Uuid) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM config_nodes
        WHERE config_id = ?1 AND node_id = ?2
        "#,
    )
    .bind(config_id)
    .bind(node_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn configs_for_deployment(pool: &Db, deployment_id: Uuid) -> Result<Vec<Uuid>> {
    let rows = sqlx::query_as::<_, (Uuid,)>(
        r#"
        SELECT config_id FROM config_deployments WHERE deployment_id = ?1
        ORDER BY config_id
        "#,
    )
    .bind(deployment_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn configs_for_node(pool: &Db, node_id: Uuid) -> Result<Vec<Uuid>> {
    let rows = sqlx::query_as::<_, (Uuid,)>(
        r#"
        SELECT config_id FROM config_nodes WHERE node_id = ?1
        ORDER BY config_id
        "#,
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

async fn insert_config_entries_tx(
    tx: &mut Transaction<'_, Sqlite>,
    config_id: Uuid,
    entries: &[ConfigEntry],
) -> Result<()> {
    for entry in entries {
        sqlx::query(
            r#"
            INSERT INTO config_entries (config_id, key, value, secret_ref)
            VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .bind(config_id)
        .bind(&entry.key)
        .bind(&entry.value)
        .bind(&entry.secret_ref)
        .execute(tx.as_mut())
        .await?;
    }

    Ok(())
}

async fn insert_config_files_tx(
    tx: &mut Transaction<'_, Sqlite>,
    config_id: Uuid,
    files: &[ConfigFileRef],
) -> Result<()> {
    for file in files {
        sqlx::query(
            r#"
            INSERT INTO config_files (config_id, path, file_ref)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(config_id)
        .bind(&file.path)
        .bind(&file.file_ref)
        .execute(tx.as_mut())
        .await?;
    }

    Ok(())
}
