use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use sqlx::migrate::{AppliedMigration, Migrate};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use uuid::Uuid;

use super::Db;
use crate::Result;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub const fn core_migrator() -> &'static sqlx::migrate::Migrator {
    &MIGRATOR
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MigrationLabel {
    pub version: i64,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MigrationSnapshot {
    pub latest_applied: Option<i64>,
    pub latest_available: Option<i64>,
    pub applied: Vec<MigrationLabel>,
    pub pending: Vec<MigrationLabel>,
}

#[derive(Debug, Clone)]
pub struct MigrationRunOutcome {
    pub snapshot: MigrationSnapshot,
    pub applied: Vec<MigrationLabel>,
}

fn dedup_sorted(labels: impl IntoIterator<Item = MigrationLabel>) -> Vec<MigrationLabel> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<i64, MigrationLabel> = BTreeMap::new();
    for label in labels {
        map.insert(label.version, label);
    }
    map.into_values().collect()
}

pub fn merge_snapshots(base: &MigrationSnapshot, extra: &MigrationSnapshot) -> MigrationSnapshot {
    let latest_applied = base
        .latest_applied
        .into_iter()
        .chain(extra.latest_applied)
        .max();
    let latest_available = base
        .latest_available
        .into_iter()
        .chain(extra.latest_available)
        .max();

    let applied = dedup_sorted(
        base.applied
            .clone()
            .into_iter()
            .chain(extra.applied.clone()),
    );
    let pending = dedup_sorted(
        base.pending
            .clone()
            .into_iter()
            .chain(extra.pending.clone()),
    );

    MigrationSnapshot {
        latest_applied,
        latest_available,
        applied,
        pending,
    }
}

pub fn merge_run_outcomes(
    base: &MigrationRunOutcome,
    extra: &MigrationRunOutcome,
) -> MigrationRunOutcome {
    let snapshot = merge_snapshots(&base.snapshot, &extra.snapshot);
    let applied = dedup_sorted(
        base.applied
            .clone()
            .into_iter()
            .chain(extra.applied.clone()),
    );
    MigrationRunOutcome { snapshot, applied }
}

pub async fn init_pool(database_url: &str) -> Result<Db> {
    let is_memory_request = database_url.starts_with("sqlite::memory");
    let resolved_url = if is_memory_request {
        let db_path = std::env::temp_dir().join(format!(
            "distributed-edge-hosting-test-{}.sqlite",
            Uuid::new_v4()
        ));
        format!("sqlite://{}", db_path.display())
    } else {
        database_url.to_string()
    };

    ensure_db_dir(&resolved_url)?;

    let mut opts = SqliteConnectOptions::from_str(&resolved_url)?;
    let is_memory = is_memory_request;

    opts = opts.create_if_missing(true);
    if is_memory {
        // With the default settings each connection to an in-memory SQLite URL
        // gets its own private database. Using a pool would then silently point
        // different queries at different databases, producing flaky tests
        // whenever operations hop across connections. A shared cache plus a
        // single connection keeps the in-memory database consistent for tests
        // while still exercising the pool API surface.
        opts = opts.shared_cache(true);
    } else {
        opts = opts.journal_mode(SqliteJournalMode::Wal);
    }

    let pool_opts = if is_memory {
        SqlitePoolOptions::new().max_connections(1)
    } else {
        SqlitePoolOptions::new().max_connections(5)
    };

    let pool = pool_opts
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(opts)
        .await?;

    Ok(pool)
}

fn ensure_db_dir(database_url: &str) -> Result<()> {
    if let Some(path_str) = database_url.strip_prefix("sqlite://")
        && !database_url.starts_with("sqlite::memory")
    {
        let path = Path::new(path_str);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

pub fn latest_migration_version_with(migrator: &'static sqlx::migrate::Migrator) -> Option<i64> {
    migrator.iter().map(|m| m.version).max()
}

pub fn latest_migration_version() -> Option<i64> {
    latest_migration_version_with(core_migrator())
}

pub async fn migration_snapshot_with(
    pool: &Db,
    migrator: &'static sqlx::migrate::Migrator,
) -> Result<MigrationSnapshot> {
    let applied = fetch_applied_migrations(pool).await?;
    let descriptions: HashMap<i64, String> = migrator
        .iter()
        .map(|m| (m.version, m.description.to_string()))
        .collect();
    let applied_labels: Vec<MigrationLabel> = applied
        .iter()
        .map(|m| MigrationLabel {
            version: m.version,
            description: descriptions
                .get(&m.version)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
        })
        .collect();

    let applied_versions: HashSet<i64> = applied.iter().map(|m| m.version).collect();
    let pending: Vec<MigrationLabel> = migrator
        .iter()
        .filter(|m| !applied_versions.contains(&m.version))
        .map(|m| MigrationLabel {
            version: m.version,
            description: m.description.to_string(),
        })
        .collect();

    let latest_applied = applied.iter().map(|m| m.version).max();
    let latest_available = latest_migration_version_with(migrator);

    Ok(MigrationSnapshot {
        latest_applied,
        latest_available,
        applied: applied_labels,
        pending,
    })
}

pub async fn migration_snapshot(pool: &Db) -> Result<MigrationSnapshot> {
    migration_snapshot_with(pool, core_migrator()).await
}

pub async fn validate_migrations_with(
    pool: &Db,
    migrator: &'static sqlx::migrate::Migrator,
) -> Result<()> {
    let applied = fetch_applied_migrations(pool).await?;
    let known: HashMap<i64, &sqlx::migrate::Migration> =
        migrator.iter().map(|m| (m.version, m)).collect();

    for migration in &applied {
        let Some(defined) = known.get(&migration.version) else {
            anyhow::bail!(
                "database has unknown migration version {}",
                migration.version
            );
        };

        if defined.checksum != migration.checksum {
            anyhow::bail!(
                "migration {} checksum mismatch between database and binary",
                migration.version
            );
        }
    }

    Ok(())
}

async fn validate_migrations_with_allow_unknown(
    pool: &Db,
    migrator: &'static sqlx::migrate::Migrator,
) -> Result<()> {
    let applied = fetch_applied_migrations(pool).await?;
    let known: HashMap<i64, &sqlx::migrate::Migration> =
        migrator.iter().map(|m| (m.version, m)).collect();

    for migration in &applied {
        let Some(defined) = known.get(&migration.version) else {
            continue;
        };

        if defined.checksum != migration.checksum {
            anyhow::bail!(
                "migration {} checksum mismatch between database and binary",
                migration.version
            );
        }
    }

    Ok(())
}

pub async fn validate_migrations(pool: &Db) -> Result<()> {
    validate_migrations_with(pool, core_migrator()).await
}

pub async fn dry_run_migrations_with(
    pool: &Db,
    migrator: &'static sqlx::migrate::Migrator,
) -> Result<MigrationSnapshot> {
    let before = migration_snapshot_with(pool, migrator).await?;
    validate_migrations_with(pool, migrator).await?;

    let temp = init_pool("sqlite::memory:").await?;
    migrator
        .run(&temp)
        .await
        .context("dry-run execution of migrations failed")?;

    Ok(before)
}

pub async fn dry_run_migrations(pool: &Db) -> Result<MigrationSnapshot> {
    dry_run_migrations_with(pool, core_migrator()).await
}

pub async fn run_migrations_with(
    pool: &Db,
    migrator: &'static sqlx::migrate::Migrator,
) -> Result<MigrationRunOutcome> {
    let before = migration_snapshot_with(pool, migrator).await?;
    validate_migrations_with(pool, migrator).await?;

    if before.pending.is_empty() {
        return Ok(MigrationRunOutcome {
            snapshot: before.clone(),
            applied: Vec::new(),
        });
    }

    let previously_applied: HashSet<i64> = before.applied.iter().map(|m| m.version).collect();
    migrator
        .run(pool)
        .await
        .context("applying database migrations failed")?;

    let after = migration_snapshot_with(pool, migrator).await?;
    let newly_applied: Vec<MigrationLabel> = after
        .applied
        .iter()
        .filter(|m| !previously_applied.contains(&m.version))
        .cloned()
        .collect();

    Ok(MigrationRunOutcome {
        snapshot: after,
        applied: newly_applied,
    })
}

pub async fn run_migrations_with_allowing_prior_versions(
    pool: &Db,
    migrator: &'static sqlx::migrate::Migrator,
) -> Result<MigrationRunOutcome> {
    let before = migration_snapshot_with(pool, migrator).await?;
    validate_migrations_with_allow_unknown(pool, migrator).await?;

    if before.pending.is_empty() {
        return Ok(MigrationRunOutcome {
            snapshot: before.clone(),
            applied: Vec::new(),
        });
    }

    let previously_applied: HashSet<i64> = before.applied.iter().map(|m| m.version).collect();
    let migrator_owned = sqlx::migrate::Migrator {
        migrations: Cow::Borrowed(migrator.migrations.as_ref()),
        ignore_missing: true,
        locking: migrator.locking,
        no_tx: migrator.no_tx,
    };
    migrator_owned
        .run(pool)
        .await
        .context("applying database migrations failed")?;

    let after = migration_snapshot_with(pool, migrator).await?;
    let newly_applied: Vec<MigrationLabel> = after
        .applied
        .iter()
        .filter(|m| !previously_applied.contains(&m.version))
        .cloned()
        .collect();

    Ok(MigrationRunOutcome {
        snapshot: after,
        applied: newly_applied,
    })
}

pub async fn run_migrations(pool: &Db) -> Result<MigrationRunOutcome> {
    run_migrations_with(pool, core_migrator()).await
}

async fn fetch_applied_migrations(pool: &Db) -> Result<Vec<AppliedMigration>> {
    let mut conn = pool.acquire().await?;
    conn.ensure_migrations_table()
        .await
        .context("ensure migrations table exists")?;

    if let Some(version) = conn.dirty_version().await? {
        anyhow::bail!("database is in a dirty migration state at version {version}");
    }

    let applied = conn
        .list_applied_migrations()
        .await
        .context("list applied migrations")?;

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::migrate::Migrate;

    fn label(version: i64, description: &str) -> MigrationLabel {
        MigrationLabel {
            version,
            description: description.to_string(),
        }
    }

    #[test]
    fn dedup_sorted_orders_and_prefers_last() {
        let labels = vec![label(2, "b"), label(1, "a"), label(2, "c")];
        let deduped = dedup_sorted(labels);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].version, 1);
        assert_eq!(deduped[0].description, "a");
        assert_eq!(deduped[1].version, 2);
        assert_eq!(deduped[1].description, "c");
    }

    #[test]
    fn merge_snapshots_combines_latest_and_dedupes() {
        let base = MigrationSnapshot {
            latest_applied: Some(2),
            latest_available: Some(4),
            applied: vec![label(1, "base-1"), label(2, "base-2")],
            pending: vec![label(4, "base-4")],
        };
        let extra = MigrationSnapshot {
            latest_applied: Some(3),
            latest_available: Some(5),
            applied: vec![label(2, "extra-2"), label(3, "extra-3")],
            pending: vec![label(4, "extra-4"), label(5, "extra-5")],
        };

        let merged = merge_snapshots(&base, &extra);
        assert_eq!(merged.latest_applied, Some(3));
        assert_eq!(merged.latest_available, Some(5));
        assert_eq!(merged.applied.len(), 3);
        assert_eq!(merged.applied[1].description, "extra-2");
        assert_eq!(merged.pending.len(), 2);
        assert_eq!(merged.pending[0].version, 4);
        assert_eq!(merged.pending[0].description, "extra-4");
    }

    #[test]
    fn merge_run_outcomes_combines_applied() {
        let base = MigrationRunOutcome {
            snapshot: MigrationSnapshot {
                latest_applied: Some(1),
                latest_available: Some(1),
                applied: vec![label(1, "base-1")],
                pending: Vec::new(),
            },
            applied: vec![label(1, "base-1")],
        };
        let extra = MigrationRunOutcome {
            snapshot: MigrationSnapshot {
                latest_applied: Some(2),
                latest_available: Some(2),
                applied: vec![label(2, "extra-2")],
                pending: Vec::new(),
            },
            applied: vec![label(2, "extra-2")],
        };

        let merged = merge_run_outcomes(&base, &extra);
        assert_eq!(merged.snapshot.latest_applied, Some(2));
        assert_eq!(merged.applied.len(), 2);
        assert_eq!(merged.applied[0].version, 1);
        assert_eq!(merged.applied[1].version, 2);
    }

    #[test]
    fn ensure_db_dir_creates_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("nested").join("db.sqlite");
        let url = format!("sqlite://{}", db_path.display());
        ensure_db_dir(&url).expect("ensure");
        assert!(db_path.parent().expect("parent").exists());
    }

    #[tokio::test]
    async fn migration_snapshot_reports_pending_for_fresh_db() {
        let pool = init_pool("sqlite::memory:").await.expect("pool");
        let snapshot = migration_snapshot_with(&pool, core_migrator())
            .await
            .expect("snapshot");
        let total = core_migrator().iter().count();
        assert!(snapshot.applied.is_empty());
        assert_eq!(snapshot.pending.len(), total);
        assert_eq!(snapshot.latest_applied, None);
        assert_eq!(
            snapshot.latest_available,
            latest_migration_version_with(core_migrator())
        );
    }

    async fn insert_applied_migration(pool: &Db, version: i64, checksum: Vec<u8>) -> Result<()> {
        let mut conn = pool.acquire().await?;
        conn.ensure_migrations_table().await?;
        sqlx::query(
            "INSERT INTO _sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES (?, ?, CURRENT_TIMESTAMP, 1, ?, 0)",
        )
        .bind(version)
        .bind(format!("test-{version}"))
        .bind(checksum)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn validate_migrations_rejects_unknown_version() {
        let pool = init_pool("sqlite::memory:").await.expect("pool");
        let unknown = latest_migration_version_with(core_migrator()).unwrap_or(0) + 100;
        insert_applied_migration(&pool, unknown, vec![0_u8; 32])
            .await
            .expect("insert");

        let err = validate_migrations_with(&pool, core_migrator())
            .await
            .expect_err("unknown should fail");
        assert!(err.to_string().contains("unknown migration version"));
    }

    #[tokio::test]
    async fn validate_migrations_allows_unknown_when_configured() {
        let pool = init_pool("sqlite::memory:").await.expect("pool");
        let unknown = latest_migration_version_with(core_migrator()).unwrap_or(0) + 100;
        insert_applied_migration(&pool, unknown, vec![1_u8; 32])
            .await
            .expect("insert");

        validate_migrations_with_allow_unknown(&pool, core_migrator())
            .await
            .expect("allow unknown");
    }
}
