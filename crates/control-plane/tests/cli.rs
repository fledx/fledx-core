use assert_cmd::Command;
use control_plane::persistence::migrations;
use sqlx::SqlitePool;
use tempfile::tempdir;

#[tokio::test]
async fn migrations_dry_run_cli_leaves_schema_unmodified() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("dry-run.db");
    let db_url = format!("sqlite://{}", db_path.display());

    let binary = assert_cmd::cargo::cargo_bin!("fledx-cp");
    let mut cmd = Command::new(binary);
    cmd.env("FLEDX_CP_DATABASE_URL", &db_url)
        .arg("--migrations-dry-run");
    cmd.assert().success();

    let pool = SqlitePool::connect(&db_url).await.expect("connect to db");
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap_or(0);
    assert_eq!(
        applied, 0,
        "dry-run should not record migrations as applied"
    );

    let outcome = migrations::run_migrations(&pool)
        .await
        .expect("migrations should still apply");
    assert!(
        !outcome.applied.is_empty(),
        "real migration run should apply at least one migration"
    );
}
