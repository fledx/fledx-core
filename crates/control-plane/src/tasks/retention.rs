use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use tracing::{info, warn};

use crate::config::RetentionConfig;
use crate::persistence::{self as db, usage as usage_store};
use crate::Result;

pub async fn usage_retention_loop(db: db::Db, retention: RetentionConfig) {
    let sweep_interval = retention.usage_cleanup_interval_secs.max(60);
    let mut interval = tokio::time::interval(Duration::from_secs(sweep_interval));

    loop {
        interval.tick().await;

        if retention.usage_window_secs == 0 {
            continue;
        }

        match run_usage_retention_sweep(&db, &retention, Utc::now()).await {
            Ok(0) => {}
            Ok(pruned) => {
                info!(pruned, "usage retention sweep removed samples");
            }
            Err(err) => warn!(?err, "usage retention sweep failed"),
        }
    }
}

pub(crate) async fn run_usage_retention_sweep(
    db: &db::Db,
    retention: &RetentionConfig,
    now: DateTime<Utc>,
) -> Result<u64> {
    if retention.usage_window_secs == 0 {
        return Ok(0);
    }

    let cutoff =
        now - ChronoDuration::seconds(retention.usage_window_secs.min(i64::MAX as u64) as i64);
    usage_store::prune_usage_rollups(db, cutoff).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{deployments, migrations, nodes, usage};
    use uuid::Uuid;

    fn retention_cfg(window_secs: u64) -> RetentionConfig {
        RetentionConfig {
            instance_status_secs: 86_400,
            instance_metrics_secs: 600,
            usage_window_secs: window_secs,
            usage_cleanup_interval_secs: 60,
        }
    }

    fn sample_rollup(
        deployment_id: Uuid,
        node_id: Uuid,
        bucket_start: DateTime<Utc>,
    ) -> usage::UsageRollup {
        usage::UsageRollup {
            deployment_id,
            node_id,
            replica_number: 0,
            bucket_start,
            samples: 1,
            avg_cpu_percent: 0.5,
            avg_memory_bytes: 512,
            avg_network_rx_bytes: 10,
            avg_network_tx_bytes: 20,
            avg_blk_read_bytes: None,
            avg_blk_write_bytes: None,
        }
    }

    async fn seed_deployment(db: &db::Db) -> (Uuid, Uuid) {
        let node_id = Uuid::new_v4();
        nodes::create_node(
            db,
            nodes::NewNode {
                id: node_id,
                name: Some("node".into()),
                token_hash: "hash".into(),
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
                last_seen: Some(Utc::now()),
                status: nodes::NodeStatus::Ready,
            },
        )
        .await
        .expect("node");

        let deployment_id = Uuid::new_v4();
        deployments::create_deployment(
            db,
            deployments::NewDeployment {
                id: deployment_id,
                name: "dep".into(),
                image: "img:1".into(),
                replicas: 1,
                command: None,
                env: None,
                secret_env: None,
                secret_files: None,
                volumes: None,
                ports: None,
                requires_public_ip: false,
                tunnel_only: false,
                constraints: None,
                placement: None,
                health: None,
                desired_state: deployments::DesiredState::Running,
                assigned_node_id: Some(node_id),
                status: deployments::DeploymentStatus::Running,
                generation: 1,
                assignments: vec![deployments::NewDeploymentAssignment {
                    replica_number: 0,
                    node_id,
                    ports: None,
                }],
            },
        )
        .await
        .expect("deployment");

        (deployment_id, node_id)
    }

    #[tokio::test]
    async fn prunes_usage_outside_window() {
        let db = migrations::init_pool("sqlite::memory:")
            .await
            .expect("db init");
        migrations::run_migrations(&db).await.expect("migrations");

        let (deployment_id, node_id) = seed_deployment(&db).await;
        let now = Utc::now();
        let old = sample_rollup(deployment_id, node_id, now - ChronoDuration::seconds(120));
        let recent = sample_rollup(deployment_id, node_id, now - ChronoDuration::seconds(30));

        let mut tx = db.begin().await.expect("begin tx");
        usage::upsert_usage_rollups(&mut tx, &[old.clone(), recent.clone()])
            .await
            .expect("seed rollups");
        tx.commit().await.expect("commit seed");

        let pruned = run_usage_retention_sweep(&db, &retention_cfg(90), now)
            .await
            .expect("sweep");
        assert_eq!(pruned, 1);

        let remaining = usage::list_usage_rollups(&db, usage::UsageRollupFilters::default(), 10, 0)
            .await
            .expect("list rollups");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].bucket_start, recent.bucket_start);
    }

    #[tokio::test]
    async fn skips_when_window_disabled() {
        let db = migrations::init_pool("sqlite::memory:")
            .await
            .expect("db init");
        migrations::run_migrations(&db).await.expect("migrations");

        let (deployment_id, node_id) = seed_deployment(&db).await;
        let now = Utc::now();
        let rollup = sample_rollup(deployment_id, node_id, now - ChronoDuration::seconds(5));
        let mut tx = db.begin().await.expect("begin tx");
        usage::upsert_usage_rollups(&mut tx, std::slice::from_ref(&rollup))
            .await
            .expect("seed rollups");
        tx.commit().await.expect("commit seed");

        let pruned = run_usage_retention_sweep(&db, &retention_cfg(0), now)
            .await
            .expect("sweep");
        assert_eq!(pruned, 0);

        let remaining = usage::list_usage_rollups(&db, usage::UsageRollupFilters::default(), 10, 0)
            .await
            .expect("list rollups");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].bucket_start, rollup.bucket_start);
    }
}
