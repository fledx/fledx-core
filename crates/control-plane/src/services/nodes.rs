use std::collections::{HashMap, HashSet};
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use uuid::Uuid;

use crate::app_state::AppState;
use crate::error::{ApiResult, AppError};
use crate::persistence::{self as db, deployments, logs, nodes, tokens};
use crate::tokens::{generate_token, hash_token, match_token, TokenMatch};
use crate::validation;
use common::api::{InstanceStatus, NodeStatus, TunnelEndpoint, UsageSummary};

/// Domain-level node registration request (HTTP wrappers convert into this).
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct RegistrationRequest {
    pub name: Option<String>,
    pub arch: Option<String>,
    pub os: Option<String>,
    #[serde(default)]
    pub labels: Option<HashMap<String, String>>,
    #[serde(default)]
    pub capacity: Option<db::CapacityHints>,
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default)]
    pub public_host: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RegistrationResponse {
    pub node_id: Uuid,
    pub node_token: String,
    pub tunnel: TunnelEndpoint,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct NodeInventoryPayload {
    pub arch: Option<String>,
    pub os: Option<String>,
    #[serde(default)]
    pub labels: Option<HashMap<String, String>>,
    #[serde(default)]
    pub capacity: Option<db::CapacityHints>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct HeartbeatRequest {
    pub node_status: NodeStatus,
    #[serde(default)]
    pub containers: Vec<InstanceStatus>,
    #[allow(dead_code)]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default)]
    pub inventory: Option<NodeInventoryPayload>,
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default)]
    pub public_host: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NodeStatusSnapshot {
    pub node: db::NodeRecord,
    pub instances: Vec<db::InstanceStatusRecord>,
    pub usage_summary: Option<UsageSummary>,
}

#[derive(Clone, Debug)]
pub struct ListNodesRequest {
    pub status: Option<db::NodeStatus>,
    pub limit: u32,
    pub offset: u32,
}

pub async fn register_node(
    state: &AppState,
    provided_token: &str,
    payload: RegistrationRequest,
) -> ApiResult<RegistrationResponse> {
    if let Some(limiter) = &state.registration_limiter {
        let mut limiter = limiter.lock().await;
        if !limiter.try_acquire() {
            return Err(AppError::too_many_requests(
                "registration rate limit exceeded",
            ));
        }
    }

    if provided_token != state.registration_token {
        return Err(AppError::unauthorized("invalid registration token"));
    }

    let inventory_update = validation::validate_registration(&payload, &state.limits)?;

    let db::NodeInventoryUpdate {
        arch,
        os,
        labels,
        capacity,
        public_ip,
        public_host,
    } = inventory_update;

    let token = generate_token();
    let token_hash = hash_token(&token, &state.token_pepper)?;

    let new_node = db::NewNode {
        id: Uuid::new_v4(),
        name: payload.name,
        arch,
        os,
        public_ip,
        public_host,
        labels,
        capacity,
        token_hash,
        last_seen: None,
        status: db::NodeStatus::Registering,
    };

    let node = nodes::create_node(&state.db, new_node).await?;

    Ok(RegistrationResponse {
        node_id: node.id,
        node_token: token,
        tunnel: TunnelEndpoint {
            host: state.tunnel.advertised_host.clone(),
            port: state.tunnel.advertised_port,
            use_tls: state.tunnel.use_tls,
            connect_timeout_secs: state.tunnel.connect_timeout_secs,
            heartbeat_interval_secs: state.tunnel.heartbeat_interval_secs,
            heartbeat_timeout_secs: state.tunnel.heartbeat_timeout_secs,
            token_header: state.tunnel.token_header.clone(),
        },
    })
}

pub async fn heartbeat(
    state: &AppState,
    node_id: Uuid,
    token: &str,
    body: HeartbeatRequest,
) -> ApiResult<()> {
    let inventory_update = match validation::validate_heartbeat(&body, &state.limits) {
        Ok(inv) => inv,
        Err(err) => {
            ::metrics::counter!(
                "heartbeat_usage_samples_dropped_total",
                "reason" => "invalid_payload"
            )
            .increment(1);
            return Err(err);
        }
    };
    let HeartbeatRequest {
        node_status,
        containers,
        timestamp,
        inventory: _,
        ..
    } = body;

    let node = nodes::get_node(&state.db, node_id)
        .await?
        .ok_or_else(|| AppError::not_found("node not found"))?;

    if !verify_node_token(state, node_id, token, &node.token_hash).await? {
        return Err(AppError::unauthorized("invalid token"));
    }

    let seen_at = Utc::now();
    if let Some(reported_ts) = timestamp {
        let skew = reported_ts - seen_at;
        if skew.num_seconds().abs() > 30 {
            ::tracing::warn!(
                %node_id,
                skew_secs = skew.num_seconds(),
                "heartbeat timestamp skewed from server clock"
            );
        }
    }
    let deployments = deployments::list_deployments_for_node(&state.db, node_id).await?;
    let deployment_ids: HashSet<Uuid> = deployments.iter().map(|d| d.deployment.id).collect();
    let assigned_instances: HashSet<(Uuid, i64)> = deployments
        .iter()
        .map(|d| (d.deployment.id, d.assignment.replica_number))
        .collect();
    let deployment_labels: HashMap<Uuid, String> = deployments
        .iter()
        .map(|d| (d.deployment.id, d.deployment.name.clone()))
        .collect();

    let mut instances = Vec::with_capacity(containers.len());
    let metrics_window = state.retention.instance_metrics_secs;
    let metrics_cutoff = ChronoDuration::seconds(metrics_window.min(i64::MAX as u64) as i64);
    let max_series = state.limits.resource_metrics_max_series;
    let mut series_limit_hit = false;
    let mut series_seen: HashSet<(Uuid, Uuid, i64)> = HashSet::new();
    for inst in containers {
        if !deployment_ids.contains(&inst.deployment_id) {
            continue;
        }

        let replica_number = i64::from(inst.replica_number);
        if !assigned_instances.contains(&(inst.deployment_id, replica_number)) {
            continue;
        }

        let restart_count = i64::from(inst.restart_count);

        let mut metrics = inst.metrics;
        if metrics_window > 0 {
            let cutoff = seen_at - metrics_cutoff;
            metrics.retain(|sample| sample.collected_at >= cutoff);
        }
        metrics.sort_by_key(|s| s.collected_at);
        metrics.dedup_by_key(|s| s.collected_at);

        instances.push(db::InstanceStatusUpsert {
            deployment_id: inst.deployment_id,
            replica_number,
            generation: inst.generation,
            container_id: inst.container_id,
            state: crate::http::to_db_instance_state(inst.state),
            message: inst.message,
            restart_count,
            last_updated: inst.last_updated,
            last_seen: seen_at,
            endpoints: inst.endpoints,
            health: ensure_health_last_error(inst.health),
            metrics: metrics.clone(),
        });

        if let Some(latest) = metrics.last() {
            let key = (inst.deployment_id, node_id, replica_number);
            if max_series > 0 && !series_seen.contains(&key) && series_seen.len() >= max_series {
                if !series_limit_hit {
                    ::tracing::warn!(
                        %node_id,
                        max_series,
                        "skipping additional resource metric gauges; max series reached"
                    );
                    series_limit_hit = true;
                }
                continue;
            }
            series_seen.insert(key);

            let deployment_name = deployment_labels
                .get(&inst.deployment_id)
                .map(|s| s.as_str())
                .unwrap_or("");
            record_resource_gauges(
                latest,
                inst.deployment_id,
                deployment_name,
                node_id,
                replica_number,
            );
        }
    }

    let (usage_rollups, usage_stats) = aggregate_usage_rollups(
        node_id,
        &instances,
        state.limits.heartbeat_metrics_total,
        state.retention.usage_window_secs,
        seen_at,
    );

    if usage_stats.accepted_samples > 0 {
        ::metrics::counter!("heartbeat_usage_samples_ingested_total")
            .increment(usage_stats.accepted_samples as u64);
    }

    if usage_stats.dropped_samples > 0 {
        ::metrics::counter!(
            "heartbeat_usage_samples_dropped_total",
            "reason" => "retention"
        )
        .increment(usage_stats.dropped_samples as u64);
    }

    if usage_stats.truncated_buckets > 0 {
        ::metrics::counter!(
            "heartbeat_usage_samples_dropped_total",
            "reason" => "bucket_limit"
        )
        .increment(usage_stats.truncated_buckets as u64);
    }

    if !usage_rollups.is_empty() {
        record_usage_gauges(&usage_rollups, &deployment_labels);
    }

    logs::record_heartbeat(
        &state.db,
        db::RecordHeartbeatParams {
            node_id,
            status: crate::http::to_db_node_status(node_status),
            last_seen: seen_at,
            instances: &instances,
            retention: Duration::from_secs(state.retention.instance_status_secs),
            inventory: inventory_update,
            usage_rollups: &usage_rollups,
        },
    )
    .await?;

    update_deployment_statuses_for_node(&state.db, &deployments).await?;

    Ok(())
}

pub async fn node_status(state: &AppState, node_id: Uuid) -> ApiResult<NodeStatusSnapshot> {
    let node = nodes::get_node(&state.db, node_id)
        .await?
        .ok_or_else(|| AppError::not_found("node not found"))?;

    let instances = logs::list_instance_statuses_for_node(&state.db, node_id).await?;
    let usage_summary = crate::http::load_usage_summary(
        state,
        db::UsageSummaryFilters {
            node_id: Some(node_id),
            ..Default::default()
        },
    )
    .await?;

    Ok(NodeStatusSnapshot {
        node,
        instances,
        usage_summary,
    })
}

pub async fn list_nodes(state: &AppState, req: ListNodesRequest) -> ApiResult<Vec<db::NodeRecord>> {
    let nodes = nodes::list_nodes_paged(&state.db, req.status, req.limit, req.offset).await?;
    Ok(nodes)
}

#[derive(Debug, Default)]
struct UsageAggregationStats {
    accepted_samples: usize,
    dropped_samples: usize,
    truncated_buckets: usize,
}

fn ensure_health_last_error(
    health: Option<crate::http::HealthStatus>,
) -> Option<crate::http::HealthStatus> {
    crate::http::ensure_health_last_error(health)
}

fn record_resource_gauges(
    sample: &db::ResourceMetricSample,
    deployment_id: Uuid,
    deployment_name: &str,
    node_id: Uuid,
    replica_number: i64,
) {
    crate::http::record_resource_gauges(
        sample,
        deployment_id,
        deployment_name,
        node_id,
        replica_number,
    );
}

fn record_usage_gauges(rollups: &[db::UsageRollup], deployment_labels: &HashMap<Uuid, String>) {
    crate::http::record_usage_gauges(rollups, deployment_labels);
}

fn aggregate_usage_rollups(
    node_id: Uuid,
    instances: &[db::InstanceStatusUpsert],
    max_buckets: usize,
    usage_window_secs: u64,
    now: DateTime<Utc>,
) -> (Vec<db::UsageRollup>, UsageAggregationStats) {
    let (rollups, stats) = crate::http::aggregate_usage_rollups(
        node_id,
        instances,
        max_buckets,
        usage_window_secs,
        now,
    );
    (
        rollups,
        UsageAggregationStats {
            accepted_samples: stats.accepted_samples,
            dropped_samples: stats.dropped_samples,
            truncated_buckets: stats.truncated_buckets,
        },
    )
}

async fn verify_node_token(
    state: &AppState,
    node_id: Uuid,
    token: &str,
    fallback_hash: &str,
) -> ApiResult<bool> {
    let active_tokens = tokens::list_active_node_tokens(&state.db, node_id).await?;
    let has_any_tokens = if active_tokens.is_empty() {
        tokens::node_tokens_exist(&state.db, node_id).await?
    } else {
        true
    };
    for node_token in active_tokens {
        if let Some(kind) = match_token(token, &node_token.token_hash, &state.token_pepper)? {
            if matches!(kind, TokenMatch::Legacy) {
                let new_hash = hash_token(token, &state.token_pepper)?;
                if let Err(err) = tokens::update_node_token_record_hash(
                    &state.db,
                    node_token.id,
                    new_hash.clone(),
                )
                .await
                {
                    ::tracing::warn!(?err, %node_id, "failed to upgrade node token hash");
                } else {
                    let _ =
                        nodes::update_node_token_hash(&state.db, node_id, new_hash.clone()).await;
                    ::tracing::info!(%node_id, "upgraded node token hash to argon2");
                }
            }
            let _ = tokens::touch_node_token_last_used(&state.db, node_token.id).await;
            return Ok(true);
        }
    }

    if has_any_tokens {
        return Ok(false);
    }

    if fallback_hash.is_empty() {
        return Ok(false);
    }

    if let Some(kind) = match_token(token, fallback_hash, &state.token_pepper)? {
        let stored_hash = if matches!(kind, TokenMatch::Legacy) {
            hash_token(token, &state.token_pepper)?
        } else {
            fallback_hash.to_string()
        };

        match tokens::create_node_token(&state.db, node_id, stored_hash.clone(), None).await {
            Ok(record) => {
                let _ = tokens::touch_node_token_last_used(&state.db, record.id).await;
            }
            Err(err) => {
                ::tracing::warn!(?err, %node_id, "failed to persist node token record");
            }
        }
        let _ = nodes::update_node_token_hash(&state.db, node_id, stored_hash.clone()).await;
        if matches!(kind, TokenMatch::Legacy) {
            ::tracing::info!(%node_id, "upgraded node token hash to argon2");
        }
        return Ok(true);
    }

    Ok(false)
}

async fn update_deployment_statuses_for_node(
    db: &db::Db,
    deployments: &[db::DeploymentWithAssignment],
) -> ApiResult<()> {
    crate::http::update_deployment_statuses_for_node(db, deployments)
        .await
        .map_err(AppError::from)
}
