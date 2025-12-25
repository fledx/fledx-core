use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{FromRow, QueryBuilder, Sqlite, Transaction};
use uuid::Uuid;

use super::{
    DeploymentHealth, PlacementConstraints, PlacementHints, PortMapping, SecretEnv, SecretFile,
    VolumeMount, ports,
};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum DesiredState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum DeploymentStatus {
    Pending,
    Deploying,
    Running,
    Stopped,
    Failed,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct DeploymentRecord {
    pub id: Uuid,
    pub name: String,
    pub image: String,
    pub replicas: i64,
    pub command_json: Option<String>,
    pub env_json: Option<String>,
    pub secret_env_json: Option<String>,
    pub secret_files_json: Option<String>,
    pub volumes_json: Option<String>,
    pub ports_json: Option<String>,
    pub requires_public_ip: bool,
    pub tunnel_only: bool,
    #[sqlx(rename = "constraints_json")]
    pub constraints: Option<Json<PlacementConstraints>>,
    #[sqlx(rename = "placement_hints_json")]
    pub placement: Option<Json<PlacementHints>>,
    #[sqlx(rename = "health_json")]
    pub health: Option<Json<DeploymentHealth>>,
    pub desired_state: DesiredState,
    pub assigned_node_id: Option<Uuid>,
    pub status: DeploymentStatus,
    pub generation: i64,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct DeploymentAssignmentRecord {
    pub deployment_id: Uuid,
    pub replica_number: i64,
    pub node_id: Uuid,
    #[sqlx(rename = "ports_json")]
    pub ports: Option<Json<Vec<PortMapping>>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewDeploymentAssignment {
    pub replica_number: i64,
    pub node_id: Uuid,
    pub ports: Option<Vec<PortMapping>>,
}

#[derive(Debug, Clone)]
pub struct DeploymentWithAssignment {
    pub deployment: DeploymentRecord,
    pub assignment: DeploymentAssignmentRecord,
}

#[derive(Debug, Clone)]
pub struct NewDeployment {
    pub id: Uuid,
    pub name: String,
    pub image: String,
    pub replicas: i64,
    pub command: Option<Vec<String>>,
    pub env: Option<std::collections::HashMap<String, String>>,
    pub secret_env: Option<Vec<SecretEnv>>,
    pub secret_files: Option<Vec<SecretFile>>,
    pub volumes: Option<Vec<VolumeMount>>,
    pub ports: Option<Vec<PortMapping>>,
    pub requires_public_ip: bool,
    pub tunnel_only: bool,
    pub constraints: Option<PlacementConstraints>,
    pub placement: Option<PlacementHints>,
    pub health: Option<DeploymentHealth>,
    pub desired_state: DesiredState,
    pub assigned_node_id: Option<Uuid>,
    pub status: DeploymentStatus,
    pub generation: i64,
    pub assignments: Vec<NewDeploymentAssignment>,
}

impl NewDeployment {
    #[allow(dead_code)]
    pub fn new(name: String, image: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            image,
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
            desired_state: DesiredState::Running,
            assigned_node_id: None,
            status: DeploymentStatus::Pending,
            generation: 1,
            assignments: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpdatedDeployment {
    pub id: Uuid,
    pub name: String,
    pub image: String,
    pub replicas: i64,
    pub command: Option<Vec<String>>,
    pub env: Option<std::collections::HashMap<String, String>>,
    pub secret_env: Option<Vec<SecretEnv>>,
    pub secret_files: Option<Vec<SecretFile>>,
    pub volumes: Option<Vec<VolumeMount>>,
    pub ports: Option<Vec<PortMapping>>,
    pub requires_public_ip: bool,
    pub tunnel_only: bool,
    pub constraints: Option<PlacementConstraints>,
    pub placement: Option<PlacementHints>,
    pub health: Option<DeploymentHealth>,
    pub desired_state: DesiredState,
    pub assigned_node_id: Option<Uuid>,
    pub status: DeploymentStatus,
    pub generation: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct DeploymentListRow {
    pub id: Uuid,
    pub name: String,
    pub image: String,
    pub replicas: i64,
    pub desired_state: DesiredState,
    pub assigned_node_id: Option<Uuid>,
    pub status: DeploymentStatus,
    pub generation: i64,
    pub volumes_json: Option<String>,
    #[sqlx(rename = "placement_hints_json")]
    pub placement: Option<Json<PlacementHints>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_reported: Option<DateTime<Utc>>,
    pub tunnel_only: bool,
}

pub async fn create_deployment(
    pool: &super::Db,
    new_dep: NewDeployment,
) -> Result<DeploymentRecord> {
    let mut tx = pool.begin().await?;
    let dep_id = new_dep.id;
    create_deployment_tx(&mut tx, new_dep).await?;
    tx.commit().await?;
    get_deployment(pool, dep_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("deployment insert did not return row"))
}

pub async fn create_deployment_tx(
    tx: &mut Transaction<'_, Sqlite>,
    new_dep: NewDeployment,
) -> Result<()> {
    let NewDeployment {
        id,
        name,
        image,
        replicas,
        command,
        env,
        secret_env,
        secret_files,
        volumes,
        ports,
        requires_public_ip,
        tunnel_only,
        constraints,
        placement,
        health,
        desired_state,
        assigned_node_id,
        status,
        generation,
        assignments,
    } = new_dep;

    let primary_assignment = assigned_node_id.or_else(|| assignments.first().map(|a| a.node_id));

    let command_json = match command.as_ref() {
        Some(cmd) => Some(serde_json::to_string(cmd)?),
        None => None,
    };
    let env_json = match env.as_ref() {
        Some(env) => Some(serde_json::to_string(env)?),
        None => None,
    };
    let secret_env_json = match secret_env.as_ref() {
        Some(env) => Some(serde_json::to_string(env)?),
        None => None,
    };
    let secret_files_json = match secret_files.as_ref() {
        Some(files) => Some(serde_json::to_string(files)?),
        None => None,
    };
    let volumes_json = match volumes.as_ref() {
        Some(volumes) => Some(serde_json::to_string(volumes)?),
        None => None,
    };
    let ports_json = match ports.as_ref() {
        Some(ports) => Some(serde_json::to_string(ports)?),
        None => None,
    };
    let constraints_json: Option<Json<PlacementConstraints>> = constraints.clone().map(Json);
    let placement_hints_json: Option<Json<PlacementHints>> = placement.clone().map(Json);
    let health_json: Option<Json<DeploymentHealth>> = health.clone().map(Json);

    sqlx::query(
        r#"
        INSERT INTO deployments (
            id, name, image, replicas, command_json, env_json, secret_env_json, secret_files_json,
            volumes_json, ports_json, requires_public_ip, tunnel_only, constraints_json, placement_hints_json, health_json, desired_state,
            assigned_node_id, status, generation
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
        "#,
    )
    .bind(id)
    .bind(&name)
    .bind(&image)
    .bind(replicas)
    .bind(command_json)
    .bind(env_json)
    .bind(secret_env_json)
    .bind(secret_files_json)
    .bind(volumes_json)
    .bind(ports_json)
    .bind(requires_public_ip)
    .bind(tunnel_only)
    .bind(constraints_json)
    .bind(placement_hints_json)
    .bind(health_json)
    .bind(desired_state)
    .bind(primary_assignment)
    .bind(status)
    .bind(generation)
    .execute(tx.as_mut())
    .await?;

    replace_deployment_assignments_tx(tx, id, &assignments).await?;
    ports::replace_port_reservations(tx, id, &assignments, desired_state).await?;

    Ok(())
}

pub async fn get_deployment(pool: &super::Db, id: Uuid) -> Result<Option<DeploymentRecord>> {
    let record = sqlx::query_as::<_, DeploymentRecord>(
        r#"
        SELECT
            id,
            name,
            image,
            replicas,
            command_json,
            env_json,
            secret_env_json,
            secret_files_json,
            volumes_json,
            ports_json,
            requires_public_ip,
            tunnel_only,
            constraints_json,
            placement_hints_json,
            health_json,
            desired_state,
            assigned_node_id,
            status,
            generation,
            deleted_at,
            created_at,
            updated_at
        FROM deployments
        WHERE id = ?1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

pub async fn update_deployment_tx(
    tx: &mut Transaction<'_, Sqlite>,
    updated: UpdatedDeployment,
) -> Result<u64> {
    let command_json = match updated.command {
        Some(cmd) => Some(serde_json::to_string(&cmd)?),
        None => None,
    };
    let env_json = match updated.env {
        Some(env) => Some(serde_json::to_string(&env)?),
        None => None,
    };
    let secret_env_json = match updated.secret_env {
        Some(env) => Some(serde_json::to_string(&env)?),
        None => None,
    };
    let secret_files_json = match updated.secret_files {
        Some(files) => Some(serde_json::to_string(&files)?),
        None => None,
    };
    let volumes_json = match updated.volumes {
        Some(volumes) => Some(serde_json::to_string(&volumes)?),
        None => None,
    };
    let ports_json = match updated.ports {
        Some(ports) => Some(serde_json::to_string(&ports)?),
        None => None,
    };
    let constraints_json: Option<Json<PlacementConstraints>> = updated.constraints.map(Json);
    let placement_hints_json: Option<Json<PlacementHints>> = updated.placement.map(Json);
    let health_json: Option<Json<DeploymentHealth>> = updated.health.clone().map(Json);

    let result = sqlx::query(
        r#"
        UPDATE deployments
        SET name = ?2,
            image = ?3,
            replicas = ?4,
            command_json = ?5,
            env_json = ?6,
            secret_env_json = ?7,
            secret_files_json = ?8,
            volumes_json = ?9,
            ports_json = ?10,
            requires_public_ip = ?11,
            tunnel_only = ?12,
            constraints_json = ?13,
            placement_hints_json = ?14,
            health_json = ?15,
            desired_state = ?16,
            assigned_node_id = ?17,
            status = ?18,
            generation = ?19,
            updated_at = datetime('now')
        WHERE id = ?1 AND deleted_at IS NULL
        "#,
    )
    .bind(updated.id)
    .bind(&updated.name)
    .bind(&updated.image)
    .bind(updated.replicas)
    .bind(command_json)
    .bind(env_json)
    .bind(secret_env_json)
    .bind(secret_files_json)
    .bind(volumes_json)
    .bind(ports_json)
    .bind(updated.requires_public_ip)
    .bind(updated.tunnel_only)
    .bind(constraints_json)
    .bind(placement_hints_json)
    .bind(health_json)
    .bind(updated.desired_state)
    .bind(updated.assigned_node_id)
    .bind(updated.status)
    .bind(updated.generation)
    .execute(tx.as_mut())
    .await?;

    Ok(result.rows_affected())
}

pub async fn soft_delete_deployment_tx(tx: &mut Transaction<'_, Sqlite>, id: Uuid) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE deployments
        SET deleted_at = datetime('now'),
            desired_state = ?2,
            status = ?3,
            updated_at = datetime('now')
        WHERE id = ?1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .bind(DesiredState::Stopped)
    .bind(DeploymentStatus::Stopped)
    .execute(tx.as_mut())
    .await?;

    Ok(result.rows_affected())
}

pub async fn update_deployment_status(
    pool: &super::Db,
    id: Uuid,
    status: DeploymentStatus,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE deployments
        SET status = ?2, updated_at = datetime('now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(status)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn delete_deployment_assignments_tx(
    tx: &mut Transaction<'_, Sqlite>,
    deployment_id: Uuid,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM deployment_assignments
        WHERE deployment_id = ?1
        "#,
    )
    .bind(deployment_id)
    .execute(tx.as_mut())
    .await?;

    Ok(result.rows_affected())
}

pub async fn replace_deployment_assignments_tx(
    tx: &mut Transaction<'_, Sqlite>,
    deployment_id: Uuid,
    assignments: &[NewDeploymentAssignment],
) -> Result<()> {
    delete_deployment_assignments_tx(tx, deployment_id).await?;

    if assignments.is_empty() {
        return Ok(());
    }

    for assignment in assignments {
        let ports_json = match assignment.ports.as_ref() {
            Some(ports) => Some(serde_json::to_string(ports)?),
            None => None,
        };

        sqlx::query(
            r#"
            INSERT INTO deployment_assignments (
                deployment_id,
                replica_number,
                node_id,
                ports_json,
                created_at,
                updated_at
            )
            VALUES (?1, ?2, ?3, ?4, datetime('now'), datetime('now'))
            "#,
        )
        .bind(deployment_id)
        .bind(assignment.replica_number)
        .bind(assignment.node_id)
        .bind(ports_json)
        .execute(tx.as_mut())
        .await?;
    }

    Ok(())
}

pub async fn list_assignments_for_deployment(
    pool: &super::Db,
    deployment_id: Uuid,
) -> Result<Vec<DeploymentAssignmentRecord>> {
    let records = sqlx::query_as::<_, DeploymentAssignmentRecord>(
        r#"
        SELECT
            deployment_id,
            replica_number,
            node_id,
            ports_json,
            created_at,
            updated_at
        FROM deployment_assignments
        WHERE deployment_id = ?1
        ORDER BY replica_number ASC
        "#,
    )
    .bind(deployment_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn list_assignments_for_node(
    pool: &super::Db,
    node_id: Uuid,
) -> Result<Vec<DeploymentAssignmentRecord>> {
    let records = sqlx::query_as::<_, DeploymentAssignmentRecord>(
        r#"
        SELECT
            da.deployment_id,
            da.replica_number,
            da.node_id,
            da.ports_json,
            da.created_at,
            da.updated_at
        FROM deployment_assignments da
        JOIN deployments d ON d.id = da.deployment_id
        WHERE da.node_id = ?1
          AND d.deleted_at IS NULL
        ORDER BY da.replica_number ASC, d.created_at ASC
        "#,
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn list_deployments_for_node(
    pool: &super::Db,
    node_id: Uuid,
) -> Result<Vec<DeploymentWithAssignment>> {
    let assignments = list_assignments_for_node(pool, node_id).await?;
    let mut deployments = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        if let Some(deployment) = get_deployment(pool, assignment.deployment_id).await? {
            deployments.push(DeploymentWithAssignment {
                deployment,
                assignment,
            });
        }
    }

    Ok(deployments)
}

pub async fn list_unassigned_deployments(pool: &super::Db) -> Result<Vec<DeploymentRecord>> {
    let records = sqlx::query_as::<_, DeploymentRecord>(
        r#"
        SELECT
            d.id,
            d.name,
            d.image,
            d.replicas,
            d.command_json,
            d.env_json,
            d.secret_env_json,
            d.secret_files_json,
            d.volumes_json,
            d.ports_json,
            d.requires_public_ip,
            d.tunnel_only,
            d.constraints_json,
            d.placement_hints_json,
            d.health_json,
            d.desired_state,
            d.assigned_node_id,
            d.status,
            d.generation,
            d.deleted_at,
            d.created_at,
            d.updated_at
        FROM deployments d
        WHERE d.deleted_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM deployment_assignments da
              WHERE da.deployment_id = d.id
          )
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn list_under_assigned_deployments(pool: &super::Db) -> Result<Vec<DeploymentRecord>> {
    let records = sqlx::query_as::<_, DeploymentRecord>(
        r#"
        SELECT
            d.id,
            d.name,
            d.image,
            d.replicas,
            d.command_json,
            d.env_json,
            d.secret_env_json,
            d.secret_files_json,
            d.volumes_json,
            d.ports_json,
            d.requires_public_ip,
            d.tunnel_only,
            d.constraints_json,
            d.placement_hints_json,
            d.health_json,
            d.desired_state,
            d.assigned_node_id,
            d.status,
            d.generation,
            d.deleted_at,
            d.created_at,
            d.updated_at
        FROM deployments d
        WHERE d.deleted_at IS NULL
          AND (
              SELECT COUNT(*) FROM deployment_assignments da
              WHERE da.deployment_id = d.id
          ) < d.replicas
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn list_deployments_paged(
    pool: &super::Db,
    status: Option<DeploymentStatus>,
    limit: u32,
    offset: u32,
) -> Result<Vec<DeploymentListRow>> {
    let mut qb = QueryBuilder::<Sqlite>::new(
        r#"
        WITH latest_ts AS (
            SELECT deployment_id, MAX(last_seen) AS last_seen
            FROM instance_statuses
            GROUP BY deployment_id
        ),
        latest AS (
            SELECT i.deployment_id, i.last_seen
            FROM instance_statuses i
            JOIN latest_ts lt
              ON lt.deployment_id = i.deployment_id
             AND lt.last_seen = i.last_seen
        )
        SELECT
            d.id,
            d.name,
            d.image,
            d.replicas,
            d.desired_state,
            d.assigned_node_id,
            d.status,
            d.generation,
            d.volumes_json,
            d.placement_hints_json,
            d.created_at,
            d.updated_at,
            latest.last_seen as last_reported,
            d.tunnel_only
        FROM deployments d
        LEFT JOIN latest ON latest.deployment_id = d.id
        WHERE d.deleted_at IS NULL
        "#,
    );

    if status.is_some() {
        qb.push(" AND d.status = ");
        qb.push_bind(status);
    }

    qb.push(" ORDER BY d.created_at ASC LIMIT ");
    qb.push_bind(limit as i64);
    qb.push(" OFFSET ");
    qb.push_bind(offset as i64);

    let query = qb.build_query_as::<DeploymentListRow>();
    let records = query.fetch_all(pool).await?;
    Ok(records)
}

pub async fn update_deployment_assignment_tx(
    tx: &mut Transaction<'_, Sqlite>,
    deployment_id: Uuid,
    assigned_node_id: Option<Uuid>,
    generation: i64,
    status: DeploymentStatus,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE deployments
        SET assigned_node_id = ?2,
            generation = ?3,
            status = ?4,
            updated_at = datetime('now')
        WHERE id = ?1 AND deleted_at IS NULL
        "#,
    )
    .bind(deployment_id)
    .bind(assigned_node_id)
    .bind(generation)
    .bind(status)
    .execute(tx.as_mut())
    .await?;

    Ok(result.rows_affected())
}

pub async fn update_deployment_assignment_and_ports_tx(
    tx: &mut Transaction<'_, Sqlite>,
    deployment_id: Uuid,
    assigned_node_id: Option<Uuid>,
    generation: i64,
    status: DeploymentStatus,
    ports: Option<&[PortMapping]>,
) -> Result<u64> {
    let ports_json = match ports {
        Some(ports) => Some(serde_json::to_string(ports)?),
        None => None,
    };

    let result = sqlx::query(
        r#"
        UPDATE deployments
        SET assigned_node_id = ?2,
            generation = ?3,
            status = ?4,
            ports_json = COALESCE(?5, ports_json),
            updated_at = datetime('now')
        WHERE id = ?1 AND deleted_at IS NULL
        "#,
    )
    .bind(deployment_id)
    .bind(assigned_node_id)
    .bind(generation)
    .bind(status)
    .bind(ports_json)
    .execute(tx.as_mut())
    .await?;

    Ok(result.rows_affected())
}
