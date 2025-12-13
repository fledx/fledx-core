use std::collections::{HashMap, HashSet};
use std::fmt;

use sqlx::{FromRow, Sqlite, Transaction};
use uuid::Uuid;

use super::{Db, PortMapping};
use crate::Result;

#[derive(Debug, Clone, FromRow)]
pub struct PortReservationRecord {
    pub deployment_id: Uuid,
    pub node_id: Uuid,
    pub host_ip: String,
    pub protocol: String,
    pub host_port: i64,
    #[allow(dead_code)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[allow(dead_code)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct PortReservationConflict {
    pub deployment_id: Uuid,
    pub node_id: Uuid,
    pub host_ip: String,
    pub protocol: String,
    pub host_port: u16,
}

#[derive(Debug, Clone)]
pub struct PortAllocationConfig {
    pub enable_auto_assign: bool,
    pub range_start: u16,
    pub range_end: u16,
}

#[derive(Debug, Clone)]
pub enum PortAllocationError {
    AutoAssignDisabled,
    Exhausted {
        host_ip: String,
        protocol: String,
        range_start: u16,
        range_end: u16,
    },
    Conflict(PortReservationConflict),
}

impl std::error::Error for PortAllocationError {}

impl fmt::Display for PortAllocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortAllocationError::AutoAssignDisabled => {
                write!(f, "auto host port assignment is disabled")
            }
            PortAllocationError::Exhausted {
                host_ip,
                protocol,
                range_start,
                range_end,
            } => write!(
                f,
                "no available host ports in range {}-{} for {} ({})",
                range_start,
                range_end,
                PortReservationConflict::format_host(host_ip, 0),
                protocol
            ),
            PortAllocationError::Conflict(conflict) => conflict.fmt(f),
        }
    }
}

impl fmt::Display for PortReservationConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "port {}/{} on node {} reserved by deployment {}",
            PortReservationConflict::format_host(&self.host_ip, self.host_port),
            self.protocol,
            self.node_id,
            self.deployment_id
        )
    }
}

impl std::error::Error for PortReservationConflict {}

impl PortReservationConflict {
    pub fn format_host(host_ip: &str, host_port: u16) -> String {
        if host_ip.is_empty() {
            format!("0.0.0.0:{}", host_port)
        } else {
            format!("{}:{}", host_ip, host_port)
        }
    }
}

pub async fn list_port_reservations_for_node(
    pool: &Db,
    node_id: Uuid,
) -> Result<Vec<PortReservationRecord>> {
    let records = sqlx::query_as::<_, PortReservationRecord>(
        r#"
        SELECT deployment_id, node_id, host_ip, protocol, host_port, created_at, updated_at
        FROM port_reservations
        WHERE node_id = ?1
        ORDER BY host_ip ASC, protocol ASC, host_port ASC
        "#,
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

#[derive(Default)]
struct PortUsage {
    wildcard: Option<Uuid>,
    hosts: HashMap<String, Uuid>,
}

fn normalize_host_ip(host_ip: Option<&String>) -> String {
    let Some(ip) = host_ip else {
        return String::new();
    };
    let trimmed = ip.trim();
    if trimmed.is_empty() || trimmed == "0.0.0.0" || trimmed == "::" {
        String::new()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn is_wildcard_host_ip(host_ip: &str) -> bool {
    host_ip.is_empty() || host_ip == "0.0.0.0" || host_ip == "::"
}

fn record_conflict(
    usage: &PortUsage,
    node_id: Uuid,
    requested_host_ip: &str,
    protocol: &str,
    host_port: u16,
) -> Option<PortReservationConflict> {
    let is_requested_wildcard = is_wildcard_host_ip(requested_host_ip);
    if let Some(dep) = usage.wildcard {
        return Some(PortReservationConflict {
            deployment_id: dep,
            node_id,
            host_ip: String::new(),
            protocol: protocol.to_string(),
            host_port,
        });
    }

    if is_requested_wildcard {
        if let Some((existing_ip, dep)) = usage.hosts.iter().next() {
            return Some(PortReservationConflict {
                deployment_id: *dep,
                node_id,
                host_ip: existing_ip.clone(),
                protocol: protocol.to_string(),
                host_port,
            });
        }
    } else if let Some(dep) = usage.hosts.get(requested_host_ip) {
        return Some(PortReservationConflict {
            deployment_id: *dep,
            node_id,
            host_ip: requested_host_ip.to_string(),
            protocol: protocol.to_string(),
            host_port,
        });
    }

    None
}

fn note_usage(
    usage: &mut HashMap<(String, u16), PortUsage>,
    protocol: &str,
    host_port: u16,
    host_ip: &str,
    deployment_id: Uuid,
) {
    let entry = usage.entry((protocol.to_string(), host_port)).or_default();
    if is_wildcard_host_ip(host_ip) {
        entry.wildcard = Some(deployment_id);
    } else {
        entry.hosts.insert(host_ip.to_string(), deployment_id);
    }
}

pub async fn allocate_host_ports_for_node(
    pool: &Db,
    node_id: Uuid,
    deployment_id: Uuid,
    ports: &[PortMapping],
    ignore_deployment: Option<Uuid>,
    config: &PortAllocationConfig,
) -> Result<Vec<PortMapping>> {
    if ports.is_empty() {
        return Ok(Vec::new());
    }
    if !config.enable_auto_assign && ports.iter().any(|p| p.host_port.is_none()) {
        return Err(PortAllocationError::AutoAssignDisabled.into());
    }
    let mut usage: HashMap<(String, u16), PortUsage> = HashMap::new();
    let reservations = list_port_reservations_for_node(pool, node_id).await?;
    for reservation in reservations {
        if ignore_deployment
            .map(|dep| dep == reservation.deployment_id)
            .unwrap_or(false)
        {
            continue;
        }
        let host_ip = if is_wildcard_host_ip(&reservation.host_ip) {
            String::new()
        } else {
            reservation.host_ip.clone()
        };
        note_usage(
            &mut usage,
            &reservation.protocol,
            reservation.host_port as u16,
            &host_ip,
            reservation.deployment_id,
        );
    }

    let mut resolved_ports = Vec::with_capacity(ports.len());
    for port in ports {
        let host_ip = normalize_host_ip(port.host_ip.as_ref());
        let protocol = port.protocol.to_ascii_lowercase();
        let host_port = port.host_port;

        if let Some(host_port) = host_port {
            if let Some(conflict) = usage
                .get(&(protocol.clone(), host_port))
                .and_then(|u| record_conflict(u, node_id, &host_ip, &protocol, host_port))
            {
                return Err(PortAllocationError::Conflict(conflict).into());
            }
            note_usage(&mut usage, &protocol, host_port, &host_ip, deployment_id);
            let mut updated = port.clone();
            updated.host_ip = if host_ip.is_empty() {
                None
            } else {
                Some(host_ip.clone())
            };
            updated.host_port = Some(host_port);
            resolved_ports.push(updated);
            continue;
        }

        let mut allocated = None;
        for candidate in config.range_start..=config.range_end {
            if let Some(conflict) = usage
                .get(&(protocol.clone(), candidate))
                .and_then(|u| record_conflict(u, node_id, &host_ip, &protocol, candidate))
            {
                let _ = conflict;
                continue;
            }
            allocated = Some(candidate);
            break;
        }

        let Some(assigned) = allocated else {
            return Err(PortAllocationError::Exhausted {
                host_ip: host_ip.clone(),
                protocol: protocol.clone(),
                range_start: config.range_start,
                range_end: config.range_end,
            }
            .into());
        };

        note_usage(&mut usage, &protocol, assigned, &host_ip, deployment_id);
        let mut updated = port.clone();
        updated.host_ip = if host_ip.is_empty() {
            None
        } else {
            Some(host_ip.clone())
        };
        updated.host_port = Some(assigned);
        resolved_ports.push(updated);
    }

    Ok(resolved_ports)
}

pub async fn find_port_conflict_for_node(
    pool: &Db,
    node_id: Uuid,
    ports: &[PortMapping],
    ignore_deployment: Option<Uuid>,
) -> Result<Option<PortReservationConflict>> {
    for port in ports {
        let host_port = port.host_port.unwrap_or(port.container_port);
        let host_ip = normalize_host_ip(port.host_ip.as_ref());
        let protocol = port.protocol.to_ascii_lowercase();
        let record = sqlx::query_as::<_, PortReservationRecord>(
            r#"
            SELECT deployment_id, node_id, host_ip, protocol, host_port, created_at, updated_at
            FROM port_reservations
            WHERE node_id = ?1
              AND protocol = ?3
              AND host_port = ?4
              AND (
                    host_ip = ?2
                 OR host_ip = ''
                 OR host_ip = '0.0.0.0'
                 OR host_ip = '::'
                 OR ?2 = ''
                 OR ?2 = '0.0.0.0'
                 OR ?2 = '::'
              )
            LIMIT 1
            "#,
        )
        .bind(node_id)
        .bind(&host_ip)
        .bind(&protocol)
        .bind(i64::from(host_port))
        .fetch_optional(pool)
        .await?;

        if let Some(existing) = record {
            if ignore_deployment
                .map(|dep| dep == existing.deployment_id)
                .unwrap_or(false)
            {
                continue;
            }
            return Ok(Some(PortReservationConflict {
                deployment_id: existing.deployment_id,
                node_id: existing.node_id,
                host_ip: existing.host_ip,
                protocol: existing.protocol,
                host_port: existing.host_port as u16,
            }));
        }
    }

    Ok(None)
}

async fn find_port_conflict_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    node_id: Uuid,
    host_ip: &str,
    protocol: &str,
    host_port: u16,
    ignore_deployment: Option<Uuid>,
) -> Result<Option<PortReservationConflict>> {
    let record = sqlx::query_as::<_, PortReservationRecord>(
        r#"
        SELECT deployment_id, node_id, host_ip, protocol, host_port, created_at, updated_at
        FROM port_reservations
        WHERE node_id = ?1
          AND protocol = ?3
          AND host_port = ?4
          AND (
                host_ip = ?2
             OR host_ip = ''
             OR host_ip = '0.0.0.0'
             OR host_ip = '::'
             OR ?2 = ''
             OR ?2 = '0.0.0.0'
             OR ?2 = '::'
          )
        LIMIT 1
        "#,
    )
    .bind(node_id)
    .bind(host_ip)
    .bind(protocol)
    .bind(i64::from(host_port))
    .fetch_optional(tx.as_mut())
    .await?;

    if let Some(existing) = record {
        if ignore_deployment
            .map(|dep| dep == existing.deployment_id)
            .unwrap_or(false)
        {
            return Ok(None);
        }

        return Ok(Some(PortReservationConflict {
            deployment_id: existing.deployment_id,
            node_id: existing.node_id,
            host_ip: existing.host_ip,
            protocol: existing.protocol,
            host_port: existing.host_port as u16,
        }));
    }

    Ok(None)
}

pub async fn reserve_ports_for_node(
    tx: &mut Transaction<'_, Sqlite>,
    deployment_id: Uuid,
    node_id: Uuid,
    ports: &[PortMapping],
    ignore_deployment: Option<Uuid>,
) -> Result<()> {
    if ports.is_empty() {
        return Ok(());
    }

    let mut normalized_ports = Vec::with_capacity(ports.len());
    let mut seen_ports: HashMap<(String, u16), (bool, HashSet<String>)> = HashMap::new();

    for port in ports {
        let host_port = port.host_port.unwrap_or(port.container_port);
        let host_ip = normalize_host_ip(port.host_ip.as_ref());
        let protocol = port.protocol.to_ascii_lowercase();
        let key = (protocol.clone(), host_port);
        let entry = seen_ports
            .entry(key)
            .or_insert_with(|| (false, HashSet::new()));
        let (has_wildcard, hosts) = entry;
        let local_conflict = if host_ip.is_empty() {
            *has_wildcard || !hosts.is_empty()
        } else {
            *has_wildcard || hosts.contains(&host_ip)
        };
        if local_conflict {
            return Err(PortReservationConflict {
                deployment_id,
                node_id,
                host_ip,
                protocol,
                host_port,
            }
            .into());
        }
        if host_ip.is_empty() {
            *has_wildcard = true;
        } else {
            hosts.insert(host_ip.clone());
        }

        normalized_ports.push((host_ip, protocol, host_port));
    }

    for (host_ip, protocol, host_port) in &normalized_ports {
        if let Some(existing) = find_port_conflict_in_tx(
            tx,
            node_id,
            host_ip,
            protocol,
            *host_port,
            ignore_deployment,
        )
        .await?
        {
            return Err(existing.into());
        }
    }

    for (host_ip, protocol, host_port) in normalized_ports {
        let insert = sqlx::query(
            r#"
            INSERT INTO port_reservations (deployment_id, node_id, host_ip, protocol, host_port)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(deployment_id)
        .bind(node_id)
        .bind(&host_ip)
        .bind(&protocol)
        .bind(i64::from(host_port))
        .execute(tx.as_mut())
        .await;

        match insert {
            Ok(_) => {}
            Err(sqlx::Error::Database(db_err)) => {
                if let Some(conflict) = find_port_conflict_in_tx(
                    tx,
                    node_id,
                    &host_ip,
                    &protocol,
                    host_port,
                    ignore_deployment,
                )
                .await?
                {
                    return Err(conflict.into());
                }
                return Err(sqlx::Error::Database(db_err).into());
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
}

pub async fn delete_port_reservations(
    tx: &mut Transaction<'_, Sqlite>,
    deployment_id: Uuid,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM port_reservations
        WHERE deployment_id = ?1
        "#,
    )
    .bind(deployment_id)
    .execute(tx.as_mut())
    .await?;

    Ok(result.rows_affected())
}

pub async fn replace_port_reservations(
    tx: &mut Transaction<'_, Sqlite>,
    deployment_id: Uuid,
    assignments: &[super::deployments::NewDeploymentAssignment],
    desired_state: super::deployments::DesiredState,
) -> Result<()> {
    delete_port_reservations(tx, deployment_id).await?;

    if desired_state != super::deployments::DesiredState::Running {
        return Ok(());
    }

    for assignment in assignments {
        let Some(ports) = assignment.ports.as_ref() else {
            continue;
        };
        if ports.is_empty() {
            continue;
        }

        reserve_ports_for_node(
            tx,
            deployment_id,
            assignment.node_id,
            ports.as_slice(),
            Some(deployment_id),
        )
        .await?;
    }

    Ok(())
}
