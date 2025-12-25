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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::deployments::{self, DesiredState, NewDeploymentAssignment};
    use crate::persistence::migrations;
    use crate::persistence::nodes::{self, NodeStatus};

    async fn setup_db() -> Db {
        let pool = migrations::init_pool("sqlite::memory:")
            .await
            .expect("pool");
        migrations::run_migrations(&pool).await.expect("migrations");
        pool
    }

    fn port_mapping(
        container_port: u16,
        host_port: Option<u16>,
        protocol: &str,
        host_ip: Option<&str>,
    ) -> PortMapping {
        PortMapping {
            container_port,
            host_port,
            protocol: protocol.to_string(),
            host_ip: host_ip.map(str::to_string),
            expose: false,
            endpoint: None,
        }
    }

    fn new_node(name: &str) -> nodes::NewNode {
        nodes::NewNode {
            id: Uuid::new_v4(),
            name: Some(name.to_string()),
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

    async fn create_node(pool: &Db, name: &str) -> Uuid {
        nodes::create_node(pool, new_node(name))
            .await
            .expect("create node")
            .id
    }

    async fn create_deployment(pool: &Db, name: &str) -> Uuid {
        let deployment = deployments::NewDeployment::new(name.to_string(), "image".to_string());
        deployments::create_deployment(pool, deployment)
            .await
            .expect("create deployment")
            .id
    }

    async fn insert_reservation(
        pool: &Db,
        deployment_id: Uuid,
        node_id: Uuid,
        host_ip: &str,
        protocol: &str,
        host_port: u16,
    ) {
        sqlx::query(
            r#"
            INSERT INTO port_reservations (deployment_id, node_id, host_ip, protocol, host_port)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(deployment_id)
        .bind(node_id)
        .bind(host_ip)
        .bind(protocol)
        .bind(i64::from(host_port))
        .execute(pool)
        .await
        .expect("insert reservation");
    }

    #[test]
    fn normalize_host_ip_handles_wildcards_and_case() {
        assert_eq!(normalize_host_ip(None), "");
        let wildcard = " 0.0.0.0 ".to_string();
        assert_eq!(normalize_host_ip(Some(&wildcard)), "");
        let v6 = " :: ".to_string();
        assert_eq!(normalize_host_ip(Some(&v6)), "");
        let mixed = " LoCaLhOsT ".to_string();
        assert_eq!(normalize_host_ip(Some(&mixed)), "localhost");
        let address = " 10.0.0.1 ".to_string();
        assert_eq!(normalize_host_ip(Some(&address)), "10.0.0.1");

        assert!(is_wildcard_host_ip(""));
        assert!(is_wildcard_host_ip("0.0.0.0"));
        assert!(is_wildcard_host_ip("::"));
        assert!(!is_wildcard_host_ip("10.0.0.1"));

        assert_eq!(PortReservationConflict::format_host("", 80), "0.0.0.0:80");
        assert_eq!(
            PortReservationConflict::format_host("10.0.0.1", 80),
            "10.0.0.1:80"
        );
    }

    #[test]
    fn record_conflict_prefers_wildcard_then_specific() {
        let node_id = Uuid::new_v4();
        let wildcard_dep = Uuid::new_v4();
        let host_dep = Uuid::new_v4();

        let mut usage = PortUsage {
            wildcard: Some(wildcard_dep),
            ..Default::default()
        };
        usage.hosts.insert("10.0.0.1".to_string(), host_dep);

        let conflict =
            record_conflict(&usage, node_id, "10.0.0.2", "tcp", 80).expect("wildcard conflict");
        assert_eq!(conflict.deployment_id, wildcard_dep);
        assert!(conflict.host_ip.is_empty());

        let mut usage = PortUsage::default();
        usage.hosts.insert("10.0.0.1".to_string(), host_dep);
        let conflict = record_conflict(&usage, node_id, "", "tcp", 80).expect("specific conflict");
        assert_eq!(conflict.deployment_id, host_dep);
        assert_eq!(conflict.host_ip, "10.0.0.1");

        let conflict = record_conflict(&usage, node_id, "10.0.0.2", "tcp", 80);
        assert!(conflict.is_none());
    }

    #[tokio::test]
    async fn allocate_host_ports_requires_auto_assign_enabled() {
        let db = setup_db().await;
        let config = PortAllocationConfig {
            enable_auto_assign: false,
            range_start: 3000,
            range_end: 3001,
        };
        let ports = vec![port_mapping(80, None, "tcp", None)];

        let err = allocate_host_ports_for_node(
            &db,
            Uuid::new_v4(),
            Uuid::new_v4(),
            &ports,
            None,
            &config,
        )
        .await
        .expect_err("auto assign disabled");
        let allocation = err
            .downcast_ref::<PortAllocationError>()
            .expect("allocation error");
        assert!(matches!(
            allocation,
            PortAllocationError::AutoAssignDisabled
        ));
    }

    #[tokio::test]
    async fn allocate_host_ports_detects_wildcard_conflict() {
        let db = setup_db().await;
        let node_id = create_node(&db, "conflict-node").await;
        let existing_dep = create_deployment(&db, "conflict-dep").await;
        insert_reservation(&db, existing_dep, node_id, "", "tcp", 8080).await;
        let config = PortAllocationConfig {
            enable_auto_assign: true,
            range_start: 8000,
            range_end: 8001,
        };
        let ports = vec![port_mapping(80, Some(8080), "TCP", Some("10.0.0.1"))];
        let deployment_id = create_deployment(&db, "request-dep").await;

        let err = allocate_host_ports_for_node(&db, node_id, deployment_id, &ports, None, &config)
            .await
            .expect_err("conflict");
        let allocation = err
            .downcast_ref::<PortAllocationError>()
            .expect("allocation error");
        match allocation {
            PortAllocationError::Conflict(conflict) => {
                assert_eq!(conflict.deployment_id, existing_dep);
                assert_eq!(conflict.protocol, "tcp");
                assert!(conflict.host_ip.is_empty());
            }
            other => panic!("expected conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn allocate_host_ports_ignores_deployment() {
        let db = setup_db().await;
        let node_id = create_node(&db, "ignore-node").await;
        let ignored_dep = create_deployment(&db, "ignore-dep").await;
        insert_reservation(&db, ignored_dep, node_id, "10.0.0.1", "tcp", 3000).await;

        let config = PortAllocationConfig {
            enable_auto_assign: true,
            range_start: 3000,
            range_end: 3002,
        };
        let ports = vec![port_mapping(80, None, "tcp", Some("10.0.0.1"))];
        let deployment_id = create_deployment(&db, "new-dep").await;

        let resolved = allocate_host_ports_for_node(
            &db,
            node_id,
            deployment_id,
            &ports,
            Some(ignored_dep),
            &config,
        )
        .await
        .expect("allocate");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].host_port, Some(3000));
        assert_eq!(resolved[0].host_ip.as_deref(), Some("10.0.0.1"));
    }

    #[tokio::test]
    async fn allocate_host_ports_auto_assigns_first_available() {
        let db = setup_db().await;
        let node_id = create_node(&db, "auto-node").await;
        let dep = create_deployment(&db, "auto-dep").await;
        insert_reservation(&db, dep, node_id, "", "tcp", 3000).await;
        insert_reservation(&db, dep, node_id, "", "tcp", 3001).await;

        let config = PortAllocationConfig {
            enable_auto_assign: true,
            range_start: 3000,
            range_end: 3002,
        };
        let ports = vec![port_mapping(80, None, "tcp", Some("0.0.0.0"))];
        let deployment_id = create_deployment(&db, "auto-request").await;

        let resolved =
            allocate_host_ports_for_node(&db, node_id, deployment_id, &ports, None, &config)
                .await
                .expect("allocate");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].host_port, Some(3002));
        assert!(resolved[0].host_ip.is_none());
    }

    #[tokio::test]
    async fn allocate_host_ports_reports_exhausted() {
        let db = setup_db().await;
        let node_id = create_node(&db, "exhaust-node").await;
        let dep = create_deployment(&db, "exhaust-dep").await;
        insert_reservation(&db, dep, node_id, "", "tcp", 4000).await;
        insert_reservation(&db, dep, node_id, "", "tcp", 4001).await;
        let config = PortAllocationConfig {
            enable_auto_assign: true,
            range_start: 4000,
            range_end: 4001,
        };
        let ports = vec![port_mapping(80, None, "tcp", Some("0.0.0.0"))];
        let deployment_id = create_deployment(&db, "exhaust-request").await;

        let err = allocate_host_ports_for_node(&db, node_id, deployment_id, &ports, None, &config)
            .await
            .expect_err("exhausted");
        let allocation = err
            .downcast_ref::<PortAllocationError>()
            .expect("allocation error");
        match allocation {
            PortAllocationError::Exhausted {
                host_ip,
                protocol,
                range_start,
                range_end,
            } => {
                assert!(host_ip.is_empty());
                assert_eq!(protocol, "tcp");
                assert_eq!(*range_start, 4000);
                assert_eq!(*range_end, 4001);
            }
            other => panic!("expected exhausted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn find_port_conflict_respects_ignore_deployment() {
        let db = setup_db().await;
        let node_id = create_node(&db, "conflict-node").await;
        let dep = create_deployment(&db, "conflict-dep").await;
        insert_reservation(&db, dep, node_id, "", "tcp", 9000).await;

        let ports = vec![port_mapping(9000, None, "TCP", Some("1.2.3.4"))];
        let conflict = find_port_conflict_for_node(&db, node_id, &ports, None)
            .await
            .expect("query");
        assert!(conflict.is_some());

        let conflict = find_port_conflict_for_node(&db, node_id, &ports, Some(dep))
            .await
            .expect("query");
        assert!(conflict.is_none());
    }

    #[tokio::test]
    async fn reserve_ports_for_node_rejects_local_conflicts() {
        let db = setup_db().await;
        let deployment_id = create_deployment(&db, "local-dep").await;
        let node_id = create_node(&db, "local-node").await;
        let mut tx = db.begin().await.expect("tx");
        let ports = vec![
            port_mapping(80, Some(8080), "tcp", None),
            port_mapping(80, Some(8080), "tcp", Some("127.0.0.1")),
        ];

        let err = reserve_ports_for_node(&mut tx, deployment_id, node_id, &ports, None)
            .await
            .expect_err("local conflict");
        let conflict = err
            .downcast_ref::<PortReservationConflict>()
            .expect("conflict");
        assert_eq!(conflict.deployment_id, deployment_id);
        assert_eq!(conflict.node_id, node_id);
        assert_eq!(conflict.host_ip, "127.0.0.1");
        assert_eq!(conflict.host_port, 8080);

        tx.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn reserve_and_delete_port_reservations_roundtrip() {
        let db = setup_db().await;
        let deployment_id = create_deployment(&db, "roundtrip-dep").await;
        let node_id = create_node(&db, "roundtrip-node").await;
        let ports = vec![
            port_mapping(80, Some(8080), "TCP", None),
            port_mapping(443, Some(8443), "tcp", Some("10.0.0.1")),
        ];

        let mut tx = db.begin().await.expect("tx");
        reserve_ports_for_node(&mut tx, deployment_id, node_id, &ports, None)
            .await
            .expect("reserve");
        tx.commit().await.expect("commit");

        let records = list_port_reservations_for_node(&db, node_id)
            .await
            .expect("list");
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|rec| rec.host_port == 8080));
        assert!(records.iter().any(|rec| rec.protocol == "tcp"));

        let mut tx = db.begin().await.expect("tx");
        let deleted = delete_port_reservations(&mut tx, deployment_id)
            .await
            .expect("delete");
        assert_eq!(deleted, 2);
        tx.commit().await.expect("commit");

        let records = list_port_reservations_for_node(&db, node_id)
            .await
            .expect("list");
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn replace_port_reservations_honors_desired_state() {
        let db = setup_db().await;
        let deployment_id = create_deployment(&db, "replace-dep").await;
        let node_id = create_node(&db, "replace-node").await;
        insert_reservation(&db, deployment_id, node_id, "", "tcp", 7000).await;

        let assignments = vec![NewDeploymentAssignment {
            replica_number: 0,
            node_id,
            ports: Some(vec![port_mapping(80, Some(7001), "tcp", None)]),
        }];

        let mut tx = db.begin().await.expect("tx");
        replace_port_reservations(&mut tx, deployment_id, &assignments, DesiredState::Stopped)
            .await
            .expect("replace");
        tx.commit().await.expect("commit");

        let records = list_port_reservations_for_node(&db, node_id)
            .await
            .expect("list");
        assert!(records.is_empty());

        let mut tx = db.begin().await.expect("tx");
        replace_port_reservations(&mut tx, deployment_id, &assignments, DesiredState::Running)
            .await
            .expect("replace");
        tx.commit().await.expect("commit");

        let records = list_port_reservations_for_node(&db, node_id)
            .await
            .expect("list");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].host_port, 7001);
    }
}
