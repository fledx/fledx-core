use std::collections::{HashMap, HashSet};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use tokio::signal;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use crate::api::OperatorApi;
use crate::args::{
    DeployCommands, DeployCreateArgs, DeployDeleteArgs, DeployLogsArgs, DeployStatusArgs,
    DeployStopArgs, DeployUpdateArgs, HealthSpecArgs,
};
use crate::commands::configs::fetch_config_attachments_for_targets;
use crate::commands::CommandContext;
use crate::validate::{
    ensure_unique_container_ports, validate_command_args, validate_constraint_requirements,
    validate_positive_u32, validate_positive_u64, validate_replica_count,
};
use crate::view::deployments::render_deployments_table;
use crate::view::format::format_affinity_details;
use crate::view::logs::{format_log_entry_line, render_audit_logs_table};
use crate::view::status::DeploymentStatusView;
use crate::view::{to_pretty_json, to_pretty_yaml, AttachedConfigInfo};
use crate::watch::watch_deployment;
use crate::OutputMode;
use common::api::{
    self, CapacityHints, DeploymentCreateResponse, DeploymentHealth, DeploymentSpec,
    DeploymentStatusResponse, DeploymentSummary, DeploymentUpdate, DesiredState, HealthProbe,
    HealthProbeKind, Page, PlacementAffinity, PlacementConstraints, PlacementHints, PortMapping,
};

pub async fn handle_deploy_create(
    ctx: &CommandContext,
    args: DeployCreateArgs,
) -> anyhow::Result<()> {
    let DeployCreateArgs {
        name,
        image,
        replicas,
        command,
        env,
        secret_env,
        secret_env_optional,
        secret_files,
        secret_files_optional,
        desired_state,
        ports,
        expose_ports,
        affinity_nodes,
        affinity_labels,
        anti_affinity_nodes,
        anti_affinity_labels,
        spread,
        require_arch,
        require_os,
        require_labels,
        require_cpu_millis,
        require_memory_bytes,
        volumes,
        health: health_args,
    } = args;
    let api = ctx.operator_api()?;
    if image.trim().is_empty() {
        anyhow::bail!("image cannot be empty");
    }
    if let Some(cmd) = command.as_ref() {
        validate_command_args(cmd, "--command")?;
    }
    validate_replica_count(replicas)?;

    let env_map = env.map(|pairs| pairs.into_iter().collect::<HashMap<String, String>>());
    let secret_env_refs = join_secret_env(secret_env, secret_env_optional);
    let secret_env = if secret_env_refs.is_empty() {
        None
    } else {
        Some(secret_env_refs)
    };
    let secret_file_refs = join_secret_files(secret_files, secret_files_optional);
    let secret_files = if secret_file_refs.is_empty() {
        None
    } else {
        Some(secret_file_refs)
    };
    let mut parsed_ports = ports;
    let ports = if parsed_ports.is_empty() {
        if !expose_ports.is_empty() {
            anyhow::bail!("--expose-port requires at least one --port entry");
        }
        None
    } else {
        ensure_unique_container_ports(&parsed_ports)?;
        apply_expose_flags(&mut parsed_ports, &expose_ports)?;
        Some(parsed_ports)
    };
    let volumes = if volumes.is_empty() {
        None
    } else {
        Some(volumes)
    };
    validate_constraint_requirements(require_cpu_millis, require_memory_bytes)?;
    let constraints = build_constraints(
        require_arch,
        require_os,
        require_labels,
        require_cpu_millis,
        require_memory_bytes,
    );
    let placement = build_placement_hints(
        &affinity_nodes,
        &affinity_labels,
        &anti_affinity_nodes,
        &anti_affinity_labels,
        spread,
    );
    let health = health_args.build_health()?;

    let payload = DeploymentSpec {
        name,
        image: image.clone(),
        replicas: Some(replicas),
        command,
        env: env_map,
        secret_env,
        secret_files,
        ports,
        requires_public_ip: false,
        tunnel_only: false,
        constraints,
        placement,
        desired_state: Some(desired_state.into()),
        volumes,
        health,
    };
    let body: DeploymentCreateResponse = api.post_json("/api/v1/deployments", &payload).await?;
    let status = fetch_deployment_status(&api, body.deployment_id).await?;
    print_deployment_status(&status);
    Ok(())
}

pub async fn handle_deploy_update(
    ctx: &CommandContext,
    args: DeployUpdateArgs,
) -> anyhow::Result<()> {
    let DeployUpdateArgs {
        deployment_id,
        name,
        image,
        replicas,
        command,
        clear_command,
        env,
        clear_env,
        secret_env,
        secret_env_optional,
        clear_secret_env,
        secret_files,
        secret_files_optional,
        clear_secret_files,
        desired_state,
        ports,
        expose_ports,
        clear_ports,
        affinity_nodes,
        affinity_labels,
        anti_affinity_nodes,
        anti_affinity_labels,
        spread,
        require_arch,
        require_os,
        require_labels,
        require_cpu_millis,
        require_memory_bytes,
        clear_constraints,
        clear_placement,
        volumes,
        clear_volumes,
        health: health_args,
    } = args;
    let api = ctx.operator_api()?;

    if let Some(img) = image.as_ref() {
        if img.trim().is_empty() {
            anyhow::bail!("image cannot be empty");
        }
    }
    if let Some(replica_count) = replicas {
        validate_replica_count(replica_count)?;
    }
    if let Some(n) = name.as_ref() {
        if n.trim().is_empty() {
            anyhow::bail!("name cannot be empty");
        }
    }
    if clear_command && command.is_some() {
        anyhow::bail!("--clear-command cannot be combined with --command");
    }
    if clear_env && env.is_some() {
        anyhow::bail!("--clear-env cannot be combined with --env");
    }
    if clear_secret_env && (!secret_env.is_empty() || !secret_env_optional.is_empty()) {
        anyhow::bail!("--clear-secret-env cannot be combined with --secret-env flags");
    }
    if clear_secret_files && (!secret_files.is_empty() || !secret_files_optional.is_empty()) {
        anyhow::bail!("--clear-secret-files cannot be combined with --secret-file flags");
    }
    if clear_ports && !ports.is_empty() {
        anyhow::bail!("--clear-ports cannot be combined with --port");
    }
    if clear_ports && !expose_ports.is_empty() {
        anyhow::bail!("--clear-ports cannot be combined with --expose-port");
    }
    if clear_volumes && !volumes.is_empty() {
        anyhow::bail!("--clear-volumes cannot be combined with --volume");
    }
    if clear_constraints
        && (require_arch.is_some()
            || require_os.is_some()
            || require_labels.is_some()
            || require_cpu_millis.is_some()
            || require_memory_bytes.is_some())
    {
        anyhow::bail!("--clear-constraints cannot be combined with --require-* flags");
    }
    if clear_placement
        && (!affinity_nodes.is_empty()
            || affinity_labels.is_some()
            || !anti_affinity_nodes.is_empty()
            || anti_affinity_labels.is_some()
            || spread)
    {
        anyhow::bail!("--clear-placement cannot be combined with placement hint flags");
    }
    if let Some(cmd) = command.as_ref() {
        validate_command_args(cmd, "--command")?;
    }

    let env_map = if clear_env {
        Some(None)
    } else {
        env.map(|pairs| Some(pairs.into_iter().collect::<HashMap<String, String>>()))
    };
    let replicas_payload = replicas;
    let secret_env_payload = if clear_secret_env {
        Some(None)
    } else if secret_env.is_empty() && secret_env_optional.is_empty() {
        None
    } else {
        Some(Some(join_secret_env(secret_env, secret_env_optional)))
    };
    let secret_files_payload = if clear_secret_files {
        Some(None)
    } else if secret_files.is_empty() && secret_files_optional.is_empty() {
        None
    } else {
        Some(Some(join_secret_files(secret_files, secret_files_optional)))
    };
    let ports_payload = if clear_ports {
        Some(None)
    } else if ports.is_empty() {
        if !expose_ports.is_empty() {
            anyhow::bail!("--expose-port requires at least one --port entry");
        }
        None
    } else {
        let mut parsed_ports = ports;
        ensure_unique_container_ports(&parsed_ports)?;
        apply_expose_flags(&mut parsed_ports, &expose_ports)?;
        Some(Some(parsed_ports))
    };
    let volumes_payload = if clear_volumes {
        Some(None)
    } else if volumes.is_empty() {
        None
    } else {
        Some(Some(volumes))
    };
    let command_payload = if clear_command {
        Some(None)
    } else {
        command.map(Some)
    };
    if !clear_constraints {
        validate_constraint_requirements(require_cpu_millis, require_memory_bytes)?;
    }
    let constraints = if clear_constraints {
        Some(None)
    } else {
        build_constraints(
            require_arch,
            require_os,
            require_labels,
            require_cpu_millis,
            require_memory_bytes,
        )
        .map(Some)
    };
    let placement = if clear_placement {
        Some(None)
    } else {
        build_placement_hints(
            &affinity_nodes,
            &affinity_labels,
            &anti_affinity_nodes,
            &anti_affinity_labels,
            spread,
        )
        .map(Some)
    };
    let desired_state_payload = desired_state.map(DesiredState::from);
    if health_args.clear_health && health_args.spec.has_probe() {
        anyhow::bail!("--clear-health cannot be combined with --health-* flags");
    }
    let health_payload = if health_args.clear_health {
        Some(None)
    } else {
        health_args.spec.build_health()?.map(Some)
    };

    if name.is_none()
        && image.is_none()
        && replicas_payload.is_none()
        && command_payload.is_none()
        && env_map.is_none()
        && secret_env_payload.is_none()
        && secret_files_payload.is_none()
        && ports_payload.is_none()
        && desired_state_payload.is_none()
        && constraints.is_none()
        && placement.is_none()
        && volumes_payload.is_none()
        && health_payload.is_none()
    {
        anyhow::bail!("provide at least one field to update");
    }

    let payload = DeploymentUpdate {
        name,
        image,
        replicas: replicas_payload,
        command: command_payload,
        env: env_map,
        secret_env: secret_env_payload,
        secret_files: secret_files_payload,
        ports: ports_payload,
        requires_public_ip: None,
        tunnel_only: None,
        constraints,
        placement,
        desired_state: desired_state_payload,
        volumes: volumes_payload,
        health: health_payload,
    };

    let body: DeploymentStatusResponse = api
        .patch_json(&format!("/api/v1/deployments/{}", deployment_id), &payload)
        .await?;
    print_deployment_status(&body);
    Ok(())
}

pub async fn handle_deploy_stop(ctx: &CommandContext, args: DeployStopArgs) -> anyhow::Result<()> {
    let api = ctx.operator_api()?;
    let payload = DeploymentUpdate {
        name: None,
        image: None,
        replicas: None,
        command: None,
        env: None,
        secret_env: None,
        secret_files: None,
        ports: None,
        requires_public_ip: None,
        tunnel_only: None,
        constraints: None,
        placement: None,
        desired_state: Some(DesiredState::Stopped),
        volumes: None,
        health: None,
    };

    let body: DeploymentStatusResponse = api
        .patch_json(
            &format!("/api/v1/deployments/{}", args.deployment_id),
            &payload,
        )
        .await?;
    print_deployment_status(&body);
    Ok(())
}

pub async fn handle_deploy_status(
    ctx: &CommandContext,
    args: DeployStatusArgs,
) -> anyhow::Result<()> {
    let api = ctx.operator_api()?;
    let status = fetch_deployment_status(&api, args.deployment_id).await?;
    if args.json {
        println!("{}", to_pretty_json(&status)?);
    } else {
        print_deployment_status(&status);
    }
    Ok(())
}

pub async fn handle_deploy_delete(
    ctx: &CommandContext,
    args: DeployDeleteArgs,
) -> anyhow::Result<()> {
    let api = ctx.operator_api()?;
    api.delete_no_body(&format!("/api/v1/deployments/{}", args.deployment_id))
        .await?;
    println!("deployment deleted: {}", args.deployment_id);
    Ok(())
}

pub async fn handle_deploy_commands(
    ctx: &CommandContext,
    command: DeployCommands,
) -> anyhow::Result<()> {
    match command {
        DeployCommands::Create(args) => handle_deploy_create(ctx, args).await?,
        DeployCommands::Update(args) => handle_deploy_update(ctx, args).await?,
        DeployCommands::List(args) => {
            let api = ctx.operator_api()?;
            list_deployments(&api, args).await?
        }
        DeployCommands::Status(args) => {
            let api = ctx.operator_api()?;
            status_deployments(&api, args).await?
        }
        DeployCommands::Stop(args) => handle_deploy_stop(ctx, args).await?,
        DeployCommands::Delete(args) => handle_deploy_delete(ctx, args).await?,
        DeployCommands::Logs(args) => {
            let api = ctx.operator_api()?;
            tail_deployment_logs(&api, args).await?
        }
        DeployCommands::Watch(args) => {
            let api = ctx.operator_api()?;
            watch_deployment(&api, args).await?
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct LogTailQuery<'a> {
    limit: u32,
    offset: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    until: Option<String>,
}

struct LogPageParams<'a> {
    limit: u32,
    offset: u32,
    resource_type: Option<&'a str>,
    resource_id: Option<Uuid>,
    since: Option<&'a DateTime<Utc>>,
    until: Option<&'a DateTime<Utc>>,
}

async fn fetch_log_page(
    api: &OperatorApi,
    params: &LogPageParams<'_>,
) -> anyhow::Result<Page<api::AuditLogEntry>> {
    crate::validate::validate_limit(params.limit)?;
    let query = LogTailQuery {
        limit: params.limit,
        offset: params.offset,
        resource_type: params.resource_type,
        resource_id: params.resource_id,
        since: params.since.map(|ts| ts.to_rfc3339()),
        until: params.until.map(|ts| ts.to_rfc3339()),
    };
    api.get_with_query("/api/v1/logs", &query).await
}

pub(crate) async fn tail_deployment_logs(
    api: &OperatorApi,
    args: DeployLogsArgs,
) -> anyhow::Result<()> {
    let DeployLogsArgs {
        limit,
        offset,
        resource_type,
        resource_id,
        since,
        until,
        follow,
        follow_interval,
    } = args;

    crate::validate::validate_limit(limit)?;
    if follow && until.is_some() {
        anyhow::bail!("--until cannot be used with --follow");
    }
    if follow && follow_interval == 0 {
        anyhow::bail!("--follow-interval must be greater than zero");
    }

    if follow {
        let interval = Duration::from_secs(follow_interval);
        let mut seen_ids = HashSet::new();
        let mut since_cursor = since;

        loop {
            let mut offset = 0;
            let mut newest_entry_time: Option<DateTime<Utc>> = None;

            loop {
                let page = fetch_log_page(
                    api,
                    &LogPageParams {
                        limit,
                        offset,
                        resource_type: resource_type.as_deref(),
                        resource_id,
                        since: since_cursor.as_ref(),
                        until: None,
                    },
                )
                .await?;

                if page.items.is_empty() {
                    break;
                }

                if newest_entry_time.is_none() {
                    newest_entry_time = page.items.first().map(|entry| entry.created_at);
                }

                for entry in page.items.iter().rev() {
                    if !seen_ids.insert(entry.id) {
                        continue;
                    }
                    println!("{}", format_log_entry_line(entry));
                }

                let page_len = page.items.len() as u32;
                if page_len < limit {
                    break;
                }

                offset = offset.saturating_add(page_len);
            }

            if let Some(time) = newest_entry_time {
                since_cursor = Some(time);
            }

            tokio::select! {
                _ = signal::ctrl_c() => break,
                _ = sleep(interval) => {}
            }
        }
        return Ok(());
    }

    let page = fetch_log_page(
        api,
        &LogPageParams {
            limit,
            offset,
            resource_type: resource_type.as_deref(),
            resource_id,
            since: since.as_ref(),
            until: until.as_ref(),
        },
    )
    .await?;

    println!("{}", render_audit_logs_table(&page.items));
    Ok(())
}

#[derive(Serialize)]
struct DeploymentListQuery<'a> {
    limit: u32,
    offset: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a str>,
}

pub async fn fetch_deployments_page(
    api: &OperatorApi,
    limit: u32,
    offset: u32,
    status: Option<crate::args::DeploymentStatusArg>,
) -> anyhow::Result<Page<DeploymentSummary>> {
    crate::validate::validate_limit(limit)?;

    let query = DeploymentListQuery {
        limit,
        offset,
        status: status
            .as_ref()
            .map(crate::args::DeploymentStatusArg::as_str),
    };

    api.get_with_query("/api/v1/deployments", &query).await
}

pub fn sort_deployments(deployments: &mut [DeploymentSummary]) {
    deployments.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.deployment_id.cmp(&b.deployment_id))
    });
}

pub fn display_deployment_page(
    page: &Page<DeploymentSummary>,
    deployment_configs: &HashMap<Uuid, Vec<AttachedConfigInfo>>,
    mode: OutputMode,
    wide: bool,
    short_ids: bool,
    colorize: bool,
) -> anyhow::Result<()> {
    match mode {
        OutputMode::Table => {
            println!(
                "{}",
                render_deployments_table(
                    &page.items,
                    deployment_configs,
                    wide,
                    short_ids,
                    colorize,
                )
            );
        }
        OutputMode::Json => {
            let view = Page {
                limit: page.limit,
                offset: page.offset,
                items: page
                    .items
                    .iter()
                    .map(|deployment| DeploymentStatusView {
                        deployment: deployment.clone(),
                        configs: deployment_configs
                            .get(&deployment.deployment_id)
                            .cloned()
                            .unwrap_or_default(),
                    })
                    .collect(),
            };
            println!("{}", to_pretty_json(&view)?);
        }
        OutputMode::Yaml => {
            let view = Page {
                limit: page.limit,
                offset: page.offset,
                items: page
                    .items
                    .iter()
                    .map(|deployment| DeploymentStatusView {
                        deployment: deployment.clone(),
                        configs: deployment_configs
                            .get(&deployment.deployment_id)
                            .cloned()
                            .unwrap_or_default(),
                    })
                    .collect(),
            };
            println!("{}", to_pretty_yaml(&view)?);
        }
    }
    Ok(())
}

pub fn empty_deployment_page(limit: u32, offset: u32) -> Page<DeploymentSummary> {
    Page {
        limit,
        offset,
        items: Vec::new(),
    }
}

async fn list_deployments(
    api: &OperatorApi,
    args: crate::args::DeploymentListArgs,
) -> anyhow::Result<()> {
    let crate::args::DeploymentListArgs {
        limit,
        offset,
        status,
        output,
        wide,
    } = args;

    let mut page = fetch_deployments_page(api, limit, offset, status).await?;

    sort_deployments(&mut page.items);
    let empty_configs: HashMap<Uuid, Vec<AttachedConfigInfo>> = HashMap::new();
    display_deployment_page(&page, &empty_configs, output.mode(), wide, false, false)?;
    Ok(())
}

async fn status_deployments(
    api: &OperatorApi,
    args: crate::args::DeploymentStatusArgs,
) -> anyhow::Result<()> {
    let crate::args::DeploymentStatusArgs {
        limit,
        offset,
        status,
        output,
        wide,
    } = args;

    let mut page = fetch_deployments_page(api, limit, offset, status).await?;

    sort_deployments(&mut page.items);
    let deployment_ids: HashSet<Uuid> = page.items.iter().map(|d| d.deployment_id).collect();
    let attachments =
        fetch_config_attachments_for_targets(api, &HashSet::new(), &deployment_ids).await?;
    display_deployment_page(
        &page,
        &attachments.deployment_configs,
        output.mode(),
        wide,
        false,
        false,
    )?;
    Ok(())
}

pub(crate) fn format_port(port: &PortMapping) -> String {
    let host = match (port.host_ip.as_deref(), port.host_port) {
        (Some(ip), Some(host)) => format!("{}:{}", ip, host),
        (None, Some(host)) => host.to_string(),
        (Some(ip), None) => format!("{}:<auto>", ip),
        (None, None) => "<auto>".to_string(),
    };
    let mut desc = format!("{} -> {}/{}", host, port.container_port, port.protocol);
    if port.expose {
        if let Some(endpoint) = port.endpoint.as_deref() {
            desc.push_str(&format!(" (exposed: {endpoint})"));
        } else {
            desc.push_str(" (exposed)");
        }
    }
    desc
}

pub(crate) fn format_volume(volume: &api::VolumeMount) -> String {
    let mode = if volume.read_only.unwrap_or(false) {
        "ro"
    } else {
        "rw"
    };
    format!(
        "{} -> {} ({})",
        volume.host_path, volume.container_path, mode
    )
}

fn append_port_lines(lines: &mut Vec<String>, ports: &Option<Vec<PortMapping>>) {
    if let Some(ports) = ports {
        for port in ports {
            lines.push(format!("port: {}", format_port(port)));
        }
    }
}

fn format_health_probe(probe: &HealthProbe) -> String {
    let mut parts = Vec::new();
    match &probe.kind {
        HealthProbeKind::Http { port, path } => {
            parts.push(format!("http port={} path={}", port, path));
        }
        HealthProbeKind::Tcp { port } => {
            parts.push(format!("tcp port={}", port));
        }
        HealthProbeKind::Exec { command } => {
            parts.push(format!("exec {}", command.join(" ")));
        }
    }
    if let Some(interval) = probe.interval_seconds {
        parts.push(format!("interval={}s", interval));
    }
    if let Some(timeout) = probe.timeout_seconds {
        parts.push(format!("timeout={}s", timeout));
    }
    if let Some(threshold) = probe.failure_threshold {
        parts.push(format!("failure_threshold={threshold}"));
    }
    if let Some(start_period) = probe.start_period_seconds {
        parts.push(format!("start_period={}s", start_period));
    }
    parts.join(" ")
}

fn append_health_config_lines(lines: &mut Vec<String>, health: &DeploymentHealth) {
    if let Some(liveness) = &health.liveness {
        lines.push(format!(
            "health.liveness: {}",
            format_health_probe(liveness)
        ));
    }
    if let Some(readiness) = &health.readiness {
        lines.push(format!(
            "health.readiness: {}",
            format_health_probe(readiness)
        ));
    }
}

fn append_instance_health_lines(lines: &mut Vec<String>, health: &api::HealthStatus) {
    lines.push(format!("instance health: {}", health.healthy));
    if let Some(result) = &health.last_probe_result {
        lines.push(format!("  last_probe_result: {}", result));
    }
    if let Some(reason) = &health.reason {
        lines.push(format!("  reason: {}", reason));
    }
    if let Some(error) = &health.last_error {
        lines.push(format!("  last_error: {}", error));
    }
    if let Some(last_checked) = health.last_checked_at {
        lines.push(format!(
            "  last_checked_at: {}",
            last_checked.to_rfc3339_opts(SecondsFormat::Secs, true)
        ));
    }
}

pub(crate) fn deployment_status_lines(status: &DeploymentStatusResponse) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("deployment_id: {}", status.deployment_id));
    if !status.assignments.is_empty() {
        lines.push("assignments:".to_string());
        for assignment in &status.assignments {
            lines.push(format!(
                "  replica {} -> {}",
                assignment.replica_number, assignment.node_id
            ));
        }
    } else if let Some(node) = status.assigned_node_id {
        lines.push(format!("assigned_node_id: {}", node));
    }
    lines.push(format!("generation: {}", status.generation));
    lines.push(format!("replicas: {}", status.replicas));
    if let Some(placement) = status.placement.as_ref() {
        if let Some(affinity) = &placement.affinity {
            lines.push(format!(
                "placement.affinity: {}",
                format_affinity_details(affinity, false)
            ));
        }
        if let Some(anti) = &placement.anti_affinity {
            lines.push(format!(
                "placement.anti_affinity: {}",
                format_affinity_details(anti, false)
            ));
        }
        if placement.spread {
            lines.push("placement.spread: true".to_string());
        }
    }
    lines.push(format!("desired_state: {}", status.desired_state.as_str()));
    lines.push(format!("status: {}", status.status.as_str()));
    if let Some(volumes) = status.volumes.as_ref() {
        for vol in volumes {
            lines.push(format!("volume: {}", format_volume(vol)));
        }
    }
    if let Some(secret_env) = status.secret_env.as_ref() {
        for entry in secret_env {
            let kind = if entry.optional {
                "optional"
            } else {
                "required"
            };
            lines.push(format!(
                "secret_env: {} -> {} ({kind})",
                entry.name, entry.secret
            ));
        }
    }
    if let Some(secret_files) = status.secret_files.as_ref() {
        for entry in secret_files {
            let kind = if entry.optional {
                "optional"
            } else {
                "required"
            };
            lines.push(format!(
                "secret_file: {} from {} ({kind})",
                entry.path, entry.secret
            ));
        }
    }
    append_port_lines(&mut lines, &status.ports);
    if let Some(health) = status.health.as_ref() {
        append_health_config_lines(&mut lines, health);
    }
    if let Some(instance) = status.instance.as_ref() {
        if !instance.endpoints.is_empty() {
            lines.push("instance endpoints:".to_string());
            for endpoint in &instance.endpoints {
                lines.push(format!("  {}", endpoint));
            }
        }
        if let Some(health_status) = instance.health.as_ref() {
            append_instance_health_lines(&mut lines, health_status);
        }
    }
    lines
}

pub fn print_deployment_status(status: &DeploymentStatusResponse) {
    for line in deployment_status_lines(status) {
        println!("{line}");
    }
}

pub async fn fetch_deployment_status(
    api: &OperatorApi,
    deployment_id: Uuid,
) -> anyhow::Result<DeploymentStatusResponse> {
    api.get(&format!("/api/v1/deployments/{}", deployment_id))
        .await
}

fn build_constraints(
    arch: Option<String>,
    os: Option<String>,
    labels: Option<Vec<(String, String)>>,
    cpu_millis: Option<u32>,
    memory_bytes: Option<u64>,
) -> Option<PlacementConstraints> {
    let labels = labels.map(|pairs| pairs.into_iter().collect::<HashMap<_, _>>());
    let capacity = match (cpu_millis, memory_bytes) {
        (None, None) => None,
        _ => Some(CapacityHints {
            cpu_millis,
            memory_bytes,
        }),
    };

    let has_labels = labels.as_ref().map(|m| !m.is_empty()).unwrap_or(false);
    if arch.is_none() && os.is_none() && !has_labels && capacity.is_none() {
        return None;
    }

    Some(PlacementConstraints {
        arch,
        os,
        labels: labels.unwrap_or_default(),
        capacity,
        requires_public_ip: false,
    })
}

fn build_affinity(
    nodes: &[Uuid],
    labels: &Option<Vec<(String, String)>>,
) -> Option<PlacementAffinity> {
    let labels = labels
        .as_ref()
        .map(|pairs| pairs.iter().cloned().collect::<HashMap<_, _>>())
        .unwrap_or_default();

    if nodes.is_empty() && labels.is_empty() {
        return None;
    }

    Some(PlacementAffinity {
        node_ids: nodes.to_vec(),
        labels,
    })
}

fn build_placement_hints(
    affinity_nodes: &[Uuid],
    affinity_labels: &Option<Vec<(String, String)>>,
    anti_affinity_nodes: &[Uuid],
    anti_affinity_labels: &Option<Vec<(String, String)>>,
    spread: bool,
) -> Option<PlacementHints> {
    let affinity = build_affinity(affinity_nodes, affinity_labels);
    let anti_affinity = build_affinity(anti_affinity_nodes, anti_affinity_labels);

    if affinity.is_none() && anti_affinity.is_none() && !spread {
        return None;
    }

    Some(PlacementHints {
        affinity,
        anti_affinity,
        spread,
    })
}

impl HealthSpecArgs {
    pub(crate) fn has_probe(&self) -> bool {
        self.http_path.is_some() || self.tcp_port.is_some() || !self.exec_command.is_empty()
    }

    pub(crate) fn build_health(&self) -> anyhow::Result<Option<DeploymentHealth>> {
        let probe = match self.build_probe()? {
            Some(probe) => probe,
            None => return Ok(None),
        };

        let mut health = DeploymentHealth {
            liveness: None,
            readiness: None,
        };
        if self.readiness {
            health.readiness = Some(probe);
        } else {
            health.liveness = Some(probe);
        }
        Ok(Some(health))
    }

    fn build_probe(&self) -> anyhow::Result<Option<HealthProbe>> {
        let mut choices = 0;
        if self.http_path.is_some() {
            choices += 1;
        }
        if self.tcp_port.is_some() {
            choices += 1;
        }
        if !self.exec_command.is_empty() {
            choices += 1;
        }

        if choices == 0 {
            if self.readiness {
                anyhow::bail!(
                    "--readiness requires one of --health-http, --health-tcp, or --health-exec"
                );
            }
            return Ok(None);
        }
        if choices > 1 {
            anyhow::bail!("only one of --health-http, --health-tcp, or --health-exec is allowed");
        }

        let kind = if let Some(path) = &self.http_path {
            let port = self
                .health_port
                .ok_or_else(|| anyhow::anyhow!("--health-http requires --health-port"))?;
            if port == 0 {
                anyhow::bail!("--health-port must be between 1 and 65535");
            }
            let trimmed = path.trim();
            if trimmed.is_empty() {
                anyhow::bail!("--health-http path cannot be empty");
            }
            HealthProbeKind::Http {
                port,
                path: trimmed.to_string(),
            }
        } else if let Some(port) = self.tcp_port {
            if port == 0 {
                anyhow::bail!("--health-tcp port must be between 1 and 65535");
            }
            HealthProbeKind::Tcp { port }
        } else {
            let mut command = Vec::with_capacity(self.exec_command.len());
            for arg in &self.exec_command {
                let trimmed = arg.trim();
                if trimmed.is_empty() {
                    anyhow::bail!("health exec command arguments cannot be empty");
                }
                command.push(trimmed.to_string());
            }
            if command.is_empty() {
                anyhow::bail!("--health-exec requires at least one argument");
            }
            HealthProbeKind::Exec { command }
        };

        validate_positive_u64("health.interval", self.interval)?;
        validate_positive_u64("health.timeout", self.timeout)?;
        validate_positive_u32("health.failure_threshold", self.failure_threshold)?;
        validate_positive_u64("health.start_period", self.start_period)?;

        Ok(Some(HealthProbe {
            kind,
            interval_seconds: self.interval,
            timeout_seconds: self.timeout,
            failure_threshold: self.failure_threshold,
            start_period_seconds: self.start_period,
        }))
    }
}

fn join_secret_env(
    required: Vec<api::SecretEnv>,
    optional: Vec<api::SecretEnv>,
) -> Vec<api::SecretEnv> {
    let mut refs = required;
    refs.extend(optional);
    refs
}

fn join_secret_files(
    required: Vec<api::SecretFile>,
    optional: Vec<api::SecretFile>,
) -> Vec<api::SecretFile> {
    let mut refs = required;
    refs.extend(optional);
    refs
}

pub(crate) fn apply_expose_flags(
    ports: &mut [PortMapping],
    expose_ports: &[u16],
) -> anyhow::Result<()> {
    for &target in expose_ports {
        if let Some(port) = ports.iter_mut().find(|p| p.container_port == target) {
            port.expose = true;
        } else {
            anyhow::bail!(
                "cannot expose port {}: add a --port entry with that container port first",
                target
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::common::api::{self as common_api, DeploymentStatus};

    #[test]
    fn apply_expose_flags_marks_specified_ports() {
        let mut ports = vec![PortMapping {
            container_port: 8080,
            host_port: Some(8080),
            protocol: "tcp".into(),
            host_ip: None,
            expose: false,
            endpoint: None,
        }];
        apply_expose_flags(&mut ports, &[8080]).unwrap();
        assert!(ports[0].expose);
    }

    #[test]
    fn apply_expose_flags_errors_for_missing_port() {
        let mut ports = vec![PortMapping {
            container_port: 80,
            host_port: Some(80),
            protocol: "tcp".into(),
            host_ip: None,
            expose: false,
            endpoint: None,
        }];
        assert!(apply_expose_flags(&mut ports, &[8080]).is_err());
    }

    #[test]
    fn format_volume_renders_mode() {
        let vol = common_api::VolumeMount {
            host_path: "/data/app".into(),
            container_path: "/var/app".into(),
            read_only: Some(true),
        };
        assert_eq!(format_volume(&vol), "/data/app -> /var/app (ro)");
    }

    #[test]
    fn format_port_shows_exposed_endpoint() {
        let port = PortMapping {
            container_port: 8080,
            host_port: Some(18080),
            protocol: "tcp".into(),
            host_ip: Some("edge-host".into()),
            expose: true,
            endpoint: Some("edge-host:18080".into()),
        };
        let output = format_port(&port);
        assert!(output.contains("(exposed: edge-host:18080)"));
    }

    #[test]
    fn format_port_shows_exposed_flag_without_endpoint() {
        let port = PortMapping {
            container_port: 8080,
            host_port: Some(18080),
            protocol: "tcp".into(),
            host_ip: Some("edge-host".into()),
            expose: true,
            endpoint: None,
        };
        let output = format_port(&port);
        assert!(output.contains("(exposed)"));
    }

    #[test]
    fn sort_deployments_by_name_then_id() {
        let mut deployments = vec![
            DeploymentSummary {
                deployment_id: Uuid::from_u128(2),
                name: "beta".into(),
                image: "nginx".into(),
                replicas: 1,
                desired_state: DesiredState::Running,
                status: DeploymentStatus::Running,
                assigned_node_id: None,
                assignments: vec![],
                generation: 1,
                tunnel_only: false,
                placement: None,
                volumes: None,
                last_reported: None,
            },
            DeploymentSummary {
                deployment_id: Uuid::from_u128(0),
                name: "alpha".into(),
                image: "nginx".into(),
                replicas: 1,
                desired_state: DesiredState::Running,
                status: DeploymentStatus::Running,
                assigned_node_id: None,
                assignments: vec![],
                generation: 1,
                tunnel_only: false,
                placement: None,
                volumes: None,
                last_reported: None,
            },
            DeploymentSummary {
                deployment_id: Uuid::from_u128(1),
                name: "alpha".into(),
                image: "nginx".into(),
                replicas: 1,
                desired_state: DesiredState::Running,
                status: DeploymentStatus::Running,
                assigned_node_id: None,
                assignments: vec![],
                generation: 1,
                tunnel_only: false,
                placement: None,
                volumes: None,
                last_reported: None,
            },
        ];

        sort_deployments(&mut deployments);
        assert_eq!(deployments[0].deployment_id, Uuid::from_u128(0));
        assert_eq!(deployments[1].deployment_id, Uuid::from_u128(1));
        assert_eq!(deployments[2].deployment_id, Uuid::from_u128(2));
    }

    #[test]
    fn health_spec_builds_http_probe() {
        let args = HealthSpecArgs {
            http_path: Some("/live".into()),
            health_port: Some(8080),
            ..Default::default()
        };
        let health = args.build_health().expect("health").expect("probe");
        assert!(health.readiness.is_none());
        let liveness = health.liveness.expect("liveness");
        if let HealthProbeKind::Http { port, path } = liveness.kind {
            assert_eq!(port, 8080);
            assert_eq!(path, "/live");
        } else {
            panic!("expected http probe");
        }
    }

    #[test]
    fn health_spec_targets_readiness_when_flag_set() {
        let args = HealthSpecArgs {
            tcp_port: Some(9000),
            readiness: true,
            ..Default::default()
        };
        let health = args.build_health().expect("health").expect("probe");
        assert!(health.liveness.is_none());
        let readiness = health.readiness.expect("readiness");
        match readiness.kind {
            HealthProbeKind::Tcp { port } => assert_eq!(port, 9000),
            _ => panic!("expected tcp probe"),
        }
    }

    #[test]
    fn health_spec_rejects_multiple_probe_types() {
        let args = HealthSpecArgs {
            http_path: Some("/live".into()),
            health_port: Some(8080),
            tcp_port: Some(8000),
            ..Default::default()
        };
        assert!(args.build_health().is_err());
    }

    #[test]
    fn health_spec_requires_port_for_http() {
        let args = HealthSpecArgs {
            http_path: Some("/live".into()),
            ..Default::default()
        };
        assert!(args.build_health().is_err());
    }

    #[test]
    fn deployment_status_lines_include_health_details() {
        let deployment_id = Uuid::new_v4();
        let now = Utc::now();
        let health_config = DeploymentHealth {
            liveness: Some(HealthProbe {
                kind: HealthProbeKind::Http {
                    port: 8080,
                    path: "/probe".into(),
                },
                interval_seconds: Some(5),
                timeout_seconds: Some(3),
                failure_threshold: Some(2),
                start_period_seconds: Some(1),
            }),
            readiness: None,
        };
        let instance_health = common_api::HealthStatus {
            healthy: false,
            last_probe_result: Some("tcp failure".into()),
            reason: Some("connection refused".into()),
            last_error: Some("timeout".into()),
            last_checked_at: Some(now),
        };
        let status = DeploymentStatusResponse {
            deployment_id,
            name: "healthy".into(),
            image: "nginx".into(),
            replicas: 1,
            command: None,
            env: None,
            secret_env: None,
            secret_files: None,
            ports: None,
            requires_public_ip: false,
            constraints: None,
            placement: None,
            volumes: None,
            health: Some(health_config),
            desired_state: DesiredState::Running,
            status: DeploymentStatus::Running,
            assigned_node_id: None,
            assignments: Vec::new(),
            generation: 1,
            tunnel_only: false,
            last_reported: Some(now),
            instance: Some(common_api::InstanceStatusResponse {
                deployment_id,
                replica_number: 0,
                container_id: None,
                state: common_api::InstanceState::Running,
                message: None,
                restart_count: 0,
                generation: 1,
                last_updated: now,
                last_seen: now,
                endpoints: vec!["http://localhost".into()],
                health: Some(instance_health.clone()),
                metrics: Vec::new(),
            }),
            usage_summary: None,
            created_at: now,
            updated_at: now,
        };

        let lines = deployment_status_lines(&status);
        assert!(lines.iter().any(|line| line.contains("health.liveness")));
        assert!(lines.iter().any(|line| line.contains("interval=5s")));
        assert!(lines
            .iter()
            .any(|line| line.contains("instance health: false")));
        assert!(lines
            .iter()
            .any(|line| line.contains("last_probe_result: tcp failure")));
        assert!(lines
            .iter()
            .any(|line| line.contains("reason: connection refused")));
    }
}
