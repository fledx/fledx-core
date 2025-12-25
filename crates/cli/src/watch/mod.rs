use std::cmp;
use std::future::Future;
use std::io::{self, IsTerminal, Write};

use chrono::{DateTime, Utc};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::{
    signal, task,
    time::{sleep, Duration, Instant},
};

use crate::api::OperatorApi;
use crate::commands::deploy::{
    empty_deployment_page, fetch_deployment_status, tail_deployment_logs,
};
use crate::commands::nodes::empty_node_page;
use crate::commands::status::fetch_status_output;
use crate::validate::validate_deploy_watch_args;
use crate::view::{
    format::{format_optional_uuid, format_timestamp, format_uuid},
    logs::truncate_detail,
    status::{
        render_status_frame, render_status_view, DeploymentStatusCounts, NodeStatusCounts,
        StatusOutput, StatusRenderFlags, StatusSummary,
    },
    ConfigAttachmentLookup,
};
use crate::{DeployLogsArgs, DeployWatchArgs, StatusArgs, DEFAULT_PAGE_LIMIT};

use ::common::api::{DeploymentStatus, DeploymentStatusResponse, InstanceState};

pub(crate) fn should_colorize(args: &StatusArgs) -> bool {
    io::stdout().is_terminal() && !args.no_color && args.watch
}

pub(crate) async fn watch_deployment(
    api: &OperatorApi,
    args: DeployWatchArgs,
) -> anyhow::Result<()> {
    validate_deploy_watch_args(&args)?;
    let DeployWatchArgs {
        deployment_id,
        poll_interval,
        max_interval,
        max_runtime,
        follow_logs,
        follow_logs_interval,
    } = args;

    let log_handle = if follow_logs {
        let log_api = api.clone();
        let log_args = DeployLogsArgs {
            limit: DEFAULT_PAGE_LIMIT,
            offset: 0,
            resource_type: Some("deployment".to_string()),
            resource_id: Some(deployment_id),
            since: None,
            until: None,
            follow: true,
            follow_interval: follow_logs_interval,
        };
        Some(tokio::spawn(async move {
            if let Err(err) = tail_deployment_logs(&log_api, log_args).await {
                eprintln!("deployment log follow failed: {err}");
            }
        }))
    } else {
        None
    };

    let poll_duration = Duration::from_secs(poll_interval);
    let max_interval_secs = cmp::max(
        max_interval.unwrap_or(super::DEFAULT_DEPLOY_WATCH_MAX_INTERVAL_SECS),
        poll_interval,
    );
    let max_interval_duration = Duration::from_secs(max_interval_secs);
    let runtime_limit = max_runtime.map(Duration::from_secs);

    let watch_result = run_watch_loop(
        || fetch_deployment_status(api, deployment_id),
        |line| println!("{line}"),
        poll_duration,
        max_interval_duration,
        runtime_limit,
    )
    .await;

    if let Some(handle) = log_handle {
        handle.abort();
        if let Err(join_err) = handle.await {
            eprintln!("deployment log follow task aborted: {join_err}");
        }
    }

    watch_result
}

pub(crate) async fn watch_status(
    args: &StatusArgs,
    api: &OperatorApi,
    colorize: bool,
    include_nodes: bool,
    include_deploys: bool,
) -> anyhow::Result<()> {
    if io::stdout().is_terminal() {
        return watch_status_tui(args, api, colorize, include_nodes, include_deploys).await;
    }

    let interval = Duration::from_secs(args.watch_interval);
    loop {
        if io::stdout().is_terminal() {
            print!("\x1b[2J\x1b[H");
        }

        match fetch_status_output(api, args, include_nodes, include_deploys).await {
            Ok(output) => {
                let view = render_status_view(
                    &output,
                    args.wide,
                    colorize,
                    true,
                    include_nodes,
                    include_deploys,
                );
                println!("{view}");
            }
            Err(err) => {
                println!("status refresh failed: {}", err);
            }
        }

        io::stdout().flush()?;
        let sleep_fut = sleep(interval);
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = sleep_fut => {}
        }
    }
    Ok(())
}

async fn watch_status_tui(
    args: &StatusArgs,
    api: &OperatorApi,
    colorize: bool,
    include_nodes: bool,
    include_deploys: bool,
) -> anyhow::Result<()> {
    let poll_timeout = Duration::from_secs(args.watch_interval);
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let cleanup = TerminalCleanup;
    let mut last_output = StatusOutput {
        summary: StatusSummary {
            nodes: NodeStatusCounts {
                ready: 0,
                unreachable: 0,
                error: 0,
                registering: 0,
            },
            deployments: DeploymentStatusCounts {
                pending: 0,
                deploying: 0,
                running: 0,
                stopped: 0,
                failed: 0,
            },
        },
        nodes: empty_node_page(args.node_limit, args.node_offset),
        deployments: empty_deployment_page(args.deploy_limit, args.deploy_offset),
        attachments: ConfigAttachmentLookup::default(),
    };
    let mut last_error: Option<String>;

    loop {
        match fetch_status_output(api, args, include_nodes, include_deploys).await {
            Ok(output) => {
                last_output = output;
                last_error = None;
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }

        terminal.draw(|f| {
            render_status_frame(
                f,
                &last_output,
                StatusRenderFlags {
                    include_nodes,
                    include_deploys,
                    wide: args.wide,
                    colorize,
                    short_ids: true,
                },
                last_error.as_deref(),
            )
        })?;

        tokio::select! {
            _ = signal::ctrl_c() => break,
            exit = wait_for_exit_event(poll_timeout) => {
                if exit.unwrap_or(false) {
                    break;
                }
            }
        }
    }

    drop(cleanup);
    Ok(())
}

async fn wait_for_exit_event(timeout: Duration) -> io::Result<bool> {
    task::spawn_blocking(move || {
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                let is_ctrl_c =
                    key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
                if is_ctrl_c || key.code == KeyCode::Char('q') {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })
    .await
    .map_err(io::Error::other)?
}

async fn run_watch_loop<F, Fut, R>(
    mut fetch_status: F,
    mut reporter: R,
    poll_interval: Duration,
    max_interval: Duration,
    runtime_limit: Option<Duration>,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<DeploymentStatusResponse>>,
    R: FnMut(String),
{
    let mut current_interval = poll_interval;
    let start = Instant::now();
    let mut last_key: Option<DeploymentWatchKey> = None;

    loop {
        if let Some(limit) = runtime_limit {
            if Instant::now().duration_since(start) >= limit {
                reporter(format!(
                    "max runtime {}s reached, stopping watch",
                    limit.as_secs()
                ));
                break;
            }
        }

        match fetch_status().await {
            Ok(status) => {
                let key = DeploymentWatchKey::from_status(&status);
                if last_key.as_ref() != Some(&key) {
                    reporter(format_watch_event_line(&status));
                    last_key = Some(key);
                }
                current_interval = poll_interval;
                if is_terminal_deployment_status(status.status) {
                    break;
                }
            }
            Err(err) => {
                reporter(format!("watch error: {}", err));
                let doubled = current_interval.checked_mul(2).unwrap_or(max_interval);
                current_interval = doubled.min(max_interval);
            }
        }

        let sleep_fut = sleep(current_interval);
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = sleep_fut => {}
        }
    }

    Ok(())
}

fn is_terminal_deployment_status(status: DeploymentStatus) -> bool {
    matches!(
        status,
        DeploymentStatus::Running | DeploymentStatus::Stopped | DeploymentStatus::Failed
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeploymentWatchKey {
    generation: i64,
    status: DeploymentStatus,
    instance_state: Option<InstanceState>,
    instance_generation: Option<i64>,
    instance_message: Option<String>,
}

impl DeploymentWatchKey {
    fn from_status(status: &DeploymentStatusResponse) -> Self {
        let (instance_state, instance_generation, instance_message) = status
            .instance
            .as_ref()
            .map(|instance| {
                (
                    Some(instance.state),
                    Some(instance.generation),
                    instance.message.clone(),
                )
            })
            .unwrap_or((None, None, None));
        Self {
            generation: status.generation,
            status: status.status,
            instance_state,
            instance_generation,
            instance_message,
        }
    }
}

fn format_watch_event_line(status: &DeploymentStatusResponse) -> String {
    let timestamp = deployment_watch_timestamp(status);
    let mut details = Vec::new();
    details.push(format!("generation={}", status.generation));
    details.push(format!("status={}", status.status.as_str()));
    details.push(format!("assignment={}", format_assignment_summary(status)));
    if let Some(instance) = &status.instance {
        details.push(format!(
            "instance={}/gen={}",
            format_instance_state(instance.state),
            instance.generation
        ));
        details.push(format!("restarts={}", instance.restart_count));
        if let Some(message) = &instance.message {
            details.push(format!("msg={}", truncate_detail(message)));
        }
    }
    format!(
        "{} {}",
        format_timestamp(Some(timestamp)),
        details.join(" ")
    )
}

fn format_assignment_summary(status: &DeploymentStatusResponse) -> String {
    if status.assignments.is_empty() {
        format_optional_uuid(status.assigned_node_id, true)
    } else {
        let mut parts: Vec<String> = status
            .assignments
            .iter()
            .map(|assignment| {
                format!(
                    "r{}={}",
                    assignment.replica_number,
                    format_uuid(assignment.node_id, true)
                )
            })
            .collect();
        parts.sort();
        parts.join(",")
    }
}

fn deployment_watch_timestamp(status: &DeploymentStatusResponse) -> DateTime<Utc> {
    status
        .instance
        .as_ref()
        .map(|instance| instance.last_seen)
        .or(status.last_reported)
        .unwrap_or_else(Utc::now)
}

fn format_instance_state(state: InstanceState) -> &'static str {
    match state {
        InstanceState::Running => "running",
        InstanceState::Pending => "pending",
        InstanceState::Stopped => "stopped",
        InstanceState::Failed => "failed",
        InstanceState::Unknown => "unknown",
    }
}

struct TerminalCleanup;

impl Drop for TerminalCleanup {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use chrono::Utc;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    use ::common::api::{DesiredState, InstanceStatusResponse};

    fn base_status(deployment_id: Uuid) -> DeploymentStatusResponse {
        let now = Utc::now();
        DeploymentStatusResponse {
            deployment_id,
            name: "watch".into(),
            image: "registry/nginx".into(),
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
            health: None,
            desired_state: DesiredState::Running,
            status: DeploymentStatus::Deploying,
            assigned_node_id: None,
            assignments: Vec::new(),
            generation: 1,
            tunnel_only: false,
            last_reported: Some(now),
            instance: None,
            usage_summary: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn watch_loop_reports_updates_and_backoff() {
        enum WatchOutcome {
            Status(Box<DeploymentStatusResponse>),
            Error(anyhow::Error),
        }

        fn make_instance(
            deployment_id: Uuid,
            generation: i64,
            state: InstanceState,
            message: Option<&str>,
        ) -> InstanceStatusResponse {
            let now = Utc::now();
            InstanceStatusResponse {
                deployment_id,
                replica_number: 0,
                container_id: None,
                state,
                message: message.map(str::to_string),
                restart_count: 0,
                generation,
                last_updated: now,
                last_seen: now,
                endpoints: Vec::new(),
                health: None,
                metrics: Vec::new(),
            }
        }

        fn make_status(
            deployment_id: Uuid,
            generation: i64,
            status: DeploymentStatus,
            instance: Option<InstanceStatusResponse>,
        ) -> DeploymentStatusResponse {
            let now = Utc::now();
            DeploymentStatusResponse {
                deployment_id,
                name: "watch".into(),
                image: "registry/nginx".into(),
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
                health: None,
                desired_state: DesiredState::Running,
                status,
                assigned_node_id: None,
                assignments: Vec::new(),
                generation,
                tunnel_only: false,
                last_reported: Some(now),
                instance,
                usage_summary: None,
                created_at: now,
                updated_at: now,
            }
        }

        let deployment_id = Uuid::new_v4();
        let statuses = Arc::new(Mutex::new(VecDeque::from(vec![
            WatchOutcome::Status(Box::new(make_status(
                deployment_id,
                1,
                DeploymentStatus::Deploying,
                Some(make_instance(
                    deployment_id,
                    1,
                    InstanceState::Running,
                    Some("starting up"),
                )),
            ))),
            WatchOutcome::Error(anyhow!("boom")),
            WatchOutcome::Status(Box::new(make_status(
                deployment_id,
                1,
                DeploymentStatus::Deploying,
                Some(make_instance(
                    deployment_id,
                    1,
                    InstanceState::Running,
                    Some("progressing"),
                )),
            ))),
            WatchOutcome::Status(Box::new(make_status(
                deployment_id,
                2,
                DeploymentStatus::Running,
                None,
            ))),
        ])));

        let fallback_status: DeploymentStatusResponse = {
            let guard = statuses.lock().unwrap();
            guard
                .iter()
                .rev()
                .find_map(|entry| match entry {
                    WatchOutcome::Status(status) => Some(status.as_ref().clone()),
                    _ => None,
                })
                .expect("expected a successful status")
        };
        let fallback_status = Arc::new(fallback_status);

        let recorded_durations = Arc::new(Mutex::new(Vec::new()));
        let last_fetch_time = Arc::new(Mutex::new(Instant::now()));
        let outputs = Arc::new(Mutex::new(Vec::new()));

        let fetch_status = {
            let statuses = statuses.clone();
            let durations = recorded_durations.clone();
            let last_fetch_time = last_fetch_time.clone();
            let fallback = fallback_status.clone();
            move || {
                let statuses = statuses.clone();
                let durations = durations.clone();
                let last_fetch_time = last_fetch_time.clone();
                let fallback = fallback.clone();
                async move {
                    let now = Instant::now();
                    {
                        let mut last = last_fetch_time.lock().unwrap();
                        durations.lock().unwrap().push(now.duration_since(*last));
                        *last = now;
                    }
                    let outcome = {
                        let mut guard = statuses.lock().unwrap();
                        guard.pop_front()
                    };
                    match outcome {
                        Some(WatchOutcome::Status(status)) => Ok(*status),
                        Some(WatchOutcome::Error(err)) => Err(err),
                        None => Ok((*fallback).clone()),
                    }
                }
            }
        };

        let reporter = {
            let outputs = outputs.clone();
            move |line: String| {
                outputs.lock().unwrap().push(line);
            }
        };

        let handle = tokio::spawn(async move {
            run_watch_loop(
                fetch_status,
                reporter,
                Duration::from_secs(1),
                Duration::from_secs(3),
                Some(Duration::from_secs(20)),
            )
            .await
            .expect("watch loop should complete");
        });

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::advance(Duration::from_secs(1)).await;

        handle.await.unwrap();

        let recorded = recorded_durations.lock().unwrap();
        assert!(recorded.len() >= 2);
        assert_eq!(recorded[0], Duration::from_secs(1));
        assert!(recorded[1] >= Duration::from_secs(2));

        let output_lines = outputs.lock().unwrap();
        assert_eq!(output_lines.len(), 4);
        assert!(output_lines[0].contains("generation=1 status=deploying"));
        assert!(output_lines[1].starts_with("watch error"));
        assert!(output_lines[2].contains("msg=progressing"));
        assert!(output_lines[3].contains("status=running"));
    }

    #[test]
    fn format_assignment_summary_prefers_assignments() {
        let deployment_id = Uuid::new_v4();
        let mut status = base_status(deployment_id);
        let node_a = Uuid::new_v4();
        let node_b = Uuid::new_v4();
        status.assignments = vec![
            ::common::api::ReplicaAssignment {
                replica_number: 1,
                node_id: node_b,
            },
            ::common::api::ReplicaAssignment {
                replica_number: 0,
                node_id: node_a,
            },
        ];
        let summary = format_assignment_summary(&status);
        assert!(summary.contains("r0="));
        assert!(summary.contains("r1="));
    }

    #[test]
    fn format_assignment_summary_falls_back_to_assigned_node() {
        let deployment_id = Uuid::new_v4();
        let mut status = base_status(deployment_id);
        let node_id = Uuid::new_v4();
        status.assigned_node_id = Some(node_id);
        let summary = format_assignment_summary(&status);
        assert_eq!(summary, format_optional_uuid(Some(node_id), true));
    }

    #[test]
    fn format_watch_event_line_includes_instance_details() {
        let deployment_id = Uuid::new_v4();
        let now = Utc::now();
        let instance = InstanceStatusResponse {
            deployment_id,
            replica_number: 0,
            container_id: None,
            state: InstanceState::Running,
            message: Some("ready".to_string()),
            restart_count: 2,
            generation: 1,
            last_updated: now,
            last_seen: now,
            endpoints: Vec::new(),
            health: None,
            metrics: Vec::new(),
        };
        let mut status = base_status(deployment_id);
        status.instance = Some(instance);
        let line = format_watch_event_line(&status);
        assert!(line.contains("generation=1"));
        assert!(line.contains("status=deploying"));
        assert!(line.contains("instance=running/gen=1"));
        assert!(line.contains("restarts=2"));
        assert!(line.contains("msg=ready"));
    }

    #[test]
    fn deployment_watch_timestamp_prefers_instance_last_seen() {
        let deployment_id = Uuid::new_v4();
        let now = Utc::now();
        let instance = InstanceStatusResponse {
            deployment_id,
            replica_number: 0,
            container_id: None,
            state: InstanceState::Running,
            message: None,
            restart_count: 0,
            generation: 1,
            last_updated: now - chrono::Duration::seconds(10),
            last_seen: now,
            endpoints: Vec::new(),
            health: None,
            metrics: Vec::new(),
        };
        let mut status = base_status(deployment_id);
        status.last_reported = Some(now - chrono::Duration::seconds(60));
        status.instance = Some(instance);
        assert_eq!(deployment_watch_timestamp(&status), now);
    }

    #[test]
    fn format_instance_state_maps_variants() {
        assert_eq!(format_instance_state(InstanceState::Running), "running");
        assert_eq!(format_instance_state(InstanceState::Pending), "pending");
        assert_eq!(format_instance_state(InstanceState::Stopped), "stopped");
        assert_eq!(format_instance_state(InstanceState::Failed), "failed");
        assert_eq!(format_instance_state(InstanceState::Unknown), "unknown");
    }

    #[test]
    fn should_colorize_requires_watch_and_color() {
        let args = StatusArgs {
            node_limit: 10,
            node_offset: 0,
            node_status: None,
            deploy_limit: 10,
            deploy_offset: 0,
            deploy_status: None,
            json: false,
            wide: false,
            watch: false,
            watch_interval: 2,
            nodes_only: false,
            deploys_only: false,
            no_color: false,
        };
        assert!(!should_colorize(&args));
        let mut args = args.clone();
        args.watch = true;
        args.no_color = true;
        assert!(!should_colorize(&args));
    }

    #[test]
    fn is_terminal_deployment_status_detects_final_states() {
        assert!(is_terminal_deployment_status(DeploymentStatus::Running));
        assert!(is_terminal_deployment_status(DeploymentStatus::Stopped));
        assert!(is_terminal_deployment_status(DeploymentStatus::Failed));
        assert!(!is_terminal_deployment_status(DeploymentStatus::Deploying));
    }
}
