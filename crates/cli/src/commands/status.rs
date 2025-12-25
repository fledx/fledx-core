use std::collections::HashSet;

use uuid::Uuid;

use crate::args::StatusArgs;
use crate::commands::CommandContext;
use crate::commands::configs::fetch_config_attachments_for_targets;
use crate::commands::deploy::{empty_deployment_page, fetch_deployments_page, sort_deployments};
use crate::commands::nodes::{empty_node_page, fetch_nodes_page, sort_nodes};
use crate::validate::validate_status_args;
use crate::view::status::{StatusOutput, compute_summary, render_status_view, status_output_view};
use crate::watch::{should_colorize, watch_status};

pub async fn handle_status(ctx: &CommandContext, args: StatusArgs) -> anyhow::Result<()> {
    validate_status_args(&args)?;
    let include_nodes = !args.deploys_only;
    let include_deploys = !args.nodes_only;
    let colorize = should_colorize(&args);
    let api = ctx.operator_api()?;

    if args.watch {
        watch_status(&args, &api, colorize, include_nodes, include_deploys).await
    } else {
        let output = fetch_status_output(&api, &args, include_nodes, include_deploys).await?;

        if args.json {
            println!(
                "{}",
                crate::view::to_pretty_json(&status_output_view(&output))?
            );
        } else {
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
        Ok(())
    }
}

pub(crate) async fn fetch_status_output(
    api: &crate::api::OperatorApi,
    args: &StatusArgs,
    include_nodes: bool,
    include_deploys: bool,
) -> anyhow::Result<StatusOutput> {
    let (nodes, deployments) = match (include_nodes, include_deploys) {
        (true, true) => tokio::try_join!(
            fetch_nodes_page(api, args.node_limit, args.node_offset, args.node_status),
            fetch_deployments_page(
                api,
                args.deploy_limit,
                args.deploy_offset,
                args.deploy_status
            )
        )?,
        (true, false) => (
            fetch_nodes_page(api, args.node_limit, args.node_offset, args.node_status).await?,
            empty_deployment_page(args.deploy_limit, args.deploy_offset),
        ),
        (false, true) => (
            empty_node_page(args.node_limit, args.node_offset),
            fetch_deployments_page(
                api,
                args.deploy_limit,
                args.deploy_offset,
                args.deploy_status,
            )
            .await?,
        ),
        (false, false) => unreachable!("include_nodes and include_deploys cannot both be false"),
    };

    let mut nodes = nodes;
    let mut deployments = deployments;
    sort_nodes(&mut nodes.items);
    sort_deployments(&mut deployments.items);

    let node_targets: HashSet<Uuid> = nodes.items.iter().map(|n| n.node_id).collect();
    let deployment_targets: HashSet<Uuid> =
        deployments.items.iter().map(|d| d.deployment_id).collect();

    let attachments =
        fetch_config_attachments_for_targets(api, &node_targets, &deployment_targets).await?;

    let summary = compute_summary(&nodes.items, &deployments.items);
    Ok(StatusOutput {
        summary,
        nodes,
        deployments,
        attachments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{DeploymentStatusArg, NodeStatusArg};
    use common::api::{self, ConfigSummaryPage, Page};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn read_request_line(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if header_end.is_none()
                        && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                    {
                        header_end = Some(pos + 4);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let header_end = header_end.unwrap_or(buf.len());
        let headers = String::from_utf8_lossy(&buf[..header_end]);
        headers.lines().next().unwrap_or_default().to_string()
    }

    fn json_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn error_response() -> String {
        "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .to_string()
    }

    fn spawn_route_server(
        nodes_body: String,
        deployments_body: String,
        configs_body: String,
        expected: usize,
    ) -> (std::net::SocketAddr, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut handled = 0;
            while handled < expected {
                if let Ok((mut stream, _)) = listener.accept() {
                    let request_line = read_request_line(&mut stream);
                    let _ = tx.send(request_line.clone());
                    let response = if request_line.contains("/api/v1/nodes") {
                        json_response(&nodes_body)
                    } else if request_line.contains("/api/v1/deployments") {
                        json_response(&deployments_body)
                    } else if request_line.contains("/api/v1/configs") {
                        json_response(&configs_body)
                    } else {
                        error_response()
                    };
                    let _ = stream.write_all(response.as_bytes());
                    handled += 1;
                }
            }
        });
        (addr, rx)
    }

    fn base_status_args() -> StatusArgs {
        StatusArgs {
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
            no_color: true,
        }
    }

    #[tokio::test]
    async fn fetch_status_output_nodes_only_uses_nodes_endpoint() {
        let nodes_page: Page<api::NodeSummary> = Page {
            limit: 3,
            offset: 7,
            items: Vec::new(),
        };
        let body = serde_json::to_string(&nodes_page).expect("serialize");
        let (addr, rx) = spawn_route_server(body, "{}".into(), "{}".into(), 1);
        let api = crate::api::OperatorApi::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let mut args = base_status_args();
        args.node_limit = 3;
        args.node_offset = 7;
        args.node_status = Some(NodeStatusArg::Ready);
        args.deploy_limit = 5;
        args.deploy_offset = 9;

        let output = fetch_status_output(&api, &args, true, false)
            .await
            .expect("output");

        assert!(output.nodes.items.is_empty());
        assert_eq!(output.deployments.limit, 5);
        assert_eq!(output.deployments.offset, 9);
        assert!(output.deployments.items.is_empty());

        let request = rx.recv_timeout(Duration::from_secs(1)).expect("request");
        assert!(request.contains("/api/v1/nodes?"));
        assert!(request.contains("limit=3"));
        assert!(request.contains("offset=7"));
        assert!(request.contains("status=ready"));
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    }

    #[tokio::test]
    async fn fetch_status_output_deploys_only_uses_deployments_endpoint() {
        let deployments_page: Page<api::DeploymentSummary> = Page {
            limit: 4,
            offset: 2,
            items: Vec::new(),
        };
        let body = serde_json::to_string(&deployments_page).expect("serialize");
        let (addr, rx) = spawn_route_server("{}".into(), body, "{}".into(), 1);
        let api = crate::api::OperatorApi::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let mut args = base_status_args();
        args.node_limit = 8;
        args.node_offset = 1;
        args.deploy_limit = 4;
        args.deploy_offset = 2;
        args.deploy_status = Some(DeploymentStatusArg::Running);

        let output = fetch_status_output(&api, &args, false, true)
            .await
            .expect("output");

        assert_eq!(output.nodes.limit, 8);
        assert_eq!(output.nodes.offset, 1);
        assert!(output.nodes.items.is_empty());
        assert!(output.deployments.items.is_empty());

        let request = rx.recv_timeout(Duration::from_secs(1)).expect("request");
        assert!(request.contains("/api/v1/deployments?"));
        assert!(request.contains("limit=4"));
        assert!(request.contains("offset=2"));
        assert!(request.contains("status=running"));
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    }

    #[tokio::test]
    async fn fetch_status_output_requests_configs_for_targets() {
        let nodes_page = Page {
            limit: 2,
            offset: 0,
            items: vec![api::NodeSummary {
                node_id: Uuid::from_u128(1),
                name: Some("edge-1".into()),
                status: api::NodeStatus::Ready,
                last_seen: None,
                arch: Some("x86_64".into()),
                os: Some("linux".into()),
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
            }],
        };
        let deployments_page: Page<api::DeploymentSummary> = Page {
            limit: 2,
            offset: 0,
            items: Vec::new(),
        };
        let configs_page = ConfigSummaryPage {
            limit: crate::args::MAX_PAGE_LIMIT,
            offset: 0,
            items: Vec::new(),
        };
        let nodes_body = serde_json::to_string(&nodes_page).expect("serialize nodes");
        let deployments_body = serde_json::to_string(&deployments_page).expect("serialize deploys");
        let configs_body = serde_json::to_string(&configs_page).expect("serialize configs");
        let (addr, rx) = spawn_route_server(nodes_body, deployments_body, configs_body, 3);
        let api = crate::api::OperatorApi::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let args = base_status_args();

        let output = fetch_status_output(&api, &args, true, true)
            .await
            .expect("output");

        assert_eq!(output.summary.nodes.ready, 1);
        assert!(output.attachments.node_configs.is_empty());

        let mut lines = Vec::new();
        for _ in 0..3 {
            lines.push(rx.recv_timeout(Duration::from_secs(1)).expect("request"));
        }
        assert!(lines.iter().any(|line| line.contains("/api/v1/nodes?")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("/api/v1/deployments?"))
        );
        assert!(lines.iter().any(|line| line.contains("/api/v1/configs?")));
    }

    #[tokio::test]
    async fn handle_status_outputs_json() {
        let nodes_page: Page<api::NodeSummary> = Page {
            limit: 10,
            offset: 0,
            items: Vec::new(),
        };
        let deployments_page: Page<api::DeploymentSummary> = Page {
            limit: 10,
            offset: 0,
            items: Vec::new(),
        };
        let nodes_body = serde_json::to_string(&nodes_page).expect("serialize nodes");
        let deployments_body = serde_json::to_string(&deployments_page).expect("serialize deploys");
        let (addr, rx) = spawn_route_server(nodes_body, deployments_body, "{}".into(), 2);
        let ctx = CommandContext::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization".into(),
            Some("token".into()),
        );
        let mut args = base_status_args();
        args.json = true;

        handle_status(&ctx, args).await.expect("status");

        let mut lines = Vec::new();
        for _ in 0..2 {
            lines.push(rx.recv_timeout(Duration::from_secs(1)).expect("request"));
        }
        assert!(lines.iter().any(|line| line.contains("/api/v1/nodes?")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("/api/v1/deployments?"))
        );
    }
}
