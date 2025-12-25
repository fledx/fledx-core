use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::args::{UsageCommands, UsageListArgs};
use crate::commands::CommandContext;
use crate::validate::validate_limit;
use crate::view::usage::format_usage_output;
use crate::OutputMode;
use common::api;

#[derive(Serialize)]
struct UsageListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deployment_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replica_number: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    until: Option<chrono::DateTime<Utc>>,
}

pub async fn handle_usage(ctx: &CommandContext, command: UsageCommands) -> anyhow::Result<()> {
    match command {
        UsageCommands::List(args) => {
            let api = ctx.operator_api()?;
            list_usage_rollups(&api, args).await?;
        }
    }
    Ok(())
}

fn validate_usage_args(args: &UsageListArgs) -> anyhow::Result<()> {
    if args.deployment_id.is_none() && args.node_id.is_none() {
        anyhow::bail!("--deployment or --node is required");
    }
    validate_limit(args.limit)?;
    Ok(())
}

fn usage_filter_label(args: &UsageListArgs) -> String {
    let mut parts = Vec::new();
    if let Some(id) = args.deployment_id {
        parts.push(format!(
            "deployment={}",
            crate::view::format::format_uuid(id, true)
        ));
    }
    if let Some(id) = args.node_id {
        parts.push(format!(
            "node={}",
            crate::view::format::format_uuid(id, true)
        ));
    }
    if let Some(replica) = args.replica_number {
        parts.push(format!("replica={replica}"));
    }
    parts.push(format!("range={}s", args.range.num_seconds()));
    parts.join(" ")
}

fn display_usage_page(
    page: &api::Page<api::UsageRollup>,
    mode: OutputMode,
    filters: &str,
) -> anyhow::Result<()> {
    let output = format_usage_output(page, mode, filters)?;
    println!("{}", output);
    Ok(())
}

async fn fetch_usage_rollups(
    api: &crate::api::OperatorApi,
    query: UsageListQuery,
) -> anyhow::Result<api::Page<api::UsageRollup>> {
    if let Some(limit) = query.limit {
        validate_limit(limit)?;
    }
    api.get_with_query("/api/v1/usage", &query).await
}

async fn list_usage_rollups(
    api: &crate::api::OperatorApi,
    args: UsageListArgs,
) -> anyhow::Result<()> {
    validate_usage_args(&args)?;

    let now = Utc::now();
    let since = now - args.range;
    let query = UsageListQuery {
        limit: Some(args.limit),
        offset: Some(args.offset),
        deployment_id: args.deployment_id,
        node_id: args.node_id,
        replica_number: args.replica_number.map(|r| r as i64),
        since: Some(since),
        until: Some(now),
    };

    let page = fetch_usage_rollups(api, query).await?;
    let filters = usage_filter_label(&args);
    display_usage_page(&page, args.output.mode(), &filters)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn spawn_json_server(body: String) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 4096];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        addr
    }

    #[test]
    fn validate_usage_args_requires_deployment_or_node() {
        let args = UsageListArgs {
            deployment_id: None,
            node_id: None,
            replica_number: None,
            limit: 10,
            offset: 0,
            range: chrono::Duration::minutes(5),
            output: crate::args::OutputFormatArgs {
                json: false,
                yaml: false,
            },
        };
        let err = validate_usage_args(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("--deployment or --node is required"));
    }

    #[test]
    fn usage_filter_label_includes_filters() {
        let args = UsageListArgs {
            deployment_id: Some(uuid::Uuid::from_u128(42)),
            node_id: Some(uuid::Uuid::from_u128(7)),
            replica_number: Some(2),
            limit: 10,
            offset: 0,
            range: chrono::Duration::minutes(5),
            output: crate::args::OutputFormatArgs {
                json: false,
                yaml: false,
            },
        };
        let label = usage_filter_label(&args);
        assert!(label.contains("deployment="));
        assert!(label.contains("node="));
        assert!(label.contains("replica=2"));
        assert!(label.contains("range=300s"));
    }

    #[tokio::test]
    async fn list_usage_rollups_renders_table() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let rollup = api::UsageRollup {
            deployment_id: uuid::Uuid::from_u128(1),
            node_id: uuid::Uuid::from_u128(2),
            replica_number: 0,
            bucket_start: ts,
            samples: 1,
            avg_cpu_percent: 1.2,
            avg_memory_bytes: 1024,
            avg_network_rx_bytes: 2048,
            avg_network_tx_bytes: 4096,
            avg_blk_read_bytes: Some(0),
            avg_blk_write_bytes: Some(0),
        };
        let page = api::Page {
            limit: 10,
            offset: 0,
            items: vec![rollup],
        };
        let body = serde_json::to_string(&page).expect("serialize");
        let addr = spawn_json_server(body);
        let api = crate::api::OperatorApi::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let args = UsageListArgs {
            deployment_id: Some(uuid::Uuid::from_u128(1)),
            node_id: None,
            replica_number: None,
            limit: 10,
            offset: 0,
            range: chrono::Duration::minutes(5),
            output: crate::args::OutputFormatArgs {
                json: false,
                yaml: false,
            },
        };
        list_usage_rollups(&api, args).await.expect("usage list");
    }
}
