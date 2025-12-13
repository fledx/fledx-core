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
