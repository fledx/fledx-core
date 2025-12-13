use serde::Serialize;

use crate::args::{MetricsCommands, MetricsShowArgs};
use crate::commands::CommandContext;
use crate::validate::validate_limit;
use crate::view::metrics::render_metrics_table;
use crate::view::to_pretty_json;
use common::api;

#[derive(Serialize)]
struct MetricsSummaryQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
}

pub async fn handle_metrics(ctx: &CommandContext, command: MetricsCommands) -> anyhow::Result<()> {
    match command {
        MetricsCommands::Show(args) => {
            let api = ctx.operator_api()?;
            show_metrics_summary(&api, args).await?;
        }
    }
    Ok(())
}

async fn fetch_metrics_summary(
    api: &crate::api::OperatorApi,
    limit: Option<u32>,
) -> anyhow::Result<api::MetricsSummary> {
    if let Some(value) = limit {
        validate_limit(value)?;
    }
    let query = MetricsSummaryQuery { limit };
    api.get_with_query("/api/v1/metrics/summary", &query).await
}

async fn show_metrics_summary(
    api: &crate::api::OperatorApi,
    args: MetricsShowArgs,
) -> anyhow::Result<()> {
    let summary = fetch_metrics_summary(api, args.limit).await?;

    if args.json {
        println!("{}", to_pretty_json(&summary)?);
    } else {
        println!("{}", render_metrics_table(&summary.items));
    }
    Ok(())
}
