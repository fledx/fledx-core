use std::collections::HashSet;

use uuid::Uuid;

use crate::args::StatusArgs;
use crate::commands::configs::fetch_config_attachments_for_targets;
use crate::commands::deploy::{empty_deployment_page, fetch_deployments_page, sort_deployments};
use crate::commands::nodes::{empty_node_page, fetch_nodes_page, sort_nodes};
use crate::commands::CommandContext;
use crate::validate::validate_status_args;
use crate::view::status::{compute_summary, render_status_view, status_output_view, StatusOutput};
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
