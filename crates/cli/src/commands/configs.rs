use std::collections::HashSet;

use uuid::Uuid;

use crate::OutputMode;
use crate::api::OperatorApi;
use crate::args::{
    ConfigAttachCommands, ConfigAttachDeploymentArgs, ConfigAttachNodeArgs, ConfigCommands,
    ConfigCreateArgs, ConfigDeleteArgs, ConfigDetachCommands, ConfigListArgs, ConfigShowArgs,
    ConfigUpdateArgs,
};
use crate::commands::CommandContext;
use crate::validate::{
    config_entries_from_args, config_files_from_args, unique_config_ids, validate_config_name_arg,
    validate_config_version_arg, validate_limit,
};
use crate::view::format::{format_timestamp, format_uuid};
use crate::view::table::render_table;
use crate::view::{AttachedConfigInfo, ConfigAttachmentLookup, to_pretty_json, to_pretty_yaml};
use common::api::{self, ConfigSummaryPage};

pub async fn handle_configs(ctx: &CommandContext, command: ConfigCommands) -> anyhow::Result<()> {
    let api = ctx.operator_api()?;
    match command {
        ConfigCommands::List(args) => list_configs(&api, args).await?,
        ConfigCommands::Show(args) => show_config(&api, args).await?,
        ConfigCommands::Create(args) => create_config(&api, args).await?,
        ConfigCommands::Update(args) => update_config(&api, args).await?,
        ConfigCommands::Delete(args) => delete_config(&api, args).await?,
        ConfigCommands::Attach(sub) => match sub {
            ConfigAttachCommands::Deployment(args) => {
                attach_config_to_deployment(&api, args).await?
            }
            ConfigAttachCommands::Node(args) => attach_config_to_node(&api, args).await?,
        },
        ConfigCommands::Detach(sub) => match sub {
            ConfigDetachCommands::Deployment(args) => {
                detach_config_from_deployment(&api, args).await?
            }
            ConfigDetachCommands::Node(args) => detach_config_from_node(&api, args).await?,
        },
    }
    Ok(())
}

pub fn render_configs_table(configs: &[api::ConfigSummary]) -> String {
    let headers = vec!["ID", "NAME", "VERSION", "ENTRIES", "FILES", "UPDATED_AT"];
    let mut rows = Vec::with_capacity(configs.len());
    for cfg in configs {
        rows.push(vec![
            format_uuid(cfg.metadata.config_id, true),
            cfg.metadata.name.clone(),
            cfg.metadata.version.to_string(),
            cfg.entry_count.to_string(),
            cfg.file_count.to_string(),
            format_timestamp(Some(cfg.metadata.updated_at)),
        ]);
    }

    render_table(&headers, &rows)
}

fn config_lines(config: &api::ConfigResponse) -> Vec<String> {
    let mut lines = vec![
        format!("config_id: {}", config.metadata.config_id),
        format!("name: {}", config.metadata.name),
        format!("version: {}", config.metadata.version),
        format!(
            "created_at: {}",
            format_timestamp(Some(config.metadata.created_at))
        ),
        format!(
            "updated_at: {}",
            format_timestamp(Some(config.metadata.updated_at))
        ),
    ];

    if !config.entries.is_empty() {
        lines.push("entries:".to_string());
        for entry in &config.entries {
            let value = match (&entry.value, &entry.secret_ref) {
                (Some(v), None) => v.clone(),
                (None, Some(secret)) => format!("secret:{secret}"),
                _ => "-".to_string(),
            };
            lines.push(format!("  {} = {}", entry.key, value));
        }
    }

    if !config.files.is_empty() {
        lines.push("files:".to_string());
        for file in &config.files {
            lines.push(format!("  {} -> {}", file.path, file.file_ref));
        }
    }

    if !config.attached_deployments.is_empty() {
        let ids = config
            .attached_deployments
            .iter()
            .map(|id| format_uuid(*id, true))
            .collect::<Vec<_>>()
            .join(",");
        lines.push(format!("attached_deployments: {}", ids));
    }

    if !config.attached_nodes.is_empty() {
        let ids = config
            .attached_nodes
            .iter()
            .map(|id| format_uuid(*id, true))
            .collect::<Vec<_>>()
            .join(",");
        lines.push(format!("attached_nodes: {}", ids));
    }

    lines
}

async fn list_configs(api: &OperatorApi, args: ConfigListArgs) -> anyhow::Result<()> {
    validate_limit(args.limit)?;
    let page: ConfigSummaryPage = api
        .get_with_query(
            "/api/v1/configs",
            &[("limit", &args.limit), ("offset", &args.offset)],
        )
        .await?;

    match args.output.mode() {
        OutputMode::Table => println!("{}", render_configs_table(&page.items)),
        OutputMode::Json => println!("{}", to_pretty_json(&page)?),
        OutputMode::Yaml => println!("{}", to_pretty_yaml(&page)?),
    }

    Ok(())
}

async fn show_config(api: &OperatorApi, args: ConfigShowArgs) -> anyhow::Result<()> {
    let config: api::ConfigResponse = api
        .get(&format!("/api/v1/configs/{}", args.config_id))
        .await?;

    match args.output.mode() {
        OutputMode::Table => {
            for line in config_lines(&config) {
                println!("{line}");
            }
        }
        OutputMode::Json => println!("{}", to_pretty_json(&config)?),
        OutputMode::Yaml => println!("{}", to_pretty_yaml(&config)?),
    }

    Ok(())
}

async fn create_config(api: &OperatorApi, args: ConfigCreateArgs) -> anyhow::Result<()> {
    validate_config_name_arg(&args.name)?;
    let version = validate_config_version_arg(args.version)?;
    let entries = config_entries_from_args(&args.vars, &args.env_files, &args.secret_entries)?;
    let files = config_files_from_args(&args.files)?;
    let payload = api::ConfigCreateRequest {
        name: args.name.clone(),
        version,
        entries,
        files,
    };

    let config: api::ConfigResponse = api.post_json("/api/v1/configs", &payload).await?;

    for line in config_lines(&config) {
        println!("{line}");
    }

    Ok(())
}

async fn update_config(api: &OperatorApi, args: ConfigUpdateArgs) -> anyhow::Result<()> {
    if let Some(name) = args.name.as_ref() {
        validate_config_name_arg(name)?;
    }
    if args.clear_entries
        && (!args.vars.is_empty() || !args.env_files.is_empty() || !args.secret_entries.is_empty())
    {
        anyhow::bail!("--clear-entries cannot be combined with entry inputs");
    }
    if args.clear_files && !args.files.is_empty() {
        anyhow::bail!("--clear-files cannot be combined with --file");
    }
    let version = validate_config_version_arg(args.version)?;
    let entries = if args.clear_entries {
        Some(Vec::new())
    } else if !args.vars.is_empty() || !args.env_files.is_empty() || !args.secret_entries.is_empty()
    {
        Some(config_entries_from_args(
            &args.vars,
            &args.env_files,
            &args.secret_entries,
        )?)
    } else {
        None
    };

    let files = if args.clear_files {
        Some(Vec::new())
    } else if !args.files.is_empty() {
        Some(config_files_from_args(&args.files)?)
    } else {
        None
    };

    let payload = api::ConfigUpdateRequest {
        name: args.name.clone(),
        version,
        entries,
        files,
    };

    let config: api::ConfigResponse = api
        .put_json(&format!("/api/v1/configs/{}", args.config_id), &payload)
        .await?;

    for line in config_lines(&config) {
        println!("{line}");
    }

    Ok(())
}

async fn delete_config(api: &OperatorApi, args: ConfigDeleteArgs) -> anyhow::Result<()> {
    let meta: api::ConfigMetadata = api
        .delete(&format!("/api/v1/configs/{}", args.config_id))
        .await?;

    println!("config_id: {}", meta.config_id);
    println!("name: {}", meta.name);
    println!("version: {}", meta.version);
    println!("updated_at: {}", format_timestamp(Some(meta.updated_at)));

    Ok(())
}

fn print_config_attachment(res: &api::ConfigAttachmentResponse) {
    println!("config_id: {}", res.metadata.config_id);
    println!("name: {}", res.metadata.name);
    println!("version: {}", res.metadata.version);
    println!(
        "updated_at: {}",
        format_timestamp(Some(res.metadata.updated_at))
    );
    if let Some(deployment_id) = res.deployment_id {
        println!("deployment_id: {}", deployment_id);
    }
    if let Some(node_id) = res.node_id {
        println!("node_id: {}", node_id);
    }
    println!("attached: {}", res.attached);
    if let Some(attached_at) = res.attached_at {
        println!("attached_at: {}", format_timestamp(Some(attached_at)));
    }
}

async fn attach_config_to_deployment(
    api: &OperatorApi,
    args: ConfigAttachDeploymentArgs,
) -> anyhow::Result<()> {
    let config_ids = unique_config_ids(&args.config_ids)?;
    for config_id in config_ids {
        let body: api::ConfigAttachmentResponse = api
            .post_empty(&format!(
                "/api/v1/configs/{}/deployments/{}",
                config_id, args.deployment_id
            ))
            .await?
            .json()
            .await?;
        print_config_attachment(&body);
    }
    Ok(())
}

async fn detach_config_from_deployment(
    api: &OperatorApi,
    args: ConfigAttachDeploymentArgs,
) -> anyhow::Result<()> {
    let config_ids = unique_config_ids(&args.config_ids)?;
    for config_id in config_ids {
        let body: api::ConfigAttachmentResponse = api
            .delete(&format!(
                "/api/v1/configs/{}/deployments/{}",
                config_id, args.deployment_id
            ))
            .await?;
        print_config_attachment(&body);
    }
    Ok(())
}

async fn attach_config_to_node(
    api: &OperatorApi,
    args: ConfigAttachNodeArgs,
) -> anyhow::Result<()> {
    let config_ids = unique_config_ids(&args.config_ids)?;
    for config_id in config_ids {
        let body: api::ConfigAttachmentResponse = api
            .post_empty(&format!(
                "/api/v1/configs/{}/nodes/{}",
                config_id, args.node_id
            ))
            .await?
            .json()
            .await?;
        print_config_attachment(&body);
    }
    Ok(())
}

async fn detach_config_from_node(
    api: &OperatorApi,
    args: ConfigAttachNodeArgs,
) -> anyhow::Result<()> {
    let config_ids = unique_config_ids(&args.config_ids)?;
    for config_id in config_ids {
        let body: api::ConfigAttachmentResponse = api
            .delete(&format!(
                "/api/v1/configs/{}/nodes/{}",
                config_id, args.node_id
            ))
            .await?;
        print_config_attachment(&body);
    }
    Ok(())
}

pub async fn fetch_configs_page(
    api: &OperatorApi,
    limit: u32,
    offset: u32,
) -> anyhow::Result<ConfigSummaryPage> {
    validate_limit(limit)?;
    api.get_with_query("/api/v1/configs", &[("limit", &limit), ("offset", &offset)])
        .await
}

pub async fn fetch_config_detail(
    api: &OperatorApi,
    config_id: Uuid,
) -> anyhow::Result<api::ConfigResponse> {
    api.get(&format!("/api/v1/configs/{}", config_id)).await
}

pub async fn fetch_config_attachments_for_targets(
    api: &OperatorApi,
    node_targets: &HashSet<Uuid>,
    deployment_targets: &HashSet<Uuid>,
) -> anyhow::Result<ConfigAttachmentLookup> {
    if node_targets.is_empty() && deployment_targets.is_empty() {
        return Ok(ConfigAttachmentLookup::default());
    }

    let mut lookup = ConfigAttachmentLookup::default();
    let mut offset = 0;
    let limit = crate::args::MAX_PAGE_LIMIT;

    loop {
        let page = fetch_configs_page(api, limit, offset).await?;

        if page.items.is_empty() {
            break;
        }

        let page_items = page.items;
        let done = (page_items.len() as u32) < limit;

        for summary in &page_items {
            let config = fetch_config_detail(api, summary.metadata.config_id).await?;
            let info = AttachedConfigInfo {
                config_id: config.metadata.config_id,
                name: config.metadata.name.clone(),
                version: config.metadata.version,
                updated_at: config.metadata.updated_at,
            };

            for node_id in config.attached_nodes.iter().copied() {
                if node_targets.contains(&node_id) {
                    lookup
                        .node_configs
                        .entry(node_id)
                        .or_default()
                        .push(info.clone());
                }
            }

            for deployment_id in config.attached_deployments.iter().copied() {
                if deployment_targets.contains(&deployment_id) {
                    lookup
                        .deployment_configs
                        .entry(deployment_id)
                        .or_default()
                        .push(info.clone());
                }
            }
        }

        if done {
            break;
        }
        offset += limit;
    }

    for configs in lookup.node_configs.values_mut() {
        configs.sort_by(|a, b| a.name.cmp(&b.name));
    }
    for configs in lookup.deployment_configs.values_mut() {
        configs.sort_by(|a, b| a.name.cmp(&b.name));
    }

    Ok(lookup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn render_configs_table_includes_counts_and_version() {
        let summary = api::ConfigSummary {
            metadata: api::ConfigMetadata {
                config_id: Uuid::from_u128(1),
                name: "app-config".to_string(),
                version: 2,
                created_at: Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap(),
                updated_at: Utc.with_ymd_and_hms(2024, 2, 3, 4, 5, 6).unwrap(),
            },
            entry_count: 3,
            file_count: 1,
        };

        let output = render_configs_table(&[summary]);
        assert!(output.contains("app-config"));
        assert!(output.contains("2"));
        assert!(output.contains("3"));
        assert!(output.contains("1"));
    }

    #[test]
    fn config_lines_include_entries_files_and_attachments() {
        let config_id = Uuid::from_u128(42);
        let node_id = Uuid::from_u128(7);
        let config = api::ConfigResponse {
            metadata: api::ConfigMetadata {
                config_id,
                name: "demo".to_string(),
                version: 1,
                created_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
                updated_at: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
            },
            entries: vec![
                api::ConfigEntry {
                    key: "MODE".to_string(),
                    value: Some("prod".to_string()),
                    secret_ref: None,
                },
                api::ConfigEntry {
                    key: "TOKEN".to_string(),
                    value: None,
                    secret_ref: Some("token-ref".to_string()),
                },
            ],
            files: vec![api::ConfigFile {
                path: "/etc/app/config.yml".to_string(),
                file_ref: "config-blobs/app-v1".to_string(),
            }],
            attached_deployments: vec![config_id],
            attached_nodes: vec![node_id],
        };

        let lines = config_lines(&config);
        assert!(lines.iter().any(|line| line == "entries:"));
        assert!(lines.iter().any(|line| line.contains("MODE = prod")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("TOKEN = secret:token-ref"))
        );
        assert!(lines.iter().any(|line| line == "files:"));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("/etc/app/config.yml -> config-blobs/app-v1"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("attached_deployments:"))
        );
        assert!(lines.iter().any(|line| line.contains("attached_nodes:")));
    }
}
