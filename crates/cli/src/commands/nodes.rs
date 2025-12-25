use std::collections::{HashMap, HashSet};

use serde::Serialize;
use uuid::Uuid;

use crate::api::{register_node, OperatorApi};
use crate::args::{NodeCommands, NodeListArgs, NodeRegisterArgs, NodeStatusArgs};
use crate::commands::configs::fetch_config_attachments_for_targets;
use crate::commands::CommandContext;
use crate::validate::validate_limit;
use crate::view::nodes::render_nodes_table;
use crate::view::{to_pretty_json, to_pretty_yaml, AttachedConfigInfo};
use crate::OutputMode;
use common::api::{self, CapacityHints, Page};

pub async fn handle_node_register(
    client: &reqwest::Client,
    base: &str,
    registration_token: Option<String>,
    args: NodeRegisterArgs,
) -> anyhow::Result<()> {
    let NodeRegisterArgs {
        name,
        arch,
        os,
        labels,
        capacity_cpu_millis,
        capacity_memory_bytes,
    } = args;
    let labels = labels.map(|pairs| pairs.into_iter().collect::<HashMap<String, String>>());
    let capacity = match (capacity_cpu_millis, capacity_memory_bytes) {
        (None, None) => None,
        _ => Some(CapacityHints {
            cpu_millis: capacity_cpu_millis,
            memory_bytes: capacity_memory_bytes,
        }),
    };
    let payload = serde_json::json!({
        "name": name,
        "arch": arch,
        "os": os,
        "labels": labels,
        "capacity": capacity,
    });
    let body: api::RegistrationResponse =
        register_node(client, base, registration_token.as_deref(), &payload).await?;
    println!("node_id: {}", body.node_id);
    println!("node_token: {}", body.node_token);
    Ok(())
}

pub async fn handle_nodes(
    ctx: &CommandContext,
    registration_token: Option<String>,
    command: NodeCommands,
) -> anyhow::Result<()> {
    match command {
        NodeCommands::Register(args) => {
            handle_node_register(&ctx.client, &ctx.base, registration_token, args).await?
        }
        NodeCommands::List(args) => {
            let api = ctx.operator_api()?;
            list_nodes(&api, args).await?
        }
        NodeCommands::Status(args) => {
            let api = ctx.operator_api()?;
            status_nodes(&api, args).await?
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct NodeListQuery<'a> {
    limit: u32,
    offset: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a str>,
}

pub async fn fetch_nodes_page(
    api: &OperatorApi,
    limit: u32,
    offset: u32,
    status: Option<crate::args::NodeStatusArg>,
) -> anyhow::Result<Page<api::NodeSummary>> {
    validate_limit(limit)?;
    let query = NodeListQuery {
        limit,
        offset,
        status: status.as_ref().map(crate::args::NodeStatusArg::as_str),
    };

    api.get_with_query("/api/v1/nodes", &query).await
}

pub fn sort_nodes(nodes: &mut [api::NodeSummary]) {
    nodes.sort_by(|a, b| {
        let a_name = a.name.as_deref().unwrap_or("");
        let b_name = b.name.as_deref().unwrap_or("");
        a_name.cmp(b_name).then_with(|| a.node_id.cmp(&b.node_id))
    });
}

pub fn display_node_page(
    page: &Page<api::NodeSummary>,
    node_configs: &HashMap<Uuid, Vec<AttachedConfigInfo>>,
    mode: OutputMode,
    wide: bool,
    short_ids: bool,
    colorize: bool,
) -> anyhow::Result<()> {
    match mode {
        OutputMode::Table => {
            println!(
                "{}",
                render_nodes_table(&page.items, node_configs, wide, short_ids, colorize)
            );
        }
        OutputMode::Json => {
            let view = Page {
                limit: page.limit,
                offset: page.offset,
                items: page
                    .items
                    .iter()
                    .map(|node| crate::view::status::NodeStatusView {
                        node: node.clone(),
                        configs: node_configs.get(&node.node_id).cloned().unwrap_or_default(),
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
                    .map(|node| crate::view::status::NodeStatusView {
                        node: node.clone(),
                        configs: node_configs.get(&node.node_id).cloned().unwrap_or_default(),
                    })
                    .collect(),
            };
            println!("{}", to_pretty_yaml(&view)?);
        }
    }
    Ok(())
}

pub fn empty_node_page(limit: u32, offset: u32) -> Page<api::NodeSummary> {
    Page {
        limit,
        offset,
        items: Vec::new(),
    }
}

async fn list_nodes(api: &OperatorApi, args: NodeListArgs) -> anyhow::Result<()> {
    let NodeListArgs {
        limit,
        offset,
        status,
        output,
        wide,
    } = args;
    let mut page = fetch_nodes_page(api, limit, offset, status).await?;
    sort_nodes(&mut page.items);
    let empty_configs: HashMap<Uuid, Vec<AttachedConfigInfo>> = HashMap::new();
    display_node_page(&page, &empty_configs, output.mode(), wide, false, false)?;
    Ok(())
}

async fn status_nodes(api: &OperatorApi, args: NodeStatusArgs) -> anyhow::Result<()> {
    let NodeStatusArgs {
        limit,
        offset,
        status,
        output,
        wide,
    } = args;
    let mut page = fetch_nodes_page(api, limit, offset, status).await?;
    sort_nodes(&mut page.items);
    let node_ids: HashSet<Uuid> = page.items.iter().map(|n| n.node_id).collect();
    let attachments = fetch_config_attachments_for_targets(api, &node_ids, &HashSet::new()).await?;
    display_node_page(
        &page,
        &attachments.node_configs,
        output.mode(),
        wide,
        false,
        false,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn sort_nodes_by_name_then_id() {
        let mut nodes = vec![
            api::NodeSummary {
                node_id: Uuid::from_u128(2),
                name: Some("beta".into()),
                status: api::NodeStatus::Ready,
                last_seen: None,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
            },
            api::NodeSummary {
                node_id: Uuid::from_u128(1),
                name: Some("alpha".into()),
                status: api::NodeStatus::Ready,
                last_seen: None,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
            },
            api::NodeSummary {
                node_id: Uuid::from_u128(0),
                name: Some("alpha".into()),
                status: api::NodeStatus::Ready,
                last_seen: None,
                arch: None,
                os: None,
                public_ip: None,
                public_host: None,
                labels: None,
                capacity: None,
            },
        ];

        sort_nodes(&mut nodes);
        assert_eq!(nodes[0].node_id, Uuid::from_u128(0));
        assert_eq!(nodes[1].node_id, Uuid::from_u128(1));
        assert_eq!(nodes[2].node_id, Uuid::from_u128(2));
    }

    #[test]
    fn empty_node_page_returns_limits() {
        let page = empty_node_page(25, 50);
        assert_eq!(page.limit, 25);
        assert_eq!(page.offset, 50);
        assert!(page.items.is_empty());
    }

    #[test]
    fn display_node_page_outputs_json() {
        let page = Page {
            limit: 1,
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
        let configs = HashMap::new();
        assert!(display_node_page(&page, &configs, OutputMode::Json, false, false, false).is_ok());
    }

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

    #[tokio::test]
    async fn fetch_nodes_page_rejects_invalid_limit() {
        let api = OperatorApi::new(
            reqwest::Client::new(),
            "http://127.0.0.1:9",
            "authorization",
            "token",
        );
        let err = fetch_nodes_page(&api, 0, 0, None).await.unwrap_err();
        assert!(err.to_string().contains("limit must be between"));
    }

    #[tokio::test]
    async fn list_nodes_fetches_and_displays_page() {
        let page = Page {
            limit: 10,
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
        let body = serde_json::to_string(&page).expect("serialize");
        let addr = spawn_json_server(body);
        let api = OperatorApi::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let args = NodeListArgs {
            limit: 10,
            offset: 0,
            status: None,
            output: crate::args::OutputFormatArgs {
                json: false,
                yaml: false,
            },
            wide: false,
        };
        list_nodes(&api, args).await.expect("list");
    }

    #[test]
    fn display_node_page_outputs_yaml() {
        let page = Page {
            limit: 1,
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
        let configs = HashMap::new();
        assert!(display_node_page(&page, &configs, OutputMode::Yaml, false, false, false).is_ok());
    }
}
