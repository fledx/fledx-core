use chrono::{TimeZone, Utc};
use common::api::{
    ConfigEntry, ConfigFile, ConfigMetadata, ConfigResponse, ConfigSummary, ConfigSummaryPage,
    DeploymentStatus, DeploymentSummary, DesiredState, NodeStatus, NodeSummary, Page,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use uuid::Uuid;

#[test]
fn configs_list_json_includes_pagination_and_items() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let seen = Arc::new(Mutex::new(String::new()));
    let seen_clone = seen.clone();

    let ts = Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap();
    let page = ConfigSummaryPage {
        limit: 5,
        offset: 2,
        items: vec![
            ConfigSummary {
                metadata: ConfigMetadata {
                    config_id: Uuid::new_v4(),
                    name: "alpha".into(),
                    version: 1,
                    created_at: ts,
                    updated_at: ts,
                },
                entry_count: 1,
                file_count: 0,
            },
            ConfigSummary {
                metadata: ConfigMetadata {
                    config_id: Uuid::new_v4(),
                    name: "beta".into(),
                    version: 2,
                    created_at: ts,
                    updated_at: ts,
                },
                entry_count: 0,
                file_count: 2,
            },
        ],
    };
    let body = serde_json::to_string(&page).expect("serialize page");

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            *seen_clone.lock().expect("seen lock") = request.clone();

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_CLI_OPERATOR_TOKEN", "token")
        .args(["configs", "list", "--limit", "5", "--offset", "2", "--json"])
        .output()
        .expect("run cli");

    server.join().expect("server thread");

    assert!(output.status.success(), "cli should succeed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(json["limit"], 5);
    assert_eq!(json["offset"], 2);
    assert_eq!(json["items"].as_array().map(|a| a.len()), Some(2));
    assert!(json.to_string().contains("alpha"));
    assert!(json.to_string().contains("beta"));

    let captured = seen.lock().expect("seen lock").to_lowercase();
    assert!(
        captured.starts_with("get /api/v1/configs?limit=5&offset=2 "),
        "unexpected request path: {captured}"
    );
}

#[test]
fn configs_show_outputs_entries_and_attachments_in_table() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    let config_id = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let node_id = Uuid::new_v4();
    let ts = Utc.with_ymd_and_hms(2025, 4, 1, 6, 0, 0).unwrap();

    let config = ConfigResponse {
        metadata: ConfigMetadata {
            config_id,
            name: "app-config".into(),
            version: 5,
            created_at: ts,
            updated_at: ts,
        },
        entries: vec![ConfigEntry {
            key: "API_URL".into(),
            value: Some("https://example.test".into()),
            secret_ref: None,
        }],
        files: vec![ConfigFile {
            path: "/etc/app/config.yaml".into(),
            file_ref: "config-ref".into(),
        }],
        attached_deployments: vec![deployment_id],
        attached_nodes: vec![node_id],
    };
    let body = serde_json::to_string(&config).expect("serialize config");

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_lowercase();
            assert!(request.starts_with("get /api/v1/configs/"));

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_CLI_OPERATOR_TOKEN", "token")
        .args(["configs", "show", "--id", &config_id.to_string()])
        .output()
        .expect("run cli");

    server.join().expect("server thread");

    assert!(output.status.success(), "cli should succeed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let node_short = &node_id.simple().to_string()[..8];
    let deploy_short = &deployment_id.simple().to_string()[..8];
    assert!(stdout.contains("config_id:"));
    assert!(stdout.contains("entries:"));
    assert!(stdout.contains("files:"));
    assert!(stdout.contains(node_short));
    assert!(stdout.contains(deploy_short));
    assert!(stdout.contains("API_URL = https://example.test"));
    assert!(stdout.contains("/etc/app/config.yaml -> config-ref"));
}

#[test]
fn configs_show_outputs_json_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    let config_id = Uuid::new_v4();
    let ts = Utc.with_ymd_and_hms(2025, 4, 1, 6, 0, 0).unwrap();

    let config = ConfigResponse {
        metadata: ConfigMetadata {
            config_id,
            name: "json-config".into(),
            version: 2,
            created_at: ts,
            updated_at: ts,
        },
        entries: vec![ConfigEntry {
            key: "FOO".into(),
            value: Some("bar".into()),
            secret_ref: None,
        }],
        files: Vec::new(),
        attached_deployments: Vec::new(),
        attached_nodes: Vec::new(),
    };
    let body = serde_json::to_string(&config).expect("serialize config");

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_lowercase();
            assert!(request.starts_with("get /api/v1/configs/"));

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_CLI_OPERATOR_TOKEN", "token")
        .args(["configs", "show", "--id", &config_id.to_string(), "--json"])
        .output()
        .expect("run cli");

    server.join().expect("server thread");

    assert!(output.status.success(), "cli should succeed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: ConfigResponse = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(parsed.metadata.config_id, config_id);
    assert_eq!(parsed.metadata.name, "json-config");
    assert_eq!(parsed.entries[0].key, "FOO");
}

fn spawn_status_server(
    node_page: Page<NodeSummary>,
    deployment_page: Page<DeploymentSummary>,
    config_page: ConfigSummaryPage,
    config_details: Vec<ConfigResponse>,
) -> (
    std::net::SocketAddr,
    thread::JoinHandle<()>,
    Arc<Mutex<Vec<String>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_clone = seen.clone();

    let handle = thread::spawn(move || {
        for _ in 0..(3 + config_details.len()) {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = request
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            seen_clone.lock().expect("seen lock").push(path.clone());

            let body = if path.starts_with("/api/v1/nodes") {
                serde_json::to_string(&node_page).expect("serialize nodes")
            } else if path.starts_with("/api/v1/deployments") {
                serde_json::to_string(&deployment_page).expect("serialize deployments")
            } else if path.starts_with("/api/v1/configs?") {
                serde_json::to_string(&config_page).expect("serialize configs page")
            } else if let Some(id_str) = path.strip_prefix("/api/v1/configs/") {
                let parsed_id = id_str.split('?').next().unwrap_or("");
                let target = Uuid::parse_str(parsed_id).expect("parse config id");
                let cfg = config_details
                    .iter()
                    .find(|c| c.metadata.config_id == target)
                    .expect("config detail");
                serde_json::to_string(cfg).expect("serialize config detail")
            } else {
                "{}".to_string()
            };

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });

    (addr, handle, seen)
}

#[test]
fn status_command_shows_attached_configs_in_table() {
    let node_id = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let node_config_id = Uuid::new_v4();
    let deploy_config_id = Uuid::new_v4();
    let ts = Utc.with_ymd_and_hms(2025, 5, 5, 12, 0, 0).unwrap();

    let node_page = Page {
        limit: 1,
        offset: 0,
        items: vec![NodeSummary {
            node_id,
            name: Some("edge-1".into()),
            status: NodeStatus::Ready,
            last_seen: Some(ts),
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
        }],
    };

    let deployment_page = Page {
        limit: 1,
        offset: 0,
        items: vec![DeploymentSummary {
            deployment_id,
            name: "api".into(),
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
            last_reported: Some(ts),
        }],
    };

    let config_page = ConfigSummaryPage {
        limit: 100,
        offset: 0,
        items: vec![
            ConfigSummary {
                metadata: ConfigMetadata {
                    config_id: node_config_id,
                    name: "edge-config".into(),
                    version: 2,
                    created_at: ts,
                    updated_at: ts,
                },
                entry_count: 1,
                file_count: 0,
            },
            ConfigSummary {
                metadata: ConfigMetadata {
                    config_id: deploy_config_id,
                    name: "deploy-config".into(),
                    version: 3,
                    created_at: ts,
                    updated_at: ts,
                },
                entry_count: 0,
                file_count: 1,
            },
        ],
    };

    let config_details = vec![
        ConfigResponse {
            metadata: config_page.items[0].metadata.clone(),
            entries: Vec::new(),
            files: Vec::new(),
            attached_deployments: Vec::new(),
            attached_nodes: vec![node_id],
        },
        ConfigResponse {
            metadata: config_page.items[1].metadata.clone(),
            entries: Vec::new(),
            files: Vec::new(),
            attached_deployments: vec![deployment_id],
            attached_nodes: Vec::new(),
        },
    ];

    let (addr, handle, _seen) =
        spawn_status_server(node_page, deployment_page, config_page, config_details);

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_CLI_OPERATOR_TOKEN", "token")
        .args(["status", "--node-limit", "1", "--deploy-limit", "1"])
        .output()
        .expect("run cli");

    handle.join().expect("server thread");

    assert!(output.status.success(), "cli should succeed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("edge-config@v2"));
    assert!(stdout.contains(&node_config_id.simple().to_string()[..8]));
    assert!(stdout.contains("deploy-config@v3"));
    assert!(stdout.contains(&deploy_config_id.simple().to_string()[..8]));
    assert!(stdout.contains("Nodes: ready=1"));
    assert!(stdout.contains("Deployments: running=1"));
}

#[test]
fn status_command_outputs_json_with_config_attachments() {
    let node_id = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let config_id = Uuid::new_v4();
    let ts = Utc.with_ymd_and_hms(2025, 5, 6, 12, 0, 0).unwrap();

    let node_page = Page {
        limit: 1,
        offset: 0,
        items: vec![NodeSummary {
            node_id,
            name: None,
            status: NodeStatus::Ready,
            last_seen: Some(ts),
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
        }],
    };

    let deployment_page = Page {
        limit: 1,
        offset: 0,
        items: vec![DeploymentSummary {
            deployment_id,
            name: "api".into(),
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
            last_reported: Some(ts),
        }],
    };

    let config_page = ConfigSummaryPage {
        limit: 100,
        offset: 0,
        items: vec![ConfigSummary {
            metadata: ConfigMetadata {
                config_id,
                name: "shared".into(),
                version: 1,
                created_at: ts,
                updated_at: ts,
            },
            entry_count: 0,
            file_count: 0,
        }],
    };

    let config_details = vec![ConfigResponse {
        metadata: config_page.items[0].metadata.clone(),
        entries: Vec::new(),
        files: Vec::new(),
        attached_deployments: vec![deployment_id],
        attached_nodes: vec![node_id],
    }];

    let (addr, handle, _seen) =
        spawn_status_server(node_page, deployment_page, config_page, config_details);

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_CLI_OPERATOR_TOKEN", "token")
        .args([
            "status",
            "--node-limit",
            "1",
            "--deploy-limit",
            "1",
            "--json",
        ])
        .output()
        .expect("run cli");

    handle.join().expect("server thread");

    assert!(output.status.success(), "cli should succeed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("parse json");
    let node_configs = &json["nodes"]["items"][0]["configs"];
    let deploy_configs = &json["deployments"]["items"][0]["configs"];
    assert_eq!(node_configs.as_array().map(|a| a.len()), Some(1));
    assert_eq!(deploy_configs.as_array().map(|a| a.len()), Some(1));
    assert_eq!(node_configs[0]["config_id"], config_id.to_string());
    assert_eq!(deploy_configs[0]["config_id"], config_id.to_string());
}
