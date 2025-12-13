use chrono::{TimeZone, Utc};
use common::api::{ConfigAttachmentResponse, ConfigMetadata};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use uuid::Uuid;

fn respond_attachment(stream: &mut std::net::TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .expect("write response");
}

#[test]
fn configs_attach_deduplicates_ids_and_sends_one_request_each() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let seen_paths = Arc::new(Mutex::new(Vec::new()));
    let seen_paths_clone = seen_paths.clone();

    let config_a = Uuid::new_v4();
    let config_b = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let ts = Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap();

    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = request
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            seen_paths_clone
                .lock()
                .expect("lock paths")
                .push(path.clone());

            let target_config = if path.contains(&config_a.to_string()) {
                config_a
            } else {
                config_b
            };
            let body = serde_json::to_string(&ConfigAttachmentResponse {
                metadata: ConfigMetadata {
                    config_id: target_config,
                    name: format!("cfg-{}", &target_config.simple().to_string()[..8]),
                    version: 1,
                    created_at: ts,
                    updated_at: ts,
                },
                deployment_id: Some(deployment_id),
                node_id: None,
                attached: true,
                attached_at: Some(ts),
            })
            .expect("serialize body");
            respond_attachment(&mut stream, &body);
        }
    });

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_OPERATOR_TOKEN", "token")
        .args([
            "configs",
            "attach",
            "deployment",
            "--config-id",
            &format!("{},{},{}", config_a, config_b, config_a),
            "--deployment-id",
            &deployment_id.to_string(),
        ])
        .output()
        .expect("run cli");

    server.join().expect("server thread");

    assert!(output.status.success(), "cli should succeed: {:?}", output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "warning: ignoring duplicate --config-id values: {}",
            config_a
        )),
        "missing duplicate warning: {stderr}"
    );

    let paths = seen_paths.lock().expect("paths lock");
    assert_eq!(paths.len(), 2, "expected two HTTP requests, got {paths:?}");
    assert!(
        paths.iter().any(|p| p.contains(&config_a.to_string())),
        "missing request for config_a: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.contains(&config_b.to_string())),
        "missing request for config_b: {paths:?}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("config_id: {}", config_a)));
    assert!(stdout.contains(&format!("config_id: {}", config_b)));
}

#[test]
fn configs_detach_reports_idempotent_state() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    let config_id = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let ts = Utc.with_ymd_and_hms(2025, 2, 2, 10, 0, 0).unwrap();

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_lowercase();
            assert!(request.starts_with("delete /api/v1/configs"));

            let body = serde_json::to_string(&ConfigAttachmentResponse {
                metadata: ConfigMetadata {
                    config_id,
                    name: "app".into(),
                    version: 3,
                    created_at: ts,
                    updated_at: ts,
                },
                deployment_id: Some(deployment_id),
                node_id: None,
                attached: false,
                attached_at: Some(ts),
            })
            .expect("serialize body");
            respond_attachment(&mut stream, &body);
        }
    });

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_OPERATOR_TOKEN", "token")
        .args([
            "configs",
            "detach",
            "deployment",
            "--config-id",
            &config_id.to_string(),
            "--deployment-id",
            &deployment_id.to_string(),
        ])
        .output()
        .expect("run cli");

    server.join().expect("server thread");

    assert!(output.status.success(), "cli should succeed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("attached: false"),
        "unexpected stdout: {stdout}"
    );
    assert!(stdout.contains(&deployment_id.to_string()));
}
