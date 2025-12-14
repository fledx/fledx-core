use chrono::{TimeZone, Utc};
use common::api::{ConfigCreateRequest, ConfigEntry, ConfigFile, ConfigMetadata, ConfigResponse};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn configs_create_accepts_env_file_and_inline_vars() {
    let env_dir = tempdir().expect("tempdir");
    let env_path = env_dir.path().join("config.env");
    fs::write(
        &env_path,
        "API_URL=https://example.test\n# comment\nexport LOG_LEVEL=debug\n",
    )
    .expect("write env file");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let seen_request = Arc::new(Mutex::new(String::new()));
    let seen_body = Arc::new(Mutex::new(String::new()));
    let seen_request_clone = seen_request.clone();
    let seen_body_clone = seen_body.clone();

    let config_id = Uuid::new_v4();
    let ts = Utc
        .with_ymd_and_hms(2025, 1, 1, 12, 0, 0)
        .single()
        .expect("timestamp");
    let response = ConfigResponse {
        metadata: ConfigMetadata {
            config_id,
            name: "app".into(),
            version: 1,
            created_at: ts,
            updated_at: ts,
        },
        entries: vec![
            ConfigEntry {
                key: "API_URL".into(),
                value: Some("https://example.test".into()),
                secret_ref: None,
            },
            ConfigEntry {
                key: "LOG_LEVEL".into(),
                value: Some("debug".into()),
                secret_ref: None,
            },
            ConfigEntry {
                key: "INLINE".into(),
                value: Some("yes".into()),
                secret_ref: None,
            },
        ],
        files: vec![ConfigFile {
            path: "/etc/app/config.yaml".into(),
            file_ref: "config-ref".into(),
        }],
        attached_deployments: Vec::new(),
        attached_nodes: Vec::new(),
    };
    let body = serde_json::to_string(&response).expect("serialize response");

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            *seen_request_clone.lock().expect("lock request") = request.clone();

            if let Some((_, body_part)) = request.split_once("\r\n\r\n") {
                *seen_body_clone.lock().expect("lock body") = body_part.to_string();
            }

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

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_CLI_OPERATOR_TOKEN", "test-token")
        .args([
            "configs",
            "create",
            "--name",
            "app",
            "--var",
            "INLINE=yes",
            "--from-env-file",
            env_path.to_str().expect("utf8 path"),
            "--file",
            "/etc/app/config.yaml=config-ref",
        ])
        .output()
        .expect("run cli");

    server.join().expect("server thread");

    assert!(output.status.success(), "cli should succeed: {:?}", output);

    let captured_body = seen_body.lock().expect("body lock").clone();
    let request: ConfigCreateRequest =
        serde_json::from_str(captured_body.trim()).expect("parse create request");

    assert_eq!(request.name, "app");
    let mut entries: HashMap<String, Option<String>> = HashMap::new();
    for entry in request.entries {
        assert!(entry.secret_ref.is_none());
        entries.insert(entry.key, entry.value);
    }

    assert_eq!(
        entries.get("API_URL"),
        Some(&Some("https://example.test".into()))
    );
    assert_eq!(entries.get("LOG_LEVEL"), Some(&Some("debug".into())));
    assert_eq!(entries.get("INLINE"), Some(&Some("yes".into())));

    assert_eq!(request.files.len(), 1);
    assert_eq!(request.files[0].path, "/etc/app/config.yaml");
    assert_eq!(request.files[0].file_ref, "config-ref");

    let request_line = seen_request.lock().expect("req lock").to_lowercase();
    assert!(
        request_line.starts_with("post /api/v1/configs"),
        "unexpected request: {request_line}"
    );
    assert!(request_line.contains("authorization: bearer test-token"));
}

#[test]
fn configs_create_rejects_mixed_plain_and_secret_entries() {
    let env_dir = tempdir().expect("tempdir");
    let env_path = env_dir.path().join("config.env");
    fs::write(&env_path, "FOO=bar\n").expect("write env file");

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", "http://127.0.0.1:9")
        .env("FLEDX_CLI_OPERATOR_TOKEN", "token")
        .args([
            "configs",
            "create",
            "--name",
            "bad",
            "--from-env-file",
            env_path.to_str().expect("utf8 path"),
            "--secret-entry",
            "API_TOKEN=secretref",
        ])
        .output()
        .expect("run cli");

    assert!(
        !output.status.success(),
        "cli should fail for mixed entries"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("cannot mix plaintext"),
        "unexpected stderr: {stderr}"
    );
}
