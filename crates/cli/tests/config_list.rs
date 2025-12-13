use chrono::{TimeZone, Utc};
use common::api::{ConfigMetadata, ConfigSummary, ConfigSummaryPage};
use std::process::Command;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};
use uuid::Uuid;

#[test]
fn configs_list_command_renders_table_and_uses_pagination_params() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");
    let seen_request = Arc::new(Mutex::new(String::new()));
    let seen_clone = seen_request.clone();

    let id_one = Uuid::new_v4();
    let id_two = Uuid::new_v4();
    let ts = Utc
        .with_ymd_and_hms(2025, 1, 1, 12, 0, 0)
        .single()
        .expect("timestamp");
    let page = ConfigSummaryPage {
        limit: 2,
        offset: 1,
        items: vec![
            ConfigSummary {
                metadata: ConfigMetadata {
                    config_id: id_one,
                    name: "alpha".into(),
                    version: 1,
                    created_at: ts,
                    updated_at: ts,
                },
                entry_count: 2,
                file_count: 1,
            },
            ConfigSummary {
                metadata: ConfigMetadata {
                    config_id: id_two,
                    name: "bravo".into(),
                    version: 3,
                    created_at: ts,
                    updated_at: ts,
                },
                entry_count: 0,
                file_count: 0,
            },
        ],
    };
    let body = serde_json::to_string(&page).expect("serialize page");

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            *seen_clone.lock().expect("lock request") = request.clone();

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
        .env("FLEDX_CONTROL_PLANE_URL", format!("http://{}", addr))
        .env("FLEDX_OPERATOR_TOKEN", "test-token")
        .args(["configs", "list", "--limit", "2", "--offset", "1"])
        .output()
        .expect("run cli");

    server.join().expect("server thread");
    assert!(
        output.status.success(),
        "cli should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let header = lines.next().unwrap_or_default();
    let header_cols: Vec<&str> = header.split_whitespace().collect();
    assert_eq!(
        header_cols,
        vec!["ID", "NAME", "VERSION", "ENTRIES", "FILES", "UPDATED_AT"]
    );

    let id_one_short = &id_one.simple().to_string()[..8];
    let id_two_short = &id_two.simple().to_string()[..8];
    let expected_ts = ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let row_one: Vec<&str> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    assert_eq!(
        row_one,
        vec![id_one_short, "alpha", "1", "2", "1", expected_ts.as_str()]
    );

    let row_two: Vec<&str> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    assert_eq!(
        row_two,
        vec![id_two_short, "bravo", "3", "0", "0", expected_ts.as_str()]
    );

    let captured = seen_request.lock().expect("read request").to_lowercase();
    assert!(
        captured.starts_with("get /api/v1/configs?limit=2&offset=1 "),
        "unexpected request line: {captured}"
    );
    assert!(
        captured.contains("authorization: bearer test-token"),
        "auth header missing: {captured}"
    );
}
