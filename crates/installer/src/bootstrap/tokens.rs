use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::Context;
use rand::TryRngCore;
use serde::Deserialize;
use tokio::time::timeout as tokio_timeout;
use tokio::time::{Instant, sleep};

fn describe_timeout(timeout: Duration) -> String {
    // Keep this short and stable for CLI output.
    if timeout.as_millis().is_multiple_of(1000) {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{:.1}s", timeout.as_secs_f32())
    }
}

async fn send_with_timeout(
    req: reqwest::RequestBuilder,
    timeout: Duration,
    url: &str,
) -> anyhow::Result<reqwest::Response> {
    match tokio_timeout(timeout, req.send()).await {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(err)) => Err(err).with_context(|| format!("request failed: {url}")),
        Err(_) => anyhow::bail!(
            "request timed out after {}: {}",
            describe_timeout(timeout),
            url
        ),
    }
}

async fn read_text_with_timeout(
    res: reqwest::Response,
    timeout: Duration,
    url: &str,
) -> anyhow::Result<(reqwest::StatusCode, String)> {
    let status = res.status();
    match tokio_timeout(timeout, res.text()).await {
        Ok(Ok(body)) => Ok((status, body)),
        Ok(Err(err)) => Err(err).with_context(|| format!("failed to read response body: {url}")),
        Err(_) => anyhow::bail!(
            "reading response body timed out after {}: {}",
            describe_timeout(timeout),
            url
        ),
    }
}

pub fn generate_master_key_hex() -> String {
    let mut bytes = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut bytes).expect("os rng failure");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn generate_token_hex(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut bytes).expect("os rng failure");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn resolve_ipv4_host(value: &str) -> anyhow::Result<String> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Ok(v4.to_string()),
            IpAddr::V6(_) => {
                anyhow::bail!("IPv6 is not supported for --cp-hostname; use an IPv4 address")
            }
        };
    }

    let mut addrs = (value, 0)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve hostname '{}'", value))?;
    let ip = addrs
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            anyhow::anyhow!("hostname '{}' did not resolve to an IPv4 address", value)
        })?;
    Ok(ip.to_string())
}

pub fn extract_host_from_url(url: &str) -> anyhow::Result<String> {
    let parsed = reqwest::Url::parse(url).context("invalid control-plane URL")?;
    parsed
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("control-plane URL must include a host"))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlPlaneHealthResponse {
    pub control_plane_version: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub tunnel_statuses: Vec<ControlPlaneTunnelStatus>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlPlaneTunnelStatus {
    pub node_id: uuid::Uuid,
    pub status: String,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_heartbeat_secs: Option<u64>,
}

pub fn health_url(base_url: &str) -> String {
    format!("{}/health", base_url.trim_end_matches('/'))
}

pub async fn fetch_control_plane_version(
    client: &reqwest::Client,
    base_url: &str,
) -> anyhow::Result<String> {
    let parsed = fetch_control_plane_health(client, base_url).await?;
    let version = parsed
        .control_plane_version
        .or(parsed.version)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "control-plane health response missing version fields: {}",
                health_url(base_url)
            )
        })?;
    Ok(super::normalize_version(&version))
}

pub async fn fetch_control_plane_health(
    client: &reqwest::Client,
    base_url: &str,
) -> anyhow::Result<ControlPlaneHealthResponse> {
    let url = health_url(base_url);
    // Keep individual requests short; callers already implement a total timeout
    // by retrying and checking elapsed time.
    let request_timeout = Duration::from_secs(3);
    let body_timeout = Duration::from_secs(3);

    let res = send_with_timeout(client.get(&url), request_timeout, &url)
        .await
        .with_context(|| format!("failed to query control-plane health: {url}"))?;
    let (status, body) = read_text_with_timeout(res, body_timeout, &url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "control-plane health request failed (status {}): {}",
            status,
            body.trim()
        );
    }

    let parsed: ControlPlaneHealthResponse = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse control-plane health response: {url}"))?;
    Ok(parsed)
}

pub async fn wait_for_node_tunnel_connected(
    client: &reqwest::Client,
    base_url: &str,
    node_id: uuid::Uuid,
    timeout: Duration,
) -> anyhow::Result<()> {
    let url = health_url(base_url);
    eprintln!(
        "waiting for agent tunnel connection: node {} via {} (timeout {}s)",
        node_id,
        url,
        timeout.as_secs()
    );
    let start = Instant::now();
    let mut last_log = Instant::now();
    let mut attempt: u32 = 0;

    loop {
        attempt = attempt.saturating_add(1);
        match fetch_control_plane_health(client, base_url).await {
            Ok(health) => match health.tunnel_statuses.iter().find(|s| s.node_id == node_id) {
                Some(status) if status.status == "connected" => return Ok(()),
                Some(status) => {
                    if last_log.elapsed() >= Duration::from_secs(5) {
                        let details = status.last_error.as_deref().unwrap_or("no error reported");
                        eprintln!(
                            "agent not connected yet (attempt {attempt}): status={} last_heartbeat_secs={:?} last_error={details}",
                            status.status, status.last_heartbeat_secs
                        );
                        last_log = Instant::now();
                    }
                }
                None => {
                    if last_log.elapsed() >= Duration::from_secs(5) {
                        eprintln!(
                            "agent not connected yet (attempt {attempt}): node not present in /health tunnel_statuses"
                        );
                        last_log = Instant::now();
                    }
                }
            },
            Err(err) => {
                if last_log.elapsed() >= Duration::from_secs(5) {
                    eprintln!("agent connectivity check not ready yet (attempt {attempt}): {err}");
                    last_log = Instant::now();
                }
            }
        }

        if start.elapsed() >= timeout {
            anyhow::bail!(
                "timed out waiting for agent tunnel connection: node {node_id} via {url}"
            );
        }

        let sleep_ms = (200u64 * attempt as u64).clamp(200, 2_000);
        sleep(Duration::from_millis(sleep_ms)).await;
    }
}

pub async fn wait_for_http_ok(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    eprintln!(
        "waiting for health check: {url} (timeout {}s)",
        timeout.as_secs()
    );
    let start = Instant::now();
    let mut last_log = Instant::now();
    let mut attempt: u32 = 0;

    loop {
        attempt = attempt.saturating_add(1);
        let res = tokio_timeout(Duration::from_secs(3), client.get(url).send()).await;
        match res {
            Ok(Ok(res)) if res.status().is_success() => {
                eprintln!("health check ok (attempt {attempt}): {url}");
                return Ok(());
            }
            Ok(Ok(res)) => {
                if last_log.elapsed() >= Duration::from_secs(5) {
                    eprintln!(
                        "health check not ready yet (attempt {attempt}): status {}",
                        res.status()
                    );
                    last_log = Instant::now();
                }
            }
            Ok(Err(err)) => {
                if last_log.elapsed() >= Duration::from_secs(5) {
                    eprintln!("health check not ready yet (attempt {attempt}): {err}");
                    last_log = Instant::now();
                }
            }
            Err(_) => {
                if last_log.elapsed() >= Duration::from_secs(5) {
                    eprintln!("health check not ready yet (attempt {attempt}): request timed out");
                    last_log = Instant::now();
                }
            }
        }

        if start.elapsed() >= timeout {
            anyhow::bail!("timed out waiting for control-plane health: {url}");
        }

        let sleep_ms = (200u64 * attempt as u64).clamp(200, 2_000);
        sleep(Duration::from_millis(sleep_ms)).await;
    }
}

pub async fn register_node(
    client: &reqwest::Client,
    base: &str,
    registration_token: &str,
    input: RegisterNodeInputs<'_>,
) -> anyhow::Result<(uuid::Uuid, String, common::api::TunnelEndpoint)> {
    let RegisterNodeInputs {
        name,
        arch,
        os,
        labels,
        capacity,
        agent_version,
    } = input;

    let base = base.trim_end_matches('/');
    let url = format!("{base}/api/v1/nodes/register");
    let payload = serde_json::json!({
        "name": name,
        "arch": arch,
        "os": os,
        "labels": labels,
        "capacity": capacity,
    });

    let res = client
        .post(url)
        .header("x-agent-version", agent_version)
        .bearer_auth(registration_token)
        .json(&payload)
        .send()
        .await?;
    let res = res
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("node registration failed: {}", e))?;

    let body: common::api::RegistrationResponse = res.json().await?;
    let tunnel = body
        .tunnel
        .ok_or_else(|| anyhow::anyhow!("control-plane did not return a tunnel endpoint"))?;
    Ok((body.node_id, body.node_token, tunnel))
}

pub struct RegisterNodeInputs<'a> {
    pub name: &'a str,
    pub arch: &'a str,
    pub os: &'a str,
    pub labels: Option<HashMap<String, String>>,
    pub capacity: Option<common::api::CapacityHints>,
    pub agent_version: &'a str,
}

pub fn parse_labels(values: &[String]) -> anyhow::Result<Option<HashMap<String, String>>> {
    if values.is_empty() {
        return Ok(None);
    }

    let mut out = HashMap::new();
    for raw in values {
        let (key, value) = parse_label(raw)?;
        if out.insert(key.clone(), value).is_some() {
            anyhow::bail!("duplicate label key: {}", key);
        }
    }
    Ok(Some(out))
}

pub fn parse_label(raw: &str) -> anyhow::Result<(String, String)> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("invalid label '{}': expected KEY=VALUE", raw))?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() {
        anyhow::bail!("invalid label '{}': key is empty", raw);
    }
    if value.is_empty() {
        anyhow::bail!("invalid label '{}': value is empty", raw);
    }
    Ok((key.to_string(), value.to_string()))
}

pub fn capacity_from_args(
    cpu_millis: Option<u32>,
    memory_bytes: Option<u64>,
) -> Option<common::api::CapacityHints> {
    if cpu_millis.is_none() && memory_bytes.is_none() {
        None
    } else {
        Some(common::api::CapacityHints {
            cpu_millis,
            memory_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn parse_label_rejects_missing_separator() {
        let err = parse_label("foo").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("expected KEY=VALUE"), "{msg}");
    }

    #[test]
    fn parse_label_trims_and_parses() {
        let (key, value) = parse_label("  region = eu-west  ").expect("parse");
        assert_eq!(key, "region");
        assert_eq!(value, "eu-west");
    }

    #[test]
    fn parse_label_rejects_empty_key_or_value() {
        let err = parse_label("=value").expect_err("empty key");
        assert!(err.to_string().contains("key is empty"));

        let err = parse_label("key=").expect_err("empty value");
        assert!(err.to_string().contains("value is empty"));
    }

    #[test]
    fn parse_labels_returns_none_when_empty() {
        let labels = parse_labels(&[]).expect("empty labels");
        assert!(labels.is_none());
    }

    #[test]
    fn parse_labels_rejects_duplicate_keys() {
        let err = parse_labels(&["a=1".to_string(), "a=2".to_string()]).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("duplicate label key"), "{msg}");
    }

    #[test]
    fn describe_timeout_formats_seconds_and_fractions() {
        assert_eq!(describe_timeout(Duration::from_secs(2)), "2s");
        assert_eq!(describe_timeout(Duration::from_millis(1500)), "1.5s");
    }

    #[test]
    fn health_url_trims_trailing_slash() {
        assert_eq!(
            health_url("https://cp.example.com/"),
            "https://cp.example.com/health"
        );
        assert_eq!(
            health_url("https://cp.example.com"),
            "https://cp.example.com/health"
        );
    }

    #[test]
    fn generate_token_hex_has_expected_length() {
        let token = generate_token_hex(4);
        assert_eq!(token.len(), 8);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        let master = generate_master_key_hex();
        assert_eq!(master.len(), 64);
        assert!(master.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn resolve_ipv4_host_accepts_ipv4_and_rejects_ipv6() {
        assert_eq!(resolve_ipv4_host("127.0.0.1").unwrap(), "127.0.0.1");
        let err = resolve_ipv4_host("::1").expect_err("should reject ipv6");
        assert!(err.to_string().contains("IPv6 is not supported"));
    }

    #[test]
    fn extract_host_from_url_requires_valid_host() {
        let err = extract_host_from_url("http:///").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("invalid control-plane URL"), "{msg}");
    }

    #[test]
    fn extract_host_from_url_returns_hostname() {
        let host =
            extract_host_from_url("https://control-plane.example.com:49421/api/v1").expect("host");
        assert_eq!(host, "control-plane.example.com");
    }

    fn spawn_http_server(response: String) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        addr
    }

    #[tokio::test]
    async fn fetch_control_plane_health_rejects_non_success_status() {
        let addr = spawn_http_server(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror".to_string(),
        );
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        let err = fetch_control_plane_health(&client, &base_url)
            .await
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("status 500"), "{msg}");
        assert!(msg.contains("error"), "{msg}");
    }

    #[tokio::test]
    async fn fetch_control_plane_health_rejects_invalid_json() {
        let response =
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Type: application/json\r\n\r\nnotjson";
        let addr = spawn_http_server(response.to_string());
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        let err = fetch_control_plane_health(&client, &base_url)
            .await
            .expect_err("invalid json");
        assert!(
            err.to_string()
                .contains("failed to parse control-plane health response")
        );
    }

    #[tokio::test]
    async fn fetch_control_plane_version_prefers_control_plane_version() {
        let body = "{\"control_plane_version\":\"1.2.3\",\"tunnel_statuses\":[]}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let addr = spawn_http_server(response);
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        let version = fetch_control_plane_version(&client, &base_url)
            .await
            .expect("version");
        assert_eq!(version, "1.2.3");
    }

    #[tokio::test]
    async fn fetch_control_plane_version_falls_back_to_version() {
        let body = "{\"version\":\"2.0.1\",\"tunnel_statuses\":[]}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let addr = spawn_http_server(response);
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        let version = fetch_control_plane_version(&client, &base_url)
            .await
            .expect("version");
        assert_eq!(version, "2.0.1");
    }

    #[tokio::test]
    async fn fetch_control_plane_version_errors_when_missing_fields() {
        let body = "{\"tunnel_statuses\":[]}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let addr = spawn_http_server(response);
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        let err = fetch_control_plane_version(&client, &base_url)
            .await
            .expect_err("missing version");
        assert!(err.to_string().contains("missing version fields"));
    }

    #[tokio::test]
    async fn wait_for_http_ok_succeeds_when_healthy() {
        let addr = spawn_http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_string());
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/health");
        wait_for_http_ok(&client, &url, Duration::from_secs(1))
            .await
            .expect("wait ok");
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_http_ok_times_out() {
        let addr = spawn_http_server(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror".to_string(),
        );
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/health");
        let handle =
            tokio::spawn(
                async move { wait_for_http_ok(&client, &url, Duration::from_secs(1)).await },
            );
        tokio::time::advance(Duration::from_secs(3)).await;
        let err = handle.await.unwrap().expect_err("should timeout");
        assert!(
            err.to_string()
                .contains("timed out waiting for control-plane health")
        );
    }

    #[tokio::test]
    async fn wait_for_node_tunnel_connected_succeeds() {
        let node_id = uuid::Uuid::new_v4();
        let body = format!(
            "{{\"tunnel_statuses\":[{{\"node_id\":\"{}\",\"status\":\"connected\"}}]}}",
            node_id
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let addr = spawn_http_server(response);
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        wait_for_node_tunnel_connected(&client, &base_url, node_id, Duration::from_secs(1))
            .await
            .expect("connected");
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_node_tunnel_connected_times_out() {
        let node_id = uuid::Uuid::new_v4();
        let body = format!(
            "{{\"tunnel_statuses\":[{{\"node_id\":\"{}\",\"status\":\"connecting\"}}]}}",
            node_id
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let addr = spawn_http_server(response);
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            wait_for_node_tunnel_connected(&client, &base_url, node_id, Duration::from_secs(1))
                .await
        });
        tokio::time::advance(Duration::from_secs(3)).await;
        let err = handle.await.unwrap().expect_err("timeout");
        assert!(
            err.to_string()
                .contains("timed out waiting for agent tunnel connection")
        );
    }

    #[tokio::test]
    async fn register_node_requires_tunnel_endpoint() {
        let body = "{\"node_id\":\"00000000-0000-0000-0000-000000000042\",\"node_token\":\"t\"}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let addr = spawn_http_server(response);
        let client = reqwest::Client::new();
        let inputs = RegisterNodeInputs {
            name: "node",
            arch: "x86_64",
            os: "linux",
            labels: None,
            capacity: None,
            agent_version: "1.0.0",
        };
        let err = register_node(&client, &format!("http://{addr}"), "token", inputs)
            .await
            .expect_err("missing tunnel");
        assert!(err.to_string().contains("did not return a tunnel endpoint"));
    }
}
