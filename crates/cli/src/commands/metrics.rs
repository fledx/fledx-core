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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

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

    fn spawn_json_server_with_path(
        body: String,
        path_tx: mpsc::Sender<String>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_string();
                let _ = path_tx.send(path);
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
    async fn fetch_metrics_summary_rejects_invalid_limit() {
        let api = crate::api::OperatorApi::new(
            reqwest::Client::new(),
            "http://127.0.0.1:9",
            "authorization",
            "token",
        );
        let err = fetch_metrics_summary(&api, Some(0)).await.unwrap_err();
        assert!(err.to_string().contains("limit must be between"));
    }

    #[tokio::test]
    async fn show_metrics_summary_renders_table_and_json() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let summary = api::MetricsSummary {
            limit: 1,
            window_secs: 60,
            as_of: ts,
            items: vec![api::MetricSample {
                method: "GET".into(),
                path: "/health".into(),
                status: "200".into(),
                count: 12.0,
            }],
        };
        let body = serde_json::to_string(&summary).expect("serialize");
        let addr = spawn_json_server(body);
        let api = crate::api::OperatorApi::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );

        let args = MetricsShowArgs {
            limit: Some(1),
            json: false,
        };
        show_metrics_summary(&api, args)
            .await
            .expect("table output");

        let body = serde_json::to_string(&summary).expect("serialize");
        let addr = spawn_json_server(body);
        let api = crate::api::OperatorApi::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let args = MetricsShowArgs {
            limit: Some(1),
            json: true,
        };
        show_metrics_summary(&api, args).await.expect("json output");
    }

    #[tokio::test]
    async fn fetch_metrics_summary_without_limit_avoids_query_param() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let summary = api::MetricsSummary {
            limit: 25,
            window_secs: 120,
            as_of: ts,
            items: vec![api::MetricSample {
                method: "POST".into(),
                path: "/v1/push".into(),
                status: "201".into(),
                count: 1.0,
            }],
        };
        let body = serde_json::to_string(&summary).expect("serialize");
        let (tx, rx) = mpsc::channel();
        let addr = spawn_json_server_with_path(body, tx);

        let api = crate::api::OperatorApi::new(
            reqwest::Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );

        let result = fetch_metrics_summary(&api, None).await.expect("fetch");
        assert_eq!(result.limit, 25);

        let path = rx.recv_timeout(Duration::from_secs(1)).expect("request");
        assert!(path.starts_with("/api/v1/metrics/summary"));
        assert!(!path.contains("limit="), "unexpected query: {path}");
    }
}
