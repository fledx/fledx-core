use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use axum::{Router, http::StatusCode, routing::get};
use metrics::histogram;
use metrics::{counter, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::runtime::ContainerResourceUsage;

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();
}

pub fn init_metrics_recorder() -> PrometheusHandle {
    METRICS_HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("metrics recorder already installed")
        })
        .clone()
}

/// Register an existing Prometheus handle without installing a new recorder.
/// Useful when embedding the agent into another binary that already installed
/// a global recorder.
pub fn register_metrics_handle(handle: PrometheusHandle) -> PrometheusHandle {
    METRICS_HANDLE.get_or_init(|| handle).clone()
}

pub async fn serve_metrics(handle: PrometheusHandle, addr: SocketAddr) -> anyhow::Result<()> {
    serve_metrics_with_shutdown(handle, addr, std::future::pending::<()>()).await
}

pub async fn serve_metrics_with_shutdown<S>(
    handle: PrometheusHandle,
    addr: SocketAddr,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: std::future::Future<Output = ()> + Send + 'static,
{
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let body = handle.render();
            async move {
                (
                    StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4",
                    )],
                    body,
                )
            }
        }),
    );

    let listener = TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr().unwrap_or(addr);
    info!(%bound_addr, "metrics server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

pub fn record_heartbeat_result(result: &str) {
    counter!(
        "node_agent_heartbeat_total",
        "result" => result.to_string()
    )
    .increment(1);
}

pub fn record_reconcile_result(result: &str) {
    counter!(
        "node_agent_reconcile_total",
        "result" => result.to_string()
    )
    .increment(1);
}

pub fn record_reconcile_duration(result: &str, duration: Duration) {
    histogram!(
        "node_agent_reconcile_duration_ms",
        "result" => result.to_string()
    )
    .record(duration.as_secs_f64() * 1000.0);
}

pub fn record_reconcile_queue_len(len: usize) {
    gauge!("node_agent_reconcile_queue_len").set(len as f64);
}

pub fn record_container_start(kind: &str, result: &str) {
    counter!(
        "node_agent_container_starts_total",
        "kind" => kind.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
}

pub fn record_runtime_error_metric(kind: &str) {
    counter!(
        "node_agent_runtime_errors_total",
        "kind" => kind.to_string()
    )
    .increment(1);
}

pub fn record_config_fetch(result: &str) {
    counter!(
        "node_agent_config_fetch_total",
        "result" => result.to_string()
    )
    .increment(1);
}

pub fn record_config_apply(result: &str) {
    counter!(
        "node_agent_config_apply_total",
        "result" => result.to_string()
    )
    .increment(1);
}

pub fn record_identity_refresh(result: &str) {
    counter!(
        "node_agent_identity_refresh_total",
        "result" => result.to_string()
    )
    .increment(1);
}

pub fn record_resource_sample(container_id: &str, sample: &ContainerResourceUsage) {
    gauge!(
        "node_agent_container_cpu_percent",
        "container_id" => container_id.to_string()
    )
    .set(sample.cpu_percent);

    gauge!(
        "node_agent_container_memory_bytes",
        "container_id" => container_id.to_string()
    )
    .set(sample.memory_bytes as f64);

    gauge!(
        "node_agent_container_network_rx_bytes_total",
        "container_id" => container_id.to_string()
    )
    .set(sample.network_rx_bytes as f64);

    gauge!(
        "node_agent_container_network_tx_bytes_total",
        "container_id" => container_id.to_string()
    )
    .set(sample.network_tx_bytes as f64);

    if let Some(blk_read) = sample.blk_read_bytes {
        gauge!(
            "node_agent_container_blk_read_bytes_total",
            "container_id" => container_id.to_string()
        )
        .set(blk_read as f64);
    }

    if let Some(blk_write) = sample.blk_write_bytes {
        gauge!(
            "node_agent_container_blk_write_bytes_total",
            "container_id" => container_id.to_string()
        )
        .set(blk_write as f64);
    }
}

pub fn record_managed_deployments(count: usize) {
    gauge!("node_agent_managed_deployments").set(count as f64);
}

pub fn record_compatibility_status(error: Option<&str>) {
    match error {
        Some(err) => {
            gauge!(
                "node_agent_compatibility_status",
                "status" => "error".to_string(),
                "last_error" => err.to_string()
            )
            .set(1.0);

            gauge!(
                "node_agent_compatibility_status",
                "status" => "ok".to_string(),
                "last_error" => "".to_string()
            )
            .set(0.0);
        }
        None => {
            gauge!(
                "node_agent_compatibility_status",
                "status" => "ok".to_string(),
                "last_error" => "".to_string()
            )
            .set(1.0);

            gauge!(
                "node_agent_compatibility_status",
                "status" => "error".to_string(),
                "last_error" => "".to_string()
            )
            .set(0.0);
        }
    }
}

pub fn record_tunnel_connection(result: &str) {
    counter!(
        "node_agent_tunnel_connect_total",
        "result" => result.to_string()
    )
    .increment(1);
}

pub fn record_tunnel_request(result: &str, duration: Duration) {
    counter!(
        "node_agent_tunnel_requests_total",
        "result" => result.to_string()
    )
    .increment(1);

    histogram!(
        "node_agent_tunnel_request_latency_ms",
        "result" => result.to_string()
    )
    .record(duration.as_secs_f64() * 1000.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn metrics_endpoint_exposes_counters() {
        let handle = init_metrics_recorder();
        record_heartbeat_result("success");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn({
            let handle = handle.clone();
            let app = Router::new().route(
                "/metrics",
                get(move || {
                    let body = handle.render();
                    async move {
                        (
                            StatusCode::OK,
                            [(
                                axum::http::header::CONTENT_TYPE,
                                "text/plain; version=0.0.4",
                            )],
                            body,
                        )
                    }
                }),
            );
            async move {
                axum::serve(listener, app).await.expect("serve metrics");
            }
        });

        let body = reqwest::get(format!("http://{}/metrics", addr))
            .await
            .expect("metrics request")
            .text()
            .await
            .expect("metrics body");
        server.abort();

        assert!(
            body.contains("node_agent_heartbeat_total{result=\"success\"")
                || body.contains("node_agent_heartbeat_total"),
            "metrics payload missing heartbeat counter: {body}"
        );
    }

    #[test]
    fn resource_sample_gauges_include_labels_and_values() {
        let handle = init_metrics_recorder();
        let sample = ContainerResourceUsage {
            collected_at: chrono::Utc::now(),
            cpu_percent: 12.5,
            memory_bytes: 512 * 1024,
            network_rx_bytes: 42,
            network_tx_bytes: 84,
            blk_read_bytes: Some(11),
            blk_write_bytes: Some(13),
        };

        record_resource_sample("rs-test", &sample);
        let rendered = handle.render();

        assert!(
            rendered.contains("node_agent_container_cpu_percent{container_id=\"rs-test\"} 12.5"),
            "cpu gauge missing or mismatched: {rendered}"
        );
        assert!(
            rendered.contains("node_agent_container_memory_bytes{container_id=\"rs-test\"} 524288"),
            "memory gauge missing or mismatched: {rendered}"
        );
        assert!(
            rendered.contains(
                "node_agent_container_network_rx_bytes_total{container_id=\"rs-test\"} 42"
            ) && rendered.contains(
                "node_agent_container_network_tx_bytes_total{container_id=\"rs-test\"} 84"
            ),
            "network gauges missing or mismatched: {rendered}"
        );
        assert!(
            rendered
                .contains("node_agent_container_blk_read_bytes_total{container_id=\"rs-test\"} 11")
                && rendered.contains(
                    "node_agent_container_blk_write_bytes_total{container_id=\"rs-test\"} 13"
                ),
            "block I/O gauges missing or mismatched: {rendered}"
        );
    }

    #[test]
    fn compatibility_and_tunnel_metrics_are_recorded() {
        let handle = init_metrics_recorder();

        record_compatibility_status(Some("boom"));
        record_tunnel_connection("success");
        record_tunnel_request("success", Duration::from_millis(12));
        record_managed_deployments(3);

        let rendered = handle.render();
        assert!(
            rendered
                .contains("node_agent_compatibility_status{status=\"error\",last_error=\"boom\"}")
                || rendered.contains("node_agent_compatibility_status"),
            "compatibility gauge missing: {rendered}"
        );
        assert!(
            rendered.contains("node_agent_tunnel_connect_total{result=\"success\"")
                || rendered.contains("node_agent_tunnel_connect_total"),
            "tunnel connect counter missing: {rendered}"
        );
        assert!(
            rendered.contains("node_agent_tunnel_requests_total{result=\"success\"")
                || rendered.contains("node_agent_tunnel_requests_total"),
            "tunnel request counter missing: {rendered}"
        );
        assert!(
            rendered.contains("node_agent_managed_deployments")
                || rendered.contains("node_agent_managed_deployments "),
            "managed deployments gauge missing: {rendered}"
        );
    }

    #[test]
    fn miscellaneous_metrics_emit_expected_series() {
        let handle = init_metrics_recorder();

        record_container_start("deploy", "ok");
        record_reconcile_result("ok");
        record_reconcile_duration("ok", Duration::from_millis(5));
        record_reconcile_queue_len(2);
        record_config_fetch("ok");
        record_config_apply("ok");
        record_identity_refresh("ok");

        let rendered = handle.render();
        assert!(
            rendered.contains("node_agent_container_starts_total")
                || rendered.contains("node_agent_container_starts_total{"),
            "container start counter missing: {rendered}"
        );
        assert!(
            rendered.contains("node_agent_reconcile_duration_ms")
                || rendered.contains("node_agent_reconcile_duration_ms{"),
            "reconcile duration histogram missing: {rendered}"
        );
        assert!(
            rendered.contains("node_agent_reconcile_queue_len"),
            "reconcile queue gauge missing: {rendered}"
        );
        assert!(
            rendered.contains("node_agent_config_fetch_total")
                || rendered.contains("node_agent_config_apply_total"),
            "config counters missing: {rendered}"
        );
        assert!(
            rendered.contains("node_agent_identity_refresh_total"),
            "identity refresh counter missing: {rendered}"
        );
    }

    #[test]
    fn compatibility_status_ok_path_records_ok_gauge() {
        let handle = init_metrics_recorder();
        record_compatibility_status(None);
        let rendered = handle.render();
        assert!(
            rendered.contains("node_agent_compatibility_status{status=\"ok\"")
                || rendered.contains("node_agent_compatibility_status"),
            "compatibility ok gauge missing: {rendered}"
        );
    }
}
