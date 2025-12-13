use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    extract::MatchedPath,
    http::{Request, Response as HttpResponse},
};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::sync::Mutex;
use tower::{Layer, Service};

static METRICS_HANDLE: std::sync::OnceLock<PrometheusHandle> = std::sync::OnceLock::new();

pub fn init_metrics_recorder() -> PrometheusHandle {
    METRICS_HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .add_global_label("app_version", crate::version::VERSION)
                .install_recorder()
                .expect("metrics recorder already installed")
        })
        .clone()
}

pub fn record_build_info(snapshot: &crate::persistence::MigrationSnapshot) {
    let schema_version = snapshot
        .latest_applied
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string());
    let target_version = snapshot
        .latest_available
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string());

    gauge!(
        "control_plane_info",
        "version" => crate::version::VERSION,
        "git_sha" => crate::version::GIT_SHA,
        "schema_version" => schema_version.clone(),
        "schema_target_version" => target_version.clone()
    )
    .set(1.0);

    gauge!("control_plane_schema_version").set(snapshot.latest_applied.unwrap_or_default() as f64);
    gauge!("control_plane_schema_target_version")
        .set(snapshot.latest_available.unwrap_or_default() as f64);
    gauge!("control_plane_migrations_pending").set(snapshot.pending.len() as f64);
}

#[derive(Clone)]
pub struct MetricsHistory {
    inner: Arc<Mutex<MetricsHistoryInner>>,
    window: Option<Duration>,
}

struct MetricsHistoryInner {
    events: VecDeque<MetricEvent>,
}

#[derive(Clone)]
struct MetricEvent {
    timestamp: Instant,
    method: String,
    path: String,
    status: String,
}

impl MetricsHistory {
    pub fn new(window_secs: u64) -> Self {
        let window = if window_secs > 0 {
            Some(Duration::from_secs(window_secs))
        } else {
            None
        };

        Self {
            inner: Arc::new(Mutex::new(MetricsHistoryInner {
                events: VecDeque::new(),
            })),
            window,
        }
    }

    pub async fn record(&self, method: String, path: String, status: String) {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        inner.events.push_back(MetricEvent {
            timestamp: now,
            method,
            path,
            status,
        });
        Self::prune(&mut inner, self.window, now);
    }

    pub async fn aggregate(&self) -> HashMap<(String, String, String), f64> {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        Self::prune(&mut inner, self.window, now);
        let mut counts: HashMap<(String, String, String), f64> = HashMap::new();
        for event in inner.events.iter() {
            let key = (
                event.method.clone(),
                event.path.clone(),
                event.status.clone(),
            );
            *counts.entry(key).or_insert(0.0) += 1.0;
        }
        counts
    }

    fn prune(inner: &mut MetricsHistoryInner, window: Option<Duration>, now: Instant) {
        if let Some(window) = window {
            while let Some(front) = inner.events.front() {
                if now.duration_since(front.timestamp) > window {
                    inner.events.pop_front();
                } else {
                    break;
                }
            }
        }
    }
}

/// Middleware layer that records HTTP request metrics.
#[derive(Clone)]
pub struct HttpMetricsLayer {
    history: MetricsHistory,
}

impl HttpMetricsLayer {
    pub fn new(history: MetricsHistory) -> Self {
        Self { history }
    }
}

impl Default for HttpMetricsLayer {
    fn default() -> Self {
        Self {
            history: MetricsHistory::new(0),
        }
    }
}

impl<S> Layer<S> for HttpMetricsLayer {
    type Service = HttpMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpMetricsService {
            inner,
            history: self.history.clone(),
        }
    }
}

#[derive(Clone)]
pub struct HttpMetricsService<S> {
    inner: S,
    history: MetricsHistory,
}

impl<S, B, ResBody> Service<Request<B>> for HttpMetricsService<S>
where
    S: Service<Request<B>, Response = HttpResponse<ResBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let method = req.method().to_string();
        let path = req
            .extensions()
            .get::<MatchedPath>()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_else(|| req.uri().path().to_string());
        let start = Instant::now();
        let fut = self.inner.call(req);

        let history = self.history.clone();
        Box::pin(async move {
            let result = fut.await;
            let latency = start.elapsed().as_secs_f64();

            let status_label = match &result {
                Ok(response) => {
                    let status = response.status().as_u16().to_string();
                    counter!(
                        "control_plane_http_requests_total",
                        "method" => method.clone(),
                        "path" => path.clone(),
                        "status" => status.clone()
                    )
                    .increment(1);
                    histogram!(
                        "control_plane_http_request_duration_seconds",
                        "method" => method.clone(),
                        "path" => path.clone()
                    )
                    .record(latency);
                    status
                }
                Err(_) => {
                    let status = "error".to_string();
                    counter!(
                        "control_plane_http_requests_total",
                        "method" => method.clone(),
                        "path" => path.clone(),
                        "status" => status.clone()
                    )
                    .increment(1);
                    status
                }
            };

            history
                .record(method.clone(), path.clone(), status_label.clone())
                .await;

            result
        })
    }
}
