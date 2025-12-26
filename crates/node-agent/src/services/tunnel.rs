use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::Utc;
use h2::{RecvStream, SendStream};
use http::{
    Request, StatusCode, Uri,
    header::{HeaderName, HeaderValue as HttpHeaderValue},
};
use reqwest::{
    Client, Method as ReqwestMethod,
    header::{
        HeaderMap as ReqwestHeaderMap, HeaderName as ReqwestHeaderName,
        HeaderValue as ReqwestHeaderValue,
    },
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{Mutex, Semaphore, mpsc, watch},
    time,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        self, ClientConfig, RootCertStore,
        client::danger::{ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName},
    },
};
use tracing::{error, warn};
use uuid::Uuid;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{
    AGENT_BUILD_HEADER, AGENT_VERSION_HEADER,
    config::{AppConfig, TunnelRoute},
    health,
    state::{self, SharedState},
    telemetry, version,
};

const FRAME_CHANNEL_CAPACITY: usize = 128;
const MAX_CONCURRENT_FORWARD_REQUESTS: usize = 32;
const CLIENT_CAPABILITIES: &[&str] = &["forward"];

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum TunnelFrame {
    #[serde(rename = "client_hello")]
    ClientHello {
        node_id: Uuid,
        agent_version: String,
        agent_build: String,
        capabilities: Vec<String>,
        heartbeat_interval_secs: u64,
    },
    #[serde(rename = "server_hello")]
    ServerHello {
        tunnel_id: Uuid,
        heartbeat_timeout_secs: u64,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat { sent_at: String },
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck { received_at: String },
    #[serde(rename = "forward_request")]
    ForwardRequest {
        id: String,
        method: String,
        path: String,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default)]
        body_b64: String,
    },
    #[serde(rename = "forward_response")]
    ForwardResponse {
        id: String,
        status: u16,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default)]
        body_b64: String,
    },
}

struct TunnelRouteMap {
    routes: Vec<TunnelRoute>,
}

impl TunnelRouteMap {
    fn new(routes: &[TunnelRoute]) -> Self {
        let mut result: Vec<TunnelRoute> = routes.to_vec();
        result.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));
        Self { routes: result }
    }

    fn match_route(&self, path: &str) -> Option<&TunnelRoute> {
        self.routes
            .iter()
            .find(|route| path.starts_with(&route.path_prefix))
    }
}

struct ForwardRequestContext {
    frame_tx: mpsc::Sender<TunnelFrame>,
    route_map: Arc<TunnelRouteMap>,
    http_client: Arc<Client>,
}

struct HeartbeatState {
    last_ack: Mutex<Instant>,
}

impl HeartbeatState {
    fn new() -> Self {
        Self {
            last_ack: Mutex::new(Instant::now()),
        }
    }
}

pub async fn tunnel_loop(
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut backoff_attempts: u32 = 0;
    loop {
        if *shutdown.borrow() {
            break;
        }

        let result = run_tunnel_once(&state, &mut shutdown).await;

        if *shutdown.borrow() {
            break;
        }

        match result {
            Ok(_) => {
                backoff_attempts = 0;
            }
            Err(err) => {
                telemetry::record_tunnel_connection("failure");
                let reason = err.to_string();
                health::report_tunnel_health(&state, false, Some(reason)).await;
                warn!(error = ?err, "tunnel service terminated, retrying");

                backoff_attempts = backoff_attempts.saturating_add(1);
                let (backoff_base, backoff_max) = {
                    let guard = state.lock().await;
                    (
                        Duration::from_millis(guard.cfg.restart_backoff_ms),
                        Duration::from_millis(guard.cfg.restart_backoff_max_ms),
                    )
                };
                let sleep_duration =
                    state::backoff_with_jitter(backoff_base, backoff_max, backoff_attempts);
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = time::sleep(sleep_duration) => {}
                }
            }
        }
    }

    Ok(())
}

async fn run_tunnel_once(
    state: &SharedState,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let cfg = { state.lock().await.cfg.clone() };
    let endpoint = state::current_tunnel_endpoint(state).await;
    let transport = connect_transport(&cfg, &endpoint).await?;
    let (mut h2_sender, connection) = h2::client::handshake(transport).await?;
    let mut connection_handle =
        tokio::spawn(async move { connection.await.map_err(|err| anyhow::anyhow!(err)) });

    let connect_request = build_connect_request(&cfg, &endpoint)?;
    let (response_future, mut send_stream) = h2_sender.send_request(connect_request, false)?;
    let response = response_future.await?;
    if response.status() != StatusCode::OK {
        return Err(anyhow!(
            "tunnel CONNECT failed with status {}",
            response.status()
        ));
    }

    let mut recv_stream = response.into_parts().1;
    let mut buffer = BytesMut::new();

    send_frame(
        &mut send_stream,
        TunnelFrame::ClientHello {
            node_id: cfg.node_id,
            agent_version: version::VERSION.to_string(),
            agent_build: version::GIT_SHA.to_string(),
            capabilities: CLIENT_CAPABILITIES
                .iter()
                .map(|&cap| cap.to_string())
                .collect(),
            heartbeat_interval_secs: endpoint.heartbeat_interval_secs,
        },
    )
    .await?;

    let handshake_frame = read_next_frame(&mut recv_stream, &mut buffer)
        .await?
        .ok_or_else(|| anyhow!("tunnel closed before server hello"))?;
    let heartbeat_timeout_secs = match handshake_frame {
        TunnelFrame::ServerHello {
            heartbeat_timeout_secs,
            ..
        } => heartbeat_timeout_secs,
        other => {
            return Err(anyhow!("unexpected frame during handshake: {:?}", other));
        }
    };

    telemetry::record_tunnel_connection("success");
    health::report_tunnel_health(state, true, None).await;

    let route_map = Arc::new(TunnelRouteMap::new(&cfg.tunnel_routes));
    let http_client = Arc::new(Client::builder().timeout(Duration::from_secs(30)).build()?);
    let request_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_FORWARD_REQUESTS));
    let heartbeat_state = Arc::new(HeartbeatState::new());
    let heartbeat_interval = Duration::from_secs(endpoint.heartbeat_interval_secs);
    let heartbeat_timeout = Duration::from_secs(heartbeat_timeout_secs);

    let (frame_tx, frame_rx) = mpsc::channel(FRAME_CHANNEL_CAPACITY);

    let request_ctx = Arc::new(ForwardRequestContext {
        frame_tx: frame_tx.clone(),
        route_map: route_map.clone(),
        http_client: http_client.clone(),
    });

    let mut reader_handle = Box::pin(tokio::spawn({
        let semaphore = request_semaphore.clone();
        let heartbeat_state = heartbeat_state.clone();
        let mut shutdown = shutdown.clone();
        let request_ctx = request_ctx.clone();
        async move {
            read_loop(
                recv_stream,
                buffer,
                request_ctx,
                semaphore,
                heartbeat_state,
                &mut shutdown,
            )
            .await
        }
    }));

    let mut writer_handle = Box::pin(tokio::spawn({
        let mut shutdown = shutdown.clone();
        async move { write_loop(send_stream, frame_rx, &mut shutdown).await }
    }));

    let mut heartbeat_handle = Box::pin(tokio::spawn({
        let frame_tx = frame_tx.clone();
        let heartbeat_state = heartbeat_state.clone();
        let mut shutdown = shutdown.clone();
        async move {
            heartbeat_loop(
                frame_tx,
                heartbeat_interval,
                heartbeat_timeout,
                heartbeat_state,
                &mut shutdown,
            )
            .await
        }
    }));

    tokio::select! {
        _ = shutdown.changed() => {
            reader_handle.abort();
            writer_handle.abort();
            heartbeat_handle.abort();
            connection_handle.abort();
            Ok(())
        }
        res = &mut reader_handle => {
            writer_handle.abort();
            heartbeat_handle.abort();
            connection_handle.abort();
            res?
        }
        res = &mut writer_handle => {
            reader_handle.abort();
            heartbeat_handle.abort();
            connection_handle.abort();
            res?
        }
        res = &mut heartbeat_handle => {
            reader_handle.abort();
            writer_handle.abort();
            connection_handle.abort();
            res?
        }
        res = &mut connection_handle => {
            reader_handle.abort();
            writer_handle.abort();
            heartbeat_handle.abort();
            res?
        }
    }
}

async fn write_loop(
    mut send_stream: SendStream<Bytes>,
    mut rx: mpsc::Receiver<TunnelFrame>,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            frame = rx.recv() => match frame {
                Some(frame) => send_frame(&mut send_stream, frame).await?,
                None => return Ok(()),
            },
        }
    }
}

async fn heartbeat_loop(
    frame_tx: mpsc::Sender<TunnelFrame>,
    interval: Duration,
    timeout: Duration,
    heartbeat_state: Arc<HeartbeatState>,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            _ = ticker.tick() => {
                let sent_at = Utc::now().to_rfc3339();
                frame_tx
                    .send(TunnelFrame::Heartbeat { sent_at })
                    .await
                    .context("failed to send heartbeat frame")?;

                let last_ack = heartbeat_state.last_ack.lock().await;
                if Instant::now().duration_since(*last_ack) > timeout {
                    return Err(anyhow!("tunnel heartbeat ack timeout"));
                }
            }
        }
    }
}

async fn read_loop(
    mut recv: h2::RecvStream,
    mut buffer: BytesMut,
    ctx: Arc<ForwardRequestContext>,
    semaphore: Arc<Semaphore>,
    heartbeat_state: Arc<HeartbeatState>,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        let frame = read_next_frame(&mut recv, &mut buffer).await?;
        let frame = match frame {
            Some(frame) => frame,
            None => return Err(anyhow!("tunnel stream closed unexpectedly")),
        };

        match frame {
            TunnelFrame::HeartbeatAck { .. } => {
                let mut guard = heartbeat_state.last_ack.lock().await;
                *guard = Instant::now();
            }
            TunnelFrame::ForwardRequest {
                id,
                method,
                path,
                headers,
                body_b64,
            } => {
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        send_error_response(
                            ctx.frame_tx.clone(),
                            id,
                            503,
                            "too many active forwarded requests".to_string(),
                        )
                        .await?;
                        continue;
                    }
                };

                let ctx_clone = ctx.clone();
                tokio::spawn({
                    let _permit = permit;
                    let ctx = ctx_clone;
                    async move {
                        if let Err(err) =
                            handle_forward_request(ctx, id, method, path, headers, body_b64).await
                        {
                            error!(error = ?err, "failed to proxy tunnel request");
                        }
                    }
                });
            }
            _ => {}
        }
    }
}

async fn handle_forward_request(
    ctx: Arc<ForwardRequestContext>,
    id: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body_b64: String,
) -> anyhow::Result<()> {
    let frame_tx = ctx.frame_tx.clone();
    let http_client = ctx.http_client.clone();
    let route = match ctx.route_map.match_route(&path) {
        Some(route) => route,
        None => {
            send_error_response(
                frame_tx.clone(),
                id,
                404,
                "no tunnel route configured".to_string(),
            )
            .await?;
            telemetry::record_tunnel_request("failure", Duration::ZERO);
            return Ok(());
        }
    };

    let method = match ReqwestMethod::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(err) => {
            send_error_response(
                frame_tx.clone(),
                id,
                400,
                format!("invalid method: {}", err),
            )
            .await?;
            telemetry::record_tunnel_request("failure", Duration::ZERO);
            return Ok(());
        }
    };

    let decoded_body = match decode_base64_body(&body_b64) {
        Ok(body) => body,
        Err(err) => {
            send_error_response(frame_tx.clone(), id, 400, err.to_string()).await?;
            telemetry::record_tunnel_request("failure", Duration::ZERO);
            return Ok(());
        }
    };

    let start = Instant::now();
    let url = format!(
        "http://{}{}",
        format_authority(&route.target_host, route.target_port),
        path
    );

    let mut request_builder = http_client.request(method, url);
    request_builder = request_builder.headers(build_header_map(&headers));

    let response = match request_builder.body(decoded_body).send().await {
        Ok(resp) => resp,
        Err(err) => {
            send_error_response(frame_tx.clone(), id, 502, err.to_string()).await?;
            telemetry::record_tunnel_request("failure", Duration::ZERO);
            return Ok(());
        }
    };

    let duration = start.elapsed();
    telemetry::record_tunnel_request("success", duration);

    let status = response.status().as_u16();
    let response_headers = flatten_headers(response.headers());
    let body_bytes = response
        .bytes()
        .await
        .context("failed to read tunneled response body")?;

    send_response(
        frame_tx.clone(),
        id,
        status,
        response_headers,
        body_bytes.to_vec(),
    )
    .await?;
    Ok(())
}

fn build_header_map(headers: &HashMap<String, String>) -> ReqwestHeaderMap {
    let mut map = ReqwestHeaderMap::new();
    for (key, value) in headers.iter() {
        if let Ok(name) = ReqwestHeaderName::from_bytes(key.to_ascii_lowercase().as_bytes())
            && let Ok(value) = ReqwestHeaderValue::from_str(value)
        {
            map.append(name, value);
        }
    }
    map
}

fn flatten_headers(map: &ReqwestHeaderMap) -> HashMap<String, String> {
    map.iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect()
}

fn decode_base64_body(body_b64: &str) -> anyhow::Result<Vec<u8>> {
    if body_b64.is_empty() {
        return Ok(Vec::new());
    }
    general_purpose::STANDARD
        .decode(body_b64)
        .map_err(|err| anyhow!("invalid base64 body: {}", err))
}

async fn send_response(
    frame_tx: mpsc::Sender<TunnelFrame>,
    id: String,
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> anyhow::Result<()> {
    let body_b64 = general_purpose::STANDARD.encode(body);
    frame_tx
        .send(TunnelFrame::ForwardResponse {
            id,
            status,
            headers,
            body_b64,
        })
        .await
        .context("failed to enqueue tunnel response frame")
}

async fn send_error_response(
    frame_tx: mpsc::Sender<TunnelFrame>,
    id: String,
    status: u16,
    message: String,
) -> anyhow::Result<()> {
    send_response(
        frame_tx,
        id,
        status,
        HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
        message.into_bytes(),
    )
    .await
}

async fn send_frame(send_stream: &mut SendStream<Bytes>, frame: TunnelFrame) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(&frame).context("serialize tunnel frame")?;
    let mut buffer = BytesMut::with_capacity(4 + payload.len());
    buffer.put_u32(payload.len() as u32);
    buffer.extend_from_slice(&payload);
    send_stream
        .send_data(buffer.freeze(), false)
        .context("failed to send tunnel frame")
}

async fn read_next_frame(
    recv: &mut RecvStream,
    buffer: &mut BytesMut,
) -> anyhow::Result<Option<TunnelFrame>> {
    loop {
        if let Some(frame) = try_parse_frame(buffer)? {
            return Ok(Some(frame));
        }

        match recv.data().await {
            Some(Ok(bytes)) => buffer.extend_from_slice(&bytes),
            Some(Err(err)) => return Err(anyhow!(err)),
            None => {
                if buffer.is_empty() {
                    return Ok(None);
                } else {
                    return Err(anyhow!("tunnel stream ended mid-frame"));
                }
            }
        }
    }
}

fn try_parse_frame(buffer: &mut BytesMut) -> anyhow::Result<Option<TunnelFrame>> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    if buffer.len() < 4 + len {
        return Ok(None);
    }

    buffer.advance(4);
    let payload = buffer.split_to(len);
    let frame = serde_json::from_slice(&payload).context("parse tunnel frame")?;
    Ok(Some(frame))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn build_tls_config(cfg: &AppConfig) -> anyhow::Result<Arc<ClientConfig>> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());

    if let Some(ca_path) = cfg.ca_cert_path.as_ref() {
        use rustls::pki_types::pem::PemObject;
        let cert_bytes = std::fs::read(ca_path).context("read tunnel ca_cert_path")?;
        let certs = CertificateDer::pem_slice_iter(&cert_bytes);
        for cert in certs {
            root_store
                .add(cert.context("parse PEM certificate")?)
                .context("add tunnel CA certificate")?;
        }
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if cfg.tls_insecure_skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));
    }

    Ok(Arc::new(config))
}

async fn connect_tls(
    _cfg: &AppConfig,
    endpoint: &crate::api::TunnelEndpoint,
    config: Arc<ClientConfig>,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    let stream = TcpStream::connect(addr)
        .await
        .context("connect to tunnel gateway")?;
    let server_name = resolve_server_name(&endpoint.host)?;
    let connector = TlsConnector::from(config);
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("tls handshake for tunnel")?;

    Ok(tls_stream)
}

async fn connect_transport(
    cfg: &AppConfig,
    endpoint: &crate::api::TunnelEndpoint,
) -> anyhow::Result<Box<dyn TunnelIo>> {
    if endpoint.use_tls {
        let tls_cfg = build_tls_config(cfg)?;
        let tls_stream = connect_tls(cfg, endpoint, tls_cfg).await?;
        Ok(Box::new(tls_stream))
    } else {
        let addr = format!("{}:{}", endpoint.host, endpoint.port);
        let stream = TcpStream::connect(addr)
            .await
            .context("connect to tunnel gateway")?;
        Ok(Box::new(stream))
    }
}

fn resolve_server_name(host: &str) -> anyhow::Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }

    ServerName::try_from(host.to_owned()).map_err(|e| anyhow!("invalid tunnel gateway host: {}", e))
}

fn build_connect_request(
    cfg: &AppConfig,
    endpoint: &crate::api::TunnelEndpoint,
) -> anyhow::Result<Request<()>> {
    let authority = format_authority(&endpoint.host, endpoint.port);
    let scheme = if endpoint.use_tls { "https" } else { "http" };
    let uri = format!("{scheme}://{}/agent-tunnel", authority)
        .parse::<Uri>()
        .context("invalid tunnel endpoint URI")?;

    let token_name = HeaderName::from_bytes(endpoint.token_header.to_ascii_lowercase().as_bytes())
        .context("invalid tunnel token header name")?;
    let token_value = HttpHeaderValue::from_str(&format!("Bearer {}", cfg.node_token))
        .context("invalid tunnel token header value")?;

    let node_id = cfg.node_id.to_string();

    Request::builder()
        .method("CONNECT")
        .uri(uri)
        .header("host", authority)
        .header(token_name, token_value)
        .header("x-fledx-node-id", node_id)
        .header(AGENT_VERSION_HEADER, version::VERSION)
        .header(AGENT_BUILD_HEADER, version::GIT_SHA)
        .body(())
        .context("build tunnel CONNECT request")
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> TunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_config;
    use base64::engine::general_purpose;
    use bytes::{Bytes, BytesMut};
    use httpmock::{Method::POST, MockServer};
    use rcgen::generate_simple_self_signed;
    use reqwest::header::HeaderValue as ReqwestHeaderValue;
    use std::sync::Once;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, watch};

    fn framed_payload(frame: &TunnelFrame) -> BytesMut {
        let payload = serde_json::to_vec(frame).expect("serialize frame");
        let mut buffer = BytesMut::with_capacity(4 + payload.len());
        buffer.put_u32(payload.len() as u32);
        buffer.extend_from_slice(&payload);
        buffer
    }

    #[test]
    fn route_map_prefers_longest_prefix() {
        let routes = vec![
            TunnelRoute {
                path_prefix: "/".to_string(),
                target_host: "root".to_string(),
                target_port: 80,
            },
            TunnelRoute {
                path_prefix: "/api".to_string(),
                target_host: "api".to_string(),
                target_port: 8080,
            },
        ];
        let map = TunnelRouteMap::new(&routes);

        let matched = map.match_route("/api/v1/users").expect("route");
        assert_eq!(matched.target_host, "api");
        assert_eq!(matched.target_port, 8080);
    }

    #[test]
    fn route_map_returns_none_when_no_match() {
        let routes = vec![TunnelRoute {
            path_prefix: "/api".to_string(),
            target_host: "api".to_string(),
            target_port: 8080,
        }];
        let map = TunnelRouteMap::new(&routes);
        assert!(map.match_route("/health").is_none());
    }

    #[test]
    fn build_header_map_filters_invalid_headers() {
        let headers = HashMap::from([
            ("x-test".to_string(), "ok".to_string()),
            ("bad header".to_string(), "no".to_string()),
            ("x-bad-value".to_string(), "line\nbreak".to_string()),
        ]);

        let map = build_header_map(&headers);
        assert_eq!(
            map.get("x-test").and_then(|v| v.to_str().ok()).unwrap(),
            "ok"
        );
        assert!(map.get("bad header").is_none());
        assert!(map.get("x-bad-value").is_none());
    }

    #[test]
    fn flatten_headers_skips_non_utf8_values() {
        let mut map = ReqwestHeaderMap::new();
        map.insert(
            "content-type",
            ReqwestHeaderValue::from_static("text/plain"),
        );
        map.insert(
            "x-binary",
            ReqwestHeaderValue::from_bytes(&[0xFF]).expect("header value"),
        );

        let flattened = flatten_headers(&map);
        assert_eq!(
            flattened.get("content-type").map(String::as_str),
            Some("text/plain")
        );
        assert!(!flattened.contains_key("x-binary"));
    }

    #[test]
    fn decode_base64_body_accepts_valid_payload() {
        let decoded = decode_base64_body("aGVsbG8=").expect("decode");
        assert_eq!(decoded, b"hello");
        assert!(decode_base64_body("").expect("empty").is_empty());
    }

    #[test]
    fn decode_base64_body_rejects_invalid_payload() {
        let err = decode_base64_body("not-base64").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("invalid base64 body"), "{msg}");
    }

    #[test]
    fn try_parse_frame_parses_and_leaves_extra_bytes() {
        let frame = TunnelFrame::Heartbeat {
            sent_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let mut buffer = framed_payload(&frame);
        buffer.extend_from_slice(b"extra");

        let parsed = try_parse_frame(&mut buffer).expect("parse");
        assert!(matches!(parsed, Some(TunnelFrame::Heartbeat { .. })));
        assert_eq!(&buffer[..], b"extra");
    }

    #[test]
    fn try_parse_frame_errors_on_invalid_json() {
        let payload = b"not-json";
        let mut buffer = BytesMut::with_capacity(4 + payload.len());
        buffer.put_u32(payload.len() as u32);
        buffer.extend_from_slice(payload);
        let err = try_parse_frame(&mut buffer).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("parse tunnel frame"), "{msg}");
    }

    #[test]
    fn format_authority_handles_ipv6_and_hostnames() {
        assert_eq!(format_authority("example.com", 443), "example.com:443");
        assert_eq!(format_authority("2001:db8::1", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn resolve_server_name_accepts_ip_and_rejects_invalid_host() {
        let ip = resolve_server_name("127.0.0.1").expect("ip");
        assert!(matches!(ip, ServerName::IpAddress(_)));

        let err = resolve_server_name("bad host").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("invalid tunnel gateway host"), "{msg}");
    }

    #[test]
    fn build_connect_request_includes_expected_headers() {
        let mut cfg = base_config();
        cfg.node_token = "token123".to_string();
        let endpoint = crate::api::TunnelEndpoint {
            host: "example.com".to_string(),
            port: 443,
            use_tls: true,
            connect_timeout_secs: 10,
            heartbeat_interval_secs: 30,
            heartbeat_timeout_secs: 90,
            token_header: "x-fledx-tunnel-token".to_string(),
        };

        let request = build_connect_request(&cfg, &endpoint).expect("request");
        assert_eq!(request.method(), "CONNECT");
        assert_eq!(
            request.uri().to_string(),
            "https://example.com:443/agent-tunnel"
        );

        let headers = request.headers();
        assert_eq!(
            headers
                .get("host")
                .and_then(|value| value.to_str().ok())
                .unwrap(),
            "example.com:443"
        );
        assert!(headers.get("x-fledx-node-id").is_some());
        assert!(headers.get(AGENT_VERSION_HEADER).is_some());
        assert!(headers.get(AGENT_BUILD_HEADER).is_some());
        assert_eq!(
            headers
                .get("x-fledx-tunnel-token")
                .and_then(|value| value.to_str().ok())
                .unwrap(),
            "Bearer token123"
        );
    }

    #[test]
    fn build_connect_request_rejects_invalid_token_header() {
        let cfg = base_config();
        let endpoint = crate::api::TunnelEndpoint {
            host: "example.com".to_string(),
            port: 443,
            use_tls: true,
            connect_timeout_secs: 10,
            heartbeat_interval_secs: 30,
            heartbeat_timeout_secs: 90,
            token_header: "bad header".to_string(),
        };

        let err = build_connect_request(&cfg, &endpoint).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("invalid tunnel token header name"), "{msg}");
    }

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn build_tls_config_accepts_custom_ca_and_insecure_flag() {
        install_crypto_provider();
        let mut cfg = base_config();
        let cert = generate_simple_self_signed(["example.com".into()]).expect("cert");
        let pem = cert.serialize_pem().expect("pem");
        let tmp = tempfile::NamedTempFile::new().expect("tmp");
        std::fs::write(tmp.path(), pem).expect("write");
        cfg.ca_cert_path = Some(tmp.path().to_string_lossy().into_owned());
        cfg.tls_insecure_skip_verify = true;

        let config = build_tls_config(&cfg).expect("tls config");
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn build_tls_config_rejects_invalid_ca() {
        install_crypto_provider();
        let mut cfg = base_config();
        let tmp = tempfile::NamedTempFile::new().expect("tmp");
        let invalid = "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n";
        std::fs::write(tmp.path(), invalid).expect("write");
        cfg.ca_cert_path = Some(tmp.path().to_string_lossy().into_owned());

        let err = build_tls_config(&cfg).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("parse PEM certificate"), "{msg}");
    }

    async fn next_response(
        rx: &mut mpsc::Receiver<TunnelFrame>,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        match rx.recv().await.expect("frame") {
            TunnelFrame::ForwardResponse {
                status,
                headers,
                body_b64,
                ..
            } => {
                let body = general_purpose::STANDARD
                    .decode(body_b64.as_bytes())
                    .expect("decode body");
                (status, headers, body)
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    fn forward_context(
        routes: Vec<TunnelRoute>,
    ) -> (Arc<ForwardRequestContext>, mpsc::Receiver<TunnelFrame>) {
        let (tx, rx) = mpsc::channel(4);
        let ctx = Arc::new(ForwardRequestContext {
            frame_tx: tx,
            route_map: Arc::new(TunnelRouteMap::new(&routes)),
            http_client: Arc::new(Client::new()),
        });
        (ctx, rx)
    }

    #[tokio::test]
    async fn handle_forward_request_returns_not_found_when_no_route() {
        let routes = vec![TunnelRoute {
            path_prefix: "/api".to_string(),
            target_host: "localhost".to_string(),
            target_port: 8080,
        }];
        let (ctx, mut rx) = forward_context(routes);

        handle_forward_request(
            ctx,
            "req-1".to_string(),
            "GET".to_string(),
            "/missing".to_string(),
            HashMap::new(),
            "".to_string(),
        )
        .await
        .expect("handler");

        let (status, _headers, body) = next_response(&mut rx).await;
        assert_eq!(status, 404);
        assert!(String::from_utf8_lossy(&body).contains("no tunnel route configured"));
    }

    #[tokio::test]
    async fn handle_forward_request_rejects_invalid_method() {
        let routes = vec![TunnelRoute {
            path_prefix: "/".to_string(),
            target_host: "localhost".to_string(),
            target_port: 8080,
        }];
        let (ctx, mut rx) = forward_context(routes);

        handle_forward_request(
            ctx,
            "req-2".to_string(),
            "BAD METHOD".to_string(),
            "/".to_string(),
            HashMap::new(),
            "".to_string(),
        )
        .await
        .expect("handler");

        let (status, _headers, body) = next_response(&mut rx).await;
        assert_eq!(status, 400);
        assert!(String::from_utf8_lossy(&body).contains("invalid method"));
    }

    #[tokio::test]
    async fn handle_forward_request_rejects_invalid_body() {
        let routes = vec![TunnelRoute {
            path_prefix: "/".to_string(),
            target_host: "localhost".to_string(),
            target_port: 8080,
        }];
        let (ctx, mut rx) = forward_context(routes);

        handle_forward_request(
            ctx,
            "req-3".to_string(),
            "GET".to_string(),
            "/".to_string(),
            HashMap::new(),
            "not-base64".to_string(),
        )
        .await
        .expect("handler");

        let (status, _headers, body) = next_response(&mut rx).await;
        assert_eq!(status, 400);
        assert!(String::from_utf8_lossy(&body).contains("invalid base64 body"));
    }

    #[tokio::test]
    async fn handle_forward_request_forwards_request_and_returns_response() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/echo")
                    .header("x-test", "1")
                    .body("payload");
                then.status(201).header("x-response", "ok").body("reply");
            })
            .await;

        let base_uri: Uri = server.url("").parse().expect("uri");
        let host = base_uri.host().expect("host").to_string();
        let port = base_uri.port_u16().expect("port");

        let routes = vec![TunnelRoute {
            path_prefix: "/".to_string(),
            target_host: host,
            target_port: port,
        }];
        let (ctx, mut rx) = forward_context(routes);
        let mut headers = HashMap::new();
        headers.insert("X-Test".to_string(), "1".to_string());

        handle_forward_request(
            ctx,
            "req-4".to_string(),
            "POST".to_string(),
            "/echo".to_string(),
            headers,
            general_purpose::STANDARD.encode("payload"),
        )
        .await
        .expect("handler");

        let (status, response_headers, body) = next_response(&mut rx).await;
        assert_eq!(status, 201);
        assert_eq!(
            response_headers.get("x-response").map(String::as_str),
            Some("ok")
        );
        assert_eq!(body, b"reply");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn connect_transport_non_tls_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let cfg = base_config();
        let endpoint = crate::api::TunnelEndpoint {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            use_tls: false,
            connect_timeout_secs: 1,
            heartbeat_interval_secs: 10,
            heartbeat_timeout_secs: 30,
            token_header: "x-token".to_string(),
        };

        let _transport = connect_transport(&cfg, &endpoint).await.expect("connect");
        accept_task.await.expect("accept task");
    }

    async fn h2_stream_pair() -> (
        SendStream<Bytes>,
        RecvStream,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let (mut client, client_conn) = h2::client::handshake(client_io).await.expect("client");
        let client_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let mut server = h2::server::handshake(server_io).await.expect("server");
        let (response_fut, send_stream) = client
            .send_request(
                Request::builder()
                    .method("CONNECT")
                    .uri("http://example")
                    .body(())
                    .expect("request"),
                false,
            )
            .expect("send request");
        let (request, mut respond) = server.accept().await.expect("accept").expect("stream");
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .expect("response");
        respond.send_response(response, false).expect("respond");
        let server_task = tokio::spawn(async move {
            while let Some(result) = server.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let _ = response_fut.await;

        (send_stream, request.into_body(), client_task, server_task)
    }

    #[tokio::test]
    async fn write_loop_sends_frames_until_channel_closes() {
        let (send_stream, mut recv_stream, client_task, server_task) = h2_stream_pair().await;
        let (tx, rx) = mpsc::channel(2);
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let writer =
            tokio::spawn(async move { write_loop(send_stream, rx, &mut shutdown_rx).await });

        tx.send(TunnelFrame::Heartbeat {
            sent_at: "2025-01-01T00:00:00Z".to_string(),
        })
        .await
        .expect("send frame");
        drop(tx);

        let mut buffer = BytesMut::new();
        let frame = read_next_frame(&mut recv_stream, &mut buffer)
            .await
            .expect("read")
            .expect("frame");
        assert!(matches!(frame, TunnelFrame::Heartbeat { .. }));

        writer.await.expect("writer").expect("writer ok");
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn heartbeat_loop_sends_and_times_out() {
        let (tx, mut rx) = mpsc::channel(2);
        let heartbeat_state = Arc::new(HeartbeatState::new());
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn({
            let heartbeat_state = heartbeat_state.clone();
            async move {
                heartbeat_loop(
                    tx,
                    Duration::from_millis(5),
                    Duration::from_secs(60),
                    heartbeat_state,
                    &mut shutdown_rx,
                )
                .await
            }
        });

        let frame = rx.recv().await.expect("frame");
        assert!(matches!(frame, TunnelFrame::Heartbeat { .. }));
        shutdown_tx.send(true).expect("shutdown");
        handle.await.expect("join").expect("ok");

        let (tx, _rx) = mpsc::channel(1);
        let heartbeat_state = Arc::new(HeartbeatState::new());
        {
            let mut guard = heartbeat_state.last_ack.lock().await;
            *guard = Instant::now() - Duration::from_secs(60);
        }
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let err = heartbeat_loop(
            tx,
            Duration::from_millis(1),
            Duration::from_millis(0),
            heartbeat_state,
            &mut shutdown_rx,
        )
        .await
        .expect_err("timeout");
        assert!(err.to_string().contains("heartbeat ack timeout"));
    }

    #[tokio::test]
    async fn read_loop_sends_busy_response_when_semaphore_exhausted() {
        let (mut send_stream, recv_stream, client_task, server_task) = h2_stream_pair().await;
        let (tx, mut rx) = mpsc::channel(1);
        let ctx = Arc::new(ForwardRequestContext {
            frame_tx: tx,
            route_map: Arc::new(TunnelRouteMap::new(&[])),
            http_client: Arc::new(Client::new()),
        });
        let semaphore = Arc::new(Semaphore::new(0));
        let heartbeat_state = Arc::new(HeartbeatState::new());
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        send_frame(
            &mut send_stream,
            TunnelFrame::ForwardRequest {
                id: "req-busy".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: HashMap::new(),
                body_b64: "".to_string(),
            },
        )
        .await
        .expect("send frame");
        send_stream.send_data(Bytes::new(), true).expect("close");

        let read_task = tokio::spawn(async move {
            read_loop(
                recv_stream,
                BytesMut::new(),
                ctx,
                semaphore,
                heartbeat_state,
                &mut shutdown_rx,
            )
            .await
        });

        let response = rx.recv().await.expect("response");
        match response {
            TunnelFrame::ForwardResponse { status, .. } => assert_eq!(status, 503),
            other => panic!("unexpected frame: {other:?}"),
        }

        let _ = read_task.await;
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn send_frame_round_trips_via_h2() {
        let (mut send_stream, mut recv_stream, client_task, server_task) = h2_stream_pair().await;
        let mut buffer = BytesMut::new();

        send_frame(
            &mut send_stream,
            TunnelFrame::Heartbeat {
                sent_at: "2025-01-01T00:00:00Z".to_string(),
            },
        )
        .await
        .expect("send frame");

        let frame = read_next_frame(&mut recv_stream, &mut buffer)
            .await
            .expect("read")
            .expect("frame");
        assert!(matches!(frame, TunnelFrame::Heartbeat { .. }));

        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn read_next_frame_parses_multiple_frames_from_buffer() {
        let (mut send_stream, mut recv_stream, client_task, server_task) = h2_stream_pair().await;
        let mut buffer = BytesMut::new();

        send_frame(
            &mut send_stream,
            TunnelFrame::Heartbeat {
                sent_at: "2025-01-01T00:00:00Z".to_string(),
            },
        )
        .await
        .expect("send frame 1");
        send_frame(
            &mut send_stream,
            TunnelFrame::HeartbeatAck {
                received_at: "2025-01-01T00:00:01Z".to_string(),
            },
        )
        .await
        .expect("send frame 2");
        send_stream.send_data(Bytes::new(), true).expect("close");

        let first = read_next_frame(&mut recv_stream, &mut buffer)
            .await
            .expect("read")
            .expect("frame");
        assert!(matches!(first, TunnelFrame::Heartbeat { .. }));

        let second = read_next_frame(&mut recv_stream, &mut buffer)
            .await
            .expect("read")
            .expect("frame");
        assert!(matches!(second, TunnelFrame::HeartbeatAck { .. }));

        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn read_next_frame_returns_none_on_clean_close() {
        let (mut send_stream, mut recv_stream, client_task, server_task) = h2_stream_pair().await;
        send_stream.send_data(Bytes::new(), true).expect("send");

        let mut buffer = BytesMut::new();
        let frame = read_next_frame(&mut recv_stream, &mut buffer)
            .await
            .expect("read");
        assert!(frame.is_none());

        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn read_next_frame_errors_on_invalid_json_payload() {
        let (mut send_stream, mut recv_stream, client_task, server_task) = h2_stream_pair().await;

        let payload = b"not-json";
        let mut buffer = BytesMut::with_capacity(4 + payload.len());
        buffer.put_u32(payload.len() as u32);
        buffer.extend_from_slice(payload);
        send_stream.send_data(buffer.freeze(), true).expect("send");

        let mut recv_buffer = BytesMut::new();
        let err = read_next_frame(&mut recv_stream, &mut recv_buffer)
            .await
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("parse tunnel frame"), "{msg}");

        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn read_next_frame_errors_on_partial_payload() {
        let (mut send_stream, mut recv_stream, client_task, server_task) = h2_stream_pair().await;
        send_stream
            .send_data(Bytes::from_static(&[0, 0, 0, 5]), true)
            .expect("send");

        let mut buffer = BytesMut::new();
        let err = read_next_frame(&mut recv_stream, &mut buffer)
            .await
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("ended mid-frame"), "{msg}");

        client_task.abort();
        server_task.abort();
    }
}
