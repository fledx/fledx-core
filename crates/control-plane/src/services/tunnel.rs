use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant as StdInstant},
};

use anyhow::Context;
use base64::{engine::general_purpose, Engine as _};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Utc};
use h2::server;
use http::{
    header::{HeaderName, HeaderValue},
    Method, Response, StatusCode,
};
use metrics::{counter, histogram};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, Semaphore},
    time,
};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    persistence::{nodes as node_store, tokens as token_store},
    tokens::{hash_token, match_token, TokenMatch},
    tunnel::{ForwardResponse, TunnelCommand, TunnelRegistry},
};

const NODE_ID_HEADER: &str = "x-fledx-node-id";
const COMMAND_CHANNEL_CAPACITY: usize = 128;
const MAX_FORWARD_CONCURRENCY: usize = 32;

struct PendingForward {
    started_at: StdInstant,
    response_tx: oneshot::Sender<anyhow::Result<ForwardResponse>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
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
        headers: std::collections::HashMap<String, String>,
        #[serde(default)]
        body_b64: String,
    },
}

pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let addr: SocketAddr = format!(
        "{}:{}",
        state.tunnel.advertised_host, state.tunnel.advertised_port
    )
    .parse()
    .context("parse tunnel listen address")?;

    if state.tunnel.use_tls {
        warn!(
            %addr,
            "tunnel.use_tls is enabled but TLS termination is not implemented; listener is plaintext. Front this endpoint with TLS or set use_tls=false."
        );
    }

    let listener = TcpListener::bind(addr)
        .await
        .context("bind tunnel listener")?;
    info!(%addr, "starting tunnel listener");

    let listener_state = state.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    error!(?err, "accept failed for tunnel listener");
                    continue;
                }
            };

            let state = listener_state.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_connection(stream, state).await {
                    error!(error = ?err, "tunnel connection failed");
                }
            });
        }
    });

    Ok(())
}

async fn handle_connection(stream: tokio::net::TcpStream, state: AppState) -> anyhow::Result<()> {
    let mut h2 = server::handshake(stream).await?;

    while let Some(result) = h2.accept().await {
        let (request, mut respond) = result?;

        let start = StdInstant::now();
        let mut node_label = "unknown".to_string();
        // CONNECT requests in HTTP/2 don't include a path, only authority
        if request.method() != Method::CONNECT {
            record_connect_metrics(&node_label, "bad_method", start);
            let response = Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
            continue;
        }

        let token_header =
            match HeaderName::from_bytes(state.tunnel.token_header.to_ascii_lowercase().as_bytes())
            {
                Ok(name) => name,
                Err(_) => {
                    record_connect_metrics(&node_label, "bad_token_header", start);
                    let response = Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(response, true);
                    continue;
                }
            };

        let node_id = match request.headers().get(NODE_ID_HEADER) {
            Some(value) => match value.to_str().ok().and_then(|s| Uuid::parse_str(s).ok()) {
                Some(id) => {
                    node_label = id.to_string();
                    id
                }
                None => {
                    record_connect_metrics(&node_label, "invalid_node_id", start);
                    let response = Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(response, true);
                    continue;
                }
            },
            None => {
                record_connect_metrics(&node_label, "missing_node_id", start);
                let response = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
        };

        let token = match request.headers().get(&token_header) {
            Some(value) => match parse_bearer(value) {
                Some(token) => token,
                None => {
                    record_connect_metrics(&node_label, "invalid_bearer", start);
                    let response = Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(response, true);
                    continue;
                }
            },
            None => {
                record_connect_metrics(&node_label, "missing_bearer", start);
                let response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
        };

        let node = match node_store::get_node(&state.db, node_id).await {
            Ok(Some(node)) => node,
            Ok(None) => {
                record_connect_metrics(&node_label, "unknown_node", start);
                let response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
            Err(err) => {
                warn!(%node_id, error=?err, "node lookup failed");
                record_connect_metrics(&node_label, "node_lookup_failed", start);
                let response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
        };

        if !verify_node_token(&state, node_id, &token, &node.token_hash).await {
            record_connect_metrics(&node_label, "unauthorized", start);
            let response = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
            continue;
        }

        let mut send_stream =
            respond.send_response(Response::builder().status(StatusCode::OK).body(())?, false)?;
        let mut recv_stream = request.into_body();

        record_connect_metrics(&node_label, "accepted", start);

        let registry = state.tunnel_registry.clone();
        let heartbeat_timeout = Duration::from_secs(state.tunnel.heartbeat_timeout_secs);
        let inflight = Arc::new(Semaphore::new(MAX_FORWARD_CONCURRENCY));
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            if let Err(err) = drive_connection(
                node_id,
                &mut send_stream,
                &mut recv_stream,
                registry,
                heartbeat_timeout,
                command_rx,
                command_tx,
                inflight,
            )
            .await
            {
                error!(%node_id, error=?err, "tunnel stream failed");
            }
        });
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drive_connection(
    node_id: Uuid,
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    registry: TunnelRegistry,
    heartbeat_timeout: Duration,
    mut command_rx: mpsc::Receiver<TunnelCommand>,
    command_tx: mpsc::Sender<TunnelCommand>,
    inflight: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let mut buffer = BytesMut::new();
    let hello_frame = read_next_frame(recv_stream, &mut buffer)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream closed before client_hello"))?;

    let heartbeat_interval = match hello_frame {
        TunnelFrame::ClientHello {
            heartbeat_interval_secs,
            ..
        } => heartbeat_interval_secs,
        other => anyhow::bail!("unexpected frame during handshake: {:?}", other),
    };

    let tunnel_id = Uuid::new_v4();
    send_frame(
        send_stream,
        TunnelFrame::ServerHello {
            tunnel_id,
            heartbeat_timeout_secs: heartbeat_timeout.as_secs(),
        },
    )
    .await?;
    registry
        .upsert(node_id, tunnel_id, command_tx, inflight)
        .await;

    let heartbeat_timer = time::sleep(heartbeat_timeout);
    tokio::pin!(heartbeat_timer);
    let mut pending: HashMap<String, PendingForward> = HashMap::new();

    loop {
        tokio::select! {
            _ = &mut heartbeat_timer => {
                registry.remove(node_id, "heartbeat_timeout").await;
                anyhow::bail!("heartbeat timeout");
            }
            frame = read_next_frame(recv_stream, &mut buffer) => {
                let Some(frame) = frame? else {
                    registry.remove(node_id, "eos").await;
                    break;
                };

            match frame {
                    TunnelFrame::Heartbeat { sent_at } => {
                        registry.touch_heartbeat(node_id).await;
                        record_heartbeat_latency(&node_id, &sent_at);
                        send_frame(send_stream, TunnelFrame::HeartbeatAck {
                            received_at: Utc::now().to_rfc3339(),
                        }).await?;
                        heartbeat_timer.as_mut().reset(time::Instant::now() + heartbeat_timeout);
                    }
                    TunnelFrame::ForwardResponse { id, status, headers, body_b64 } => {
                        if let Some(entry) = pending.remove(&id) {
                            let duration = entry.started_at.elapsed().as_secs_f64();
                            histogram!(
                                "control_plane_tunnel_forward_duration_seconds",
                                "result" => "ok"
                            ).record(duration);
                            counter!(
                                "control_plane_tunnel_forward_total",
                                "result" => "ok"
                            ).increment(1);
                            let response = ForwardResponse { id, status, headers, body_b64 };
                            let _ = entry.response_tx.send(Ok(response));
                        } else {
                            warn!(%node_id, %id, "received forward_response for unknown request");
                        }
                    }
                    other => {
                        warn!(%node_id, frame=?other, "unexpected tunnel frame");
                    }
                }
            }
            command = command_rx.recv() => {
                let Some(command) = command else {
                    registry.remove(node_id, "command_channel_closed").await;
                    break;
                };

                match command {
                    TunnelCommand::Forward { id, method, path, headers, body, started_at, response_tx } => {
                        let body_b64 = general_purpose::STANDARD.encode(body);
                        let frame = TunnelFrame::ForwardRequest {
                            id: id.clone(),
                            method,
                            path,
                            headers,
                            body_b64,
                        };

                        match send_frame(send_stream, frame).await {
                            Ok(_) => {
                                pending.insert(id, PendingForward {
                                    started_at,
                                    response_tx,
                                });
                            }
                            Err(err) => {
                                counter!(
                                    "control_plane_tunnel_forward_total",
                                    "result" => "error"
                                ).increment(1);
                                let _ = response_tx.send(Err(err));
                                registry.remove(node_id, "forward_send_failed").await;
                                anyhow::bail!("failed to send forward_request frame");
                            }
                        }
                    }
                }
            }
        }
    }

    let delay = Duration::from_secs(heartbeat_interval.max(1));
    time::sleep(delay).await;
    for (_id, entry) in pending.drain() {
        let _ = entry
            .response_tx
            .send(Err(anyhow::anyhow!("tunnel closed before response")));
    }
    registry.remove(node_id, "closed").await;
    Ok(())
}

fn parse_bearer(value: &HeaderValue) -> Option<String> {
    let raw = value.to_str().ok()?.trim();
    let prefix = "Bearer ";
    if raw.len() <= prefix.len() || !raw.starts_with(prefix) {
        return None;
    }
    Some(raw[prefix.len()..].to_string())
}

async fn verify_node_token(
    state: &AppState,
    node_id: Uuid,
    token: &str,
    fallback_hash: &str,
) -> bool {
    let active_tokens = match token_store::list_active_node_tokens(&state.db, node_id).await {
        Ok(tokens) => tokens,
        Err(err) => {
            warn!(?err, %node_id, "failed to list node tokens");
            return false;
        }
    };
    let has_any_tokens = if active_tokens.is_empty() {
        match token_store::node_tokens_exist(&state.db, node_id).await {
            Ok(exists) => exists,
            Err(err) => {
                warn!(?err, %node_id, "failed to check token existence");
                false
            }
        }
    } else {
        true
    };

    for node_token in active_tokens {
        if let Ok(Some(kind)) = match_token(token, &node_token.token_hash, &state.token_pepper) {
            if matches!(kind, TokenMatch::Legacy) {
                if let Ok(new_hash) = hash_token(token, &state.token_pepper) {
                    if let Err(err) = token_store::update_node_token_record_hash(
                        &state.db,
                        node_token.id,
                        new_hash.clone(),
                    )
                    .await
                    {
                        warn!(?err, %node_id, "failed to upgrade node token hash");
                    } else {
                        let _ =
                            node_store::update_node_token_hash(&state.db, node_id, new_hash).await;
                        info!(%node_id, "upgraded node token hash to argon2");
                    }
                }
            }
            let _ = token_store::touch_node_token_last_used(&state.db, node_token.id).await;
            return true;
        }
    }

    if has_any_tokens {
        return false;
    }

    if fallback_hash.is_empty() {
        return false;
    }

    let Ok(Some(kind)) = match_token(token, fallback_hash, &state.token_pepper) else {
        return false;
    };

    let stored_hash = if matches!(kind, TokenMatch::Legacy) {
        match hash_token(token, &state.token_pepper) {
            Ok(hash) => hash,
            Err(err) => {
                warn!(?err, %node_id, "failed to hash fallback token");
                return false;
            }
        }
    } else {
        fallback_hash.to_string()
    };

    match token_store::create_node_token(&state.db, node_id, stored_hash.clone(), None).await {
        Ok(record) => {
            let _ = token_store::touch_node_token_last_used(&state.db, record.id).await;
        }
        Err(err) => {
            warn!(?err, %node_id, "failed to persist node token record");
        }
    }
    let _ = node_store::update_node_token_hash(&state.db, node_id, stored_hash.clone()).await;
    if matches!(kind, TokenMatch::Legacy) {
        info!(%node_id, "upgraded node token hash to argon2");
    }
    true
}

async fn send_frame(
    send_stream: &mut h2::SendStream<Bytes>,
    frame: TunnelFrame,
) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(&frame).context("serialize tunnel frame")?;
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    buf.put_u32(payload.len() as u32);
    buf.extend_from_slice(&payload);
    send_stream
        .send_data(buf.freeze(), false)
        .context("send tunnel frame")?;
    Ok(())
}

async fn read_next_frame(
    recv: &mut h2::RecvStream,
    buffer: &mut BytesMut,
) -> anyhow::Result<Option<TunnelFrame>> {
    loop {
        if let Some(frame) = try_parse_frame(buffer)? {
            return Ok(Some(frame));
        }

        match recv.data().await {
            Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
            Some(Err(err)) => return Err(anyhow::anyhow!(err)),
            None => {
                if buffer.is_empty() {
                    return Ok(None);
                } else {
                    return Err(anyhow::anyhow!("stream ended mid-frame"));
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

fn record_connect_metrics(node_id: &str, result: &str, start: StdInstant) {
    let node = if node_id.is_empty() {
        "unknown"
    } else {
        node_id
    };
    counter!(
        "control_plane_tunnel_connect_total",
        "result" => result.to_string(),
        "node_id" => node.to_string(),
    )
    .increment(1);
    histogram!(
        "control_plane_tunnel_connect_duration_seconds",
        "result" => result.to_string(),
        "node_id" => node.to_string(),
    )
    .record(start.elapsed().as_secs_f64());
}

fn record_heartbeat_latency(node_id: &Uuid, sent_at: &str) {
    match DateTime::parse_from_rfc3339(sent_at) {
        Ok(sent) => {
            let latency_secs = (Utc::now() - sent.with_timezone(&Utc))
                .num_milliseconds()
                .max(0) as f64
                / 1000.0;
            histogram!(
                "control_plane_tunnel_heartbeat_rtt_seconds",
                "node_id" => node_id.to_string()
            )
            .record(latency_secs);
            counter!(
                "control_plane_tunnel_heartbeat_total",
                "node_id" => node_id.to_string(),
                "result" => "ok"
            )
            .increment(1);
        }
        Err(_) => {
            counter!(
                "control_plane_tunnel_heartbeat_total",
                "node_id" => node_id.to_string(),
                "result" => "parse_error"
            )
            .increment(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn framed_payload(frame: &TunnelFrame) -> BytesMut {
        let payload = serde_json::to_vec(frame).expect("serialize frame");
        let mut buffer = BytesMut::with_capacity(4 + payload.len());
        buffer.put_u32(payload.len() as u32);
        buffer.extend_from_slice(&payload);
        buffer
    }

    #[test]
    fn parse_bearer_extracts_token() {
        let value = HeaderValue::from_str("Bearer abc123").expect("header");
        assert_eq!(parse_bearer(&value).as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_bearer_rejects_missing_prefix() {
        let value = HeaderValue::from_str("Token abc123").expect("header");
        assert_eq!(parse_bearer(&value), None);
    }

    #[test]
    fn try_parse_frame_returns_none_for_short_buffer() {
        let mut buffer = BytesMut::from(&[0x00, 0x01][..]);
        assert!(try_parse_frame(&mut buffer).unwrap().is_none());
    }

    #[test]
    fn try_parse_frame_returns_none_for_partial_payload() {
        let mut buffer = BytesMut::from(&[0x00, 0x00, 0x00, 0x05][..]);
        assert!(try_parse_frame(&mut buffer).unwrap().is_none());
        assert_eq!(buffer.len(), 4);
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
    fn try_parse_frame_parses_frame_and_leaves_extra_bytes() {
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
    fn record_connect_metrics_handles_empty_node_id() {
        record_connect_metrics("", "ok", StdInstant::now());
    }

    #[test]
    fn record_heartbeat_latency_tracks_success_and_parse_error() {
        let node_id = Uuid::new_v4();
        record_heartbeat_latency(&node_id, &Utc::now().to_rfc3339());
        record_heartbeat_latency(&node_id, "not-a-timestamp");
    }
}
