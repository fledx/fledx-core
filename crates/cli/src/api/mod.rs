use ::common::api as common_api;
use anyhow::Result;
use reqwest::{
    header::{HeaderMap, HeaderName},
    Client, RequestBuilder, Response, StatusCode,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

use crate::version;

mod session;
pub use session::{SessionTokenCache, SessionTokenConfig};

pub const CLIENT_FINGERPRINT_HEADER: &str = "x-fledx-client-fingerprint";

#[derive(Clone)]
enum OperatorAuth {
    Static(String),
    Session(Arc<SessionTokenCache>),
}

#[derive(Clone)]
pub struct OperatorApi {
    client: Client,
    base: String,
    operator_header: String,
    operator_auth: OperatorAuth,
    client_fingerprint: Option<String>,
}

impl OperatorApi {
    pub fn new(
        client: Client,
        base: impl Into<String>,
        operator_header: impl Into<String>,
        operator_token: impl Into<String>,
    ) -> Self {
        Self {
            client,
            base: base.into(),
            operator_header: operator_header.into(),
            operator_auth: OperatorAuth::Static(operator_token.into()),
            client_fingerprint: None,
        }
    }

    pub fn new_with_session(
        client: Client,
        base: impl Into<String>,
        operator_header: impl Into<String>,
        session_cache: Arc<SessionTokenCache>,
    ) -> Self {
        Self {
            client,
            base: base.into(),
            operator_header: operator_header.into(),
            operator_auth: OperatorAuth::Session(session_cache.clone()),
            client_fingerprint: Some(session_cache.client_fingerprint().to_string()),
        }
    }

    pub fn with_client_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.client_fingerprint = Some(fingerprint.into());
        self
    }

    fn url(&self, path: &str) -> String {
        let trimmed = path.trim_start_matches('/');
        format!("{}/{}", self.base.trim_end_matches('/'), trimmed)
    }

    fn apply_operator_auth_with_token(
        &self,
        req: RequestBuilder,
        token: &str,
    ) -> Result<RequestBuilder> {
        let header = HeaderName::from_bytes(self.operator_header.as_bytes()).map_err(|err| {
            anyhow::anyhow!(
                "invalid operator header name '{}': {}",
                self.operator_header,
                err
            )
        })?;
        let req = req.header(header, format!("Bearer {}", token));
        let req = if let Some(fingerprint) = &self.client_fingerprint {
            req.header(CLIENT_FINGERPRINT_HEADER, fingerprint)
        } else {
            req
        };
        Ok(req)
    }

    async fn send(&self, req: RequestBuilder) -> Result<Response> {
        let retry = req.try_clone();
        let req = self.apply_operator_auth(req).await?;
        let res = req.send().await?;
        let status = res.status();

        if matches!(self.operator_auth, OperatorAuth::Session(_))
            && (status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN)
        {
            if let OperatorAuth::Session(cache) = &self.operator_auth {
                cache.invalidate().await;
            }
            if let Some(retry) = retry {
                let req = self.apply_operator_auth(retry).await?;
                let res = req.send().await?;
                return handle_operator_response(res).await;
            }
        }

        handle_operator_response(res).await
    }

    pub async fn get<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let res = self.send(self.client.get(self.url(path))).await?;
        Ok(res.json().await?)
    }

    pub async fn get_with_query<Q, T>(&self, path: &str, query: &Q) -> Result<T>
    where
        Q: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let req = self.client.get(self.url(path)).query(query);
        let res = self.send(req).await?;
        Ok(res.json().await?)
    }

    #[cfg(test)]
    pub(crate) fn apply_auth(&self, req: RequestBuilder) -> Result<RequestBuilder> {
        match &self.operator_auth {
            OperatorAuth::Static(token) => self.apply_operator_auth_with_token(req, token),
            OperatorAuth::Session(_) => {
                Err(anyhow::anyhow!("session-auth requires async request path"))
            }
        }
    }

    async fn operator_token(&self) -> Result<String> {
        match &self.operator_auth {
            OperatorAuth::Static(token) => Ok(token.clone()),
            OperatorAuth::Session(cache) => cache.token().await,
        }
    }

    async fn apply_operator_auth(&self, req: RequestBuilder) -> Result<RequestBuilder> {
        let token = self.operator_token().await?;
        self.apply_operator_auth_with_token(req, &token)
    }

    pub async fn post_json<B, T>(&self, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let req = self.client.post(self.url(path)).json(body);
        let res = self.send(req).await?;
        Ok(res.json().await?)
    }

    pub async fn post_json_with_headers<B, T>(
        &self,
        path: &str,
        body: &B,
        headers: HeaderMap,
    ) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let req = self.client.post(self.url(path)).json(body).headers(headers);
        let res = self.send(req).await?;
        Ok(res.json().await?)
    }

    pub async fn post_empty(&self, path: &str) -> Result<Response> {
        let req = self.client.post(self.url(path));
        self.send(req).await
    }

    pub async fn patch_json<B, T>(&self, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let req = self.client.patch(self.url(path)).json(body);
        let res = self.send(req).await?;
        Ok(res.json().await?)
    }

    pub async fn put_json<B, T>(&self, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let req = self.client.put(self.url(path)).json(body);
        let res = self.send(req).await?;
        Ok(res.json().await?)
    }

    pub async fn delete<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let req = self.client.delete(self.url(path));
        let res = self.send(req).await?;
        Ok(res.json().await?)
    }

    pub async fn delete_no_body(&self, path: &str) -> Result<()> {
        let req = self.client.delete(self.url(path));
        let res = self.send(req).await?;
        let _ = res.bytes().await?;
        Ok(())
    }
}

pub async fn register_node(
    client: &Client,
    base: &str,
    registration_token: Option<&str>,
    payload: &Value,
) -> Result<common_api::RegistrationResponse> {
    let url = format!("{}/api/v1/nodes/register", base.trim_end_matches('/'));
    let mut req = client
        .post(url)
        .json(payload)
        .header("x-agent-version", version::VERSION);
    if let Some(token) = registration_token {
        req = req.bearer_auth(token);
    }
    let res = req.send().await?.error_for_status()?;
    Ok(res.json().await?)
}

async fn handle_operator_response(res: Response) -> Result<Response> {
    let status = res.status();
    if status.is_success() {
        return Ok(res);
    }

    let request_id = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = res.text().await.unwrap_or_default();
    let parsed_error = extract_error_message(&body);

    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        let hint = "Set --operator-token or FLEDX_CLI_OPERATOR_TOKEN and \
--operator-header/FLEDX_CLI_OPERATOR_HEADER if the control plane uses a custom header.";
        let hint = format!(
            "{} If requests are forbidden, ensure the operator token has the required \
role/scopes.",
            hint
        );
        let message = match parsed_error {
            Some(err) => format!("operator auth failed with {}: {} {}", status, err, hint),
            None if body.is_empty() => format!("operator auth failed with {}. {}", status, hint),
            None => format!("operator auth failed with {}: {} {}", status, body, hint),
        };
        let message = append_request_id(message, request_id);
        return Err(anyhow::anyhow!(message));
    }

    let message = render_control_plane_error(status, &body);
    Err(anyhow::anyhow!(append_request_id(message, request_id)))
}

pub(crate) fn render_control_plane_error(status: StatusCode, body: &str) -> String {
    if let Some(err) = extract_error_message(body) {
        return format!("control-plane error (status {}): {}", status, err);
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        format!("control-plane request failed with status {}", status)
    } else {
        format!("control-plane error (status {}): {}", status, trimmed)
    }
}

pub(crate) fn append_request_id(message: String, request_id: Option<String>) -> String {
    match request_id {
        Some(id) => format!("{message} [request_id={id}]"),
        None => message,
    }
}

pub(crate) fn extract_error_message(body: &str) -> Option<String> {
    if let Ok(val) = serde_json::from_str::<Value>(body) {
        if let Some(err) = val.get("error").and_then(|e| e.as_str()) {
            return Some(err.to_string());
        }
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn apply_operator_auth_sets_custom_header() {
        let api = OperatorApi::new(
            Client::new(),
            "http://example.com",
            "x-operator-token",
            "abc",
        )
        .with_client_fingerprint("host=test;user=test");
        let req = api
            .apply_auth(Client::new().post("http://example.com"))
            .unwrap();
        let built = req.build().unwrap();
        let header = built.headers().get("x-operator-token").unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer abc");
        let fingerprint = built.headers().get(CLIENT_FINGERPRINT_HEADER).unwrap();
        assert_eq!(fingerprint.to_str().unwrap(), "host=test;user=test");
    }

    #[test]
    fn apply_operator_auth_rejects_invalid_header() {
        let api = OperatorApi::new(Client::new(), "http://example.com", "bad header", "abc");
        let req = Client::new().post("http://example.com");
        let err = api.apply_auth(req).unwrap_err();
        assert!(err.to_string().contains("invalid operator header name"));
    }

    #[test]
    fn render_control_plane_error_prefers_json_payload() {
        let status = StatusCode::BAD_REQUEST;
        let body = r#"{"error":"missing field"}"#;
        let message = render_control_plane_error(status, body);
        assert!(message.contains("missing field"));
        let empty_message = render_control_plane_error(status, "");
        assert!(empty_message.contains("control-plane request failed with status"));
    }

    #[test]
    fn append_request_id_includes_value_when_present() {
        let message = append_request_id("boom".to_string(), Some("req-1".to_string()));
        assert!(message.contains("[request_id=req-1]"));
        let plain = append_request_id("boom".to_string(), None);
        assert_eq!(plain, "boom");
    }

    #[test]
    fn extract_error_message_prefers_json_error_field() {
        let body = r#"{"error":"host port conflict","code":"bad_request"}"#;
        assert_eq!(
            extract_error_message(body),
            Some("host port conflict".to_string())
        );
        assert_eq!(
            extract_error_message("plain text"),
            Some("plain text".into())
        );
        assert_eq!(extract_error_message("   "), None);
    }

    fn spawn_http_server(
        status_line: String,
        body: String,
        headers: Vec<(String, String)>,
        capture: Option<Arc<Mutex<String>>>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 4096];
                if let Ok(n) = stream.read(&mut buf) {
                    if let Some(capture) = capture {
                        let request = String::from_utf8_lossy(&buf[..n]).to_string();
                        *capture.lock().expect("lock") = request;
                    }
                }

                let mut response = String::new();
                response.push_str(&status_line);
                response.push_str("\r\ncontent-type: application/json\r\n");
                for (key, value) in &headers {
                    response.push_str(key);
                    response.push_str(": ");
                    response.push_str(value);
                    response.push_str("\r\n");
                }
                response.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
                response.push_str(&body);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        addr
    }

    #[tokio::test]
    async fn handle_operator_response_reports_auth_failures() {
        let body = r#"{"error":"bad token"}"#;
        let addr = spawn_http_server(
            "HTTP/1.1 401 Unauthorized".to_string(),
            body.to_string(),
            vec![("x-request-id".to_string(), "req-123".to_string())],
            None,
        );
        let api = OperatorApi::new(
            Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let err = api
            .get::<serde_json::Value>("/api/v1/test")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("operator auth failed with 401"), "{msg}");
        assert!(msg.contains("bad token"), "{msg}");
        assert!(msg.contains("request_id=req-123"), "{msg}");
    }

    #[tokio::test]
    async fn handle_operator_response_reports_non_auth_errors() {
        let addr = spawn_http_server(
            "HTTP/1.1 500 Internal Server Error".to_string(),
            "boom".to_string(),
            Vec::new(),
            None,
        );
        let api = OperatorApi::new(
            Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let err = api
            .get::<serde_json::Value>("/api/v1/test")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("control-plane error (status 500"), "{msg}");
        assert!(msg.contains("boom"), "{msg}");
    }

    #[tokio::test]
    async fn operator_api_supports_common_methods() {
        #[derive(serde::Deserialize)]
        struct OkResponse {
            ok: bool,
        }

        let addr = spawn_http_server(
            "HTTP/1.1 200 OK".to_string(),
            r#"{"ok":true}"#.to_string(),
            Vec::new(),
            None,
        );
        let api = OperatorApi::new(
            Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let response: OkResponse = api.get("/api/v1/check").await.expect("get");
        assert!(response.ok);

        let addr = spawn_http_server(
            "HTTP/1.1 200 OK".to_string(),
            r#"{"ok":true}"#.to_string(),
            Vec::new(),
            None,
        );
        let api = OperatorApi::new(
            Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let response: OkResponse = api
            .post_json("/api/v1/check", &json!({}))
            .await
            .expect("post");
        assert!(response.ok);

        let addr = spawn_http_server(
            "HTTP/1.1 200 OK".to_string(),
            r#"{"ok":true}"#.to_string(),
            Vec::new(),
            None,
        );
        let api = OperatorApi::new(
            Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let response: OkResponse = api
            .patch_json("/api/v1/check", &json!({"a":1}))
            .await
            .expect("patch");
        assert!(response.ok);

        let addr = spawn_http_server(
            "HTTP/1.1 200 OK".to_string(),
            r#"{"ok":true}"#.to_string(),
            Vec::new(),
            None,
        );
        let api = OperatorApi::new(
            Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let response: OkResponse = api
            .put_json("/api/v1/check", &json!({"a":1}))
            .await
            .expect("put");
        assert!(response.ok);

        let addr = spawn_http_server(
            "HTTP/1.1 200 OK".to_string(),
            r#"{"ok":true}"#.to_string(),
            Vec::new(),
            None,
        );
        let api = OperatorApi::new(
            Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        let response: OkResponse = api.delete("/api/v1/check").await.expect("delete");
        assert!(response.ok);

        let addr = spawn_http_server(
            "HTTP/1.1 204 No Content".to_string(),
            "".to_string(),
            Vec::new(),
            None,
        );
        let api = OperatorApi::new(
            Client::new(),
            format!("http://{addr}"),
            "authorization",
            "token",
        );
        api.delete_no_body("/api/v1/check")
            .await
            .expect("delete no body");
    }

    #[tokio::test]
    async fn register_node_sends_version_and_optional_token() {
        let captured = Arc::new(Mutex::new(String::new()));
        let addr = spawn_http_server(
            "HTTP/1.1 200 OK".to_string(),
            r#"{"node_id":"00000000-0000-0000-0000-000000000042","node_token":"t","control_plane_version":"1.0.0"}"#.to_string(),
            Vec::new(),
            Some(captured.clone()),
        );

        let payload = json!({"name":"node","arch":"x86_64","os":"linux"});
        let _ = register_node(
            &Client::new(),
            &format!("http://{addr}"),
            Some("reg-token"),
            &payload,
        )
        .await
        .expect("register");

        let request = captured.lock().expect("lock").to_lowercase();
        assert!(request.contains("x-agent-version"), "{request}");
        assert!(
            request.contains("authorization: bearer reg-token"),
            "{request}"
        );
    }
}
