use ::common::api as common_api;
use anyhow::Result;
use reqwest::{header::HeaderName, Client, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone)]
pub struct OperatorApi {
    client: Client,
    base: String,
    operator_header: String,
    operator_token: String,
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
            operator_token: operator_token.into(),
        }
    }

    fn url(&self, path: &str) -> String {
        let trimmed = path.trim_start_matches('/');
        format!("{}/{}", self.base.trim_end_matches('/'), trimmed)
    }

    fn apply_operator_auth(&self, req: RequestBuilder) -> Result<RequestBuilder> {
        let header = HeaderName::from_bytes(self.operator_header.as_bytes()).map_err(|err| {
            anyhow::anyhow!(
                "invalid operator header name '{}': {}",
                self.operator_header,
                err
            )
        })?;
        Ok(req.header(header, format!("Bearer {}", self.operator_token)))
    }

    async fn send(&self, req: RequestBuilder) -> Result<Response> {
        let req = self.apply_operator_auth(req)?;
        let res = req.send().await?;
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
        self.apply_operator_auth(req)
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
    let mut req = client.post(url).json(payload);
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

    #[test]
    fn apply_operator_auth_sets_custom_header() {
        let api = OperatorApi::new(
            Client::new(),
            "http://example.com",
            "x-operator-token",
            "abc",
        );
        let req = api
            .apply_auth(Client::new().post("http://example.com"))
            .unwrap();
        let built = req.build().unwrap();
        let header = built.headers().get("x-operator-token").unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer abc");
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
}
