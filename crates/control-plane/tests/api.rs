#[path = "support/common.rs"]
mod common;

use std::{fs, time::Duration};

use ::common::api::{
    ConfigAttachmentResponse, ConfigCreateRequest, ConfigEntry, ConfigFile, ConfigResponse,
    ConfigSummaryPage, ConfigUpdateRequest, HealthProbeKind, HealthStatus,
};
use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use common::{
    agent_request, legacy_hash, register_ready_node, register_ready_node_with_ingress,
    register_ready_node_with_payload, setup_app, setup_app_with_config, setup_app_with_state,
    setup_apps, setup_apps_with_config, DeploymentCreateResponse, DeploymentStatus,
    DeploymentStatusResponse, DesiredState, DesiredStateResponse, NodeConfigResponse, NodeStatus,
    NodeStatusResponse, RegistrationResponse, TestAppConfig, TEST_OPERATOR_TOKEN, TEST_REG_TOKEN,
};
use control_plane::{
    config::{PortsConfig, ReachabilityConfig, VolumesConfig},
    persistence as db,
    persistence::{configs, deployments, logs, migrations, nodes},
    routes::{run_reachability_sweep, ReachabilityReport},
    validation,
};
use http_body_util::BodyExt;
use sqlx::Row;
use tower::ServiceExt;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs as unix_fs;

#[tokio::test]
async fn metrics_endpoint_reports_http_requests() {
    let (app, metrics_app, _db) = setup_apps().await;

    let _ = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let response = metrics_app
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(
        body.contains("control_plane_http_requests_total") && body.contains("path=\"/health\""),
        "metrics payload missing http counters: {body}"
    );
}

#[tokio::test]
async fn health_and_metrics_report_schema_versions() {
    let (app, metrics_app, _db) = setup_apps().await;
    let expected_version = migrations::latest_migration_version();
    let expected_label = expected_version
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string());

    let health = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let health_bytes = health.into_body().collect().await.unwrap().to_bytes();
    let health_json: serde_json::Value = serde_json::from_slice(&health_bytes).unwrap();
    assert_eq!(
        health_json.get("schema_version").and_then(|v| v.as_i64()),
        expected_version
    );
    assert_eq!(
        health_json
            .get("target_schema_version")
            .and_then(|v| v.as_i64()),
        expected_version
    );
    assert_eq!(
        health_json
            .get("pending_migrations")
            .and_then(|v| v.as_u64()),
        Some(0)
    );

    let metrics = metrics_app
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = metrics.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(
        body.contains("control_plane_info")
            && body.contains(&format!("schema_version=\"{}\"", expected_label))
            && body.contains("control_plane_migrations_pending{"),
        "metrics missing schema/version labels: {body}"
    );
}

#[tokio::test]
async fn migration_dry_run_executes_without_applying() {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");

    let snapshot = migrations::dry_run_migrations(&db)
        .await
        .expect("dry run succeeds");
    assert!(snapshot.latest_applied.is_none());

    let applied_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&db)
        .await
        .expect("read migrations table");
    assert_eq!(applied_count, 0);

    let outcome = migrations::run_migrations(&db)
        .await
        .expect("apply migrations");
    let applied_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&db)
        .await
        .expect("read migrations table after apply");

    assert!(applied_after > 0);
    assert!(!outcome.applied.is_empty());
}

#[tokio::test]
async fn register_node_creates_record_and_returns_token() {
    let (app, db) = setup_app().await;

    let payload = serde_json::json!({
        "name": "edge-1",
        "arch": "amd64",
        "os": "linux"
    });

    let response = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let reg: RegistrationResponse =
        serde_json::from_slice(&body_bytes).expect("parse registration response");

    assert!(!reg.node_token.is_empty());

    let node = nodes::get_node(&db, reg.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(node.name.as_deref(), Some("edge-1"));
    assert_eq!(node.arch.as_deref(), Some("amd64"));
}

#[tokio::test]
async fn registration_requires_bearer_token() {
    let (app, _) = setup_app().await;

    let payload = serde_json::json!({ "name": "unauth" });

    let response = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_node_persists_public_ingress_metadata() {
    let (app, db) = setup_app().await;

    let registration = register_ready_node_with_ingress(
        &app,
        &db,
        "edge-public",
        Some("  192.0.2.5 "),
        Some("Edge.Example.COM "),
    )
    .await;

    assert!(!registration.node_token.is_empty());

    let node = nodes::get_node(&db, registration.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(node.public_ip.as_deref(), Some("192.0.2.5"));
    assert_eq!(node.public_host.as_deref(), Some("edge.example.com"));
}

#[tokio::test]
async fn registration_rejects_overlong_name() {
    let (app, db) = setup_app().await;

    let long_name = "a".repeat(300);
    let payload = serde_json::json!({
        "name": long_name,
        "arch": "amd64",
        "os": "linux"
    });

    let response = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let nodes = nodes::list_nodes(&db).await.expect("list nodes");
    assert!(
        nodes.is_empty(),
        "no nodes should be created on validation failure"
    );
}

#[tokio::test]
async fn registration_rejects_invalid_token() {
    let (app, _) = setup_app().await;

    let payload = serde_json::json!({ "name": "bad-token" });

    let response = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", "Bearer wrong")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registration_is_rate_limited() {
    let config = TestAppConfig::default();
    let (app, _) = setup_app_with_config(config).await;

    let payload = serde_json::json!({ "name": "edge-rl-1" });
    let second = serde_json::json!({ "name": "edge-rl-2" });

    let first = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second_res = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(second.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn missing_agent_version_header_uses_fallback_and_respects_bounds() {
    let cfg = TestAppConfig {
        compat_min: Some("1.2.0".into()),
        compat_max: Some("1.2.9".into()),
        ..Default::default()
    };
    let (app, metrics_app, _db) = setup_apps_with_config(cfg).await;

    let payload = serde_json::json!({ "name": "no-agent-version" });

    let response = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .header("x-agent-build", "test-sha")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("unsupported_agent_version")
    );
    assert_eq!(
        body.get("agent_version").and_then(|v| v.as_str()),
        Some("0.0.0")
    );
    assert_eq!(
        body.get("min_supported").and_then(|v| v.as_str()),
        Some("1.2.0")
    );
    assert_eq!(
        body.get("max_supported").and_then(|v| v.as_str()),
        Some("1.2.9")
    );

    let metrics = metrics_app
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let metrics_body = metrics.into_body().collect().await.unwrap().to_bytes();
    let metrics_text = String::from_utf8_lossy(&metrics_body);
    assert!(
        metrics_text.contains("control_plane_agent_version_mismatch_total")
            && metrics_text.contains("reason=\"unsupported_version\"")
            && metrics_text.contains("app_version=\""),
        "metrics should record fallback rejection with reason unsupported_version"
    );
}

#[tokio::test]
async fn unsupported_agent_version_returns_upgrade_required() {
    let cfg = TestAppConfig {
        compat_min: Some("9.9.9".into()),
        compat_max: Some("9.9.9".into()),
        ..Default::default()
    };
    let (app, _db) = setup_app_with_config(cfg).await;

    let response = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .header("x-agent-version", "1.0.0")
                .header("x-agent-build", "test-sha")
                .body(Body::from(
                    serde_json::json!({ "name": "too-old" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("unsupported_agent_version")
    );
    assert_eq!(
        body.get("min_supported").and_then(|v| v.as_str()),
        Some("9.9.9")
    );
    assert_eq!(
        body.get("max_supported").and_then(|v| v.as_str()),
        Some("9.9.9")
    );
}

#[tokio::test]
async fn invalid_agent_version_returns_bad_request() {
    let (app, _db) = setup_app().await;

    let response = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .header("x-agent-version", "v1-not-semver")
                .header("x-agent-build", "test-sha")
                .body(Body::from(
                    serde_json::json!({ "name": "bad-version" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        body.get("agent_version").and_then(|v| v.as_str()),
        Some("v1-not-semver")
    );
}

#[tokio::test]
async fn compatibility_enforcement_can_be_disabled() {
    let cfg = TestAppConfig {
        enforce_agent_compatibility: Some(false),
        ..Default::default()
    };
    let (app, _db) = setup_app_with_config(cfg).await;

    let response = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(
                    serde_json::json!({ "name": "compat-disabled" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let headers = response.headers();
    assert!(
        headers.contains_key("x-agent-compat-min") && headers.contains_key("x-agent-compat-max"),
        "compatibility headers should still be present when enforcement disabled"
    );
}

#[tokio::test]
async fn legacy_agent_without_version_header_is_rejected() {
    let (app, _db) = setup_app().await;

    let response = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(
                    serde_json::json!({ "name": "legacy-agent-no-version" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    let headers = response.headers();
    assert!(
        headers.contains_key("x-agent-compat-min") && headers.contains_key("x-agent-compat-max"),
        "compatibility headers should be returned"
    );
}

#[tokio::test]
async fn supported_agent_version_allows_registration_and_reports_window() {
    let cfg = TestAppConfig::default().with_current_agent_compat_window();
    let (app, _db) = setup_app_with_config(cfg).await;

    let payload = serde_json::json!({ "name": "compatible-agent" });

    let response = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let health = app
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let health_bytes = health.into_body().collect().await.unwrap().to_bytes();
    let health_json: serde_json::Value = serde_json::from_slice(&health_bytes).unwrap();
    assert_eq!(
        health_json
            .get("min_supported_agent_version")
            .and_then(|v| v.as_str()),
        Some(control_plane::version::VERSION)
    );
    assert_eq!(
        health_json
            .get("max_supported_agent_version")
            .and_then(|v| v.as_str()),
        Some(control_plane::version::VERSION)
    );
}

#[tokio::test]
async fn operator_endpoints_require_auth() {
    let (app, db) = setup_app().await;

    let reg_body = serde_json::json!({ "name": "operator-protected" });
    let reg_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    let reg_bytes = reg_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&reg_bytes).unwrap();

    nodes::update_node_status(&db, reg.node_id, db::NodeStatus::Ready, Some(Utc::now()))
        .await
        .expect("mark node ready");

    let dep_body = serde_json::json!({
        "name": "needs-auth",
        "image": "nginx:alpine"
    });

    let missing_auth = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

    let bad_auth = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", "Bearer wrong-operator")
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_auth.status(), StatusCode::FORBIDDEN);

    let ok = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::CREATED);

    let node_status = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/nodes/{}", reg.node_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(node_status.status(), StatusCode::UNAUTHORIZED);

    let node_status_authed = app
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/nodes/{}", reg.node_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(node_status_authed.status(), StatusCode::OK);
}

#[tokio::test]
async fn deployment_create_returns_full_payload_and_status_fields() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "edge-deploy").await;

    let dep_body = serde_json::json!({
        "name": "web",
        "image": "nginx:alpine",
        "command": ["nginx", "-g", "daemon off;"],
        "env": { "KEY": "VALUE" },
        "secret_env": [{ "name": "API_TOKEN", "secret": "demo-api" }],
        "secret_files": [{
            "path": "/etc/secret/api",
            "secret": "api-key",
            "optional": true
        }],
        "ports": [{
            "container_port": 8080,
            "host_port": 18080,
            "protocol": "udp",
            "host_ip": "127.0.0.1",
            "expose": true
        }],
        "desired_state": "stopped"
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");

    assert_eq!(created.assigned_node_id, reg.node_id);
    assert_eq!(created.generation, 1);

    let status = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let status_body = status.into_body().collect().await.expect("body").to_bytes();
    let deployment: DeploymentStatusResponse =
        serde_json::from_slice(&status_body).expect("parse status");

    assert_eq!(deployment.name, "web");
    assert_eq!(deployment.command.as_ref().unwrap()[0], "nginx");
    assert_eq!(deployment.desired_state, DesiredState::Stopped);
    assert_eq!(deployment.generation, 1);
    let env = deployment.env.as_ref().unwrap();
    assert_eq!(env.get("KEY"), Some(&"VALUE".to_string()));
    let secret_env = deployment.secret_env.as_ref().expect("secret env refs");
    assert_eq!(secret_env[0].name, "API_TOKEN");
    assert_eq!(secret_env[0].secret, "demo-api");
    assert!(!secret_env[0].optional);
    let secret_files = deployment.secret_files.as_ref().expect("secret files");
    assert_eq!(secret_files[0].path, "/etc/secret/api");
    assert_eq!(secret_files[0].secret, "api-key");
    assert!(secret_files[0].optional);
    let port = deployment.ports.as_ref().unwrap().first().unwrap();
    assert_eq!(port.container_port, 8080);
    assert_eq!(port.host_port, Some(18080));
    assert_eq!(port.protocol, "udp");
    assert_eq!(port.host_ip.as_deref(), Some("127.0.0.1"));
    assert!(port.expose);
    assert_eq!(port.endpoint.as_deref(), Some("127.0.0.1:18080"));
    assert!(deployment.created_at <= deployment.updated_at);

    let desired = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(desired.status(), StatusCode::OK);
    let desired_body = desired
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let desired: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("parse desired-state");
    let desired_dep = desired.deployments.first().expect("deployment present");
    let desired_port = desired_dep.ports.as_ref().unwrap().first().unwrap();
    assert_eq!(desired_dep.desired_state, DesiredState::Stopped);
    assert_eq!(desired_dep.generation, 1);
    let desired_secret_env = desired_dep.secret_env.as_ref().expect("secret env");
    assert_eq!(desired_secret_env[0].name, "API_TOKEN");
    assert_eq!(desired_secret_env[0].secret, "demo-api");
    assert_eq!(
        desired_dep
            .secret_files
            .as_ref()
            .and_then(|files| files.first().map(|f| f.path.clone()))
            .as_deref(),
        Some("/etc/secret/api")
    );
    assert!(desired_dep
        .secret_files
        .as_ref()
        .map(|files| files[0].optional)
        .unwrap_or(false));
    assert_eq!(desired_port.host_port, Some(18080));
    assert!(desired_port.expose);
    assert_eq!(desired_port.endpoint.as_deref(), Some("127.0.0.1:18080"));
}

#[tokio::test]
async fn deployment_create_requires_host_port_for_expose_when_auto_assign_disabled() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-expose-host-port").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{ "container_port": 8080, "expose": true }]
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body_bytes = res
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let error: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("parse error response");
    let message = error.get("error").and_then(|value| value.as_str()).unwrap();
    assert!(message.contains("expose"));
    assert!(message.contains("host_port"));
}

#[tokio::test]
async fn deployment_create_rejects_invalid_health_check() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-health-invalid").await;

    let dep_body = serde_json::json!({
        "name": "bad-health",
        "image": "nginx:alpine",
        "health": {
            "liveness": {
                "type": "tcp",
                "port": 0
            }
        }
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body_bytes = res.into_body().collect().await.expect("body").to_bytes();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(body.contains("health.probe.port"), "{body}");
}

#[tokio::test]
async fn health_checks_are_persisted_and_status_reports_health() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "edge-health-persist").await;

    let dep_body = serde_json::json!({
        "name": "health-check",
        "image": "nginx:alpine",
        "health": {
            "liveness": {
                "type": "http",
                "port": 8080,
                "path": " /healthz "
            },
            "readiness": {
                "type": "exec",
                "command": ["   health-check   ", "ok"]
            }
        }
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let created: DeploymentCreateResponse = serde_json::from_slice(
        &create
            .into_body()
            .collect()
            .await
            .expect("read create body")
            .to_bytes(),
    )
    .expect("parse create response");

    let desired = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(desired.status(), StatusCode::OK);
    let desired_body = desired
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let desired: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("parse desired state");
    let desired_dep = desired.deployments.first().expect("deployment present");
    let desired_health = desired_dep.health.as_ref().expect("health config");

    if let HealthProbeKind::Http { port, path } = &desired_health.liveness.as_ref().unwrap().kind {
        assert_eq!(*port, 8080);
        assert_eq!(path, "/healthz");
    } else {
        panic!("expected http probe");
    }

    if let HealthProbeKind::Exec { command } = &desired_health.readiness.as_ref().unwrap().kind {
        assert_eq!(command, &vec!["health-check".to_string(), "ok".to_string()]);
    } else {
        panic!("expected exec probe");
    }

    let heartbeat_body = serde_json::json!({
        "node_status": "ready",
        "containers": [{
            "deployment_id": created.deployment_id,
            "replica_number": 0,
            "state": "running",
            "generation": created.generation,
            "restart_count": 0,
            "last_updated": Utc::now().to_rfc3339(),
            "health": {
                "healthy": false,
                "last_probe_result": "tcp failure",
                "reason": "connection refused"
            }
        }],
        "timestamp": Utc::now().to_rfc3339()
    });

    let heartbeat = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::from(heartbeat_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(heartbeat.status(), StatusCode::OK);

    let status = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status_body = status.into_body().collect().await.expect("body").to_bytes();
    let deployment_status: DeploymentStatusResponse =
        serde_json::from_slice(&status_body).expect("parse status");
    let expected_health = desired_health.clone();
    assert_eq!(deployment_status.health, Some(expected_health.clone()));

    let expected_status = HealthStatus {
        healthy: false,
        last_probe_result: Some("tcp failure".to_string()),
        reason: Some("connection refused".to_string()),
        last_error: Some("connection refused".to_string()),
        last_checked_at: None,
    };
    let reported_instance_health = deployment_status
        .instance
        .as_ref()
        .and_then(|instance| instance.health.as_ref())
        .expect("instance health");
    assert_eq!(reported_instance_health, &expected_status);

    let node_status = app
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/nodes/{}", reg.node_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let node_body = node_status
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let node_status: NodeStatusResponse =
        serde_json::from_slice(&node_body).expect("parse node status");
    let reported_health = node_status
        .instances
        .iter()
        .filter_map(|instance| instance.health.as_ref())
        .next()
        .expect("node health");
    assert_eq!(reported_health, &expected_status);
}

#[tokio::test]
async fn updating_health_check_bumps_generation() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-health-update").await;

    let dep_body = serde_json::json!({
        "name": "health-update",
        "image": "nginx:alpine",
        "health": {
            "liveness": {
                "type": "tcp",
                "port": 8080
            }
        }
    });

    let created = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let created_body = created
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let deployment_created: DeploymentCreateResponse =
        serde_json::from_slice(&created_body).expect("parse create response");
    let deployment_id = deployment_created.deployment_id;

    let before_status = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let before_body = before_status
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let before: DeploymentStatusResponse =
        serde_json::from_slice(&before_body).expect("parse status");
    let initial_generation = before.generation;

    let update_body = serde_json::json!({
        "health": {
            "liveness": {
                "type": "http",
                "port": 9090,
                "path": "/ready"
            }
        }
    });

    let update = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("PATCH")
                .uri(format!("/api/v1/deployments/{}", deployment_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(update_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let update_body_bytes = update.into_body().collect().await.expect("body").to_bytes();
    let updated: DeploymentStatusResponse =
        serde_json::from_slice(&update_body_bytes).expect("parse update response");
    assert!(updated.generation > initial_generation);

    let liveness = updated
        .health
        .as_ref()
        .and_then(|health| health.liveness.as_ref())
        .expect("liveness probe");
    if let HealthProbeKind::Http { port, path } = &liveness.kind {
        assert_eq!(*port, 9090);
        assert_eq!(path, "/ready");
    } else {
        panic!("expected http probe");
    }
}

#[tokio::test]
async fn deployment_create_rejects_expose_with_invalid_protocol() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-expose-proto").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{
            "container_port": 8080,
            "host_port": 18080,
            "protocol": "icmp",
            "expose": true
        }]
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body_bytes = res
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let error: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("parse error response");
    let message = error.get("error").and_then(|value| value.as_str()).unwrap();
    assert!(message.contains("protocol"));
}

#[tokio::test]
async fn deployment_create_rejects_expose_with_invalid_host_ip() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-expose-ip").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{
            "container_port": 8080,
            "host_port": 18080,
            "protocol": "tcp",
            "host_ip": "   ",
            "expose": true
        }]
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body_bytes = res
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let error: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("parse error response");
    let message = error.get("error").and_then(|value| value.as_str()).unwrap();
    assert!(message.contains("host_ip"));
}

#[tokio::test]
async fn deployment_status_expose_endpoint_prefers_public_host() {
    let config = TestAppConfig {
        ports: Some(PortsConfig {
            auto_assign: false,
            range_start: 30000,
            range_end: 40000,
            public_host: Some("edge.example.com".into()),
        }),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;
    let reg = register_ready_node(&app, &db, "edge-public-host").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{
            "container_port": 8080,
            "host_port": 18180,
            "protocol": "tcp",
            "expose": true
        }]
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");

    let status = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let status_body = status.into_body().collect().await.expect("body").to_bytes();
    let deployment: DeploymentStatusResponse =
        serde_json::from_slice(&status_body).expect("parse status");
    let port = deployment.ports.as_ref().unwrap().first().unwrap();
    assert_eq!(port.host_ip, None);
    assert!(port.expose);
    assert_eq!(port.endpoint.as_deref(), Some("edge.example.com:18180"));

    let desired = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(desired.status(), StatusCode::OK);
    let desired_body = desired
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let desired: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("parse desired-state");
    let desired_port = desired
        .deployments
        .first()
        .unwrap()
        .ports
        .as_ref()
        .unwrap()
        .first()
        .unwrap();
    assert!(desired_port.expose);
    assert_eq!(
        desired_port.endpoint.as_deref(),
        Some("edge.example.com:18180")
    );
}

#[tokio::test]
async fn deployment_status_expose_endpoint_uses_assignment_ports() {
    let config = TestAppConfig {
        ports: Some(PortsConfig {
            auto_assign: true,
            range_start: 40000,
            range_end: 40005,
            public_host: Some("edge.example.com".into()),
        }),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;
    let _reg_a = register_ready_node(&app, &db, "edge-a").await;
    let _reg_b = register_ready_node(&app, &db, "edge-b").await;

    let dep_body = serde_json::json!({
        "name": "web-expose",
        "image": "nginx:alpine",
        "replicas": 2,
        "ports": [{ "container_port": 8080, "expose": true }]
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");

    let status = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(status.status(), StatusCode::OK);
    let status_body = status.into_body().collect().await.expect("body").to_bytes();
    let deployment: DeploymentStatusResponse =
        serde_json::from_slice(&status_body).expect("parse status");
    let port = deployment.ports.as_ref().unwrap().first().unwrap();
    assert!(port.expose);
    let host_port = port
        .host_port
        .expect("host_port should be set for exposed port");
    let expected_endpoint = format!("edge.example.com:{host_port}");
    assert_eq!(port.endpoint.as_deref(), Some(expected_endpoint.as_str()));
}

#[tokio::test]
async fn deployment_port_mapping_persists_expose_flag() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-expose-persist").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{
            "container_port": 8080,
            "host_port": 18181,
            "protocol": "tcp",
            "host_ip": "127.0.0.1",
            "expose": true
        }]
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");

    let deployment = deployments::get_deployment(&db, created.deployment_id)
        .await
        .expect("db get")
        .expect("deployment missing");
    let stored_ports: Vec<db::PortMapping> = deployment
        .ports_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .expect("deserialize stored ports")
        .unwrap_or_default();
    assert_eq!(stored_ports.len(), 1);
    let stored = &stored_ports[0];
    assert!(stored.expose);
    assert_eq!(stored.host_port, Some(18181));
    assert_eq!(stored.protocol, "tcp");
    assert_eq!(stored.host_ip.as_deref(), Some("127.0.0.1"));
}

#[tokio::test]
async fn deployment_create_rejects_unsatisfiable_constraints() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-constraint").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "constraints": { "labels": { "gpu": "true" } }
    });

    let res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deployment_create_honors_arch_and_labels() {
    let (app, db) = setup_app().await;
    let _amd = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({
            "name": "edge-amd",
            "arch": "amd64",
            "labels": { "zone": "us" }
        }),
    )
    .await;
    let arm = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({
            "name": "edge-arm",
            "arch": "arm64",
            "labels": { "zone": "eu" }
        }),
    )
    .await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "constraints": {
            "arch": "arm64",
            "labels": { "zone": "eu" }
        }
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let body = res.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&body).expect("parse created deployment");
    assert_eq!(created.assigned_node_id, arm.node_id);
}

#[tokio::test]
async fn deployment_create_places_requires_public_ip_on_public_node() {
    let (app, db) = setup_app().await;
    let _private = register_ready_node(&app, &db, "edge-private-public-ingress").await;
    let public = register_ready_node_with_ingress(
        &app,
        &db,
        "edge-public-ingress",
        Some("198.51.100.10"),
        Some("public.edge.test"),
    )
    .await;

    let dep_body = serde_json::json!({
        "name": "needs-public",
        "image": "nginx:alpine",
        "ports": [{
            "container_port": 8080,
            "host_port": 31080,
            "protocol": "tcp",
            "expose": true
        }],
        "requires_public_ip": true
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let body = res.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&body).expect("parse created deployment");

    assert_eq!(created.assigned_node_id, public.node_id);
    assert_eq!(created.assigned_node_ids, vec![public.node_id]);
    assert_eq!(created.unplaced_replicas, 0);

    let stored = deployments::get_deployment(&db, created.deployment_id)
        .await
        .expect("db fetch")
        .expect("deployment missing");
    assert!(stored.requires_public_ip);
    assert_eq!(stored.assigned_node_id, Some(public.node_id));
}

#[tokio::test]
async fn deployment_create_errors_when_public_ingress_unavailable() {
    let (app, db) = setup_app().await;
    let _private = register_ready_node(&app, &db, "edge-private-only").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{
            "container_port": 8080,
            "host_port": 31081,
            "protocol": "tcp",
            "expose": true
        }],
        "requires_public_ip": true
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = res.into_body().collect().await.expect("body").to_bytes();
    let error: serde_json::Value = serde_json::from_slice(&body).expect("parse error body");
    let message = error.get("error").and_then(|v| v.as_str()).unwrap();
    assert_eq!(
        message,
        "no public nodes available for requires_public_ip deployments"
    );
}

#[tokio::test]
async fn deployment_create_rejects_invalid_ports() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-invalid").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{
            "container_port": 0,
            "host_port": 8080,
            "protocol": "tcp"
        }]
    });

    let res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deployment_create_rejects_invalid_volumes() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-volumes").await;

    let relative_host = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [{ "host_path": "tmp/data", "container_path": "/data" }]
    });

    let bad_host_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(relative_host.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_host_res.status(), StatusCode::BAD_REQUEST);

    let relative_container = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [{ "host_path": "/data", "container_path": "data" }]
    });

    let bad_container_res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(relative_container.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(bad_container_res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deployment_create_rejects_disallowed_volume_prefix() {
    let config = TestAppConfig {
        volumes: Some(VolumesConfig {
            allowed_host_prefixes: vec!["/data".into()],
        }),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;
    let _reg = register_ready_node(&app, &db, "edge-vol-prefix").await;

    let disallowed = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [{ "host_path": "/opt/data", "container_path": "/data" }]
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(disallowed.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let traversal = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [{ "host_path": "/data/../etc/passwd", "container_path": "/etc/passwd" }]
    });

    let traverse_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(traversal.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(traverse_res.status(), StatusCode::BAD_REQUEST);

    let allowed = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [{ "host_path": "/data/app", "container_path": "/data" }]
    });

    let ok = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(allowed.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ok.status(), StatusCode::CREATED);
}

#[cfg(unix)]
#[tokio::test]
async fn deployment_create_rejects_symlink_escape_volume() {
    let allowed_dir = std::env::temp_dir().join(format!("fledx-volumes-{}", Uuid::new_v4()));
    fs::create_dir_all(&allowed_dir).expect("create allowed dir");

    let escape_link = allowed_dir.join("etc_link");
    unix_fs::symlink("/etc", &escape_link).expect("create escape symlink");

    let config = TestAppConfig {
        volumes: Some(VolumesConfig {
            allowed_host_prefixes: vec![allowed_dir.to_string_lossy().into_owned()],
        }),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;
    let _reg = register_ready_node(&app, &db, "edge-vol-symlink").await;

    let host_path = escape_link.join("passwd");
    let body = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [{ "host_path": host_path.to_string_lossy(), "container_path": "/etc/passwd" }]
    });

    let res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let _ = fs::remove_file(&escape_link);
    let _ = fs::remove_dir_all(&allowed_dir);
}

#[tokio::test]
async fn deployment_create_rejects_volumes_when_allowlist_empty() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-vol-disabled").await;

    let body = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [{ "host_path": "/data/app", "container_path": "/var/app" }]
    });

    let res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deployment_create_rejects_zero_replicas() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-replicas").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "replicas": 0
    });

    let res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deployment_create_rejects_anti_affinity_with_single_node() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-anti").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "placement": { "anti_affinity": { "labels": { "zone": "a" } } }
    });

    let res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deployment_create_rejects_invalid_secret_refs() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-secrets").await;

    let bad_env = serde_json::json!({
        "image": "nginx:alpine",
        "secret_env": [{ "name": "bad name", "secret": "api" }]
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(bad_env.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let bad_file = serde_json::json!({
        "image": "nginx:alpine",
        "secret_files": [{ "path": "relative/path", "secret": "db" }]
    });

    let file_res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(bad_file.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(file_res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deployment_create_rejects_conflicting_host_port() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "edge-conflict").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{
            "container_port": 8080,
            "host_port": 8080,
            "protocol": "tcp"
        }]
    });

    let first = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let conflict = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);

    let conflict_body = conflict
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&conflict_body).unwrap();
    let error = payload
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("reserved"),
        "expected port conflict message, got {error}"
    );

    let desired = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(desired.status(), StatusCode::OK);
}

#[tokio::test]
async fn deployment_create_rejects_missing_host_port_when_auto_assign_disabled() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-missing-port").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{ "container_port": 8080 }]
    });

    let res = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deployment_status_and_desired_include_volumes() {
    let config = TestAppConfig {
        volumes: Some(VolumesConfig {
            allowed_host_prefixes: vec!["/data".into(), "/logs".into()],
        }),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;
    let reg = register_ready_node(&app, &db, "edge-volume-status").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [
            { "host_path": "/data/app", "container_path": "/var/app", "read_only": true },
            { "host_path": "/logs", "container_path": "/var/log/app" }
        ]
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_bytes = create
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let created: DeploymentCreateResponse = serde_json::from_slice(&create_bytes).unwrap();

    let status = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let status_bytes = status.into_body().collect().await.unwrap().to_bytes();
    let deployment: DeploymentStatusResponse =
        serde_json::from_slice(&status_bytes).expect("status response");
    let vols = deployment.volumes.as_ref().expect("volumes in status");
    assert_eq!(vols.len(), 2);
    assert_eq!(vols[0].host_path, "/data/app");
    assert_eq!(vols[0].container_path, "/var/app");
    assert_eq!(vols[0].read_only, Some(true));
    assert_eq!(vols[1].host_path, "/logs");
    assert_eq!(vols[1].read_only, None);

    let desired = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(desired.status(), StatusCode::OK);
    let desired_body = desired.into_body().collect().await.unwrap().to_bytes();
    let desired_state: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("desired-state body");
    let desired_dep = desired_state
        .deployments
        .iter()
        .find(|d| d.deployment_id == created.deployment_id)
        .expect("deployment in desired-state");
    let desired_vols = desired_dep.volumes.as_ref().expect("desired volumes");
    assert_eq!(desired_vols.len(), 2);
    assert_eq!(desired_vols[0].container_path, "/var/app");
    assert_eq!(desired_vols[0].read_only, Some(true));
}

#[tokio::test]
async fn deployment_create_auto_assigns_host_port_and_stays_stable() {
    let (app, db) = setup_app_with_config(TestAppConfig {
        ports: Some(PortsConfig {
            auto_assign: true,
            range_start: 30000,
            range_end: 30002,
            public_host: None,
        }),
        ..Default::default()
    })
    .await;
    let reg = register_ready_node(&app, &db, "edge-auto").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{ "container_port": 8080 }]
    });

    let res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let created_body = res.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&created_body).expect("parse created deployment");

    let desired = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(desired.status(), StatusCode::OK);
    let desired_body = desired
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let desired: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("parse desired-state");
    assert_eq!(desired.deployments.len(), 1);
    let desired_dep = desired.deployments.first().unwrap();
    let desired_port = desired_dep.ports.as_ref().unwrap().first().unwrap();
    assert_eq!(desired_dep.deployment_id, created.deployment_id);
    assert_eq!(desired_port.host_port, Some(30000));

    let second_dep = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_dep.status(), StatusCode::CREATED);
    let second_body = second_dep
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let second_created: DeploymentCreateResponse =
        serde_json::from_slice(&second_body).expect("parse second deployment");
    assert_ne!(second_created.deployment_id, created.deployment_id);
}

#[tokio::test]
async fn deployment_create_returns_4xx_when_auto_port_range_exhausted() {
    let (app, db) = setup_app_with_config(TestAppConfig {
        ports: Some(PortsConfig {
            auto_assign: true,
            range_start: 32000,
            range_end: 32000,
            public_host: None,
        }),
        ..Default::default()
    })
    .await;
    let _reg = register_ready_node(&app, &db, "edge-auto-range").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{ "container_port": 8080 }]
    });

    let first = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let body = second.into_body().collect().await.expect("body").to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let error = payload
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("host ports available in range 32000-32000"),
        "{error}"
    );
}

#[tokio::test]
async fn deployment_delete_releases_port_reservations() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "edge-delete-ports").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{ "container_port": 8080, "host_port": 18080, "protocol": "tcp" }]
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create.into_body().collect().await.expect("body").to_bytes())
            .expect("parse create response");

    let delete = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("DELETE")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let recreate = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recreate.status(), StatusCode::CREATED);

    let recreated: DeploymentCreateResponse = serde_json::from_slice(
        &recreate
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("parse recreate");
    assert_eq!(recreated.assigned_node_id, reg.node_id);
}

#[tokio::test]
async fn deployment_update_bumps_generation_on_spec_change() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "edge-update").await;

    let dep_body = serde_json::json!({
        "name": "web",
        "image": "nginx:alpine",
        "env": { "KEY": "VALUE" },
        "ports": [{
            "container_port": 8080,
            "host_port": 18080,
            "protocol": "tcp"
        }]
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");

    let update_body = serde_json::json!({
        "image": "nginx:1.27",
        "env": { "NEW": "VALUE2" },
        "ports": [{
            "container_port": 9090,
            "host_port": 9090
        }],
        "desired_state": "running"
    });

    let update_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("PATCH")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(update_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_res.status(), StatusCode::OK);

    let update_body = update_res
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let updated: DeploymentStatusResponse =
        serde_json::from_slice(&update_body).expect("parse update response");

    assert_eq!(updated.generation, 2);
    assert_eq!(updated.image, "nginx:1.27");
    assert_eq!(updated.desired_state, DesiredState::Running);
    assert_eq!(updated.status, DeploymentStatus::Pending);
    let port = updated.ports.as_ref().unwrap().first().unwrap();
    assert_eq!(port.container_port, 9090);
    assert_eq!(port.host_port, Some(9090));
    assert_eq!(port.protocol, "tcp");

    let desired = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(desired.status(), StatusCode::OK);
    let desired_body = desired
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let desired: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("parse desired-state");
    let desired_dep = desired.deployments.first().expect("deployment present");
    assert_eq!(desired_dep.generation, 2);
    let desired_port = desired_dep.ports.as_ref().unwrap().first().unwrap();
    assert_eq!(desired_port.container_port, 9090);
}

#[tokio::test]
async fn deployment_update_bumps_generation_on_volume_change() {
    let config = TestAppConfig {
        volumes: Some(VolumesConfig {
            allowed_host_prefixes: vec!["/data".into()],
        }),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;
    let reg = register_ready_node(&app, &db, "edge-update-volumes").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "volumes": [{ "host_path": "/data/app", "container_path": "/var/app" }]
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let created_bytes = create.into_body().collect().await.unwrap().to_bytes();
    let created: DeploymentCreateResponse = serde_json::from_slice(&created_bytes).unwrap();

    let update_body = serde_json::json!({
        "volumes": [{ "host_path": "/data/cache", "container_path": "/var/cache", "read_only": true }]
    });

    let update = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("PATCH")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(update_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let update_bytes = update.into_body().collect().await.unwrap().to_bytes();
    let updated: DeploymentStatusResponse = serde_json::from_slice(&update_bytes).unwrap();

    assert_eq!(updated.generation, created.generation + 1);
    let vols = updated.volumes.as_ref().expect("volumes in updated status");
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].host_path, "/data/cache");
    assert_eq!(vols[0].read_only, Some(true));

    let desired = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let desired_body = desired.into_body().collect().await.unwrap().to_bytes();
    let desired_state: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("desired-state body");
    let dep = desired_state
        .deployments
        .iter()
        .find(|d| d.deployment_id == created.deployment_id)
        .expect("deployment present in desired-state");
    let desired_vol = dep.volumes.as_ref().expect("volumes propagated");
    assert_eq!(desired_vol[0].host_path, "/data/cache");
}

#[tokio::test]
async fn deployment_update_changes_replicas_and_placement() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "edge-replica-update").await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine"
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");

    let update_body = serde_json::json!({
        "replicas": 2,
        "placement": {
            "affinity": { "node_ids": [reg.node_id] },
            "spread": true
        }
    });

    let update_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("PATCH")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(update_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_res.status(), StatusCode::OK);

    let update_body = update_res
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let updated: DeploymentStatusResponse =
        serde_json::from_slice(&update_body).expect("parse update response");

    assert_eq!(updated.replicas, 2);
    assert_eq!(updated.generation, 2);
    let placement = updated.placement.expect("placement missing");
    assert!(placement.spread);
    let affinity_nodes = placement
        .affinity
        .as_ref()
        .map(|aff| aff.node_ids.clone())
        .unwrap_or_default();
    assert!(affinity_nodes.contains(&reg.node_id));

    let desired = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(desired.status(), StatusCode::OK);
    let desired_body = desired
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let desired: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("parse desired-state");
    let desired_dep = desired.deployments.first().expect("deployment present");
    assert_eq!(desired_dep.replicas, 2);
    assert!(desired_dep
        .placement
        .as_ref()
        .and_then(|p| p.affinity.as_ref())
        .is_some());
}

#[tokio::test]
async fn deployment_update_reassigns_when_constraints_change() {
    let (app, db) = setup_app().await;
    let amd = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({ "name": "edge-amd-update", "arch": "amd64" }),
    )
    .await;
    let arm = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({ "name": "edge-arm-update", "arch": "arm64" }),
    )
    .await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine"
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");
    assert_eq!(created.assigned_node_id, amd.node_id);

    let update_body = serde_json::json!({
        "constraints": { "arch": "arm64" }
    });

    let update = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("PATCH")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(update_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(update.status(), StatusCode::OK);
    let body = update.into_body().collect().await.expect("body").to_bytes();
    let updated: DeploymentStatusResponse =
        serde_json::from_slice(&body).expect("parse update response");

    assert_eq!(updated.assigned_node_id, Some(arm.node_id));
    assert_eq!(updated.status, DeploymentStatus::Pending);
    assert_eq!(updated.generation, 2);
    assert_eq!(
        updated.constraints.as_ref().and_then(|c| c.arch.as_deref()),
        Some("arm64")
    );
}

#[tokio::test]
async fn deployment_stop_sets_desired_state_without_generation_bump() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "edge-stop").await;

    let dep_body = serde_json::json!({
        "name": "api",
        "image": "nginx:alpine"
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");

    let stop_body = serde_json::json!({ "desired_state": "stopped" });
    let stop_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("PATCH")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(stop_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(stop_res.status(), StatusCode::OK);
    let stop_body = stop_res
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let stopped: DeploymentStatusResponse =
        serde_json::from_slice(&stop_body).expect("parse stop response");

    assert_eq!(stopped.generation, 1);
    assert_eq!(stopped.desired_state, DesiredState::Stopped);
    assert_eq!(stopped.status, DeploymentStatus::Stopped);

    let desired = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let desired_body = desired
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let desired: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("parse desired-state");
    assert_eq!(
        desired
            .deployments
            .first()
            .expect("deployment")
            .desired_state,
        DesiredState::Stopped
    );
}

#[tokio::test]
async fn deployment_update_rejects_conflicting_host_port() {
    let (app, db) = setup_app().await;
    let _reg = register_ready_node(&app, &db, "edge-update-conflict").await;

    let first = serde_json::json!({
        "image": "nginx:first",
        "ports": [{ "container_port": 8080, "host_port": 8080, "protocol": "tcp" }]
    });
    let second = serde_json::json!({
        "image": "nginx:second",
        "ports": [{ "container_port": 9090, "host_port": 9090, "protocol": "tcp" }]
    });

    let created_first = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(first.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created_first.status(), StatusCode::CREATED);

    let created_second = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(second.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created_second.status(), StatusCode::CREATED);
    let dep: DeploymentCreateResponse = serde_json::from_slice(
        &created_second
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("parse create response");

    let update = serde_json::json!({
        "ports": [{ "container_port": 8080, "host_port": 8080, "protocol": "tcp" }]
    });
    let conflict = app
        .oneshot(
            HttpRequest::builder()
                .method("PATCH")
                .uri(format!("/api/v1/deployments/{}", dep.deployment_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(update.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);
    let body = conflict
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let error = payload
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("reserved"),
        "expected port conflict message, got {error}"
    );
}

#[tokio::test]
async fn deployment_update_moves_reservations_on_reassignment() {
    let (app, db) = setup_app().await;
    let node_a = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({ "name": "edge-a", "labels": { "zone": "a" } }),
    )
    .await;
    let node_b = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({ "name": "edge-b", "labels": { "zone": "b" } }),
    )
    .await;

    let dep_body = serde_json::json!({
        "image": "nginx:alpine",
        "ports": [{ "container_port": 8080, "host_port": 8080, "protocol": "tcp" }],
        "constraints": { "labels": { "zone": "a" } }
    });
    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");
    assert_eq!(created.assigned_node_id, node_a.node_id);

    let update_body = serde_json::json!({
        "constraints": { "labels": { "zone": "b" } }
    });
    let update = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("PATCH")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(update_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let updated: DeploymentStatusResponse =
        serde_json::from_slice(&update.into_body().collect().await.expect("body").to_bytes())
            .expect("parse update");
    assert_eq!(updated.assigned_node_id, Some(node_b.node_id));

    let follow_up = serde_json::json!({
        "image": "nginx:follow-up",
        "ports": [{ "container_port": 8080, "host_port": 8080, "protocol": "tcp" }],
        "constraints": { "labels": { "zone": "a" } }
    });
    let recreate = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(follow_up.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recreate.status(), StatusCode::CREATED);
    let recreated: DeploymentCreateResponse = serde_json::from_slice(
        &recreate
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("parse recreate");
    assert_eq!(recreated.assigned_node_id, node_a.node_id);
}

#[tokio::test]
async fn deployment_delete_soft_deletes_and_removes_from_desired_state() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "edge-delete").await;

    let dep_body = serde_json::json!({
        "name": "api",
        "image": "nginx:alpine"
    });

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let create_body = create.into_body().collect().await.expect("body").to_bytes();
    let created: DeploymentCreateResponse =
        serde_json::from_slice(&create_body).expect("parse create response");

    let delete = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("DELETE")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let status = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", created.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::NOT_FOUND);

    let desired = app
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let desired_body = desired
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let desired: DesiredStateResponse =
        serde_json::from_slice(&desired_body).expect("parse desired-state");
    assert!(
        desired.deployments.is_empty(),
        "deleted deployment should not be in desired-state"
    );

    let deleted_at: Option<String> =
        sqlx::query_scalar(r#"SELECT deleted_at FROM deployments WHERE id = ?1"#)
            .bind(created.deployment_id)
            .fetch_one(&db)
            .await
            .expect("select deleted_at");
    assert!(deleted_at.is_some(), "deleted_at should be set");
}

#[tokio::test]
async fn heartbeat_updates_status_with_token_auth() {
    let (app, db) = setup_app().await;

    let reg_body = serde_json::json!({ "name": "edge-2" });
    let reg_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let reg_bytes = reg_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&reg_bytes).unwrap();

    let hb_body = serde_json::json!({
        "node_status": "ready",
        "containers": [],
        "timestamp": null
    });

    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::from(hb_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(hb_res.status(), StatusCode::OK);

    let node = nodes::get_node(&db, reg.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(node.status, db::NodeStatus::Ready);
    assert!(node.last_seen.is_some());
}

#[tokio::test]
async fn heartbeat_clears_inventory_when_empty_payloads_arrive() {
    let (app, db) = setup_app().await;

    let reg_body = serde_json::json!({
        "name": "edge-clear",
        "labels": { "region": "us-west", "tier": "gpu" },
        "capacity": { "cpu_millis": 2_000, "memory_bytes": 512_000 }
    });
    let reg = register_ready_node_with_payload(&app, &db, reg_body).await;

    let before = nodes::get_node(&db, reg.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(
        before
            .labels
            .as_ref()
            .and_then(|labels| labels.0.get("region"))
            .cloned(),
        Some("us-west".to_string())
    );
    assert_eq!(
        before.capacity.as_ref().and_then(|cap| cap.0.cpu_millis),
        Some(2_000)
    );

    let hb_body = serde_json::json!({
        "node_status": "ready",
        "containers": [],
        "inventory": {
            "labels": {},
            "capacity": {}
        }
    });

    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::from(hb_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(hb_res.status(), StatusCode::OK);

    let after = nodes::get_node(&db, reg.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert!(
        after
            .labels
            .as_ref()
            .map(|labels| labels.0.is_empty())
            .unwrap_or(false),
        "labels should be cleared when empty map is reported"
    );
    assert!(
        after
            .capacity
            .as_ref()
            .map(|cap| cap.0.cpu_millis.is_none() && cap.0.memory_bytes.is_none())
            .unwrap_or(false),
        "capacity hints should be cleared when empty object is reported"
    );
}

#[tokio::test]
async fn heartbeat_persists_instances_and_status_endpoints() {
    let config = TestAppConfig {
        retention_secs: Some(86_400),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;

    let reg_body = serde_json::json!({ "name": "edge-status" });
    let reg_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let reg_bytes = reg_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&reg_bytes).unwrap();

    nodes::update_node_status(&db, reg.node_id, db::NodeStatus::Ready, Some(Utc::now()))
        .await
        .expect("mark node ready");

    let dep_body = serde_json::json!({
        "name": "app",
        "image": "nginx:alpine"
    });

    let dep_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dep_res.status(), StatusCode::CREATED);

    let dep_bytes = dep_res
        .into_body()
        .collect()
        .await
        .expect("read dep body")
        .to_bytes();
    let dep_resp: DeploymentCreateResponse = serde_json::from_slice(&dep_bytes).unwrap();
    assert_eq!(dep_resp.assigned_node_id, reg.node_id);

    let hb_ts = Utc::now();
    let last_updated = hb_ts - ChronoDuration::seconds(1);
    let endpoint_hint = format!("edge.example.com:{}", 18080);
    let hb_body = serde_json::json!({
        "node_status": "ready",
        "timestamp": hb_ts.to_rfc3339(),
        "containers": [{
            "deployment_id": dep_resp.deployment_id,
            "replica_number": 0,
            "container_id": "abc123",
            "state": "running",
            "message": null,
            "restart_count": 2,
            "generation": 1,
            "last_updated": last_updated.to_rfc3339(),
            "endpoints": [ endpoint_hint.clone() ]
        }]
    });

    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::from(hb_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let hb_received_at = Utc::now();
    assert_eq!(hb_res.status(), StatusCode::OK);

    let instances = logs::list_instance_statuses_for_node(&db, reg.node_id)
        .await
        .expect("list instances");
    assert_eq!(instances.len(), 1);
    let inst = &instances[0];
    assert_eq!(inst.deployment_id, dep_resp.deployment_id);
    assert_eq!(inst.replica_number, 0);
    assert_eq!(inst.generation, 1);
    assert_eq!(inst.container_id.as_deref(), Some("abc123"));
    assert_eq!(inst.state, db::InstanceState::Running);
    assert!(
        inst.last_seen.timestamp() >= hb_ts.timestamp(),
        "last_seen should be at least the heartbeat send time"
    );
    assert!(
        inst.last_seen <= hb_received_at,
        "last_seen should not be after heartbeat response"
    );
    assert_eq!(inst.restart_count, 2);
    assert_eq!(
        inst.endpoints.as_ref().map(|json| json.0.clone()),
        Some(vec![endpoint_hint.clone()])
    );

    let deployment = deployments::get_deployment(&db, dep_resp.deployment_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deployment.status, db::DeploymentStatus::Running);

    let node_status_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/nodes/{}", reg.node_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(node_status_res.status(), StatusCode::OK);
    let node_status_bytes = node_status_res
        .into_body()
        .collect()
        .await
        .expect("read node status")
        .to_bytes();
    let node_status: NodeStatusResponse =
        serde_json::from_slice(&node_status_bytes).expect("parse node status");
    assert_eq!(node_status.node_id, reg.node_id);
    assert_eq!(node_status.status, NodeStatus::Ready);
    let node_last_seen = node_status.last_seen.expect("node last_seen");
    assert!(
        node_last_seen >= hb_ts && node_last_seen <= hb_received_at,
        "node last_seen should track latest heartbeat"
    );
    assert_eq!(node_status.instances.len(), 1);
    assert_eq!(
        node_status.instances[0].deployment_id,
        dep_resp.deployment_id
    );
    assert_eq!(node_status.instances[0].replica_number, 0);
    assert_eq!(node_status.instances[0].generation, 1);
    assert_eq!(
        node_status.instances[0].endpoints,
        vec![endpoint_hint.clone()]
    );

    let dep_status_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", dep_resp.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dep_status_res.status(), StatusCode::OK);
    let dep_status_bytes = dep_status_res
        .into_body()
        .collect()
        .await
        .expect("read dep status")
        .to_bytes();
    let dep_status: DeploymentStatusResponse =
        serde_json::from_slice(&dep_status_bytes).expect("parse dep status");
    assert_eq!(dep_status.status, DeploymentStatus::Running);
    let dep_instance = dep_status.instance.expect("instance response");
    assert_eq!(dep_instance.replica_number, 0);
    assert_eq!(dep_instance.generation, 1);
    assert_eq!(dep_instance.container_id.as_deref(), Some("abc123"));
    assert_eq!(dep_instance.endpoints, vec![endpoint_hint]);
    let last_reported = dep_status.last_reported.expect("last_reported");
    assert!(
        last_reported.timestamp() >= hb_ts.timestamp() && last_reported <= hb_received_at,
        "last_reported should be between heartbeat timestamp and response"
    );
}

#[tokio::test]
async fn heartbeat_rejects_unassigned_replicas() {
    let (app, db) = setup_app().await;

    let reg_a = register_ready_node(&app, &db, "edge-a").await;
    let reg_b = register_ready_node(&app, &db, "edge-b").await;

    let dep_body = serde_json::json!({
        "name": "multi-replica",
        "image": "nginx:alpine",
        "replicas": 2
    });
    let dep_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dep_res.status(), StatusCode::CREATED);
    let dep_bytes = dep_res
        .into_body()
        .collect()
        .await
        .expect("read dep body")
        .to_bytes();
    let dep: DeploymentCreateResponse = serde_json::from_slice(&dep_bytes).unwrap();

    let assignments = deployments::list_assignments_for_deployment(&db, dep.deployment_id)
        .await
        .expect("list assignments");
    assert_eq!(assignments.len(), 2);
    let a_assignment = assignments
        .iter()
        .find(|a| a.node_id == reg_a.node_id)
        .expect("assignment for node a");
    let b_assignment = assignments
        .iter()
        .find(|a| a.node_id == reg_b.node_id)
        .expect("assignment for node b");

    let deployment = deployments::get_deployment(&db, dep.deployment_id)
        .await
        .expect("get deployment")
        .expect("deployment missing");
    let now = Utc::now();

    let hb_body = serde_json::json!({
        "node_status": "ready",
        "containers": [
            {
                "deployment_id": dep.deployment_id,
                "replica_number": a_assignment.replica_number,
                "container_id": "ctr-a",
                "state": "running",
                "message": null,
                "restart_count": 0,
                "generation": deployment.generation,
                "last_updated": now,
            },
            {
                "deployment_id": dep.deployment_id,
                "replica_number": b_assignment.replica_number,
                "container_id": "ctr-b",
                "state": "running",
                "message": null,
                "restart_count": 0,
                "generation": deployment.generation,
                "last_updated": now,
            }
        ],
        "timestamp": now
    });

    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg_a.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg_a.node_token))
                .body(Body::from(hb_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hb_res.status(), StatusCode::OK);

    let node_a_instances = logs::list_instance_statuses_for_node(&db, reg_a.node_id)
        .await
        .expect("list instances for node a");
    assert_eq!(node_a_instances.len(), 1);
    assert_eq!(
        node_a_instances[0].replica_number,
        a_assignment.replica_number
    );
    assert_eq!(node_a_instances[0].deployment_id, dep.deployment_id);

    let deployment_instances = logs::list_instance_statuses_for_deployment(&db, dep.deployment_id)
        .await
        .expect("list instances for deployment");
    assert_eq!(deployment_instances.len(), 1);
    assert_eq!(deployment_instances[0].node_id, reg_a.node_id);
}

#[tokio::test]
async fn heartbeat_prunes_stale_instance_statuses() {
    let config = TestAppConfig {
        retention_secs: Some(1),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;

    let reg_body = serde_json::json!({ "name": "edge-prune" });
    let reg_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let reg_bytes = reg_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&reg_bytes).unwrap();

    nodes::update_node_status(&db, reg.node_id, db::NodeStatus::Ready, Some(Utc::now()))
        .await
        .expect("mark node ready");

    let dep_body = serde_json::json!({
        "name": "app",
        "image": "nginx:alpine"
    });
    let dep_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let dep_bytes = dep_res
        .into_body()
        .collect()
        .await
        .expect("read dep body")
        .to_bytes();
    let dep_resp: DeploymentCreateResponse = serde_json::from_slice(&dep_bytes).unwrap();

    let first_ts = Utc::now();
    let hb_body = serde_json::json!({
        "node_status": "ready",
        "timestamp": first_ts.to_rfc3339(),
        "containers": [{
            "deployment_id": dep_resp.deployment_id,
            "replica_number": 0,
            "container_id": "abc123",
            "state": "running",
            "message": null,
            "restart_count": 1,
            "generation": 1,
            "last_updated": first_ts.to_rfc3339()
        }]
    });
    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::from(hb_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hb_res.status(), StatusCode::OK);

    let instances = logs::list_instance_statuses_for_node(&db, reg.node_id)
        .await
        .expect("list instances");
    assert_eq!(instances.len(), 1);

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let later_ts = first_ts + ChronoDuration::seconds(5);
    let second_hb = serde_json::json!({
        "node_status": "ready",
        "timestamp": later_ts.to_rfc3339(),
        "containers": []
    });
    let second_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::from(second_hb.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_res.status(), StatusCode::OK);

    let after = logs::list_instance_statuses_for_node(&db, reg.node_id)
        .await
        .expect("list instances");
    assert!(
        after.is_empty(),
        "stale instance status should be pruned on heartbeat"
    );

    let deployment = deployments::get_deployment(&db, dep_resp.deployment_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deployment.status, db::DeploymentStatus::Deploying);
}

#[tokio::test]
async fn desired_state_returns_assigned_deployments() {
    let (app, db) = setup_app().await;

    let reg_body = serde_json::json!({ "name": "edge-3" });
    let reg_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let reg_bytes = reg_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&reg_bytes).unwrap();

    nodes::update_node_status(&db, reg.node_id, db::NodeStatus::Ready, Some(Utc::now()))
        .await
        .expect("mark node ready");

    let dep_body = serde_json::json!({
        "name": "app",
        "image": "nginx:alpine",
        "command": ["nginx", "-g", "daemon off;"]
    });

    let dep_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(dep_res.status(), StatusCode::CREATED);
    let dep_bytes = dep_res
        .into_body()
        .collect()
        .await
        .expect("read dep body")
        .to_bytes();
    let dep_resp: DeploymentCreateResponse = serde_json::from_slice(&dep_bytes).unwrap();
    assert_eq!(dep_resp.assigned_node_id, reg.node_id);

    let desired_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/desired-state", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(desired_res.status(), StatusCode::OK);

    let body_bytes = desired_res
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let desired: DesiredStateResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(desired.deployments.len(), 1);
    assert_eq!(desired.deployments[0].image, "nginx:alpine");
    assert_eq!(desired.deployments[0].desired_state, DesiredState::Running);
}

#[tokio::test]
async fn heartbeat_body_limit_rejects_large_payload() {
    let config = TestAppConfig {
        hb_body_limit: Some(200),
        ..Default::default()
    };
    let (app, db) = setup_app_with_config(config).await;

    let reg_body = serde_json::json!({ "name": "edge-hb" });
    let reg_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let reg_bytes = reg_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&reg_bytes).unwrap();

    let big_payload = serde_json::json!({
        "node_status": "ready",
        "timestamp": Utc::now().to_rfc3339(),
        "containers": [{
            "deployment_id": reg.node_id,
            "replica_number": 0,
            "container_id": "abc",
            "state": "running",
            "message": "x".repeat(500),
            "restart_count": 0,
            "generation": 1,
            "last_updated": Utc::now().to_rfc3339()
        }]
    });

    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::from(big_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(hb_res.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let node = nodes::get_node(&db, reg.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(node.status, db::NodeStatus::Registering);
}

#[tokio::test]
async fn legacy_token_is_upgraded_on_heartbeat() {
    let (app, db) = setup_app().await;
    let node_id = Uuid::new_v4();
    let token = "legacy-token";

    let node = db::NewNode {
        id: node_id,
        name: Some("legacy-node".into()),
        token_hash: legacy_hash(token),
        arch: None,
        os: None,
        public_ip: None,
        public_host: None,
        labels: None,
        capacity: None,
        last_seen: None,
        status: db::NodeStatus::Registering,
    };
    nodes::create_node(&db, node).await.expect("create node");

    let hb_body = serde_json::json!({
        "node_status": "ready",
        "containers": [],
        "timestamp": null
    });

    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::from(hb_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(hb_res.status(), StatusCode::OK);

    let updated = nodes::get_node(&db, node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert!(
        updated.token_hash.starts_with("$argon2"),
        "token hash should be upgraded to argon2"
    );
    assert_ne!(updated.token_hash, legacy_hash(token));
}

#[tokio::test]
async fn heartbeat_updates_public_ingress_metadata() {
    let (app, db) = setup_app().await;
    let registration = register_ready_node(&app, &db, "edge-heartbeat").await;

    let first_payload = serde_json::json!({
        "node_status": "ready",
        "containers": [],
        "public_ip": " 203.0.113.8 ",
        "public_host": "Ingress.Example.COM "
    });

    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", registration.node_id))
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    format!("Bearer {}", registration.node_token),
                )
                .body(Body::from(first_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(hb_res.status(), StatusCode::OK);

    let updated_first = nodes::get_node(&db, registration.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(updated_first.public_ip.as_deref(), Some("203.0.113.8"));
    assert_eq!(
        updated_first.public_host.as_deref(),
        Some("ingress.example.com")
    );

    let second_payload = serde_json::json!({
        "node_status": "ready",
        "containers": []
    });

    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", registration.node_id))
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    format!("Bearer {}", registration.node_token),
                )
                .body(Body::from(second_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(hb_res.status(), StatusCode::OK);

    let updated_second = nodes::get_node(&db, registration.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(updated_second.public_ip, updated_first.public_ip);
    assert_eq!(updated_second.public_host, updated_first.public_host);
}

#[tokio::test]
async fn node_marked_unreachable_and_recovers_on_heartbeat() {
    let reachability = ReachabilityConfig {
        heartbeat_stale_secs: 1,
        sweep_interval_secs: 60,
        reschedule_on_unreachable: false,
    };
    let (app, state) = setup_app_with_state(Some(reachability)).await;

    let reg_body = serde_json::json!({ "name": "edge-reachability" });
    let reg_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    let reg_bytes = reg_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&reg_bytes).unwrap();

    let stale_seen = Utc::now() - ChronoDuration::seconds(120);
    nodes::update_node_status(
        &state.db,
        reg.node_id,
        db::NodeStatus::Ready,
        Some(stale_seen),
    )
    .await
    .expect("mark node ready");

    let report: ReachabilityReport = run_reachability_sweep(
        &state.db,
        &state.scheduler,
        Duration::from_secs(1),
        false,
        &state.ports,
    )
    .await
    .expect("sweep reachability");
    assert_eq!(report.marked_unreachable, 1);

    let node = nodes::get_node(&state.db, reg.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(node.status, db::NodeStatus::Unreachable);

    let node_status_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/nodes/{}", reg.node_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(node_status_res.status(), StatusCode::OK);
    let node_status_bytes = node_status_res
        .into_body()
        .collect()
        .await
        .expect("read node status")
        .to_bytes();
    let node_status: NodeStatusResponse =
        serde_json::from_slice(&node_status_bytes).expect("parse node status");
    assert_eq!(node_status.status, NodeStatus::Unreachable);

    let hb_body = serde_json::json!({
        "node_status": "ready",
        "containers": [],
        "timestamp": null
    });
    let hb_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri(format!("/api/v1/nodes/{}/heartbeats", reg.node_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::from(hb_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hb_res.status(), StatusCode::OK);

    let recovered = nodes::get_node(&state.db, reg.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(recovered.status, db::NodeStatus::Ready);
}

#[tokio::test]
async fn reschedules_deployments_when_node_unreachable() {
    let reachability = ReachabilityConfig {
        heartbeat_stale_secs: 1,
        sweep_interval_secs: 60,
        reschedule_on_unreachable: true,
    };
    let (app, state) = setup_app_with_state(Some(reachability)).await;

    let reg_a_body = serde_json::json!({ "name": "edge-a" });
    let reg_a_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_a_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let reg_a_bytes = reg_a_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg_a: RegistrationResponse = serde_json::from_slice(&reg_a_bytes).unwrap();

    let reg_b_body = serde_json::json!({ "name": "edge-b" });
    let reg_b_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_b_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let reg_b_bytes = reg_b_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg_b: RegistrationResponse = serde_json::from_slice(&reg_b_bytes).unwrap();

    nodes::update_node_status(
        &state.db,
        reg_a.node_id,
        db::NodeStatus::Ready,
        Some(Utc::now()),
    )
    .await
    .expect("mark node a ready");
    nodes::update_node_status(
        &state.db,
        reg_b.node_id,
        db::NodeStatus::Ready,
        Some(Utc::now()),
    )
    .await
    .expect("mark node b ready");

    let dep_body = serde_json::json!({
        "name": "web-app",
        "image": "nginx:alpine"
    });

    let dep_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dep_res.status(), StatusCode::CREATED);
    let dep_bytes = dep_res
        .into_body()
        .collect()
        .await
        .expect("read dep body")
        .to_bytes();
    let dep_resp: DeploymentCreateResponse = serde_json::from_slice(&dep_bytes).unwrap();
    assert_eq!(dep_resp.assigned_node_id, reg_a.node_id);

    let stale_seen = Utc::now() - ChronoDuration::seconds(120);
    nodes::update_node_status(
        &state.db,
        reg_a.node_id,
        db::NodeStatus::Ready,
        Some(stale_seen),
    )
    .await
    .expect("set stale timestamp for node a");

    let report = run_reachability_sweep(
        &state.db,
        &state.scheduler,
        Duration::from_secs(1),
        true,
        &state.ports,
    )
    .await
    .expect("sweep reachability");
    assert_eq!(report.rescheduled, 1);

    let node_a = nodes::get_node(&state.db, reg_a.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(node_a.status, db::NodeStatus::Unreachable);

    let deployment = deployments::get_deployment(&state.db, dep_resp.deployment_id)
        .await
        .expect("db get")
        .expect("deployment missing");
    assert_eq!(deployment.assigned_node_id, Some(reg_b.node_id));
    assert_eq!(deployment.status, db::DeploymentStatus::Pending);
    assert_eq!(deployment.generation, 2);

    let dep_status_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", dep_resp.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dep_status_res.status(), StatusCode::OK);
    let dep_status_bytes = dep_status_res
        .into_body()
        .collect()
        .await
        .expect("read dep status")
        .to_bytes();
    let dep_status: DeploymentStatusResponse =
        serde_json::from_slice(&dep_status_bytes).expect("parse dep status");
    assert_eq!(dep_status.assigned_node_id, Some(reg_b.node_id));
    assert_eq!(dep_status.status, DeploymentStatus::Pending);
}

#[tokio::test]
async fn reschedules_multi_replica_auto_ports_without_pinning_first_assignment() {
    let _ = tracing_subscriber::fmt::try_init();
    let reachability = ReachabilityConfig {
        heartbeat_stale_secs: 1,
        sweep_interval_secs: 60,
        reschedule_on_unreachable: true,
    };
    let ports_config = PortsConfig {
        auto_assign: true,
        range_start: 30000,
        range_end: 30002,
        public_host: None,
    };
    let (app, db) = setup_app_with_config(TestAppConfig {
        reachability: Some(reachability),
        ports: Some(ports_config.clone()),
        ..Default::default()
    })
    .await;
    let scheduler = control_plane::scheduler::RoundRobinScheduler::new(db.clone());
    let applied_versions: Vec<i64> =
        sqlx::query("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&db)
            .await
            .expect("read migrations table")
            .into_iter()
            .map(|row| row.get::<i64, _>("version"))
            .collect();
    assert!(
        applied_versions.contains(&11),
        "latest migration should be applied, got {:?}",
        applied_versions
    );
    let pk_info = sqlx::query("PRAGMA table_info('port_reservations')")
        .fetch_all(&db)
        .await
        .expect("read port_reservations schema");
    let pk_cols: Vec<String> = pk_info
        .iter()
        .filter(|row| row.get::<i64, _>("pk") > 0)
        .map(|row| row.get::<String, _>("name"))
        .collect();
    assert!(
        pk_cols.iter().any(|name| name == "node_id"),
        "port_reservations primary key should include node_id, got {:?} (migrations {:?})",
        pk_cols,
        applied_versions
    );

    let reg_a = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({ "name": "edge-a", "labels": { "zone": "a" } }),
    )
    .await;
    let reg_b = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({ "name": "edge-b", "labels": { "zone": "b" } }),
    )
    .await;
    let reg_c = register_ready_node_with_payload(
        &app,
        &db,
        serde_json::json!({ "name": "edge-c", "labels": { "zone": "c" } }),
    )
    .await;

    let blocker_body = serde_json::json!({
        "name": "blocker",
        "image": "nginx:alpine",
        "ports": [{ "container_port": 8080, "host_port": 30000 }],
        "constraints": { "labels": { "zone": "c" } }
    });
    let blocker_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(blocker_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocker_res.status(), StatusCode::CREATED);
    let blocker_bytes = blocker_res
        .into_body()
        .collect()
        .await
        .expect("read blocker body")
        .to_bytes();
    let blocker_resp: DeploymentCreateResponse = serde_json::from_slice(&blocker_bytes).unwrap();
    assert_eq!(blocker_resp.assigned_node_id, reg_c.node_id);

    let dep_body = serde_json::json!({
        "name": "web",
        "image": "nginx:alpine",
        "replicas": 2,
        "ports": [{ "container_port": 8080 }]
    });
    let dep_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let dep_status = dep_res.status();
    let dep_bytes = dep_res
        .into_body()
        .collect()
        .await
        .expect("read dep body")
        .to_bytes();
    if dep_status != StatusCode::CREATED {
        panic!(
            "deployment create failed: status {dep_status}, body: {}",
            String::from_utf8_lossy(&dep_bytes)
        );
    }
    let dep_resp: DeploymentCreateResponse = serde_json::from_slice(&dep_bytes).unwrap();
    assert!(dep_resp.assigned_node_ids.contains(&reg_a.node_id));
    assert!(dep_resp.assigned_node_ids.contains(&reg_b.node_id));

    let dep_record = deployments::get_deployment(&db, dep_resp.deployment_id)
        .await
        .expect("db get")
        .expect("deployment missing");
    let stored_ports: Vec<db::PortMapping> = dep_record
        .ports_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .expect("deserialize stored ports")
        .unwrap_or_default();
    assert!(
        stored_ports.iter().all(|p| p.host_port.is_none()),
        "multi-replica deployments should keep unresolved ports when auto-assigning"
    );

    let now = Utc::now();
    nodes::update_node_status(&db, reg_a.node_id, db::NodeStatus::Ready, Some(now))
        .await
        .expect("refresh node a");
    nodes::update_node_status(&db, reg_c.node_id, db::NodeStatus::Ready, Some(now))
        .await
        .expect("refresh node c");
    let stale_seen = now - ChronoDuration::seconds(120);
    nodes::update_node_status(&db, reg_b.node_id, db::NodeStatus::Ready, Some(stale_seen))
        .await
        .expect("set stale timestamp for node b");

    let report =
        run_reachability_sweep(&db, &scheduler, Duration::from_secs(1), true, &ports_config)
            .await
            .expect("sweep reachability");
    assert_eq!(report.rescheduled, 1, "report: {:?}", report);

    let assignments = deployments::list_assignments_for_deployment(&db, dep_resp.deployment_id)
        .await
        .expect("list assignments");
    assert_eq!(assignments.len(), 2);
    assert!(assignments.iter().any(|a| a.node_id == reg_a.node_id));
    assert!(assignments.iter().any(|a| a.node_id == reg_c.node_id));
    let c_assignment = assignments
        .iter()
        .find(|a| a.node_id == reg_c.node_id)
        .expect("assignment on node c");
    let c_port = c_assignment
        .ports
        .as_ref()
        .and_then(|ports| ports.0.first())
        .expect("ports on node c");
    assert_eq!(c_port.host_port, Some(30001));
}

#[tokio::test]
async fn marks_deployments_pending_when_no_ready_nodes() {
    let reachability = ReachabilityConfig {
        heartbeat_stale_secs: 1,
        sweep_interval_secs: 60,
        reschedule_on_unreachable: true,
    };
    let (app, state) = setup_app_with_state(Some(reachability)).await;

    let reg_body = serde_json::json!({ "name": "edge-single" });
    let reg_res = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("POST")
                .uri("/api/v1/nodes/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_REG_TOKEN))
                .body(Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let reg_bytes = reg_res
        .into_body()
        .collect()
        .await
        .expect("read reg body")
        .to_bytes();
    let reg: RegistrationResponse = serde_json::from_slice(&reg_bytes).unwrap();

    nodes::update_node_status(
        &state.db,
        reg.node_id,
        db::NodeStatus::Ready,
        Some(Utc::now()),
    )
    .await
    .expect("mark node ready");

    let dep_body = serde_json::json!({
        "name": "orphaned",
        "image": "nginx:alpine"
    });
    let dep_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/deployments")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(dep_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dep_res.status(), StatusCode::CREATED);
    let dep_bytes = dep_res
        .into_body()
        .collect()
        .await
        .expect("read dep body")
        .to_bytes();
    let dep_resp: DeploymentCreateResponse = serde_json::from_slice(&dep_bytes).unwrap();

    let stale_seen = Utc::now() - ChronoDuration::seconds(120);
    nodes::update_node_status(
        &state.db,
        reg.node_id,
        db::NodeStatus::Ready,
        Some(stale_seen),
    )
    .await
    .expect("set stale timestamp");

    let report = run_reachability_sweep(
        &state.db,
        &state.scheduler,
        Duration::from_secs(1),
        true,
        &state.ports,
    )
    .await
    .expect("sweep reachability");
    assert_eq!(report.marked_pending, 1);

    let node = nodes::get_node(&state.db, reg.node_id)
        .await
        .expect("db get")
        .expect("node missing");
    assert_eq!(node.status, db::NodeStatus::Unreachable);

    let deployment = deployments::get_deployment(&state.db, dep_resp.deployment_id)
        .await
        .expect("db get")
        .expect("deployment missing");
    assert_eq!(deployment.assigned_node_id, None);
    assert_eq!(deployment.status, db::DeploymentStatus::Pending);
    assert_eq!(deployment.generation, 2);

    let dep_status_res = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/deployments/{}", dep_resp.deployment_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dep_status_res.status(), StatusCode::OK);
    let dep_status_bytes = dep_status_res
        .into_body()
        .collect()
        .await
        .expect("read dep status")
        .to_bytes();
    let dep_status: DeploymentStatusResponse =
        serde_json::from_slice(&dep_status_bytes).expect("parse dep status");
    assert_eq!(dep_status.assigned_node_id, None);
    assert_eq!(dep_status.status, DeploymentStatus::Pending);
}

#[tokio::test]
async fn config_crud_returns_versions_and_timestamps() {
    let (app, _db) = setup_app().await;

    let create_payload = ConfigCreateRequest {
        name: "app-config".into(),
        version: None,
        entries: vec![ConfigEntry {
            key: "API_URL".into(),
            value: Some("https://example".into()),
            secret_ref: None,
        }],
        files: vec![ConfigFile {
            path: "/etc/app/config.yaml".into(),
            file_ref: "config-blob".into(),
        }],
    };

    let create = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let created: ConfigResponse =
        serde_json::from_slice(&create.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(created.metadata.name, "app-config");
    assert_eq!(created.metadata.version, 1);
    assert!(created.metadata.updated_at >= created.metadata.created_at);
    assert_eq!(created.entries.len(), 1);
    assert_eq!(created.files.len(), 1);

    let fetched = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri(format!("/api/v1/configs/{}", created.metadata.config_id))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let fetched_status = fetched.status();
    let fetched_body = fetched.into_body().collect().await.unwrap().to_bytes();
    if fetched_status != StatusCode::OK {
        panic!(
            "unexpected status {} body {}",
            fetched_status,
            String::from_utf8_lossy(&fetched_body)
        );
    }
    let fetched: ConfigResponse = serde_json::from_slice(&fetched_body).unwrap();
    assert_eq!(fetched.metadata.version, 1);
    assert_eq!(fetched.entries[0].value.as_deref(), Some("https://example"));

    let listed = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri("/api/v1/configs?limit=10&offset=0")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let page: ConfigSummaryPage =
        serde_json::from_slice(&listed.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].metadata.version, 1);
    assert_eq!(page.items[0].entry_count, 1);
    assert_eq!(page.items[0].file_count, 1);

    let update_payload = ConfigUpdateRequest {
        name: None,
        version: None,
        entries: Some(vec![ConfigEntry {
            key: "API_TOKEN".into(),
            value: None,
            secret_ref: Some("secretref".into()),
        }]),
        files: Some(Vec::new()),
    };

    let updated = app
        .oneshot(
            HttpRequest::builder()
                .method("PUT")
                .uri(format!("/api/v1/configs/{}", created.metadata.config_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(serde_json::to_vec(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let updated_status = updated.status();
    let updated_body = updated.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        updated_status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&updated_body)
    );
    let updated: ConfigResponse = serde_json::from_slice(&updated_body).unwrap();
    assert_eq!(updated.metadata.version, 2);
    assert_eq!(updated.entries[0].secret_ref.as_deref(), Some("secretref"));
    assert!(updated.metadata.updated_at >= updated.metadata.created_at);
    assert!(updated.files.is_empty());
}

#[tokio::test]
async fn config_create_validation_rejects_overlong_and_duplicate_inputs() {
    let (app, _db) = setup_app().await;

    let long_name = "x".repeat(260);
    let too_long_value = "y".repeat(validation::MAX_CONFIG_VALUE_LEN + 1);

    let bad_name = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(
                    serde_json::to_vec(&ConfigCreateRequest {
                        name: long_name,
                        version: None,
                        entries: vec![ConfigEntry {
                            key: "KEY".into(),
                            value: Some("v".into()),
                            secret_ref: None,
                        }],
                        files: Vec::new(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_name.status(), StatusCode::BAD_REQUEST);
    let body = bad_name.into_body().collect().await.unwrap().to_bytes();
    let msg = String::from_utf8_lossy(&body);
    assert!(
        msg.contains("config name too long"),
        "expected name length error, got {msg}"
    );

    let bad_value = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(
                    serde_json::to_vec(&ConfigCreateRequest {
                        name: "valid".into(),
                        version: None,
                        entries: vec![ConfigEntry {
                            key: "KEY".into(),
                            value: Some(too_long_value),
                            secret_ref: None,
                        }],
                        files: Vec::new(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_value.status(), StatusCode::BAD_REQUEST);
    let body = bad_value.into_body().collect().await.unwrap().to_bytes();
    let msg = String::from_utf8_lossy(&body);
    assert!(
        msg.contains("config entry value too long"),
        "expected value length error, got {msg}"
    );

    let create_ok = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(
                    serde_json::to_vec(&ConfigCreateRequest {
                        name: "dup-check".into(),
                        version: None,
                        entries: vec![ConfigEntry {
                            key: "KEY".into(),
                            value: Some("v".into()),
                            secret_ref: None,
                        }],
                        files: Vec::new(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_ok.status(), StatusCode::CREATED);

    let duplicate = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(
                    serde_json::to_vec(&ConfigCreateRequest {
                        name: "dup-check".into(),
                        version: None,
                        entries: vec![ConfigEntry {
                            key: "KEY".into(),
                            value: Some("v2".into()),
                            secret_ref: None,
                        }],
                        files: Vec::new(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let body = duplicate.into_body().collect().await.unwrap().to_bytes();
    let msg = String::from_utf8_lossy(&body);
    assert!(
        msg.contains("config name already exists"),
        "expected duplicate name error, got {msg}"
    );
}

#[tokio::test]
async fn config_entries_cannot_mix_plaintext_and_secret_refs() {
    let (app, _db) = setup_app().await;

    let payload = ConfigCreateRequest {
        name: "mixed-entries".into(),
        version: None,
        entries: vec![
            ConfigEntry {
                key: "PLAIN".into(),
                value: Some("v".into()),
                secret_ref: None,
            },
            ConfigEntry {
                key: "SECRET".into(),
                value: None,
                secret_ref: Some("ref".into()),
            },
        ],
        files: Vec::new(),
    };

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let msg = String::from_utf8_lossy(&body);
    assert!(
        msg.contains("config entries cannot mix plaintext values and secret refs"),
        "expected mixed secret/plaintext error, got {msg}"
    );
}

#[tokio::test]
async fn config_list_returns_paginated_summaries() {
    let (app, _db) = setup_app().await;

    let configs = [("alpha", 2, 1), ("bravo", 1, 0), ("charlie", 0, 0)];

    let mut created = Vec::new();
    for (name, entries, files) in configs {
        let payload = ConfigCreateRequest {
            name: name.into(),
            version: None,
            entries: (0..entries)
                .map(|idx| ConfigEntry {
                    key: format!("K{idx}"),
                    value: Some(format!("V{idx}")),
                    secret_ref: None,
                })
                .collect(),
            files: (0..files)
                .map(|idx| ConfigFile {
                    path: format!("/etc/{name}/{idx}"),
                    file_ref: format!("ref-{idx}"),
                })
                .collect(),
        };
        let res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/configs")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let cfg: ConfigResponse =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        created.push((cfg.metadata, entries as i64, files as i64));
    }

    created.sort_by(|(meta_a, _, _), (meta_b, _, _)| {
        meta_b
            .updated_at
            .cmp(&meta_a.updated_at)
            .then_with(|| meta_a.name.cmp(&meta_b.name))
    });

    let listed = app
        .oneshot(
            HttpRequest::builder()
                .method("GET")
                .uri("/api/v1/configs?limit=2&offset=1")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let page: ConfigSummaryPage =
        serde_json::from_slice(&listed.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(page.limit, 2);
    assert_eq!(page.offset, 1);
    let expected: Vec<_> = created.iter().skip(1).take(2).collect();
    assert_eq!(page.items.len(), expected.len());

    for (item, (meta, entry_count, file_count)) in page.items.iter().zip(expected) {
        assert_eq!(item.metadata.config_id, meta.config_id);
        assert_eq!(item.metadata.name, meta.name);
        assert_eq!(item.metadata.version, meta.version);
        assert_eq!(item.entry_count, *entry_count);
        assert_eq!(item.file_count, *file_count);
        assert!(item.metadata.updated_at >= meta.created_at);
    }
}

#[tokio::test]
async fn config_attach_and_detach_targets_return_metadata() {
    let (app, db) = setup_app().await;

    let create_payload = ConfigCreateRequest {
        name: "attachable".into(),
        version: None,
        entries: vec![],
        files: vec![],
    };

    let created = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let created: ConfigResponse =
        serde_json::from_slice(&created.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let deployment =
        deployments::create_deployment(&db, db::NewDeployment::new("demo".into(), "nginx".into()))
            .await
            .expect("deployment created");
    let node = nodes::create_node(
        &db,
        db::NewNode {
            id: Uuid::new_v4(),
            name: Some("node-a".into()),
            token_hash: "node-token".into(),
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
            last_seen: None,
            status: db::NodeStatus::Ready,
        },
    )
    .await
    .expect("node created");

    let attach_dep = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/configs/{}/deployments/{}",
                    created.metadata.config_id, deployment.id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(attach_dep.status(), StatusCode::CREATED);
    let attach_dep: ConfigAttachmentResponse =
        serde_json::from_slice(&attach_dep.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(attach_dep.attached);
    assert!(attach_dep.attached_at.is_some());
    assert_eq!(attach_dep.deployment_id, Some(deployment.id));
    assert_eq!(attach_dep.metadata.config_id, created.metadata.config_id);

    assert_eq!(
        configs::configs_for_deployment(&db, deployment.id)
            .await
            .unwrap(),
        vec![created.metadata.config_id]
    );

    let detach_dep = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/configs/{}/deployments/{}",
                    created.metadata.config_id, deployment.id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detach_dep.status(), StatusCode::OK);
    let detach_dep: ConfigAttachmentResponse =
        serde_json::from_slice(&detach_dep.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(!detach_dep.attached);
    assert!(detach_dep.attached_at.is_none());
    assert!(configs::configs_for_deployment(&db, deployment.id)
        .await
        .unwrap()
        .is_empty());

    let attach_node = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/configs/{}/nodes/{}",
                    created.metadata.config_id, node.id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(attach_node.status(), StatusCode::CREATED);
    let attach_node: ConfigAttachmentResponse =
        serde_json::from_slice(&attach_node.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(attach_node.attached);
    assert!(attach_node.attached_at.is_some());
    assert_eq!(attach_node.node_id, Some(node.id));

    let detach_node = app
        .oneshot(
            HttpRequest::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/configs/{}/nodes/{}",
                    created.metadata.config_id, node.id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detach_node.status(), StatusCode::OK);
    let detach_node: ConfigAttachmentResponse =
        serde_json::from_slice(&detach_node.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(!detach_node.attached);
    assert!(detach_node.attached_at.is_none());
    assert!(configs::configs_for_node(&db, node.id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn config_attachment_requires_targets_and_is_idempotent() {
    let (app, db) = setup_app().await;

    let created: ConfigResponse = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(
                    serde_json::to_vec(&ConfigCreateRequest {
                        name: "attach-rules".into(),
                        version: None,
                        entries: Vec::new(),
                        files: Vec::new(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .map(|body| serde_json::from_slice(&body.to_bytes()).unwrap())
        .unwrap();

    let deployment =
        deployments::create_deployment(&db, db::NewDeployment::new("demo".into(), "nginx".into()))
            .await
            .expect("deployment created");
    let node = nodes::create_node(
        &db,
        db::NewNode {
            id: Uuid::new_v4(),
            name: Some("node-attach".into()),
            token_hash: "node-token".into(),
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
            last_seen: None,
            status: db::NodeStatus::Ready,
        },
    )
    .await
    .expect("node created");

    let missing_dep = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/configs/{}/deployments/{}",
                    created.metadata.config_id,
                    Uuid::new_v4()
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_dep.status(), StatusCode::NOT_FOUND);
    let body = missing_dep.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("deployment not found"),
        "expected deployment not found error"
    );

    let missing_config = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/configs/{}/nodes/{}",
                    Uuid::new_v4(),
                    node.id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_config.status(), StatusCode::NOT_FOUND);
    let body = missing_config
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("config not found"),
        "expected config not found error"
    );

    let first_attach = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/configs/{}/deployments/{}",
                    created.metadata.config_id, deployment.id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_attach.status(), StatusCode::CREATED);
    let first_attach: ConfigAttachmentResponse =
        serde_json::from_slice(&first_attach.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(first_attach.attached);
    let first_attached_at = first_attach.attached_at;

    let second_attach = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/configs/{}/deployments/{}",
                    created.metadata.config_id, deployment.id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_attach.status(), StatusCode::OK);
    let second_attach: ConfigAttachmentResponse = serde_json::from_slice(
        &second_attach
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert!(second_attach.attached);
    assert_eq!(second_attach.attached_at, first_attached_at);

    let detach = app
        .oneshot(
            HttpRequest::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/configs/{}/deployments/{}",
                    created.metadata.config_id, deployment.id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detach.status(), StatusCode::OK);
    let detached: ConfigAttachmentResponse =
        serde_json::from_slice(&detach.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(!detached.attached);
    assert!(configs::configs_for_deployment(&db, deployment.id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn node_configs_endpoint_serves_configs_and_supports_etag() {
    let (app, db) = setup_app().await;
    let reg = register_ready_node(&app, &db, "config-agent").await;

    let create_payload = ConfigCreateRequest {
        name: "agent-config".into(),
        version: None,
        entries: vec![ConfigEntry {
            key: "API_URL".into(),
            value: Some("https://example".into()),
            secret_ref: None,
        }],
        files: vec![ConfigFile {
            path: "/etc/config/app.yaml".into(),
            file_ref: "blob-ref".into(),
        }],
    };

    let created: ConfigResponse = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .map(|body| serde_json::from_slice(&body.to_bytes()).unwrap())
        .unwrap();

    let attach = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/configs/{}/nodes/{}",
                    created.metadata.config_id, reg.node_id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        attach.status(),
        StatusCode::CREATED | StatusCode::OK
    ));

    let first = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/configs", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let etag = first
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .expect("etag header")
        .to_string();
    let first_body = first.into_body().collect().await.unwrap().to_bytes();
    let response: NodeConfigResponse = serde_json::from_slice(&first_body).unwrap();
    assert_eq!(response.configs.len(), 1);
    let config = &response.configs[0];
    assert_eq!(config.metadata.config_id, created.metadata.config_id);
    assert_eq!(config.metadata.version, 1);
    assert_eq!(config.entries[0].key, "API_URL");
    assert_eq!(config.files[0].path, "/etc/config/app.yaml");
    assert_eq!(config.attached_nodes, vec![reg.node_id]);
    assert!(config.attached_deployments.is_empty());
    assert!(config
        .checksum
        .as_ref()
        .map(|c| !c.is_empty())
        .unwrap_or(false));

    let cached = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/configs", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .header("if-none-match", etag.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);

    let update_payload = ConfigUpdateRequest {
        name: None,
        version: None,
        entries: Some(vec![ConfigEntry {
            key: "API_TOKEN".into(),
            value: Some("secure".into()),
            secret_ref: None,
        }]),
        files: Some(Vec::new()),
    };

    let updated = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("PUT")
                .uri(format!("/api/v1/configs/{}", created.metadata.config_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(serde_json::to_vec(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);

    let refreshed = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/configs", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .header("if-none-match", etag.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.status(), StatusCode::OK);
    let new_etag = refreshed
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .expect("etag header after update");
    assert_ne!(new_etag, etag);
    let refreshed_body = refreshed.into_body().collect().await.unwrap().to_bytes();
    let updated_response: NodeConfigResponse = serde_json::from_slice(&refreshed_body).unwrap();
    assert_eq!(updated_response.configs[0].metadata.version, 2);
    assert_eq!(updated_response.configs[0].entries[0].key, "API_TOKEN");
}

#[tokio::test]
async fn node_configs_enforces_payload_limit() {
    let (app, db) = setup_app_with_config(TestAppConfig {
        config_payload_limit: Some(64),
        ..Default::default()
    })
    .await;
    let reg = register_ready_node(&app, &db, "config-limit").await;

    let create_payload = ConfigCreateRequest {
        name: "big-config".into(),
        version: None,
        entries: vec![ConfigEntry {
            key: "LARGE".into(),
            value: Some("x".repeat(200)),
            secret_ref: None,
        }],
        files: Vec::new(),
    };

    let created: ConfigResponse = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/configs")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .map(|body| serde_json::from_slice(&body.to_bytes()).unwrap())
        .unwrap();

    let _ = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/configs/{}/nodes/{}",
                    created.metadata.config_id, reg.node_id
                ))
                .header("authorization", format!("Bearer {}", TEST_OPERATOR_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            agent_request(HttpRequest::builder())
                .method("GET")
                .uri(format!("/api/v1/nodes/{}/configs", reg.node_id))
                .header("authorization", format!("Bearer {}", reg.node_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let msg = String::from_utf8_lossy(&body);
    assert!(
        msg.contains("payload") || msg.contains("limit"),
        "body: {msg}"
    );
}
