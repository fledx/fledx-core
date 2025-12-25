#[path = "support/common.rs"]
mod support;

use axum::http::{HeaderMap, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use control_plane::persistence::{migrations, nodes, tokens};
use control_plane::services::{compatibility, tokens as token_service};
use control_plane::tokens::{match_token, TokenMatch};
use support::{make_state, TestAppConfig};
use uuid::Uuid;

#[tokio::test]
async fn rotate_node_token_creates_token_and_updates_node_hash() {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");
    let migration_outcome = migrations::run_migrations(&db).await.expect("migrations");
    let state = make_state(
        db.clone(),
        &TestAppConfig::default(),
        migration_outcome.snapshot,
    );

    let node_id = Uuid::new_v4();
    let _node = nodes::create_node(
        &db,
        nodes::NewNode {
            id: node_id,
            name: None,
            token_hash: "old-token-hash".to_string(),
            arch: None,
            os: None,
            public_ip: None,
            public_host: None,
            labels: None,
            capacity: None,
            last_seen: None,
            status: nodes::NodeStatus::Registering,
        },
    )
    .await
    .expect("node");

    let old = tokens::create_node_token(&db, node_id, "legacy-hash".to_string(), None)
        .await
        .expect("old token");

    let expires_at = Some(Utc::now() + ChronoDuration::minutes(10));
    let response = token_service::rotate_node_token(
        &state,
        token_service::RotateNodeTokenRequest {
            node_id,
            expires_at,
            disable_existing: true,
        },
    )
    .await
    .expect("rotate");

    assert_eq!(response.expires_at, expires_at);
    assert!(!response.token.is_empty(), "token should be returned");

    let updated = nodes::get_node(&db, node_id)
        .await
        .expect("node fetch")
        .expect("node exists");
    let matched = match_token(&response.token, &updated.token_hash, &state.token_pepper)
        .expect("match")
        .expect("token should match");
    assert!(
        matches!(matched, TokenMatch::Argon2),
        "expected argon2 match"
    );

    let old_record = tokens::get_node_token(&db, old.id)
        .await
        .expect("old token fetch")
        .expect("old token exists");
    assert!(
        old_record.disabled_at.is_some(),
        "old token should be disabled"
    );
}

#[tokio::test]
async fn rotate_node_token_rejects_past_expiration() {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");
    let migration_outcome = migrations::run_migrations(&db).await.expect("migrations");
    let state = make_state(db, &TestAppConfig::default(), migration_outcome.snapshot);

    let err = token_service::rotate_node_token(
        &state,
        token_service::RotateNodeTokenRequest {
            node_id: Uuid::new_v4(),
            expires_at: Some(Utc::now() - ChronoDuration::seconds(1)),
            disable_existing: false,
        },
    )
    .await
    .expect_err("should fail");

    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(
        err.message.contains("expires_at"),
        "unexpected message: {}",
        err.message
    );
}

#[tokio::test]
async fn rotate_node_token_errors_when_node_missing() {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");
    let migration_outcome = migrations::run_migrations(&db).await.expect("migrations");
    let state = make_state(db, &TestAppConfig::default(), migration_outcome.snapshot);

    let err = token_service::rotate_node_token(
        &state,
        token_service::RotateNodeTokenRequest {
            node_id: Uuid::new_v4(),
            expires_at: None,
            disable_existing: false,
        },
    )
    .await
    .expect_err("should fail");

    assert_eq!(err.status, StatusCode::NOT_FOUND);
    assert!(
        err.message.contains("node not found"),
        "unexpected message: {}",
        err.message
    );
}

#[tokio::test]
async fn compatibility_headers_include_configured_values() {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");
    let migration_outcome = migrations::run_migrations(&db).await.expect("migrations");
    let config = TestAppConfig {
        compat_min: Some("1.2.3".to_string()),
        compat_max: Some("1.2.5".to_string()),
        compat_upgrade_url: Some("https://example.com/upgrade".to_string()),
        ..Default::default()
    };
    let state = make_state(db, &config, migration_outcome.snapshot);

    let mut headers = HeaderMap::new();
    compatibility::add_headers(&state, &mut headers);

    assert_eq!(
        headers.get("x-control-plane-version").unwrap(),
        control_plane::version::VERSION
    );
    assert_eq!(headers.get("x-agent-compat-min").unwrap(), "1.2.3");
    assert_eq!(headers.get("x-agent-compat-max").unwrap(), "1.2.5");
    assert_eq!(
        headers.get("x-agent-compat-upgrade-url").unwrap(),
        "https://example.com/upgrade"
    );
}

#[tokio::test]
async fn compatibility_headers_skip_invalid_upgrade_url() {
    let db = migrations::init_pool("sqlite::memory:")
        .await
        .expect("db init");
    let migration_outcome = migrations::run_migrations(&db).await.expect("migrations");
    let config = TestAppConfig {
        compat_min: Some("1.2.3".to_string()),
        compat_max: Some("1.2.5".to_string()),
        compat_upgrade_url: Some("https://example.com/upgrade\nbad".to_string()),
        ..Default::default()
    };
    let state = make_state(db, &config, migration_outcome.snapshot);

    let mut headers = HeaderMap::new();
    compatibility::add_headers(&state, &mut headers);

    assert_eq!(
        headers.get("x-control-plane-version").unwrap(),
        control_plane::version::VERSION
    );
    assert_eq!(headers.get("x-agent-compat-min").unwrap(), "1.2.3");
    assert_eq!(headers.get("x-agent-compat-max").unwrap(), "1.2.5");
    assert!(
        headers.get("x-agent-compat-upgrade-url").is_none(),
        "invalid upgrade url should be omitted"
    );
}
