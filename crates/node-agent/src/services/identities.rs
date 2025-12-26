use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::{api::ServiceIdentityBundle, config::AppConfig, state::SharedState, telemetry};

const CERT_FILENAME: &str = "cert.pem";
const KEY_FILENAME: &str = "key.pem";
const CA_FILENAME: &str = "ca.pem";

/// Periodically writes service identity bundles to disk and nudges Envoy to
/// pick up changes via file watches. Does not log key material.
pub async fn service_identity_loop(
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
    http: Client,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut last_applied_fp: Option<String> = None;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                if let Err(err) = sync_bundles(&state, &http, &mut last_applied_fp).await {
                    warn!(?err, "service identity sync failed");
                    telemetry::record_identity_refresh("error");
                }
            }
        }
    }

    Ok(())
}

async fn sync_bundles(
    state: &SharedState,
    http: &Client,
    last_applied_fp: &mut Option<String>,
) -> anyhow::Result<()> {
    let (cfg, bundles, fingerprint) = {
        let guard = state.lock().await;
        (
            guard.cfg.clone(),
            guard.service_identities.clone(),
            guard.service_identities_fingerprint.clone(),
        )
    };

    if bundles.is_empty() {
        return Ok(());
    }

    if fingerprint.is_some() && fingerprint == *last_applied_fp {
        return Ok(()); // nothing new
    }

    let changed = persist_bundles(&cfg, &bundles)?;
    if changed {
        info!(count = bundles.len(), "service identities updated on disk");
        nudge_envoy(&cfg, http).await?;
    }

    *last_applied_fp = fingerprint;
    telemetry::record_identity_refresh("success");
    Ok(())
}

/// Writes bundles to the configured directory, replacing outdated entries and
/// pruning removed identities. Returns true when filesystem content changed.
fn persist_bundles(cfg: &AppConfig, bundles: &[ServiceIdentityBundle]) -> anyhow::Result<bool> {
    let root = PathBuf::from(&cfg.service_identity_dir);
    fs::create_dir_all(&root).context("create service_identity_dir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&root)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&root, perms).ok();
    }

    let mut seen = HashSet::new();
    let mut changed = false;

    for bundle in bundles {
        let dir = root.join(sanitize(&bundle.identity));
        seen.insert(dir.clone());
        fs::create_dir_all(&dir).with_context(|| format!("create dir for {}", bundle.identity))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&dir, perms).ok();
        }

        changed |= write_if_changed(&dir.join(CERT_FILENAME), bundle.cert_pem.as_bytes(), 0o644)?;
        changed |= write_if_changed(&dir.join(KEY_FILENAME), bundle.key_pem.as_bytes(), 0o600)?;

        if let Some(ca) = bundle.ca_pem.as_ref() {
            changed |= write_if_changed(&dir.join(CA_FILENAME), ca.as_bytes(), 0o644)?;
        } else if dir.join(CA_FILENAME).exists() {
            fs::remove_file(dir.join(CA_FILENAME)).ok();
            changed = true;
        }
    }

    // prune stale identities
    if let Ok(entries) = fs::read_dir(&root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !seen.contains(&path) {
                fs::remove_dir_all(&path).ok();
                changed = true;
            }
        }
    }

    Ok(changed)
}

fn write_if_changed(path: &Path, data: &[u8], mode: u32) -> anyhow::Result<bool> {
    let existing = fs::read(path).ok();
    if let Some(current) = existing
        && current == data
    {
        return Ok(false);
    }

    let parent = path.parent().context("path missing parent")?;
    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    fs::write(tmp.path(), data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode)).ok();
    }
    tmp.persist(path)?;
    Ok(true)
}

fn sanitize(identity: &str) -> String {
    let mut filtered = String::with_capacity(identity.len());
    let mut last_dash = false;
    for c in identity.chars() {
        let mapped = if c.is_ascii_alphanumeric() { c } else { '-' };
        if mapped == '-' {
            if last_dash {
                continue;
            }
            last_dash = true;
            filtered.push('-');
        } else {
            last_dash = false;
            filtered.push(mapped);
        }
    }
    let mut trimmed = filtered.trim_matches('-').to_string();
    if trimmed.is_empty() {
        trimmed.push_str("identity");
    }
    if trimmed.len() > 80 {
        trimmed.truncate(80);
    }
    trimmed
}

async fn nudge_envoy(cfg: &AppConfig, http: &Client) -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{}/ready", cfg.gateway.admin_port);
    let _ = http.get(url).timeout(Duration::from_secs(1)).send().await;
    // Envoy reloads SDS/file secrets automatically on write; the probe above is
    // only to surface readiness issues in logs/metrics via the gateway loop.
    Ok(())
}

/// Returns the earliest rotate_after to help tests assert refresh ordering.
#[allow(dead_code)]
fn earliest_rotation(bundles: &[ServiceIdentityBundle]) -> Option<DateTime<Utc>> {
    bundles.iter().filter_map(|b| b.rotate_after).min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state,
        test_support::{MockRuntime, base_config, state_with_runtime_and_config},
    };
    use httpmock::{Method::GET, MockServer};

    #[test]
    fn persist_writes_files_with_permissions() {
        let mut cfg = base_config();
        let dir = tempfile::tempdir().unwrap();
        cfg.service_identity_dir = dir.path().to_string_lossy().to_string();

        let bundle = ServiceIdentityBundle {
            identity: "service://tenant/app".into(),
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            ca_pem: Some("CA".into()),
            expires_at: None,
            rotate_after: None,
        };

        let changed = persist_bundles(&cfg, &[bundle]).expect("persist");
        assert!(changed, "first write should mark changed");

        let base = dir.path().join("service-tenant-app");
        assert_eq!(fs::read(base.join(CERT_FILENAME)).unwrap(), b"CERT");
        assert_eq!(fs::read(base.join(KEY_FILENAME)).unwrap(), b"KEY");
        assert_eq!(fs::read(base.join(CA_FILENAME)).unwrap(), b"CA");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key_mode = fs::metadata(base.join(KEY_FILENAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(key_mode, 0o600);
        }
    }

    #[test]
    fn persist_prunes_removed_bundles() {
        let mut cfg = base_config();
        let dir = tempfile::tempdir().unwrap();
        cfg.service_identity_dir = dir.path().to_string_lossy().to_string();

        let first = ServiceIdentityBundle {
            identity: "one".into(),
            cert_pem: "A".into(),
            key_pem: "B".into(),
            ca_pem: None,
            expires_at: None,
            rotate_after: None,
        };
        let second = ServiceIdentityBundle {
            identity: "two".into(),
            cert_pem: "C".into(),
            key_pem: "D".into(),
            ca_pem: None,
            expires_at: None,
            rotate_after: None,
        };

        persist_bundles(&cfg, &[first.clone(), second.clone()]).expect("persist");
        assert!(
            dir.path().join("one").exists() || dir.path().join("one").join(CERT_FILENAME).exists()
        );

        persist_bundles(&cfg, &[second]).expect("persist second");
        assert!(
            !dir.path().join("one").exists(),
            "stale bundle should be pruned"
        );
    }

    #[test]
    fn persist_returns_false_when_unchanged() {
        let mut cfg = base_config();
        let dir = tempfile::tempdir().unwrap();
        cfg.service_identity_dir = dir.path().to_string_lossy().to_string();

        let bundle = ServiceIdentityBundle {
            identity: "svc".into(),
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            ca_pem: Some("CA".into()),
            expires_at: None,
            rotate_after: None,
        };

        let changed = persist_bundles(&cfg, std::slice::from_ref(&bundle)).expect("persist");
        assert!(changed);

        let changed_again = persist_bundles(&cfg, &[bundle]).expect("persist again");
        assert!(!changed_again);
    }

    #[test]
    fn sanitize_replaces_invalid_chars_and_trims() {
        assert_eq!(sanitize("service://tenant/app"), "service-tenant-app");
        assert_eq!(sanitize("!!!"), "identity");

        let long = "a".repeat(200);
        let sanitized = sanitize(&long);
        assert!(sanitized.len() <= 80);
    }

    #[test]
    fn write_if_changed_detects_updates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");

        let first = write_if_changed(&path, b"one", 0o644).expect("write");
        assert!(first);
        let second = write_if_changed(&path, b"one", 0o644).expect("rewrite");
        assert!(!second);
        let third = write_if_changed(&path, b"two", 0o644).expect("update");
        assert!(third);
    }

    #[test]
    fn earliest_rotation_picks_min_timestamp() {
        let now = Utc::now();
        let bundles = vec![
            ServiceIdentityBundle {
                identity: "a".into(),
                cert_pem: "C".into(),
                key_pem: "K".into(),
                ca_pem: None,
                expires_at: None,
                rotate_after: Some(now + chrono::Duration::seconds(30)),
            },
            ServiceIdentityBundle {
                identity: "b".into(),
                cert_pem: "C".into(),
                key_pem: "K".into(),
                ca_pem: None,
                expires_at: None,
                rotate_after: Some(now + chrono::Duration::seconds(10)),
            },
        ];

        let earliest = earliest_rotation(&bundles).expect("rotation");
        assert!(earliest <= now + chrono::Duration::seconds(10));
    }

    #[tokio::test]
    async fn sync_bundles_writes_and_nudges_on_change() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path("/ready");
                then.status(200);
            })
            .await;

        let mut cfg = base_config();
        let dir = tempfile::tempdir().unwrap();
        cfg.service_identity_dir = dir.path().to_string_lossy().to_string();
        cfg.gateway.admin_port = server.port();

        let runtime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, cfg);

        let bundle = ServiceIdentityBundle {
            identity: "service://tenant/app".into(),
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            ca_pem: Some("CA".into()),
            expires_at: None,
            rotate_after: None,
        };

        state::set_service_identities(&state, vec![bundle], Some("fp1".into())).await;

        let mut last_applied_fp = None;
        sync_bundles(&state, &Client::new(), &mut last_applied_fp)
            .await
            .expect("sync succeeds");

        assert_eq!(last_applied_fp.as_deref(), Some("fp1"));
        mock.assert_async().await;

        let base = dir.path().join("service-tenant-app");
        assert!(base.join(CERT_FILENAME).exists());
        assert!(base.join(KEY_FILENAME).exists());
        assert!(base.join(CA_FILENAME).exists());
    }

    #[tokio::test]
    async fn sync_bundles_skips_when_fingerprint_matches() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path("/ready");
                then.status(200);
            })
            .await;

        let mut cfg = base_config();
        let dir = tempfile::tempdir().unwrap();
        cfg.service_identity_dir = dir.path().to_string_lossy().to_string();
        cfg.gateway.admin_port = server.port();

        let runtime = std::sync::Arc::new(MockRuntime::default());
        let state = state_with_runtime_and_config(runtime, cfg);

        let bundle = ServiceIdentityBundle {
            identity: "service://tenant/app".into(),
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            ca_pem: None,
            expires_at: None,
            rotate_after: None,
        };

        state::set_service_identities(&state, vec![bundle], Some("fp1".into())).await;

        let mut last_applied_fp = Some("fp1".into());
        sync_bundles(&state, &Client::new(), &mut last_applied_fp)
            .await
            .expect("sync succeeds");

        assert_eq!(last_applied_fp.as_deref(), Some("fp1"));
        assert_eq!(mock.calls(), 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
