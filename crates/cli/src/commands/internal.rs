use serde::Serialize;

use crate::args::InternalCommands;

#[derive(Debug, Serialize)]
struct ReleaseSigningKeysStatusView {
    configured: bool,
    source: &'static str,
    env_present: bool,
}

pub fn handle_internal(command: InternalCommands) -> anyhow::Result<()> {
    match command {
        InternalCommands::ReleaseSigningKeys { json } => {
            let status = installer::bootstrap::release_signing_keys_status()?;
            let view = ReleaseSigningKeysStatusView {
                configured: status.configured,
                source: status.source.as_str(),
                env_present: status.env_present,
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                let state = if status.configured {
                    "configured"
                } else {
                    "missing"
                };
                println!("release signing keys: {state}");
                println!("source: {}", view.source);
                if status.env_present
                    && matches!(
                        status.source,
                        installer::bootstrap::ReleaseSigningKeysSource::Compiled
                    )
                {
                    println!("note: runtime env var is set but build-time keys are in use");
                }
            }

            if status.configured {
                Ok(())
            } else {
                anyhow::bail!("release signing keys are not configured")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE_SIGNING_KEYS_ENV: &str = "FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS";

    fn with_release_keys_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        let original = std::env::var(RELEASE_SIGNING_KEYS_ENV).ok();
        // SAFETY: Tests hold ENV_LOCK to serialize env mutations.
        unsafe {
            match value {
                Some(value) => std::env::set_var(RELEASE_SIGNING_KEYS_ENV, value),
                None => std::env::remove_var(RELEASE_SIGNING_KEYS_ENV),
            }
        }
        let out = f();
        // SAFETY: Tests hold ENV_LOCK to serialize env mutations.
        unsafe {
            match original {
                Some(value) => std::env::set_var(RELEASE_SIGNING_KEYS_ENV, value),
                None => std::env::remove_var(RELEASE_SIGNING_KEYS_ENV),
            }
        }
        out
    }

    #[test]
    fn release_signing_keys_status_view_serializes_fields() {
        let view = ReleaseSigningKeysStatusView {
            configured: true,
            source: "compiled",
            env_present: false,
        };
        let json = serde_json::to_string_pretty(&view).expect("json");
        assert!(json.contains("\"configured\": true"));
        assert!(json.contains("\"source\": \"compiled\""));
        assert!(json.contains("\"env_present\": false"));
    }

    #[test]
    fn handle_internal_json_matches_status() {
        with_release_keys_env(None, || {
            let status = installer::bootstrap::release_signing_keys_status().expect("status");
            let result = handle_internal(InternalCommands::ReleaseSigningKeys { json: true });
            assert_eq!(result.is_ok(), status.configured);
        });
    }

    #[test]
    fn handle_internal_text_matches_status() {
        with_release_keys_env(None, || {
            let status = installer::bootstrap::release_signing_keys_status().expect("status");
            let result = handle_internal(InternalCommands::ReleaseSigningKeys { json: false });
            assert_eq!(result.is_ok(), status.configured);
        });
    }
}
