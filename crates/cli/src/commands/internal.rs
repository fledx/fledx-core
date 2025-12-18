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
