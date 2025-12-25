use crate::args::{
    BootstrapRepoOwnerCommands, BootstrapRepoOwnerSetArgs, ProfileCommands, ProfileSetArgs,
    ProfileSetDefaultArgs, ProfileShowArgs,
};
use crate::profile_store::{Profile, ProfileStore};

pub fn handle_profiles(
    selected_profile: Option<String>,
    command: ProfileCommands,
) -> anyhow::Result<()> {
    let mut store = ProfileStore::load()?;

    match command {
        ProfileCommands::List => {
            if let Some(default) = store.default_profile.as_deref() {
                println!("default_profile: {}", default);
            } else {
                println!("default_profile: <unset>");
            }

            if let Some(owner) = store.bootstrap_repo_owner.as_deref() {
                println!("bootstrap_repo_owner: {}", owner);
            } else {
                println!("bootstrap_repo_owner: <unset>");
            }

            if store.profiles.is_empty() {
                println!("profiles: <none>");
                return Ok(());
            }

            println!("profiles:");
            for name in store.profiles.keys() {
                println!("- {}", name);
            }
        }
        ProfileCommands::Show(ProfileShowArgs { name }) => {
            let name = name
                .or(selected_profile)
                .or_else(|| store.default_profile.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!("no profile selected and default_profile is unset")
                })?;

            let profile = store
                .profiles
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("profile '{}' not found", name))?;

            println!("name: {}", name);
            if let Some(url) = profile.control_plane_url.as_deref() {
                println!("control_plane_url: {}", url);
            }
            if let Some(header) = profile.operator_header.as_deref() {
                println!("operator_header: {}", header);
            }
            if profile.operator_token.is_some() {
                println!("operator_token: <set>");
            }
            if profile.registration_token.is_some() {
                println!("registration_token: <set>");
            }
            if let Some(path) = profile.ca_cert_path.as_deref() {
                println!("ca_cert_path: {}", path);
            }
        }
        ProfileCommands::Set(ProfileSetArgs {
            name,
            control_plane_url,
            operator_header,
            operator_token,
            registration_token,
            ca_cert_path,
        }) => {
            let entry = store
                .profiles
                .entry(name.clone())
                .or_insert_with(Profile::default);
            if control_plane_url.is_some() {
                entry.control_plane_url = control_plane_url;
            }
            if operator_header.is_some() {
                entry.operator_header = operator_header;
            }
            if operator_token.is_some() {
                entry.operator_token = operator_token;
            }
            if registration_token.is_some() {
                entry.registration_token = registration_token;
            }
            if ca_cert_path.is_some() {
                entry.ca_cert_path = ca_cert_path;
            }

            if store.default_profile.is_none() {
                store.default_profile = Some(name.clone());
            }
            store.save()?;
            println!("updated profile: {}", name);
        }
        ProfileCommands::SetDefault(ProfileSetDefaultArgs { name }) => {
            if !store.profiles.contains_key(&name) {
                anyhow::bail!(
                    "profile '{}' not found (create it via `fledx profile set`)",
                    name
                );
            }
            store.default_profile = Some(name.clone());
            store.save()?;
            println!("default_profile set to: {}", name);
        }
        ProfileCommands::BootstrapRepoOwner { command } => match command {
            BootstrapRepoOwnerCommands::Show => {
                if let Some(owner) = store.bootstrap_repo_owner.as_deref() {
                    println!("bootstrap_repo_owner: {}", owner);
                } else {
                    println!("bootstrap_repo_owner: <unset>");
                }
            }
            BootstrapRepoOwnerCommands::Set(BootstrapRepoOwnerSetArgs { owner }) => {
                let owner = owner.trim();
                if owner.is_empty() {
                    anyhow::bail!("invalid owner (empty)");
                }
                if owner.contains('/') {
                    anyhow::bail!("invalid owner (must not contain '/'): {}", owner);
                }
                store.bootstrap_repo_owner = Some(owner.to_string());
                store.save()?;
                println!("bootstrap_repo_owner set to: {}", owner);
            }
            BootstrapRepoOwnerCommands::Unset => {
                store.bootstrap_repo_owner = None;
                store.save()?;
                println!("bootstrap_repo_owner unset");
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{BootstrapRepoOwnerCommands, BootstrapRepoOwnerSetArgs};
    use crate::test_support::ENV_LOCK;
    use tempfile::tempdir;

    fn with_temp_config<F: FnOnce()>(f: F) {
        let _guard = ENV_LOCK.lock().expect("lock");
        let dir = tempdir().expect("tempdir");
        // SAFETY: Tests hold ENV_LOCK to serialize env mutations.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
            std::env::remove_var("HOME");
        }
        f();
    }

    #[test]
    fn list_profiles_handles_empty_store() {
        with_temp_config(|| {
            handle_profiles(None, ProfileCommands::List).expect("list");
        });
    }

    #[test]
    fn set_profile_persists_and_sets_default() {
        with_temp_config(|| {
            handle_profiles(
                None,
                ProfileCommands::Set(ProfileSetArgs {
                    name: "prod".into(),
                    control_plane_url: Some("https://cp.example".into()),
                    operator_header: Some("authorization".into()),
                    operator_token: Some("token".into()),
                    registration_token: Some("reg".into()),
                    ca_cert_path: Some("/etc/ca.pem".into()),
                }),
            )
            .expect("set");

            let loaded = ProfileStore::load().expect("load");
            assert_eq!(loaded.default_profile.as_deref(), Some("prod"));
            assert!(loaded.profiles.contains_key("prod"));
        });
    }

    #[test]
    fn show_profile_errors_without_selection() {
        with_temp_config(|| {
            let err = handle_profiles(None, ProfileCommands::Show(ProfileShowArgs { name: None }))
                .expect_err("should fail");
            assert!(err.to_string().contains("default_profile is unset"));
        });
    }

    #[test]
    fn set_default_requires_existing_profile() {
        with_temp_config(|| {
            let err = handle_profiles(
                None,
                ProfileCommands::SetDefault(ProfileSetDefaultArgs {
                    name: "missing".into(),
                }),
            )
            .expect_err("should fail");
            assert!(err.to_string().contains("profile 'missing' not found"));
        });
    }

    #[test]
    fn bootstrap_repo_owner_set_and_unset() {
        with_temp_config(|| {
            handle_profiles(
                None,
                ProfileCommands::BootstrapRepoOwner {
                    command: BootstrapRepoOwnerCommands::Set(BootstrapRepoOwnerSetArgs {
                        owner: "acme".into(),
                    }),
                },
            )
            .expect("set owner");

            let loaded = ProfileStore::load().expect("load");
            assert_eq!(loaded.bootstrap_repo_owner.as_deref(), Some("acme"));

            handle_profiles(
                None,
                ProfileCommands::BootstrapRepoOwner {
                    command: BootstrapRepoOwnerCommands::Unset,
                },
            )
            .expect("unset owner");

            let loaded = ProfileStore::load().expect("load");
            assert!(loaded.bootstrap_repo_owner.is_none());
        });
    }

    #[test]
    fn bootstrap_repo_owner_rejects_invalid_values() {
        with_temp_config(|| {
            let err = handle_profiles(
                None,
                ProfileCommands::BootstrapRepoOwner {
                    command: BootstrapRepoOwnerCommands::Set(BootstrapRepoOwnerSetArgs {
                        owner: "  ".into(),
                    }),
                },
            )
            .expect_err("empty owner");
            assert!(err.to_string().contains("invalid owner"));

            let err = handle_profiles(
                None,
                ProfileCommands::BootstrapRepoOwner {
                    command: BootstrapRepoOwnerCommands::Set(BootstrapRepoOwnerSetArgs {
                        owner: "bad/owner".into(),
                    }),
                },
            )
            .expect_err("slash owner");
            assert!(err.to_string().contains("must not contain '/'"));
        });
    }
}
