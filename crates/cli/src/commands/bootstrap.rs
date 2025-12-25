use crate::args::BootstrapCommands;
use crate::args::BootstrapRootArgs;
use crate::bootstrap_flow;
use crate::bootstrap_spec::BootstrapReleaseSpec;
use crate::profile_store::ProfileStore;

pub async fn handle_bootstrap(
    client: reqwest::Client,
    selected_profile: Option<String>,
    globals: &crate::GlobalArgs,
    spec: BootstrapReleaseSpec,
    root: BootstrapRootArgs,
    command: BootstrapCommands,
) -> anyhow::Result<()> {
    let mut profiles = ProfileStore::load()?;
    let repo_owner = resolve_repo_owner(&root, &profiles);
    let repo_owner = repo_owner.as_deref();

    match command {
        BootstrapCommands::Cp(args) => {
            bootstrap_flow::bootstrap_cp(
                &client,
                &mut profiles,
                selected_profile,
                globals,
                args,
                spec,
                repo_owner,
            )
            .await?
        }
        BootstrapCommands::Agent(args) => {
            bootstrap_flow::bootstrap_agent(
                &client,
                &mut profiles,
                selected_profile,
                globals,
                args,
                spec,
                repo_owner,
            )
            .await?
        }
    }

    Ok(())
}

fn resolve_repo_owner(root: &BootstrapRootArgs, profiles: &ProfileStore) -> Option<String> {
    root.repo_owner
        .clone()
        .or_else(|| profiles.bootstrap_repo_owner.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn resolve_repo_owner_prefers_root_value() {
        let root = BootstrapRootArgs {
            repo_owner: Some("from-root".to_string()),
        };
        let profiles = ProfileStore {
            bootstrap_repo_owner: Some("from-profile".to_string()),
            ..Default::default()
        };

        let resolved = resolve_repo_owner(&root, &profiles);
        assert_eq!(resolved.as_deref(), Some("from-root"));
    }

    #[test]
    fn resolve_repo_owner_uses_profile_when_root_missing() {
        let root = BootstrapRootArgs { repo_owner: None };
        let profiles = ProfileStore {
            bootstrap_repo_owner: Some("from-profile".to_string()),
            ..Default::default()
        };

        let resolved = resolve_repo_owner(&root, &profiles);
        assert_eq!(resolved.as_deref(), Some("from-profile"));
    }

    #[test]
    fn resolve_repo_owner_returns_none_when_missing() {
        let root = BootstrapRootArgs { repo_owner: None };
        let profiles = ProfileStore::default();

        let resolved = resolve_repo_owner(&root, &profiles);
        assert!(resolved.is_none());
    }

    #[test]
    fn handle_bootstrap_rejects_empty_repo_override() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        let dir = tempfile::tempdir().expect("tempdir");
        // SAFETY: Tests hold ENV_LOCK to serialize env mutations.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
            std::env::remove_var("HOME");
        }

        let globals = crate::GlobalArgs {
            control_plane_url: "http://127.0.0.1:49421".into(),
            operator_token: None,
            operator_header: "authorization".into(),
            registration_token: None,
            ca_cert_path: None,
        };

        let args = crate::args::BootstrapCpArgs {
            cp_hostname: "127.0.0.1".into(),
            ssh_host: None,
            ssh_user: None,
            ssh_port: 22,
            ssh_identity_file: None,
            ssh_interactive: false,
            ssh_connect_timeout_secs: 10,
            ssh_host_key_checking: crate::args::SshHostKeyChecking::Strict,
            version: None,
            repo: Some("   ".into()),
            repo_owner: None,
            archive_template: None,
            bin_dir: PathBuf::from("/usr/local/bin"),
            config_dir: PathBuf::from("/etc/fledx"),
            data_dir: PathBuf::from("/var/lib/fledx"),
            server_port: 49421,
            tunnel_port: 49423,
            service_user: "fledx-cp".into(),
            tokens_pepper: None,
            sudo_interactive: false,
            insecure_allow_unsigned: false,
            no_wait: true,
            wait_timeout_secs: 1,
        };

        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let err = runtime
            .block_on(handle_bootstrap(
                reqwest::Client::new(),
                None,
                &globals,
                crate::bootstrap_spec::BootstrapReleaseSpec::core(),
                BootstrapRootArgs { repo_owner: None },
                BootstrapCommands::Cp(args),
            ))
            .expect_err("should fail");

        assert!(err.to_string().contains("invalid --repo (empty)"));
    }
}
