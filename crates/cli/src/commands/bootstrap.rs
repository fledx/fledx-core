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
}
