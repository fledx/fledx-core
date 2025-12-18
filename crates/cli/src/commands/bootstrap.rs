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
    let repo_owner = root
        .repo_owner
        .clone()
        .or_else(|| profiles.bootstrap_repo_owner.clone());
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
