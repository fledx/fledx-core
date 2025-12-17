use crate::args::BootstrapCommands;
use crate::bootstrap_flow;
use crate::profile_store::ProfileStore;

pub async fn handle_bootstrap(
    client: reqwest::Client,
    selected_profile: Option<String>,
    globals: &crate::GlobalArgs,
    command: BootstrapCommands,
) -> anyhow::Result<()> {
    let mut profiles = ProfileStore::load()?;

    match command {
        BootstrapCommands::Cp(args) => {
            bootstrap_flow::bootstrap_cp(&client, &mut profiles, selected_profile, globals, args)
                .await?
        }
        BootstrapCommands::Agent(args) => {
            bootstrap_flow::bootstrap_agent(&client, &mut profiles, selected_profile, globals, args)
                .await?
        }
    }

    Ok(())
}
