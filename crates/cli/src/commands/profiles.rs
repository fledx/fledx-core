use crate::args::{ProfileCommands, ProfileSetArgs, ProfileSetDefaultArgs, ProfileShowArgs};
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
        }
        ProfileCommands::Set(ProfileSetArgs {
            name,
            control_plane_url,
            operator_header,
            operator_token,
            registration_token,
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
    }

    Ok(())
}
