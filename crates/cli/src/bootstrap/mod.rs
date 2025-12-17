use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;

use crate::args::{BootstrapAgentArgs, BootstrapCpArgs};
use crate::profile_store::{Profile, ProfileStore};

const CORE_REPO: &str = "fledx/fledx-core";

pub async fn bootstrap_cp(
    client: &reqwest::Client,
    profiles: &mut ProfileStore,
    selected_profile: Option<String>,
    globals: &crate::GlobalArgs,
    args: BootstrapCpArgs,
) -> anyhow::Result<()> {
    let target = match &args.ssh_host {
        Some(host) => installer::bootstrap::InstallTarget::Ssh(installer::bootstrap::SshTarget::from_user_at_host(
            host,
            args.ssh_user.clone(),
            args.ssh_port,
            args.ssh_identity_file.clone(),
        )),
        None => installer::bootstrap::InstallTarget::Local,
    };

    let arch = target.detect_arch(args.sudo_interactive)?;

    let release = installer::bootstrap::fetch_release(client, CORE_REPO, args.version.as_deref())
        .await?;
    let version = installer::bootstrap::normalize_version(&release.tag_name);
    let archive_name = format!("fledx-cp-{}-{}-linux.tar.gz", version, arch.as_str());

    let dir = tempfile::tempdir()?;
    let archive_path = dir.path().join(&archive_name);
    let sha_path = dir.path().join(format!("{archive_name}.sha256"));
    let sha_sig_path = dir.path().join(format!("{archive_name}.sha256.sig"));

    installer::bootstrap::download_asset(client, CORE_REPO, &release, &archive_name, &archive_path)
        .await?;
    installer::bootstrap::download_asset(
        client,
        CORE_REPO,
        &release,
        &format!("{archive_name}.sha256"),
        &sha_path,
    )
    .await?;
    if args.insecure_allow_unsigned {
        installer::bootstrap::verify_sha256(
            CORE_REPO,
            &release.tag_name,
            &archive_name,
            &archive_path,
            &sha_path,
        )?;
    } else {
        installer::bootstrap::download_asset(
            client,
            CORE_REPO,
            &release,
            &format!("{archive_name}.sha256.sig"),
            &sha_sig_path,
        )
        .await?;
        installer::bootstrap::verify_signed_sha256(
            CORE_REPO,
            &release.tag_name,
            &archive_name,
            &archive_path,
            &sha_path,
            &sha_sig_path,
        )?;
    }

    let extracted = installer::bootstrap::extract_single_file(&archive_path, "fledx-cp", dir.path())
        .with_context(|| {
            format!(
                "failed to extract fledx-cp from {}@{} asset {}",
                CORE_REPO, release.tag_name, archive_name
            )
        })?;

    let registration_token = globals
        .registration_token
        .clone()
        .unwrap_or_else(|| installer::bootstrap::generate_token_hex(16));
    let operator_token = globals
        .operator_token
        .clone()
        .unwrap_or_else(|| installer::bootstrap::generate_token_hex(16));
    let tokens_pepper = args
        .tokens_pepper
        .clone()
        .unwrap_or_else(|| installer::bootstrap::generate_token_hex(32));

    let tunnel_bind_host = installer::bootstrap::resolve_ipv4_host(&args.cp_hostname)?;

    let cp_data_dir = args.data_dir.join("cp");
    let db_path = cp_data_dir.join("control-plane.db");
    let db_url = format!("sqlite:///{}", db_path.display());

    let env = render_cp_env(&CpEnvInputs {
        server_port: args.server_port,
        tunnel_host: tunnel_bind_host,
        tunnel_port: args.tunnel_port,
        db_url,
        registration_token: registration_token.clone(),
        operator_token: operator_token.clone(),
        operator_header: globals.operator_header.clone(),
        tokens_pepper,
        public_host: args.cp_hostname.clone(),
    });

    let unit = render_cp_unit(&CpUnitInputs {
        service_user: args.service_user.clone(),
        env_path: args.config_dir.join("fledx-cp.env"),
        bin_path: args.bin_dir.join("fledx-cp"),
    });

    let settings = installer::bootstrap::ControlPlaneInstallSettings {
        bin_dir: args.bin_dir.clone(),
        config_dir: args.config_dir.clone(),
        data_dir: args.data_dir.clone(),
        service_user: args.service_user.clone(),
        sudo_interactive: args.sudo_interactive,
    };

    match &target {
        installer::bootstrap::InstallTarget::Local => {
            installer::bootstrap::install_cp_local(&extracted, &env, &unit, &settings)?
        }
        installer::bootstrap::InstallTarget::Ssh(ssh) => {
            installer::bootstrap::install_cp_ssh(ssh, &extracted, &env, &unit, &settings)?
        }
    }

    if !args.no_wait {
        let timeout = Duration::from_secs(args.wait_timeout_secs);
        installer::bootstrap::wait_for_systemd_active(&target, "fledx-cp", timeout).await?;

        let cp_url = format!("http://{}:{}", args.cp_hostname, args.server_port);
        installer::bootstrap::wait_for_http_ok(
            client,
            &installer::bootstrap::health_url(&cp_url),
            timeout,
        )
        .await?;
    }

    let profile_name = selected_profile
        .or_else(|| profiles.default_profile.clone())
        .unwrap_or_else(|| "default".to_string());

    let cp_url = format!("http://{}:{}", args.cp_hostname, args.server_port);
    let entry = profiles
        .profiles
        .entry(profile_name.clone())
        .or_insert_with(Profile::default);
    entry.control_plane_url = Some(cp_url);
    entry.operator_header = Some(globals.operator_header.clone());
    entry.operator_token = Some(operator_token);
    entry.registration_token = Some(registration_token);
    profiles.default_profile = Some(profile_name.clone());
    profiles.save()?;

    println!("control-plane installed (core) version {}", version);
    println!("profile updated: {}", profile_name);
    Ok(())
}

pub async fn bootstrap_agent(
    client: &reqwest::Client,
    _profiles: &mut ProfileStore,
    _selected_profile: Option<String>,
    globals: &crate::GlobalArgs,
    args: BootstrapAgentArgs,
) -> anyhow::Result<()> {
    let Some(registration_token) = globals.registration_token.clone() else {
        anyhow::bail!(
            "registration token is required for bootstrap; pass --registration-token, set FLEDX_CLI_REGISTRATION_TOKEN, or configure a profile"
        );
    };

    let ssh = installer::bootstrap::SshTarget::from_user_at_host(
        &args.ssh_host,
        args.ssh_user.clone(),
        args.ssh_port,
        args.ssh_identity_file.clone(),
    );

    if !args.no_wait {
        let timeout = Duration::from_secs(args.wait_timeout_secs);
        installer::bootstrap::wait_for_http_ok(
            client,
            &installer::bootstrap::health_url(&globals.control_plane_url),
            timeout,
        )
        .await?;
    }

    let arch =
        installer::bootstrap::InstallTarget::Ssh(ssh.clone()).detect_arch(args.sudo_interactive)?;

    let requested_from_control_plane = args.version.is_none();
    let requested_version = match args.version.as_deref() {
        Some(v) => v.to_string(),
        None => installer::bootstrap::fetch_control_plane_version(client, &globals.control_plane_url)
            .await
            .context(
                "failed to determine control-plane version (rerun without --no-wait or pass --version latest)",
            )?,
    };

    let release = installer::bootstrap::fetch_release(client, CORE_REPO, Some(&requested_version))
        .await
        .with_context(|| {
            if requested_from_control_plane {
                format!(
                    "failed to resolve agent release matching control-plane version {} (override with --version latest or --version <semver>)",
                    requested_version
                )
            } else {
                format!("failed to resolve agent release version {}", requested_version)
            }
        })?;
    let version = installer::bootstrap::normalize_version(&release.tag_name);
    let archive_name = format!("fledx-agent-{}-{}-linux.tar.gz", version, arch.as_str());

    let dir = tempfile::tempdir()?;
    let archive_path = dir.path().join(&archive_name);
    let sha_path = dir.path().join(format!("{archive_name}.sha256"));
    let sha_sig_path = dir.path().join(format!("{archive_name}.sha256.sig"));

    installer::bootstrap::download_asset(client, CORE_REPO, &release, &archive_name, &archive_path)
        .await?;
    installer::bootstrap::download_asset(
        client,
        CORE_REPO,
        &release,
        &format!("{archive_name}.sha256"),
        &sha_path,
    )
    .await?;
    if args.insecure_allow_unsigned {
        installer::bootstrap::verify_sha256(
            CORE_REPO,
            &release.tag_name,
            &archive_name,
            &archive_path,
            &sha_path,
        )?;
    } else {
        installer::bootstrap::download_asset(
            client,
            CORE_REPO,
            &release,
            &format!("{archive_name}.sha256.sig"),
            &sha_sig_path,
        )
        .await?;
        installer::bootstrap::verify_signed_sha256(
            CORE_REPO,
            &release.tag_name,
            &archive_name,
            &archive_path,
            &sha_path,
            &sha_sig_path,
        )?;
    }

    let extracted =
        installer::bootstrap::extract_single_file(&archive_path, "fledx-agent", dir.path())
            .with_context(|| {
                format!(
                    "failed to extract fledx-agent from {}@{} asset {}",
                    CORE_REPO, release.tag_name, archive_name
                )
            })?;

    let node_name = args.name.clone().unwrap_or_else(|| ssh.host.clone());
    let labels = installer::bootstrap::parse_labels(&args.labels)?;
    let capacity = installer::bootstrap::capacity_from_args(
        args.capacity_cpu_millis,
        args.capacity_memory_bytes,
    );
    let (node_id, node_token, tunnel) = installer::bootstrap::register_node(
        client,
        &globals.control_plane_url,
        &registration_token,
        &node_name,
        arch.as_str(),
        "linux",
        labels,
        capacity,
        &version,
    )
    .await?;

    let cp_host = installer::bootstrap::extract_host_from_url(&globals.control_plane_url)?;
    let agent_env = installer::bootstrap::render_agent_env(&installer::bootstrap::AgentEnvInputs {
        control_plane_url: globals.control_plane_url.clone(),
        node_id,
        node_token,
        allow_insecure_http: globals.control_plane_url.starts_with("http://"),
        volume_dir: args.data_dir.join("volumes"),
        tunnel_host: cp_host,
        tunnel,
    });

    let bin_path = agent_bin_path(&args)?;
    let agent_unit = installer::bootstrap::render_agent_unit(&installer::bootstrap::AgentUnitInputs {
        service_user: args.service_user.clone(),
        env_path: args.config_dir.join("fledx-agent.env"),
        bin_path: bin_path.clone(),
    });

    let settings = installer::bootstrap::AgentInstallSettings {
        config_dir: args.config_dir.clone(),
        data_dir: args.data_dir.clone(),
        service_user: args.service_user.clone(),
        sudo_interactive: args.sudo_interactive,
    };

    installer::bootstrap::install_agent_ssh(
        &ssh,
        &extracted,
        &agent_env,
        &agent_unit,
        &settings,
        &bin_path,
    )?;

    if !args.no_wait {
        let timeout = Duration::from_secs(args.wait_timeout_secs);
        installer::bootstrap::wait_for_systemd_active_ssh(&ssh, "fledx-agent", timeout).await?;
        installer::bootstrap::wait_for_node_tunnel_connected(
            client,
            &globals.control_plane_url,
            node_id,
            timeout,
        )
        .await?;
    }

    println!("agent installed (core) version {}", version);
    println!("node registered: {}", node_id);
    Ok(())
}

fn agent_bin_path(args: &BootstrapAgentArgs) -> anyhow::Result<PathBuf> {
    let path = match &args.install_path {
        Some(path) => path.clone(),
        None => args.bin_dir.join("fledx-agent"),
    };

    if path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .is_empty()
    {
        anyhow::bail!("invalid --install-path (missing file name): {}", path.display());
    }

    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "invalid --install-path (missing parent directory): {}",
            path.display()
        )
    })?;
    if parent.as_os_str().is_empty() {
        anyhow::bail!("invalid --install-path (missing parent directory): {}", path.display());
    }

    Ok(path)
}

fn render_cp_env(input: &CpEnvInputs) -> String {
    let CpEnvInputs {
        server_port,
        tunnel_host,
        tunnel_port,
        db_url,
        registration_token,
        operator_token,
        operator_header,
        tokens_pepper,
        public_host,
    } = input;

    format!(
        "\
FLEDX_CP_SERVER_HOST=0.0.0.0
FLEDX_CP_SERVER_PORT={server_port}
FLEDX_CP_TUNNEL_ADVERTISED_HOST={tunnel_host}
FLEDX_CP_TUNNEL_ADVERTISED_PORT={tunnel_port}
FLEDX_CP_DATABASE_URL={db_url}
FLEDX_CP_REGISTRATION_TOKEN={registration_token}
FLEDX_CP_OPERATOR_TOKENS={operator_token}
FLEDX_CP_OPERATOR_HEADER_NAME={operator_header}
FLEDX_CP_TOKENS_PEPPER={tokens_pepper}
FLEDX_CP_PORTS_PUBLIC_HOST={public_host}
RUST_LOG=info
"
    )
}

struct CpEnvInputs {
    server_port: u16,
    tunnel_host: String,
    tunnel_port: u16,
    db_url: String,
    registration_token: String,
    operator_token: String,
    operator_header: String,
    tokens_pepper: String,
    public_host: String,
}

fn render_cp_unit(input: &CpUnitInputs) -> String {
    let CpUnitInputs {
        service_user,
        env_path,
        bin_path,
    } = input;

    format!(
        "\
[Unit]
Description=Distributed Edge Hosting Control Plane
After=network-online.target
Wants=network-online.target

[Service]
User={service_user}
EnvironmentFile={}
ExecStart={}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
",
        env_path.display(),
        bin_path.display()
    )
}

struct CpUnitInputs {
    service_user: String,
    env_path: PathBuf,
    bin_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_bin_path_defaults_to_bin_dir() {
        let args = BootstrapAgentArgs {
            ssh_host: "root@example.com".into(),
            ssh_user: None,
            ssh_port: 22,
            ssh_identity_file: None,
            name: None,
            version: None,
            bin_dir: PathBuf::from("/usr/local/bin"),
            install_path: None,
            config_dir: PathBuf::from("/etc/fledx"),
            data_dir: PathBuf::from("/var/lib/fledx"),
            service_user: "fledx-agent".into(),
            labels: Vec::new(),
            capacity_cpu_millis: None,
            capacity_memory_bytes: None,
            sudo_interactive: false,
            insecure_allow_unsigned: false,
            no_wait: true,
            wait_timeout_secs: 1,
        };

        let path = agent_bin_path(&args).expect("path");
        assert_eq!(path, PathBuf::from("/usr/local/bin/fledx-agent"));
    }

    #[test]
    fn agent_bin_path_respects_install_path() {
        let args = BootstrapAgentArgs {
            ssh_host: "root@example.com".into(),
            ssh_user: None,
            ssh_port: 22,
            ssh_identity_file: None,
            name: None,
            version: None,
            bin_dir: PathBuf::from("/usr/local/bin"),
            install_path: Some(PathBuf::from("/opt/fledx/bin/fledx-agent")),
            config_dir: PathBuf::from("/etc/fledx"),
            data_dir: PathBuf::from("/var/lib/fledx"),
            service_user: "fledx-agent".into(),
            labels: Vec::new(),
            capacity_cpu_millis: None,
            capacity_memory_bytes: None,
            sudo_interactive: false,
            insecure_allow_unsigned: false,
            no_wait: true,
            wait_timeout_secs: 1,
        };

        let path = agent_bin_path(&args).expect("path");
        assert_eq!(path, PathBuf::from("/opt/fledx/bin/fledx-agent"));
    }

    #[test]
    fn agent_bin_path_rejects_missing_filename() {
        let args = BootstrapAgentArgs {
            ssh_host: "root@example.com".into(),
            ssh_user: None,
            ssh_port: 22,
            ssh_identity_file: None,
            name: None,
            version: None,
            bin_dir: PathBuf::from("/usr/local/bin"),
            install_path: Some(PathBuf::from("/")),
            config_dir: PathBuf::from("/etc/fledx"),
            data_dir: PathBuf::from("/var/lib/fledx"),
            service_user: "fledx-agent".into(),
            labels: Vec::new(),
            capacity_cpu_millis: None,
            capacity_memory_bytes: None,
            sudo_interactive: false,
            insecure_allow_unsigned: false,
            no_wait: true,
            wait_timeout_secs: 1,
        };

        let err = agent_bin_path(&args).expect_err("should fail");
        assert!(err.to_string().contains("missing file name"));
    }
}
