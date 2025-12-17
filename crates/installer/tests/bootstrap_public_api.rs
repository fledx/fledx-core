use std::path::PathBuf;

#[test]
fn bootstrap_api_reexports_smoke() {
    let url = installer::bootstrap::release_api_url("fledx/fledx-core", Some("latest"));
    assert_eq!(
        url,
        "https://api.github.com/repos/fledx/fledx-core/releases/latest"
    );

    let target = installer::bootstrap::SshTarget::from_user_at_host("alice@host", None, 22, None);
    assert_eq!(target.destination(), "alice@host");

    let (key, value) = installer::bootstrap::parse_label("region=eu-west").expect("parse");
    assert_eq!(key, "region");
    assert_eq!(value, "eu-west");
}

#[test]
fn bootstrap_verify_sha256_works_from_integration_test() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("asset.tar.gz");
    std::fs::write(&archive, b"hello").expect("write archive");
    let actual = installer::bootstrap::sha256_hex(&archive).expect("hash");

    let sha_file = dir.path().join("asset.tar.gz.sha256");
    std::fs::write(&sha_file, format!("{actual}  asset.tar.gz\n")).expect("write sha");

    installer::bootstrap::verify_sha256(
        "fledx/fledx-core",
        "v0.3.0",
        "asset.tar.gz",
        &archive,
        &sha_file,
    )
    .expect("verify");
}

#[test]
fn bootstrap_systemd_unit_rendering_is_public_and_escapes_percent() {
    let unit = installer::bootstrap::render_agent_unit(&installer::bootstrap::AgentUnitInputs {
        service_user: "fledx-agent".to_string(),
        env_path: PathBuf::from("/etc/fledx dir/fledx%agent.env"),
        bin_path: PathBuf::from("/usr/local/bin dir/fledx-agent"),
    });

    assert!(unit.contains("EnvironmentFile=\"/etc/fledx dir/fledx%%agent.env\""));
    assert!(unit.contains("ExecStart=\"/usr/local/bin dir/fledx-agent\""));
}
