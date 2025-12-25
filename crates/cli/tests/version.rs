use semver::Version;
use std::process::Command;

#[test]
fn prints_semver_git_sha_and_dirty_flag() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .arg("--version")
        .output()
        .expect("run --version");

    assert!(output.status.success(), "--version should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();

    let mut tokens = line.split_whitespace();
    let binary_name = tokens.next().unwrap_or_default();
    assert_eq!(
        binary_name, "fledx",
        "binary name should prefix version output"
    );

    let semver = tokens.next().unwrap_or_default();
    Version::parse(semver).expect("first token must be semver");

    let rest = tokens.collect::<Vec<_>>().join(" ");
    assert!(
        !rest.is_empty(),
        "long version should include git metadata: {line}"
    );

    assert!(rest.contains("(git "), "missing git label: {rest}");
    assert!(rest.contains("dirty="), "missing dirty flag: {rest}");

    let sha_section = rest
        .split("(git ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap_or("")
        .trim_end_matches(')')
        .trim();

    let sha = sha_section.trim_end_matches("-dirty");
    let looks_hex = sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit());
    assert!(
        looks_hex || sha == "unknown",
        "git sha should be short hex or unknown: {sha_section}"
    );

    if looks_hex
        && let Ok(git_output) = Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
        && git_output.status.success()
    {
        let expected = String::from_utf8_lossy(&git_output.stdout)
            .trim()
            .to_string();
        assert!(
            sha_section.contains(&expected),
            "version should surface current git SHA (expected prefix {expected})"
        );
    }
}
