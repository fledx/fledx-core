use std::fs;
use std::process::Command;

use tempfile::tempdir;

/// Ensure env file parsing surfaces helpful errors when a line is malformed.
#[test]
fn configs_create_rejects_invalid_env_file_lines() {
    let dir = tempdir().expect("tempdir");
    let env_path = dir.path().join("broken.env");
    fs::write(&env_path, "GOOD=ok\nbad-line\n").expect("write env");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", "http://127.0.0.1:9")
        .env("FLEDX_CLI_OPERATOR_TOKEN", "test-token")
        .args([
            "configs",
            "create",
            "--name",
            "app",
            "--from-env-file",
            env_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("run cli");

    assert!(
        !output.status.success(),
        "cli should fail on malformed env line"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("env file"),
        "expected env file context in stderr: {stderr}"
    );
    assert!(
        stderr.contains("line 2"),
        "expected line number in stderr: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("key=value"),
        "expected KEY=VALUE hint in stderr: {stderr}"
    );
}

/// Duplicate keys, even with different casing, should be rejected with a clear error.
#[test]
fn configs_create_rejects_duplicate_keys_case_insensitive() {
    let dir = tempdir().expect("tempdir");
    let env_path = dir.path().join("dupe.env");
    fs::write(&env_path, "FOO=from-file\n").expect("write env");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", "http://127.0.0.1:9")
        .env("FLEDX_CLI_OPERATOR_TOKEN", "test-token")
        .args([
            "configs",
            "create",
            "--name",
            "app",
            "--var",
            "foo=inline",
            "--from-env-file",
            env_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("run cli");

    assert!(
        !output.status.success(),
        "cli should fail on duplicate keys"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("duplicate config entry key: FOO"),
        "unexpected stderr: {stderr}"
    );
}

/// Oversized keys and values should be validated before any HTTP call is made.
#[test]
fn configs_create_rejects_oversized_keys_and_values() {
    let long_key = "K".repeat(256); // exceeds CONFIG_MAX_FIELD_LEN (255)
    let long_value = "v".repeat(4097); // exceeds CONFIG_MAX_VALUE_LEN (4096)

    let key_arg = format!("{}=ok", long_key);
    let key_output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", "http://127.0.0.1:9")
        .env("FLEDX_CLI_OPERATOR_TOKEN", "test-token")
        .args([
            "configs",
            "create",
            "--name",
            "big-key",
            "--var",
            key_arg.as_str(),
        ])
        .output()
        .expect("run cli");

    assert!(
        !key_output.status.success(),
        "cli should fail for oversized key"
    );
    let key_stderr = String::from_utf8_lossy(&key_output.stderr);
    assert!(
        key_stderr.contains("config entry key too long (max 255 characters)"),
        "unexpected stderr: {key_stderr}"
    );

    let value_arg = format!("KEY={}", long_value);
    let value_output = Command::new(assert_cmd::cargo::cargo_bin!("fledx"))
        .env("FLEDX_CLI_CONTROL_PLANE_URL", "http://127.0.0.1:9")
        .env("FLEDX_CLI_OPERATOR_TOKEN", "test-token")
        .args([
            "configs",
            "create",
            "--name",
            "big-value",
            "--var",
            value_arg.as_str(),
        ])
        .output()
        .expect("run cli");

    assert!(
        !value_output.status.success(),
        "cli should fail for oversized value"
    );
    let value_stderr = String::from_utf8_lossy(&value_output.stderr);
    assert!(
        value_stderr.contains("config entry value too long (max 4096 characters)"),
        "unexpected stderr: {value_stderr}"
    );
}
