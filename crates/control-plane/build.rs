use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    write_version().expect("write version.rs");

    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
}

fn write_version() -> anyhow::Result<()> {
    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let git_sha = env::var("GIT_SHA")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(git_short_sha)
        .unwrap_or_else(|| "unknown".to_string());
    let git_dirty = env::var("GIT_DIRTY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| git_dirty().unwrap_or(false));
    let build_timestamp = current_timestamp();
    let git_label = format_git_label(&git_sha, git_dirty);
    let long_version =
        format!("{pkg_version} (git {git_label}, dirty={git_dirty}, built {build_timestamp})");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let dest = out_dir.join("version.rs");
    let contents = format!(
        "pub const VERSION: &str = \"{pkg_version}\";\n\
         pub const GIT_SHA: &str = \"{git_sha}\";\n\
         pub const GIT_DIRTY: bool = {git_dirty};\n\
         pub const BUILD_TIMESTAMP: &str = \"{build_timestamp}\";\n\
         pub const GIT_LABEL: &str = \"{git_label}\";\n\
         pub const FULL_VERSION: &str = \"{long_version}\";\n"
    );
    fs::write(&dest, contents)?;
    Ok(())
}

fn git_short_sha() -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
}

fn git_dirty() -> Option<bool> {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|output| !output.stdout.is_empty())
}

fn current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn format_git_label(git_sha: &str, dirty: bool) -> String {
    match git_sha {
        "unknown" => "unknown".to_string(),
        sha => {
            let suffix = if dirty { "-dirty" } else { "" };
            format!("{sha}{suffix}")
        }
    }
}
