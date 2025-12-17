use std::fs;
use std::path::Path;

use anyhow::Context;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use super::GITHUB_USER_AGENT;

#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
}

pub async fn fetch_release(
    client: &reqwest::Client,
    repo: &str,
    version: Option<&str>,
) -> anyhow::Result<GitHubRelease> {
    let url = release_api_url(repo, version);
    let res = client
        .get(&url)
        .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
        .send()
        .await
        .with_context(|| format!("failed to fetch GitHub release metadata: {url}"))?;
    let res = res
        .error_for_status()
        .with_context(|| format!("GitHub release request failed: {url}"))?;
    Ok(res.json().await?)
}

pub fn release_api_url(repo: &str, version: Option<&str>) -> String {
    match version.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("latest") => {
            format!("https://api.github.com/repos/{repo}/releases/latest")
        }
        Some(v) => {
            let normalized = v.trim_start_matches('v');
            format!("https://api.github.com/repos/{repo}/releases/tags/v{normalized}")
        }
        None => format!("https://api.github.com/repos/{repo}/releases/latest"),
    }
}

pub async fn download_asset(
    client: &reqwest::Client,
    repo: &str,
    release: &GitHubRelease,
    name: &str,
    dest: &Path,
) -> anyhow::Result<()> {
    let asset = release.assets.iter().find(|a| a.name == name).ok_or_else(|| {
        let available = release
            .assets
            .iter()
            .map(|a| a.name.as_str())
            .take(12)
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::anyhow!(
            "release asset not found: {} (repo {} tag {}; available: {})",
            name,
            repo,
            release.tag_name,
            available
        )
    })?;

    let bytes = client
        .get(&asset.browser_download_url)
        .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
        .send()
        .await
        .with_context(|| {
            format!(
                "failed to download {}@{} asset {} from {}",
                repo, release.tag_name, name, asset.browser_download_url
            )
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "failed to download {}@{} asset {} from {}",
                repo, release.tag_name, name, asset.browser_download_url
            )
        })?
        .bytes()
        .await
        .with_context(|| {
            format!(
                "failed to read {}@{} asset {} download body from {}",
                repo, release.tag_name, name, asset.browser_download_url
            )
        })?;

    fs::write(dest, &bytes).with_context(|| {
        format!(
            "failed to write downloaded {}@{} asset {} to {}",
            repo,
            release.tag_name,
            name,
            dest.display()
        )
    })?;
    Ok(())
}

pub fn normalize_version(tag: &str) -> String {
    tag.trim().trim_start_matches('v').to_string()
}

const RELEASE_SIGNING_PUBKEYS_ED25519_ENV: &str = "FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS";
const RELEASE_SIGNING_PUBKEYS_ED25519_COMPILED: Option<&str> =
    option_env!("FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseSigningKeysSource {
    Compiled,
    Environment,
    None,
}

#[derive(Debug, Clone, Copy)]
struct ReleaseSigningKeysInfo {
    source: ReleaseSigningKeysSource,
    env_present: bool,
}

fn describe_release_signing_keys_source(info: ReleaseSigningKeysInfo) -> String {
    let base = match info.source {
        ReleaseSigningKeysSource::Compiled => "build-time embedded keys",
        ReleaseSigningKeysSource::Environment => "runtime environment variable",
        ReleaseSigningKeysSource::None => "not configured",
    };

    if info.source == ReleaseSigningKeysSource::Compiled && info.env_present {
        format!(
            "{} (runtime {} is set but ignored)",
            base, RELEASE_SIGNING_PUBKEYS_ED25519_ENV
        )
    } else {
        base.to_string()
    }
}

fn parse_hex_n<const N: usize>(value: &str) -> anyhow::Result<[u8; N]> {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if without_prefix.len() != N * 2 {
        anyhow::bail!(
            "invalid hex length: expected {} chars, got {}",
            N * 2,
            without_prefix.len()
        );
    }

    let mut out = [0u8; N];
    for (idx, chunk) in without_prefix.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("invalid hex character '{}'", chunk[0] as char))?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("invalid hex character '{}'", chunk[1] as char))?;
    out[idx] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn load_release_signing_keys_ed25519() -> anyhow::Result<(Vec<VerifyingKey>, ReleaseSigningKeysInfo)> {
    let mut keys = std::collections::HashSet::<[u8; 32]>::new();

    let compiled = RELEASE_SIGNING_PUBKEYS_ED25519_COMPILED
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let env_value = std::env::var(RELEASE_SIGNING_PUBKEYS_ED25519_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let env_present = env_value.is_some();
    let (raw, source) = match compiled {
        Some(compiled) => (Some(std::borrow::Cow::Borrowed(compiled)), ReleaseSigningKeysSource::Compiled),
        None => match env_value {
            Some(env_value) => (Some(std::borrow::Cow::Owned(env_value)), ReleaseSigningKeysSource::Environment),
            None => (None, ReleaseSigningKeysSource::None),
        },
    };

    if let Some(raw) = raw {
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let bytes = parse_hex_n::<32>(entry).with_context(|| {
                format!(
                    "failed to parse ed25519 public key from {} entry '{}'",
                    RELEASE_SIGNING_PUBKEYS_ED25519_ENV, entry
                )
            })?;
            keys.insert(bytes);
        }
    }

    let mut verifying = Vec::with_capacity(keys.len());
    for key in keys {
        verifying.push(
            VerifyingKey::from_bytes(&key).context("invalid ed25519 public key bytes")?,
        );
    }
    Ok((
        verifying,
        ReleaseSigningKeysInfo {
            source,
            env_present,
        },
    ))
}

fn verify_ed25519_detached_signature_with_any_key(
    keys: &[VerifyingKey],
    message: &[u8],
    signature: &Signature,
) -> bool {
    keys.iter().any(|key| key.verify(message, signature).is_ok())
}

pub fn verify_signed_sha256(
    repo: &str,
    tag: &str,
    asset: &str,
    archive: &Path,
    sha_file: &Path,
    sha_sig_file: &Path,
) -> anyhow::Result<()> {
    let (keys, key_info) = load_release_signing_keys_ed25519()?;
    if keys.is_empty() {
        anyhow::bail!(
            "release signature verification is enabled but no trusted ed25519 \
release signing keys are configured.\n\
Set {} to a comma-separated list of 32-byte hex public keys (64 hex chars), \
or pass --insecure-allow-unsigned to skip signature verification.\n\
\nkey source: {}\n\
\nrepo: {}\ntag: {}\nasset: {}",
            RELEASE_SIGNING_PUBKEYS_ED25519_ENV,
            describe_release_signing_keys_source(key_info),
            repo,
            tag,
            asset
        );
    }

    let message = fs::read(sha_file).with_context(|| {
        format!(
            "failed to read sha256 file for {}@{} asset {}: {}",
            repo,
            tag,
            asset,
            sha_file.display()
        )
    })?;
    let sig_bytes = fs::read(sha_sig_file).with_context(|| {
        format!(
            "failed to read sha256 signature for {}@{} asset {}: {}",
            repo,
            tag,
            asset,
            sha_sig_file.display()
        )
    })?;

    let sig_len = sig_bytes.len();
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "invalid ed25519 signature length for {}@{} asset {}: expected 64 bytes, got {}.\n\
Hint: this usually means the release was signed with a non-Ed25519 key, or the \
signature is not a raw 64-byte Ed25519 signature.\n\
The release workflow must use an Ed25519 private key and write raw signature \
bytes (e.g. `openssl pkeyutl -sign -rawin`).",
            repo,
            tag,
            asset,
            sig_len
        )
    })?;
    let signature = Signature::from_bytes(&sig_array);

    if !verify_ed25519_detached_signature_with_any_key(&keys, &message, &signature) {
        anyhow::bail!(
            "signature verification failed for {}@{} asset {}.\n\
Hint: ensure the release contains a valid {} signature file and that {} \
contains the correct public key.\n\
\nkey source: {}\n\
\nsha256 file: {}\nsignature file: {}",
            repo,
            tag,
            asset,
            sha_sig_file
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("*.sig"),
            RELEASE_SIGNING_PUBKEYS_ED25519_ENV,
            describe_release_signing_keys_source(key_info),
            sha_file.display(),
            sha_sig_file.display()
        );
    }

    super::verify_sha256(repo, tag, asset, archive, sha_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn release_api_url_defaults_to_latest() {
        let url = release_api_url("fledx/fledx-core", None);
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/latest"
        );
    }

    #[test]
    fn release_api_url_accepts_latest_flag() {
        let url = release_api_url("fledx/fledx-core", Some("latest"));
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/latest"
        );

        let url = release_api_url("fledx/fledx-core", Some("Latest"));
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/latest"
        );
    }

    #[test]
    fn release_api_url_strips_v_prefix() {
        let url = release_api_url("fledx/fledx-core", Some("v0.3.0"));
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/tags/v0.3.0"
        );
    }

    #[test]
    fn release_api_url_adds_v_prefix() {
        let url = release_api_url("fledx/fledx-core", Some("0.3.0"));
        assert_eq!(
            url,
            "https://api.github.com/repos/fledx/fledx-core/releases/tags/v0.3.0"
        );
    }

    #[test]
    fn verify_ed25519_detached_signature_accepts_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let message = b"hello";
        let signature = signing_key.sign(message);

        assert!(verify_ed25519_detached_signature_with_any_key(
            &[verifying_key],
            message,
            &signature
        ));
    }

    #[test]
    fn verify_ed25519_detached_signature_rejects_invalid_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let signature = signing_key.sign(b"hello");

        assert!(!verify_ed25519_detached_signature_with_any_key(
            &[verifying_key],
            b"not-hello",
            &signature
        ));
    }
}
