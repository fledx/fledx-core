use std::fs;
use std::path::Path;

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::timeout as tokio_timeout;

use super::GITHUB_USER_AGENT;

async fn send_with_timeout(
    req: reqwest::RequestBuilder,
    timeout: Duration,
    url: &str,
) -> anyhow::Result<reqwest::Response> {
    match tokio_timeout(timeout, req.send()).await {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(err)) => Err(err).with_context(|| format!("request failed: {url}")),
        Err(_) => anyhow::bail!("request timed out after {}s: {}", timeout.as_secs(), url),
    }
}

async fn read_bytes_with_timeout(
    res: reqwest::Response,
    timeout: Duration,
    url: &str,
) -> anyhow::Result<Vec<u8>> {
    match tokio_timeout(timeout, res.bytes()).await {
        Ok(Ok(bytes)) => Ok(bytes.to_vec()),
        Ok(Err(err)) => Err(err).with_context(|| format!("failed to read response body: {url}")),
        Err(_) => anyhow::bail!(
            "reading response body timed out after {}s: {}",
            timeout.as_secs(),
            url
        ),
    }
}

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
    let urls = release_api_urls(repo, version);
    debug_assert!(!urls.is_empty());

    let mut tried = Vec::with_capacity(urls.len());
    for url in urls {
        tried.push(url.clone());
        let res = send_with_timeout(
            client
                .get(&url)
                .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT),
            Duration::from_secs(15),
            &url,
        )
        .await
        .with_context(|| format!("failed to fetch GitHub release metadata: {url}"))?;

        if res.status() == StatusCode::NOT_FOUND {
            // Some repos use `0.3.0` tags instead of `v0.3.0` (or vice versa).
            // Try the next candidate.
            continue;
        }

        let res = res
            .error_for_status()
            .with_context(|| format!("GitHub release request failed: {url}"))?;
        return Ok(res.json().await?);
    }

    let version = version.unwrap_or("latest");
    anyhow::bail!(
        "GitHub release not found for repo {} version {} (tried: {})",
        repo,
        version,
        tried.join(", ")
    );
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

fn release_api_urls(repo: &str, version: Option<&str>) -> Vec<String> {
    match version.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("latest") => vec![format!(
            "https://api.github.com/repos/{repo}/releases/latest"
        )],
        Some(v) => {
            let normalized = v.trim_start_matches('v');
            vec![
                format!("https://api.github.com/repos/{repo}/releases/tags/v{normalized}"),
                format!("https://api.github.com/repos/{repo}/releases/tags/{normalized}"),
            ]
        }
        None => vec![format!(
            "https://api.github.com/repos/{repo}/releases/latest"
        )],
    }
}

pub async fn download_asset(
    client: &reqwest::Client,
    repo: &str,
    release: &GitHubRelease,
    name: &str,
    dest: &Path,
) -> anyhow::Result<()> {
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| {
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

    let res = send_with_timeout(
        client
            .get(&asset.browser_download_url)
            .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT),
        Duration::from_secs(30),
        &asset.browser_download_url,
    )
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
    })?;

    let bytes = read_bytes_with_timeout(res, Duration::from_secs(300), &asset.browser_download_url)
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
pub enum ReleaseSigningKeysSource {
    Compiled,
    Environment,
    None,
}

impl ReleaseSigningKeysSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseSigningKeysSource::Compiled => "compiled",
            ReleaseSigningKeysSource::Environment => "environment",
            ReleaseSigningKeysSource::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ReleaseSigningKeysInfo {
    source: ReleaseSigningKeysSource,
    env_present: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ReleaseSigningKeysStatus {
    pub configured: bool,
    pub source: ReleaseSigningKeysSource,
    pub env_present: bool,
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

fn read_ssh_string<'a>(data: &'a [u8], cursor: &mut usize) -> anyhow::Result<&'a [u8]> {
    if *cursor + 4 > data.len() {
        anyhow::bail!("invalid ssh-ed25519 public key (truncated length)");
    }
    let len = u32::from_be_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
    ]) as usize;
    *cursor += 4;
    if *cursor + len > data.len() {
        anyhow::bail!("invalid ssh-ed25519 public key (truncated data)");
    }
    let out = &data[*cursor..*cursor + len];
    *cursor += len;
    Ok(out)
}

fn parse_ssh_ed25519_pubkey(value: &str) -> anyhow::Result<[u8; 32]> {
    let mut parts = value.split_whitespace();
    let key_type = parts.next().unwrap_or_default();
    if key_type != "ssh-ed25519" {
        anyhow::bail!(
            "unsupported ssh public key type '{}'; expected ssh-ed25519",
            key_type
        );
    }
    let key_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("ssh-ed25519 public key is missing base64 data"))?;
    let decoded = general_purpose::STANDARD
        .decode(key_b64)
        .context("invalid ssh-ed25519 base64 data")?;
    let mut cursor = 0;
    let decoded_type = read_ssh_string(&decoded, &mut cursor)?;
    if decoded_type != b"ssh-ed25519" {
        anyhow::bail!(
            "invalid ssh-ed25519 public key (unexpected type {})",
            String::from_utf8_lossy(decoded_type)
        );
    }
    let key_bytes = read_ssh_string(&decoded, &mut cursor)?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "invalid ed25519 public key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }
    if cursor != decoded.len() {
        anyhow::bail!("invalid ssh-ed25519 public key (trailing data)");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(key_bytes);
    Ok(out)
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

fn parse_ed25519_pubkey_entry(value: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty entry");
    }
    let first_token = trimmed.split_whitespace().next().unwrap_or_default();
    if first_token.starts_with("ssh-") {
        return parse_ssh_ed25519_pubkey(trimmed);
    }
    if trimmed.starts_with("-----BEGIN") {
        anyhow::bail!("PEM public keys are not supported; use 64-hex (optional 0x) or ssh-ed25519");
    }
    parse_hex_n::<32>(trimmed)
        .with_context(|| "expected 64 hex chars (32 bytes), optionally 0x-prefixed, or ssh-ed25519")
}

fn load_release_signing_keys_ed25519() -> anyhow::Result<(Vec<VerifyingKey>, ReleaseSigningKeysInfo)>
{
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
        Some(compiled) => (
            Some(std::borrow::Cow::Borrowed(compiled)),
            ReleaseSigningKeysSource::Compiled,
        ),
        None => match env_value {
            Some(env_value) => (
                Some(std::borrow::Cow::Owned(env_value)),
                ReleaseSigningKeysSource::Environment,
            ),
            None => (None, ReleaseSigningKeysSource::None),
        },
    };

    if let Some(raw) = raw {
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let bytes = parse_ed25519_pubkey_entry(entry).with_context(|| {
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
        verifying.push(VerifyingKey::from_bytes(&key).context("invalid ed25519 public key bytes")?);
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
    keys.iter()
        .any(|key| key.verify(message, signature).is_ok())
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
Set {} to a comma-separated list of 32-byte public keys in hex (64 chars, \
optional 0x) or ssh-ed25519 format, or pass --insecure-allow-unsigned to skip \
signature verification.\n\
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

pub fn release_signing_keys_status() -> anyhow::Result<ReleaseSigningKeysStatus> {
    let (keys, info) = load_release_signing_keys_ed25519()?;
    Ok(ReleaseSigningKeysStatus {
        configured: !keys.is_empty(),
        source: info.source,
        env_present: info.env_present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Mutex, OnceLock};
    use std::thread;
    use std::time::Duration;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn compiled_keys_available() -> bool {
        RELEASE_SIGNING_PUBKEYS_ED25519_COMPILED
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn with_release_keys_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = env_lock().lock().expect("env lock");
        let original = std::env::var(RELEASE_SIGNING_PUBKEYS_ED25519_ENV).ok();
        // SAFETY: Tests hold env_lock to serialize env mutations.
        unsafe {
            match value {
                Some(value) => std::env::set_var(RELEASE_SIGNING_PUBKEYS_ED25519_ENV, value),
                None => std::env::remove_var(RELEASE_SIGNING_PUBKEYS_ED25519_ENV),
            }
        }
        let out = f();
        // SAFETY: Tests hold env_lock to serialize env mutations.
        unsafe {
            match original {
                Some(value) => std::env::set_var(RELEASE_SIGNING_PUBKEYS_ED25519_ENV, value),
                None => std::env::remove_var(RELEASE_SIGNING_PUBKEYS_ED25519_ENV),
            }
        }
        out
    }

    fn drain_http_request(stream: &mut std::net::TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
        let mut buf = [0u8; 1024];
        let mut received = Vec::new();
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|chunk| chunk == b"\r\n\r\n") {
                        break;
                    }
                    if received.len() > 8192 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

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
    fn release_api_urls_includes_v_and_plain_tag() {
        let urls = release_api_urls("fledx/fledx-core", Some("0.3.0"));
        assert_eq!(
            urls[0],
            "https://api.github.com/repos/fledx/fledx-core/releases/tags/v0.3.0"
        );
        assert_eq!(
            urls[1],
            "https://api.github.com/repos/fledx/fledx-core/releases/tags/0.3.0"
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

    #[test]
    fn parse_ed25519_pubkey_entry_accepts_hex() {
        let key = parse_ed25519_pubkey_entry(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("hex key");
        assert_eq!(key, [0x11u8; 32]);
    }

    #[test]
    fn parse_ed25519_pubkey_entry_accepts_ssh_ed25519() {
        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0XDtf2pLFc+LVsG9CUlgpOm7GmL+bBcUKDD940ZNmP";
        let expected =
            parse_hex_n::<32>("ad170ed7f6a4b15cf8b56c1bd094960a4e9bb1a62fe6c17142830fde3464d98f")
                .expect("expected hex");
        let parsed = parse_ed25519_pubkey_entry(ssh_key).expect("ssh key");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn parse_ed25519_pubkey_entry_rejects_pem() {
        let err =
            parse_ed25519_pubkey_entry("-----BEGIN PUBLIC KEY-----").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("PEM public keys are not supported"), "{msg}");
    }

    #[test]
    fn parse_ed25519_pubkey_entry_rejects_empty() {
        let err = parse_ed25519_pubkey_entry("   ").expect_err("empty");
        assert!(err.to_string().contains("empty entry"));
    }

    #[test]
    fn parse_hex_n_rejects_invalid_length() {
        let err = parse_hex_n::<4>("abc").expect_err("invalid length");
        assert!(err.to_string().contains("invalid hex length"));
    }

    #[test]
    fn parse_hex_n_rejects_invalid_character() {
        let err = parse_hex_n::<2>("zzzz").expect_err("invalid char");
        assert!(err.to_string().contains("invalid hex character"));
    }

    #[test]
    fn parse_ssh_ed25519_pubkey_rejects_wrong_type() {
        let err = parse_ssh_ed25519_pubkey("ssh-rsa AAAA").expect_err("wrong type");
        assert!(err.to_string().contains("expected ssh-ed25519"));
    }

    #[test]
    fn parse_ssh_ed25519_pubkey_rejects_missing_base64() {
        let err = parse_ssh_ed25519_pubkey("ssh-ed25519").expect_err("missing");
        assert!(err.to_string().contains("missing base64"));
    }

    #[test]
    fn parse_ssh_ed25519_pubkey_rejects_invalid_base64() {
        let err = parse_ssh_ed25519_pubkey("ssh-ed25519 !!!").expect_err("invalid");
        assert!(err.to_string().contains("invalid ssh-ed25519 base64 data"));
    }

    #[test]
    fn load_release_signing_keys_uses_environment() {
        if compiled_keys_available() {
            return;
        }
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let key_hex = hex_encode(&signing_key.verifying_key().to_bytes());
        let (keys, info) = with_release_keys_env(Some(&key_hex), || {
            load_release_signing_keys_ed25519().expect("load keys")
        });
        assert_eq!(keys.len(), 1);
        assert_eq!(info.source, ReleaseSigningKeysSource::Environment);
        assert!(info.env_present);
    }

    #[test]
    fn verify_signed_sha256_errors_when_keys_missing() {
        if compiled_keys_available() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("asset.tar.gz");
        let sha_file = dir.path().join("asset.tar.gz.sha256");
        let sig_file = dir.path().join("asset.tar.gz.sha256.sig");
        std::fs::write(&archive, b"archive").expect("archive");
        std::fs::write(&sha_file, b"deadbeef  asset.tar.gz\n").expect("sha");
        std::fs::write(&sig_file, b"sig").expect("sig");

        let err = with_release_keys_env(None, || {
            verify_signed_sha256(
                "fledx/fledx-core",
                "v1.0.0",
                "asset.tar.gz",
                &archive,
                &sha_file,
                &sig_file,
            )
            .expect_err("should fail without keys")
        });
        assert!(
            err.to_string()
                .contains("no trusted ed25519 release signing keys")
        );
    }

    #[test]
    fn verify_signed_sha256_rejects_invalid_signature_length() {
        if compiled_keys_available() {
            return;
        }
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let key_hex = hex_encode(&signing_key.verifying_key().to_bytes());
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("asset.tar.gz");
        let sha_file = dir.path().join("asset.tar.gz.sha256");
        let sig_file = dir.path().join("asset.tar.gz.sha256.sig");
        std::fs::write(&archive, b"archive").expect("archive");
        std::fs::write(&sha_file, b"deadbeef  asset.tar.gz\n").expect("sha");
        std::fs::write(&sig_file, b"short").expect("sig");

        let err = with_release_keys_env(Some(&key_hex), || {
            verify_signed_sha256(
                "fledx/fledx-core",
                "v1.0.0",
                "asset.tar.gz",
                &archive,
                &sha_file,
                &sig_file,
            )
            .expect_err("invalid signature length")
        });
        assert!(err.to_string().contains("invalid ed25519 signature length"));
    }

    #[test]
    fn verify_signed_sha256_rejects_signature_mismatch() {
        if compiled_keys_available() {
            return;
        }
        let signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let key_hex = hex_encode(&signing_key.verifying_key().to_bytes());
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("asset.tar.gz");
        let sha_file = dir.path().join("asset.tar.gz.sha256");
        let sig_file = dir.path().join("asset.tar.gz.sha256.sig");
        std::fs::write(&archive, b"archive").expect("archive");
        std::fs::write(&sha_file, b"expected").expect("sha");
        let signature = signing_key.sign(b"different");
        std::fs::write(&sig_file, signature.to_bytes()).expect("sig");

        let err = with_release_keys_env(Some(&key_hex), || {
            verify_signed_sha256(
                "fledx/fledx-core",
                "v1.0.0",
                "asset.tar.gz",
                &archive,
                &sha_file,
                &sig_file,
            )
            .expect_err("signature mismatch")
        });
        assert!(err.to_string().contains("signature verification failed"));
    }

    fn spawn_http_server(body: &'static [u8]) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        addr
    }

    fn spawn_http_server_with_response(
        status: &str,
        headers: &str,
        body: Vec<u8>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let status = status.to_string();
        let headers = headers.to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                drain_http_request(&mut stream);
                let response = format!("HTTP/1.1 {status}\r\n{headers}\r\n\r\n");
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        addr
    }

    fn spawn_http_server_with_delay(
        headers: &str,
        delay: Duration,
        body: Vec<u8>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let headers = headers.to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                drain_http_request(&mut stream);
                let response = format!("HTTP/1.1 200 OK\r\n{headers}\r\n\r\n");
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                thread::sleep(delay);
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        addr
    }

    #[test]
    fn normalize_version_trims_prefix_and_whitespace() {
        assert_eq!(normalize_version(" v1.2.3 "), "1.2.3");
        assert_eq!(normalize_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn describe_release_signing_keys_source_mentions_env_override() {
        let info = ReleaseSigningKeysInfo {
            source: ReleaseSigningKeysSource::Compiled,
            env_present: true,
        };
        let msg = describe_release_signing_keys_source(info);
        assert!(msg.contains("ignored"), "{msg}");
    }

    #[tokio::test]
    async fn send_with_timeout_returns_response() {
        let addr = spawn_http_server_with_response(
            "200 OK",
            "Content-Length: 2\r\nConnection: close",
            b"ok".to_vec(),
        );
        let client = reqwest::Client::builder()
            .http1_only()
            .build()
            .expect("client");
        let url = format!("http://{addr}/hello");
        let res = send_with_timeout(client.get(&url), Duration::from_secs(5), &url)
            .await
            .expect("response");
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn send_with_timeout_reports_connection_failure() {
        let client = reqwest::Client::new();
        let url = "http://127.0.0.1:1/unreachable";
        let err = send_with_timeout(client.get(url), Duration::from_secs(1), url)
            .await
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("request failed") || msg.contains("request timed out"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn read_bytes_with_timeout_times_out() {
        let body = b"delayed".to_vec();
        let addr = spawn_http_server_with_delay(
            "Content-Length: 7\r\nConnection: close",
            Duration::from_millis(200),
            body,
        );
        let client = reqwest::Client::builder()
            .http1_only()
            .build()
            .expect("client");
        let url = format!("http://{addr}/delayed");
        let res = send_with_timeout(client.get(&url), Duration::from_secs(5), &url)
            .await
            .expect("response");
        let err = read_bytes_with_timeout(res, Duration::from_millis(50), &url)
            .await
            .expect_err("should fail");
        assert!(err.to_string().contains("reading response body timed out"));
    }

    #[tokio::test]
    async fn download_asset_writes_response_body() {
        let addr = spawn_http_server(b"payload");
        let release = GitHubRelease {
            tag_name: "v1.0.0".into(),
            assets: vec![GitHubAsset {
                name: "asset.tar.gz".into(),
                browser_download_url: format!("http://{addr}/asset"),
            }],
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("asset.tar.gz");
        download_asset(
            &reqwest::Client::builder()
                .http1_only()
                .build()
                .expect("client"),
            "fledx/fledx-core",
            &release,
            "asset.tar.gz",
            &dest,
        )
        .await
        .expect("download");
        let content = fs::read(&dest).expect("read");
        assert_eq!(content, b"payload");
    }

    #[tokio::test]
    async fn download_asset_errors_when_missing() {
        let release = GitHubRelease {
            tag_name: "v1.0.0".into(),
            assets: Vec::new(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("asset.tar.gz");
        let err = download_asset(
            &reqwest::Client::new(),
            "fledx/fledx-core",
            &release,
            "missing.tar.gz",
            &dest,
        )
        .await
        .expect_err("missing asset");
        assert!(err.to_string().contains("release asset not found"));
    }
}
