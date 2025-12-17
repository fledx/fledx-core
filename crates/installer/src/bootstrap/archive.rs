use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use flate2::read::GzDecoder;
use sha2::Digest;

pub fn parse_sha256_file(path: &Path) -> anyhow::Result<String> {
    let raw = fs::read_to_string(path)?;
    let hash = raw
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid sha256 file: {}", path.display()))?;
    Ok(hash.to_string())
}

pub fn verify_sha256(
    repo: &str,
    tag: &str,
    asset: &str,
    archive: &Path,
    sha_file: &Path,
) -> anyhow::Result<()> {
    let expected = parse_sha256_file(sha_file).with_context(|| {
        format!(
            "failed to parse sha256 file for {}@{} asset {}: {}",
            repo,
            tag,
            asset,
            sha_file.display()
        )
    })?;
    let actual = sha256_hex(archive).with_context(|| {
        format!(
            "failed to compute sha256 for {}@{} asset {}: {}",
            repo,
            tag,
            asset,
            archive.display()
        )
    })?;
    if expected != actual {
        anyhow::bail!(
            "checksum mismatch for {}@{} asset {} ({}): expected {}, got {}",
            repo,
            tag,
            asset,
            archive.display(),
            expected,
            actual
        );
    }
    Ok(())
}

pub fn sha256_hex(path: &Path) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn extract_single_file(
    archive_path: &Path,
    bin_name: &str,
    out_dir: &Path,
) -> anyhow::Result<PathBuf> {
    let tar_gz = fs::File::open(archive_path)?;
    let gz = GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(gz);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if file_name == bin_name {
            let dest = out_dir.join(bin_name);
            entry.unpack(&dest)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))?;
            }
            return Ok(dest);
        }
    }

    anyhow::bail!(
        "archive {} did not contain expected binary '{}'",
        archive_path.display(),
        bin_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha256_file_reads_first_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("asset.tar.gz.sha256");
        fs::write(&path, "abc123  asset.tar.gz\n").expect("write");

        let parsed = parse_sha256_file(&path).expect("parse");
        assert_eq!(parsed, "abc123");
    }

    #[test]
    fn verify_sha256_succeeds_for_matching_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("asset.tar.gz");
        fs::write(&archive, b"hello").expect("write archive");
        let actual = sha256_hex(&archive).expect("hash");

        let sha_file = dir.path().join("asset.tar.gz.sha256");
        fs::write(&sha_file, format!("{actual}  asset.tar.gz\n")).expect("write sha");

        verify_sha256(
            "fledx/fledx-core",
            "v0.3.0",
            "asset.tar.gz",
            &archive,
            &sha_file,
        )
        .expect("verify");
    }

    #[test]
    fn verify_sha256_errors_with_context_on_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("asset.tar.gz");
        fs::write(&archive, b"hello").expect("write archive");
        let actual = sha256_hex(&archive).expect("hash");

        let sha_file = dir.path().join("asset.tar.gz.sha256");
        fs::write(&sha_file, "deadbeef  asset.tar.gz\n").expect("write sha");

        let err = verify_sha256(
            "fledx/fledx-core",
            "v0.3.0",
            "asset.tar.gz",
            &archive,
            &sha_file,
        )
        .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("checksum mismatch"), "{msg}");
        assert!(msg.contains("fledx/fledx-core"), "{msg}");
        assert!(msg.contains("v0.3.0"), "{msg}");
        assert!(msg.contains("asset.tar.gz"), "{msg}");
        assert!(msg.contains("deadbeef"), "{msg}");
        assert!(msg.contains(&actual), "{msg}");
    }
}

