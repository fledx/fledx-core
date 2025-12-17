use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub control_plane_url: Option<String>,
    #[serde(default)]
    pub operator_header: Option<String>,
    #[serde(default)]
    pub operator_token: Option<String>,
    #[serde(default)]
    pub registration_token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileStore {
    #[serde(default)]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl ProfileStore {
    pub fn path() -> anyhow::Result<PathBuf> {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(xdg).join("fledx").join("config.toml"));
        }

        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| anyhow::anyhow!("HOME is not set and XDG_CONFIG_HOME is not set"))?;
        Ok(home.join(".config").join("fledx").join("config.toml"))
    }

    pub fn load() -> anyhow::Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        ensure_private_file(&path)?;
        let raw = fs::read_to_string(&path)?;
        let cfg = toml::from_str::<Self>(&raw)?;
        Ok(cfg)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        let dir = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid config path: missing parent dir"))?;
        ensure_private_dir(dir)?;

        let rendered = toml::to_string_pretty(self)?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        set_private_file_perms(tmp.path())?;
        tmp.write_all(rendered.as_bytes())?;
        tmp.flush()?;
        tmp.persist(path)?;
        Ok(())
    }
}

fn ensure_private_dir(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_perms(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn ensure_private_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "profile config is too permissive (mode {:o}); run: chmod 600 {}",
                mode,
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_creates_toml_with_private_perms() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::env::remove_var("HOME");

        let mut store = ProfileStore {
            default_profile: Some("default".into()),
            ..Default::default()
        };
        store.profiles.insert(
            "default".into(),
            Profile {
                control_plane_url: Some("http://127.0.0.1:8080".into()),
                operator_header: Some("authorization".into()),
                operator_token: Some("op".into()),
                registration_token: Some("reg".into()),
            },
        );

        store.save().expect("save");

        let path = ProfileStore::path().expect("path");
        assert!(path.exists());
        let raw = fs::read_to_string(path).expect("read");
        assert!(raw.contains("default_profile"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(ProfileStore::path().expect("path"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn load_returns_default_when_missing() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::env::remove_var("HOME");

        let loaded = ProfileStore::load().expect("load");
        assert!(loaded.default_profile.is_none());
        assert!(loaded.profiles.is_empty());
    }

    #[test]
    fn load_roundtrips_saved_file() {
        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::env::remove_var("HOME");

        let mut store = ProfileStore {
            default_profile: Some("prod".into()),
            ..Default::default()
        };
        store.profiles.insert(
            "prod".into(),
            Profile {
                control_plane_url: Some("https://cp.example:8443".into()),
                operator_header: Some("authorization".into()),
                operator_token: Some("secret".into()),
                registration_token: Some("reg".into()),
            },
        );
        store.save().expect("save");

        let loaded = ProfileStore::load().expect("load");
        assert_eq!(loaded.default_profile.as_deref(), Some("prod"));
        let profile = loaded.profiles.get("prod").expect("profile");
        assert_eq!(
            profile.control_plane_url.as_deref(),
            Some("https://cp.example:8443")
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_fails_when_file_is_too_permissive() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::test_support::ENV_LOCK.lock().expect("lock");
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::env::remove_var("HOME");

        let path = ProfileStore::path().expect("path");
        let parent = path.parent().expect("parent");
        fs::create_dir_all(parent).expect("mkdir");
        fs::write(&path, "default_profile = \"default\"\n").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        let err = ProfileStore::load().expect_err("should fail");
        assert!(err.to_string().contains("too permissive"));
    }
}
