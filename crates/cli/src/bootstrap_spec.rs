/// Configuration that describes where bootstrap should download binaries from.
///
/// The bootstrap implementation lives in the core CLI crate, but other binaries
/// (like `fledx-enterprise`) may want to reuse it while pulling release assets
/// from a different repository and/or with a different naming scheme.
///
/// The goal is to avoid duplicating the bootstrap logic and only parameterize
/// the "distribution" (repo + asset naming).
#[cfg(feature = "bootstrap")]
#[derive(Debug, Clone, Copy)]
pub enum BootstrapSecretsMasterKey {
    /// Do not inject `FLEDX_CP_SECRETS_MASTER_KEY`.
    None,
    /// Generate and inject `FLEDX_CP_SECRETS_MASTER_KEY` during bootstrap.
    ///
    /// This is used by enterprise control-planes that require a master key for
    /// encrypting sensitive persisted data (e.g. TLS private keys).
    Generate,
}

#[cfg(feature = "bootstrap")]
#[derive(Debug, Clone, Copy)]
pub enum BootstrapAgentVersionFallback {
    /// Never fall back; if we cannot find an agent release matching the
    /// requested version, bootstrap fails.
    None,
    /// If the agent version was derived from the control-plane version and no
    /// matching agent release exists, fall back to the latest agent release.
    LatestWhenControlPlaneDerived,
}

#[cfg(feature = "bootstrap")]
#[derive(Debug, Clone, Copy)]
pub struct BootstrapReleaseSpec {
    /// GitHub repo for control-plane release assets (e.g. `owner/repo`).
    pub cp_repo: &'static str,
    /// GitHub repo for node-agent release assets (e.g. `owner/repo`).
    pub agent_repo: &'static str,
    /// Map `(version, arch)` -> archive asset name.
    ///
    /// `version` is normalized (no leading `v`).
    pub cp_archive_name: fn(version: &str, arch: &str) -> String,
    /// Map `(version, arch)` -> archive asset name.
    ///
    /// `version` is normalized (no leading `v`).
    pub agent_archive_name: fn(version: &str, arch: &str) -> String,
    /// Label used in user-facing output for control-plane installs.
    pub cp_label: &'static str,
    /// Label used in user-facing output for agent installs.
    pub agent_label: &'static str,

    /// Behavior when resolving agent releases by version.
    pub agent_version_fallback: BootstrapAgentVersionFallback,

    /// If set, bootstrap will inject a secrets master key into the generated
    /// control-plane environment file.
    pub cp_secrets_master_key: BootstrapSecretsMasterKey,
}

#[cfg(feature = "bootstrap")]
fn core_cp_archive_name(version: &str, arch: &str) -> String {
    format!("fledx-cp-{version}-{arch}-linux.tar.gz")
}

#[cfg(feature = "bootstrap")]
fn core_agent_archive_name(version: &str, arch: &str) -> String {
    format!("fledx-agent-{version}-{arch}-linux.tar.gz")
}

#[cfg(feature = "bootstrap")]
impl BootstrapReleaseSpec {
    pub fn core() -> Self {
        Self {
            cp_repo: "fledx/fledx-core",
            agent_repo: "fledx/fledx-core",
            cp_archive_name: core_cp_archive_name,
            agent_archive_name: core_agent_archive_name,
            cp_label: "core",
            agent_label: "core",
            agent_version_fallback: BootstrapAgentVersionFallback::None,
            cp_secrets_master_key: BootstrapSecretsMasterKey::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_release_spec_has_expected_defaults() {
        let spec = BootstrapReleaseSpec::core();
        assert_eq!(spec.cp_repo, "fledx/fledx-core");
        assert_eq!(spec.agent_repo, "fledx/fledx-core");
        assert_eq!(spec.cp_label, "core");
        assert_eq!(spec.agent_label, "core");
        assert!(matches!(
            spec.agent_version_fallback,
            BootstrapAgentVersionFallback::None
        ));
    }

    #[test]
    fn core_release_spec_does_not_generate_secrets_key() {
        let spec = BootstrapReleaseSpec::core();
        assert!(!matches!(
            spec.cp_secrets_master_key,
            BootstrapSecretsMasterKey::Generate
        ));
    }

    #[test]
    fn core_archive_names_render_expected() {
        let spec = BootstrapReleaseSpec::core();
        let cp = (spec.cp_archive_name)("1.2.3", "x86_64");
        let agent = (spec.agent_archive_name)("1.2.3", "x86_64");
        assert_eq!(cp, "fledx-cp-1.2.3-x86_64-linux.tar.gz");
        assert_eq!(agent, "fledx-agent-1.2.3-x86_64-linux.tar.gz");
    }

    #[test]
    fn core_archive_names_are_distinct() {
        let spec = BootstrapReleaseSpec::core();
        let cp = (spec.cp_archive_name)("1.2.3", "x86_64");
        let agent = (spec.agent_archive_name)("1.2.3", "x86_64");
        assert_ne!(cp, agent);
    }
}
