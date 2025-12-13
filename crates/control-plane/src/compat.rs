use anyhow::Context;
use semver::Version;

use crate::config::CompatibilityConfig;

#[derive(Debug, Clone)]
pub struct AgentCompatibility {
    pub min_supported: Version,
    pub max_supported: Version,
    pub upgrade_url: Option<String>,
}

impl AgentCompatibility {
    pub fn from_config(cfg: &CompatibilityConfig) -> anyhow::Result<Self> {
        let cp_version = Version::parse(crate::version::VERSION)
            .context("parse control-plane version for compatibility gating")?;

        let min_supported = match &cfg.min_agent_version {
            Some(value) if !value.trim().is_empty() => {
                Version::parse(value).context("parse compatibility.min_agent_version")?
            }
            _ => default_min_supported(&cp_version),
        };

        let max_supported = match &cfg.max_agent_version {
            Some(value) if !value.trim().is_empty() => {
                Version::parse(value).context("parse compatibility.max_agent_version")?
            }
            _ => default_max_supported(&cp_version),
        };

        if min_supported > max_supported {
            anyhow::bail!("compatibility.min_agent_version must be <= max_agent_version");
        }

        let upgrade_url = cfg.upgrade_url.as_ref().and_then(|url| {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        Ok(Self {
            min_supported,
            max_supported,
            upgrade_url,
        })
    }

    pub fn is_supported(&self, agent_version: &Version) -> bool {
        agent_version >= &self.min_supported && agent_version <= &self.max_supported
    }
}

fn default_min_supported(cp_version: &Version) -> Version {
    Version::new(cp_version.major, cp_version.minor.saturating_sub(1), 0)
}

fn default_max_supported(cp_version: &Version) -> Version {
    // Allow any patch release within the forward minor by setting a generous
    // patch ceiling while keeping the value readable in logs and error payloads.
    Version::new(
        cp_version.major,
        cp_version.minor.saturating_add(1),
        999_999,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(min: Option<&str>, max: Option<&str>) -> CompatibilityConfig {
        CompatibilityConfig {
            min_agent_version: min.map(|s| s.to_string()),
            max_agent_version: max.map(|s| s.to_string()),
            upgrade_url: None,
        }
    }

    fn cfg_with_upgrade(
        min: Option<&str>,
        max: Option<&str>,
        upgrade: Option<&str>,
    ) -> CompatibilityConfig {
        CompatibilityConfig {
            min_agent_version: min.map(|s| s.to_string()),
            max_agent_version: max.map(|s| s.to_string()),
            upgrade_url: upgrade.map(|s| s.to_string()),
        }
    }

    #[test]
    fn defaults_span_minor_window() {
        let compat = AgentCompatibility::from_config(&cfg(None, None)).unwrap();
        let cp = Version::parse(crate::version::VERSION).unwrap();
        assert_eq!(
            compat.min_supported,
            Version::new(cp.major, cp.minor.saturating_sub(1), 0)
        );
        assert_eq!(
            compat.max_supported,
            Version::new(cp.major, cp.minor.saturating_add(1), 999_999)
        );
    }

    #[test]
    fn honors_overrides() {
        let compat = AgentCompatibility::from_config(&cfg(Some("1.2.3"), Some("2.0.0"))).unwrap();
        assert_eq!(compat.min_supported, Version::new(1, 2, 3));
        assert_eq!(compat.max_supported, Version::new(2, 0, 0));
    }

    #[test]
    fn rejects_inverted_bounds() {
        let result = AgentCompatibility::from_config(&cfg(Some("2.0.0"), Some("1.0.0")));
        assert!(result.is_err());
    }

    #[test]
    fn trims_upgrade_url_and_ignores_blank() {
        let compat = AgentCompatibility::from_config(&cfg_with_upgrade(
            None,
            None,
            Some("  https://docs/upgrade  "),
        ))
        .unwrap();
        assert_eq!(compat.upgrade_url.as_deref(), Some("https://docs/upgrade"));

        let blank =
            AgentCompatibility::from_config(&cfg_with_upgrade(None, None, Some("   "))).unwrap();
        assert!(blank.upgrade_url.is_none());
    }

    #[test]
    fn is_supported_is_inclusive_on_bounds() {
        let compat = AgentCompatibility::from_config(&cfg(Some("1.2.3"), Some("1.4.0"))).unwrap();
        assert!(
            compat.is_supported(&Version::new(1, 2, 3)),
            "min bound should be inclusive"
        );
        assert!(
            compat.is_supported(&Version::new(1, 3, 5)),
            "middle of range should pass"
        );
        assert!(
            compat.is_supported(&Version::new(1, 4, 0)),
            "max bound should be inclusive"
        );
        assert!(
            !compat.is_supported(&Version::new(1, 4, 1)),
            "beyond max should fail"
        );
    }

    #[test]
    fn control_plane_version_is_valid_semver() {
        Version::parse(crate::version::VERSION).expect("control-plane VERSION must be semver");
    }

    #[test]
    fn invalid_override_surfaces_parse_context() {
        let err = AgentCompatibility::from_config(&cfg(Some("not-a-semver"), None)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("compatibility.min_agent_version"));
    }
}
