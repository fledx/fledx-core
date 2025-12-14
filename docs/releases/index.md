# Releases

This page provides release notes and upgrade information for Distributed Edge Hosting.

## Latest Release: v0.1.0

**Release Date:** 2025-12-03

### Highlights

- Initial production-ready release of Distributed Edge Hosting
- Control Plane with Axum API, SQLite backend, and scheduler
- Node Agent with Docker runtime integration and heartbeat loops
- CLI for deployment management and node registration
- Local demo and E2E bootstrap scripts
- Comprehensive documentation suite

### Components

This release includes:

- **Control Plane** - Central orchestration service with REST API
- **Node Agent** - Edge node agent with Docker integration
- **CLI** - Command-line interface for operators
- **Observability UI** - Web-based deployment and metrics console
- **Documentation** - Complete guides and reference documentation

### Key Features

- **Deployment Management** - Create, update, stop, and delete containerized deployments
- **Node Registration** - Secure node enrollment with token-based authentication
- **Health Checks** - HTTP, TCP, and exec-based readiness/liveness probes
- **Configuration Management** - First-class config resources with versioning
- **Metrics & Monitoring** - Prometheus-compatible metrics endpoints
- **TLS Support** - Secure transport with reverse proxy integration
- **Version Compatibility** - Enforced version windows for control plane and agents

### Breaking Changes

None (initial release)

### Upgrade Notes

This is the initial release. For future upgrades, refer to the [Upgrade Guide](../guides/upgrades.md).

## Release Information

Each release follows semantic versioning (MAJOR.MINOR.PATCH) and includes:

- **Version Number** - Semantic versioning (MAJOR.MINOR.PATCH)
- **Release Highlights** - Key features and improvements
- **Breaking Changes** - Incompatible changes requiring action
- **Upgrade Steps** - Instructions for upgrading from previous versions
- **API/CLI/UI Changes** - Interface changes and deprecations
- **Compatibility Notes** - Supported version windows between control plane and agents

## Versioning Policy

Distributed Edge Hosting follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

### Compatibility Window

The control plane maintains a compatibility window of ±1 minor version for node agents:

- Example: Control Plane v1.5.x supports Node Agents v1.4.x through v1.6.x
- This window is configurable via `FLEDX_CP_COMPATIBILITY_MIN_AGENT_VERSION` and `FLEDX_CP_COMPATIBILITY_MAX_AGENT_VERSION`

## Upgrade Process

For detailed upgrade instructions, see the [Upgrade Guide](../guides/upgrades.md).

### Pre-Upgrade Checklist

Before upgrading:

1. Review release notes for breaking changes
2. Backup the control plane database
3. Test upgrade in staging environment
4. Verify node agent compatibility window
5. Schedule maintenance window for production

### Upgrade Order

Always upgrade in this order:

1. **Control Plane** - Upgrade first to maintain compatibility
2. **Node Agents** - Upgrade one at a time to avoid service disruption
3. **CLI** - Upgrade operator workstations

## Version History

### v0.1.0 - Initial Release (2025-12-03)

**Status:** Current

**Highlights:**
- Initial production-ready release
- Control Plane with REST API
- Node Agent with Docker integration
- CLI for deployment management
- Web UI for monitoring

**Components:**
- fledx-cp v0.1.0
- fledx-agent v0.1.0
- fledx CLI v0.1.0

**Upgrade:** N/A (initial release)

**Known Issues:**
- None reported

---

### Future Releases

Future releases will be documented here following this format:

#### v0.2.0 - Example Minor Release (TBD)

**Status:** Planned

**Highlights:**
- New feature: Multi-tenant support
- Improvement: Enhanced metrics
- Bug fix: Memory leak in agent

**Breaking Changes:**
- API: New required field in deployment spec
- Config: New environment variable format

**Upgrade from v0.1.0:**
```bash
# 1. Backup database
sudo systemctl stop fledx-cp
sudo cp /var/lib/fledx/fledx-cp.db /var/lib/fledx/backups/

# 2. Upgrade control plane
sudo cp fledx-cp-v0.2.0 /usr/local/bin/fledx-cp
sudo systemctl start fledx-cp

# 3. Verify
curl http://localhost:8080/health

# 4. Upgrade agents
ssh <node-host>
sudo systemctl stop fledx-agent
sudo cp fledx-agent-v0.2.0 /usr/local/bin/fledx-agent
sudo systemctl start fledx-agent
```

**Components:**
- fledx-cp v0.2.0
- fledx-agent v0.2.0
- fledx CLI v0.2.0

**Known Issues:**
- Minor UI rendering delay in dashboard on first load
- Workaround: Refresh browser if UI appears unresponsive

---

## Release Calendar

| Version | Planned Date | Status | Focus |
|---------|-------------|--------|-------|
| v0.1.0 | 2025-12-03 | ✅ Released | Initial release |
| v0.2.0 | 2026-Q1 | 📋 Planned | Multi-tenancy, enhanced metrics |
| v0.3.0 | 2026-Q2 | 📋 Planned | High availability, clustering |
| v1.0.0 | 2026-Q3 | 🎯 Target | Production hardening, performance |

## Complete Changelog

For detailed changelogs with all commits and contributors, see [`CHANGELOG.md`](../../CHANGELOG.md) in the project root.

## Support

For questions about specific releases or upgrade issues, refer to:

- [Upgrade Guide](../guides/upgrades.md) - Step-by-step upgrade procedures
- [Troubleshooting Guide](../guides/troubleshooting.md) - Common issues and solutions
- [Monitoring Guide](../guides/monitoring.md) - Day-2 operations
- [FAQ](../faq.md) - Frequently asked questions

