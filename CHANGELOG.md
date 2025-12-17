# Changelog

All notable changes to fledx-core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Changed the default control-plane API port to 49421 and the metrics port to 49422.
- Changed the default tunnel port to 49423.
- Changed the default node-agent metrics port to 49431.
- Changed the default gateway ports to 49441 (admin) and 49442 (listener).

## [0.4.1] – 2025-12-19

### Changed

- Refactor bootstrap workflow

## [0.4.0] - 2025-12-17

### Added

- Bootstrap and profile workflows for operator/DevOps installations:
    - `fledx bootstrap cp --cp-hostname <HOST> [--ssh-host ...]`: installs and configures
      the control plane (local or via SSH), writes a systemd unit + env file, and
      waits for readiness by default (`--no-wait`, `--wait-timeout-secs`).
    - `fledx bootstrap agent --ssh-host <HOST> [--name ...]`: installs an agent via SSH,
      auto-registers it with the control plane, and sets up a systemd unit + env file
      (waits for readiness by default).
    - Version selection:
        - `bootstrap cp`: defaults to the latest release (or use `--version latest` /
          `--version <TAG>`).
        - `bootstrap agent`: defaults to the control-plane version (queried via `GET /health`),
          or use `--version latest` / `--version <TAG>`.
    - SSH / sudo behavior:
        - SSH target via `--ssh-host`, optional `--ssh-user`, `--ssh-port`,
          `--ssh-identity-file`.
        - Sudo defaults to non-interactive (`sudo -n`); use `--sudo-interactive` to allow
          password prompts.
    - Local CLI profiles for repeatable operations:
        - `fledx profile set|show|list|set-default` manages local profiles (control-plane URL,
          operator header/token, registration token).
        - Global `--profile <NAME>` selects a profile for all commands.
        - Override precedence: CLI flags > environment variables > profile > defaults.
    - Local config file / secrets handling:
        - Expected path: `$XDG_CONFIG_HOME/fledx/config.toml` or `~/.config/fledx/config.toml`.
        - On Unix, overly-permissive config files are rejected (must be effectively `0600`)
          to avoid accidental token leakage.

> WARNING (Supply chain / security boundary):
> `--insecure-allow-unsigned` allows installs without signature verification (SHA256 only).
> This significantly weakens the trust model and should only be used for dev or legacy
> releases. In production, signature verification is the hard boundary intended to
> detect tampering of release assets.

### Changed

- Global CLI configuration can now be sourced from local profiles when using
  `--profile` (precedence: CLI flags > environment variables > profile > defaults).
- On Unix, the local profile config file must have private permissions; config
  files readable by group/other are rejected to reduce accidental token leaks.

## [0.3.0] - 2025-12-15

### Added

- Control Plane `--standalone` mode to run an embedded Node Agent for
  single-node deployments (the standalone agent binary remains available)

## [0.2.0] - 2025-12-15

### Breaking Changes

- Environment variable naming convention changed from double to single underscore separators
    - Control Plane: `FLEDX_CP__*` → `FLEDX_CP_*` (e.g., `FLEDX_CP__SERVER__HOST` → `FLEDX_CP_SERVER_HOST`)
    - Node Agent: `FLEDX_AGENT__*` → `FLEDX_AGENT_*` (e.g., `FLEDX_AGENT__CONTROL_PLANE_URL` →
      `FLEDX_AGENT_CONTROL_PLANE_URL`)
    - CLI: Variables now use `FLEDX_CLI_` prefix (e.g., `FLEDX_CONTROL_PLANE_URL` → `FLEDX_CLI_CONTROL_PLANE_URL`,
      `FLEDX_OPERATOR_TOKEN` → `FLEDX_CLI_OPERATOR_TOKEN`)
- Removed `FLEDX_TOKEN` environment variable alias - Use `FLEDX_CLI_OPERATOR_TOKEN` instead

### Fixes

- CLI now sends `x-agent-version` during node registration to satisfy
  control-plane compatibility enforcement

## [0.1.0] - 2025-12-14

Initial release of fledx-core, a distributed edge hosting platform for managing Docker containers across geographically
distributed edge nodes.

### Added

#### Core Platform

- Distributed container orchestration system for edge computing
- Centralized control plane with REST API
- Lightweight node agents for edge devices
- SQLite-based persistent storage with automatic migrations
- OpenAPI/Swagger documentation for all APIs
- Business Source License 1.1 (converts to Apache 2.0 on 2029-01-01)

#### Control Plane Features

- **Deployment Management**
    - Multi-replica deployments with automatic placement
    - Round-robin scheduling across nodes
    - Placement constraints (architecture, OS, labels, capacity requirements)
    - Placement hints (node affinity, anti-affinity, replica spreading)
    - Deployment lifecycle states (pending, deploying, running, stopped, failed)
    - Generation-based reconciliation for zero-downtime updates
    - Graceful start/stop operations
    - Port conflict detection and auto-assignment
    - Public ingress support with IP requirement flags

- **Configuration Management**
    - Named configuration objects with versioning
    - Key-value entries (plaintext or secret references)
    - File-based configuration references
    - Config attachments to deployments and nodes
    - Integrity checksums for config validation
    - Atomic config updates

- **Container Runtime**
    - Image-based container deployments
    - Custom entrypoint and command override
    - Environment variable injection
    - Secret management (environment variables and file mounts)
    - Port mappings with protocol support (TCP/UDP)
    - Volume mounts with configurable host path restrictions
    - Health checks (HTTP, TCP, exec probes)
    - Liveness and readiness probe support
    - Configurable probe intervals, timeouts, and failure thresholds

- **Networking & Connectivity**
    - HTTP CONNECT-based tunnel protocol for NAT traversal
    - HTTP relay/proxy through agent tunnels
    - TLS support for tunnel endpoints
    - Tunnel registry with status tracking
    - Configurable heartbeat intervals and timeouts
    - Automatic reconnection on tunnel failure

- **Monitoring & Observability**
    - Prometheus metrics export endpoint
    - Resource metrics collection (CPU, memory, network, disk I/O)
    - Usage rollups with minute-level aggregation
    - Per-replica and deployment-level metrics
    - HTTP request metrics with status code tracking
    - Audit logging for operator actions
    - Structured logging with JSON output support
    - Request ID tracking across components

- **Security**
    - Operator token authentication with bearer tokens
    - Node token authentication for agent registration
    - Registration token requirement for node enrollment
    - Token rotation and expiry support
    - Argon2-based token hashing with configurable pepper
    - Rate limiting on registration endpoint
    - Service identity bundle delivery for mTLS
    - Certificate and CA chain management

- **Operational Features**
    - Node inventory and status tracking
    - Heartbeat-based health monitoring
    - Automatic rescheduling on node failure
    - Version compatibility enforcement between control plane and agents
    - Automatic upgrade guidance for incompatible agents
    - Data retention policies for metrics and audit logs
    - Configurable resource limits and quotas
    - Dry-run migration mode

- **REST API Endpoints**
    - `/health` - Health check with version metadata
    - `/metrics` - Prometheus metrics
    - `/api/v1/deployments` - Deployment CRUD operations
    - `/api/v1/deployments/{id}/metrics` - Deployment resource metrics
    - `/api/v1/nodes` - Node management
    - `/api/v1/nodes/register` - Node registration
    - `/api/v1/nodes/{id}/heartbeats` - Agent heartbeats
    - `/api/v1/nodes/{id}/desired-state` - Desired state synchronization
    - `/api/v1/nodes/{id}/configs` - Config delivery
    - `/api/v1/configs` - Configuration management
    - `/api/v1/metrics/summary` - HTTP metrics summary
    - `/api/v1/usage` - Resource usage rollups
    - `/relay/{node_id}/{*path}` - HTTP tunnel relay

#### Node Agent Features

- **Container Management**
    - Docker daemon integration via Bollard
    - Container lifecycle management (create, start, stop, remove)
    - Automatic restart on failure with exponential backoff
    - Restart count tracking
    - Orphan container adoption and cleanup
    - Generation-based state reconciliation
    - Optional cleanup on agent shutdown

- **Health Checking**
    - HTTP health probe execution
    - TCP health probe execution
    - Exec health probe execution (command in container)
    - Configurable probe intervals and timeouts
    - Failure threshold tracking
    - Separate liveness and readiness probe support

- **Resource Monitoring**
    - Real-time CPU utilization tracking
    - Memory usage monitoring
    - Network I/O statistics (RX/TX bytes)
    - Disk I/O statistics (read/write bytes)
    - Bounded sample windows with configurable intervals
    - Concurrent metric collection
    - Automatic metric reporting to control plane

- **Tunnel Client**
    - HTTP CONNECT tunnel establishment
    - Automatic reconnection with backoff
    - Heartbeat frames for keepalive
    - TLS support for secure tunnels
    - Token-based authentication
    - Configurable tunnel routes
    - Forward request handling through tunnel

- **Envoy Gateway Integration**
    - Optional Envoy sidecar deployment
    - Automatic Envoy container lifecycle management
    - Admin port for metrics and health checks
    - Listener port for public ingress traffic
    - xDS integration with control plane
    - Configurable Envoy image version

- **Configuration Synchronization**
    - Automatic config sync from control plane
    - Environment variable injection from configs
    - Secret file mounting with permission management
    - Config versioning and checksum validation
    - Service identity certificate delivery

- **Prometheus Metrics**
    - Agent-level metrics export
    - Resource utilization metrics
    - Container state metrics
    - Health check status metrics

#### CLI Features

- **Node Management**
    - Register new edge nodes
    - List all nodes with filtering
    - Get detailed node information
    - Delete nodes
    - Attach/detach configs to nodes

- **Deployment Management**
    - Create deployments with full specification
    - Update existing deployments
    - Show deployment status and details
    - Stop/start deployments
    - Delete deployments
    - List deployments with filtering
    - Interactive deployment monitoring with TUI
    - Real-time log streaming

- **Configuration Management**
    - List all configurations
    - Show configuration details
    - Create configurations from files or inline
    - Update configurations
    - Delete configurations
    - Attach/detach configs to deployments
    - Load configs from environment files
    - Secret-backed configuration entries

- **Monitoring & Metrics**
    - View HTTP request metrics summary
    - List resource usage rollups with time filtering
    - Real-time status monitoring with TUI
    - Deployment progress tracking
    - Health status visualization

- **CLI Capabilities**
    - Multiple output formats (table, JSON, YAML)
    - Wide mode for additional columns
    - Interactive TUI with color-coded status
    - Watch mode for real-time updates
    - Pagination support (limit/offset)
    - Status-based filtering
    - Time range filtering for logs
    - Follow mode for log tailing
    - Shell completion generation (bash, zsh, fish, PowerShell)

#### Deployment Specification

- Name, image, and replica count
- Custom command and entrypoint override
- Environment variables (plaintext and secret references)
- Secret environment variables (optional/required)
- Secret file mounts with custom paths (optional/required)
- Port mappings with protocol selection (TCP/UDP)
- Exposed ports for public ingress
- Volume mounts (read-only/read-write)
- Health checks with full configuration
- Placement constraints (arch, OS, labels, capacity)
- Affinity hints (preferred nodes/labels)
- Anti-affinity hints (avoid nodes/labels)
- Replica spreading across nodes
- Desired state control (running/stopped)

#### Configuration Options

- **Control Plane**: 50+ environment variables for fine-tuning server, database, tunnel, authentication, limits,
  retention, scheduling, volumes, and compatibility
- **Node Agent**: 40+ environment variables for control plane connection, Docker integration, resource monitoring,
  tunnel configuration, gateway settings, and node metadata
- **CLI**: Environment variables for control plane URL, authentication, and registration

### Security

- All dependencies verified for BSL 1.1 license compatibility
- Security advisories monitored via cargo-deny
- Rustls 0.23 with modern TLS 1.3 support
- Argon2 password hashing with configurable parameters
- Token-based authentication across all components
- mTLS support for service-to-service communication
- Certificate rotation capabilities

---

## Release Notes

### What is fledx-core?

fledx-core is a lightweight, distributed container orchestration platform designed specifically for edge computing
scenarios. It enables you to deploy and manage Docker containers across geographically distributed edge nodes with:

- **Simple Architecture**: Centralized control plane + lightweight agents
- **NAT Traversal**: Tunnel-based connectivity for agents behind firewalls
- **Intelligent Scheduling**: Placement constraints and affinity rules
- **Security First**: mTLS, token authentication, and secret management
- **Edge-Optimized**: Minimal resource footprint on edge devices
- **Production Ready**: Health checks, auto-restart, metrics, and monitoring

### Getting Started

1. **Start Control Plane**:
   ```bash
   fledx-cp
   ```

2. **Register Edge Node**:
   ```bash
   fledx nodes register --name edge-1 --labels region=eu,zone=west
   ```

3. **Deploy Application**:
   ```bash
   fledx deployments create \
     --name my-app \
     --image nginx:alpine \
     --replicas 2 \
     --port 80:8080
   ```

4. **Monitor Status**:
   ```bash
   fledx status --watch
   ```

### What's Next?

Future releases will focus on:

- Enhanced scheduling algorithms
- Multi-region support
- Advanced networking features
- Performance optimizations
- Extended monitoring capabilities

---

[0.1.0]: https://github.com/fledx/fledx-core/releases/tag/v0.1.0
