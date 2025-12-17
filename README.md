# fledx-core

**Distributed Edge Hosting** – A lightweight container orchestration platform for managing Docker containers across
multiple edge nodes.

## Quick Start

Get your edge platform running in minutes with the built-in bootstrap commands.

### 1. Install the CLI

Download the latest release from [GitHub Releases](https://github.com/fledx/fledx-core/releases) or build from source:

```bash
cargo install --path crates/cli
```

### 2. Bootstrap the Control Plane

Install and configure the control plane on a server (local or remote via SSH):

```bash
# Local installation
fledx bootstrap cp --sudo-interactive --cp-hostname 192.168.178.123 # Hostname or IP must be reachable by agents

# Remote installation via SSH
fledx bootstrap cp \
  --cp-hostname your-server.example.com \
  --ssh-host user@your-server.example.com
```

The bootstrap command handles everything automatically:

- Downloads the correct binary for your platform
- Creates a dedicated system user
- Sets up systemd services
- Generates secure tokens
- Configures the CLI profile for immediate use

### 3. Add Edge Nodes

Add nodes to your cluster with a single command:

```bash
fledx bootstrap agent --ssh-host user@edge-node-1.local
fledx bootstrap agent --ssh-host user@edge-node-2.local
```

Each node is automatically:

- Installed with the matching agent version
- Registered with the control plane
- Configured and started as a systemd service

### 4. Deploy Your First Application

```bash
fledx deployments create \
  --name nginx-demo \
  --image nginx:latest \
  --replicas 2 \
  --port 80

# Watch deployment status in real-time
fledx status --watch
```

That's it! Your application is now running across your edge nodes.

## Key Features

- **One-Command Setup** – Bootstrap control plane and agents via SSH
- **Intelligent Scheduling** – Placement constraints, affinity, and anti-affinity rules
- **Health Monitoring** – HTTP, TCP, and exec health checks with auto-restart
- **Tunnel Connectivity** – NAT/firewall-friendly agent connections
- **Public Ingress** – Envoy-based gateway for external traffic routing
- **Real-Time Status Watch** – Live terminal updates for monitoring deployments
- **Prometheus Metrics** – Built-in observability and monitoring

## Architecture

```
┌─────────────────┐
│  CLI (fledx)    │
└────────┬────────┘
         │ REST API
         ▼
┌─────────────────────┐
│   Control Plane     │◄──── Tunnel/Heartbeat ────┐
│  (fledx-cp)         │                           │
└─────────────────────┘                           │
         │                                        │
         │ Deployment Sync                        │
         ▼                                        │
┌─────────────────────┐                  ┌────────┴────────┐
│   Node Agent 1      │                  │   Node Agent N  │
│   (fledx-agent)     │                  │   (fledx-agent) │
│   + Docker          │       ...        │   + Docker      │
└─────────────────────┘                  └─────────────────┘
```

## Bootstrap Options

### Control Plane Bootstrap

```bash
fledx bootstrap cp --cp-hostname <HOST> [OPTIONS]
```

| Option                | Default        | Description                               |
|-----------------------|----------------|-------------------------------------------|
| `--cp-hostname`       | (required)     | Hostname/IP reachable by agents           |
| `--ssh-host`          | -              | SSH target for remote install (user@host) |
| `--ssh-identity-file` | -              | SSH private key path                      |
| `--version`           | latest         | Version to install                        |
| `--server-port`       | 8080           | HTTP API port                             |
| `--tunnel-port`       | 7443           | Agent tunnel port                         |
| `--bin-dir`           | /usr/local/bin | Binary installation directory             |
| `--config-dir`        | /etc/fledx     | Configuration directory                   |
| `--data-dir`          | /var/lib/fledx | Persistent data directory                 |

### Agent Bootstrap

```bash
fledx bootstrap agent --ssh-host <HOST> [OPTIONS]
```

| Option                    | Default               | Description                         |
|---------------------------|-----------------------|-------------------------------------|
| `--ssh-host`              | (required)            | SSH target (user@host)              |
| `--ssh-identity-file`     | -                     | SSH private key path                |
| `--name`                  | ssh hostname          | Node name for registration          |
| `--version`               | control-plane version | Version to install                  |
| `--label`                 | -                     | Node labels (repeatable, KEY=VALUE) |
| `--capacity-cpu-millis`   | -                     | CPU capacity hint                   |
| `--capacity-memory-bytes` | -                     | Memory capacity hint                |

## CLI Commands

### Status Overview

```bash
# Combined status for nodes and deployments
fledx status

# Watch status in real-time
fledx status --watch

# Filter by status
fledx status --node-status ready --deploy-status running

# Show only nodes or deployments
fledx status --nodes-only
fledx status --deploys-only
```

### Deployments

```bash
# Create a new deployment
fledx deployments create --name myapp --image myapp:v1.0 --replicas 3 --port 8080

# List all deployments
fledx deployments list
fledx deployments list --status running --wide

# Show deployment status summaries
fledx deployments status
fledx deployments status --status running

# Update a deployment (requires UUID)
fledx deployments update --id <UUID> --image myapp:v1.1
fledx deployments update --id <UUID> --replicas 5

# Watch a specific deployment
fledx deployments watch --id <UUID>
fledx deployments watch --id <UUID> --follow-logs

# Stop a deployment
fledx deployments stop --id <UUID>

# Delete a deployment
fledx deployments delete --id <UUID>

# View deployment logs
fledx deployments logs
fledx deployments logs --resource-id <UUID> --follow
```

### Nodes

```bash
# Register a new node manually
fledx nodes register --name edge-node-1 --arch amd64 --os linux
fledx nodes register --name edge-node-1 --label region=eu --label zone=west

# List all nodes
fledx nodes list
fledx nodes list --status ready --wide

# Show node status summaries
fledx nodes status
fledx nodes status --status unreachable
```

### Configurations

```bash
# Create a new config
fledx configs create --name myconfig --var KEY=VALUE
fledx configs create --name myconfig --from-env-file ./config.env
fledx configs create --name myconfig --secret-entry API_KEY=my-secret

# List all configs
fledx configs list

# Show a specific config
fledx configs show --id <UUID>

# Update a config
fledx configs update --id <UUID> --var NEW_KEY=NEW_VALUE

# Delete a config
fledx configs delete --id <UUID>

# Attach/detach configs to deployments or nodes
fledx configs attach deployment --config-id <UUID> --deployment-id <UUID>
fledx configs attach node --config-id <UUID> --node-id <UUID>
fledx configs detach deployment --config-id <UUID> --deployment-id <UUID>
fledx configs detach node --config-id <UUID> --node-id <UUID>
```

### Monitoring

```bash
# Show aggregated HTTP metrics
fledx metrics show
fledx metrics show --limit 10 --json

# List resource usage
fledx usage list --deployment <UUID>
fledx usage list --node <UUID> --range 30m

# Real-time status monitoring
fledx status --watch
```

### Profiles

Profiles store CLI configuration locally (`~/.config/fledx/profiles.toml`).

```bash
# List configured profiles
fledx profile list

# Show current profile
fledx profile show
fledx profile show --name production

# Create or update a profile
fledx profile set --name production \
  --control-plane-url https://cp.example.com \
  --operator-token <TOKEN>

# Set the default profile
fledx profile set-default --name production

# Use a specific profile for a command
fledx --profile production status
```

## Development

### Development Commands

Using [Just](https://github.com/casey/just) task runner:

```bash
# Format code
just fmt

# Run linter
just clippy

# Check compilation
just check

# Run tests
just test

# Run chaos recovery tests
just chaos-test

# Pre-commit checks (format + lint + test)
just pre-commit
```

Or using Cargo directly:

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Run specific crate
cargo run -p control-plane
cargo run -p node-agent
cargo run -p cli -- deployments list
```

### Database Migrations

Migrations are managed by SQLx and located in `crates/control-plane/migrations/`.

```bash
# Run migrations (automatic on control plane startup)
fledx-cp

# Dry-run mode (show migrations without applying)
fledx-cp --migrations-dry-run
```

### Testing

```bash
# Run all tests
cargo test

# Run chaos recovery tests (tests agent recovery from failures)
FLEDX_RUN_CHAOS=1 cargo test -p node-agent

# Run integration tests
cargo test -p control-plane --test '*'
```

## Observability

### Logging

Structured logging with JSON output support:

```bash
# Enable JSON logging
export RUST_LOG=info
fledx-cp --json-logs

# Adjust log level
export RUST_LOG=debug,hyper=info
fledx-agent
```

### Metrics

Prometheus metrics are exported by the control plane:

```bash
# Metrics endpoint
curl http://localhost:8080/metrics
```

### Health Checks

```bash
# Control plane health
curl http://localhost:8080/health

# Node agent health
curl http://localhost:9901/health  # Envoy admin endpoint
```

## Advanced Configuration

For manual installations or fine-tuning, components can be configured via environment variables. The bootstrap commands
handle all of this automatically.

<details>
<summary>Control Plane Environment Variables</summary>

```bash
# Server
FLEDX_CP_SERVER_HOST=0.0.0.0
FLEDX_CP_SERVER_PORT=8080
FLEDX_CP_DATABASE_URL=sqlite:///var/lib/fledx/fledx.db

# Tunnel
FLEDX_CP_TUNNEL_ADVERTISED_HOST=your-server.example.com
FLEDX_CP_TUNNEL_ADVERTISED_PORT=7443
FLEDX_CP_TUNNEL_USE_TLS=false

# Authentication
FLEDX_CP_OPERATOR_TOKENS=token1,token2
FLEDX_CP_TOKENS_PEPPER=your-pepper

# Reachability
FLEDX_CP_REACHABILITY_HEARTBEAT_STALE_SECS=90
FLEDX_CP_REACHABILITY_RESCHEDULE_ON_UNREACHABLE=true
```

</details>

<details>
<summary>Node Agent Environment Variables</summary>

```bash
# Control plane connection (required)
FLEDX_AGENT_CONTROL_PLANE_URL=https://control.example.com
FLEDX_AGENT_NODE_ID=<uuid>
FLEDX_AGENT_NODE_TOKEN=<token>

# Node metadata
FLEDX_AGENT_LABELS=region=eu,zone=west
FLEDX_AGENT_CAPACITY_CPU_MILLIS=4000
FLEDX_AGENT_CAPACITY_MEMORY_BYTES=8589934592

# Tunnel
FLEDX_AGENT_TUNNEL_ENDPOINT_HOST=your-server.example.com
FLEDX_AGENT_TUNNEL_ENDPOINT_PORT=7443

# Gateway (Envoy)
FLEDX_AGENT_GATEWAY_ENABLED=true
FLEDX_AGENT_GATEWAY_ENVOY_IMAGE=envoyproxy/envoy:v1.33-latest
```

</details>

<details>
<summary>CLI Environment Variables</summary>

```bash
FLEDX_CLI_CONTROL_PLANE_URL=http://localhost:8080
FLEDX_CLI_OPERATOR_TOKEN=your-operator-token
```

Note: The CLI can also be configured via profiles (`~/.config/fledx/profiles.toml`), which are automatically managed by
the bootstrap commands.

</details>

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `just pre-commit` to ensure code quality
5. Submit a pull request

## Acknowledgments

Built with:

- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [Bollard](https://github.com/fussybeaver/bollard) - Docker API client
- [SQLx](https://github.com/launchbadge/sqlx) - Async SQL toolkit
- [Tokio](https://tokio.rs/) - Async runtime
- [Ratatui](https://github.com/ratatui-org/ratatui) - Terminal UI framework
- [Envoy Proxy](https://www.envoyproxy.io/) - Gateway and proxy
