# fledx-core

**Distributed Edge Hosting** - A lightweight, distributed container orchestration platform for managing Docker
containers across multiple edge nodes.

## Overview

fledx-core is a (not yet) production-ready edge computing platform that enables centralized management of containerized 
workloads across geographically distributed edge devices. Built with Rust for performance and reliability, it provides 
a complete solution for deploying, monitoring, and managing applications at the edge.

### Key Features

- **Centralized Control Plane** - Single point of control for managing deployments across all edge nodes
- **Distributed Node Agents** - Lightweight agents running on edge devices to execute container workloads
- **Intelligent Scheduling** - Round-robin scheduling with placement constraints, affinity rules, and anti-affinity
  support
- **Multi-Replica Deployments** - Scale applications across multiple nodes with automatic placement
- **Health Monitoring** - Built-in health checks (HTTP, TCP, exec) with automatic container restarts
- **Resource Tracking** - Real-time monitoring of CPU, memory, network, and disk usage
- **Tunnel-Based Connectivity** - Secure agent connections through NAT/firewalls without complex networking
- **Public Ingress** - Envoy-based gateway for routing external traffic to containerized services
- **Configuration Management** - Centralized config and secrets injection (environment variables and files)
- **CLI Tool** - Powerful command-line interface with interactive TUI and watch mode
- **Observability** - Structured logging, Prometheus metrics, and audit trails
- **Production Ready** - Database migrations, chaos recovery tests, and compatibility enforcement

## Architecture

fledx-core consists of three main components:

```
┌─────────────────┐
│  CLI (Operator) │
└────────┬────────┘
         │
         │ REST API
         ▼
┌─────────────────────┐
│   Control Plane     │◄──────┐
│  - Scheduler        │       │
│  - API Server       │       │ Tunnel/Heartbeat
│  - SQLite DB        │       │
│  - Tunnel Registry  │       │
└─────────────────────┘       │
         │                    │
         │ Deployment Sync    │
         ▼                    │
┌─────────────────────┐       │
│    Node Agent 1     │───────┘
│  - Docker Runtime   │
│  - Health Checker   │
│  - Envoy Gateway    │
└─────────────────────┘

┌─────────────────────┐
│    Node Agent 2     │───────┐
│  - Docker Runtime   │       │
│  - Health Checker   │       │ Tunnel/Heartbeat
│  - Envoy Gateway    │       │
└─────────────────────┘       │
                              │
         ...                  ▼
                     ┌─────────────────────┐
                     │   Control Plane     │
                     └─────────────────────┘
```

### Components

#### Control Plane

The centralized orchestration server that:

- Manages deployment lifecycle and scheduling decisions
- Tracks node health and availability
- Provides REST API for CLI and agents
- Maintains persistent state in SQLite
- Manages tunnel connections from agents
- Exports Prometheus metrics

#### Node Agent

Lightweight agent running on each edge node that:

- Connects to control plane via HTTP/HTTPS
- Manages Docker containers using the local Docker daemon
- Reports health and resource metrics
- Establishes persistent tunnels for connectivity
- Runs Envoy gateway for public ingress routing
- Syncs configuration and secrets from control plane

#### CLI

Command-line interface for operators to:

- Deploy and manage containerized applications
- Register and monitor edge nodes
- Manage configurations and secrets
- Query metrics and usage statistics
- Watch real-time deployment status with interactive TUI

## Getting Started

### Prerequisites

- **Rust toolchain** (1.70+) - [Install Rust](https://rustup.rs/)
- **Docker** - For running containers on edge nodes
- **SQLite** - For control plane persistence (usually pre-installed)
- **Just** (optional) - Task runner for development - [Install Just](https://github.com/casey/just)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/fledx/fledx-core.git
cd fledx-core

# Build all components
cargo build --release

# Or use just
just build
```

The compiled binaries will be in `target/release/`:

- `fledx-cp` - Control plane server
- `fledx-agent` - Edge node agent
- `fledx` - CLI tool

### Quick Start

#### 1. Start the Control Plane

```bash
# Run with default settings (SQLite in current directory)
./target/release/fledx-cp

# Or with custom configuration via environment variables
export FLEDX_CP_SERVER_HOST=0.0.0.0
export FLEDX_CP_SERVER_PORT=8080
export FLEDX_CP_DATABASE_URL=sqlite://./fledx.db
./target/release/fledx-cp
```

#### 2. Register an Edge Node

First, generate a registration token via the control plane API or database. Then start the node agent:

```bash
# Configure the agent
export FLEDX_AGENT_CONTROL_PLANE_URL=http://localhost:8080
export FLEDX_AGENT_NODE_ID=550e8400-e29b-41d4-a716-446655440000
export FLEDX_AGENT_NODE_TOKEN=your-node-token

# Start the agent
./target/release/fledx-agent
```

#### 3. Deploy a Container

```bash
# Configure CLI
export FLEDX_CLI_CONTROL_PLANE_URL=http://localhost:8080
export FLEDX_CLI_OPERATOR_TOKEN=your-operator-token

# Create a deployment
./target/release/fledx deployments create \
  --name nginx-demo \
  --image nginx:latest \
  --replicas 2 \
  --port 80

# Check deployment status
./target/release/fledx deployments status nginx-demo

# Watch deployment in real-time (interactive TUI)
./target/release/fledx deployments status nginx-demo --watch
```

## Configuration

### Control Plane Configuration

Configuration via environment variables with prefix `FLEDX_CP_`:

```bash
# Server settings
FLEDX_CP_SERVER_HOST=0.0.0.0
FLEDX_CP_SERVER_PORT=8080

# Database
FLEDX_CP_DATABASE_URL=sqlite://./fledx.db

# Tunnel settings
FLEDX_CP_TUNNEL_ADVERTISED_HOST=127.0.0.1
FLEDX_CP_TUNNEL_ADVERTISED_PORT=7443
FLEDX_CP_TUNNEL_USE_TLS=false
FLEDX_CP_TUNNEL_HEARTBEAT_INTERVAL_SECS=30
FLEDX_CP_TUNNEL_HEARTBEAT_TIMEOUT_SECS=90

# Authentication
FLEDX_CP_REGISTRATION_TOKEN=your-registration-token
FLEDX_CP_OPERATOR_TOKENS=token1,token2  # Comma-separated list
FLEDX_CP_OPERATOR_HEADER_NAME=authorization
FLEDX_CP_TOKENS_PEPPER=your-token-pepper

# Limits
FLEDX_CP_LIMITS_REGISTRATION_BODY_BYTES=16384
FLEDX_CP_LIMITS_HEARTBEAT_BODY_BYTES=65536
FLEDX_CP_LIMITS_CONFIG_PAYLOAD_BYTES=131072

# Retention (in seconds)
FLEDX_CP_RETENTION_INSTANCE_STATUS_SECS=86400      # 24 hours
FLEDX_CP_RETENTION_INSTANCE_METRICS_SECS=600       # 10 minutes
FLEDX_CP_RETENTION_USAGE_WINDOW_SECS=604800        # 7 days
FLEDX_CP_RETENTION_USAGE_CLEANUP_INTERVAL_SECS=300 # 5 minutes

# Reachability
FLEDX_CP_REACHABILITY_HEARTBEAT_STALE_SECS=90
FLEDX_CP_REACHABILITY_SWEEP_INTERVAL_SECS=15
FLEDX_CP_REACHABILITY_RESCHEDULE_ON_UNREACHABLE=true

# Ports
FLEDX_CP_PORTS_AUTO_ASSIGN=false
FLEDX_CP_PORTS_RANGE_START=30000
FLEDX_CP_PORTS_RANGE_END=40000

# Volumes
FLEDX_CP_VOLUMES_ALLOWED_HOST_PREFIXES=/data,/mnt/storage

# Features
FLEDX_CP_FEATURES_ENFORCE_AGENT_COMPATIBILITY=true
```

### Node Agent Configuration

Configuration via environment variables with prefix `FLEDX_AGENT_`:

```bash
# Control plane connection (required)
FLEDX_AGENT_CONTROL_PLANE_URL=https://control.example.com
FLEDX_AGENT_NODE_ID=550e8400-e29b-41d4-a716-446655440000
FLEDX_AGENT_NODE_TOKEN=your-node-token

# Secrets
FLEDX_AGENT_SECRETS_DIR=/var/run/secrets
FLEDX_AGENT_SECRETS_PREFIX=FLEDX_SECRET_

# Heartbeat
FLEDX_AGENT_HEARTBEAT_INTERVAL_SECS=30
FLEDX_AGENT_HEARTBEAT_TIMEOUT_SECS=5
FLEDX_AGENT_HEARTBEAT_MAX_RETRIES=3

# Resource monitoring
FLEDX_AGENT_RESOURCE_SAMPLE_INTERVAL_SECS=30
FLEDX_AGENT_RESOURCE_SAMPLE_WINDOW=120

# Reconciliation
FLEDX_AGENT_RECONCILE_INTERVAL_SECS=10

# Restart policy
FLEDX_AGENT_RESTART_BACKOFF_MS=1000
FLEDX_AGENT_RESTART_BACKOFF_MAX_MS=30000
FLEDX_AGENT_RESTART_FAILURE_LIMIT=5

# TLS settings
FLEDX_AGENT_ALLOW_INSECURE_HTTP=false
FLEDX_AGENT_TLS_INSECURE_SKIP_VERIFY=false
FLEDX_AGENT_CA_CERT_PATH=/path/to/ca.crt

# Metrics
FLEDX_AGENT_METRICS_HOST=127.0.0.1
FLEDX_AGENT_METRICS_PORT=9091

# Node metadata
FLEDX_AGENT_ARCH=x86_64
FLEDX_AGENT_OS=linux
FLEDX_AGENT_LABELS=region=eu,zone=west  # Comma-separated key=value pairs

# Capacity
FLEDX_AGENT_CAPACITY_CPU_MILLIS=4000
FLEDX_AGENT_CAPACITY_MEMORY_BYTES=8589934592  # 8GB

# Volumes
FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES=/var/lib/fledx/volumes
FLEDX_AGENT_VOLUME_DATA_DIR=/var/lib/fledx

# Tunnel settings (nested)
FLEDX_AGENT_TUNNEL_ENDPOINT_HOST=127.0.0.1
FLEDX_AGENT_TUNNEL_ENDPOINT_PORT=7443
FLEDX_AGENT_TUNNEL_USE_TLS=false

# Gateway (Envoy) settings (nested)
FLEDX_AGENT_GATEWAY_ENABLED=true
# Required when enabled=true:
FLEDX_AGENT_GATEWAY_ENVOY_IMAGE=envoyproxy/envoy:v1.33-latest
FLEDX_AGENT_GATEWAY_ADMIN_PORT=9901
FLEDX_AGENT_GATEWAY_LISTENER_PORT=10000
FLEDX_AGENT_GATEWAY_XDS_PORT=18000

# Cleanup
FLEDX_AGENT_CLEANUP_ON_SHUTDOWN=false
```

### CLI Configuration

```bash
# Control plane URL
export FLEDX_CLI_CONTROL_PLANE_URL=http://localhost:8080

# Operator authentication token
export FLEDX_CLI_OPERATOR_TOKEN=your-operator-token
```

## Usage Examples

### Deployment Management

```bash
# Create a deployment
fledx deployments create \
  --name myapp \
  --image myapp:v1.0 \
  --replicas 3 \
  --port 8080 \
  --env KEY=value

# Update deployment
fledx deployments update myapp --image myapp:v1.1

# Scale deployment
fledx deployments update myapp --replicas 5

# Delete deployment
fledx deployments delete myapp

# List all deployments
fledx deployments list

# Get deployment status
fledx deployments status myapp
```

### Node Management

```bash
# List all nodes
fledx nodes list

# Get node details
fledx nodes get edge-node-1

# Remove a node
fledx nodes delete edge-node-1
```

### Configuration Management

```bash
# Create configuration
fledx configs create myconfig --from-file ./config.yaml

# List configurations
fledx configs list

# Delete configuration
fledx configs delete myconfig
```

### Monitoring and Metrics

```bash
# Query resource metrics
fledx metrics query --node edge-node-1

# Get usage statistics
fledx usage get --deployment myapp

# Watch deployment status in real-time
fledx deployments status myapp --watch
```

## Development

### Project Structure

```
fledx-core/
├── crates/
│   ├── fledx-cp/    # Control plane server
│   │   ├── src/
│   │   │   ├── http/     # REST API routes
│   │   │   ├── persistence/  # Database layer
│   │   │   └── services/ # Business logic
│   │   ├── migrations/   # Database migrations
│   │   └── tests/        # Integration tests
│   ├── fledx-agent/       # Edge node agent
│   │   ├── src/
│   │   │   ├── runtime/  # Docker runtime abstraction
│   │   │   └── services/ # Background tasks
│   │   └── tests/        # Agent tests
│   ├── fledx/              # CLI tool
│   │   ├── src/
│   │   │   ├── commands/ # Command implementations
│   │   │   └── view/     # TUI rendering
│   │   └── tests/        # CLI tests
│   └── common/           # Shared types and DTOs
├── Cargo.toml            # Workspace manifest
└── justfile              # Build automation
```

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
cargo run -p fledx-cp
cargo run -p fledx-agent
cargo run -p fledx -- deployments list
```

### Database Migrations

Migrations are managed by SQLx and located in `crates/fledx-cp/migrations/`.

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
FLEDX_RUN_CHAOS=1 cargo test -p fledx-agent

# Run integration tests
cargo test -p fledx-cp --test '*'
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

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Setup

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
