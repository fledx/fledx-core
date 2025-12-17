# Getting Started

Get your edge platform running in minutes with the built-in bootstrap commands.

## Prerequisites

- Linux hosts with Docker installed on agent nodes
- SSH access to your servers (for remote installation)
- Downloaded CLI binary (`fledx`) for your platform

## Quick Start

### 1. Install the CLI

Download the latest release from the product download page or build from source:

```bash
# From release
tar -xf fledx-cli.tar.gz
sudo install -m 0755 fledx /usr/local/bin/

# Or build from source
cargo install --path crates/cli
```

### 2. Bootstrap the Control Plane

Install and configure the control plane on a server:

```bash
# Local installation (on the current machine)
fledx bootstrap cp --cp-hostname localhost

# Remote installation via SSH
fledx bootstrap cp \
  --cp-hostname your-server.example.com \
  --ssh-host user@your-server.example.com
```

The bootstrap command handles everything automatically:

- Downloads the correct binary for the target platform
- Creates a dedicated `fledx` system user
- Sets up systemd services
- Generates secure tokens
- Configures the CLI profile for immediate use

After bootstrap completes, your CLI is automatically configured to connect to the new control plane.

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

### 4. Verify the Setup

Check that everything is running:

```bash
# View system status
fledx status

# Or watch in real-time
fledx status --watch
```

You should see your control plane healthy and nodes in `ready` state.

### 5. Deploy Your First Application

```bash
fledx deployments create \
  --name hello-web \
  --image hashicorp/http-echo:0.2.3 \
  --port 8080:5678/tcp \
  --env TEXT="Hello from the edge!"

# Watch deployment progress
fledx deployments watch --id <deployment-id>
```

Access your application:

```bash
curl http://<node-ip>:8080
# Output: Hello from the edge!
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
| `--server-port`       | 49421          | HTTP API port                             |
| `--tunnel-port`       | 49423          | Agent tunnel port                         |
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
| `--name`                  | SSH hostname          | Node name for registration          |
| `--version`               | control-plane version | Version to install                  |
| `--label`                 | -                     | Node labels (repeatable, KEY=VALUE) |
| `--capacity-cpu-millis`   | -                     | CPU capacity hint                   |
| `--capacity-memory-bytes` | -                     | Memory capacity hint                |

## Managing Profiles

The bootstrap commands automatically create CLI profiles. You can manage multiple control planes:

```bash
# List profiles
fledx profile list

# Show current profile
fledx profile show

# Switch default profile
fledx profile set-default --name production

# Use a specific profile for one command
fledx --profile staging status
```

## What's Next

- **Deploy Applications:** [First Deployment Tutorial](first-deployment.md)
- **Production Setup:** [Installation Guide](../guides/installation.md) for advanced configurations
- **Security:** [Security Guide](../guides/security.md) for TLS and token management
- **CLI Reference:** [CLI Reference](../reference/cli.md) for all commands

## Manual Setup (Alternative)

If you prefer manual installation or need custom configurations, see the [Installation Guide](../guides/installation.md)
for step-by-step instructions using environment variables and systemd units directly.
