# Installation Guide

This guide covers production installations with a single control plane and one or more node agents.

## Components

- Control plane: single instance (SQLite by default). Put behind TLS.
- Node agent: per node; talks to control plane; requires Docker.
- CLI: operator workstation tool (`fledx`).

## Prerequisites

- Linux hosts with systemd (recommended) and outbound HTTPS.
- Docker Engine on every node agent host.
- Ports: control plane default 8080 (HTTP) or 8443 (HTTPS behind proxy).
- SSH access to target hosts (for bootstrap method).

## Installation Methods

Choose the method that fits your needs:

| Method                      | Best For                                       | Complexity |
|-----------------------------|------------------------------------------------|------------|
| **Bootstrap (Recommended)** | Most users, quick setup                        | Low        |
| **Manual**                  | Custom configurations, air-gapped environments | Medium     |

---

## Method 1: Bootstrap Installation (Recommended)

The bootstrap commands automate the entire installation process via SSH.

### Install the CLI

Download the CLI binary for your workstation:

```bash
# Download and install
curl -fsSL https://releases.example.com/fledx-cli-linux-amd64.tar.gz | tar -xz
sudo install -m 0755 fledx /usr/local/bin/
```

### Bootstrap the Control Plane

```bash
# Remote installation via SSH
fledx bootstrap cp \
  --cp-hostname control-plane.example.com \
  --ssh-host root@control-plane.example.com \
  --server-port 8080 \
  --tunnel-port 7443
```

This command:

- Downloads the correct binary for the target architecture
- Creates the `fledx` system user and directories
- Generates secure tokens (registration, operator, pepper)
- Creates systemd service and environment file
- Starts the control plane
- Configures your local CLI profile

### Bootstrap Node Agents

```bash
# Add nodes via SSH
fledx bootstrap agent --ssh-host root@edge-node-1.example.com
fledx bootstrap agent --ssh-host root@edge-node-2.example.com \
  --name edge-eu-west \
  --label region=eu-west \
  --label role=edge
```

Each command:

- Downloads the matching agent version
- Registers the node with the control plane
- Creates systemd service with correct credentials
- Starts the agent

### Verify Installation

```bash
# Check system status
fledx status

# Detailed node view
fledx nodes status --wide
```

### Bootstrap Options Reference

**Control Plane (`fledx bootstrap cp`):**

| Option                | Default        | Description                     |
|-----------------------|----------------|---------------------------------|
| `--cp-hostname`       | (required)     | Hostname/IP reachable by agents |
| `--ssh-host`          | -              | SSH target (user@host)          |
| `--ssh-identity-file` | -              | SSH private key                 |
| `--version`           | latest         | Version to install              |
| `--server-port`       | 8080           | HTTP API port                   |
| `--tunnel-port`       | 7443           | Agent tunnel port               |
| `--bin-dir`           | /usr/local/bin | Binary directory                |
| `--config-dir`        | /etc/fledx     | Config directory                |
| `--data-dir`          | /var/lib/fledx | Data directory                  |

**Agent (`fledx bootstrap agent`):**

| Option                    | Default    | Description            |
|---------------------------|------------|------------------------|
| `--ssh-host`              | (required) | SSH target (user@host) |
| `--ssh-identity-file`     | -          | SSH private key        |
| `--name`                  | hostname   | Node name              |
| `--version`               | CP version | Version to install     |
| `--label`                 | -          | Labels (repeatable)    |
| `--capacity-cpu-millis`   | -          | CPU capacity           |
| `--capacity-memory-bytes` | -          | Memory capacity        |

---

## Method 2: Manual Installation

For custom configurations, air-gapped environments, or when SSH access is not available.

### Get the Binaries

1) Download the release bundle for your OS/arch from the official downloads page.
2) Extract and move binaries into `/usr/local/bin`:

```bash
sudo tar -xf fledx.tar.gz -C /usr/local/bin
sudo chmod 0755 /usr/local/bin/fledx-cp /usr/local/bin/fledx-agent /usr/local/bin/fledx
```

Adjust paths if your bundle layout differs.

## Control Plane (single instance)

Create user and data directory:

```bash
sudo useradd -r -s /bin/false fledx 2>/dev/null || true
sudo install -d -o fledx -g fledx /var/lib/fledx
sudo install -d -o root -g root /etc/fledx
```

Environment file `/etc/fledx/fledx-cp.env` (edit secrets):

```
FLEDX_CP_SERVER_HOST=0.0.0.0
FLEDX_CP_SERVER_PORT=8080
FLEDX_CP_DATABASE_URL=sqlite:///var/lib/fledx/fledx-cp.db
FLEDX_CP_REGISTRATION_TOKEN=change-me-registration
FLEDX_CP_OPERATOR_TOKENS=change-me-operator
FLEDX_CP_OPERATOR_HEADER_NAME=authorization
FLEDX_CP_TOKENS_PEPPER=change-me-pepper
# Optional hardening
# FLEDX_CP_PORTS_AUTO_ASSIGN=true
# FLEDX_CP_FEATURES_ENFORCE_AGENT_COMPATIBILITY=true
RUST_LOG=info
```

Systemd unit `/etc/systemd/system/fledx-cp.service`:

```
[Unit]
Description=Distributed Edge Hosting Control Plane
After=network-online.target
Wants=network-online.target

[Service]
User=fledx
Group=fledx
EnvironmentFile=/etc/fledx/fledx-cp.env
ExecStart=/usr/local/bin/fledx-cp
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Enable and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fledx-cp
sudo systemctl status fledx-cp
curl -fsSL http://127.0.0.1:8080/health
```

TLS: terminate with your reverse proxy (nginx/Caddy/Traefik) and forward to
the control plane. Ensure the proxy adds no auth headers.

## Node Agent (per node)

Create user and directories:

```bash
sudo useradd -r -s /bin/false fledx 2>/dev/null || true
sudo install -d -o fledx -g fledx /var/lib/fledx
sudo install -d -o fledx -g fledx /var/lib/fledx/volumes
sudo install -d -o root -g root /etc/fledx
```

Environment file `/etc/fledx/fledx-agent.env` (fill from node registration):

```
FLEDX_AGENT_CONTROL_PLANE_URL=https://control-plane.example.com
FLEDX_AGENT_NODE_ID=<node-uuid>
FLEDX_AGENT_NODE_TOKEN=<node-token>
FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES=/var/lib/fledx/volumes
# For labs only (not production):
# FLEDX_AGENT_ALLOW_INSECURE_HTTP=true
# FLEDX_AGENT_TLS_INSECURE_SKIP_VERIFY=true
```

Systemd unit `/etc/systemd/system/fledx-agent.service`:

```
[Unit]
Description=Distributed Edge Hosting Node Agent
After=network-online.target docker.service
Requires=docker.service
Wants=network-online.target

[Service]
User=fledx
Group=fledx
EnvironmentFile=/etc/fledx/fledx-agent.env
ExecStart=/usr/local/bin/fledx-agent
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Enable and check:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fledx-agent
sudo systemctl status fledx-agent
```

## CLI (operator workstation)

Place `fledx` in your PATH:

```bash
sudo install -m 0755 fledx /usr/local/bin/fledx
```

Shell completions:

```bash
fledx completions bash | sudo tee /etc/bash_completion.d/fledx >/dev/null
fledx completions zsh  | sudo tee /usr/share/zsh/site-functions/_fledx >/dev/null
fledx completions fish | sudo tee /usr/share/fish/vendor_completions.d/fledx.fish >/dev/null
```

## Bootstrap Flow (Day 1)

1) Start the control plane (see above).
2) Register each node:

```bash
FLEDX_CLI_CONTROL_PLANE_URL=https://control-plane.example.com \
FLEDX_CLI_REGISTRATION_TOKEN=<control-plane registration token> \
fledx nodes register --name edge-1
```

Capture the `node_id` and `node_token`.

3) Configure and start the node agent with those values.
4) Verify:

```bash
curl -fsSL https://control-plane.example.com/health
FLEDX_CLI_CONTROL_PLANE_URL=https://control-plane.example.com \
FLEDX_CLI_OPERATOR_TOKEN=<operator token> \
fledx nodes status --wide
```

5) Deploy a workload (example):

```bash
FLEDX_CLI_CONTROL_PLANE_URL=https://control-plane.example.com \
FLEDX_CLI_OPERATOR_TOKEN=<operator token> \
fledx deployments create \
  --name web \
  --image nginx:alpine \
  --port 80:80/tcp
```

## Security & compatibility

- Use HTTPS for fledx-cp and agents; only enable insecure flags in labs.
- Treat registration and operator tokens as secrets; rotate periodically.
- Pin allowed volume prefixes and avoid running agents as root when possible.
- Enforce agent compatibility with `FLEDX_CP_FEATURES_ENFORCE_AGENT_COMPATIBILITY=true`.

## Links

- Configs: [Configuration Guide](configuration.md)
- Upgrades: [Upgrade Guide](upgrades.md)
- Security: [Security Guide](security.md)
- Day-2 ops: [Monitoring Guide](monitoring.md)
