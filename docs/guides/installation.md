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
- Downloaded release artifacts for your platform (fledx-cp, fledx-agent,
  fledx CLI). Verify checksums/signatures from your distribution channel.

## Get the Binaries

1) Download the release bundle for your OS/arch from the official downloads
   page and place it on each host.
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
FLEDX_CP__SERVER__HOST=0.0.0.0
FLEDX_CP__SERVER__PORT=8080
FLEDX_CP__DATABASE__URL=sqlite:///var/lib/fledx/fledx-cp.db
FLEDX_CP__REGISTRATION__TOKEN=change-me-registration
FLEDX_CP__OPERATOR__TOKENS=change-me-operator
FLEDX_CP__OPERATOR__HEADER_NAME=authorization
FLEDX_CP__TOKENS__PEPPER=change-me-pepper
# Optional hardening
# FLEDX_CP__PORTS__AUTO_ASSIGN=true
# FLEDX_CP__FEATURES__ENFORCE_AGENT_COMPATIBILITY=true
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
FLEDX_AGENT__CONTROL_PLANE_URL=https://control-plane.example.com
FLEDX_AGENT__NODE_ID=<node-uuid>
FLEDX_AGENT__NODE_TOKEN=<node-token>
FLEDX_AGENT__ALLOWED_VOLUME_PREFIXES=/var/lib/fledx/volumes
# For labs only (not production):
# FLEDX_AGENT__ALLOW_INSECURE_HTTP=true
# FLEDX_AGENT__TLS_INSECURE_SKIP_VERIFY=true
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
FLEDX_CONTROL_PLANE_URL=https://control-plane.example.com \
FLEDX_REGISTRATION_TOKEN=<control-plane registration token> \
fledx nodes register --name edge-1
```

Capture the `node_id` and `node_token`.

3) Configure and start the node agent with those values.
4) Verify:

```bash
curl -fsSL https://control-plane.example.com/health
FLEDX_CONTROL_PLANE_URL=https://control-plane.example.com \
FLEDX_OPERATOR_TOKEN=<operator token> \
fledx nodes status --wide
```

5) Deploy a workload (example):

```bash
FLEDX_CONTROL_PLANE_URL=https://control-plane.example.com \
FLEDX_OPERATOR_TOKEN=<operator token> \
fledx deployments create \
  --name web \
  --image nginx:alpine \
  --port 80:80/tcp
```

## Security & compatibility

- Use HTTPS for fledx-cp and agents; only enable insecure flags in labs.
- Treat registration and operator tokens as secrets; rotate periodically.
- Pin allowed volume prefixes and avoid running agents as root when possible.
- Enforce agent compatibility with `FLEDX_CP__FEATURES__ENFORCE_AGENT_COMPATIBILITY=true`.

## Links

- Configs: [Configuration Guide](configuration.md)
- Upgrades: [Upgrade Guide](upgrades.md)
- Security: [Security Guide](security.md)
- Day-2 ops: [Monitoring Guide](monitoring.md)
