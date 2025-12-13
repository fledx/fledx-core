# Getting Started

This guide walks you through running a two-host demo in approximately 20 minutes (control plane on Host A, node agent on
Host B).

## What You Will Do

- Start the control plane on Host A.
- Register one node.
- Start the node agent on Host B.
- Deploy nginx with custom HTML to that node and open it locally.

## Prerequisites

- Linux/macOS with Docker and `curl`.
- A shell with basic POSIX tools (`tar`, `sed`, `openssl` recommended).
- Downloaded release bundles containing the binaries `fledx-cp`, `fledx-agent`, `fledx`.

> Download: grab the latest platform bundle from the product download page and
> place it in the current directory as `fledx.tar.gz`. Verify the checksum/signature
> if provided by your distribution channel.

## 1) Unpack and place binaries on PATH

Do this on both hosts (or unpack on Host A and copy the binaries to Host B).

```bash
mkdir -p quickstart/bin quickstart/data
tar -xf fledx.tar.gz -C quickstart/bin
export PATH="$PWD/quickstart/bin:$PATH"
```

## 2) Start the control plane (Host A)

Choose demo-only secrets (replace for anything beyond this quickstart).

```bash
export FLEDX_REG_TOKEN=quickstart-reg-123
export FLEDX_OPERATOR_TOKEN=quickstart-operator-123
export FLEDX_TOKEN_PEPPER=pepper-123

FLEDX_CP__SERVER__HOST=0.0.0.0 \
FLEDX_CP__SERVER__PORT=8080 \
FLEDX_CP__DATABASE__URL=sqlite://$PWD/quickstart/data/fledx-cp.db \
FLEDX_CP__REGISTRATION__TOKEN=$FLEDX_REG_TOKEN \
FLEDX_CP__OPERATOR__TOKENS=$FLEDX_OPERATOR_TOKEN \
FLEDX_CP__TOKENS__PEPPER=$FLEDX_TOKEN_PEPPER \
RUST_LOG=info \
fledx-cp
```

Keep this terminal open; it shows logs. Health check:

```bash
curl -fsSL http://<control-plane-host>:8080/health
```

## 3) Register a node (Host A)

In a new terminal (with PATH pointing to `quickstart/bin`):

```bash
FLEDX_CONTROL_PLANE_URL=http://<control-plane-host>:8080 \
FLEDX_REGISTRATION_TOKEN=$FLEDX_REG_TOKEN \
fledx nodes register --name edge-1
```

Note the printed `node_id` and `node_token`; you need them for the agent.

## 4) Run the node agent (Host B)

```bash
FLEDX_AGENT__CONTROL_PLANE_URL=http://<control-plane-host>:8080 \
FLEDX_AGENT__NODE_ID=<node_id from step 3> \
FLEDX_AGENT__NODE_TOKEN=<node_token from step 3> \
FLEDX_AGENT__ALLOW_INSECURE_HTTP=true \
FLEDX_AGENT__PUBLIC_HOST=<agent-hostname-or-ip> \
fledx-agent
```

Leave this running to keep the node connected.

## 5) Deploy nginx with custom HTML (Host A)

```bash
FLEDX_CONTROL_PLANE_URL=http://<control-plane-host>:8080 \
FLEDX_OPERATOR_TOKEN=$FLEDX_OPERATOR_TOKEN \
fledx deployments create \
  --name edge-nginx \
  --image nginx:alpine \
  --command sh -c \"echo '<h1>Hello from the edge node</h1>' > /usr/share/nginx/html/index.html && nginx -g 'daemon off;'\" \
  --port 8081:80/tcp \
  --env NGINX_ENTRYPOINT_QUIET_LOGS=1
```

Check status:

```bash
fledx deployments status --status running
```

## 6) Try the interfaces

- UI: open `http://<control-plane-host>:8080/ui` and paste the operator token
  (`$FLEDX_OPERATOR_TOKEN`).
- API: `curl -H "authorization: $FLEDX_OPERATOR_TOKEN" http://<control-plane-host>:8080/api/v1/deployments`.
- CLI: `fledx nodes list --wide`.
- App: `curl http://<agent-hostname-or-ip>:8081` should return the custom HTML.

## 7) Cleanup

- Stop the agent and fledx-cp processes (Ctrl+C).
- Remove the `quickstart` directory if you want to reset state.

## Next Steps

- Production install: [Installation Guide](../guides/installation.md)
- Security: [Security Guide](../guides/security.md)
- Day-2 ops and upgrades: [Monitoring](../guides/monitoring.md), [Upgrades](../guides/upgrades.md)
- CLI reference: [CLI Reference](../reference/cli.md)
- UI guide: [UI Reference](../reference/ui.md)
- API spec: [API Reference](../reference/api.md)
