# CLI Reference

The `fledx` CLI is the primary command-line tool for managing Distributed Edge Hosting. This guide covers common
workflows for beginners and detailed reference material for advanced users.

## Quick Start

### Environment Setup

Before using the CLI, configure your environment:

```bash
export FLEDX_CLI_CONTROL_PLANE_URL=https://control-plane.example.com
export FLEDX_CLI_OPERATOR_TOKEN=your-operator-token-here
export FLEDX_CLI_REGISTRATION_TOKEN=your-registration-token-here
```

Add these to your `~/.bashrc` or `~/.zshrc` for persistence.

### Common Commands

**Check system health:**

```bash
# Control plane health
curl $FLEDX_CLI_CONTROL_PLANE_URL/health

# List all nodes
fledx nodes status

# List all deployments
fledx deployments status
```

**Deploy an application:**

```bash
fledx deployments create \
  --name my-app \
  --image nginx:alpine \
  --port 8080:80/tcp
```

**Monitor deployment:**

```bash
# Get deployment ID (save from deploy-create output or list all)
DEPLOY_ID=$(fledx deployments status --json | jq -r '.items[] | select(.name=="my-app") | .deployment_id')

# Watch deployment until running
fledx deployments watch --id $DEPLOY_ID

# View logs
fledx deployments logs --resource-type deployment --resource-id $DEPLOY_ID
```

**Scale an application:**

```bash
# Scale using deployment ID
fledx deployments update --id $DEPLOY_ID --replicas 3
```

**Delete deployment:**

```bash
fledx deployments delete --id $DEPLOY_ID
```

## Bootstrap Commands

The bootstrap commands automate installation and setup of control plane and agents.

### Bootstrap Control Plane

Install and configure the control plane on a local or remote host:

```bash
# Local installation
fledx bootstrap cp --cp-hostname localhost

# Remote installation via SSH
fledx bootstrap cp \
  --cp-hostname control-plane.example.com \
  --ssh-host root@control-plane.example.com
```

**Options:**

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

The command automatically:

- Downloads the correct binary for the target platform
- Creates the `fledx` system user
- Sets up systemd service
- Generates secure tokens
- Configures your local CLI profile

### Bootstrap Agent

Install and register a node agent via SSH:

```bash
# Basic agent bootstrap
fledx bootstrap agent --ssh-host root@edge-node.example.com

# With labels and capacity hints
fledx bootstrap agent \
  --ssh-host root@edge-node.example.com \
  --name edge-eu-west \
  --label region=eu-west \
  --label role=worker \
  --capacity-cpu-millis 4000 \
  --capacity-memory-bytes 8589934592
```

**Options:**

| Option                    | Default               | Description                         |
|---------------------------|-----------------------|-------------------------------------|
| `--ssh-host`              | (required)            | SSH target (user@host)              |
| `--ssh-identity-file`     | -                     | SSH private key path                |
| `--name`                  | SSH hostname          | Node name for registration          |
| `--version`               | control-plane version | Version to install                  |
| `--label`                 | -                     | Node labels (repeatable, KEY=VALUE) |
| `--capacity-cpu-millis`   | -                     | CPU capacity hint                   |
| `--capacity-memory-bytes` | -                     | Memory capacity hint                |

## Profile Commands

Manage CLI profiles for connecting to multiple control planes.

### List Profiles

```bash
fledx profile list
```

Shows all configured profiles with their control plane URLs.

### Show Profile

```bash
# Show current/default profile
fledx profile show

# Show specific profile
fledx profile show --name production
```

### Create or Update Profile

```bash
fledx profile set \
  --name production \
  --control-plane-url https://cp.example.com \
  --operator-token <TOKEN> \
  --registration-token <TOKEN>
```

**Options:**

| Option                 | Description                                   |
|------------------------|-----------------------------------------------|
| `--name`               | Profile name (required)                       |
| `--control-plane-url`  | Control plane base URL                        |
| `--operator-header`    | Header name for auth (default: authorization) |
| `--operator-token`     | Bearer token for operator endpoints           |
| `--registration-token` | Token for node registration                   |

### Set Default Profile

```bash
fledx profile set-default --name production
```

### Using Profiles

```bash
# Use default profile
fledx status

# Use specific profile for one command
fledx --profile staging status
```

## Status Command

The `fledx status` command provides a combined overview of system health.

```bash
# Show nodes and deployments
fledx status

# Watch mode with real-time updates
fledx status --watch

# Filter by status
fledx status --node-status ready --deploy-status running

# Show only nodes or deployments
fledx status --nodes-only
fledx status --deploys-only
```

**Options:**

| Option              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `--watch`           | Enable real-time updates (TUI mode)                                         |
| `--node-status`     | Filter nodes by status (ready, unreachable, error)                          |
| `--deploy-status`   | Filter deployments by status (pending, deploying, running, stopped, failed) |
| `--nodes-only`      | Show only node status                                                       |
| `--deploys-only`    | Show only deployment status                                                 |
| `--wide`            | Show extended columns                                                       |
| `--json` / `--yaml` | Output in structured format                                                 |

## Common Workflows

### Workflow 1: First Deployment

Step-by-step guide to deploying your first application:

```bash
# 1. Verify control plane is healthy
curl $FLEDX_CLI_CONTROL_PLANE_URL/health

# 2. Check available nodes
fledx nodes status --wide

# 3. Deploy nginx (save the deployment ID from output)
DEPLOY_ID=$(fledx deployments create \
  --name web-server \
  --image nginx:alpine \
  --port 8080:80/tcp \
  --env NGINX_PORT=80 \
  --json | jq -r '.deployment_id')

echo "Deployment ID: $DEPLOY_ID"

# 4. Watch deployment progress
fledx deployments watch --id $DEPLOY_ID --follow-logs

# 5. Verify deployment is running
fledx deployments status --json | jq '.items[] | select(.deployment_id=="'$DEPLOY_ID'")'

# 6. Get the node IP and test
fledx nodes status --wide  # Note the node IP
curl http://<node-ip>:8080
```

### Workflow 2: Update & Rollback

Update an application and rollback if needed:

```bash
# Get deployment ID by name
DEPLOY_ID=$(fledx deployments status --json | jq -r '.items[] | select(.name=="my-app") | .deployment_id')

# Check current version
fledx deployments status --json | jq '.items[] | select(.deployment_id=="'$DEPLOY_ID'")'

# Update to new version
fledx deployments update --id $DEPLOY_ID --image my-app:v2.0

# Watch the update
fledx deployments watch --id $DEPLOY_ID

# If something goes wrong, rollback
fledx deployments update --id $DEPLOY_ID --image my-app:v1.9

# Verify rollback
fledx deployments status --json | jq '.items[] | select(.deployment_id=="'$DEPLOY_ID'")'
```

### Workflow 3: Multi-Node Deployment

Deploy across multiple nodes with replicas:

```bash
# Register nodes with labels during registration
fledx nodes register --name node-us-east --label region=us-east
fledx nodes register --name node-us-west --label region=us-west

# Deploy with spread replicas (distributes across nodes)
fledx deployments create \
  --name distributed-app \
  --image my-app:latest \
  --replicas 3 \
  --spread \
  --port 8080:3000/tcp

# Or deploy with affinity to specific labels
fledx deployments create \
  --name regional-app \
  --image my-app:latest \
  --replicas 2 \
  --affinity-label region=us-east \
  --port 8080:3000/tcp

# Monitor placement
fledx deployments status --wide

# Check which nodes have instances
fledx nodes status --wide
```

### Workflow 4: Managing Secrets

Deploy applications with configuration:

```bash
# Create configuration
fledx configs create \
  --name app-config \
  --var DATABASE_URL=postgres://db.example.com/mydb \
  --var API_KEY=secret-key-here

# Note the config ID from output
CONFIG_ID=<config-id-from-output>

# Deploy with configuration
fledx deployments create \
  --name my-app \
  --image my-app:latest \
  --port 8080:3000/tcp

# Attach config to deployment
fledx configs attach deployment \
  --config-id $CONFIG_ID \
  --deployment-id <deployment-id>

# Verify configuration
fledx configs list
```

### Workflow 5: Node Management

Add and manage nodes:

```bash
# Register a new node with labels
fledx nodes register \
  --name edge-1 \
  --label role=edge \
  --label site=hq \
  --label region=us-east \
  --capacity-cpu-millis 4000 \
  --capacity-memory-bytes 8589934592

# Save the node_id and node_token from output
NODE_ID=<node-id-from-output>
NODE_TOKEN=<node-token-from-output>

# On the node machine, configure and start agent
# (See installation guide for agent setup)

# Verify node is connected
fledx nodes status

# View node details including labels
fledx nodes status --wide

# Note: To rotate a compromised node token, re-register the node
# and update the agent configuration with new credentials

# To remove a node:
# 1. Stop the agent on the node
ssh <node-host> "sudo systemctl stop node-agent"

# 2. Node will become "unreachable" after heartbeat timeout
# 3. Deployments will be rescheduled to other nodes automatically
# 4. Node record remains for audit purposes

# View all nodes including unreachable
fledx nodes status
```

### Workflow 6: Monitoring & Debugging

Troubleshoot deployment issues:

```bash
# Get deployment ID
DEPLOY_ID=$(fledx deployments status --json | jq -r '.items[] | select(.name=="my-app") | .deployment_id')

# Check deployment status
fledx deployments status --wide

# View detailed logs for specific deployment
fledx deployments logs \
  --resource-type deployment \
  --resource-id $DEPLOY_ID \
  --limit 100

# Check node health
fledx nodes status --wide
```

## Command Reference

### Global Flags

All commands support these global flags:

- `--json` - Output in JSON format
- `--yaml` - Output in YAML format
- `--help` - Show help for any command

### Environment Variables

- `FLEDX_CLI_CONTROL_PLANE_URL` - Control plane URL (required)
- `FLEDX_CLI_OPERATOR_TOKEN` - Operator authentication token
- `FLEDX_CLI_REGISTRATION_TOKEN` - Node registration token

## List & status commands

`fledx nodes list`, `fledx nodes status`, `fledx deployments list`, and `fledx deployments status` share the same
pagination and output
controls. All four accept `--limit`/`--offset` (default 50, must be 1‑100) plus a status filter (
`--status ready|unreachable|error|registering` for nodes, `--status pending|deploying|running|stopped|failed` for
deployments). Pass `--wide` to expose the richer columns shown by `render_nodes_table` and `render_deployments_table`,
and add `--json` or `--yaml` for machine-readable payloads.

### Table output (default)

The default view emits a plain-text table. `fledx nodes status`/`list` renders `ID`, `NAME`, `STATUS`, and `LAST_SEEN` (
plus `ARCH`, `OS`, `LABELS`, `CAPACITY` under `--wide`). `fledx deployments status`/`list` prints `ID`, `NAME`,
`STATUS`,
`DESIRED`, `GENERATION`, and `ASSIGNED_NODE` (with `REPLICAS`, `ASSIGNMENTS`, `IMAGE`, `PLACEMENT`, `LAST_REPORTED` when
`--wide` is set).

```
Nodes:
ID                                   NAME      STATUS  LAST_SEEN
8e7f3d4a-8d7b-4fdc-91cf-2c1f0d6b9a1a  edge-1    ready   2025-12-07T21:16:08Z
f2c1a5b9-3cba-4ee4-a840-7a518e1c3d7b  edge-2    ready   2025-12-07T21:15:43Z

Deployments:
ID                                   NAME         STATUS    DESIRED  GENERATION  ASSIGNED_NODE
c2d4e1f5-1b2c-4e5a-8b1f-9b4d1e82964b  web-service  running   running  3           8e7f3d4a-8d7b-4fdc-91cf-2c1f0d6b9a1a
```

Use these tables to quickly scan health, or add `--status`/`--limit` to reduce verbosity while troubleshooting.

### JSON & YAML output

The structured output modes print the paginated response body rather than a table. Both reply with a `limit`, `offset`,
and an `items` array of `NodeSummary` or `DeploymentSummary` records, so the JSON/YAML shape matches the OpenAPI schema
at `docs/openapi.json`.

JSON example (node list):

```json
{
  "limit": 50,
  "offset": 0,
  "items": [
    {
      "node_id": "8e7f3d4a-8d7b-4fdc-91cf-2c1f0d6b9a1a",
      "name": "edge-1",
      "status": "ready",
      "last_seen": "2025-12-07T21:16:08Z",
      "arch": "amd64",
      "os": "linux",
      "labels": {
        "site": "hq"
      },
      "capacity": {
        "cpu_millis": 4000,
        "memory_bytes": 8589934592
      }
    }
  ]
}
```

YAML example (deployment list):

```yaml
limit: 50
offset: 0
items:
  - deployment_id: c2d4e1f5-1b2c-4e5a-8b1f-9b4d1e82964b
    name: web-service
    image: hashicorp/http-echo:0.2.3
    replicas: 1
    desired_state: running
    status: running
    assigned_node_id: 8e7f3d4a-8d7b-4fdc-91cf-2c1f0d6b9a1a
    assignments:
      - replica_number: 0
        node_id: 8e7f3d4a-8d7b-4fdc-91cf-2c1f0d6b9a1a
    generation: 3
    placement:
      spread: true
    last_reported: 2025-12-07T21:12:54Z
```

## Watch mode & log follow

`fledx deployments watch --id <deployment-id>` periodically polls the control plane until the deployment reaches a
terminal
state or you stop it with `Ctrl+C`. The CLI prints a newline only when the status changes (generation, status,
assignment, or instance state), e.g.:

```
2025-12-07T21:17:04Z generation=3 status=running assignment=node/8e7f3d4a instance=running/gen=2 restarts=0 msg=Healthy
```

Recommended knobs:

- `--poll-interval` (`u64`, default `2`) controls how often the CLI fetches the deployment status during normal
  operation.
- `--max-interval` (`u64`, default `30`) caps the exponential backoff that doubles the interval after each failure; the
  runtime never sleeps longer than this value.
- `--max-runtime` (`u64`, optional) stops the watch after the given number of seconds so you do not forgot a
  long-running watch.
- `--follow-logs` enables the paired log tail (`fledx deployments logs --follow`) and accepts `--follow-logs-interval` (
  default
  `2`) to throttle the log polling rate.

Errors surfaced during the watch are printed as `watch error: …` and inherit the `[request_id=…]` suffix from the
control plane so you can correlate with audit logs.

When `--follow-logs` is used, the CLI concurrently runs
`fledx deployments logs --resource-type deployment --resource-id <id> --follow`. The log tail respects the same
`--limit` (
1‑100, default 50) and `--follow-interval` flag, refuses to run with `--until`, and prints each line like
`TIMESTAMP STATUS ACTION RESOURCE request_id=… detail=…`. Failures in the log stream show
`deployment log follow failed: …` on stderr.

## Request IDs & error context

Every control-plane response that includes `x-request-id` is surfaced by the CLI. Operator API errors append
`[request_id=<id>]`, `watch` errors echo the same suffix, and `fledx deployments logs` prints a `REQUEST_ID` column for
tracking and debugging.

The control plane normalizes request context: if a W3C `traceparent` header is present it becomes the canonical
`x-request-id`; otherwise an incoming `x-request-id` is used or a fresh UUID is generated. The same value is echoed on
responses (including agent-facing desired-state) and pinned onto tracing spans so logs and telemetry share a stable ID.
When the CLI issues requests it simply forwards whatever header you provide.

## Shell completions

Run `fledx completions <bash|zsh|fish>` (e.g., `cargo run -p cli -- completions bash`) to emit a shell script for the
CLI.
Install the script via your shell's standard location:

- **Bash:** `mkdir -p ~/.local/share/fledx/completions` and
  `cargo run -p cli -- completions bash > ~/.local/share/fledx/completions/fledx.bash`, then
  `source ~/.local/share/fledx/completions/fledx.bash` from `~/.bashrc`.
- **Zsh:** `cargo run -p cli -- completions zsh > ~/.zfunc/_fledx`, add `fpath=(~/.zfunc $fpath)` plus
  `autoload -Uz compinit && compinit` in your `~/.zshrc`, and keep `_fledx` in your `fpath`.
- **Fish:** `cargo run -p cli -- completions fish > ~/.config/fish/completions/fledx.fish`; fish loads anything in
  `~/.config/fish/completions/` automatically.

Regenerate these whenever the CLI binary changes so the completion script stays in sync with new commands or flags.
