# Configuration Management

This guide covers managing runtime configuration as first-class resources that can be attached to deployments and nodes.

## Placeholders in Examples

Throughout this guide, you'll see placeholders in angle brackets. Here's how to find the actual values:

- `<config-id>` - Config UUID. Get from: `fledx configs list`
- `<deployment-id>` - Deployment UUID. Get from: `fledx deployments status`
- `<node-id>` - Node UUID. Get from: `fledx nodes status`
- `<node-ip>` - Node's IP address. Get from: `fledx nodes status --wide` (see `address` column)

## Overview

Configuration in Distributed Edge Hosting can be managed in two ways:

1. **Direct environment variables** - Defined in deployment specs (see [Deployment Guide](deployment.md))
2. **Config resources** - Reusable configuration objects that can be attached to multiple deployments or nodes

Config resources are useful when you need to:

- Share configuration across multiple deployments
- Apply the same settings to all deployments on a node
- Manage configuration independently of deployment lifecycle
- Version and update configuration without redeploying

## Configuration Concepts

### Configs vs Environment Variables

**Use direct environment variables when:**

- Configuration is specific to one deployment
- Values don't change frequently
- Configuration is simple (few variables)

**Use config resources when:**

- Multiple deployments need the same configuration
- You want to update configuration without redeploying
- Configuration needs to be versioned
- You have many environment variables to manage

### Config Scope

Configs can be attached at two levels:

1. **Node-level** - Applied to all deployments on a node
2. **Deployment-level** - Applied to a specific deployment

If both exist, deployment-level configs override node-level configs for duplicate keys.

### Config Precedence

Configuration is applied in this order (later wins):

1. Node-level configs (sorted alphabetically by name)
2. Deployment-level configs (sorted alphabetically by name)
3. Direct deployment environment variables (highest priority)

## Creating Configs (CLI)

### Basic Plaintext Config

Create a config with environment variables:

```bash
fledx configs create \
  --name app-config \
  --var DATABASE_URL=postgres://app:secret@db:5432/app \
  --var LOG_LEVEL=info \
  --var CACHE_TTL=3600
```

### Import from .env File

Create a config from an existing `.env` file:

```bash
# app.env
DATABASE_URL=postgres://app:secret@db:5432/app
LOG_LEVEL=info
CACHE_TTL=3600
# Comments are ignored
export OPTIONAL_PREFIX=ignored
```

```bash
fledx configs create --name app-config --from-env-file ./app.env
```

**Note:** Blank lines, comments (`#`), and optional `export` prefixes are automatically ignored.

### Secret-Backed Configs

For sensitive data, use secret-backed entries:

```bash
fledx configs create \
  --name app-secrets \
  --secret-entry DB_PASSWORD=db-password \
  --secret-entry API_TOKEN=api-token
```

**Important:** When using `--secret-entry`, **all** entries in the config must be secret-backed. You cannot mix
plaintext and secret entries.

The node agent must have matching secrets configured:

```bash
# On the node
export FLEDX_SECRET_db-password=actual-db-password
export FLEDX_SECRET_api-token=actual-api-token
```

### Config with Files

Mount configuration files into containers:

```bash
fledx configs create \
  --name nginx-config \
  --file /etc/nginx/nginx.conf=config-blobs/nginx-v1
```

The agent reads file blobs from `FLEDX_AGENT__VOLUME_DATA_DIR/configs/<file_ref>`.

**Prepare the file on nodes:**

```bash
sudo mkdir -p /var/lib/fledx/configs/config-blobs
sudo tee /var/lib/fledx/configs/config-blobs/nginx-v1 <<EOF
server {
    listen 80;
    server_name localhost;
    location / {
        root /usr/share/nginx/html;
    }
}
EOF
```

### Combined Example

```bash
fledx configs create \
  --name full-app-config \
  --var LOG_LEVEL=info \
  --var PORT=8080 \
  --file /etc/app/config.yaml=config-blobs/app-v1
```

## Creating Configs (API)

Use an operator token in `Authorization: Bearer <token>`.

### Basic Config

```bash
curl -X POST "$CONTROL_PLANE/api/v1/configs" \
  -H "authorization: Bearer $FLEDX_OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{
        "name": "app-config",
        "entries": [
          { "key": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app" },
          { "key": "LOG_LEVEL", "value": "info" }
        ]
      }'
```

### Config with Files

```bash
curl -X POST "$CONTROL_PLANE/api/v1/configs" \
  -H "authorization: Bearer $FLEDX_OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{
        "name": "app-config",
        "entries": [
          { "key": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app" }
        ],
        "files": [
          { "path": "/etc/app/config.yaml", "file_ref": "config-blobs/app-v1" }
        ]
      }'
```

## Updating Configs

### Update Variables

```bash
fledx configs update \
  --id <config-uuid> \
  --var FEATURE_FLAG=on \
  --var NEW_VAR=value
```

### Clear Files

```bash
fledx configs update --id <config-uuid> --clear-files
```

### Version Management

By default, updates increment the version automatically:

```bash
# Auto-increments version
fledx configs update --id <config-uuid> --var KEY=new-value
```

Pin a specific version:

```bash
fledx configs update --id <config-uuid> --var KEY=value --version 5
```

### API Update

```bash
curl -X PUT "$CONTROL_PLANE/api/v1/configs/<config-id>" \
  -H "authorization: Bearer $FLEDX_OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{
        "name": "app-config",
        "entries": [
          { "key": "UPDATED_KEY", "value": "new-value" }
        ],
        "files": []
      }'
```

## Attaching Configs

### Attach to Deployment

```bash
fledx configs attach deployment \
  --config-id <config-uuid> \
  --deployment-id <deployment-uuid>
```

Attach multiple configs:

```bash
fledx configs attach deployment \
  --config-id <cfg-a>,<cfg-b>,<cfg-c> \
  --deployment-id <deployment-uuid>
```

### Attach to Node

Apply config to all deployments on a node:

```bash
fledx configs attach node \
  --config-id <config-uuid> \
  --node-id <node-uuid>
```

### API Attachment

**Deployment:**

```bash
curl -X POST "$CONTROL_PLANE/api/v1/configs/<config-id>/deployments/<deployment-id>" \
  -H "authorization: Bearer $FLEDX_OPERATOR_TOKEN"
```

**Node:**

```bash
curl -X POST "$CONTROL_PLANE/api/v1/configs/<config-id>/nodes/<node-id>" \
  -H "authorization: Bearer $FLEDX_OPERATOR_TOKEN"
```

## Detaching Configs

### Detach from Deployment

```bash
fledx configs detach deployment \
  --config-id <config-uuid> \
  --deployment-id <deployment-uuid>
```

### Detach from Node

```bash
fledx configs detach node \
  --config-id <config-uuid> \
  --node-id <node-uuid>
```

### API Detachment

```bash
# From deployment
curl -X DELETE "$CONTROL_PLANE/api/v1/configs/<config-id>/deployments/<deployment-id>" \
  -H "authorization: Bearer $FLEDX_OPERATOR_TOKEN"

# From node
curl -X DELETE "$CONTROL_PLANE/api/v1/configs/<config-id>/nodes/<node-id>" \
  -H "authorization: Bearer $FLEDX_OPERATOR_TOKEN"
```

## Config Reload & Propagation

### How Reloads Work

1. Control plane stores config changes immediately
2. Node agents poll `/api/v1/nodes/<id>/configs` every `FLEDX_AGENT__RECONCILE_INTERVAL_SECS` (default: 10s)
3. Agent computes config fingerprint (config_id + version + checksum)
4. If fingerprint differs from running container, agent restarts the replica
5. New container starts with updated configuration

### Monitoring Reloads

Check agent metrics:

```bash
curl http://<node-ip>:9091/metrics | grep config
```

Key metrics:

- `node_agent_config_fetch_total{result="success|not_modified|error"}`
- `node_agent_config_apply_total{result="applied|skipped|failed"}`

Check deployment status:

```bash
fledx deployments status --id <deployment-id> --wide
```

Look for restart counts and instance state.

### Restart Behavior

- Restarts respect backoff (exponential)
- Max restart attempts: `FLEDX_AGENT__RESTART_FAILURE_LIMIT` (default: 5)
- Agent logs show: `container config fingerprint mismatch, scheduling restart`

## Limits and Validation

### Field Limits

- **Names/Keys:** ≤255 characters
- **Secret refs:** ≤255 characters
- **File refs:** ≤255 characters
- **File paths:** ≤512 characters
- **Values:** ≤4096 characters
- Empty keys/values are rejected

### Entry Restrictions

- **Cannot mix:** Plaintext (`--var`/`--from-env-file`) and secret refs (`--secret-entry`)
- **Duplicate keys:** Case-insensitive errors (`duplicate config entry key: FOO`)

### Payload Limits

- **Total payload:** Capped by `FLEDX_CP__LIMITS__CONFIG_PAYLOAD_BYTES` (default: 131072 bytes / 128 KB)
- Exceeding returns `413 payload_too_large`

### Env File Parsing

Errors include line numbers:

```
env file app.env line 3 must be in KEY=VALUE form
```

## Best Practices

### 1. Separate Configs by Purpose

Create separate configs for different concerns:

```bash
# Database config
fledx configs create --name db-config --var DATABASE_URL=postgres://...

# Logging config
fledx configs create --name logging-config --var LOG_LEVEL=info

# Feature flags
fledx configs create --name features --var FEATURE_A=on --var FEATURE_B=off
```

### 2. Use Secrets for Sensitive Data

Never store passwords or API keys in plaintext configs:

```bash
# Bad
fledx configs create --name app-config --var DB_PASSWORD=supersecret

# Good
fledx configs create --name app-secrets --secret-entry DB_PASSWORD=db-pass-ref
```

### 3. Apply Common Config at Node Level

For settings shared across all deployments on a node:

```bash
fledx configs create --name node-defaults --var REGION=us-east-1
fledx configs attach node --config-id <id> --node-id <node-id>
```

### 4. Version Your Configs

Track changes by incrementing versions explicitly:

```bash
fledx configs update --id <id> --var KEY=new-value --version 2
```

### 5. Test Before Production

Test config changes on a single deployment before rolling out:

```bash
# Attach to test deployment
fledx configs attach deployment --config-id <id> --deployment-id <test-id>

# Verify it works
fledx deployments status --id <test-id>

# Roll out to production
fledx configs attach deployment --config-id <id> --deployment-id <prod-id>
```

## Troubleshooting

### Config Not Applied

**Symptom:** Deployment doesn't have expected environment variables.

**Checks:**

1. Verify config is attached:
   ```bash
   fledx configs list-attachments --deployment-id <id>
   ```

2. Check config precedence - deployment env vars override configs

3. Verify agent is fetching configs:
   ```bash
   curl http://<node-ip>:9091/metrics | grep config_fetch_total
   ```

### Payload Too Large Error

**Symptom:** `413 payload_too_large` when agent fetches config.

**Solutions:**

1. Split into multiple configs
2. Remove unused entries/files
3. Increase limit: `FLEDX_CP__LIMITS__CONFIG_PAYLOAD_BYTES=262144`

### Secret Not Found

**Symptom:** Container fails to start with `required secret <NAME> missing`.

**Solution:**

Ensure secret is set on the node:

```bash
# Check node agent env
sudo systemctl status fledx-agent

# Add secret
sudo tee -a /etc/fledx/fledx-agent.env <<EOF
FLEDX_SECRET_<NAME>=actual-value
EOF

sudo systemctl restart fledx-agent
```

### Container Restart Loop

**Symptom:** Container repeatedly restarts after config update.

**Causes:**

- Invalid configuration values (e.g., malformed JSON)
- Port conflicts
- Missing dependencies

**Solution:**

```bash
# Check logs
fledx deployments logs --resource-type deployment --resource-id <id>

# Check instance state
fledx deployments status --id <id> --wide
```

## Example Workflows

### Shared Database Config

```bash
# Create shared DB config
fledx configs create \
  --name shared-db \
  --var DATABASE_URL=postgres://app:secret@db:5432/app \
  --var DB_POOL_SIZE=10

# Attach to multiple deployments
fledx configs attach deployment --config-id <db-config-id> --deployment-id <api-id>
fledx configs attach deployment --config-id <db-config-id> --deployment-id <worker-id>
fledx configs attach deployment --config-id <db-config-id> --deployment-id <cron-id>
```

### Environment-Specific Configs

```bash
# Development
fledx configs create --name dev-config --var ENV=dev --var DEBUG=true

# Production
fledx configs create --name prod-config --var ENV=prod --var DEBUG=false

# Attach based on environment
fledx configs attach deployment --config-id <dev-config-id> --deployment-id <dev-deploy>
fledx configs attach deployment --config-id <prod-config-id> --deployment-id <prod-deploy>
```

### Rolling Config Update

```bash
# Update config
fledx configs update --id <config-id> --var NEW_FEATURE=enabled

# Watch deployments reload
fledx deployments watch --id <deployment-1>

# Config propagates automatically to all attached deployments
```

## Next Steps

- **Deploy Applications:** [Deployment Guide](deployment.md)
- **YAML Configs:** [YAML Deployments](yaml-deployments.md)
- **Security:** [Security Guide](security.md)
- **Monitoring:** [Monitoring Guide](monitoring.md)
