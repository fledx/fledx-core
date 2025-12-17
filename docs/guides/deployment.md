# Deployment Guide

This guide covers advanced deployment workflows, best practices, and patterns for managing containerized applications on
Distributed Edge Hosting.

**Note:** For YAML-based deployments with declarative configuration files, see
the [YAML Deployments Guide](yaml-deployments.md).

## Placeholders in Examples

Throughout this guide, you'll see placeholders in angle brackets. Here's how to find the actual values:

- `<node-ip>` - Node's IP address or hostname. Get from: `fledx nodes status --wide` (see `address` column)
- `<node-id>` - Node UUID. Get from: `fledx nodes status` (see `id` column)
- `<deployment-id>` - Deployment UUID. Get from: `fledx deployments status` or `fledx deployments create` output
- `<config-id>` - Config UUID. Get from: `fledx configs list`
- `<port>` - Assigned host port. Get from: `fledx deployments status --id <deployment-id> --wide` (see `ports` column)

## Deployment Lifecycle

### 1. Create

Define and create a new deployment (save the ID for later operations):

```bash
# Create and save deployment ID
DEPLOY_ID=$(fledx deployments create \
  --name my-app \
  --image registry.example.com/my-app:v1.0 \
  --replicas 2 \
  --port 8080:3000/tcp \
  --env NODE_ENV=production \
  --json | jq -r '.deployment_id')

echo "Created deployment: $DEPLOY_ID"
```

### 2. Monitor

Watch deployment progress:

```bash
fledx deployments watch --id $DEPLOY_ID --follow-logs
```

Check status:

```bash
# List all deployments
fledx deployments status --wide

# Or filter for specific deployment
fledx deployments status --json | jq '.items[] | select(.deployment_id=="'$DEPLOY_ID'")'
```

### 3. Update

Modify configuration, scale, or update image:

```bash
fledx deployments update \
  --id $DEPLOY_ID \
  --image registry.example.com/my-app:v1.1 \
  --replicas 3
```

### 4. Stop

Temporarily stop without deleting:

```bash
fledx deployments stop --id $DEPLOY_ID
```

### 5. Delete

Permanently remove:

```bash
fledx deployments delete --id $DEPLOY_ID
```

## Replica Management

### Scaling

Increase or decrease replicas:

```bash
# Scale up
fledx deployments update --id <deployment-id> --replicas 5

# Scale down
fledx deployments update --id <deployment-id> --replicas 1
```

### Spread Replicas

Distribute replicas across multiple nodes for resilience:

```bash
fledx deployments create \
  --name distributed-app \
  --image my-app:latest \
  --replicas 3 \
  --spread
```

## Port Configuration

### Single Port

```bash
--port 8080:3000/tcp
```

Maps host port 8080 to container port 3000.

### Multiple Ports

```bash
--port 8080:3000/tcp --port 8443:3443/tcp
```

### Auto-Assigned Ports

Let the platform assign ports automatically:

```bash
fledx deployments create \
  --name auto-port-app \
  --image my-app:latest \
  --port 3000/tcp
```

The control plane will assign an available port on the node.

## Environment Variables

### Simple Variables

```bash
--env KEY=value --env ANOTHER_KEY=another_value
```

### Secret Variables

For sensitive data, use secret-backed environment variables (requires node-side secrets):

```bash
fledx deployments create \
  --name secure-app \
  --image my-app:latest \
  --secret-env DB_PASSWORD=db-secret-ref
```

Node agents must have `FLEDX_SECRET_db-secret-ref` set.

### Configuration Files

Use the configuration management system for complex configurations:

```bash
# Create config
fledx configs create \
  --name app-config \
  --var DATABASE_URL=postgres://... \
  --var API_KEY=xyz

# Attach to deployment
fledx configs attach deployment \
  --config-id <config-id> \
  --deployment-id <deployment-id>
```

See the [Configuration Guide](configuration.md) for details.

## Placement & Constraints

### Node Affinity

Deploy only to specific nodes by label:

```bash
fledx deployments create \
  --name edge-only-app \
  --image my-app:latest \
  --affinity-label region=edge
```

Node must have the matching label (set during registration):

```bash
# Register node with labels
fledx nodes register --name edge-node --label region=edge
```

### Resource Constraints

Specify CPU and memory requirements:

```bash
fledx deployments create \
  --name resource-app \
  --image my-app:latest \
  --require-cpu-millis 2000 \
  --require-memory-bytes 2147483648
```

## Volume Mounts

### Bind Mounts

Mount host directories into containers:

```bash
fledx deployments create \
  --name volume-app \
  --image my-app:latest \
  --volume /var/lib/fledx/volumes/app-data:/data
```

### Security

Only allowed prefixes (set in `FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES`) can be mounted:

```bash
FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES=/var/lib/fledx/volumes
```

## Multi-Container Applications

### Pattern: Web + Database

```bash
# Database
fledx deployments create \
  --name postgres \
  --image postgres:15-alpine \
  --port 5432:5432/tcp \
  --env POSTGRES_PASSWORD=secret \
  --volume /var/lib/fledx/volumes/postgres:/var/lib/postgresql/data

# Web App
fledx deployments create \
  --name web \
  --image my-web-app:latest \
  --port 8080:3000/tcp \
  --env DATABASE_URL="postgres://postgres:secret@<node-ip>:5432/app"
```

### Pattern: Microservices

```bash
# Service A
fledx deployments create --name service-a --image service-a:v1 --port 8081:8080/tcp

# Service B
fledx deployments create --name service-b --image service-b:v1 --port 8082:8080/tcp

# API Gateway
fledx deployments create \
  --name gateway \
  --image nginx:alpine \
  --port 80:80/tcp \
  --volume /var/lib/fledx/volumes/nginx-config:/etc/nginx/conf.d:ro
```

## Rolling Updates

### Update Image Version

```bash
# Get deployment ID (if not already saved)
DEPLOY_ID=$(fledx deployments status --json | jq -r '.items[] | select(.name=="my-app") | .deployment_id')

# Update to new version
fledx deployments update --id $DEPLOY_ID --image my-app:v2.0

# Watch rollout
fledx deployments watch --id $DEPLOY_ID
```

The platform will:

1. Pull the new image on assigned nodes
2. Stop old containers
3. Start new containers with the new image
4. Report health status

### Rollback

If an update fails, roll back to the previous image:

```bash
fledx deployments update --id $DEPLOY_ID --image my-app:v1.9
```

## Health Checks & Monitoring

### Watch Deployment

Monitor in real-time:

```bash
fledx deployments watch --id $DEPLOY_ID --follow-logs
```

### Check Instance Status

```bash
# List all deployments
fledx deployments status --wide

# Or check specific deployment
fledx deployments status --json | jq '.items[] | select(.deployment_id=="'$DEPLOY_ID'")'
```

Look for:

- `STATUS: running` – Healthy
- `STATUS: deploying` – Still starting
- `STATUS: failed` – Check logs

### View Logs

```bash
fledx deployments logs --resource-type deployment --resource-id <id>
```

## Best Practices

### 1. Use Specific Image Tags

**Good:**

```bash
--image my-app:v1.2.3
```

**Bad:**

```bash
--image my-app:latest
```

### 2. Set Resource Limits

Prevent resource exhaustion:

```bash
--cpu-millis 2000 --memory-bytes 2147483648
```

### 3. Use Configurations for Secrets

Never hardcode secrets in commands:

```bash
# Bad
--env DB_PASSWORD=supersecret

# Good
fledx configs create --name secrets --secret-entry DB_PASSWORD=db-pass-ref
```

### 4. Spread Critical Services

Use `--spread` and `--replicas > 1` for high availability:

```bash
--replicas 3 --spread
```

### 5. Label Nodes Appropriately

Group nodes by role, region, or capability (set during registration):

```bash
# Register nodes with descriptive labels
fledx nodes register --name web-node-eu --label role=web --label region=eu
```

### 6. Monitor Deployments

Regularly check status and logs:

```bash
fledx deployments status --wide
fledx deployments logs --resource-type deployment --resource-id <id> --follow
```

## Troubleshooting

### Deployment Stuck in "Deploying"

**Possible causes:**

- Image pull failure (check registry access)
- Port conflict (try different port)
- Insufficient node resources

**Solution:**

```bash
# Check node status
fledx nodes status --wide

# Check agent logs
sudo journalctl -u fledx-agent -f

# Delete and recreate
fledx deployments delete --id <deployment-id>
fledx deployments create ...
```

### Container Restarts Frequently

**Check restart count:**

```bash
# List all deployments with details
fledx deployments status --wide
```

**Common causes:**

- Application crashes (check logs)
- Health check failures
- Resource limits too low

**Solution:**

```bash
# Get deployment ID
DEPLOY_ID=$(fledx deployments status --json | jq -r '.items[] | select(.name=="my-app") | .deployment_id')

# View logs
fledx deployments logs --resource-type deployment --resource-id $DEPLOY_ID

# Increase resources
fledx deployments update --id $DEPLOY_ID --require-memory-bytes 4294967296
```

### Can't Access Service

**Check:**

1. Deployment is running: `fledx deployments status`
2. Port is open: `curl http://<node-ip>:<port>`
3. Firewall rules allow traffic
4. Node is reachable: `ping <node-ip>`

## Next Steps

- **YAML Deployments:** [YAML Deployments Guide](yaml-deployments.md)
- **Configuration Management:** [Configuration Guide](configuration.md)
- **Monitoring:** [Monitoring Guide](monitoring.md)
- **Security:** [Security Guide](security.md)
- **CLI Reference:** [CLI Reference](../reference/cli.md)
- **API Reference:** [API Reference](../reference/api.md)
