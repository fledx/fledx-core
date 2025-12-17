# Your First Deployment

This guide walks you through deploying your first containerized application after completing
the [Getting Started](index.md) guide.

## Prerequisites

- Control plane running and accessible
- At least one node registered and agent running
- CLI configured with `FLEDX_CLI_CONTROL_PLANE_URL` and `FLEDX_CLI_OPERATOR_TOKEN`

## Verify Node Status

Before deploying, verify your node is connected and ready:

```bash
fledx nodes status
```

You should see at least one node with `STATUS: ready`.

## Deploy a Simple Web Server

Let's deploy a simple HTTP echo server that returns request information.

### Create the Deployment

```bash
# Create deployment and save ID for later operations
DEPLOY_ID=$(fledx deployments create \
  --name hello-web \
  --image hashicorp/http-echo:0.2.3 \
  --port 8080:5678/tcp \
  --env TEXT="Hello from Distributed Edge Hosting!" \
  --json | jq -r '.deployment_id')

echo "Deployment ID: $DEPLOY_ID"
```

### Understanding the Command

- `--name hello-web` – A friendly name for your deployment
- `--image hashicorp/http-echo:0.2.3` – The Docker image to run
- `--port 8080:5678/tcp` – Map host port 8080 to container port 5678
- `--env TEXT="..."` – Pass an environment variable to the container
- `--json | jq -r '.deployment_id'` – Extract and save the deployment ID

### Check Deployment Status

```bash
fledx deployments status --status running
```

Or watch the deployment in real-time:

```bash
fledx deployments watch --id $DEPLOY_ID
```

### Access Your Application

Find the node's public IP or hostname from the status output, then:

```bash
curl http://<node-ip>:8080
```

You should see: `Hello from Distributed Edge Hosting!`

## Deploy with Custom Configuration

### Example: Nginx with Custom HTML

```bash
fledx deployments create \
  --name custom-nginx \
  --image nginx:alpine \
  --port 8081:80/tcp \
  --command sh -c "echo '<h1>Welcome to Fledx</h1>' > /usr/share/nginx/html/index.html && nginx -g 'daemon off;'" \
  --env NGINX_ENTRYPOINT_QUIET_LOGS=1
```

Access it:

```bash
curl http://<node-ip>:8081
```

### Example: Multi-Replica Deployment

Deploy multiple replicas for redundancy:

```bash
fledx deployments create \
  --name multi-web \
  --image hashicorp/http-echo:0.2.3 \
  --replicas 2 \
  --port 8082:5678/tcp \
  --env TEXT="Replica instance"
```

Check which nodes the replicas are running on:

```bash
fledx deployments status --wide
```

## Update a Deployment

### Change Environment Variables

```bash
# Get deployment ID first
DEPLOY_ID=$(fledx deployments list --json | jq -r '.items[] | select(.name=="hello-web") | .deployment_id')

fledx deployments update \
  --id $DEPLOY_ID \
  --env TEXT="Updated message!"
```

### Scale Replicas

```bash
fledx deployments update \
  --id $DEPLOY_ID \
  --replicas 3
```

### Change the Image Version

```bash
fledx deployments update \
  --id $DEPLOY_ID \
  --image hashicorp/http-echo:latest
```

## Stop and Delete Deployments

### Stop a Deployment

Stop without deleting:

```bash
fledx deployments stop --id $DEPLOY_ID
```

### Restart a Deployment

```bash
fledx deployments update --id $DEPLOY_ID --desired-state running
```

### Delete a Deployment

Permanently remove:

```bash
fledx deployments delete --id $DEPLOY_ID
```

## Using the Web UI

You can also manage deployments through the Web UI:

1. Open `http://<control-plane>:8080/ui`
2. Enter your operator token
3. Navigate to the "Create Deployment" tab
4. Fill in the form (image, ports, environment, etc.)
5. Click "Submit"

The UI provides the same functionality as the CLI with a visual interface.

## Common Deployment Patterns

### Web Application with Database

```bash
# Deploy database
fledx deployments create \
  --name postgres-db \
  --image postgres:15-alpine \
  --port 5432:5432/tcp \
  --env POSTGRES_PASSWORD=secret \
  --env POSTGRES_DB=appdb

# Deploy web app
fledx deployments create \
  --name web-app \
  --image your-registry.com/web-app:v1.0 \
  --port 8080:3000/tcp \
  --env DATABASE_URL="postgres://postgres:secret@<node-ip>:5432/appdb"
```

### Static Site

```bash
fledx deployments create \
  --name static-site \
  --image nginx:alpine \
  --port 8080:80/tcp \
  --volume /var/lib/fledx/volumes/static-content:/usr/share/nginx/html:ro
```

### Background Worker

```bash
fledx deployments create \
  --name background-worker \
  --image your-registry.com/worker:v1.0 \
  --env QUEUE_URL="redis://<node-ip>:6379"
  # No --port needed for background services
```

## Troubleshooting

### Deployment Stuck in "Deploying"

Check node agent logs:

```bash
sudo journalctl -u fledx-agent -f
```

Common causes:

- Image pull failures (check registry access)
- Port conflicts (try a different port)
- Insufficient resources (check node capacity)

### Container Fails to Start

View deployment details:

```bash
fledx deployments status --wide
```

Check for:

- Invalid environment variables
- Missing dependencies
- Incorrect command/arguments

### Can't Access Deployed Service

Verify:

- Node is reachable: `ping <node-ip>`
- Port is correct: `fledx deployments status --wide`
- Firewall allows traffic on the port
- Service is actually listening: Check container logs

## Next Steps

- **Deploy with YAML Files:** [YAML Deployments Guide](../guides/yaml-deployments.md)
- **Learn about Configuration Management:** [Configuration Guide](../guides/configuration.md)
- **Set up Monitoring:** [Monitoring Guide](../guides/monitoring.md)
- **Explore Advanced Deployments:** [Deployment Guide](../guides/deployment.md)
- **Read CLI Reference:** [CLI Reference](../reference/cli.md)
- **Use the API:** [API Reference](../reference/api.md)
