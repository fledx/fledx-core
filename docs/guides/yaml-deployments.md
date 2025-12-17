# YAML-Based Deployments

This guide explains how to define and deploy applications using YAML specification files instead of CLI flags.

## Placeholders in Examples

Throughout this guide, you'll see placeholders in angle brackets. Here's how to find the actual values:

- `<node-ip>` - Node's IP address or hostname. Get from: `fledx nodes status --wide` (see `address` column)
- `<deployment-id>` - Deployment UUID. Get from: `fledx deployments status` or the output of your deployment command
- `<port>` - Assigned host port. Get from: `fledx deployments status --id <deployment-id> --wide` (see `ports` column)

## Overview

While the CLI provides a quick way to create deployments with flags like `--name`, `--image`, and `--port`, YAML files
offer a more structured and version-controllable approach. YAML deployments are especially useful for:

- Complex configurations with many options
- Version control and GitOps workflows
- Repeatable deployments across environments
- Documentation of deployment specifications
- Advanced features like health checks and multiple probes

## Basic YAML Structure

A deployment specification file contains the following main sections:

```yaml
# Basic deployment metadata
name: my-app
image: nginx:alpine
replicas: 1

# Environment variables
env:
  KEY: value

# Port mappings
ports:
  - container_port: 80
    host_port: 8080
    protocol: tcp
    expose: true

# Volume mounts
volumes:
  - host_path: /var/lib/fledx/data
    container_path: /app/data
    read_only: false

# Health checks
health:
  readiness:
    type: http
    port: 80
    path: /health
  liveness:
    type: tcp
    port: 80
```

## Field Reference

### Basic Fields

#### `name` (required)

The deployment name. Must be unique.

```yaml
name: web-server
```

#### `image` (required)

The container image to deploy.

```yaml
image: nginx:1.27-alpine
```

#### `replicas` (optional, default: 1)

Number of replicas to run.

```yaml
replicas: 3
```

### Environment Variables

Define environment variables as key-value pairs:

```yaml
env:
  DATABASE_URL: postgres://db:5432/app
  LOG_LEVEL: info
  DEBUG: "false"
```

**Note:** All values are strings in YAML. Quote numbers and booleans to avoid type conversion issues.

### Port Mappings

The `ports` section defines how container ports are exposed on the host.

#### Fields

- `container_port` (required) - Port inside the container
- `host_port` (optional) - Port on the host (auto-assigned if omitted when `expose: true`)
- `protocol` (optional, default: `tcp`) - Protocol (`tcp` or `udp`)
- `expose` (optional, default: `false`) - Whether to expose the port externally

#### Examples

**Simple port mapping:**

```yaml
ports:
  - container_port: 80
    host_port: 8080
    protocol: tcp
    expose: true
```

**Auto-assigned host port:**

```yaml
ports:
  - container_port: 3000
    expose: true
```

The platform will assign an available port from the configured range.

**Multiple ports:**

```yaml
ports:
  - container_port: 80
    host_port: 8080
    protocol: tcp
    expose: true
  - container_port: 443
    host_port: 8443
    protocol: tcp
    expose: true
```

**Internal port (not exposed):**

```yaml
ports:
  - container_port: 9090
    protocol: tcp
    expose: false
```

### Volume Mounts

The `volumes` section defines bind mounts from the host to the container.

#### Fields

- `host_path` (required) - Absolute path on the host
- `container_path` (required) - Absolute path in the container
- `read_only` (optional, default: `false`) - Mount as read-only

#### Examples

**Read-write data volume:**

```yaml
volumes:
  - host_path: /var/lib/fledx/postgres-data
    container_path: /var/lib/postgresql/data
```

**Read-only config file:**

```yaml
volumes:
  - host_path: /var/lib/fledx/config/app.conf
    container_path: /etc/app/app.conf
    read_only: true
```

**Multiple volumes:**

```yaml
volumes:
  - host_path: /var/lib/fledx/data
    container_path: /app/data
  - host_path: /var/lib/fledx/logs
    container_path: /app/logs
```

**Security Note:** Only paths matching `FLEDX_AGENT_ALLOWED_VOLUME_PREFIXES` can be mounted. By default, this is
`/var/lib/fledx/volumes`.

### Health Checks

Health checks monitor application health and determine when containers are ready and alive.

#### Probe Types

Fledx supports two types of health probes:

- **Readiness** – Determines when the container is ready to accept traffic
- **Liveness** – Determines if the container is still healthy

#### Check Types

##### HTTP Check

Performs an HTTP GET request:

```yaml
health:
  readiness:
    type: http
    port: 80
    path: /health
    interval_seconds: 5
    timeout_seconds: 2
    failure_threshold: 3
```

##### TCP Check

Tests if a TCP port is accepting connections:

```yaml
health:
  liveness:
    type: tcp
    port: 5432
    interval_seconds: 10
    timeout_seconds: 3
```

##### Exec Check

Runs a command inside the container:

```yaml
health:
  readiness:
    type: exec
    command:
      - pg_isready
      - -U
      - postgres
    interval_seconds: 10
    timeout_seconds: 5
    failure_threshold: 6
```

#### Health Check Fields

- `type` (required) - `http`, `tcp`, or `exec`
- `port` (required for `http` and `tcp`) - Port to check
- `path` (required for `http`) - HTTP path to request
- `command` (required for `exec`) - Command array to execute
- `interval_seconds` (optional, default: 10) - Seconds between checks
- `timeout_seconds` (optional, default: 5) - Seconds before timeout
- `failure_threshold` (optional, default: 3) - Failures before marking unhealthy

#### Combined Readiness and Liveness

You can define both probes:

```yaml
health:
  readiness:
    type: http
    port: 80
    path: /ready
    interval_seconds: 5
    timeout_seconds: 2
    failure_threshold: 3
  liveness:
    type: http
    port: 80
    path: /alive
    interval_seconds: 10
    timeout_seconds: 2
    failure_threshold: 3
```

## Deploying from YAML

### Using the CLI

Convert YAML to JSON and POST to the API:

```bash
curl -sSL -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "Content-Type: application/json" \
  -H "x-operator-token: $FLEDX_CLI_OPERATOR_TOKEN" \
  -d "$(yq -o=json < deployment.yaml)"
```

**Prerequisites:**

- `yq` installed ([yq installation guide](https://github.com/mikefarah/yq))
- `FLEDX_CLI_CONTROL_PLANE_URL` and `FLEDX_CLI_OPERATOR_TOKEN` environment variables set

### Using a Deployment Script

For automation, create a helper script:

```bash
#!/bin/bash
set -e

YAML_FILE="$1"
if [ -z "$YAML_FILE" ]; then
  echo "Usage: $0 <deployment.yaml>"
  exit 1
fi

curl -sSL -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "Content-Type: application/json" \
  -H "x-operator-token: $FLEDX_CLI_OPERATOR_TOKEN" \
  -d "$(yq -o=json < "$YAML_FILE")"
```

Save as `deploy.sh`, make executable, and use:

```bash
chmod +x deploy.sh
./deploy.sh my-deployment.yaml
```

## Example Deployments

The following examples demonstrate common deployment patterns.

### Example 1: Nginx Web Server

Simple web server with HTTP health checks.

**File:** `nginx-web.yaml`

```yaml
name: web-nginx
image: nginx:1.27-alpine
replicas: 1
ports:
  - container_port: 80
    host_port: 8080
    protocol: tcp
    expose: true
health:
  readiness:
    type: http
    port: 80
    path: /
    interval_seconds: 5
    timeout_seconds: 2
    failure_threshold: 3
  liveness:
    type: http
    port: 80
    path: /
    interval_seconds: 10
    timeout_seconds: 2
    failure_threshold: 3
```

**Deploy:**

```bash
curl -sSL -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "Content-Type: application/json" \
  -H "x-operator-token: $FLEDX_CLI_OPERATOR_TOKEN" \
  -d "$(yq -o=json < nginx-web.yaml)"
```

**Verify:**

```bash
fledx deployments list | grep web-nginx
curl http://<node-ip>:8080/
```

### Example 2: Mosquitto MQTT Broker

MQTT broker with config file mount and TCP health check.

**File:** `mosquitto-mqtt.yaml`

```yaml
name: mqtt-broker
image: eclipse-mosquitto:2.0
replicas: 1
ports:
  - container_port: 1883
    host_port: 1883
    protocol: tcp
    expose: true
volumes:
  - host_path: /var/lib/fledx/volumes/mosquitto.conf
    container_path: /mosquitto/config/mosquitto.conf
    read_only: true
health:
  liveness:
    type: tcp
    port: 1883
    interval_seconds: 10
    timeout_seconds: 3
```

**Prerequisites:**

Create the config file on the node:

```bash
sudo mkdir -p /var/lib/fledx/volumes
sudo tee /var/lib/fledx/volumes/mosquitto.conf <<EOF
listener 1883
allow_anonymous true
EOF
```

**Deploy:**

```bash
curl -sSL -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "Content-Type: application/json" \
  -H "x-operator-token: $FLEDX_CLI_OPERATOR_TOKEN" \
  -d "$(yq -o=json < mosquitto-mqtt.yaml)"
```

**Verify:**

```bash
fledx deployments list | grep mqtt-broker

# Test with mosquitto clients
mosquitto_sub -h <node-ip> -p 1883 -t test &
mosquitto_pub -h <node-ip> -p 1883 -t test -m "Hello MQTT"
```

### Example 3: PostgreSQL Database

Database with persistent volume and exec health check.

**File:** `postgres-db.yaml`

```yaml
name: postgres-db
image: postgres:16-alpine
replicas: 1
env:
  POSTGRES_USER: app
  POSTGRES_PASSWORD: changeme
  POSTGRES_DB: app
ports:
  - container_port: 5432
    host_port: 5432
    protocol: tcp
    expose: true
volumes:
  - host_path: /var/lib/fledx/volumes/postgres-data
    container_path: /var/lib/postgresql/data
health:
  readiness:
    type: exec
    command:
      - pg_isready
      - -U
      - app
    interval_seconds: 10
    timeout_seconds: 5
    failure_threshold: 6
  liveness:
    type: tcp
    port: 5432
    interval_seconds: 20
    timeout_seconds: 5
```

**Prerequisites:**

Create the data directory on the node:

```bash
sudo mkdir -p /var/lib/fledx/volumes/postgres-data
sudo chown -R 999:999 /var/lib/fledx/volumes/postgres-data  # Postgres UID
```

**Deploy:**

```bash
curl -sSL -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "Content-Type: application/json" \
  -H "x-operator-token: $FLEDX_CLI_OPERATOR_TOKEN" \
  -d "$(yq -o=json < postgres-db.yaml)"
```

**Verify:**

```bash
fledx deployments list | grep postgres-db
psql postgres://app:changeme@<node-ip>:5432/app -c "SELECT 1"
```

**Cleanup:**

Data persists after deployment deletion. Remove manually:

```bash
fledx deployments delete --id <deployment-id>
sudo rm -rf /var/lib/fledx/volumes/postgres-data
```

## Advanced Patterns

### Multi-Tier Application

Deploy a web app with database:

**database.yaml:**

```yaml
name: app-db
image: postgres:16-alpine
replicas: 1
env:
  POSTGRES_USER: appuser
  POSTGRES_PASSWORD: secret
  POSTGRES_DB: appdb
ports:
  - container_port: 5432
    host_port: 5432
    expose: true
volumes:
  - host_path: /var/lib/fledx/volumes/app-db
    container_path: /var/lib/postgresql/data
health:
  readiness:
    type: exec
    command: [ pg_isready, -U, appuser ]
    interval_seconds: 10
```

**webapp.yaml:**

```yaml
name: app-web
image: myapp:v1.0
replicas: 2
env:
  DATABASE_URL: postgres://appuser:secret@<node-ip>:5432/appdb
  PORT: "3000"
ports:
  - container_port: 3000
    host_port: 8080
    expose: true
health:
  readiness:
    type: http
    port: 3000
    path: /health
    interval_seconds: 5
  liveness:
    type: http
    port: 3000
    path: /health
    interval_seconds: 10
```

Deploy both:

```bash
# Deploy database first
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "Content-Type: application/json" \
  -H "x-operator-token: $FLEDX_CLI_OPERATOR_TOKEN" \
  -d "$(yq -o=json < database.yaml)"

# Wait for database to be ready
fledx deployments watch --id <deployment-id>

# Deploy web app
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "Content-Type: application/json" \
  -H "x-operator-token: $FLEDX_CLI_OPERATOR_TOKEN" \
  -d "$(yq -o=json < webapp.yaml)"
```

### Configuration as Code

Store deployment specs in Git for version control:

```
deployments/
├── production/
│   ├── web.yaml
│   ├── api.yaml
│   └── db.yaml
├── staging/
│   ├── web.yaml
│   └── api.yaml
└── README.md
```

Deploy all production services:

```bash
for file in deployments/production/*.yaml; do
  echo "Deploying $file..."
  curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
    -H "Content-Type: application/json" \
    -H "x-operator-token: $FLEDX_CLI_OPERATOR_TOKEN" \
    -d "$(yq -o=json < "$file")"
done
```

## Troubleshooting

### YAML Syntax Errors

Use `yq` to validate YAML before deploying:

```bash
yq eval deployment.yaml
```

### Port Conflicts

If ports are in use, check existing deployments:

```bash
fledx deployments list --wide
```

Change `host_port` in your YAML or remove it for auto-assignment.

### Volume Permission Issues

Ensure the host path exists and has correct permissions:

```bash
sudo mkdir -p /var/lib/fledx/volumes/myapp
sudo chown 1000:1000 /var/lib/fledx/volumes/myapp  # Match container UID
```

### Health Check Failures

Check deployment status and logs:

```bash
fledx deployments status --wide
fledx deployments logs --resource-type deployment --resource-id <id>
```

Increase `failure_threshold` or `interval_seconds` if checks are too aggressive.

## Best Practices

1. **Use specific image tags** – Avoid `latest` in production
2. **Version control YAML files** – Track changes in Git
3. **Set health checks** – Always define readiness and liveness probes
4. **Document environment variables** – Add comments explaining each var
5. **Use read-only volumes** – When possible, mount config files as `read_only: true`
6. **Test locally first** – Validate YAML syntax before deploying to production
7. **Store secrets separately** – Use config management for sensitive data (see [Configuration Guide](configuration.md))

## Next Steps

- **Learn about Configuration Management:** [Configuration Guide](configuration.md)
- **Explore Deployment Patterns:** [Deployment Guide](deployment.md)
- **Set up Monitoring:** [Monitoring Guide](monitoring.md)
- **API Reference:** [API Documentation](../reference/api.md)
