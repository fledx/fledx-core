# API Reference

The REST API provides programmatic access to all Distributed Edge Hosting functionality. This guide covers
authentication, common workflows, and practical examples for integrating Fledx into your automation pipelines.

## OpenAPI Specification

The complete OpenAPI spec lives in `docs/openapi.json` and is the source of truth for the public API.

**View the spec:**

- Local render with Redoc: `npx redoc-cli bundle docs/openapi.json -o docs/reference/api.html`
- The OpenAPI specification is located at `docs/openapi.json` in your installation

## Base URL & Versioning

All API endpoints are prefixed with `/api/v1`:

```
https://control-plane.example.com/api/v1/
```

The API follows semantic versioning. Breaking changes will increment the major version (`v2`, `v3`, etc.).

## Authentication

### Operator Tokens

All operator endpoints require bearer token authentication via the `authorization` header (header name is configurable
via `FLEDX_CP_OPERATOR_HEADER_NAME`).

**Request format:**

```bash
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments"
```

**Environment setup:**

```bash
export FLEDX_CLI_CONTROL_PLANE_URL=https://control-plane.example.com
export FLEDX_CLI_OPERATOR_TOKEN=your-operator-token-here
```

**Token management:**

- Tokens are configured in the control plane: `FLEDX_CP_OPERATOR_TOKENS=token1,token2`
- Multiple tokens supported (comma-separated)
- Rotate tokens by updating control plane config and restarting
- Env tokens are for bootstrap only. The control-plane logs a warning on use; set
  `FLEDX_CP_OPERATOR_ENV_DISABLE_AFTER_FIRST_SUCCESS=true` to disable env tokens after the first successful admin call
  and remove them from your config once rotated.

### Public Endpoints

The following endpoints do not require authentication:

- `GET /health` - Control plane health check
- `GET /metrics` - Prometheus metrics (requires operator token)

## Common Workflows

### 1. Health Check & System Status

**Check control plane health:**

```bash
curl -fsSL "$FLEDX_CLI_CONTROL_PLANE_URL/health"
```

**Response:**

```json
{
  "status": "healthy",
  "version": "1.5.0",
  "database": "ok",
  "uptime_seconds": 86400
}
```

**List all nodes:**

```bash
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/nodes?limit=50&offset=0"
```

**Response:**

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

### 2. Deploy an Application

**Simple deployment:**

```bash
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "name": "nginx-web",
    "image": "nginx:alpine",
    "replicas": 1,
    "desired_state": "running",
    "ports": [
      {
        "container_port": 80,
        "host_port": 8080,
        "protocol": "tcp"
      }
    ]
  }'
```

**Response:**

```json
{
  "deployment_id": "c2d4e1f5-1b2c-4e5a-8b1f-9b4d1e82964b",
  "name": "nginx-web",
  "image": "nginx:alpine",
  "replicas": 1,
  "desired_state": "running",
  "status": "pending",
  "generation": 1,
  "created_at": "2025-12-11T10:00:00Z"
}
```

**Deployment with environment variables:**

```bash
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "name": "my-app",
    "image": "my-app:v1.0",
    "replicas": 2,
    "desired_state": "running",
    "environment": {
      "NODE_ENV": "production",
      "API_URL": "https://api.example.com"
    },
    "ports": [
      {"container_port": 3000, "host_port": 8080, "protocol": "tcp"}
    ]
  }'
```

**Deploy from YAML file:**

```bash
# Using yq to convert YAML to JSON
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d "$(yq -o=json < deployment.yaml)"
```

### 3. Monitor Deployments

**List all deployments:**

```bash
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments?limit=50&offset=0"
```

**Get specific deployment:**

```bash
DEPLOYMENT_ID="c2d4e1f5-1b2c-4e5a-8b1f-9b4d1e82964b"
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments/$DEPLOYMENT_ID"
```

**Filter by status:**

```bash
# Only running deployments
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments?status=running"

# Failed deployments
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments?status=failed"
```

### 4. Update a Deployment

**Update image version:**

```bash
DEPLOYMENT_ID="c2d4e1f5-1b2c-4e5a-8b1f-9b4d1e82964b"
curl -X PATCH "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "image": "nginx:1.25-alpine"
  }'
```

**Scale replicas:**

```bash
curl -X PATCH "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "replicas": 5
  }'
```

**Update environment variables:**

```bash
curl -X PATCH "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "environment": {
      "NODE_ENV": "production",
      "LOG_LEVEL": "debug"
    }
  }'
```

### 5. Stop & Delete Deployments

**Stop (without deleting):**

```bash
curl -X PATCH "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "desired_state": "stopped"
  }'
```

**Delete permanently:**

```bash
curl -X DELETE "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN"
```

### 6. Node Management

**Register a new node:**

```bash
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/nodes/register" \
  -H "content-type: application/json" \
  -H "x-registration-token: $FLEDX_CLI_REGISTRATION_TOKEN" \
  -d '{
    "name": "edge-1",
    "arch": "amd64",
    "os": "linux"
  }'
```

**Response:**

```json
{
  "node_id": "8e7f3d4a-8d7b-4fdc-91cf-2c1f0d6b9a1a",
  "node_token": "secure-node-token-here",
  "name": "edge-1"
}
```

**Update node labels:**

```bash
NODE_ID="8e7f3d4a-8d7b-4fdc-91cf-2c1f0d6b9a1a"
curl -X PATCH "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/nodes/$NODE_ID" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "labels": {
      "region": "eu-west",
      "role": "edge",
      "site": "hq"
    }
  }'
```

**Delete a node:**

```bash
curl -X DELETE "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/nodes/$NODE_ID" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN"
```

### 7. View Logs

**Get deployment logs:**

```bash
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/logs?resource_type=deployment&resource_id=$DEPLOYMENT_ID&limit=100"
```

**Response:**

```json
{
  "limit": 100,
  "items": [
    {
      "timestamp": "2025-12-11T10:05:00Z",
      "status": "info",
      "action": "container_started",
      "resource": "deployment/nginx-web",
      "request_id": "req-123",
      "details": "Container started successfully"
    }
  ]
}
```

### 8. Configuration Management

Configuration objects store environment variables and secrets that can be attached to deployments and nodes.

**Create a configuration:**

```bash
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/configs" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "name": "app-config",
    "version": 1,
    "entries": {
      "DATABASE_URL": "postgres://db.example.com/mydb",
      "API_KEY": "your-api-key",
      "LOG_LEVEL": "info"
    },
    "secret_entries": {
      "DB_PASSWORD": "db-secret-ref"
    }
  }'
```

**Response:**

```json
{
  "config_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "app-config",
  "version": 1,
  "entry_count": 3,
  "secret_entry_count": 1,
  "created_at": "2025-12-11T10:00:00Z"
}
```

**List configurations:**

```bash
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/configs?limit=50&offset=0"
```

**Response:**

```json
{
  "limit": 50,
  "offset": 0,
  "items": [
    {
      "config_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "app-config",
      "version": 1,
      "entry_count": 3,
      "secret_entry_count": 1,
      "created_at": "2025-12-11T10:00:00Z"
    }
  ]
}
```

**Get specific configuration:**

```bash
CONFIG_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/configs/$CONFIG_ID"
```

**Update a configuration:**

```bash
curl -X PUT "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/configs/$CONFIG_ID" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "name": "app-config",
    "version": 2,
    "entries": {
      "DATABASE_URL": "postgres://new-db.example.com/mydb",
      "API_KEY": "updated-api-key"
    }
  }'
```

**Attach config to deployment:**

```bash
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/configs/$CONFIG_ID/deployments/$DEPLOYMENT_ID" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN"
```

**Attach config to node:**

```bash
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/configs/$CONFIG_ID/nodes/$NODE_ID" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN"
```

**Detach config from deployment:**

```bash
curl -X DELETE "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/configs/$CONFIG_ID/deployments/$DEPLOYMENT_ID" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN"
```

**Delete configuration:**

```bash
curl -X DELETE "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/configs/$CONFIG_ID" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN"
```

## Advanced Patterns

### CI/CD Integration

Integrate Fledx deployments into your CI/CD pipeline using the REST API:

**Generic CI/CD script:**

```bash
#!/bin/bash
# deploy.sh - Generic deployment script for CI/CD

# Set from CI/CD environment variables
CONTROL_PLANE_URL="${FLEDX_CLI_CONTROL_PLANE_URL}"
OPERATOR_TOKEN="${FLEDX_CLI_OPERATOR_TOKEN}"
APP_NAME="${APP_NAME:-my-app}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REPLICAS="${REPLICAS:-3}"

# Deploy via API
curl -X POST "${CONTROL_PLANE_URL}/api/v1/deployments" \
  -H "content-type: application/json" \
  -H "authorization: Bearer ${OPERATOR_TOKEN}" \
  -d "{
    \"name\": \"${APP_NAME}\",
    \"image\": \"registry.example.com/my-app:${IMAGE_TAG}\",
    \"replicas\": ${REPLICAS},
    \"desired_state\": \"running\"
  }"

# Wait for deployment
DEPLOYMENT_ID=$(curl -s "${CONTROL_PLANE_URL}/api/v1/deployments?name=${APP_NAME}" \
  -H "authorization: Bearer ${OPERATOR_TOKEN}" | jq -r '.items[0].deployment_id')

echo "Deployment created: ${DEPLOYMENT_ID}"
echo "Monitor at: ${CONTROL_PLANE_URL}/ui"
```

**Environment variables for CI/CD:**

Configure these in your CI/CD system's secret management:

```bash
FLEDX_CLI_CONTROL_PLANE_URL=https://control-plane.example.com
FLEDX_CLI_OPERATOR_TOKEN=your-operator-token
APP_NAME=my-application
IMAGE_TAG=v1.2.3
REPLICAS=3
```

**Integration example:**

```yaml
# Example pipeline configuration (platform-agnostic)
deploy:
  stage: deploy
  script:
    - ./scripts/deploy.sh
  environment:
    name: production
  only:
    - tags
```

### Blue-Green Deployments

```bash
# Deploy blue version
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "name": "app-blue",
    "image": "my-app:v1.0",
    "replicas": 3,
    "ports": [{"container_port": 3000, "host_port": 8080, "protocol": "tcp"}]
  }'

# Deploy green version (different port)
curl -X POST "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  -d '{
    "name": "app-green",
    "image": "my-app:v2.0",
    "replicas": 3,
    "ports": [{"container_port": 3000, "host_port": 8081, "protocol": "tcp"}]
  }'

# Test green version, then switch load balancer
# Finally delete blue:
curl -X DELETE "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments/app-blue" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN"
```

## Error Handling

### HTTP Status Codes

- `200` - Success
- `201` - Created (for POST requests)
- `400` - Bad Request (validation error)
- `401` - Unauthorized (invalid token)
- `404` - Not Found
- `409` - Conflict (e.g., duplicate name)
- `500` - Internal Server Error

### Error Response Format

```json
{
  "error": "Validation failed",
  "details": "Image name is required",
  "request_id": "req-abc-123"
}
```

### Request ID Tracking

Every response includes an `x-request-id` header for debugging:

```bash
curl -v -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments" 2>&1 | grep x-request-id
```

## Rate Limiting

The API does not currently enforce rate limits for operator tokens. However, node registration can be rate-limited via:

```
FLEDX_CP_REGISTRATION_RATE_LIMIT_PER_MINUTE=10
```

## Pagination

List endpoints support pagination:

- `limit` - Items per page (default: 50, max: 100)
- `offset` - Number of items to skip (default: 0)

**Example:**

```bash
# Page 1 (first 50 items)
curl "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments?limit=50&offset=0"

# Page 2 (items 51-100)
curl "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments?limit=50&offset=50"
```

## Best Practices

### 1. Store Tokens Securely

```bash
# Bad - token in command history
curl -H "authorization: Bearer my-secret-token" ...

# Good - use environment variables
export FLEDX_CLI_OPERATOR_TOKEN="$(cat /secure/location/token)"
curl -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" ...
```

### 2. Handle Errors Gracefully

```bash
response=$(curl -s -w "\n%{http_code}" \
  -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
  "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [ "$http_code" -eq 200 ]; then
  echo "Success: $body"
else
  echo "Error ($http_code): $body"
  exit 1
fi
```

### 3. Use Specific Image Tags

```bash
# Bad
"image": "my-app:latest"

# Good
"image": "my-app:v1.2.3"
```

### 4. Monitor Deployment Status

```bash
# Poll until deployment is running
DEPLOYMENT_ID="c2d4e1f5-1b2c-4e5a-8b1f-9b4d1e82964b"
while true; do
  status=$(curl -s -H "authorization: Bearer $FLEDX_CLI_OPERATOR_TOKEN" \
    "$FLEDX_CLI_CONTROL_PLANE_URL/api/v1/deployments/$DEPLOYMENT_ID" | jq -r '.status')

  echo "Status: $status"

  if [ "$status" = "running" ]; then
    echo "Deployment successful!"
    break
  elif [ "$status" = "failed" ]; then
    echo "Deployment failed!"
    exit 1
  fi

  sleep 5
done
```

## Next Steps

- **CLI Alternative:** [CLI Reference](cli.md)
- **Deployment Patterns:** [Deployment Guide](../guides/deployment.md)
- **YAML Deployments:** [YAML Guide](../guides/yaml-deployments.md)
- **Security:** [Security Guide](../guides/security.md)
