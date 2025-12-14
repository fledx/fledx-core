# Frequently Asked Questions

## Hardware

### What hardware is supported?

Distributed Edge Hosting supports x86_64 and ARM64 architectures on Linux systems. The control plane and node agents can
run on:

- Physical servers
- Virtual machines
- Raspberry Pi (ARM64)
- Edge devices with Linux

See the [Requirements Guide](getting-started/requirements.md) for detailed hardware specifications.

## Security

### How is security handled?

Security is managed through:

- **Operator Tokens** - Bearer tokens for CLI/UI/API authentication
- **Registration Tokens** - Secrets for enrolling new nodes
- **Node Tokens** - Per-node authentication tokens
- **TLS** - Required for production deployments (via reverse proxy)

See the [Security Guide](guides/security.md) for complete details.

## Node Management

### How do I add nodes?

Register a node with the control plane:

```bash
fledx nodes register --name my-node
```

Then configure and start the node agent with the returned credentials.
See [Installation Guide](guides/installation.md#node-agent-per-node) for details.

### How do I remove nodes?

Stop the node agent and delete the node from the control plane:

```bash
sudo systemctl stop fledx-agent
fledx node delete --node-id <node-id>
```

## Upgrades

### How do upgrades work?

Upgrades are performed by replacing binaries and restarting services:

1. Download new release binaries
2. Stop the service (control-plane or node-agent)
3. Replace the binary
4. Start the service

See the [Upgrade Guide](guides/upgrades.md) for detailed procedures.

## Monitoring

### Where do I find logs and metrics?

- **Control Plane Logs:** `sudo journalctl -u fledx-cp -f`
- **Node Agent Logs:** `sudo journalctl -u fledx-agent -f`
- **Metrics Endpoint:** `http://<control-plane>:8080/metrics` (Prometheus format)
- **Deployment Logs:** `fledx deployments logs --resource-type deployment --resource-id <id>`

See the [Monitoring Guide](guides/monitoring.md) for more information.

## Performance & Scaling

### How many nodes can one control plane handle?

The control plane is designed to handle dozens to hundreds of nodes, depending on:

- **Hardware resources** - More CPU/RAM allows more concurrent operations
- **Deployment frequency** - Higher churn requires more resources
- **Reconciliation interval** - Longer intervals reduce load
- **Database performance** - SQLite is suitable for small-to-medium deployments

For large-scale deployments (>100 nodes), consider:
- Using more powerful hardware for the control plane
- Increasing reconciliation intervals
- Monitoring database performance
- Planning for future horizontal scaling features

### What are the resource requirements for deployments?

Resource usage depends on your workloads:

- **Minimum per node:** 1 CPU core, 1 GB RAM (for agent + lightweight containers)
- **Recommended per node:** 2+ CPU cores, 2+ GB RAM
- **Container overhead:** Docker adds ~100-200 MB per container

The node agent itself is lightweight (<50 MB RAM), but your deployed containers determine actual resource needs.

See [Requirements Guide](getting-started/requirements.md) for detailed specifications.

### Can I limit resources for deployments?

Currently, resource limits are not directly enforced by Fledx. However, you can:

- Use Docker's resource constraints via Docker daemon configuration
- Deploy on nodes with appropriate hardware for expected workloads
- Monitor resource usage via `docker stats` and Prometheus metrics
- Implement placement constraints to spread resource-intensive workloads

Future versions may include built-in resource limit enforcement.

## Compatibility

### What Docker versions are supported?

Fledx requires Docker Engine 20.10 or newer. Tested versions:

- Docker Engine 20.10.x
- Docker Engine 23.x
- Docker Engine 24.x
- Docker Engine 25.x

The node agent uses the Docker API and should work with any recent Docker version.

### Can I use Podman instead of Docker?

Currently, Fledx is designed for Docker Engine. Podman support is not officially tested, but may work with Docker compatibility mode enabled.

For Podman:
- Enable Docker-compatible API: `systemctl enable --now podman.socket`
- Set Docker socket path: `DOCKER_HOST=unix:///run/podman/podman.sock`
- Test thoroughly before production use

Official Podman support may be added in future releases.

### What container registries are supported?

Fledx supports any Docker-compatible container registry:

- **Docker Hub** - `docker.io/nginx:alpine`
- **GitHub Container Registry** - `ghcr.io/org/image:tag`
- **GitLab Container Registry** - `registry.gitlab.com/org/project:tag`
- **Private registries** - `registry.example.com/image:tag`
- **Harbor, Quay, etc.** - Any Docker V2 API compatible registry

Authentication is handled via Docker login on each node. See [Troubleshooting](guides/monitoring.md#registry-authentication-failed) for setup instructions.

### Can I mix x86_64 and ARM64 nodes?

Yes, you can have heterogeneous architectures in the same deployment. However:

- **Container images must support target architecture** - Use multi-arch images
- **No automatic architecture matching** - You must manually ensure compatibility
- **Use placement constraints** - Target specific nodes for architecture-specific images

Example multi-arch image: `nginx:alpine` (supports both x86_64 and ARM64)

Example architecture-specific deployment:
```bash
fledx deployments create --name arm-app --image arm64v8/nginx:alpine --node-label arch=arm64
```

## Troubleshooting

### Why is my deployment stuck in "deploying" state?

Common causes:

1. **Image pull issues** - Check `fledx deployments logs --resource-type deployment --resource-id <id>`
2. **Port conflicts** - Another container is using the same host port
3. **Resource exhaustion** - Node is out of memory or disk space
4. **Health check failing** - Container starts but health check fails repeatedly

See [Troubleshooting Guide](guides/monitoring.md#troubleshooting) for detailed diagnosis steps.

### How do I debug network connectivity issues?

```bash
# Test control plane reachability from node
curl -fsSL $CONTROL_PLANE_URL/health

# Check node agent logs for connection errors
sudo journalctl -u fledx-agent -n 50 | grep -i error

# Verify DNS resolution
nslookup control-plane.example.com

# Check firewall rules
sudo iptables -L -n | grep <port>

# Test TLS certificate
openssl s_client -connect control-plane.example.com:443 -showcerts
```

### What happens if the control plane goes down?

- **Running deployments continue** - Existing containers keep running
- **No new deployments** - Cannot create or update deployments
- **Health checks continue** - Node agents continue monitoring locally
- **No state changes** - Agents wait for control plane to return

When the control plane comes back online:
- Agents reconnect automatically
- State is reconciled from the database
- Pending operations resume

For high availability, plan regular backups and have a recovery procedure ready. See [Monitoring Guide](guides/monitoring.md#automated-backups) for backup strategies.

### How do I recover from a corrupted database?

```bash
# Stop control plane
sudo systemctl stop fledx-cp

# Restore from latest backup
sudo cp /var/lib/fledx/backups/fledx-cp.db.latest /var/lib/fledx/fledx-cp.db

# Verify database integrity
sqlite3 /var/lib/fledx/fledx-cp.db "PRAGMA integrity_check;"

# Start control plane
sudo systemctl start fledx-cp

# Verify health
curl http://localhost:8080/health
```

Always maintain regular automated backups. See [Monitoring Guide](guides/monitoring.md#automated-backups) for setup.

## Development & Integration

### Can I use Fledx with CI/CD pipelines?

Yes! Fledx's CLI and API are designed for automation:

```bash
# Example CI/CD deployment script
deploy:
  script:
    - export FLEDX_CLI_CONTROL_PLANE_URL=$FLEDX_URL
    - export FLEDX_CLI_OPERATOR_TOKEN=$FLEDX_TOKEN
    - fledx deployments create --name my-app --image registry.example.com/my-app:$VERSION_TAG
```

Fledx integrates with any CI/CD platform that can execute shell commands or make HTTP API calls.

See [Deployment Guide](guides/deployment.md) and [API Reference](reference/api.md) for integration examples.

### Is there a Terraform provider?

Not currently. Fledx can be managed via:

- **CLI** - Scriptable command-line interface
- **REST API** - Direct API calls from Terraform's `http` provider
- **YAML deployments** - Declarative specifications

A dedicated Terraform provider may be developed in the future based on community interest.

### Can I integrate with Kubernetes?

Fledx is an alternative to Kubernetes for edge/distributed scenarios. It does not integrate with Kubernetes clusters.

However, you can:
- Run Fledx and Kubernetes in parallel (different workloads)
- Use Fledx for edge nodes, K8s for datacenter
- Migrate from K8s to Fledx (or vice versa) using container images

## Support

### Where can I get help?

- **Documentation** - Start with the [Getting Started Guide](getting-started/index.md)
- **Troubleshooting** - Check [Monitoring Guide](guides/monitoring.md#troubleshooting)
- **Issues** - Report bugs or request features via your support channel

### How do I report a bug?

When reporting bugs, include:

1. **Version information** - `fledx-cp --version` and `fledx-agent --version`
2. **Logs** - Relevant logs from control plane and node agent
3. **Steps to reproduce** - Clear reproduction steps
4. **Environment details** - OS, Docker version, hardware specs
5. **Expected vs actual behavior** - What you expected and what happened

### Where can I find information about upcoming features?

For information about upcoming features and improvements, please refer to:

- [Releases Documentation](releases/index.md) - Current and recent releases
- Official release announcements from your distribution channel
- Contact your support channel for feature requests and feedback

