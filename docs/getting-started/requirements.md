# Requirements

This page lists the system requirements and prerequisites for running Distributed Edge Hosting.

## Control Plane Requirements

### Hardware

- **CPU:** 2+ cores recommended
- **Memory:** 2 GB RAM minimum, 4 GB recommended
- **Storage:** 10 GB for SQLite database and logs
- **Network:** Stable internet connection with public IP or reverse proxy

### Software

- **Operating System:** Linux (systemd recommended) or macOS
- **Architecture:** x86_64 or ARM64
- **Network Access:** Ability to accept inbound HTTPS connections

### Ports

- **8080** (HTTP) or **8443** (HTTPS) for API, UI, and agent communication
- Configurable via `FLEDX_CP__SERVER__PORT`

## Node Agent Requirements

### Hardware

- **CPU:** 1+ cores (varies by workload)
- **Memory:** 1 GB RAM minimum (varies by workload)
- **Storage:** 5 GB+ for Docker images and container data
- **Network:** Outbound HTTPS access to control plane

### Software

- **Operating System:** Linux (systemd recommended)
- **Architecture:** x86_64 or ARM64 (including Raspberry Pi)
- **Docker:** Docker Engine 20.10 or newer
- **Network Access:** Outbound HTTPS to control plane required

### Docker Setup

Verify Docker is installed and running:

```bash
docker --version
docker ps
```

If Docker is not installed, follow the [official Docker installation guide](https://docs.docker.com/engine/install/).

## Operator Workstation Requirements

### CLI Tool

- **Operating System:** Linux, macOS, or Windows
- **Architecture:** x86_64 or ARM64
- **Network Access:** HTTPS access to control plane

### Web UI

- **Browser:** Modern web browser (Chrome, Firefox, Safari, Edge)
- **Network Access:** HTTPS access to control plane

## Network Requirements

### Connectivity

- **Control Plane → Internet:** Optional (only if pulling public container images)
- **Node Agents → Control Plane:** Required (HTTPS outbound)
- **Operator → Control Plane:** Required (HTTPS)
- **Users → Workloads:** Required (HTTP/HTTPS to node public IPs/ports)

### Firewall Rules

- **Control Plane:** Allow inbound on port 8080 (HTTP) or 8443 (HTTPS)
- **Node Agents:** Allow outbound HTTPS to control plane
- **Workloads:** Allow inbound on assigned ports (configurable per deployment)

### TLS/HTTPS

- **Production:** TLS termination via reverse proxy (nginx, Caddy, Traefik) required
- **Development:** Insecure HTTP mode available with `FLEDX_AGENT__ALLOW_INSECURE_HTTP=true`

## Security Requirements

### Tokens & Secrets

You will need to generate and securely store:

- **Registration Token:** Used to register new nodes
- **Operator Token(s):** Used for CLI/UI/API authentication
- **Token Pepper:** Used for cryptographic operations
- **Node Tokens:** Generated per node during registration

### Best Practices

- Use strong, randomly generated tokens (32+ characters)
- Store tokens securely (environment variables, secret managers)
- Rotate tokens periodically
- Use HTTPS in production
- Limit operator token distribution

## Container Registry Access

### Public Registries

- Internet access required to pull from Docker Hub, GitHub Container Registry, etc.

### Private Registries

- Nodes must have network access to your private registry
- Authentication via Docker login on each node

## Optional Components

### Monitoring & Observability

- **Prometheus:** For metrics collection (optional)
- **Log Aggregation:** For centralized logging (optional)

### Reverse Proxy

- **nginx, Caddy, or Traefik:** For TLS termination (recommended for production)

## Quick Compatibility Check

Run this on your control plane host:

```bash
# Check OS
uname -a

# Check architecture
uname -m

# Check available disk space
df -h
```

Run this on your node agent hosts:

```bash
# Check Docker
docker --version
docker info

# Check connectivity to control plane (replace with your URL)
curl -fsSL https://your-control-plane.example.com/health
```

## Next Steps

- **Quickstart:** [Getting Started Guide](index.md)
- **Production Install:** [Installation Guide](../guides/installation.md)
- **Security Setup:** [Security Guide](../guides/security.md)
