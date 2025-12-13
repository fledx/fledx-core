# Day-2 Operations & Monitoring

This guide covers monitoring, backups, maintenance, and troubleshooting for ongoing platform operations.

## Overview

Day-2 operations encompass all activities required to keep Distributed Edge Hosting running smoothly:

- **Health Monitoring** – Track system and deployment health
- **Metrics & Alerting** – Collect metrics and configure alerts
- **Log Management** – Aggregate and analyze logs
- **Backup & Restore** – Protect against data loss
- **Capacity Planning** – Ensure adequate resources
- **Routine Maintenance** – Keep the system healthy

## Health Monitoring

### Control Plane Health

The control plane exposes a health endpoint:

```bash
curl -fsSL http://localhost:8080/health
```

Response format:

```json
{
  "status": "healthy",
  "version": "1.5.0",
  "database": "ok",
  "uptime_seconds": 86400
}
```

**Monitoring frequency:** Check every 30–60 seconds

**Alert on:** Status not "healthy" for >2 minutes

### Node Health

Check node status via CLI:

```bash
# List all nodes
fledx nodes status

# Detailed view
fledx nodes status --wide

# Watch mode
fledx nodes status --watch
```

**Node states:**

- `ready` - Node is healthy and accepting work
- `unreachable` - Node hasn't sent heartbeat (check network/agent)
- `error` - Node reported an error (check agent logs)
- `registering` - Node is in registration process

**Alert on:**

- Node in `unreachable` state for >2× heartbeat interval (default: 60 seconds)
- Node in `error` state

### Deployment Health

Monitor deployment status:

```bash
# List all deployments
fledx deployments status

# Detailed view
fledx deployments status --wide

# Watch specific deployment
fledx deployments watch --id <deployment-id>
```

**Deployment states:**

- `running` - All replicas healthy
- `deploying` - Deployment in progress
- `failed` - Deployment failed (check logs)
- `stopped` - Intentionally stopped
- `pending` - Awaiting scheduling

**Alert on:**

- Deployment in `failed` state
- Deployment stuck in `deploying` for >5 minutes
- Deployment `stopped` unexpectedly

## Metrics & Alerting

### Overview

Distributed Edge Hosting exposes Prometheus-compatible metrics that can be monitored using a complete observability
stack **deployed on Fledx itself**. This section shows how to deploy Prometheus, Grafana, and Loki as Fledx workloads.

### Quick Start: Deploy Complete Monitoring Stack

Deploy the full observability stack in minutes:

```bash
# 1. Deploy Prometheus for metrics
fledx deployments create \
  --name prometheus \
  --image prom/prometheus:latest \
  --port 9090:9090/tcp \
  --volume /var/lib/fledx/volumes/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro

# 2. Deploy Grafana for visualization
fledx deployments create \
  --name grafana \
  --image grafana/grafana:latest \
  --port 3000:3000/tcp

# 3. Deploy Loki for logs (optional)
fledx deployments create \
  --name loki \
  --image grafana/loki:latest \
  --port 3100:3100/tcp

# Verify all deployments
fledx deployments status
```

**Access:**

- Prometheus: `http://<node-ip>:9090`
- Grafana: `http://<node-ip>:3000` (admin/admin)
- Loki: `http://<node-ip>:3100`

See detailed setup instructions below for configuration files and alert rules.

### Metrics Endpoints

**Control Plane Metrics:**

```bash
curl http://localhost:8080/metrics
```

**Node Agent Metrics:**

```bash
curl http://<node-ip>:9091/metrics
```

Both endpoints expose Prometheus-compatible metrics.

### Setting Up Prometheus

#### Prometheus Configuration

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  # Control Plane
  - job_name: 'fledx-control-plane'
    static_configs:
      - targets: [ 'control-plane.example.com:8080' ]
    metrics_path: '/metrics'

  # Node Agents
  - job_name: 'fledx-node-agents'
    static_configs:
      - targets:
          - 'node-1.example.com:9091'
          - 'node-2.example.com:9091'
          - 'node-3.example.com:9091'
    relabel_configs:
      - source_labels: [ __address__ ]
        target_label: instance
```

#### Deploy Prometheus on Fledx

First, prepare the Prometheus configuration on your node:

```bash
# On the node
sudo mkdir -p /var/lib/fledx/volumes/prometheus
sudo tee /var/lib/fledx/volumes/prometheus/prometheus.yml <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  # Control Plane
  - job_name: 'fledx-control-plane'
    static_configs:
      - targets: ['control-plane.example.com:8080']
    metrics_path: '/metrics'

  # Node Agents
  - job_name: 'fledx-node-agents'
    static_configs:
      - targets:
        - 'node-1.example.com:9091'
        - 'node-2.example.com:9091'
        - 'node-3.example.com:9091'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
EOF
```

Deploy Prometheus using Fledx:

```bash
fledx deployments create \
  --name prometheus \
  --image prom/prometheus:latest \
  --port 9090:9090/tcp \
  --volume /var/lib/fledx/volumes/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro

# Verify deployment
fledx deployments status

# Access Prometheus UI
curl http://<node-ip>:9090/targets
```

### Key Metrics to Monitor

#### Control Plane Metrics

- `control_plane_http_requests_total` - Total HTTP requests
- `control_plane_active_deployments` - Number of active deployments
- `control_plane_active_nodes` - Number of connected nodes
- `control_plane_db_queries_duration_seconds` - Database query latency

#### Node Agent Metrics

- `node_agent_heartbeat_success_total` - Successful heartbeats
- `node_agent_heartbeat_failure_total` - Failed heartbeats
- `node_agent_containers_running` - Running containers
- `node_agent_config_fetch_total` - Config fetches
- `node_agent_config_apply_total` - Config applications

### Alert Rules

Create `alert.rules.yml`:

```yaml
groups:
  - name: deh_alerts
    rules:
      # Control plane down
      - alert: ControlPlaneDown
        expr: up{job="fledx-control-plane"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Control plane is down"
          description: "Control plane has been down for more than 2 minutes"

      # Node agent down
      - alert: NodeAgentDown
        expr: up{job="fledx-node-agents"} == 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Node agent {{ $labels.instance }} is down"
          description: "Node agent has been unreachable for more than 1 minute"

      # High error rate
      - alert: HighErrorRate
        expr: |
          rate(control_plane_http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on control plane"
          description: "More than 5% of requests are failing"

      # Database slow
      - alert: DatabaseSlow
        expr: |
          histogram_quantile(0.95, rate(control_plane_db_queries_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database queries are slow"
          description: "95th percentile query time is over 1 second"
```

### Setting Up Grafana

#### Deploy Grafana on Fledx

```bash
fledx deployments create \
  --name grafana \
  --image grafana/grafana:latest \
  --port 3000:3000/tcp

# Verify deployment
fledx deployments status

# Access Grafana UI
# Open browser: http://<node-ip>:3000
```

Default credentials: `admin` / `admin`

#### Add Prometheus Data Source

1. Open Grafana: `http://<node-ip>:3000`
2. Navigate to Configuration → Data Sources
3. Add Prometheus
4. URL: `http://<prometheus-node-ip>:9090`
5. Save & Test

#### Example Dashboard Queries

**Active Deployments:**

```promql
control_plane_active_deployments
```

**Node Health:**

```promql
up{job="fledx-node-agents"}
```

**Request Rate:**

```promql
rate(control_plane_http_requests_total[5m])
```

**Error Rate:**

```promql
rate(control_plane_http_requests_total{status=~"5.."}[5m])
```

**Agent Heartbeat Success Rate:**

```promql
rate(node_agent_heartbeat_success_total[5m]) /
  (rate(node_agent_heartbeat_success_total[5m]) + rate(node_agent_heartbeat_failure_total[5m]))
```

## Log Management

### Accessing Logs

#### Control Plane Logs

```bash
# Real-time
sudo journalctl -u fledx-cp -f

# Last 100 lines
sudo journalctl -u fledx-cp -n 100

# Since timestamp
sudo journalctl -u fledx-cp --since "2024-01-01 00:00:00"

# Errors only
sudo journalctl -u fledx-cp -p err
```

#### Node Agent Logs

```bash
# Real-time
sudo journalctl -u fledx-agent -f

# Last 50 lines
sudo journalctl -u fledx-agent -n 50

# Filter by priority
sudo journalctl -u fledx-agent -p warning
```

#### Deployment Logs

```bash
# Via CLI
fledx deployments logs --resource-type deployment --resource-id <id>

# Follow mode
fledx deployments logs --resource-type deployment --resource-id <id> --follow

# Limit lines
fledx deployments logs --resource-type deployment --resource-id <id> --limit 100
```

### Centralized Logging

#### Using Loki

**Promtail Configuration** (`promtail-config.yml`):

```yaml
server:
  http_listen_port: 9080

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          __path__: /var/log/journal/*.journal
    pipeline_stages:
      - match:
          selector: '{job="varlogs"}'
          stages:
            - regex:
                expression: 'fledx-cp|fledx-agent'
```

**Deploy Loki on Fledx:**

```bash
# Deploy Loki
fledx deployments create \
  --name loki \
  --image grafana/loki:latest \
  --port 3100:3100/tcp

# Verify
fledx deployments status
```

**Deploy Promtail on each node:**

First, prepare the Promtail config on the node:

```bash
# On each node
sudo mkdir -p /var/lib/fledx/volumes/promtail
sudo tee /var/lib/fledx/volumes/promtail/promtail-config.yml <<EOF
server:
  http_listen_port: 9080

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://<loki-node-ip>:3100/loki/api/v1/push

scrape_configs:
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          __path__: /var/log/journal/*.journal
    pipeline_stages:
      - match:
          selector: '{job="varlogs"}'
          stages:
            - regex:
                expression: 'fledx-cp|fledx-agent'
EOF
```

Deploy Promtail:

```bash
fledx deployments create \
  --name promtail \
  --image grafana/promtail:latest \
  --volume /var/log/journal:/var/log/journal:ro \
  --volume /var/lib/fledx/volumes/promtail/promtail-config.yml:/etc/promtail/config.yml:ro \
  --command -config.file=/etc/promtail/config.yml

# Verify
fledx deployments status
```

#### Log Rotation

Configure journald log rotation in `/etc/systemd/journald.conf`:

```ini
[Journal]
SystemMaxUse=1G
SystemMaxFileSize=100M
MaxRetentionSec=7day
```

Apply changes:

```bash
sudo systemctl restart systemd-journald
```

## Backup & Restore

### Control Plane Database Backup

The control plane uses SQLite by default. Regular backups are critical.

#### Automated Backup Script

Create `/usr/local/bin/backup-fledx-db.sh`:

```bash
#!/bin/bash
set -e

BACKUP_DIR="/var/lib/fledx/backups"
DB_PATH="/var/lib/fledx/fledx-cp.db"
DATE=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=7

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop control plane for consistent backup
systemctl stop fledx-cp

# Backup database
cp "$DB_PATH" "$BACKUP_DIR/fledx-cp.db.$DATE"

# Backup WAL if exists
if [ -f "$DB_PATH-wal" ]; then
  cp "$DB_PATH-wal" "$BACKUP_DIR/fledx-cp.db.$DATE-wal"
fi

# Start control plane
systemctl start fledx-cp

# Compress old backups
find "$BACKUP_DIR" -name "fledx-cp.db.*" -mtime +1 -type f ! -name "*.gz" -exec gzip {} \;

# Remove old backups
find "$BACKUP_DIR" -name "fledx-cp.db.*.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_DIR/fledx-cp.db.$DATE"
```

Make executable:

```bash
sudo chmod +x /usr/local/bin/backup-fledx-db.sh
```

#### Schedule with Cron

```bash
# Edit crontab
sudo crontab -e

# Add daily backup at 2 AM
0 2 * * * /usr/local/bin/backup-fledx-db.sh >> /var/log/fledx-backup.log 2>&1
```

#### Online Backup (No Downtime)

For minimal disruption, use SQLite's backup API:

```bash
sqlite3 /var/lib/fledx/fledx-cp.db ".backup /var/lib/fledx/backups/fledx-cp.db.$(date +%Y%m%d-%H%M%S)"
```

### Restore Procedure

```bash
# Stop control plane
sudo systemctl stop fledx-cp

# Restore database
sudo cp /var/lib/fledx/backups/fledx-cp.db.YYYYMMDD-HHMMSS /var/lib/fledx/fledx-cp.db

# Start control plane
sudo systemctl start fledx-cp

# Verify
curl http://localhost:8080/health
fledx nodes status
fledx deployments status
```

### Backup Volume Data

For persistent volumes on nodes:

```bash
# Backup script for node volumes
#!/bin/bash
VOLUME_DIR="/var/lib/fledx/volumes"
BACKUP_DIR="/var/lib/fledx/volume-backups"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/volumes-$DATE.tar.gz" -C "$VOLUME_DIR" .

# Keep last 14 days
find "$BACKUP_DIR" -name "volumes-*.tar.gz" -mtime +14 -delete
```

## Capacity Planning

### Monitor Disk Usage

**Control Plane:**

```bash
# Database size
du -sh /var/lib/fledx/fledx-cp.db

# Total Fledx data
du -sh /var/lib/fledx/

# Available space
df -h /var/lib/fledx/
```

**Node Agents:**

```bash
# Volume data
du -sh /var/lib/fledx/volumes/

# Container images (Docker)
docker system df

# Available space
df -h /var/lib/fledx/
```

### Port Range Management

Check available ports:

```bash
# Current range
grep "PORTS__RANGE" /etc/fledx/fledx-cp.env

# Used ports
fledx deployments status --wide | grep -oP '\d+:\d+' | cut -d: -f1 | sort -n | uniq
```

Adjust if needed:

```bash
# Edit config
sudo vi /etc/fledx/fledx-cp.env

# Update range
FLEDX_CP__PORTS__RANGE_START=8000
FLEDX_CP__PORTS__RANGE_END=9000

# Restart
sudo systemctl restart fledx-cp
```

### Resource Monitoring

Monitor node resources:

```bash
# CPU and memory
top

# Detailed stats
htop

# Container resources
docker stats
```

## Routine Maintenance

### Certificate Management

If using TLS with Let's Encrypt:

```bash
# Check certificate expiry
openssl s_client -connect control-plane.example.com:443 -servername control-plane.example.com < /dev/null 2>/dev/null | openssl x509 -noout -dates

# Renew with certbot
sudo certbot renew

# Reload reverse proxy
sudo systemctl reload nginx
```

### Token Rotation

#### Operator Tokens

```bash
# Generate new token
NEW_TOKEN=$(openssl rand -hex 32)

# Update control plane config
sudo vi /etc/fledx/fledx-cp.env
# Add new token to FLEDX_CP__OPERATOR__TOKENS (comma-separated)

# Restart control plane
sudo systemctl restart fledx-cp

# Update clients to use new token
export FLEDX_OPERATOR_TOKEN=$NEW_TOKEN

# Verify
fledx nodes status

# After verification, remove old token from config
```

#### Node Tokens

```bash
# Revoke old node
fledx node delete --node-id <old-node-id>

# Register new node with new token
fledx nodes register --name <node-name>

# Update node agent config with new credentials
sudo vi /etc/fledx/fledx-agent.env

# Restart agent
sudo systemctl restart fledx-agent
```

### Cleanup Tasks

#### Remove Unused Deployments

```bash
# List stopped deployments
fledx deployments list --status stopped

# Delete
fledx deployments delete --deployment-id <id>
```

#### Prune Docker Images

> **WARNING:** `docker image prune -a` removes ALL unused images, including tagged images not currently in use. This can
> cause deployment delays if images need to be re-downloaded. Use with caution.

On each node:

```bash
# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune
```

#### Clean Old Logs

```bash
# Vacuum journal logs
sudo journalctl --vacuum-time=7d

# Or by size
sudo journalctl --vacuum-size=1G
```

## Troubleshooting

### Node Unreachable

**Symptom:** Node shows as `unreachable` in status.

**Diagnosis:**

```bash
# Check agent logs
sudo journalctl -u fledx-agent -n 50

# Check agent is running
sudo systemctl status fledx-agent

# Test connectivity to control plane
curl -fsSL $CONTROL_PLANE_URL/health
```

**Common Causes:**

- Agent service stopped
- Network connectivity issues
- Invalid node token
- Control plane URL changed

**Solution:**

```bash
# Verify configuration
cat /etc/fledx/fledx-agent.env | grep -E "CONTROL_PLANE_URL|NODE_TOKEN"

# Restart agent
sudo systemctl restart fledx-agent

# Check status
fledx nodes status | grep <node-name>
```

### Deployment Failing

**Symptom:** Deployment stuck in `failed` state.

**Diagnosis:**

```bash
# Check deployment logs
fledx deployments logs --resource-type deployment --resource-id <id>

# Check detailed status
fledx deployments status --id <id> --wide

# Check agent logs
sudo journalctl -u fledx-agent -n 100 | grep <deployment-id>
```

**Common Causes:**

- Image pull failure (registry auth, network)
- Port already in use
- Insufficient resources
- Invalid environment variables

**Solutions:**

```bash
# Image pull issues
docker login <registry>

# Port conflicts
fledx deployments update --id <id> --port <different-port>:80/tcp

# Resource issues
docker stats  # Check available resources
fledx deployments update --id <id> --memory-bytes <higher-value>

# Delete and recreate if needed
fledx deployments delete --id <id>
fledx deployments create --name <name> --image <image> ...
```

### Control Plane Down

**Symptom:** Health endpoint not responding.

**Diagnosis:**

```bash
# Check service status
sudo systemctl status fledx-cp

# Check logs
sudo journalctl -u fledx-cp -n 50

# Check database
ls -lh /var/lib/fledx/fledx-cp.db
```

**Common Causes:**

- Service crashed
- Database corruption
- Port already in use
- Insufficient disk space

**Solutions:**

```bash
# Restart service
sudo systemctl restart fledx-cp

# Check disk space
df -h /var/lib/fledx/

# Restore from backup if DB corrupted
sudo systemctl stop fledx-cp
sudo cp /var/lib/fledx/backups/fledx-cp.db.latest /var/lib/fledx/fledx-cp.db
sudo systemctl start fledx-cp
```

### High Memory Usage

**Symptom:** Control plane or agents consuming excessive memory.

**Diagnosis:**

```bash
# Check process memory
ps aux | grep -E 'fledx-cp|fledx-agent'

# System memory
free -h

# Container memory
docker stats
```

**Solutions:**

```bash
# Restart control plane
sudo systemctl restart fledx-cp

# Restart agent
sudo systemctl restart fledx-agent

# Reduce deployment replicas if needed
fledx deployments update --id <id> --replicas 1

# Add resource limits to systemd service
sudo vi /etc/systemd/system/fledx-cp.service
# Add: MemoryLimit=2G
sudo systemctl daemon-reload
sudo systemctl restart fledx-cp
```

### Database Growing Large

**Symptom:** SQLite database file size increasing rapidly.

**Diagnosis:**

```bash
# Check database size
du -sh /var/lib/fledx/fledx-cp.db

# Check WAL size
du -sh /var/lib/fledx/fledx-cp.db-wal
```

**Solutions:**

```bash
# Vacuum database (compact)
sqlite3 /var/lib/fledx/fledx-cp.db "VACUUM;"

# Check for audit log growth
sqlite3 /var/lib/fledx/fledx-cp.db "SELECT COUNT(*) FROM audit_logs;"

# Implement log retention policy (if available)
# Or periodically clean old logs
```

### Agent Not Connecting

**Symptom:** Node agent fails to connect to control plane after registration.

**Diagnosis:**

```bash
# Check agent logs for connection errors
sudo journalctl -u fledx-agent -n 100 | grep -i "error\|failed"

# Verify node credentials
cat /etc/fledx/fledx-agent.env | grep -E "NODE_ID|NODE_TOKEN"

# Test control plane reachability
curl -fsSL $FLEDX_AGENT__CONTROL_PLANE_URL/health

# Check TLS/certificate issues
openssl s_client -connect control-plane.example.com:443 -showcerts
```

**Common Causes:**

- Incorrect `FLEDX_AGENT__CONTROL_PLANE_URL` (typo, wrong protocol)
- Invalid or expired node token
- TLS certificate issues (self-signed, expired)
- Firewall blocking outbound connections
- Control plane not running or unreachable

**Solutions:**

```bash
# Fix control plane URL
sudo vi /etc/fledx/fledx-agent.env
# Set: FLEDX_AGENT__CONTROL_PLANE_URL=https://correct-hostname.example.com

# Regenerate node token if invalid
fledx nodes token rotate --node-id <node-id>
# Update /etc/fledx/fledx-agent.env with new token

# For labs: temporarily disable TLS verification
sudo vi /etc/fledx/fledx-agent.env
# Add: FLEDX_AGENT__TLS_INSECURE_SKIP_VERIFY=true
# WARNING: Never use in production!

# Restart agent
sudo systemctl restart fledx-agent

# Verify connection
fledx nodes status | grep <node-name>
```

### Out of Disk Space

**Symptom:** Deployments failing, containers not starting, or agent crashes.

**Diagnosis:**

```bash
# Check disk space on all partitions
df -h

# Check Docker space usage
docker system df

# Check specific directories
du -sh /var/lib/fledx/*
du -sh /var/lib/docker/*

# Check inode usage (can be exhausted even with free space)
df -i
```

**Common Causes:**

- Docker images accumulating
- Container logs growing unbounded
- Large volume mounts
- Database and audit logs growing
- Many stopped containers

**Solutions:**

```bash
# Clean Docker images and containers
docker system prune -a -f
docker volume prune -f

# Limit container log size (add to daemon.json)
sudo vi /etc/docker/daemon.json
# Add:
# {
#   "log-driver": "json-file",
#   "log-opts": {
#     "max-size": "10m",
#     "max-file": "3"
#   }
# }
sudo systemctl restart docker

# Clean journald logs
sudo journalctl --vacuum-size=500M

# Vacuum database
sqlite3 /var/lib/fledx/fledx-cp.db "VACUUM;"

# Move volumes to larger partition if needed
sudo systemctl stop fledx-agent
sudo mv /var/lib/fledx/volumes /mnt/large-disk/fledx-volumes
sudo ln -s /mnt/large-disk/fledx-volumes /var/lib/fledx/volumes
sudo systemctl start fledx-agent
```

### Registry Authentication Failed

**Symptom:** Deployment fails with "image pull failed" or "unauthorized" errors.

**Diagnosis:**

```bash
# Check deployment logs
fledx deployments logs --resource-type deployment --resource-id <id>

# Check agent logs for registry errors
sudo journalctl -u fledx-agent -n 50 | grep -i "pull\|registry\|auth"

# Test Docker registry login on the node
docker login registry.example.com

# Try pulling the image manually
docker pull registry.example.com/my-app:v1.0
```

**Common Causes:**

- No Docker registry credentials configured
- Expired registry credentials
- Private registry requires authentication
- Network connectivity to registry
- Image name or tag incorrect

**Solutions:**

```bash
# Configure Docker registry credentials on the node
docker login registry.example.com
# Enter username and password when prompted

# Verify credentials are saved
cat ~/.docker/config.json

# For systemd service, copy credentials to service user
sudo mkdir -p /home/fledx/.docker
sudo cp ~/.docker/config.json /home/fledx/.docker/
sudo chown -R fledx:fledx /home/fledx/.docker

# Restart node agent to pick up credentials
sudo systemctl restart fledx-agent

# Retry deployment
fledx deployments update --id <id> --image registry.example.com/my-app:v1.0

# For public images, verify image name spelling
# docker.io/nginx:alpine (not just nginx:alpine for some configs)
```

## Performance Tuning

### Control Plane

```bash
# Increase connection pool (if needed)
FLEDX_CP__DATABASE__MAX_CONNECTIONS=20

# Adjust reconciliation interval
FLEDX_CP__RECONCILE_INTERVAL_SECS=30
```

### Node Agent

```bash
# Adjust heartbeat interval
FLEDX_AGENT__HEARTBEAT_INTERVAL_SECS=30

# Adjust reconcile interval
FLEDX_AGENT__RECONCILE_INTERVAL_SECS=10
```

## Monitoring Checklist

Daily:

- [ ] Check node status (`fledx nodes status`)
- [ ] Check deployment health (`fledx deployments status`)
- [ ] Review error logs
- [ ] Verify backups completed

Weekly:

- [ ] Review metrics and trends in Grafana
- [ ] Check disk usage on all hosts
- [ ] Review and clean up unused deployments
- [ ] Test restore from backup

Monthly:

- [ ] Rotate tokens
- [ ] Review and update alert rules
- [ ] Test disaster recovery procedures
- [ ] Update documentation

## Next Steps

- **Upgrades:** [Upgrade Guide](upgrades.md)
- **Security:** [Security Guide](security.md)
- **Configuration:** [Configuration Guide](configuration.md)
- **Backups:** See backup procedures above
