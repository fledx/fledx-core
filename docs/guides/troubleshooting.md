# Troubleshooting Guide

This guide provides solutions to common problems encountered when running Distributed Edge Hosting.

## Quick Diagnosis

### System Health Checklist

Run these commands to get a quick overview of system health:

```bash
# 1. Control plane health
curl -fsSL $FLEDX_CONTROL_PLANE_URL/health

# 2. Node status
fledx nodes status --wide

# 3. Deployment status
fledx deployments status --wide

# 4. Recent logs
fledx audit-logs --limit 20
```

### Common Issues by Symptom

| Symptom                         | Likely Cause                                | Jump To                                         |
|---------------------------------|---------------------------------------------|-------------------------------------------------|
| Deployment stuck in "deploying" | Image pull failure, port conflict           | [Deployment Issues](#deployment-issues)         |
| Node shows "unreachable"        | Network connectivity, agent not running     | [Node Issues](#node-connectivity-issues)        |
| Cannot access deployed service  | Firewall, wrong port, container not started | [Network Issues](#network-connectivity-issues)  |
| Control plane not responding    | Service down, database locked               | [Control Plane Issues](#control-plane-issues)   |
| Authentication failures         | Wrong token, token not configured           | [Authentication Issues](#authentication-issues) |

## Deployment Issues

### Deployment Stuck in "Deploying" State

**Symptoms:**

```bash
$ fledx deployments status
STATUS: deploying (for >5 minutes)
```

**Common causes & solutions:**

#### 1. Image Pull Failure

**Diagnose:**

```bash
# Check deployment logs
fledx deployments logs --resource-type deployment --resource-id <id> --limit 50

# Check node agent logs
ssh <node-host>
sudo journalctl -u fledx-agent -n 100 | grep -i "pull\|image"
```

**Solution A - Authentication:**

```bash
# On the node, log into the registry
ssh <node-host>
docker login registry.example.com
# Enter credentials

# Restart agent to retry
sudo systemctl restart fledx-agent
```

**Solution B - Image doesn't exist:**

```bash
# Verify image exists
docker pull my-app:v1.0

# If it doesn't exist, fix the image name
fledx deployments update --id <deployment-id> --image my-app:v1.0-correct
```

#### 2. Port Conflict

**Diagnose:**

```bash
# Check if port is already in use on the node
ssh <node-host>
sudo netstat -tlnp | grep :8080
```

**Solution:**

```bash
# Use a different port
fledx deployments update --id <deployment-id> --port 8081:3000/tcp

# Or stop the conflicting service
ssh <node-host>
sudo docker stop <conflicting-container-id>
```

#### 3. Resource Exhaustion

**Diagnose:**

```bash
# Check node resources
ssh <node-host>
df -h                  # Disk space
free -h                # Memory
docker system df       # Docker disk usage
```

**Solution:**

```bash
# Free up disk space
ssh <node-host>
docker system prune -a --volumes

# Or deploy to a different node
fledx deployments update --id <deployment-id> --node-affinity site=other-location
```

#### 4. Container Exits Immediately

**Diagnose:**

```bash
# View container logs
fledx deployments logs --resource-type deployment --resource-id <id> --limit 100

# Check Docker logs on node
ssh <node-host>
sudo docker ps -a | grep my-app
sudo docker logs <container-id>
```

**Solution:**

Fix the application issue causing the exit. Common problems:

- Missing environment variables
- Configuration errors
- Incorrect command/entrypoint

```bash
# Add missing environment variables
fledx deployments update --id <deployment-id> --env DATABASE_URL=postgres://...
```

### Deployment Failed State

**Symptoms:**

```bash
$ fledx deployments status
STATUS: failed
```

**Solution:**

```bash
# 1. Check what went wrong
fledx deployments logs --resource-type deployment --resource-id <id>

# 2. Fix the issue (e.g., correct image, add env vars)
fledx deployments update --id <deployment-id> --image correct-image:v1.0

# 3. If updates don't work, delete and recreate
fledx deployments delete --id <deployment-id>
fledx deployments create --name my-app --image my-app:v1.0 ...
```

### Container Keeps Restarting

**Diagnose:**

```bash
# Check restart count
fledx deployments status --wide

# View logs for crash details
fledx deployments logs --resource-type deployment --resource-id <id> --limit 200
```

**Common causes:**

1. **Application crash** - Fix the application bug
2. **Health check failure** - Adjust health check settings
3. **Resource limits too low** - Increase memory/CPU limits

```bash
# Increase resources
fledx deployments update \
  --name my-app \
  --cpu-millis 2000 \
  --memory-bytes 2147483648  # 2GB
```

## Node Connectivity Issues

### Node Shows "Unreachable"

**Symptoms:**

```bash
$ fledx nodes status
ID                    NAME      STATUS
abc123...             edge-1    unreachable
```

**Diagnose:**

```bash
# 1. Check if node agent is running
ssh <node-host>
sudo systemctl status fledx-agent

# 2. Check agent logs
sudo journalctl -u fledx-agent -n 50 -f

# 3. Test connectivity to control plane
curl -fsSL $FLEDX_CONTROL_PLANE_URL/health
```

**Solution A - Agent not running:**

```bash
ssh <node-host>
sudo systemctl start fledx-agent
sudo systemctl status fledx-agent
```

**Solution B - Network connectivity:**

```bash
# Check DNS resolution
nslookup control-plane.example.com

# Check firewall
sudo iptables -L -n | grep 443

# Test HTTPS connection
curl -v https://control-plane.example.com/health
```

**Solution C - Authentication failure:**

```bash
# Check agent logs for auth errors
sudo journalctl -u fledx-agent -n 100 | grep -i "auth\|token\|401"

# Verify node token is correct
cat /etc/fledx/fledx-agent.env | grep NODE_TOKEN

# If wrong, get new token by re-registering
# (See Node Management section)
```

### Node in "Error" State

**Diagnose:**

```bash
# Check agent logs
ssh <node-host>
sudo journalctl -u fledx-agent -n 100

# Check Docker daemon
sudo systemctl status docker
```

**Solution:**

```bash
# Restart Docker if needed
sudo systemctl restart docker

# Restart agent
sudo systemctl restart fledx-agent

# Verify
fledx nodes status
```

### Node Not Receiving Deployments

**Diagnose:**

```bash
# Check node labels vs deployment requirements
fledx nodes status --wide
fledx deployments status --wide

# Check node capacity
fledx nodes status --wide  # Look at capacity column
```

**Solution:**

```bash
# If labels don't match, add required labels
fledx node update --node-id <id> --label region=us-east

# If node is at capacity, scale down or add nodes
fledx deployments update --id <other-deployment-id> --replicas 1  # Free up resources
```

## Network Connectivity Issues

### Cannot Access Deployed Service

**Symptoms:**

```bash
$ curl http://<node-ip>:8080
Connection refused
```

**Diagnose:**

```bash
# 1. Verify deployment is running
fledx deployments status

# 2. Verify port mapping
fledx deployments status --wide  # Check PORTS column

# 3. Check if port is listening
ssh <node-host>
sudo netstat -tlnp | grep 8080

# 4. Check container status
ssh <node-host>
sudo docker ps | grep my-app
```

**Solution A - Wrong node or port:**

```bash
# Get correct node and port
fledx deployments status --wide
fledx nodes status --wide

# Use correct address
curl http://<correct-node-ip>:<correct-port>
```

**Solution B - Firewall blocking:**

```bash
# Check firewall rules
ssh <node-host>
sudo iptables -L -n | grep 8080

# Allow port if needed
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Or disable firewall temporarily for testing
sudo systemctl stop firewalld  # RHEL/CentOS
sudo ufw disable              # Ubuntu
```

**Solution C - Container not healthy:**

```bash
# Check container logs
fledx deployments logs --resource-type deployment --resource-id <id>

# Restart deployment
fledx deployments stop --id <deployment-id>
fledx deployments update --id <deployment-id> --desired-state running
```

### Intermittent Connectivity

**Symptoms:**

Requests sometimes succeed, sometimes fail.

**Diagnose:**

```bash
# Test multiple times
for i in {1..10}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://<node-ip>:8080
  sleep 1
done

# Check if multiple replicas are deployed
fledx deployments status --wide
```

**Solution:**

Could be:

1. **Load balancing issue** - If using external LB, check LB health
2. **Container restarting** - Fix application stability
3. **Network flapping** - Check node network stability

```bash
# Check restart count
fledx deployments status --wide

# View agent logs
ssh <node-host>
sudo journalctl -u fledx-agent -f
```

## Control Plane Issues

### Control Plane Not Responding

**Symptoms:**

```bash
$ curl $FLEDX_CONTROL_PLANE_URL/health
Connection refused
```

**Diagnose:**

```bash
# Check if service is running
ssh <control-plane-host>
sudo systemctl status fledx-cp

# Check logs
sudo journalctl -u fledx-cp -n 50 -f

# Check port is listening
sudo netstat -tlnp | grep 8080
```

**Solution:**

```bash
# Start control plane if stopped
sudo systemctl start fledx-cp

# Check for errors in logs
sudo journalctl -u fledx-cp -n 200 | grep -i error

# Verify configuration
cat /etc/fledx/fledx-cp.env
```

### Database Locked/Corrupted

**Symptoms:**

```bash
# Control plane logs show database errors
sudo journalctl -u fledx-cp | grep -i "database\|sqlite"
```

**Diagnose:**

```bash
# Check database integrity
sqlite3 /var/lib/fledx/fledx-cp.db "PRAGMA integrity_check;"

# Check disk space
df -h /var/lib/fledx
```

**Solution:**

```bash
# Stop control plane
sudo systemctl stop fledx-cp

# Restore from backup
sudo cp /var/lib/fledx/backups/fledx-cp.db.latest /var/lib/fledx/fledx-cp.db

# Verify integrity
sqlite3 /var/lib/fledx/fledx-cp.db "PRAGMA integrity_check;"

# Start control plane
sudo systemctl start fledx-cp
sudo systemctl status fledx-cp
```

### High CPU/Memory Usage

**Diagnose:**

```bash
# Check resource usage
ssh <control-plane-host>
top -p $(pgrep fledx-cp)

# Check number of nodes and deployments
fledx nodes status | wc -l
fledx deployments status | wc -l
```

**Solution:**

```bash
# Increase reconciliation interval (reduces CPU)
# Edit /etc/fledx/fledx-cp.env
FLEDX_CP__RECONCILIATION__INTERVAL_SECONDS=60

# Restart control plane
sudo systemctl restart fledx-cp

# Consider upgrading hardware if managing many nodes
```

## Authentication Issues

### "401 Unauthorized" Errors

**Symptoms:**

```bash
$ fledx nodes status
Error: 401 Unauthorized
```

**Solution:**

```bash
# 1. Verify token is set
echo $FLEDX_OPERATOR_TOKEN

# 2. Verify token is correct (check control plane config)
ssh <control-plane-host>
cat /etc/fledx/fledx-cp.env | grep OPERATOR__TOKENS

# 3. Set correct token
export FLEDX_OPERATOR_TOKEN=correct-token-here

# 4. Test
fledx nodes status
```

### Node Registration Fails

**Symptoms:**

```bash
$ fledx nodes register --name edge-1
Error: Registration failed: invalid token
```

**Solution:**

```bash
# 1. Verify registration token
ssh <control-plane-host>
cat /etc/fledx/fledx-cp.env | grep REGISTRATION__TOKEN

# 2. Use correct token
export FLEDX_REGISTRATION_TOKEN=correct-registration-token

# 3. Retry registration
fledx nodes register --name edge-1
```

### Node Token Invalid/Expired

**Symptoms:**

Node agent logs show authentication errors:

```bash
sudo journalctl -u fledx-agent | grep "401\|auth"
```

**Solution:**

```bash
# Rotate node token
fledx node-token-rotate --node-id <node-id>

# Update agent configuration with new token
ssh <node-host>
sudo nano /etc/fledx/fledx-agent.env
# Update FLEDX_AGENT__NODE_TOKEN

# Restart agent
sudo systemctl restart fledx-agent
```

## Performance Issues

### Slow Deployment Times

**Symptoms:**

Deployments take >5 minutes to become "running".

**Diagnose:**

```bash
# Check where time is spent
fledx deployments watch --id <deployment-id> --follow-logs

# Common bottlenecks:
# - Image pull (large images)
# - Container startup (slow application)
# - Node resource constraints
```

**Solution:**

```bash
# Use smaller images
# Before: FROM ubuntu:latest (72MB)
# After:  FROM alpine:latest (5MB)

# Use image caching
# Pre-pull images on nodes:
ssh <node-host>
docker pull my-app:v1.0

# Increase node resources (CPU/RAM)
```

### High Memory Usage on Nodes

**Diagnose:**

```bash
ssh <node-host>
free -h
docker stats --no-stream

# Check for memory leaks in containers
watch -n 5 'docker stats --no-stream'
```

**Solution:**

```bash
# Set memory limits on deployments
fledx deployments update \
  --name my-app \
  --memory-bytes 1073741824  # 1GB limit

# Restart leaking containers
fledx deployments stop --id <deployment-id>
fledx deployments update --id <deployment-id> --desired-state running

# Clean up unused Docker resources
ssh <node-host>
docker system prune -a
```

## Data & State Issues

### Lost Deployment Configuration

**Symptoms:**

Deployment exists but configuration is wrong after control plane restart.

**Solution:**

```bash
# Check database backup exists
ssh <control-plane-host>
ls -lh /var/lib/fledx/backups/

# If needed, restore from backup
sudo systemctl stop fledx-cp
sudo cp /var/lib/fledx/backups/fledx-cp.db.latest /var/lib/fledx/fledx-cp.db
sudo systemctl start fledx-cp

# Verify deployments
fledx deployments status --wide
```

### Volume Data Lost

**Symptoms:**

Container data disappeared after restart.

**Diagnose:**

```bash
# Check volume mount
fledx deployments status --wide  # Check if volumes are configured

# Check volume path on node
ssh <node-host>
ls -lh /var/lib/fledx/volumes/my-app-data
```

**Solution:**

Volumes must be explicitly configured:

```bash
# Add volume to deployment
fledx deployments update \
  --name my-app \
  --volume /var/lib/fledx/volumes/my-app-data:/data

# Verify volume is mounted
ssh <node-host>
docker inspect <container-id> | grep -A 5 Mounts
```

## Upgrade Issues

### Control Plane Won't Start After Upgrade

**Solution:**

```bash
# Check logs for migration errors
sudo journalctl -u fledx-cp -n 100

# Rollback if needed
sudo systemctl stop fledx-cp
sudo cp /usr/local/bin/fledx-cp.backup /usr/local/bin/fledx-cp
sudo systemctl start fledx-cp

# Check health
curl http://localhost:8080/health
```

### Node Agent Incompatible Version

**Symptoms:**

```bash
# Agent logs show version mismatch
sudo journalctl -u fledx-agent | grep version
```

**Solution:**

```bash
# Upgrade node agent to match control plane version
ssh <node-host>
sudo systemctl stop fledx-agent
sudo cp fledx-agent-new /usr/local/bin/fledx-agent
sudo systemctl start fledx-agent
```

## Getting Help

### Collecting Diagnostic Information

When reporting issues, collect this information:

```bash
#!/bin/bash
# Save as: collect-diagnostics.sh

echo "=== System Info ===" > diagnostics.txt
uname -a >> diagnostics.txt
echo >> diagnostics.txt

echo "=== Control Plane Health ===" >> diagnostics.txt
curl -fsSL $FLEDX_CONTROL_PLANE_URL/health >> diagnostics.txt 2>&1
echo >> diagnostics.txt

echo "=== Nodes ===" >> diagnostics.txt
fledx nodes status --wide >> diagnostics.txt 2>&1
echo >> diagnostics.txt

echo "=== Deployments ===" >> diagnostics.txt
fledx deployments status --wide >> diagnostics.txt 2>&1
echo >> diagnostics.txt

echo "=== Control Plane Logs ===" >> diagnostics.txt
ssh control-plane-host "sudo journalctl -u fledx-cp -n 100" >> diagnostics.txt 2>&1
echo >> diagnostics.txt

echo "=== Node Agent Logs ===" >> diagnostics.txt
ssh node-host "sudo journalctl -u fledx-agent -n 100" >> diagnostics.txt 2>&1

echo "Diagnostics saved to diagnostics.txt"
```

### Where to Get Help

- **Documentation:** Review the [Monitoring Guide](monitoring.md) and [FAQ](../faq.md)
- **Logs:** Always check control plane and node agent logs first
- **Community:** Check your support channel for assistance

## Quick Reference

### Essential Commands

```bash
# Health check
curl $FLEDX_CONTROL_PLANE_URL/health

# View system status
fledx nodes status --wide
fledx deployments status --wide

# View logs
sudo journalctl -u fledx-cp -n 50 -f
sudo journalctl -u fledx-agent -n 50 -f
fledx deployments logs --resource-type deployment --resource-id <id>

# Restart services
sudo systemctl restart fledx-cp
sudo systemctl restart fledx-agent

# Check Docker
docker ps -a
docker logs <container-id>
docker stats

# Check connectivity
curl -v https://control-plane.example.com/health
ping <node-ip>
telnet <node-ip> <port>
```

## Next Steps

- **Monitoring:** Set up proactive monitoring - [Monitoring Guide](monitoring.md)
- **Upgrades:** Plan regular maintenance - [Upgrade Guide](upgrades.md)
- **Security:** Review security practices - [Security Guide](security.md)
- **FAQ:** Check common questions - [FAQ](../faq.md)
