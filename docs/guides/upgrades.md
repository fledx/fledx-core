# Upgrade Guide

This guide covers safe upgrade procedures for Distributed Edge Hosting components.

## Overview

Distributed Edge Hosting upgrades involve updating two main components:

1. **Control Plane** - The central orchestration service
2. **Node Agents** - The agents running on each edge node

Upgrades should be performed in this order to maintain compatibility.

## Version Compatibility

### Compatibility Window

The control plane enforces a version compatibility window for node agents:

- **Default:** Agents within ±1 minor version are allowed
- **Example:** Control plane v1.5.x accepts agents v1.4.x through v1.6.x

### Configuration

Control compatibility enforcement via environment variables:

```bash
# Minimum agent version
FLEDX_CP__COMPATIBILITY__MIN_AGENT_VERSION=1.4.0

# Maximum agent version
FLEDX_CP__COMPATIBILITY__MAX_AGENT_VERSION=1.6.0

# Enforcement mode (default: true)
FLEDX_CP__FEATURES__ENFORCE_AGENT_COMPATIBILITY=true
```

### Warn-Only Mode

For testing or gradual rollouts, disable strict enforcement:

```bash
FLEDX_CP__FEATURES__ENFORCE_AGENT_COMPATIBILITY=false
```

Agents outside the version window will trigger warnings but remain operational.

## Pre-Upgrade Checklist

Before starting an upgrade, ensure:

- [ ] **Backup Database** - Backup the control plane SQLite database
- [ ] **Check Capacity** - Verify nodes have resources for workload redistribution
- [ ] **Review Release Notes** - Check for breaking changes
- [ ] **Test in Staging** - Test upgrade on non-production environment first
- [ ] **Schedule Downtime** - Plan for brief service interruption
- [ ] **Prepare Rollback** - Have previous binaries ready

## Upgrade Procedure

### Step 1: Backup Control Plane Database

> **WARNING:** Always backup the control plane database before upgrading. Database corruption or failed migrations cannot be reversed without a backup. Service will be unavailable during the backup process.

**Critical:** Always backup before upgrading the control plane.

```bash
# Stop control plane
sudo systemctl stop fledx-cp

# Backup database
sudo cp /var/lib/fledx/fledx-cp.db /var/lib/fledx/fledx-cp.db.backup-$(date +%Y%m%d-%H%M%S)

# Verify backup
ls -lh /var/lib/fledx/fledx-cp.db.backup-*
```

Alternatively, if using a volume snapshot system:

```bash
# Snapshot the volume (example for LVM)
sudo lvcreate -L 1G -s -n cp-snapshot /dev/vg0/fledx-data
```

### Step 2: Upgrade Control Plane

#### Download New Binary

> **WARNING:** Always verify checksums before installing binaries. Compromised binaries can provide attackers with full system access.

```bash
# Download new release (replace URL with actual release)
wget https://releases.example.com/fledx/fledx-cp-v1.6.0-linux-amd64.tar.gz

# Verify checksum
sha256sum fledx-cp-v1.6.0-linux-amd64.tar.gz
# Compare with published checksum

# Extract
tar -xzf fledx-cp-v1.6.0-linux-amd64.tar.gz
```

#### Replace Binary

```bash
# Stop service
sudo systemctl stop fledx-cp

# Backup current binary
sudo cp /usr/local/bin/fledx-cp /usr/local/bin/fledx-cp.old

# Install new binary
sudo install -m 0755 fledx-cp /usr/local/bin/fledx-cp

# Verify version
/usr/local/bin/fledx-cp --version
```

#### Start and Verify

```bash
# Start service
sudo systemctl start fledx-cp

# Check status
sudo systemctl status fledx-cp

# Verify health endpoint shows new version
curl -fsSL http://localhost:8080/health | jq .
```

Expected response:

```json
{
  "status": "healthy",
  "version": "1.6.0",
  "compatibility": {
    "min_agent_version": "1.5.0",
    "max_agent_version": "1.7.0"
  }
}
```

#### Verify Compatibility Window

```bash
# Check compatibility settings
curl -fsSL http://localhost:8080/health | jq '.compatibility'
```

Ensure the window includes your current agent versions.

### Step 3: Upgrade Node Agents

Upgrade agents **one at a time** to avoid service disruption.

#### For Each Node

**Download and prepare:**

```bash
# On the node
wget https://releases.example.com/fledx/fledx-agent-v1.6.0-linux-amd64.tar.gz
sha256sum fledx-agent-v1.6.0-linux-amd64.tar.gz
tar -xzf fledx-agent-v1.6.0-linux-amd64.tar.gz
```

**Stop agent:**

```bash
sudo systemctl stop fledx-agent
```

**Replace binary:**

```bash
# Backup current binary
sudo cp /usr/local/bin/fledx-agent /usr/local/bin/fledx-agent.old

# Install new binary
sudo install -m 0755 fledx-agent /usr/local/bin/fledx-agent

# Verify version
/usr/local/bin/fledx-agent --version
```

**Start and verify:**

```bash
# Start agent
sudo systemctl start fledx-agent

# Check status
sudo systemctl status fledx-agent

# Verify node is connected
fledx nodes status | grep <node-name>
```

**Wait for deployments to stabilize:**

```bash
# Check all deployments on this node are running
fledx deployments list --wide | grep <node-id>

# Wait for health checks to pass
sleep 30
```

**Repeat for next node** only after confirming current node is healthy.

### Step 4: Verify Upgrade

After all components are upgraded:

```bash
# Check control plane version
curl http://localhost:8080/health | jq '.version'

# Check all nodes are connected
fledx nodes status

# Check all deployments are running
fledx deployments status

# Verify no errors in logs
sudo journalctl -u fledx-cp --since "10 minutes ago" | grep -i error
sudo journalctl -u fledx-agent --since "10 minutes ago" | grep -i error
```

## Rollback Procedure

If the upgrade fails, roll back to the previous version.

### Rollback Control Plane

```bash
# Stop new version
sudo systemctl stop fledx-cp

# Restore database backup
sudo cp /var/lib/fledx/fledx-cp.db.backup-YYYYMMDD-HHMMSS /var/lib/fledx/fledx-cp.db

# Restore old binary
sudo cp /usr/local/bin/fledx-cp.old /usr/local/bin/fledx-cp

# Start service
sudo systemctl start fledx-cp

# Verify
curl http://localhost:8080/health
sudo systemctl status fledx-cp
```

### Rollback Node Agent

```bash
# On each node
sudo systemctl stop fledx-agent

# Restore old binary
sudo cp /usr/local/bin/fledx-agent.old /usr/local/bin/fledx-agent

# Start service
sudo systemctl start fledx-agent

# Verify
sudo systemctl status fledx-agent
fledx nodes status | grep <node-name>
```

## Upgrade Strategies

### Blue-Green Deployment (Control Plane)

For zero-downtime upgrades, run two control planes behind a load balancer:

1. Deploy new control plane version on separate host
2. Point load balancer to both old and new
3. Drain traffic from old control plane
4. Verify new control plane
5. Decommission old control plane

**Note:** Requires shared database or replication setup.

### Canary Rollout (Node Agents)

Upgrade agents gradually:

1. Upgrade 1-2 "canary" nodes first
2. Monitor for 24-48 hours
3. If stable, upgrade 25% of nodes
4. If stable, upgrade remaining 75%

### Maintenance Window

For production environments, schedule upgrades during low-traffic periods:

1. Notify users of maintenance window
2. Stop accepting new deployments
3. Perform upgrade
4. Verify system health
5. Resume normal operations

## Common Upgrade Issues

### Issue: Agent Rejected (Version Out of Range)

**Symptom:**

```
Agent version 1.4.0 outside allowed range [1.5.0, 1.7.0]
```

**Solution:**

Either:
- Upgrade the agent to a compatible version
- Adjust control plane compatibility window:
  ```bash
  FLEDX_CP__COMPATIBILITY__MIN_AGENT_VERSION=1.4.0
  ```

### Issue: Database Migration Failed

**Symptom:**

Control plane fails to start after upgrade:

```
Failed to run migrations: ...
```

**Solution:**

1. Stop control plane
2. Restore database backup
3. Check release notes for manual migration steps
4. Apply migrations if needed
5. Retry upgrade

### Issue: Deployments Not Starting After Upgrade

**Symptom:**

Deployments stuck in "deploying" state after agent upgrade.

**Solution:**

```bash
# Check agent logs
sudo journalctl -u fledx-agent -f

# Check deployment status
fledx deployments status --id <id> --wide

# Common causes:
# - New agent requires updated config
# - Port assignment changed
# - Compatibility issue with deployment spec
```

### Issue: Performance Degradation

**Symptom:**

System slower after upgrade.

**Solution:**

1. Check resource usage:
   ```bash
   top
   df -h
   ```

2. Review release notes for new resource requirements

3. Check for new configuration options that need tuning

4. Consider rolling back if degradation is severe

## Best Practices

### 1. Test Upgrades in Staging

Always test the upgrade process in a non-production environment first:

```bash
# Staging environment
1. Backup staging database
2. Upgrade control plane
3. Upgrade agents
4. Run smoke tests
5. Verify for 24 hours
6. Document any issues
```

### 2. Maintain Backups

Keep multiple backup generations:

```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d-%H%M%S)
sudo systemctl stop fledx-cp
sudo cp /var/lib/fledx/fledx-cp.db /var/lib/fledx/backups/fledx-cp.db.$DATE
sudo systemctl start fledx-cp

# Keep last 7 days
find /var/lib/fledx/backups/ -name "fledx-cp.db.*" -mtime +7 -delete
```

### 3. Monitor During Upgrade

Watch key metrics during the upgrade:

```bash
# In separate terminals:
watch -n 5 'fledx nodes status'
watch -n 5 'fledx deployments status'
sudo journalctl -u fledx-cp -f
sudo journalctl -u fledx-agent -f
```

### 4. Document Upgrade Process

Keep a runbook with:
- Exact commands used
- Timing of each step
- Any issues encountered
- Rollback procedures tested

### 5. Communicate with Users

For production systems:
- Announce maintenance window in advance
- Provide status updates during upgrade
- Confirm completion and system health

## Release Notes

Always review release notes before upgrading. Key items to check:

- **Breaking Changes** - API/CLI/configuration changes
- **Migration Steps** - Required manual actions
- **New Features** - Capabilities to test
- **Bug Fixes** - Issues resolved
- **Security Updates** - Critical patches

Release notes are available in:
- [Releases Documentation](../releases/index.md)
- Project `CHANGELOG.md`
- Official releases page provided by your distribution channel

## Automated Upgrade Tools

For large deployments, consider automation:

### Ansible Playbook Example

```yaml
---
- name: Upgrade Control Plane
  hosts: control_plane
  become: yes
  tasks:
    - name: Backup database
      copy:
        src: /var/lib/fledx/fledx-cp.db
        dest: /var/lib/fledx/fledx-cp.db.backup
        remote_src: yes

    - name: Stop service
      systemd:
        name: fledx-cp
        state: stopped

    - name: Install new binary
      copy:
        src: fledx-cp-v1.6.0
        dest: /usr/local/bin/fledx-cp
        mode: '0755'

    - name: Start service
      systemd:
        name: fledx-cp
        state: started

    - name: Verify health
      uri:
        url: http://localhost:8080/health
        return_content: yes
      register: health_check
      failed_when: "'healthy' not in health_check.content"
```

## Next Steps

- **Installation:** [Installation Guide](installation.md)
- **Monitoring:** [Monitoring Guide](monitoring.md)
- **Security:** [Security Guide](security.md)
- **Troubleshooting:** [Day-2 Operations](monitoring.md)
