# Migration Guide

This guide helps you migrate workloads to Distributed Edge Hosting from other container orchestration platforms.

## Overview

Fledx is designed for edge and distributed scenarios where traditional orchestrators may be too complex or
resource-intensive. This guide covers:

- Migrating from Kubernetes
- Migrating from Docker Swarm
- Migrating from Docker Compose
- Migrating from Nomad
- General migration strategies

## Migration from Kubernetes

### Conceptual Mapping

| Kubernetes       | Fledx Equivalent         | Notes                                  |
|------------------|------------------------|----------------------------------------|
| Deployment       | Deployment             | Similar concept, simpler configuration |
| Pod              | Container instance     | Fledx manages containers directly        |
| Service          | Port mapping           | Expose via host ports, use external LB |
| ConfigMap        | Config                 | Managed via `fledx configs`              |
| Secret           | Secret-backed env vars | Node-level secrets                     |
| Node             | Node                   | Similar concept                        |
| Label/Selector   | Node labels + affinity | Placement control                      |
| Namespace        | N/A                    | Single namespace per control plane     |
| Ingress          | External reverse proxy | Use nginx/Caddy/Traefik                |
| PersistentVolume | Volume mount           | Host path bind mounts                  |
| ReplicaSet       | Replicas + spread      | Automatic spreading available          |

### Example: Kubernetes to Fledx

**Kubernetes deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-web
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.25-alpine
        ports:
        - containerPort: 80
        env:
        - name: NGINX_PORT
          value: "80"
        volumeMounts:
        - name: html
          mountPath: /usr/share/nginx/html
      volumes:
      - name: html
        persistentVolumeClaim:
          claimName: nginx-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  selector:
    app: nginx
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: LoadBalancer
```

**Fledx equivalent (CLI):**

```bash
# Create deployment
fledx deployments create \
  --name nginx-web \
  --image nginx:1.25-alpine \
  --replicas 3 \
  --spread-replicas \
  --port 8080:80/tcp \
  --env NGINX_PORT=80 \
  --volume /var/lib/fledx/volumes/nginx-html:/usr/share/nginx/html
```

**Fledx equivalent (YAML):**

```yaml
name: nginx-web
image: nginx:1.25-alpine
replicas: 3
desired_state: running
placement:
  spread: true
ports:
  - container_port: 80
    host_port: 8080
    protocol: tcp
environment:
  NGINX_PORT: "80"
volumes:
  - host_path: /var/lib/fledx/volumes/nginx-html
    container_path: /usr/share/nginx/html
```

### Migration Strategy

#### Phase 1: Planning

```bash
# 1. Inventory your Kubernetes workloads
kubectl get deployments --all-namespaces

# 2. Export deployment configs
kubectl get deployment nginx-web -o yaml > k8s-nginx.yaml

# 3. Identify dependencies
kubectl get services,configmaps,secrets,pvc --all-namespaces

# 4. Plan node mapping
kubectl get nodes -o wide
# Map to Fledx nodes based on location/capacity
```

#### Phase 2: Setup Fledx

```bash
# 1. Install control plane and register nodes
# (See Installation Guide)

# 2. Label nodes to match K8s node selectors
fledx node update --node-id <id> --label zone=us-east-1
fledx node update --node-id <id> --label env=production

# 3. Pre-pull images on nodes to speed up migration
ssh <node-host>
docker pull nginx:1.25-alpine
```

#### Phase 3: Migrate Workloads

**Option A: Blue-Green Migration (Zero Downtime)**

```bash
# 1. Deploy on Fledx (different port)
fledx deployments create \
  --name nginx-web-fledx \
  --image nginx:1.25-alpine \
  --replicas 3 \
  --spread-replicas \
  --port 8080:80/tcp

# 2. Verify Fledx deployment
fledx deployments status
curl http://<node-ip>:8080

# 3. Update load balancer to point to Fledx nodes

# 4. Monitor traffic shift

# 5. Once stable, scale down Kubernetes deployment
kubectl scale deployment nginx-web --replicas=0

# 6. Delete Kubernetes resources after validation period
kubectl delete deployment nginx-web
```

**Option B: Parallel Migration (Gradual)**

```bash
# 1. Deploy on Fledx with reduced replicas
fledx deployments create \
  --name nginx-web \
  --image nginx:1.25-alpine \
  --replicas 1 \
  --port 8080:80/tcp

# 2. Test thoroughly

# 3. Gradually scale up Fledx, scale down K8s
fledx deployments update --id <deployment-id> --replicas 2
kubectl scale deployment nginx-web --replicas=2

# Repeat until fully migrated
```

#### Phase 4: Migrate Configurations

**ConfigMaps → Fledx Configs:**

```bash
# Export from Kubernetes
kubectl get configmap app-config -o json > config.json

# Extract key-value pairs
cat config.json | jq -r '.data | to_entries[] | "--var \(.key)=\(.value)"'

# Create in Fledx
fledx configs create \
  --name app-config \
  --var DATABASE_URL=postgres://... \
  --var API_KEY=xyz

# Attach to deployment
fledx configs attach deployment \
  --config-id <config-id> \
  --deployment-id <deployment-id>
```

**Secrets → Secret-backed environment:**

```bash
# On each Fledx node, set secret environment variables
ssh <node-host>
sudo tee -a /etc/fledx/fledx-agent.env <<EOF
FLEDX_SECRET_db_password=supersecret
FLEDX_SECRET_api_key=secret-key-here
EOF

sudo systemctl restart fledx-agent

# Reference in deployment
fledx deployments create \
  --name my-app \
  --image my-app:latest \
  --secret-env DB_PASSWORD=db_password \
  --secret-env API_KEY=api_key
```

#### Phase 5: Migrate Persistent Data

```bash
# 1. Prepare volume directories on Fledx nodes
ssh <node-host>
sudo mkdir -p /var/lib/fledx/volumes/nginx-html
sudo chown fledx:fledx /var/lib/fledx/volumes/nginx-html

# 2. Copy data from K8s PVC
kubectl cp <pod-name>:/usr/share/nginx/html /tmp/nginx-data
scp -r /tmp/nginx-data/* <node-host>:/var/lib/fledx/volumes/nginx-html/

# 3. Mount volume in Fledx deployment
fledx deployments create \
  --name nginx-web \
  --image nginx:1.25-alpine \
  --volume /var/lib/fledx/volumes/nginx-html:/usr/share/nginx/html
```

### Not Supported in Fledx

The following Kubernetes features have no direct Fledx equivalent:

- **Namespaces** - Use separate control plane instances if needed
- **Network Policies** - Use OS-level firewall rules
- **RBAC** - Operator tokens are all-or-nothing (future enhancement)
- **DaemonSets** - Deploy individually to each node
- **StatefulSets** - Use labels and volume mounts for stateful workloads
- **Jobs/CronJobs** - Use external cron + Fledx CLI
- **Auto-scaling** - Manual scaling via `fledx deployments update --replicas`

## Migration from Docker Swarm

### Conceptual Mapping

| Docker Swarm | Fledx Equivalent         |
|--------------|------------------------|
| Service      | Deployment             |
| Stack        | Multiple deployments   |
| Task         | Container instance     |
| Node         | Node                   |
| Secret       | Secret-backed env vars |
| Config       | Config                 |
| Network      | Host network           |
| Volume       | Volume mount           |

### Example: Swarm to Fledx

**Docker Swarm stack.yml:**

```yaml
version: '3.8'
services:
  web:
    image: nginx:alpine
    replicas: 3
    ports:
      - "80:80"
    environment:
      - NGINX_PORT=80
    volumes:
      - html-data:/usr/share/nginx/html
    deploy:
      placement:
        constraints:
          - node.role == worker

volumes:
  html-data:
```

**Fledx equivalent:**

```bash
# Create volume directory on nodes first
ssh <node-host>
sudo mkdir -p /var/lib/fledx/volumes/html-data

# Deploy
fledx deployments create \
  --name web \
  --image nginx:alpine \
  --replicas 3 \
  --spread-replicas \
  --port 80:80/tcp \
  --env NGINX_PORT=80 \
  --volume /var/lib/fledx/volumes/html-data:/usr/share/nginx/html \
  --node-affinity role=worker
```

### Migration Steps

```bash
# 1. List Swarm services
docker service ls

# 2. Inspect each service
docker service inspect web --pretty

# 3. Deploy to Fledx
fledx deployments create \
  --name web \
  --image nginx:alpine \
  --replicas 3 \
  --port 80:80/tcp

# 4. Verify
fledx deployments status

# 5. Remove from Swarm
docker service rm web
```

## Migration from Docker Compose

### Example: Compose to Fledx

**docker-compose.yml:**

```yaml
version: '3'
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    environment:
      - NGINX_PORT=80
    volumes:
      - ./html:/usr/share/nginx/html

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_PASSWORD=secret
    volumes:
      - db-data:/var/lib/postgresql/data

volumes:
  db-data:
```

**Fledx equivalent:**

```bash
# Prepare volumes on node
ssh <node-host>
sudo mkdir -p /var/lib/fledx/volumes/html
sudo mkdir -p /var/lib/fledx/volumes/db-data
scp -r ./html/* <node-host>:/var/lib/fledx/volumes/html/

# Deploy web
fledx deployments create \
  --name web \
  --image nginx:alpine \
  --port 8080:80/tcp \
  --env NGINX_PORT=80 \
  --volume /var/lib/fledx/volumes/html:/usr/share/nginx/html

# Deploy db
fledx deployments create \
  --name db \
  --image postgres:15-alpine \
  --port 5432:5432/tcp \
  --env POSTGRES_PASSWORD=secret \
  --volume /var/lib/fledx/volumes/db-data:/var/lib/postgresql/data
```

### Automated Conversion

Use `kompose` to convert Compose files:

```bash
# Install kompose
curl -L https://github.com/kubernetes/kompose/releases/download/v1.31.2/kompose-linux-amd64 -o kompose
chmod +x kompose
sudo mv kompose /usr/local/bin/

# Convert (creates K8s YAML)
kompose convert -f docker-compose.yml

# Then manually adapt K8s YAML to Fledx format
# (See Kubernetes migration section)
```

## Migration from Nomad

### Conceptual Mapping

| Nomad      | Fledx Equivalent     |
|------------|--------------------|
| Job        | Deployment         |
| Task Group | Container instance |
| Task       | Container          |
| Client     | Node               |
| Constraint | Node affinity      |

### Example: Nomad to Fledx

**Nomad job.hcl:**

```hcl
job "nginx-web" {
  datacenters = ["dc1"]
  type = "service"

  group "web" {
    count = 3

    task "nginx" {
      driver = "docker"

      config {
        image = "nginx:alpine"
        ports = ["http"]
      }

      resources {
        cpu    = 500
        memory = 256
      }
    }

    network {
      port "http" {
        static = 8080
        to     = 80
      }
    }
  }
}
```

**Fledx equivalent:**

```bash
fledx deployments create \
  --name nginx-web \
  --image nginx:alpine \
  --replicas 3 \
  --spread-replicas \
  --port 8080:80/tcp \
  --cpu-millis 500 \
  --memory-bytes 268435456  # 256MB

# Label nodes by datacenter
fledx node update --node-id <id> --label datacenter=dc1

# Target specific datacenter
fledx deployments create \
  --name nginx-web \
  --image nginx:alpine \
  --node-affinity datacenter=dc1
```

## General Migration Best Practices

### 1. Start Small

```bash
# Begin with stateless, non-critical services
# Example: internal tools, monitoring agents, static web servers

# NOT recommended for first migration:
# - Stateful databases
# - Mission-critical services
# - Complex multi-service applications
```

### 2. Test Thoroughly

```bash
# Create test deployment
fledx deployments create \
  --name test-app \
  --image test-app:latest \
  --replicas 1

# Run integration tests
curl http://<node-ip>:<port>/health
# Run load tests
# Monitor for 24-48 hours

# Scale up when confident
fledx deployments update --id <deployment-id> --replicas 3
```

### 3. Plan for Load Balancing

Fledx doesn't include a built-in load balancer. Use external solutions:

```bash
# Option 1: nginx reverse proxy
upstream deh_backend {
    server node1.example.com:8080;
    server node2.example.com:8080;
    server node3.example.com:8080;
}

server {
    listen 80;
    location / {
        proxy_pass http://deh_backend;
    }
}

# Option 2: Caddy
node1.example.com:8080
node2.example.com:8080
node3.example.com:8080

# Option 3: HAProxy
backend deh_nodes
    server node1 node1.example.com:8080 check
    server node2 node2.example.com:8080 check
    server node3 node3.example.com:8080 check
```

### 4. Handle State Carefully

```bash
# For databases and stateful apps:

# 1. Take backup before migration
pg_dump mydb > backup.sql

# 2. Stop writes to old system

# 3. Copy final state to Fledx volumes
scp backup.sql <node-host>:/var/lib/fledx/volumes/db-data/

# 4. Start Fledx deployment
fledx deployments create \
  --name postgres \
  --image postgres:15 \
  --volume /var/lib/fledx/volumes/db-data:/var/lib/postgresql/data

# 5. Restore and verify
ssh <node-host>
docker exec -i <container-id> psql -U postgres mydb < backup.sql

# 6. Cutover traffic to Fledx
```

### 5. Monitor During Migration

```bash
# Watch deployment status
fledx deployments watch --id <deployment-id> --follow-logs

# Monitor node health
watch -n 5 'fledx nodes status --wide'

# Check logs continuously
fledx deployments logs \
  --resource-type deployment \
  --resource-id <id> \
  --follow

# Set up Prometheus/Grafana
# (See Monitoring Guide)
```

## Migration Checklist

### Pre-Migration

- [ ] Document all current workloads
- [ ] Identify dependencies between services
- [ ] Plan node topology (how many nodes, where)
- [ ] Install and test Fledx control plane
- [ ] Register and verify all nodes
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Create backup strategy
- [ ] Plan rollback procedure

### During Migration

- [ ] Start with non-critical services
- [ ] Test each service thoroughly
- [ ] Monitor resource usage
- [ ] Verify networking and connectivity
- [ ] Test failure scenarios
- [ ] Document any issues encountered

### Post-Migration

- [ ] Monitor for 24-48 hours
- [ ] Verify backups are working
- [ ] Update documentation
- [ ] Train team on Fledx operations
- [ ] Decommission old infrastructure
- [ ] Celebrate! 🎉

## Rollback Plan

Always have a rollback plan before migrating:

```bash
# Keep old system running during migration
# Document exact steps to revert

# Example rollback for Kubernetes migration:
# 1. Update load balancer to point back to K8s services
# 2. Scale up K8s deployments
kubectl scale deployment my-app --replicas=3

# 3. Scale down or delete Fledx deployments
fledx deployments stop --id <deployment-id>

# 4. Verify traffic is back on old system
# 5. Investigate what went wrong with Fledx migration
```

## Common Migration Challenges

### Challenge 1: Service Discovery

**Problem:** Kubernetes has built-in DNS service discovery. Fledx uses host ports.

**Solution:**

```bash
# Option A: Use environment variables with node IPs
fledx deployments create \
  --name backend \
  --image backend:latest \
  --env DATABASE_HOST=node1.example.com \
  --env DATABASE_PORT=5432

# Option B: Use external DNS (Consul, etcd)

# Option C: Deploy a service registry container
fledx deployments create \
  --name consul \
  --image consul:latest \
  --port 8500:8500/tcp
```

### Challenge 2: No Built-in Secrets Management

**Problem:** Kubernetes has Secrets API. Fledx uses node-level environment variables.

**Solution:**

```bash
# Use external secrets manager (Vault, AWS Secrets Manager)
# or node-level secret environment variables

# On each node:
ssh <node-host>
sudo tee -a /etc/fledx/fledx-agent.env <<EOF
FLEDX_SECRET_db_password=<vault-get-secret>
EOF
```

### Challenge 3: Different Networking Model

**Problem:** Kubernetes has overlay networking. Fledx uses host networking.

**Solution:**

```bash
# Explicitly manage port assignments
# Use external load balancer for service abstraction
# Document port mappings clearly

# Create port mapping reference:
# Service: web       -> node1.example.com:8080
# Service: api       -> node2.example.com:8081
# Service: database  -> node3.example.com:5432
```

## Next Steps

- **Installation:** [Installation Guide](installation.md)
- **Deployment:** [Deployment Guide](deployment.md)
- **Monitoring:** [Monitoring Guide](monitoring.md)
- **Troubleshooting:** [Troubleshooting Guide](troubleshooting.md)
