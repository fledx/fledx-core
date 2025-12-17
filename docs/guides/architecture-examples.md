# Real-World Architecture Examples

This guide provides practical architecture patterns and deployment scenarios for Distributed Edge Hosting.

## Table of Contents

1. [Single Region Edge Network](#single-region-edge-network)
2. [Multi-Region Distributed Setup](#multi-region-distributed-setup)
3. [Hybrid Cloud-Edge Architecture](#hybrid-cloud-edge-architecture)
4. [High Availability Setup](#high-availability-setup)
5. [IoT & Sensor Network](#iot--sensor-network)
6. [Content Delivery Network](#content-delivery-network)
7. [Development & Staging Environment](#development--staging-environment)

## Single Region Edge Network

### Use Case

Small business with multiple locations in one region needing to run applications closer to users.

### Architecture

```
                     ┌─────────────────────┐
                     │  Control Plane      │
                     │  (Cloud/Datacenter) │
                     │  + Monitoring Stack │
                     └──────────┬──────────┘
                                │
                ┌───────────────┼──────────────┐
                │               │              │
        ┌───────▼──────┐ ┌──────▼──────┐ ┌─────▼───────┐
        │ Edge Node 1  │ │ Edge Node 2 │ │ Edge Node 3 │
        │ (Office A)   │ │ (Office B)  │ │ (Office C)  │
        │ - Web App    │ │ - Web App   │ │ - Web App   │
        │ - Local DB   │ │ - Local DB  │ │ - API Svr   │
        └──────────────┘ └─────────────┘ └─────────────┘
             │                  │                │
          [Users]           [Users]          [Users]
```

### Deployment

**1. Setup control plane:**

```bash
# Install control plane (see Installation Guide)
# Location: Central cloud VM or datacenter server
```

**2. Register and label nodes:**

```bash
# Register nodes with labels for each location
fledx nodes register --name office-a --label location=office-a --label region=us-east
fledx nodes register --name office-b --label location=office-b --label region=us-east
fledx nodes register --name office-c --label location=office-c --label region=us-east
```

**3. Deploy applications:**

```bash
# Web application (deployed to all locations)
fledx deployments create \
  --name web-app \
  --image company/web-app:v1.0 \
  --replicas 3 \
  --spread \
  --port 80:8080/tcp \
  --env ENVIRONMENT=production

# Local database (one per location)
for location in office-a office-b office-c; do
  fledx deployments create \
    --name db-$location \
    --image postgres:15-alpine \
    --replicas 1 \
    --port 5432:5432/tcp \
    --node-affinity location=$location \
    --volume /var/lib/fledx/volumes/$location-db:/var/lib/postgresql/data \
    --env POSTGRES_PASSWORD=<secret>
done

# Central API server
fledx deployments create \
  --name api-server \
  --image company/api:v1.0 \
  --replicas 3 \
  --spread \
  --port 8081:3000/tcp
```

### Benefits

- Low latency for local users
- Each location has local data
- Simple to manage (single control plane)
- Automatic failover if one location goes down

## Multi-Region Distributed Setup

### Use Case

Global application requiring presence in multiple geographic regions.

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Global Load Balancer                   │
│                  (Route53 / CloudFlare)                  │
└────┬───────────────────────┬──────────────────────┬──────┘
     │                       │                      │
┌────▼────────┐      ┌───────▼──────┐      ┌──────▼──────┐
│   US-EAST   │      │   EU-WEST    │      │   AP-SOUTH  │
│             │      │              │      │             │
│ ┌─────────┐ │      │ ┌──────────┐ │      │ ┌─────────┐ │
│ │ Control │ │      │ │ Control  │ │      │ │ Control │ │
│ │ Plane   │ │      │ │ Plane    │ │      │ │ Plane   │ │
│ └────┬────┘ │      │ └────┬─────┘ │      │ └────┬────┘ │
│      │      │      │      │       │      │      │      │
│  ┌───┴───┐  │      │  ┌───┴────┐  │      │  ┌───┴───┐  │
│  │ Node1 │  │      │  │ Node1  │  │      │  │ Node1 │  │
│  │ Node2 │  │      │  │ Node2  │  │      │  │ Node2 │  │
│  └───────┘  │      │  └────────┘  │      │  └───────┘  │
└─────────────┘      └──────────────┘      └─────────────┘
```

### Deployment

**1. Deploy control plane in each region:**

```bash
# Region: US-EAST (control-us.example.com)
# Region: EU-WEST (control-eu.example.com)
# Region: AP-SOUTH (control-ap.example.com)
```

**2. Register nodes to regional control planes:**

```bash
# US nodes
export FLEDX_CLI_CONTROL_PLANE_URL=https://control-us.example.com
fledx nodes register --name us-node-1
fledx nodes register --name us-node-2

# EU nodes
export FLEDX_CLI_CONTROL_PLANE_URL=https://control-eu.example.com
fledx nodes register --name eu-node-1
fledx nodes register --name eu-node-2

# AP nodes
export FLEDX_CLI_CONTROL_PLANE_URL=https://control-ap.example.com
fledx nodes register --name ap-node-1
fledx nodes register --name ap-node-2
```

**3. Deploy to all regions:**

```bash
# Deploy script for all regions
for region in us eu ap; do
  export FLEDX_CLI_CONTROL_PLANE_URL=https://control-${region}.example.com
  export FLEDX_CLI_OPERATOR_TOKEN=$OPERATOR_TOKEN_${region}

  fledx deployments create \
    --name web-app \
    --image company/web-app:v1.0 \
    --replicas 2 \
    --spread \
    --port 80:8080/tcp \
    --env REGION=$region
done
```

**4. Setup global load balancing:**

```bash
# AWS Route53 latency-based routing
aws route53 create-health-check \
  --type HTTPS \
  --resource-path /health \
  --fully-qualified-domain-name us-node-1.example.com

# CloudFlare load balancing
# Configure via UI or API to distribute across regions
```

### Benefits

- Global presence with regional isolation
- Comply with data residency requirements
- Better fault isolation (regional failures)
- Optimal latency for global users

## Hybrid Cloud-Edge Architecture

### Use Case

Enterprise with cloud infrastructure and on-premise edge locations.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Cloud (AWS/Azure/GCP)               │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐  ┌────────────┐  │
│  │ Control      │    │ Monitoring   │  │ Container  │  │
│  │ Plane        │    │ (Prometheus) │  │ Registry   │  │
│  │              │    │ (Grafana)    │  │            │  │
│  └──────┬───────┘    └──────────────┘  └────────────┘  │
│         │                                               │
└─────────┼───────────────────────────────────────────────┘
          │ VPN / Private Link
          │
    ┌─────┴──────────────────────────┐
    │                                │
┌───▼──────────┐            ┌────────▼──────┐
│ Edge Site 1  │            │ Edge Site 2   │
│ (Factory)    │            │ (Retail)      │
│              │            │               │
│ ┌──────────┐ │            │ ┌───────────┐ │
│ │ Node 1   │ │            │ │ Node 3    │ │
│ │ - MES    │ │            │ │ - POS     │ │
│ │ - SCADA  │ │            │ │ - Invntry │ │
│ └──────────┘ │            │ └───────────┘ │
│              │            │               │
│ ┌──────────┐ │            │ ┌───────────┐ │
│ │ Node 2   │ │            │ │ Node 4    │ │
│ │ - TimeSr │ │            │ │ - DigSig  │ │
│ │ - ReprtG │ │            │ │ - Cams    │ │
│ └──────────┘ │            │ └───────────┘ │
└──────────────┘            └───────────────┘
```

### Deployment

**1. Cloud infrastructure:**

```bash
# Deploy control plane in cloud
# Region: AWS us-east-1
# VPC with private subnet
# VPN tunnel to on-premise sites

# Deploy monitoring stack
fledx deployments create \
  --name prometheus \
  --image prom/prometheus:latest \
  --port 9090:9090/tcp \
  --volume /var/lib/fledx/volumes/prometheus:/prometheus

fledx deployments create \
  --name grafana \
  --image grafana/grafana:latest \
  --port 3000:3000/tcp
```

**2. Edge site setup:**

```bash
# Factory site - register nodes with labels
fledx nodes register --name factory-node-1 --label site=factory --label type=industrial
fledx nodes register --name factory-node-2 --label site=factory --label type=industrial

# Deploy manufacturing execution system
fledx deployments create \
  --name mes-system \
  --image company/mes:v2.0 \
  --replicas 2 \
  --node-affinity site=factory \
  --port 8080:80/tcp \
  --volume /var/lib/fledx/volumes/mes-data:/data

# Retail site - register nodes with labels
fledx nodes register --name retail-node-3 --label site=retail --label type=commercial
fledx nodes register --name retail-node-4 --label site=retail --label type=commercial

# Deploy POS system
fledx deployments create \
  --name pos-system \
  --image company/pos:v1.5 \
  --replicas 2 \
  --node-affinity site=retail \
  --port 8081:80/tcp
```

**3. Networking:**

```bash
# Setup VPN between cloud and edge sites
# All nodes connect to cloud control plane via VPN

# On-premise nodes configuration:
FLEDX_AGENT_CONTROL_PLANE_URL=https://control-plane.internal.vpc:49421
```

### Benefits

- Centralized management
- Keep sensitive data on-premise
- Cloud-based monitoring and control
- Cost-effective (reuse existing hardware)

## High Availability Setup

### Use Case

Mission-critical application requiring maximum uptime.

### Architecture

```
┌──────────────────────────────────────────────────┐
│              Load Balancer (HAProxy)             │
│           Primary: 10.0.1.10 (VRRP)              │
│           Backup:  10.0.1.11 (VRRP)              │
└────┬────────────────────┬────────────────────┬───┘
     │                    │                    │
┌────▼──────────┐   ┌─────▼─────────┐   ┌─────▼─────────┐
│ Node 1        │   │ Node 2        │   │ Node 3        │
│ Zone A        │   │ Zone B        │   │ Zone C        │
│               │   │               │   │               │
│ - App (1/3)   │   │ - App (1/3)   │   │ - App (1/3)   │
│ - DB Primary  │   │ - DB Replica  │   │ - DB Replica  │
│               │   │               │   │               │
└───────────────┘   └───────────────┘   └───────────────┘
       │                   │                    │
       └───────────────────┴────────────────────┘
              PostgreSQL Streaming Replication
```

### Deployment

**1. Setup nodes in different availability zones:**

```bash
# Register nodes in different availability zones with labels
fledx nodes register --name node-1-zone-a --label zone=a --label role=primary
fledx nodes register --name node-2-zone-b --label zone=b --label role=replica
fledx nodes register --name node-3-zone-c --label zone=c --label role=replica
```

**2. Deploy application with spread replicas:**

```bash
fledx deployments create \
  --name critical-app \
  --image company/app:v1.0 \
  --replicas 3 \
  --spread \
  --port 8080:80/tcp \
  --env DB_HOST=10.0.1.10 \
  --health-check-path /health
```

**3. Deploy database with replication:**

```bash
# Primary database
fledx deployments create \
  --name db-primary \
  --image postgres:15-alpine \
  --replicas 1 \
  --node-affinity role=primary \
  --port 5432:5432/tcp \
  --volume /var/lib/fledx/volumes/db-primary:/var/lib/postgresql/data \
  --env POSTGRES_PASSWORD=<secret> \
  --env POSTGRES_REPLICATION_MODE=master

# Replica databases
fledx deployments create \
  --name db-replica \
  --image postgres:15-alpine \
  --replicas 2 \
  --node-affinity role=replica \
  --port 5432:5432/tcp \
  --volume /var/lib/fledx/volumes/db-replica:/var/lib/postgresql/data \
  --env POSTGRES_PASSWORD=<secret> \
  --env POSTGRES_REPLICATION_MODE=slave \
  --env POSTGRES_MASTER_HOST=<primary-node-ip>
```

**4. Setup load balancer with health checks:**

```bash
# HAProxy configuration
cat > /etc/haproxy/haproxy.cfg <<EOF
frontend http_front
    bind *:80
    default_backend app_servers

backend app_servers
    balance roundrobin
    option httpchk GET /health
    server node1 10.0.2.10:8080 check
    server node2 10.0.2.11:8080 check
    server node3 10.0.2.12:8080 check
EOF
```

### Benefits

- High availability (survives single node failure)
- Load distribution across zones
- Database replication for data safety
- Automatic failover

## IoT & Sensor Network

### Use Case

IoT platform collecting and processing sensor data at the edge.

### Architecture

```
                  ┌────────────────┐
                  │ Cloud Backend  │
                  │ - Analytics    │
                  │ - Long-term DB │
                  └───────▲────────┘
                          │
                ┌─────────┴─────────┐
                │ Control Plane     │
                │ (Regional)        │
                └──────────┬────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
  ┌─────▼──────┐    ┌──────▼─────┐    ┌──────▼─────┐
  │ Gateway 1  │    │ Gateway 2  │    │ Gateway 3  │
  │ (Building) │    │ (Building) │    │ (Building) │
  │            │    │            │    │            │
  │ - Collector│    │ - Collector│    │ - Collector│
  │ - Processor│    │ - Processor│    │ - Processor│
  │ - Local DB │    │ - Local DB │    │ - Local DB │
  └─────┬──────┘    └──────┬─────┘    └──────┬─────┘
        │                  │                  │
   [IoT Sensors]      [IoT Sensors]      [IoT Sensors]
   - Temp/Humidity    - Motion/Light     - Energy
   - Air Quality      - Occupancy        - Water
```

### Deployment

**1. Deploy gateways:**

```bash
# Register gateway nodes (Raspberry Pi, edge devices) with labels
fledx nodes register --name gateway-building-1 --label building=1 --label type=iot-gateway
fledx nodes register --name gateway-building-2 --label building=2 --label type=iot-gateway
fledx nodes register --name gateway-building-3 --label building=3 --label type=iot-gateway
```

**2. Deploy data collection services:**

```bash
# MQTT broker for sensor data
fledx deployments create \
  --name mqtt-broker \
  --image eclipse-mosquitto:latest \
  --replicas 3 \
  --node-affinity type=iot-gateway \
  --port 1883:1883/tcp \
  --port 8883:8883/tcp \
  --volume /var/lib/fledx/volumes/mqtt-config:/mosquitto/config

# Data processor (per building)
for building in 1 2 3; do
  fledx deployments create \
    --name processor-building-$building \
    --image company/iot-processor:v1.0 \
    --replicas 1 \
    --node-affinity building=$building \
    --port 8080:8080/tcp \
    --env MQTT_BROKER=localhost:1883 \
    --env BUILDING_ID=$building
done

# Local time-series database
fledx deployments create \
  --name timeseries-db \
  --image timescale/timescaledb:latest \
  --replicas 3 \
  --node-affinity type=iot-gateway \
  --port 5432:5432/tcp \
  --volume /var/lib/fledx/volumes/timeseries:/var/lib/postgresql/data
```

**3. Deploy aggregation service:**

```bash
# Aggregates data from all buildings and sends to cloud
fledx deployments create \
  --name data-aggregator \
  --image company/iot-aggregator:v1.0 \
  --replicas 1 \
  --port 8081:8080/tcp \
  --env CLOUD_API=https://api.cloud.example.com \
  --env BUILDINGS=1,2,3
```

### Benefits

- Process data locally (low latency)
- Reduce cloud bandwidth costs
- Continue operating during network outages
- Privacy (sensitive data stays local)

## Content Delivery Network

### Use Case

Media company distributing content from edge locations.

### Architecture

```
              ┌──────────────────────┐
              │   Origin Server      │
              │   (Cloud Storage)    │
              └──────────┬───────────┘
                         │
              ┌──────────┴───────────┐
              │   Control Plane      │
              └──────────┬───────────┘
                         │
     ┌───────────────────┼────────────────────┐
     │                   │                    │
┌────▼──────┐      ┌─────▼──────┐      ┌─────▼──────┐
│ CDN Edge1 │      │ CDN Edge2  │      │ CDN Edge3  │
│ (US-West) │      │ (US-East)  │      │ (EU)       │
│           │      │            │      │            │
│ - Nginx   │      │ - Nginx    │      │ - Nginx    │
│ - Cache   │      │ - Cache    │      │ - Cache    │
│ - Metrics │      │ - Metrics  │      │ - Metrics  │
└───────────┘      └────────────┘      └────────────┘
     │                  │                    │
  [Users]            [Users]              [Users]
```

### Deployment

```bash
# Register edge nodes with region labels
fledx nodes register --name cdn-us-west --label region=us-west --label type=cdn
fledx nodes register --name cdn-us-east --label region=us-east --label type=cdn
fledx nodes register --name cdn-eu --label region=eu --label type=cdn

# Deploy nginx cache servers
fledx deployments create \
  --name cdn-cache \
  --image nginx:alpine \
  --replicas 3 \
  --spread \
  --node-affinity type=cdn \
  --port 80:80/tcp \
  --port 443:443/tcp \
  --volume /var/lib/fledx/volumes/nginx-cache:/var/cache/nginx \
  --volume /var/lib/fledx/volumes/nginx-config:/etc/nginx/conf.d:ro

# Deploy cache warming service
fledx deployments create \
  --name cache-warmer \
  --image company/cache-warmer:v1.0 \
  --replicas 3 \
  --node-affinity type=cdn \
  --env ORIGIN_URL=https://origin.example.com
```

## Development & Staging Environment

### Use Case

Development team needs staging environment mimicking production.

### Architecture

```
Production:                      Staging:
┌───────────────────┐           ┌───────────────────┐
│ Control Plane     │           │ Control Plane     │
│ (Production)      │           │ (Staging)         │
└──────┬────────────┘           └──────┬────────────┘
       │                               │
   ┌───┴───┐                       ┌───┴───┐
   │ Nodes │                       │ Nodes │
   │ (3x)  │                       │ (2x)  │
   └───────┘                       └───────┘
```

### Deployment

```bash
# Staging control plane (separate instance)
export FLEDX_CLI_CONTROL_PLANE_URL=https://staging-control.example.com

# Register staging nodes with environment label
fledx nodes register --name staging-node-1 --label env=staging
fledx nodes register --name staging-node-2 --label env=staging

# Deploy staging apps
fledx deployments create \
  --name web-app \
  --image company/web-app:staging \
  --replicas 2 \
  --port 80:8080/tcp \
  --env ENVIRONMENT=staging \
  --env DEBUG=true

# Use same deployment commands as production
# (Different control plane URL = different environment)
```

### Benefits

- Isolated from production
- Test deployment procedures
- Validate changes before production
- Cost-effective (fewer nodes)

## Next Steps

- **Deployment Guide:** [Deployment Best Practices](deployment.md)
- **Monitoring:** [Set up monitoring](monitoring.md)
- **Security:** [Secure your architecture](security.md)
- **Migration:** [Migrate from other platforms](migration.md)
