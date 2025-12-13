#!/usr/bin/env bash
set -euo pipefail

# fledx Quick Start Script
# This script sets up a local demo with control plane + agent + sample deployment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${PROJECT_ROOT}/quickstart-data"
LOG_DIR="${DATA_DIR}/logs"

# Demo credentials (insecure - for demo only!)
REG_TOKEN="quickstart-reg-$(openssl rand -hex 8)"
OP_TOKEN="quickstart-op-$(openssl rand -hex 8)"
PEPPER="quickstart-pepper-$(openssl rand -hex 16)"

# Ports
CP_PORT=8080
TUNNEL_PORT=7443

# PIDs
CP_PID=""
AGENT_PID=""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"

    if [ -n "$AGENT_PID" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        echo "Stopping node agent (PID: $AGENT_PID)..."
        kill "$AGENT_PID" 2>/dev/null || true
    fi

    if [ -n "$CP_PID" ] && kill -0 "$CP_PID" 2>/dev/null; then
        echo "Stopping control plane (PID: $CP_PID)..."
        kill "$CP_PID" 2>/dev/null || true
    fi

    echo -e "${GREEN}Cleanup complete.${NC}"
    echo ""
    echo "To restart the demo, run: $0"
}

trap cleanup EXIT INT TERM

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

wait_for_health() {
    local url=$1
    local max_attempts=30
    local attempt=1

    log_info "Waiting for $url to be healthy..."

    while [ $attempt -le $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            log_success "Service is healthy!"
            return 0
        fi

        echo -n "."
        sleep 1
        attempt=$((attempt + 1))
    done

    log_error "Service did not become healthy after $max_attempts seconds"
    return 1
}

# Print banner
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                               ║${NC}"
echo -e "${BLUE}║        ${GREEN}fledx Quick Start Demo${BLUE}                 ║${NC}"
echo -e "${BLUE}║                                               ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v cargo &> /dev/null; then
    log_error "Rust/Cargo is not installed. Please install from https://rustup.rs/"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker info &> /dev/null; then
    log_error "Docker daemon is not running. Please start Docker."
    exit 1
fi

log_success "Prerequisites check passed"

# Check port availability
log_info "Checking port availability..."
if command -v ss &> /dev/null; then
    if ss -tuln | grep -q ":${CP_PORT} "; then
        log_error "Port $CP_PORT is already in use. Please stop the service using it."
        exit 1
    fi
    if ss -tuln | grep -q ":${TUNNEL_PORT} "; then
        log_error "Port $TUNNEL_PORT is already in use. Please stop the service using it."
        exit 1
    fi
elif command -v netstat &> /dev/null; then
    if netstat -tuln | grep -q ":${CP_PORT} "; then
        log_error "Port $CP_PORT is already in use. Please stop the service using it."
        exit 1
    fi
    if netstat -tuln | grep -q ":${TUNNEL_PORT} "; then
        log_error "Port $TUNNEL_PORT is already in use. Please stop the service using it."
        exit 1
    fi
elif command -v lsof &> /dev/null; then
    if lsof -i ":${CP_PORT}" > /dev/null 2>&1; then
        log_error "Port $CP_PORT is already in use. Please stop the service using it."
        exit 1
    fi
    if lsof -i ":${TUNNEL_PORT}" > /dev/null 2>&1; then
        log_error "Port $TUNNEL_PORT is already in use. Please stop the service using it."
        exit 1
    fi
else
    log_warn "No port checking tool available (ss/netstat/lsof). Skipping port check."
fi
log_success "Ports are available"

# Setup directories
log_info "Setting up directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR/volumes"
log_success "Directories created"

# Build binaries
log_info "Building binaries (this may take a few minutes on first run)..."
cd "$PROJECT_ROOT"

if cargo build --release --quiet; then
    log_success "Binaries built successfully"
else
    log_error "Failed to build binaries"
    exit 1
fi

FLEDX_CP="${PROJECT_ROOT}/target/release/fledx-cp"
FLEDX_AGENT="${PROJECT_ROOT}/target/release/fledx-agent"
FLEDX_CLI="${PROJECT_ROOT}/target/release/fledx"

# Start Control Plane
log_info "Starting control plane on port $CP_PORT..."

export FLEDX_CP__SERVER__HOST="0.0.0.0"
export FLEDX_CP__SERVER__PORT="$CP_PORT"
export FLEDX_CP__DATABASE__URL="sqlite://${DATA_DIR}/fledx-cp.db"
export FLEDX_CP__REGISTRATION__TOKEN="$REG_TOKEN"
export FLEDX_CP__OPERATOR__TOKENS="$OP_TOKEN"
export FLEDX_CP__TOKENS__PEPPER="$PEPPER"
export FLEDX_CP__TUNNEL__ADVERTISED_HOST="127.0.0.1"
export FLEDX_CP__TUNNEL__ADVERTISED_PORT="$TUNNEL_PORT"
export FLEDX_CP__TUNNEL__USE_TLS="false"
export FLEDX_CP__PORTS__AUTO_ASSIGN="true"
export FLEDX_CP__PORTS__RANGE_START="30000"
export FLEDX_CP__PORTS__RANGE_END="31000"
export RUST_LOG="info"

"$FLEDX_CP" > "${LOG_DIR}/control-plane.log" 2>&1 &
CP_PID=$!

log_success "Control plane started (PID: $CP_PID)"

# Wait for control plane to be ready
wait_for_health "http://localhost:$CP_PORT/health"

# Register a node
log_info "Registering edge node..."

export FLEDX_CONTROL_PLANE_URL="http://localhost:$CP_PORT"
export FLEDX_REGISTRATION_TOKEN="$REG_TOKEN"

NODE_INFO=$("$FLEDX_CLI" nodes register \
    --name quickstart-node \
    --label "env=demo" \
    --label "region=local")

NODE_ID=$(echo "$NODE_INFO" | grep "node_id:" | awk '{print $2}')
NODE_TOKEN=$(echo "$NODE_INFO" | grep "node_token:" | awk '{print $2}')

if [ -z "$NODE_ID" ] || [ -z "$NODE_TOKEN" ]; then
    log_error "Failed to register node"
    exit 1
fi

log_success "Node registered: $NODE_ID"

# Start Node Agent
log_info "Starting node agent..."

export FLEDX_AGENT__CONTROL_PLANE_URL="http://localhost:$CP_PORT"
export FLEDX_AGENT__NODE_ID="$NODE_ID"
export FLEDX_AGENT__NODE_TOKEN="$NODE_TOKEN"
export FLEDX_AGENT__ALLOW_INSECURE_HTTP="true"
export FLEDX_AGENT__ALLOWED_VOLUME_PREFIXES="${DATA_DIR}/volumes"
export FLEDX_AGENT__VOLUME_DATA_DIR="$DATA_DIR"
export FLEDX_AGENT__GATEWAY__ENABLED="false"
export FLEDX_AGENT__TUNNEL__ENDPOINT_HOST="127.0.0.1"
export FLEDX_AGENT__TUNNEL__ENDPOINT_PORT="$TUNNEL_PORT"
export FLEDX_AGENT__TUNNEL__USE_TLS="false"
export RUST_LOG="info"

"$FLEDX_AGENT" > "${LOG_DIR}/node-agent.log" 2>&1 &
AGENT_PID=$!

log_success "Node agent started (PID: $AGENT_PID)"

# Export credentials for CLI commands
export FLEDX_CONTROL_PLANE_URL="http://localhost:$CP_PORT"
export FLEDX_OPERATOR_TOKEN="$OP_TOKEN"

# Wait for node to become ready
log_info "Waiting for node to become ready..."
max_wait=60
elapsed=0
node_ready=false

while [ $elapsed -lt $max_wait ]; do
    # Check node status using the CLI
    if NODE_STATUS=$("$FLEDX_CLI" nodes status 2>&1); then
        # Check if the node exists AND has a healthy heartbeat
        # The node should appear in the output with status information
        if echo "$NODE_STATUS" | grep -q "quickstart-node"; then
            # Give the node a moment to send first heartbeat and be marked as reachable
            # Wait at least 5 seconds before considering it ready
            if [ $elapsed -ge 5 ]; then
                node_ready=true
                log_success "Node is ready!"
                break
            fi
        fi
    fi

    echo -n "."
    sleep 2
    elapsed=$((elapsed + 2))
done

if [ "$node_ready" = false ]; then
    log_error "Node did not become ready after $max_wait seconds"
    log_info "Check logs: tail -f ${LOG_DIR}/node-agent.log"
    exit 1
fi

# Give the node extra time for heartbeat to be processed and marked as ready
log_info "Waiting for node to be marked as reachable..."
sleep 5

# Clean up old quickstart deployments from previous runs
log_info "Cleaning up old demo deployments..."
OLD_DEPLOYS=$("$FLEDX_CLI" deployments status 2>/dev/null | grep "quickstart-nginx" | awk '{print $1}' || true)
if [ -n "$OLD_DEPLOYS" ]; then
    echo "$OLD_DEPLOYS" | while read -r deploy_id; do
        if [ -n "$deploy_id" ]; then
            "$FLEDX_CLI" deployments delete --id "$deploy_id" 2>/dev/null || true
        fi
    done
    log_success "Old deployments cleaned up"
    # Give some time for cleanup to complete
    sleep 2
else
    log_info "No old deployments to clean up"
fi

# Deploy a demo application
log_info "Deploying demo application (nginx)..."

DEPLOY_OUTPUT=$("$FLEDX_CLI" deployments create \
    --name quickstart-nginx \
    --image nginx:alpine \
    --port auto:80/tcp \
    --env "WELCOME_MSG=Hello from fledx!" \
    --replicas 1)

DEPLOY_ID=$(echo "$DEPLOY_OUTPUT" | grep "deployment_id:" | awk '{print $2}')

if [ -z "$DEPLOY_ID" ]; then
    log_error "Failed to create deployment"
    exit 1
fi

log_success "Deployment created: $DEPLOY_ID"

# Get the assigned port for nginx from the database
log_info "Getting assigned port for nginx..."
if command -v sqlite3 &> /dev/null; then
    # Convert UUID to hex format without hyphens for BLOB comparison
    DEPLOY_ID_HEX=$(echo "$DEPLOY_ID" | tr -d '-' | tr '[:lower:]' '[:upper:]')

    # Retry a few times in case the deployment hasn't been fully written yet
    for i in {1..10}; do
        NGINX_PORT=$(sqlite3 "${DATA_DIR}/fledx-cp.db" \
            "SELECT json_extract(ports_json, '\$[0].host_port') FROM deployments WHERE hex(id) = '$DEPLOY_ID_HEX';" 2>/dev/null || echo "")
        if [ -n "$NGINX_PORT" ]; then
            break
        fi
        sleep 1
    done
fi

if [ -z "$NGINX_PORT" ]; then
    NGINX_PORT="(check 'deployments status' for assigned port)"
    log_warn "Could not determine assigned port"
else
    log_success "Nginx assigned to port $NGINX_PORT"

    # Wait for nginx to be ready and responding
    log_info "Waiting for nginx to be ready..."
    nginx_ready=false
    for i in {1..60}; do
        if curl -sf "http://localhost:$NGINX_PORT" > /dev/null 2>&1; then
            nginx_ready=true
            log_success "Nginx is ready and responding!"
            break
        fi
        echo -n "."
        sleep 1
    done

    if [ "$nginx_ready" = false ]; then
        log_warn "Nginx did not respond after 60 seconds, but container may still be starting"
    fi
fi

# Show status
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                               ║${NC}"
echo -e "${GREEN}║           Quick Start Demo Ready!            ║${NC}"
echo -e "${GREEN}║                                               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BLUE}Access Points:${NC}"
echo "  Control Plane API: http://localhost:$CP_PORT"
echo "  Control Plane Health: http://localhost:$CP_PORT/health"
echo "  Control Plane Metrics: http://localhost:$CP_PORT/metrics"
echo "  Nginx Demo: http://localhost:$NGINX_PORT"
echo ""

# Verify nginx is working
if [[ "$NGINX_PORT" =~ ^[0-9]+$ ]]; then
    echo -e "${BLUE}Demo Verification:${NC}"
    if NGINX_RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:$NGINX_PORT" 2>/dev/null); then
        HTTP_CODE=$(echo "$NGINX_RESPONSE" | tail -1)
        if [ "$HTTP_CODE" = "200" ]; then
            echo -e "  ${GREEN}✓${NC} Nginx is responding (HTTP $HTTP_CODE)"
        else
            echo -e "  ${YELLOW}⚠${NC} Nginx responded with HTTP $HTTP_CODE"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} Could not verify nginx (curl failed)"
    fi
    echo ""
fi

echo -e "${BLUE}Demo Credentials:${NC}"
echo "  Registration Token: $REG_TOKEN"
echo "  Operator Token:     $OP_TOKEN"
echo "  Node ID:            $NODE_ID"
echo ""

echo -e "${BLUE}Try it out! Open a new terminal and run:${NC}"
echo ""
echo -e "${GREEN}# Export credentials first${NC}"
echo "export FLEDX_CONTROL_PLANE_URL=http://localhost:$CP_PORT"
echo "export FLEDX_OPERATOR_TOKEN=$OP_TOKEN"
echo ""
echo -e "${GREEN}# List all nodes${NC}"
echo "$FLEDX_CLI nodes status"
echo ""
echo -e "${GREEN}# List all deployments${NC}"
echo "$FLEDX_CLI deployments status"
echo ""
echo -e "${GREEN}# Watch deployment in real-time${NC}"
echo "$FLEDX_CLI deployments watch --id $DEPLOY_ID"
echo ""
echo -e "${GREEN}# View combined status (nodes + deployments)${NC}"
echo "$FLEDX_CLI status"
echo ""
echo -e "${GREEN}# View detailed status with all columns${NC}"
echo "$FLEDX_CLI status --wide"
echo ""
echo -e "${GREEN}# Check logs${NC}"
echo "tail -f ${LOG_DIR}/control-plane.log"
echo "tail -f ${LOG_DIR}/node-agent.log"
echo ""

echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop all services and clean up${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo ""

# Keep script running
while true; do
    sleep 1

    # Check if processes are still running
    if [ -n "$CP_PID" ] && ! kill -0 "$CP_PID" 2>/dev/null; then
        log_error "Control plane has stopped unexpectedly"
        break
    fi

    if [ -n "$AGENT_PID" ] && ! kill -0 "$AGENT_PID" 2>/dev/null; then
        log_error "Node agent has stopped unexpectedly"
        break
    fi
done
