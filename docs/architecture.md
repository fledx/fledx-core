# Architecture Overview

This document provides a high-level view of the Distributed Edge Hosting system architecture.

## System Map

```mermaid
graph LR
    Operator["Operator (UI / CLI / API client)"]
    Proxy["TLS Reverse Proxy"]
    CP["Control Plane\n(scheduler, API, SQLite)"]
    Registry["Container Registry"]
    subgraph Edge["Edge nodes"]
        Agent1["Node Agent"]
        Workload1["Workload containers"]
        Agent2["Node Agent"]
        Workload2["Workload containers"]
    end

    Operator -->|HTTPS| Proxy -->|HTTP| CP
    CP -->|assign deployments| Agent1
    CP -->|assign deployments| Agent2
    Agent1 -->|pull images| Registry
    Agent2 -->|pull images| Registry
    Agent1 --> Workload1
    Agent2 --> Workload2
    Operator -. metrics/logs .-> CP
```

Key points

- Control plane exposes API/UI; TLS is terminated at a reverse proxy.
- Agents connect outbound to the control plane, receive work assignments, and
  pull images from your registry.
- Operator tools (UI/CLI/API) authenticate with operator tokens.

## Deploy flow (happy path)

```mermaid
sequenceDiagram
    participant Operator
    participant CLI as CLI/UI/API
    participant CP as Control Plane
    participant Agent as Node Agent
    participant Registry as Registry
    participant Workload
    Operator ->> CLI: Submit deploy spec (name, image, ports)
    CLI ->> CP: POST /api/v1/deployments
    CP -->> CLI: Deployment created (id, desired_state)
    CP ->> Agent: Assign deployment (desired_state=running)
    Agent ->> Registry: Pull image
    Agent ->> Workload: Start container(s) with env/ports
    Agent -->> CP: Report status + health
    CLI ->> CP: GET /api/v1/deployments/{id}/status
    CP -->> CLI: Status running + placement
```

Where to go next

- Quickstart: [Getting Started](getting-started/index.md)
- Install: [Installation Guide](guides/installation.md)
- Security: [Security Guide](guides/security.md)
- Day-2 ops: [Monitoring Guide](guides/monitoring.md)
