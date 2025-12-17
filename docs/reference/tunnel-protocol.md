# HTTP/2 tunnel between gateway and private agents

The gateway exposes an HTTP/2 CONNECT endpoint that private node-agents use to
open a long-lived reverse tunnel. The tunnel carries small, framed control
messages so the gateway can reach agents that sit behind NAT/firewalls.

## Endpoint & configuration

- Listener: `https://<advertised_host>:<advertised_port>/agent-tunnel`
- Auth header: bearer token in `x-fledx-tunnel-token` (configurable)
- Defaults (control-plane / agent):
    - `advertised_host` / `endpoint_host`: `127.0.0.1`
    - `advertised_port` / `endpoint_port`: `49423`
    - `connect_timeout_secs`: `10`
    - `heartbeat_interval_secs`: `30`
    - `heartbeat_timeout_secs`: `90`
    - `token_header`: `x-fledx-tunnel-token`

Configuration keys (env overrides follow the normal prefixes):

| Control-plane key                | Env                                       | Meaning                             |
|----------------------------------|-------------------------------------------|-------------------------------------|
| `tunnel.advertised_host`         | `FLEDX_CP_TUNNEL_ADVERTISED_HOST`         | Hostname/IP agents should dial      |
| `tunnel.advertised_port`         | `FLEDX_CP_TUNNEL_ADVERTISED_PORT`         | Port agents should dial             |
| `tunnel.connect_timeout_secs`    | `FLEDX_CP_TUNNEL_CONNECT_TIMEOUT_SECS`    | Dial timeout for CONNECT            |
| `tunnel.heartbeat_interval_secs` | `FLEDX_CP_TUNNEL_HEARTBEAT_INTERVAL_SECS` | Cadence for agent pings             |
| `tunnel.heartbeat_timeout_secs`  | `FLEDX_CP_TUNNEL_HEARTBEAT_TIMEOUT_SECS`  | Idle window before close            |
| `tunnel.token_header`            | `FLEDX_CP_TUNNEL_TOKEN_HEADER`            | Header name carrying the node token |

| Node-agent key                   | Env                                          | Meaning                        |
|----------------------------------|----------------------------------------------|--------------------------------|
| `tunnel.endpoint_host`           | `FLEDX_AGENT_TUNNEL_ENDPOINT_HOST`           | Gateway host to dial           |
| `tunnel.endpoint_port`           | `FLEDX_AGENT_TUNNEL_ENDPOINT_PORT`           | Gateway port to dial           |
| `tunnel.connect_timeout_secs`    | `FLEDX_AGENT_TUNNEL_CONNECT_TIMEOUT_SECS`    | Dial timeout                   |
| `tunnel.heartbeat_interval_secs` | `FLEDX_AGENT_TUNNEL_HEARTBEAT_INTERVAL_SECS` | Agent heartbeat cadence        |
| `tunnel.heartbeat_timeout_secs`  | `FLEDX_AGENT_TUNNEL_HEARTBEAT_TIMEOUT_SECS`  | Idle window before close       |
| `tunnel.token_header`            | `FLEDX_AGENT_TUNNEL_TOKEN_HEADER`            | Header carrying the node token |

The control-plane advertises the tunnel endpoint to agents in registration and
desired-state responses; agents treat those values as authoritative and fall
back to local config if absent. These responses share the `TunnelEndpoint`
shape (via `RegistrationResponse` and `DesiredStateResponse`) so the agent can
surface the same `host`, `port`, and timeout settings described above. If the
tunnel is missing or empty, the agent falls back to its `FLEDX_AGENT_TUNNEL_*`
settings until the control-plane sends a new endpoint.

## Handshake

1. Agent opens HTTP/2 `CONNECT` to `/agent-tunnel` on the advertised host/port.
2. Required headers:
    - `:authority` = `<host>:<port>`
    - `:path` = `/agent-tunnel`
    - `x-fledx-node-id` = node UUID
    - `<token_header>` = `Bearer <node_token>` (defaults to `x-fledx-tunnel-token`)
    - `x-agent-version` / `x-agent-build` for telemetry (same as REST APIs)
3. Gateway validates the token and returns `200` to keep the stream open. Auth
   failures return `401` with a short JSON error body; malformed headers return
   `400`.
4. After `200`, the payload switches to length-prefixed JSON frames (u32
   big-endian length followed by UTF-8 JSON). The agent immediately sends a
   `client_hello` frame, the gateway confirms the heartbeat window in a
   `server_hello`, and the tunnel is considered healthy once heartbeats start
   flowing. Missing a `server_hello` within `connect_timeout_secs` is treated as
   a failure and the agent must close and retry the stream.

## Frame shapes

- `client_hello` (agent → gateway):
  ```json
  {"type":"client_hello","node_id":"<uuid>","agent_version":"1.2.3","capabilities":["logs","exec"],"heartbeat_interval_secs":30}
  ```
- `server_hello` (gateway → agent):
  ```json
  {"type":"server_hello","tunnel_id":"<uuid>","heartbeat_timeout_secs":90}
  ```
- `heartbeat` (agent → gateway):
  ```json
  {"type":"heartbeat","sent_at":"2025-01-01T00:00:00Z"}
  ```
- `heartbeat_ack` (gateway → agent):
  The agent should include the timestamp it sent in `sent_at`; the gateway
  replies with a `heartbeat_ack` frame that mirrors the receive time.
  ```json
  {"type":"heartbeat_ack","received_at":"2025-01-01T00:00:00Z"}
  ```
- `forward_request` (gateway → agent): HTTP request destined for the private
  agent runtime.
  ```json
  {"type":"forward_request","id":"r-123","method":"GET","path":"/v1/status","headers":{"accept":"application/json"},"body_b64":""}
  ```
- `forward_response` (agent → gateway): Reply to `forward_request`.
  ```json
  {"type":"forward_response","id":"r-123","status":200,"headers":{"content-type":"application/json"},"body_b64":"eyJzdGF0dXMiOiJyZWFkeSJ9"}
  ```

## Keepalive and close semantics

- Agents must send `heartbeat` every `heartbeat_interval_secs` (default 30s).
- Gateway closes the tunnel if no heartbeat arrives within
  `heartbeat_timeout_secs` (default 90s) or if auth fails mid-stream.
- Agents close and retry the tunnel on non-`2xx` CONNECT responses or if no
  `server_hello` is received within `connect_timeout_secs`.
