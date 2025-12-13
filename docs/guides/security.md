# Security & Access Model

This guide covers setting up secure transport, token handling, and network exposure for the control plane and agents.

> **WARNING:** This guide contains security-critical configurations. Improper settings can expose your infrastructure to unauthorized access. Always use TLS in production and keep tokens secure.

## Authentication

> **WARNING:** Operator and registration tokens provide full administrative access. Store them securely and rotate regularly.

- Operator tokens: bearer-style secrets used by CLI, UI, and API. Header name
  defaults to `authorization`; override with `FLEDX_CP__OPERATOR__HEADER_NAME`.
- Registration token: single secret required to enroll nodes
  (`FLEDX_CP__REGISTRATION__TOKEN`).
- Node tokens: per-node secret issued at registration; used by agents to
  authenticate to the control plane.
- Rotation:
    - Operator tokens: rotate out of band, restart control plane or reload env.
    - Node tokens: rotate via CLI `fledx nodes token rotate --id <node-id>`.
    - Registration token: change in control-plane config; recycle agents only if
      they need re-registration.

## Transport Security

> **WARNING:** Never use `FLEDX_AGENT__ALLOW_INSECURE_HTTP=true` or `FLEDX_AGENT__TLS_INSECURE_SKIP_VERIFY=true` in production. These settings disable critical security protections and expose your system to man-in-the-middle attacks.

- Terminate TLS at your reverse proxy (e.g., nginx, Caddy, Traefik) in front of
  the control plane. Upstream to the control plane uses HTTP by default.
- Agents should reach the proxy over HTTPS; avoid `FLEDX_AGENT__ALLOW_INSECURE_HTTP`
  except in labs.
- For private CAs, supply agents with the CA bundle (`FLEDX_AGENT__CA_CERT_PATH`)
  and keep `FLEDX_AGENT__TLS_INSECURE_SKIP_VERIFY` false.

## Network Exposure

- Control plane: expose HTTPS listener only; restrict to operator and agent
  networks. Default port 8080 (HTTP) or 8443 (behind proxy).
- Agents: no inbound ports required; they initiate outbound connections to the
  control plane and pull container images from your registry.
- Workload ports: use explicit firewall rules for published ports; prefer
  reverse proxies or load balancers in front of exposed services.

## Secrets Handling

> **WARNING:** Secrets in environment files must have `600` permissions. World-readable files expose credentials. Never commit secrets to version control or log them in debug mode.

- Store tokens in environment files with `600` permissions owned by the service
  account. Avoid shell history leaks (use `ENV=... ExecStart` env files).
- For configs, prefer secret-backed entries and mount paths scoped per
  deployment. Keep `FLEDX_AGENT__SECRETS_DIR` on a tmpfs if feasible.
- Avoid logging secrets; set `RUST_LOG=info` (not `debug`) in production.

## Hardening Tips

- Run control plane and agents under dedicated users (`fledx`) without login
  shells; set `LimitNOFILE` to handle many connections.
- Pin allowed host volume prefixes for agents: `FLEDX_AGENT__ALLOWED_VOLUME_PREFIXES`
  (default `/var/lib/fledx/volumes`).
- Enforce version compatibility:
  `FLEDX_CP__FEATURES__ENFORCE_AGENT_COMPATIBILITY=true` plus min/max agent
  versions as needed.
- Rate limit registration:
  `FLEDX_CP__REGISTRATION__RATE_LIMIT_PER_MINUTE=<number>`.

## Incident Basics

- Revoke a node quickly: rotate its token with `--keep-old=false`, or delete the
  node in the control plane and recycle the agent host.
- Audit: use CLI `fledx audit-logs --limit 50` or the corresponding API endpoint
  for recent events.
- Back up control-plane database regularly (see Day-2 guide) to enable token
  recovery.
