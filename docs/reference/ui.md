# Operator UI

The control-plane serves a small observability console at `GET /ui`. The page stitches together the CSS and JavaScript
under `ui/observability` and, once you supply an operator token, it polls the same control-plane host for
`/api/v1/nodes`, `/api/v1/deployments`, `/api/v1/audit-logs`, and `/metrics`. The console shares the operator header
name that the control-plane knows about, auto-refreshes every five seconds when a token is present, and stores the token
in `localStorage` so you do not have to type it again during the next browser session.

## Running the UI Locally

1. **Fast demo (recommended for exploration).**

   ```bash
   ./scripts/local-demo.sh
   # or: just demo
   ```

   The script boots the control-plane on `127.0.0.1:49421` with a demo SQLite database, registers a node, starts the node
   agent, and deploys `hashicorp/http-echo`. It also wires the demo operator token (`dev-operator-token`) into the
   control-plane and the CLI so you can paste it into the UI login box without extra steps. Once the script is running,
   point your browser to `http://127.0.0.1:49421/ui`.

2. **Manual control-plane run (for production-style installs).**

   ```bash
   FLEDX_CP_SERVER_HOST=0.0.0.0 \
     FLEDX_CP_SERVER_PORT=49421 \
     FLEDX_CP_DATABASE_URL=sqlite:///var/lib/fledx/control-plane.db \
     FLEDX_CP_OPERATOR_TOKENS="op-token-1,op-token-2" \
     FLEDX_CP_OPERATOR_HEADER_NAME=authorization \
     ./target/release/control-plane
   ```

   Adjust the host/port if you are behind a reverse proxy. The UI uses relative paths, so ensure `/ui`, `/api/v1/*`, and
   `/metrics` all reach the same origin or that your proxy rewrites requests accordingly; otherwise, you will hit CORS
   errors when the UI attempts to hit the APIs. If you need a custom header name, change
   `FLEDX_CP_OPERATOR_HEADER_NAME` and restart the control-plane. The value you configured also appears on the UI
   so you know which header it will send.

## Authentication & Base Configuration

- **Operator tokens.** The UI requires one of the strings listed in `FLEDX_CP_OPERATOR_TOKENS` (default
  `dev-operator-token`). You paste the token into the masked input at the top of the page; the UI automatically prefixes
  it with `Bearer ` if you omit the prefix and persists it inside the browser under the key `fledx-observability-token`
  for the next session.
- **Bootstrap-only env tokens.** Tokens from `FLEDX_CP_OPERATOR_TOKENS` are intended for initial bootstrap. The
  control-plane logs a warning whenever an env token is used. Set
  `FLEDX_CP_OPERATOR_ENV_DISABLE_AFTER_FIRST_SUCCESS=true` to automatically disable env tokens after the first
  successful admin request and rotate to database-backed/session tokens instead.
- **Operator header name.** The UI displays this name next to the token input. If you change the header (for example, to
  `x-custom-operator`), the UI will continue to read `/ui` but the header text it shows will match what the
  control-plane reports.
- **Port range hints.** The UI renders the same scheduling defaults the control-plane knows about (`ports.range_start`,
  `ports.range_end`, and `ports.auto_assign`), so the hints you see in the form already match the backend validation
  rules.

## Walkthrough (status → create → update → stop/delete → audit/metrics)

1. **Status dashboard.** The landing panel is divided into two columns: the left side lists every node with its name/ID,
   current status badge, last seen, CPU/memory capacity, and label set. The right column shows deployments similarly,
   with the desired state, replica summary, assigned node, and constraint/placement summaries. Both lists include a
   `Last refresh` footer (auto-updated via `formatTimestamp`) and a manual `Refresh now` button at the top if you want
   to pull data before the next five-second tick.

2. **Create deployment flow.** Switch to the **Create deployment** tab to see a form that mirrors the JSON schema. The
   `Image` field is required (`buildSpecFromForm` enforces it and will surface an inline error if you leave it empty),
   while fields such as `Name`, `Replicas`, `Command`, `Environment variables`, `Ports`, `Constraints`, `Node affinity`,
   `Spread replicas`, and `Desired state` are optional helpers. Once the request succeeds, the form shows the message
   “Deployment submitted.” in a green feedback bubble and the status list refreshes with the new entry.

3. **Update deployment flow.** Clicking **Edit** on any deployment card toggles the **Update deployment** tab,
   pre-selects the deployment, and populates the same set of fields. The backend only accepts the fields you change, so
   the UI checks that you provide at least one modification before issuing a `PATCH /api/v1/deployments/<id>` request.
   Success and failure follow the same inline feedback channel as creation, and the status dashboard refreshes
   afterward.

4. **Stop/Delete actions.** Each deployment card also exposes **Stop** and **Delete** buttons next to its status badge.
   Those buttons trigger a browser `confirm` dialog and, upon acceptance, send either a `PATCH` (to set
   `desired_state: stopped`) or `DELETE` to the deployment endpoint. The top status banner displays a success or error
   message (with request ID) that you can copy for debugging.

5. **Audit log & response metrics.** Below the cards, the UI streams the latest audit log entries (action, timestamp,
   status, truncated payload) and the top `/metrics` counter rows derived from `control_plane_http_requests_total`.
   These panels refresh alongside the rest of the UI and show request IDs so you can correlate CLI/API calls with what
   the UI reports.

6. **Validation and error surfaces.** When the control-plane returns a validation error, the UI highlights the field (
   `.form-field.error`) and renders the server message below it, thanks to `setFieldError`. The same message also
   appears inside the form’s feedback span (e.g., `create-feedback`). Operator authentication failures set a global
   error banner (aria-live) with the request ID so you know when the token needs replacement.

## Limitations & Alternatives

- **What the UI does not do.** It is scoped strictly to operator-level deployment CRUD and observability: nodes are
  read-only, there is no way to register a new node or change registration tokens, and there is no tenant/namespace
  filtering built in. Node registration, placement tuning, and secrets management still require CLI/API usage.
- **CLI alternatives.** The CLI calls the same APIs and accepts the same operator header, so you can script flows
  instead of clicking through the UI:

  ```bash
  FLEDX_CLI_CONTROL_PLANE_URL=http://localhost:49421 \
    FLEDX_CLI_OPERATOR_TOKEN=dev-operator-token \
    cargo run -p cli -- deployments create --name web --image nginx:alpine
  ```

  ```bash
  FLEDX_CLI_CONTROL_PLANE_URL=http://localhost:49421 \
    FLEDX_CLI_OPERATOR_TOKEN=dev-operator-token \
    cargo run -p cli -- deployments stop --id <id>
  ```

- **API alternatives.** Refer to [API Reference](api.md) for the full schema of `/api/v1/deployments`,
  `/api/v1/nodes`, `/api/v1/audit-logs`, and `/metrics`. You can also hit the same endpoints with `curl` (the UI simply
  POSTs to `/api/v1/deployments` and PATCHes/deletes `/api/v1/deployments/<id>` while sending the operator header). The
  audit log and metrics panels mirror the CLI `deploy logs` and `metrics show` commands.

This doc mirrors the current UI components (status cards, create/update forms, audit logs, metrics list) so that the
steps and validation surfaces line up with what the browser actually renders.
