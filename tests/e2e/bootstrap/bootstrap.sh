#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="/work"
KEY_PATH="${WORK_DIR}/.work/id_ed25519"
PROFILE="e2e"
INSECURE=0

for arg in "$@"; do
  case "${arg}" in
    --insecure)
      INSECURE=1
      ;;
    *)
      echo "Unknown option: ${arg}" >&2
      exit 1
      ;;
  esac
done

if [[ ! -x /usr/local/bin/fledx ]]; then
  echo "fledx binary not found at /usr/local/bin/fledx" >&2
  exit 1
fi

if [[ ! -f "${KEY_PATH}" ]]; then
  echo "SSH key not found at ${KEY_PATH}" >&2
  exit 1
fi

export FLEDX_CLI_CONTROL_PLANE_URL="http://cp:8080"

wait_for_ready_node() {
  local retries=30

  for ((i = 1; i <= retries; i++)); do
    if /usr/local/bin/fledx --profile "${PROFILE}" status --nodes-only --json \
      | jq -e '.summary.nodes.ready >= 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done

  echo "Timed out waiting for node to become ready" >&2
  return 1
}

cp_args=(
  /usr/local/bin/fledx
  --profile "${PROFILE}"
  bootstrap
  cp
  --ssh-host fledx@cp
  --ssh-identity-file "${KEY_PATH}"
  --ssh-host-key-checking off
  --cp-hostname cp
  --server-port 8080
  --tunnel-port 7443
)

if [[ ${INSECURE} -eq 1 ]]; then
  cp_args+=(--insecure-allow-unsigned)
fi

"${cp_args[@]}"

agent_args=(
  /usr/local/bin/fledx
  --profile "${PROFILE}"
  bootstrap
  agent
  --ssh-host fledx@agent
  --ssh-identity-file "${KEY_PATH}"
  --ssh-host-key-checking off
  --service-user fledx-agent
)

if [[ ${INSECURE} -eq 1 ]]; then
  agent_args+=(--insecure-allow-unsigned)
fi

"${agent_args[@]}"

wait_for_ready_node

/usr/local/bin/fledx --profile "${PROFILE}" nodes list --json > "${WORK_DIR}/.work/nodes.json"
