#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WORK_DIR="${SCRIPT_DIR}/.work"
BIN_PATH="${ROOT_DIR}/target/debug/fledx"
SYSTEMD_IMAGE="fledx-e2e-systemd-ssh"
CLI_IMAGE="fledx-e2e-cli"
NETWORK_NAME="fledx-e2e"
CP_NAME="fledx-e2e-cp"
AGENT_NAME="fledx-e2e-agent"
CLI_NAME="fledx-e2e-cli"

REBUILD=0
CLEANUP=0
INSECURE=0

for arg in "$@"; do
  case "${arg}" in
    --rebuild)
      REBUILD=1
      ;;
    --cleanup)
      CLEANUP=1
      ;;
    --insecure)
      INSECURE=1
      ;;
    --help|-h)
      echo "Usage: $0 [--rebuild] [--cleanup] [--insecure]" >&2
      exit 0
      ;;
    *)
      echo "Unknown option: ${arg}" >&2
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if [[ ! -S /var/run/docker.sock ]]; then
  echo "/var/run/docker.sock is required for the agent container" >&2
  exit 1
fi

mkdir -p "${WORK_DIR}"

KEY_PATH="${WORK_DIR}/id_ed25519"
if [[ ! -f "${KEY_PATH}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${KEY_PATH}" >/dev/null
fi

cp "${KEY_PATH}.pub" "${WORK_DIR}/authorized_keys"
chmod 600 "${KEY_PATH}" "${WORK_DIR}/authorized_keys"
chmod 700 "${WORK_DIR}"

if [[ ${REBUILD} -eq 1 || ! -x "${BIN_PATH}" ]]; then
  if [[ ${INSECURE} -eq 0 && -z "${FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS:-}" ]]; then
    echo "FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS is required to embed signing keys" >&2
    echo "for local builds. Provide it or place a release-built fledx binary" >&2
    echo "at ${BIN_PATH}." >&2
    exit 1
  fi
  (
    cd "${ROOT_DIR}"
    if [[ -n "${FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS:-}" ]]; then
      FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS="${FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS}" \
        cargo build -p cli --features bootstrap
    else
      cargo build -p cli --features bootstrap
    fi
  )
fi

if [[ ${INSECURE} -eq 0 ]]; then
  if ! "${BIN_PATH}" internal release-signing-keys --json > "${WORK_DIR}/signing-keys.json"; then
    echo "fledx binary does not report embedded release signing keys (or is too old)." >&2
    echo "Set FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS and rebuild, or provide" >&2
    echo "a release-built binary built from this source at ${BIN_PATH}." >&2
    exit 1
  fi
fi

build_args=()
if [[ ${REBUILD} -eq 1 ]]; then
  build_args+=(--no-cache)
fi

if [[ ${CLEANUP} -eq 1 ]]; then
  docker rm -f "${CP_NAME}" "${AGENT_NAME}" "${CLI_NAME}" >/dev/null 2>&1 || true

  cleanup() {
    docker rm -f "${CP_NAME}" "${AGENT_NAME}" "${CLI_NAME}" >/dev/null 2>&1 || true
    if [[ ${CREATED_NETWORK:-0} -eq 1 ]]; then
      docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup EXIT
fi

for name in "${CP_NAME}" "${AGENT_NAME}" "${CLI_NAME}"; do
  if docker ps -a --format '{{.Names}}' | grep -Fxq "${name}"; then
    echo "Container ${name} already exists. Remove it or rerun with --cleanup." >&2
    exit 1
  fi
done

docker build "${build_args[@]}" -f "${SCRIPT_DIR}/Dockerfile.systemd-ssh" -t "${SYSTEMD_IMAGE}" "${SCRIPT_DIR}"
docker build "${build_args[@]}" -f "${SCRIPT_DIR}/Dockerfile.cli-runner" -t "${CLI_IMAGE}" "${SCRIPT_DIR}"

CREATED_NETWORK=0
if ! docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1; then
  docker network create "${NETWORK_NAME}" >/dev/null
  CREATED_NETWORK=1
fi

docker run -d \
  --name "${CP_NAME}" \
  --hostname cp \
  --network "${NETWORK_NAME}" \
  --cgroupns=host \
  --privileged \
  --tmpfs /run \
  --tmpfs /run/lock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "${SYSTEMD_IMAGE}" >/dev/null

docker run -d \
  --name "${AGENT_NAME}" \
  --hostname agent \
  --network "${NETWORK_NAME}" \
  --cgroupns=host \
  --privileged \
  --tmpfs /run \
  --tmpfs /run/lock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "${SYSTEMD_IMAGE}" >/dev/null

for container in "${CP_NAME}" "${AGENT_NAME}"; do
  docker cp "${WORK_DIR}/authorized_keys" "${container}:/home/fledx/.ssh/authorized_keys"
  docker exec "${container}" /bin/bash -lc 'chown fledx:fledx /home/fledx/.ssh/authorized_keys && chmod 600 /home/fledx/.ssh/authorized_keys'
done

wait_for_unit() {
  local container=$1
  local unit=$2
  local retries=30

  for ((i = 1; i <= retries; i++)); do
    if docker exec "${container}" systemctl is-active --quiet "${unit}"; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for ${container} ${unit}" >&2
  return 1
}

wait_for_unit "${CP_NAME}" ssh
wait_for_unit "${AGENT_NAME}" ssh

docker exec "${AGENT_NAME}" /bin/bash -lc '
set -euo pipefail
gid=$(stat -c "%g" /var/run/docker.sock)
if getent group "${gid}" >/dev/null 2>&1; then
  exit 0
fi
if getent group dockersock >/dev/null 2>&1; then
  groupadd -g "${gid}" "dockersock-${gid}"
else
  groupadd -g "${gid}" dockersock
fi
'

cli_cmd=(
  docker run --rm
  --name "${CLI_NAME}"
  --network "${NETWORK_NAME}"
  -e HOME=/work
  -e XDG_CONFIG_HOME=/work/.work/config
  -e FLEDX_CLI_CONTROL_PLANE_URL=http://cp:8080
  -v "${SCRIPT_DIR}:/work"
  -v "${BIN_PATH}:/usr/local/bin/fledx:ro"
  "${CLI_IMAGE}"
  /work/bootstrap.sh
)

if [[ ${INSECURE} -eq 1 ]]; then
  cli_cmd+=(--insecure)
fi

"${cli_cmd[@]}"
