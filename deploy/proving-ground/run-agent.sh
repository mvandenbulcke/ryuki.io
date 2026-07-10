#!/usr/bin/env bash
# Run the execution agent on the HOST against the proving-ground stack.
#
# The agent deliberately runs outside compose: agents live next to the
# infrastructure they execute against (your vCenter network), and the
# agent's fail-closed transport gate refuses cleartext non-loopback
# control-plane URLs in live mode — http://localhost:18081 is loopback and
# passes. State (Ed25519 key, agent token, terraform state) persists under
# ./agent-state/, which is gitignored.
#
# First run self-registers the agent (pending approval); approve it as a
# PlatformAdmin, then run this script again to start the job loop:
#   curl -s -X POST http://localhost:18081/api/admin/agents/<platform>/approve \
#     -H "Content-Type: application/json" -H "X-Ryuki-Session-Id: <session>" \
#     -d '{"platform": "<platform>"}'
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
STATE_DIR="$HERE/agent-state"
mkdir -p "$STATE_DIR"

if [[ ! -f "$HERE/.env" ]]; then
  echo "error: $HERE/.env not found — copy env.example to .env and fill it in" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source "$HERE/.env"
set +a

command -v terraform >/dev/null || {
  echo "error: terraform not found on PATH (live and dry runs both need it)" >&2
  exit 1
}

AGENT_BIN="$REPO/target/release/ryuki-agent"
if [[ ! -x "$AGENT_BIN" ]]; then
  echo "building ryuki-agent (release)..."
  (cd "$REPO" && cargo build --release -p ryuki-agent)
fi

export RYUKI_AGENT_CP_URL="http://localhost:18081"
export RYUKI_AGENT_PLATFORM="${PG_AGENT_PLATFORM:?PG_AGENT_PLATFORM missing in .env}"
export RYUKI_AGENT_ALLOW_LIVE="${PG_AGENT_ALLOW_LIVE:-false}"
export RYUKI_AGENT_KEY_PATH="$STATE_DIR/agent.key"
export RYUKI_AGENT_TOKEN_PATH="$STATE_DIR/agent.token"
export RYUKI_AGENT_BACKEND_HCL="${PG_AGENT_BACKEND_HCL//\{STATE_DIR\}/$STATE_DIR}"

# Declared secret variables for the vsphere offerings; the agent refuses
# fail-closed (signed, value-free) if a declared one is missing or empty.
[[ -n "${PG_VSPHERE_USER:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_USER="$PG_VSPHERE_USER"
[[ -n "${PG_VSPHERE_PASSWORD:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_PASSWORD="$PG_VSPHERE_PASSWORD"
[[ -n "${PG_VSPHERE_SERVER:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_SERVER="$PG_VSPHERE_SERVER"

# First boot: no token anywhere -> self-register (exits 0 pending approval).
if [[ -z "${RYUKI_AGENT_TOKEN:-}" && ! -f "$RYUKI_AGENT_TOKEN_PATH" ]]; then
  export RYUKI_AGENT_SELF_REGISTER=true
  echo "no agent token found — self-registering '$RYUKI_AGENT_PLATFORM' (will exit pending approval)"
fi

exec "$AGENT_BIN"
