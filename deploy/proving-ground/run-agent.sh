#!/usr/bin/env bash
# Run the execution agent on the HOST against the proving-ground stack.
#
# The agent deliberately runs outside compose: agents live next to the
# infrastructure they execute against (your vCenter network), and the
# agent's fail-closed transport gate refuses cleartext non-loopback
# control-plane URLs in live mode — http://localhost:18081 is loopback and
# passes. State (Ed25519 key, agent token, Terraform state) persists under
# ./agent-state/, which is gitignored.
#
# First run self-registers the agent (pending approval); approve it as a
# PlatformAdmin, then run this script again to start the job loop:
#   curl -s -X POST http://localhost:18081/api/admin/agents/<agent-id>/approve \
#     -H "Content-Type: application/json" -H "X-Ryuki-Session-Id: <session>" \
#     -d '{"platform": "DEFRA"}'
set -euo pipefail
umask 077

# Re-exec once before reading .env so inherited tokens, provider credentials,
# Terraform controls, and unrelated secrets cannot reach the proving-ground
# agent. Only non-secret process basics and this sentinel cross the boundary.
if [[ "${RYUKI_PG_ENV_ISOLATED-}" != "1" ]]; then
  script_path="${BASH_SOURCE[0]}"
  [[ "$script_path" == /* ]] || script_path="$PWD/$script_path"
  env_bin="$(command -v env)"
  bash_bin="$(command -v bash)"
  clean_env=(
    "$env_bin" -i
    "PATH=${PATH:?PATH is required}"
    "HOME=${HOME:-/tmp}"
    "TMPDIR=${TMPDIR:-/tmp}"
    "RYUKI_PG_ENV_ISOLATED=1"
  )
  [[ -n "${LANG-}" ]] && clean_env+=("LANG=$LANG")
  [[ -n "${LC_ALL-}" ]] && clean_env+=("LC_ALL=$LC_ALL")
  exec "${clean_env[@]}" "$bash_bin" "$script_path" "$@"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
STATE_DIR="$HERE/agent-state"
mkdir -p "$STATE_DIR"

if [[ ! -f "$HERE/.env" ]]; then
  echo "error: $HERE/.env not found; copy env.example to .env and fill it in" >&2
  exit 1
fi

# shellcheck source=deploy/proving-ground/agent-env.sh
source "$HERE/agent-env.sh"
validate_private_agent_env_file "$HERE/.env"
load_agent_env "$HERE/.env"
validate_agent_env
[[ "$PG_AGENT_PLATFORM" == "DEFRA" ]] || {
  echo "error: proving-ground agent platform must be DEFRA" >&2
  exit 1
}
EXPECTED_BACKEND_HCL='terraform { backend "local" { path = "{STATE_DIR}/terraform-{STATE_KEY}.tfstate" } }'
[[ "$PG_AGENT_BACKEND_HCL" == "$EXPECTED_BACKEND_HCL" ]] || {
  echo "error: proving-ground agent requires the bundled isolated local backend template" >&2
  exit 1
}

if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && -n "$PG_VSPHERE_USER" && \
  -n "$PG_VSPHERE_SERVER" ]]; then
  PROVIDER_CONTEXT_FILE="$STATE_DIR/provider-context.sha256"
  PROVIDER_CONTEXT="$(provider_context_fingerprint "$PG_VSPHERE_USER" "$PG_VSPHERE_SERVER")"
  if [[ -f "$PROVIDER_CONTEXT_FILE" ]]; then
    IFS= read -r PINNED_PROVIDER_CONTEXT < "$PROVIDER_CONTEXT_FILE"
    [[ "$PINNED_PROVIDER_CONTEXT" == "$PROVIDER_CONTEXT" ]] || {
      echo "error: vSphere endpoint/account differs from the pinned proving-ground context" >&2
      exit 1
    }
  else
    printf '%s\n' "$PROVIDER_CONTEXT" > "$PROVIDER_CONTEXT_FILE"
    chmod 600 "$PROVIDER_CONTEXT_FILE"
  fi
fi

command -v terraform >/dev/null || {
  echo "error: terraform not found on PATH (live and dry runs both need it)" >&2
  exit 1
}

AGENT_BIN="$REPO/target/release/ryuki-agent"
echo "building current ryuki-agent checkout (release)..."
(cd "$REPO" && cargo build --release -p ryuki-agent)

export RYUKI_AGENT_CP_URL="http://localhost:18081"
export RYUKI_AGENT_PLATFORM="${PG_AGENT_PLATFORM:?PG_AGENT_PLATFORM missing in .env}"
export RYUKI_AGENT_ALLOW_LIVE="${PG_AGENT_ALLOW_LIVE:-false}"
export RYUKI_AGENT_KEY_PATH="$STATE_DIR/agent.key"
export RYUKI_AGENT_TOKEN_PATH="$STATE_DIR/agent.token"
export RYUKI_AGENT_BACKEND_HCL
RYUKI_AGENT_BACKEND_HCL="$(render_agent_backend_hcl "$PG_AGENT_BACKEND_HCL" "$STATE_DIR")"

# Declared secret variables for the vsphere offerings; the agent refuses
# fail-closed (signed, value-free) if a declared one is missing or empty.
unset RYUKI_LIVE_CRED_VSPHERE_USER RYUKI_LIVE_CRED_VSPHERE_PASSWORD \
  RYUKI_LIVE_CRED_VSPHERE_SERVER
[[ -n "${PG_VSPHERE_USER:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_USER="$PG_VSPHERE_USER"
[[ -n "${PG_VSPHERE_PASSWORD:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_PASSWORD="$PG_VSPHERE_PASSWORD" # secret-scan-allow: reviewed env reference
[[ -n "${PG_VSPHERE_SERVER:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_SERVER="$PG_VSPHERE_SERVER"

# Do not pass PG_* staging variables, or inherited control-plane secrets,
# through exec. The agent receives only its explicit RYUKI_* contract.
unset PG_AGENT_PLATFORM PG_AGENT_ALLOW_LIVE PG_AGENT_BACKEND_HCL
unset PG_VSPHERE_USER PG_VSPHERE_PASSWORD PG_VSPHERE_SERVER
unset PG_DB_PASSWORD PG_VAULT_TOKEN PG_LOCAL_USERS

# This proving ground owns its persisted token file. Ignore inherited token or
# self-registration overrides so a parent shell cannot switch agent identity.
unset RYUKI_AGENT_TOKEN RYUKI_AGENT_SELF_REGISTER

# First boot: no token anywhere -> self-register (exits 0 pending approval).
if [[ -z "${RYUKI_AGENT_TOKEN:-}" && ! -f "$RYUKI_AGENT_TOKEN_PATH" ]]; then
  export RYUKI_AGENT_SELF_REGISTER=true
  echo "no agent token found; self-registering '$RYUKI_AGENT_PLATFORM' (will exit pending approval)"
fi

unset RYUKI_PG_ENV_ISOLATED
exec "$AGENT_BIN"
