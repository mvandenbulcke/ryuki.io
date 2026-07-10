#!/usr/bin/env bash
# Non-destructive validation for the proving-ground configuration.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_INPUT="${1:-$HERE/env.example}"

fail() {
  printf 'validation failed: %s\n' "$1" >&2
  exit 1
}

compose_env_value() {
  local wanted="$1"
  local env_file="$2"
  local line key value trimmed

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    trimmed="${line#"${line%%[![:space:]]*}"}"
    case "$trimmed" in
      ''|'#'*) continue ;;
    esac
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    [[ "$key" == "$wanted" ]] || continue
    value="${line#*=}"
    # Compose treats whitespace followed by # as an inline comment for an
    # unquoted value. The agent parser does not parse these Compose-only keys.
    value="${value%% \#*}"
    printf '%s' "$value"
    return 0
  done < "$env_file"

  return 1
}

[[ -r "$ENV_INPUT" ]] || fail "cannot read $ENV_INPUT"
ENV_FILE="$(cd "$(dirname "$ENV_INPUT")" && pwd)/$(basename "$ENV_INPUT")"

bash -n "$HERE/agent-env.sh" "$HERE/run-agent.sh" "$HERE/destroy-state.sh" \
  "$HERE/validate.sh"
"$HERE/destroy-state.sh" --help >/dev/null
"$HERE/destroy-state.sh" --self-test >/dev/null

# shellcheck source=deploy/proving-ground/agent-env.sh
source "$HERE/agent-env.sh"
if [[ "$ENV_FILE" != "$HERE/env.example" ]]; then
  validate_private_agent_env_file "$ENV_FILE"
fi
load_agent_env "$ENV_FILE"
validate_agent_env

[[ "$PG_AGENT_PLATFORM" == "DEFRA" ]] || \
  fail "PG_AGENT_PLATFORM must be DEFRA for the supplied proving-ground target"
EXPECTED_BACKEND_HCL='terraform { backend "local" { path = "{STATE_DIR}/terraform-{STATE_KEY}.tfstate" } }'
[[ "$PG_AGENT_BACKEND_HCL" == "$EXPECTED_BACKEND_HCL" ]] || \
  fail "the proving ground requires the bundled isolated local backend template"
[[ "$PG_AGENT_BACKEND_HCL" == *'{STATE_KEY}'* ]] || \
  fail "backend template lost {STATE_KEY}"

rendered_backend="$(render_agent_backend_hcl "$PG_AGENT_BACKEND_HCL" "/tmp/ryuki state")"
if [[ "$PG_AGENT_BACKEND_HCL" == *'{STATE_DIR}'* ]]; then
  [[ "$rendered_backend" == *'/tmp/ryuki state'* ]] || \
    fail "local backend template did not render {STATE_DIR}"
fi
[[ "$rendered_backend" != *'{STATE_DIR}'* ]] || \
  fail "rendered backend still contains {STATE_DIR}"
[[ "$rendered_backend" == *'{STATE_KEY}'* ]] || \
  fail "rendering {STATE_DIR} also changed {STATE_KEY}"

# Exercise literal parsing with spaces and shell metacharacters. No value in
# this fixture may be evaluated, and Compose-only keys must not be assigned.
umask 077
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-pg-validate.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT
PRIVATE_FIXTURE="$TEMP_DIR/private.env"
: > "$PRIVATE_FIXTURE"
chmod 600 "$PRIVATE_FIXTURE"
validate_private_agent_env_file "$PRIVATE_FIXTURE"
chmod 640 "$PRIVATE_FIXTURE"
if validate_private_agent_env_file "$PRIVATE_FIXTURE" 2>/dev/null; then
  fail "group-readable environment file passed the permission guard"
fi
chmod 600 "$PRIVATE_FIXTURE"
MARKER="$TEMP_DIR/evaluated"
LITERAL_HCL="terraform { backend \"local\" { path = \"{STATE_DIR}/literal ; \$(touch \"$MARKER\") # {STATE_KEY}.tfstate\" } }"
{
  printf '%s\n' 'PG_DB_PASSWORD=x'
  printf '%s\n' 'PG_VAULT_TOKEN=control-plane-only'
  printf '%s\n' 'PG_LOCAL_USERS=control-plane-only'
  printf '%s\n' 'PG_AGENT_PLATFORM=DEFRA'
  printf '%s\n' 'PG_AGENT_ALLOW_LIVE=false'
  printf 'PG_AGENT_BACKEND_HCL=%s\n' "$LITERAL_HCL"
  printf '%s\n' 'PG_VSPHERE_USER=literal user'
  printf '%s\n' 'PG_VSPHERE_PASSWORD=x;y'
  printf '%s\n' 'PG_VSPHERE_SERVER=literal$(hostname)'
} > "$TEMP_DIR/literal.env"

unset PG_DB_PASSWORD PG_VAULT_TOKEN PG_LOCAL_USERS
load_agent_env "$TEMP_DIR/literal.env"
validate_agent_env
[[ "$PG_AGENT_BACKEND_HCL" == "$LITERAL_HCL" ]] || fail "HCL was not parsed literally"
[[ "$PG_VSPHERE_USER" == 'literal user' ]] || fail "spaces were not preserved"
[[ "$PG_VSPHERE_PASSWORD" == 'x;y' ]] || fail "semicolon was not preserved"
[[ "$PG_VSPHERE_SERVER" == 'literal$(hostname)' ]] || fail "command text was not preserved"
[[ ! -e "$MARKER" ]] || fail "environment value was evaluated as shell code"
[[ -z "${PG_DB_PASSWORD+x}" && -z "${PG_VAULT_TOKEN+x}" && -z "${PG_LOCAL_USERS+x}" ]] || \
  fail "control-plane values were assigned by the agent parser"

# Restore the selected file's values after the isolated hostile-value fixture.
load_agent_env "$ENV_FILE"
validate_agent_env

LOCAL_USERS="$(compose_env_value PG_LOCAL_USERS "$ENV_FILE")" || \
  fail "PG_LOCAL_USERS is missing"
IFS=',' read -r -a ACCOUNTS <<< "$LOCAL_USERS"
[[ "${#ACCOUNTS[@]}" -ge 2 ]] || fail "PG_LOCAL_USERS needs at least two principals"

REQUESTER_USER=""
ADMIN_USER=""
REQUESTER_COUNT=0
ADMIN_COUNT=0
for account in "${ACCOUNTS[@]}"; do
  IFS=':' read -r username account_value roles extra <<< "$account"
  [[ -n "$username" && -n "$account_value" && -n "$roles" && -z "${extra:-}" ]] || \
    fail "PG_LOCAL_USERS contains a malformed account"
  case "|$roles|" in
    *'|Requester|'*)
      [[ "$roles" == 'Requester' ]] || \
        fail "the proving-ground requester account must have only the Requester role"
      REQUESTER_USER="$username"
      REQUESTER_COUNT=$((REQUESTER_COUNT + 1))
      ;;
  esac
  case "|$roles|" in
    *'|PlatformAdmin|'*)
      [[ "$roles" == 'PlatformAdmin' ]] || \
        fail "the proving-ground admin account must have only the PlatformAdmin role"
      ADMIN_USER="$username"
      ADMIN_COUNT=$((ADMIN_COUNT + 1))
      ;;
  esac
done
[[ "$REQUESTER_COUNT" -eq 1 ]] || fail "PG_LOCAL_USERS needs exactly one Requester account"
[[ "$ADMIN_COUNT" -eq 1 ]] || fail "PG_LOCAL_USERS needs exactly one PlatformAdmin account"
[[ "$REQUESTER_USER" != "$ADMIN_USER" ]] || fail "requester and approver must be distinct"

if [[ "$ENV_FILE" != "$HERE/env.example" ]]; then
  DB_VALUE="$(compose_env_value PG_DB_PASSWORD "$ENV_FILE")" || \
    fail "PG_DB_PASSWORD is missing"
  VAULT_VALUE="$(compose_env_value PG_VAULT_TOKEN "$ENV_FILE")" || \
    fail "PG_VAULT_TOKEN is missing"
  [[ -n "$DB_VALUE" ]] || fail "PG_DB_PASSWORD is empty"
  [[ -n "$VAULT_VALUE" && "$VAULT_VALUE" != 'change-me-vault-root' ]] || \
    fail "replace the PG_VAULT_TOKEN placeholder"
  [[ "$LOCAL_USERS" != *'change-me-maker'* && "$LOCAL_USERS" != *'change-me-checker'* ]] || \
    fail "replace both PG_LOCAL_USERS placeholders"

  if [[ "$PG_AGENT_ALLOW_LIVE" == "true" ]]; then
    [[ -n "$PG_VSPHERE_USER" ]] || fail "live mode requires PG_VSPHERE_USER"
    [[ -n "$PG_VSPHERE_PASSWORD" ]] || fail "live mode requires PG_VSPHERE_PASSWORD"
    [[ -n "$PG_VSPHERE_SERVER" ]] || fail "live mode requires PG_VSPHERE_SERVER"
  fi
fi

grep -Fq 'http://localhost:8080/ready' "$HERE/compose.yaml" || \
  fail "platform-api healthcheck must gate on /ready"
grep -Fq 'RYUKI_SESSION__COOKIE_SECURE: "false"' "$HERE/compose.yaml" || \
  fail "loopback HTTP proving ground must disable Secure API cookies explicitly"
for binding in \
  '127.0.0.1:15432:5432' '127.0.0.1:18200:8200' \
  '127.0.0.1:18081:8080' '127.0.0.1:18001:8080'; do
  grep -Fq -- "\"$binding\"" "$HERE/compose.yaml" || \
    fail "published proving-ground port must stay loopback-only: $binding"
done
command -v docker >/dev/null 2>&1 || fail "docker is required for Compose validation"

# env.example intentionally leaves the database value empty. Supply a temporary
# process-local placeholder only while validating the committed template.
if [[ "$ENV_FILE" == "$HERE/env.example" ]]; then
  printf -v PG_DB_PASSWORD '%s' 'local-placeholder'
  export PG_DB_PASSWORD
fi
docker compose --env-file "$ENV_FILE" -f "$HERE/compose.yaml" config --quiet

printf 'proving-ground validation passed (%s)\n' "$ENV_FILE"
