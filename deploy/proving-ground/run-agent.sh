#!/usr/bin/env bash
# Run the execution agent on the HOST against the proving-ground stack.
#
# The agent deliberately runs outside compose: agents live next to the
# infrastructure they execute against (your vCenter network), and the
# agent's fail-closed transport gate refuses cleartext control-plane URLs
# unless this script explicitly opts into the narrow loopback exception for
# http://127.0.0.1:18081. State (Ed25519 key, agent token, Terraform state)
# persists under ./agent-state/, which is gitignored.
#
# First boot is deliberately two-authority: invoke
#   ./run-agent.sh --stage-enrollment /absolute/path/to/admin.headers
# with a private, temporary PlatformAdmin session header. The script creates or
# loads the durable Ed25519 key, asks the control plane for a short-lived
# challenge bound to that exact public key, and immediately self-registers.
# Approval remains a separate roster review in the portal/API.
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

STAGE_ENROLLMENT=false
ENROLLMENT_SESSION_HEADER=""
case "$#" in
  0) ;;
  1)
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
      printf 'usage: %s [--stage-enrollment /absolute/path/to/admin.headers]\n' \
        "${0##*/}"
      exit 0
    fi
    printf 'error: unsupported argument; use --help for usage\n' >&2
    exit 2
    ;;
  2)
    [[ "$1" == "--stage-enrollment" ]] || {
      printf 'error: unsupported arguments; use --help for usage\n' >&2
      exit 2
    }
    STAGE_ENROLLMENT=true
    ENROLLMENT_SESSION_HEADER="$2"
    ;;
  *)
    printf 'error: unsupported arguments; use --help for usage\n' >&2
    exit 2
    ;;
esac

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

# Read only the non-secret acceptance revision before any repository-owned
# helper is sourced. The full private environment is deliberately loaded only
# after the exact source, dependency lock, and freshly built artifact are bound.
bootstrap_env_value() {
  local wanted="$1"
  local env_file="$2"
  local line key value trimmed
  local found=false

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    trimmed="${line#"${line%%[![:space:]]*}"}"
    case "$trimmed" in
      ''|'#'*) continue ;;
    esac
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    [[ "$key" == "$wanted" ]] || continue
    [[ "$found" == "false" ]] || fail "duplicate $wanted in $env_file"
    value="${line#*=}"
    value="${value%% \#*}"
    found=true
  done < "$env_file"
  [[ "$found" == "true" ]] || fail "$wanted is missing from $env_file"
  printf '%s' "$value"
}

sha256_file() {
  local file="$1"
  local output digest remainder
  output="$("$SHASUM_BIN" -a 256 -- "$file")" || \
    fail "cannot hash $file"
  read -r digest remainder <<< "$output"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid SHA-256 output for $file"
  printf '%s' "$digest"
}

git_command() {
  GIT_NO_REPLACE_OBJECTS=1 "$GIT_BIN" -C "$REPO" \
    -c core.fsmonitor=false -c core.untrackedCache=false "$@"
}

source_manifest_sha256() {
  local output digest remainder
  output="$(git_command ls-tree -r -z --full-tree "$ACCEPTANCE_REVISION" | \
    "$SHASUM_BIN" -a 256)" || fail "cannot hash the accepted source manifest"
  read -r digest remainder <<< "$output"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid accepted source manifest digest"
  printf '%s' "$digest"
}

verify_signed_clean_checkout() {
  local root revision tree status signer signature_status configured_signer

  root="$(git_command rev-parse --show-toplevel)" || fail "cannot resolve repository root"
  [[ "$root" == "$REPO" ]] || fail "runner is not executing from the expected repository root"
  revision="$(git_command rev-parse --verify 'HEAD^{commit}')" || \
    fail "cannot resolve the checked-out commit"
  [[ "$revision" == "$ACCEPTANCE_REVISION" ]] || \
    fail "checkout does not match PG_ACCEPTANCE_REVISION"
  status="$(git_command status --porcelain=v1 --untracked-files=all)" || \
    fail "cannot inspect checkout cleanliness"
  [[ -z "$status" ]] || fail "accepted checkout contains tracked or untracked changes"

  configured_signer="$(git_command config --local --get \
    ryuki.provingGroundAcceptanceSignerFingerprint)" || \
    fail "configure the independently approved acceptance signer fingerprint"
  [[ "$configured_signer" =~ ^[0-9A-F]{40}$ ]] || \
    fail "acceptance signer fingerprint must be one full uppercase OpenPGP fingerprint"
  git_command verify-commit "$ACCEPTANCE_REVISION" >/dev/null 2>&1 || \
    fail "PG_ACCEPTANCE_REVISION is not a valid signed commit"
  signature_status="$(git_command show -s --format=%G? "$ACCEPTANCE_REVISION")" || \
    fail "cannot read acceptance signature status"
  signer="$(git_command show -s --format=%GF "$ACCEPTANCE_REVISION")" || \
    fail "cannot read acceptance signer fingerprint"
  [[ "$signature_status" == "G" && "$signer" == "$configured_signer" ]] || \
    fail "acceptance commit signer is not the configured trusted signer"

  tree="$(git_command rev-parse --verify "${ACCEPTANCE_REVISION}^{tree}")" || \
    fail "cannot resolve the accepted source tree"
  if [[ -n "${SOURCE_TREE_ID-}" ]]; then
    [[ "$tree" == "$SOURCE_TREE_ID" ]] || fail "accepted source tree changed"
    [[ "$(source_manifest_sha256)" == "$SOURCE_MANIFEST_SHA256" ]] || \
      fail "accepted source manifest digest changed"
  fi
}

verify_agent_trust_binding() {
  verify_signed_clean_checkout
  [[ ! -L "$REPO/Cargo.lock" && -f "$REPO/Cargo.lock" ]] || \
    fail "Cargo.lock must be a regular non-symlink file"
  [[ "$(sha256_file "$REPO/Cargo.lock")" == "$DEPENDENCY_LOCK_SHA256" ]] || \
    fail "Cargo.lock digest changed after the accepted build"
  [[ ! -L "$AGENT_BIN" && -f "$AGENT_BIN" && -x "$AGENT_BIN" ]] || \
    fail "accepted agent artifact is missing or unsafe"
  [[ "$(sha256_file "$AGENT_BIN")" == "$AGENT_ARTIFACT_SHA256" ]] || \
    fail "accepted agent artifact digest changed"
  [[ ! -L "$BUILD_MANIFEST" && -f "$BUILD_MANIFEST" ]] || \
    fail "agent build manifest is missing or unsafe"
  [[ "$(sha256_file "$BUILD_MANIFEST")" == "$BUILD_MANIFEST_SHA256" ]] || \
    fail "agent build manifest digest changed"
}

[[ ! -L "$HERE/.env" && -f "$HERE/.env" && -r "$HERE/.env" ]] || \
  fail "$HERE/.env not found or unsafe; copy env.example to .env and fill it in"
ACCEPTANCE_REVISION="$(bootstrap_env_value PG_ACCEPTANCE_REVISION "$HERE/.env")"
[[ "$ACCEPTANCE_REVISION" =~ ^[0-9a-f]{40}$ ]] || \
  fail "PG_ACCEPTANCE_REVISION must be one full lowercase commit SHA"

GIT_BIN="$(command -v git)" || fail "git is required to verify accepted source"
CARGO_BIN="$(command -v cargo)" || fail "cargo is required to build the accepted agent"
SHASUM_BIN="$(command -v shasum)" || fail "shasum is required to bind build digests"
TAR_BIN="$(command -v tar)" || fail "tar is required to materialize accepted source"

verify_signed_clean_checkout
# The helper is now covered by the signed, exact clean-tree proof. Source it
# before creating or using private state, but still before loading any .env
# value other than the non-secret acceptance revision.
# shellcheck source=deploy/proving-ground/agent-env.sh
source "$HERE/agent-env.sh"
validate_private_agent_env_file "$HERE/.env"
SOURCE_TREE_ID="$(git_command rev-parse --verify "${ACCEPTANCE_REVISION}^{tree}")"
SOURCE_MANIFEST_SHA256="$(source_manifest_sha256)"
[[ ! -L "$REPO/Cargo.lock" && -f "$REPO/Cargo.lock" ]] || \
  fail "Cargo.lock must be a regular non-symlink file"
DEPENDENCY_LOCK_SHA256="$(sha256_file "$REPO/Cargo.lock")"

if [[ ! -e "$STATE_DIR" && ! -L "$STATE_DIR" ]]; then
  mkdir -m 700 "$STATE_DIR"
fi
validate_private_agent_state_dir "$STATE_DIR"
for cargo_config in "$REPO/.cargo/config" "$REPO/.cargo/config.toml"; do
  if [[ -e "$cargo_config" || -L "$cargo_config" ]]; then
    git_command ls-files --error-unmatch "${cargo_config#"$REPO/"}" >/dev/null 2>&1 || \
      fail "untracked repository Cargo configuration is not accepted: $cargo_config"
  fi
done
AGENT_BIN="$STATE_DIR/ryuki-agent"
BUILD_MANIFEST="$STATE_DIR/agent-build.manifest"
BUILD_ROOT="$(mktemp -d "$STATE_DIR/.agent-build.XXXXXX")" || \
  fail "cannot create private disposable build directory"
STAGED_AGENT="$STATE_DIR/.ryuki-agent.$$"
MANIFEST_TEMP=""
cleanup_build() {
  rm -rf "$BUILD_ROOT"
  rm -f "$STAGED_AGENT"
  [[ -z "$MANIFEST_TEMP" ]] || rm -f "$MANIFEST_TEMP"
}
trap cleanup_build EXIT HUP INT TERM

echo "building the exact signed acceptance revision (locked, offline, release)..."
SOURCE_DATE_EPOCH="$(git_command show -s --format=%ct "$ACCEPTANCE_REVISION")"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || fail "invalid acceptance commit timestamp"
SOURCE_ARCHIVE="$BUILD_ROOT/accepted-source.tar"
BUILD_SOURCE="$BUILD_ROOT/source"
mkdir -m 700 "$BUILD_SOURCE"
git_command archive --format=tar --output="$SOURCE_ARCHIVE" "$ACCEPTANCE_REVISION" || \
  fail "cannot materialize the accepted source archive"
SOURCE_ARCHIVE_SHA256="$(sha256_file "$SOURCE_ARCHIVE")"
"$TAR_BIN" -xf "$SOURCE_ARCHIVE" -C "$BUILD_SOURCE" || \
  fail "cannot extract the accepted source archive"
[[ "$(sha256_file "$BUILD_SOURCE/Cargo.lock")" == "$DEPENDENCY_LOCK_SHA256" ]] || \
  fail "materialized dependency lock differs from the accepted checkout"
(
  export CARGO_INCREMENTAL=0
  export CARGO_TARGET_DIR="$BUILD_ROOT/target"
  export SOURCE_DATE_EPOCH
  cd "$BUILD_SOURCE"
  "$CARGO_BIN" build --locked --offline --release -p ryuki-agent
)
verify_signed_clean_checkout
BUILT_AGENT="$BUILD_ROOT/target/release/ryuki-agent"
[[ ! -L "$BUILT_AGENT" && -f "$BUILT_AGENT" && -x "$BUILT_AGENT" ]] || \
  fail "locked build did not produce one regular executable agent"
[[ ! -e "$STAGED_AGENT" && ! -L "$STAGED_AGENT" ]] || \
  fail "private staged agent path already exists"
mv "$BUILT_AGENT" "$STAGED_AGENT"
chmod 500 "$STAGED_AGENT"
[[ ! -d "$AGENT_BIN" ]] || fail "accepted agent path is a directory"
mv -f "$STAGED_AGENT" "$AGENT_BIN"
AGENT_ARTIFACT_SHA256="$(sha256_file "$AGENT_BIN")"

MANIFEST_TEMP="$STATE_DIR/.agent-build.manifest.$$"
[[ ! -e "$MANIFEST_TEMP" && ! -L "$MANIFEST_TEMP" ]] || \
  fail "private build manifest staging path already exists"
(set -o noclobber; : > "$MANIFEST_TEMP") || fail "cannot stage private build manifest"
chmod 600 "$MANIFEST_TEMP"
printf '%s\n' \
  "revision=$ACCEPTANCE_REVISION" \
  "source_tree=$SOURCE_TREE_ID" \
  "source_manifest_sha256=$SOURCE_MANIFEST_SHA256" \
  "source_archive_sha256=$SOURCE_ARCHIVE_SHA256" \
  "cargo_lock_sha256=$DEPENDENCY_LOCK_SHA256" \
  "agent_sha256=$AGENT_ARTIFACT_SHA256" > "$MANIFEST_TEMP"
[[ ! -d "$BUILD_MANIFEST" ]] || fail "agent build manifest path is a directory"
mv -f "$MANIFEST_TEMP" "$BUILD_MANIFEST"
BUILD_MANIFEST_SHA256="$(sha256_file "$BUILD_MANIFEST")"
verify_agent_trust_binding
cleanup_build
trap - EXIT HUP INT TERM

validate_private_agent_env_file "$BUILD_MANIFEST"
load_agent_env "$HERE/.env"
validate_agent_env
verify_agent_trust_binding
[[ "$PG_AGENT_PLATFORM" == "DEFRA" ]] || {
  echo "error: proving-ground agent platform must be DEFRA" >&2
  exit 1
}
EXPECTED_BACKEND_HCL='terraform { backend "local" { path = "{STATE_DIR}/terraform-{STATE_KEY}.tfstate" } }'
[[ "$PG_AGENT_BACKEND_HCL" == "$EXPECTED_BACKEND_HCL" ]] || {
  echo "error: proving-ground agent requires the bundled isolated local backend template" >&2
  exit 1
}
stage_approved_executable terraform "$PG_TERRAFORM_EXECUTABLE" \
  "$PG_TERRAFORM_EXPECTED_VERSION" "$PG_TERRAFORM_EXECUTABLE_SHA256" \
  "$STATE_DIR"
APPROVED_TERRAFORM_BIN="$APPROVED_EXECUTABLE_PATH"
APPROVED_TERRAFORM_SHA256="$APPROVED_EXECUTABLE_SHA256"
stage_approved_executable ansible-playbook "$PG_ANSIBLE_PLAYBOOK_EXECUTABLE" \
  "$PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION" \
  "$PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256" "$STATE_DIR"
APPROVED_ANSIBLE_PLAYBOOK_BIN="$APPROVED_EXECUTABLE_PATH"
APPROVED_ANSIBLE_PLAYBOOK_SHA256="$APPROVED_EXECUTABLE_SHA256"

if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && -n "$PG_PROVIDER_AUTHORITY_ID" && \
  -n "$PG_PROVIDER_AUTHORITY_VERSION" ]]; then
  PROVIDER_AUTHORITY_FILE="$STATE_DIR/provider-authority.ref"
  PROVIDER_AUTHORITY="$(provider_authority_record \
    "$PG_PROVIDER_AUTHORITY_ID" "$PG_PROVIDER_AUTHORITY_VERSION")"
  if [[ -f "$PROVIDER_AUTHORITY_FILE" ]]; then
    PINNED_PROVIDER_AUTHORITY="$(cat "$PROVIDER_AUTHORITY_FILE")"
    [[ "$PINNED_PROVIDER_AUTHORITY" == "$PROVIDER_AUTHORITY" ]] || {
      echo "error: provider authority reference/version differs from the pinned proving-ground authority" >&2
      exit 1
    }
  else
    printf '%s\n' "$PROVIDER_AUTHORITY" > "$PROVIDER_AUTHORITY_FILE"
    chmod 600 "$PROVIDER_AUTHORITY_FILE"
  fi
fi

if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && \
  -n "$PG_BACKEND_CREDENTIAL_AUTHORITY_ID" && \
  -n "$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION" ]]; then
  BACKEND_CREDENTIAL_AUTHORITY_FILE="$STATE_DIR/backend-credential-authority.ref"
  BACKEND_CREDENTIAL_AUTHORITY="$(backend_credential_authority_record \
    "$PG_BACKEND_CREDENTIAL_AUTHORITY_ID" \
    "$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION")"
  if [[ -f "$BACKEND_CREDENTIAL_AUTHORITY_FILE" ]]; then
    PINNED_BACKEND_CREDENTIAL_AUTHORITY="$(cat "$BACKEND_CREDENTIAL_AUTHORITY_FILE")"
    [[ "$PINNED_BACKEND_CREDENTIAL_AUTHORITY" == "$BACKEND_CREDENTIAL_AUTHORITY" ]] || {
      echo "error: backend credential authority reference/revision differs from the pinned proving-ground authority" >&2
      exit 1
    }
  else
    printf '%s\n' "$BACKEND_CREDENTIAL_AUTHORITY" > "$BACKEND_CREDENTIAL_AUTHORITY_FILE"
    chmod 600 "$BACKEND_CREDENTIAL_AUTHORITY_FILE"
  fi
fi

export RYUKI_AGENT_CP_URL="http://127.0.0.1:18081"
# Cleartext transport remains denied by default in the agent. This proving
# ground opts in only because the fixed control-plane URL above is loopback.
export RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK=true
export RYUKI_AGENT_PLATFORM="${PG_AGENT_PLATFORM:?PG_AGENT_PLATFORM missing in .env}"
export RYUKI_AGENT_ALLOW_LIVE="${PG_AGENT_ALLOW_LIVE:-false}"
export RYUKI_AGENT_KEY_PATH="$STATE_DIR/agent.key"
export RYUKI_AGENT_TOKEN_PATH="$STATE_DIR/agent.token"
ENROLLMENT_FILE="$STATE_DIR/enrollment-challenge.json"
export RYUKI_AGENT_BACKEND_HCL
RYUKI_AGENT_BACKEND_HCL="$(render_agent_backend_hcl "$PG_AGENT_BACKEND_HCL" "$STATE_DIR")"
export RYUKI_AGENT_LOCAL_STATE_ROOT="$STATE_DIR"
export RYUKI_TERRAFORM_EXECUTABLE="$APPROVED_TERRAFORM_BIN"
export RYUKI_TERRAFORM_EXPECTED_VERSION="$PG_TERRAFORM_EXPECTED_VERSION"
export RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE="$APPROVED_ANSIBLE_PLAYBOOK_BIN"
export RYUKI_ANSIBLE_PLAYBOOK_EXPECTED_VERSION="$PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION"
export RYUKI_TERRAFORM_EXECUTABLE_SHA256="$APPROVED_TERRAFORM_SHA256"
export RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256="$APPROVED_ANSIBLE_PLAYBOOK_SHA256"

# Do not pass PG_* staging variables, or inherited control-plane secrets,
# through exec. The agent receives only its explicit RYUKI_* contract.
unset PG_AGENT_PLATFORM PG_AGENT_ALLOW_LIVE PG_AGENT_BACKEND_HCL
unset PG_TERRAFORM_EXECUTABLE PG_TERRAFORM_EXPECTED_VERSION \
  PG_TERRAFORM_EXECUTABLE_SHA256
unset PG_ANSIBLE_PLAYBOOK_EXECUTABLE PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION \
  PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256
unset PG_DB_PASSWORD PG_VAULT_TOKEN PG_LOCAL_USERS

# This proving ground owns its persisted key, token, and one-time challenge.
# Ignore inherited overrides so a parent shell cannot switch agent identity or
# inject an enrollment authority that was never created by this local flow.
unset RYUKI_AGENT_TOKEN RYUKI_AGENT_SELF_REGISTER
unset RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID RYUKI_AGENT_ENROLLMENT_CHALLENGE

if [[ "$STAGE_ENROLLMENT" == "true" ]]; then
  [[ ! -e "$RYUKI_AGENT_TOKEN_PATH" && ! -L "$RYUKI_AGENT_TOKEN_PATH" ]] || {
    printf 'error: an agent token already exists; enrollment staging is not allowed\n' >&2
    exit 1
  }
  [[ ! -e "$ENROLLMENT_FILE" && ! -L "$ENROLLMENT_FILE" ]] || {
    printf 'error: staged enrollment already exists; consume it or wait for expiry before restaging\n' >&2
    exit 1
  }
  verify_agent_trust_binding
  validate_agent_enrollment_session_header "$ENROLLMENT_SESSION_HEADER"
  HEADER_DIR="$(cd "$(dirname "$ENROLLMENT_SESSION_HEADER")" && pwd -P)"
  CANONICAL_SESSION_HEADER="$HEADER_DIR/$(basename "$ENROLLMENT_SESSION_HEADER")"
  [[ "$CANONICAL_SESSION_HEADER" == "$ENROLLMENT_SESSION_HEADER" ]] || {
    printf 'error: enrollment session header path must already be canonical\n' >&2
    exit 1
  }
  case "$CANONICAL_SESSION_HEADER" in
    "$REPO"/*)
      printf 'error: enrollment session credentials must be staged outside the repository\n' >&2
      exit 1
      ;;
  esac
  CURL_BIN="$(command -v curl)" || {
    printf 'error: curl is required to stage agent enrollment\n' >&2
    exit 1
  }
  JQ_BIN="$(command -v jq)" || {
    printf 'error: jq is required to stage agent enrollment\n' >&2
    exit 1
  }

  CLEAN_ENV_BIN="$(command -v env)"
  verify_agent_trust_binding
  AGENT_PUBLIC_KEY="$("$CLEAN_ENV_BIN" -i \
    "RYUKI_AGENT_KEY_PATH=$RYUKI_AGENT_KEY_PATH" \
    "$AGENT_BIN" --enrollment-public-key)" || {
    printf 'error: could not load or create the agent enrollment identity\n' >&2
    exit 1
  }
  [[ "$AGENT_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]] || {
    unset AGENT_PUBLIC_KEY
    printf 'error: agent returned a non-canonical Ed25519 public key\n' >&2
    exit 1
  }
  (set -o noclobber; : > "$ENROLLMENT_FILE") || {
    unset AGENT_PUBLIC_KEY
    printf 'error: could not create the one-time enrollment response file\n' >&2
    exit 1
  }
  chmod 600 "$ENROLLMENT_FILE"
  verify_agent_trust_binding
  if ! "$CLEAN_ENV_BIN" -i "$JQ_BIN" -n \
      --arg agent_id "$RYUKI_AGENT_PLATFORM" \
      --arg platform "$RYUKI_AGENT_PLATFORM" \
      --arg public_key "$AGENT_PUBLIC_KEY" \
      '{agent_id: $agent_id, platform: $platform, public_key: $public_key, expires_in_seconds: 900}' | \
    "$CLEAN_ENV_BIN" -i "$CURL_BIN" \
      --disable --silent --show-error --fail-with-body --noproxy '*' \
      --connect-timeout 5 --max-time 15 \
      --request POST "$RYUKI_AGENT_CP_URL/api/admin/agents/enrollment-challenges" \
      --header 'Content-Type: application/json' \
      --header "@$CANONICAL_SESSION_HEADER" \
      --data-binary @- --output "$ENROLLMENT_FILE"; then
    rm -f "$ENROLLMENT_FILE"
    unset AGENT_PUBLIC_KEY
    printf 'error: control plane refused or could not stage agent enrollment\n' >&2
    exit 1
  fi
  unset AGENT_PUBLIC_KEY CLEAN_ENV_BIN CURL_BIN JQ_BIN
  validate_staged_agent_enrollment \
    "$ENROLLMENT_FILE" "$RYUKI_AGENT_PLATFORM" "$RYUKI_AGENT_PLATFORM" || {
    rm -f "$ENROLLMENT_FILE"
    exit 1
  }
  printf 'staged one short-lived enrollment for the persisted agent key\n'
fi

if [[ ! -e "$RYUKI_AGENT_TOKEN_PATH" && ! -L "$RYUKI_AGENT_TOKEN_PATH" ]]; then
  [[ -f "$ENROLLMENT_FILE" && ! -L "$ENROLLMENT_FILE" ]] || {
    printf 'error: no agent token or staged enrollment; run with --stage-enrollment and a temporary admin header\n' >&2
    exit 1
  }
  verify_agent_trust_binding
  validate_staged_agent_enrollment \
    "$ENROLLMENT_FILE" "$RYUKI_AGENT_PLATFORM" "$RYUKI_AGENT_PLATFORM"
  ENROLLMENT_CHALLENGE_ID="$(jq -er '.enrollment_challenge_id' "$ENROLLMENT_FILE")"
  ENROLLMENT_CHALLENGE="$(jq -er '.enrollment_challenge' "$ENROLLMENT_FILE")"
  export RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID="$ENROLLMENT_CHALLENGE_ID"
  export RYUKI_AGENT_ENROLLMENT_CHALLENGE="$ENROLLMENT_CHALLENGE"
  export RYUKI_AGENT_SELF_REGISTER=true
  # Enrollment has no provider-execution authority. Do not expose unrelated
  # provider credentials from the private .env to the bootstrap process.
  unset PG_VSPHERE_USER PG_VSPHERE_PASSWORD PG_VSPHERE_SERVER
  unset ENROLLMENT_CHALLENGE_ID ENROLLMENT_CHALLENGE RYUKI_PG_ENV_ISOLATED
  printf "self-registering '%s' with its key-bound one-time challenge\n" \
    "$RYUKI_AGENT_PLATFORM"
  if "$AGENT_BIN"; then
    unset RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID RYUKI_AGENT_ENROLLMENT_CHALLENGE
    rm -f "$ENROLLMENT_FILE"
    exit 0
  else
    AGENT_STATUS=$?
    unset RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID RYUKI_AGENT_ENROLLMENT_CHALLENGE
    printf 'error: enrollment failed; the short-lived response remains private for a bounded retry\n' >&2
    exit "$AGENT_STATUS"
  fi
fi

# A token proves registration completed. Remove any crash-leftover copy of the
# now-consumed bootstrap material before entering the long-running poll loop.
rm -f "$ENROLLMENT_FILE"
# Declared secret variables for the vSphere offerings are exported only for the
# long-running, already-enrolled agent. Missing/empty values produce a signed,
# value-free refusal at the execution boundary.
verify_agent_trust_binding
unset RYUKI_LIVE_CRED_VSPHERE_USER RYUKI_LIVE_CRED_VSPHERE_PASSWORD \
  RYUKI_LIVE_CRED_VSPHERE_SERVER
unset RYUKI_LIVE_PROVIDER_AUTHORITY_ID RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION
unset RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID \
  RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION
[[ -n "${PG_VSPHERE_USER:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_USER="$PG_VSPHERE_USER"
[[ -n "${PG_VSPHERE_PASSWORD:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_PASSWORD="$PG_VSPHERE_PASSWORD" # secret-scan-allow: reviewed env reference
[[ -n "${PG_VSPHERE_SERVER:-}" ]] && export RYUKI_LIVE_CRED_VSPHERE_SERVER="$PG_VSPHERE_SERVER"
[[ -n "${PG_PROVIDER_AUTHORITY_ID:-}" ]] && \
  export RYUKI_LIVE_PROVIDER_AUTHORITY_ID="$PG_PROVIDER_AUTHORITY_ID"
[[ -n "${PG_PROVIDER_AUTHORITY_VERSION:-}" ]] && \
  export RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION="$PG_PROVIDER_AUTHORITY_VERSION"
[[ -n "${PG_BACKEND_CREDENTIAL_AUTHORITY_ID:-}" ]] && \
  export RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID="$PG_BACKEND_CREDENTIAL_AUTHORITY_ID"
[[ -n "${PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION:-}" ]] && \
  export RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION="$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION"
unset PG_VSPHERE_USER PG_VSPHERE_PASSWORD PG_VSPHERE_SERVER
unset PG_PROVIDER_AUTHORITY_ID PG_PROVIDER_AUTHORITY_VERSION
unset PG_BACKEND_CREDENTIAL_AUTHORITY_ID \
  PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION
unset RYUKI_PG_ENV_ISOLATED
exec "$AGENT_BIN"
