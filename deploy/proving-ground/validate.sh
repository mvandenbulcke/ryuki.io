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

is_commit_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

is_image_id() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

is_security_profile_path() {
  local path="$1"

  [[ "${#path}" -le 512 ]] || return 1
  [[ "$path" =~ ^([A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.json$ ]]
}

is_nonzero_sha256_digest() {
  local digest="$1"

  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [[ "$digest" != "sha256:$(printf '%064d' 0)" ]]
}

# Exercise the reusable admission-pin guards before reading operator input.
# These mutations keep absolute/traversing/non-JSON paths and malformed or zero
# digests from becoming accepted through a future shell refactor.
for rejected_path in /absolute/registry.json ../registry.json registry/../root.json registry/root.yaml; do
  if is_security_profile_path "$rejected_path"; then
    fail "unsafe admission JSON path passed the normalized-path guard: $rejected_path"
  fi
done
for rejected_digest in \
  "sha256:$(printf '%064d' 0)" \
  "sha256:$(printf '%063d' 1)" \
  "sha256:$(printf '%064d' 1 | tr '0-9' 'A-J')"; do
  if is_nonzero_sha256_digest "$rejected_digest"; then
    fail "unsafe admission digest passed the nonzero SHA-256 guard"
  fi
done

is_deployment_id() {
  [[ "$1" =~ ^deployment:[a-z0-9][a-z0-9._-]{2,126}$ ]]
}

verify_local_revision_image() {
  local image_ref="$1"
  local expected_id="$2"
  local expected_revision="$3"
  local actual_id actual_revision

  actual_id="$(docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null)" || \
    fail "required local image is missing (no pull attempted): $image_ref"
  [[ "$actual_id" == "$expected_id" ]] || \
    fail "local image ID does not match the recorded build: $image_ref"

  actual_revision="$(docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "$image_ref" 2>/dev/null)" || \
    fail "cannot inspect local image revision label: $image_ref"
  [[ "$actual_revision" == "$expected_revision" ]] || \
    fail "local image revision label does not match PG_ACCEPTANCE_REVISION: $image_ref"
}

verify_local_digest_image() {
  local image_ref="$1"
  local digest repo_digests

  [[ "$image_ref" =~ @sha256:([0-9a-f]{64})$ ]] || \
    fail "third-party image is not pinned to a full lowercase sha256 digest: $image_ref"
  digest="${BASH_REMATCH[1]}"
  docker image inspect "$image_ref" >/dev/null 2>&1 || \
    fail "reviewed third-party digest is not staged locally (no pull attempted): $image_ref"
  repo_digests="$(docker image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image_ref" 2>/dev/null)" || \
    fail "cannot inspect staged third-party digest: $image_ref"
  [[ "$repo_digests" == *"@sha256:${digest}"* ]] || \
    fail "staged third-party image does not retain the reviewed repo digest: $image_ref"
}

[[ -r "$ENV_INPUT" ]] || fail "cannot read $ENV_INPUT"
ENV_FILE="$(cd "$(dirname "$ENV_INPUT")" && pwd)/$(basename "$ENV_INPUT")"

bash -n "$HERE/agent-env.sh" "$HERE/run-agent.sh" "$HERE/destroy-state.sh" \
  "$HERE/validate.sh"
"$HERE/run-agent.sh" --help >/dev/null
"$HERE/destroy-state.sh" --help >/dev/null
"$HERE/destroy-state.sh" --self-test >/dev/null

API_DOCKERFILE="$HERE/../../sources/ryuki-api/Dockerfile"
PORTAL_DOCKERFILE="$HERE/../../portal/portal-ui/Dockerfile"
for dockerfile in "$API_DOCKERFILE" "$PORTAL_DOCKERFILE"; do
  grep -Fqx 'USER 10001:10001' "$dockerfile" || \
    fail "application runtime image must declare the reviewed non-root identity: $dockerfile"
  grep -Fq -- '--chown=10001:10001' "$dockerfile" || \
    fail "application runtime payload must be owned by the reviewed non-root identity: $dockerfile"
done
grep -Fq 'install -d -o 10001 -g 10001 -m 0700 /app/keys' "$API_DOCKERFILE" || \
  fail "platform-api image must prepare its signing-key directory for the non-root runtime"
grep -Fq 'ca-certificates curl socat' "$PORTAL_DOCKERFILE" || \
  fail "portal image must contain the fixed loopback API relay"

# shellcheck source=deploy/proving-ground/agent-env.sh
source "$HERE/agent-env.sh"
command -v jq >/dev/null 2>&1 || fail "jq is required for enrollment validation"
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
TEMP_DIR="$(cd "$TEMP_DIR" && pwd -P)"
trap 'rm -rf "$TEMP_DIR"' EXIT

STATE_FIXTURE="$TEMP_DIR/agent-state"
mkdir -m 700 "$STATE_FIXTURE"
validate_private_agent_state_dir "$STATE_FIXTURE"
chmod 750 "$STATE_FIXTURE"
if validate_private_agent_state_dir "$STATE_FIXTURE" 2>/dev/null; then
  fail "group-accessible agent state directory passed the permission guard"
fi
chmod 700 "$STATE_FIXTURE"

# A real selected configuration is validated through the same private-copy
# boundary used by the agent and cleanup utility. env.example intentionally
# retains non-executable placeholders and is covered by the fixtures below.
if [[ "$ENV_FILE" != "$HERE/env.example" ]]; then
  stage_approved_executable terraform "$PG_TERRAFORM_EXECUTABLE" \
    "$PG_TERRAFORM_EXPECTED_VERSION" "$PG_TERRAFORM_EXECUTABLE_SHA256" \
    "$STATE_FIXTURE"
  stage_approved_executable ansible-playbook "$PG_ANSIBLE_PLAYBOOK_EXECUTABLE" \
    "$PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION" \
    "$PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256" "$STATE_FIXTURE"
fi

# Reject a digest mismatch before the copied program can run its identity
# probe. This is the regression boundary for probe-before-hash execution.
PROBE_MARKER="$TEMP_DIR/probe-executed"
BAD_PROBE_SOURCE="$TEMP_DIR/bad-probe"
printf '#!/usr/bin/env bash\n: > %q\nprintf "Terraform v1.9.8\\n"\n' \
  "$PROBE_MARKER" > "$BAD_PROBE_SOURCE"
chmod 700 "$BAD_PROBE_SOURCE"
if stage_approved_executable terraform "$BAD_PROBE_SOURCE" 1.9.8 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    "$STATE_FIXTURE" 2>/dev/null; then
  fail "an executable with the wrong approved digest passed private staging"
fi
[[ ! -e "$PROBE_MARKER" ]] || \
  fail "an executable ran its identity probe before digest approval"

# Once accepted, only the content-addressed private copy may be executed. A
# later replacement of the configured pathname must not affect that copy.
TERRAFORM_SOURCE="$TEMP_DIR/terraform"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "Terraform v1.9.8\n"' > "$TERRAFORM_SOURCE"
chmod 700 "$TERRAFORM_SOURCE"
TERRAFORM_FIXTURE_SHA256="$(approved_executable_sha256 "$TERRAFORM_SOURCE")"
stage_approved_executable terraform "$TERRAFORM_SOURCE" 1.9.8 \
  "$TERRAFORM_FIXTURE_SHA256" "$STATE_FIXTURE"
STAGED_TERRAFORM="$APPROVED_EXECUTABLE_PATH"
[[ "$APPROVED_EXECUTABLE_SHA256" == "$TERRAFORM_FIXTURE_SHA256" ]] || \
  fail "private Terraform copy did not retain its approved digest"
[[ "$STAGED_TERRAFORM" == \
  "$STATE_FIXTURE/approved-tools/terraform-$TERRAFORM_FIXTURE_SHA256" ]] || \
  fail "Terraform was not staged at its private content-addressed path"
validate_private_approved_executable \
  "$STAGED_TERRAFORM" "$TERRAFORM_FIXTURE_SHA256"
printf '#!/usr/bin/env bash\n: > %q\nprintf "Terraform v0.0.0\\n"\n' \
  "$PROBE_MARKER" > "$TERRAFORM_SOURCE"
chmod 700 "$TERRAFORM_SOURCE"
[[ "$("$STAGED_TERRAFORM" version)" == "Terraform v1.9.8" ]] || \
  fail "configured-path replacement changed the approved Terraform copy"
[[ ! -e "$PROBE_MARKER" ]] || \
  fail "the configured Terraform pathname was executed after private staging"

# Non-live/local validation may omit a publisher digest. It still receives a
# hashed private copy so the downstream runner never executes the source path.
ANSIBLE_SOURCE="$TEMP_DIR/ansible-playbook"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "ansible-playbook [core 2.18.1]\n"' > "$ANSIBLE_SOURCE"
chmod 700 "$ANSIBLE_SOURCE"
SELECTED_ALLOW_LIVE="$PG_AGENT_ALLOW_LIVE"
PG_AGENT_ALLOW_LIVE=true
if stage_approved_executable ansible-playbook "$ANSIBLE_SOURCE" 2.18.1 "" \
    "$STATE_FIXTURE" 2>/dev/null; then
  fail "live executable staging accepted a missing approved digest"
fi
PG_AGENT_ALLOW_LIVE=false
stage_approved_executable ansible-playbook "$ANSIBLE_SOURCE" 2.18.1 "" \
  "$STATE_FIXTURE"
PG_AGENT_ALLOW_LIVE="$SELECTED_ALLOW_LIVE"
[[ "$APPROVED_EXECUTABLE_PATH" == \
  "$STATE_FIXTURE/approved-tools/ansible-playbook-$APPROVED_EXECUTABLE_SHA256" ]] || \
  fail "unpinned non-live Ansible fixture was not staged privately"
validate_private_approved_executable \
  "$APPROVED_EXECUTABLE_PATH" "$APPROVED_EXECUTABLE_SHA256"

SESSION_FIXTURE="$TEMP_DIR/admin.headers"
printf 'X-Ryuki-Session-Id: rys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' \
  > "$SESSION_FIXTURE"
chmod 600 "$SESSION_FIXTURE"
validate_agent_enrollment_session_header "$SESSION_FIXTURE"
printf '%s\n%s\n' \
  'X-Ryuki-Session-Id: rys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
  'X-Injected: forbidden' > "$SESSION_FIXTURE"
if validate_agent_enrollment_session_header "$SESSION_FIXTURE" 2>/dev/null; then
  fail "multi-header enrollment credential file passed validation"
fi
printf 'X-Ryuki-Session-Id: 00000000-0000-4000-8000-000000000000\n' \
  > "$SESSION_FIXTURE"
if validate_agent_enrollment_session_header "$SESSION_FIXTURE" 2>/dev/null; then
  fail "administrative management UUID passed as an enrollment credential"
fi

ENROLLMENT_FIXTURE="$TEMP_DIR/enrollment.json"
jq -n '{
  enrollment_challenge_id: "00000000-0000-4000-8000-000000000001",
  enrollment_challenge: "ryc_0000000000000000000000000000000000000000000000000000000000000000",
  agent_id: "DEFRA",
  platform: "DEFRA",
  public_key_fingerprint: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  expires_at: "2099-01-01T00:00:00Z"
}' > "$ENROLLMENT_FIXTURE"
chmod 600 "$ENROLLMENT_FIXTURE"
validate_staged_agent_enrollment "$ENROLLMENT_FIXTURE" DEFRA DEFRA
jq '.platform = "attacker"' "$ENROLLMENT_FIXTURE" > "$TEMP_DIR/wrong-enrollment.json"
chmod 600 "$TEMP_DIR/wrong-enrollment.json"
if validate_staged_agent_enrollment \
    "$TEMP_DIR/wrong-enrollment.json" DEFRA DEFRA 2>/dev/null; then
  fail "mismatched staged enrollment identity passed validation"
fi

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
  printf '%s\n' 'PG_TERRAFORM_EXECUTABLE=/literal/terraform'
  printf '%s\n' 'PG_TERRAFORM_EXPECTED_VERSION=1.9.8'
  printf '%s\n' 'PG_TERRAFORM_EXECUTABLE_SHA256='
  printf '%s\n' 'PG_ANSIBLE_PLAYBOOK_EXECUTABLE=/literal/ansible-playbook'
  printf '%s\n' 'PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION=2.18.1'
  printf '%s\n' 'PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256='
  printf '%s\n' 'PG_VSPHERE_USER=literal user'
  printf '%s\n' 'PG_VSPHERE_PASSWORD=x;y'
  printf '%s\n' 'PG_VSPHERE_SERVER=literal$(hostname)'
  printf '%s\n' 'PG_PROVIDER_AUTHORITY_ID=provider-authority/vsphere/literal-fixture'
  printf '%s\n' 'PG_PROVIDER_AUTHORITY_VERSION=v1'
  printf '%s\n' 'PG_BACKEND_CREDENTIAL_AUTHORITY_ID=backend-credential-authority/local/literal-fixture'
  printf '%s\n' 'PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION=v1'
} > "$TEMP_DIR/literal.env"

unset PG_DB_PASSWORD PG_VAULT_TOKEN PG_LOCAL_USERS
load_agent_env "$TEMP_DIR/literal.env"
validate_agent_env
[[ "$PG_AGENT_BACKEND_HCL" == "$LITERAL_HCL" ]] || fail "HCL was not parsed literally"
[[ "$PG_VSPHERE_USER" == 'literal user' ]] || fail "spaces were not preserved"
[[ "$PG_VSPHERE_PASSWORD" == 'x;y' ]] || fail "semicolon was not preserved"
[[ "$PG_VSPHERE_SERVER" == 'literal$(hostname)' ]] || fail "command text was not preserved"
[[ "$PG_PROVIDER_AUTHORITY_ID" == 'provider-authority/vsphere/literal-fixture' ]] || \
  fail "provider authority id was not parsed literally"
[[ "$PG_PROVIDER_AUTHORITY_VERSION" == 'v1' ]] || \
  fail "provider authority version was not parsed literally"
[[ "$PG_BACKEND_CREDENTIAL_AUTHORITY_ID" == \
  'backend-credential-authority/local/literal-fixture' ]] || \
  fail "backend credential authority id was not parsed literally"
[[ "$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION" == 'v1' ]] || \
  fail "backend credential authority revision was not parsed literally"
[[ ! -e "$MARKER" ]] || fail "environment value was evaluated as shell code"
[[ -z "${PG_DB_PASSWORD+x}" && -z "${PG_VAULT_TOKEN+x}" && -z "${PG_LOCAL_USERS+x}" ]] || \
  fail "control-plane values were assigned by the agent parser"

PG_AGENT_ALLOW_LIVE=true
if validate_agent_env 2>/dev/null; then
  fail "live execution accepted missing approved executable digests"
fi
PG_TERRAFORM_EXECUTABLE_SHA256=0000000000000000000000000000000000000000000000000000000000000000
PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256=1111111111111111111111111111111111111111111111111111111111111111
validate_agent_env
PG_AGENT_ALLOW_LIVE=false
PG_TERRAFORM_EXECUTABLE_SHA256=""
PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256=""
validate_agent_env

# Restore the selected file's values after the isolated hostile-value fixture.
load_agent_env "$ENV_FILE"
validate_agent_env

if [[ "$ENV_FILE" == "$HERE/env.example" ]]; then
  # The committed template deliberately carries no admission choice. These
  # non-secret, syntactically valid values exist only in this process so
  # Compose interpolation and rendered-boundary checks can still be exercised.
  PG_DEPLOYMENT_SECURITY_PROFILE_PATH=sentinel/proving-ground-profile.json
  PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST="sha256:$(printf '%064d' 1)"
  PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH=sentinel/conformance-trust-root-registry.json
  PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST="sha256:$(printf '%064d' 2)"
  PG_EXPECTED_DEPLOYMENT_ID=deployment:proving-ground-template
  PG_SECURITY_PROFILE=test
else
  PG_DEPLOYMENT_SECURITY_PROFILE_PATH="$(
    compose_env_value PG_DEPLOYMENT_SECURITY_PROFILE_PATH "$ENV_FILE"
  )" || fail "PG_DEPLOYMENT_SECURITY_PROFILE_PATH is missing"
  PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST="$(
    compose_env_value PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST "$ENV_FILE"
  )" || fail "PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST is missing"
  PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH="$(
    compose_env_value PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH "$ENV_FILE"
  )" || fail "PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH is missing"
  PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST="$(
    compose_env_value PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST "$ENV_FILE"
  )" || fail "PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST is missing"
  PG_EXPECTED_DEPLOYMENT_ID="$(
    compose_env_value PG_EXPECTED_DEPLOYMENT_ID "$ENV_FILE"
  )" || fail "PG_EXPECTED_DEPLOYMENT_ID is missing"
  PG_SECURITY_PROFILE="$(compose_env_value PG_SECURITY_PROFILE "$ENV_FILE")" || \
    fail "PG_SECURITY_PROFILE is missing"

  is_security_profile_path "$PG_DEPLOYMENT_SECURITY_PROFILE_PATH" || \
    fail "PG_DEPLOYMENT_SECURITY_PROFILE_PATH must be a safe relative .json path without dot segments"
  is_nonzero_sha256_digest "$PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST" || \
    fail "PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST must be a nonzero sha256: digest with 64 lowercase hex digits"
  is_security_profile_path "$PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH" || \
    fail "PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH must be a safe relative .json path without dot segments"
  is_nonzero_sha256_digest "$PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST" || \
    fail "PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST must be a nonzero sha256: digest with 64 lowercase hex digits"
  is_deployment_id "$PG_EXPECTED_DEPLOYMENT_ID" || \
    fail "PG_EXPECTED_DEPLOYMENT_ID must be a canonical deployment: id"
  [[ "$PG_SECURITY_PROFILE" == "test" ]] || \
    fail "PG_SECURITY_PROFILE must be exactly test for the proving ground"
fi

LOCAL_USERS="$(compose_env_value PG_LOCAL_USERS "$ENV_FILE")" || \
  fail "PG_LOCAL_USERS is missing"
SESSION_CREDENTIAL_HMAC_KEY="$(compose_env_value PG_SESSION_CREDENTIAL_HMAC_KEY "$ENV_FILE")" || \
  fail "PG_SESSION_CREDENTIAL_HMAC_KEY is missing"
CERTIFICATE_CURSOR_HMAC_KEY="$(compose_env_value PG_CERTIFICATE_CURSOR_HMAC_KEY "$ENV_FILE")" || \
  fail "PG_CERTIFICATE_CURSOR_HMAC_KEY is missing"
ACCEPTANCE_REVISION="$(compose_env_value PG_ACCEPTANCE_REVISION "$ENV_FILE")" || \
  fail "PG_ACCEPTANCE_REVISION is missing"
PLATFORM_API_IMAGE_ID="$(compose_env_value PG_PLATFORM_API_IMAGE_ID "$ENV_FILE")" || \
  fail "PG_PLATFORM_API_IMAGE_ID is missing"
PORTAL_IMAGE_ID="$(compose_env_value PG_PORTAL_IMAGE_ID "$ENV_FILE")" || \
  fail "PG_PORTAL_IMAGE_ID is missing"
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
  [[ "${#SESSION_CREDENTIAL_HMAC_KEY}" -ge 32 ]] || \
    fail "PG_SESSION_CREDENTIAL_HMAC_KEY must contain at least 32 bytes"
  [[ "${#CERTIFICATE_CURSOR_HMAC_KEY}" -ge 32 ]] || \
    fail "PG_CERTIFICATE_CURSOR_HMAC_KEY must contain at least 32 bytes"
  [[ "$CERTIFICATE_CURSOR_HMAC_KEY" != "$SESSION_CREDENTIAL_HMAC_KEY" ]] || \
    fail "PG_CERTIFICATE_CURSOR_HMAC_KEY must differ from PG_SESSION_CREDENTIAL_HMAC_KEY"
  is_commit_sha "$ACCEPTANCE_REVISION" || \
    fail "PG_ACCEPTANCE_REVISION must be one full lowercase commit SHA"
  is_image_id "$PLATFORM_API_IMAGE_ID" || \
    fail "PG_PLATFORM_API_IMAGE_ID must be one full lowercase sha256 image ID"
  is_image_id "$PORTAL_IMAGE_ID" || \
    fail "PG_PORTAL_IMAGE_ID must be one full lowercase sha256 image ID"
  [[ "$LOCAL_USERS" != *'change-me-maker'* && "$LOCAL_USERS" != *'change-me-checker'* ]] || \
    fail "replace both PG_LOCAL_USERS placeholders"

  REPO_ROOT="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null)" || \
    fail "cannot resolve the proving-ground repository root"
  CURRENT_REVISION="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$REPO_ROOT" \
    rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || \
    fail "cannot resolve the current committed revision"
  [[ "$CURRENT_REVISION" == "$ACCEPTANCE_REVISION" ]] || \
    fail "PG_ACCEPTANCE_REVISION does not match the checked-out commit"
  [[ -z "$(GIT_NO_REPLACE_OBJECTS=1 git -C "$REPO_ROOT" \
    -c core.fsmonitor=false -c core.untrackedCache=false \
    status --porcelain=v1 --untracked-files=all)" ]] || \
    fail "acceptance images must be built and started from a clean committed worktree"
  ACCEPTANCE_SIGNER_FINGERPRINT="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$REPO_ROOT" \
    config --local --get ryuki.provingGroundAcceptanceSignerFingerprint 2>/dev/null)" || \
    fail "configure the independently approved acceptance signer fingerprint"
  [[ "$ACCEPTANCE_SIGNER_FINGERPRINT" =~ ^[0-9A-F]{40}$ ]] || \
    fail "acceptance signer fingerprint must be one full uppercase OpenPGP fingerprint"
  GIT_NO_REPLACE_OBJECTS=1 git -C "$REPO_ROOT" \
    verify-commit "$ACCEPTANCE_REVISION" >/dev/null 2>&1 || \
    fail "PG_ACCEPTANCE_REVISION is not a valid signed commit"
  ACCEPTANCE_SIGNATURE_STATUS="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$REPO_ROOT" \
    show -s --format=%G? "$ACCEPTANCE_REVISION")" || \
    fail "cannot inspect the acceptance signature status"
  ACCEPTANCE_ACTUAL_SIGNER="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$REPO_ROOT" \
    show -s --format=%GF "$ACCEPTANCE_REVISION")" || \
    fail "cannot inspect the acceptance signer fingerprint"
  [[ "$ACCEPTANCE_SIGNATURE_STATUS" == "G" && \
     "$ACCEPTANCE_ACTUAL_SIGNER" == "$ACCEPTANCE_SIGNER_FINGERPRINT" ]] || \
    fail "acceptance commit signer is not the configured trusted signer"

  if [[ "$PG_AGENT_ALLOW_LIVE" == "true" ]]; then
    [[ -n "$PG_VSPHERE_USER" ]] || fail "live mode requires PG_VSPHERE_USER"
    [[ -n "$PG_VSPHERE_PASSWORD" ]] || fail "live mode requires PG_VSPHERE_PASSWORD"
    [[ -n "$PG_VSPHERE_SERVER" ]] || fail "live mode requires PG_VSPHERE_SERVER"
    [[ -n "$PG_PROVIDER_AUTHORITY_ID" ]] || \
      fail "live mode requires PG_PROVIDER_AUTHORITY_ID"
    [[ -n "$PG_PROVIDER_AUTHORITY_VERSION" ]] || \
      fail "live mode requires PG_PROVIDER_AUTHORITY_VERSION"
    [[ -n "$PG_BACKEND_CREDENTIAL_AUTHORITY_ID" ]] || \
      fail "live mode requires PG_BACKEND_CREDENTIAL_AUTHORITY_ID"
    [[ -n "$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION" ]] || \
      fail "live mode requires PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION"
  fi
fi

grep -Fq 'http://localhost:8081/ready' "$HERE/compose.yaml" || \
  fail "platform-api healthcheck must gate on /ready"
grep -Fq 'RYUKI_SESSION__COOKIE_SECURE: "false"' "$HERE/compose.yaml" || \
  fail "loopback HTTP proving ground must disable Secure API cookies explicitly"
grep -Fq 'VAULT_ADDR: http://127.0.0.1:8200' "$HERE/compose.yaml" || \
  fail "proving-ground Vault traffic must stay on literal loopback"
grep -Fq 'VAULT_DEV_LISTEN_ADDRESS: 127.0.0.1:8200' "$HERE/compose.yaml" || \
  fail "Vault must listen only inside the API/Vault loopback namespace"
grep -Fq 'RYUKI_VAULT_ALLOW_INSECURE_LOOPBACK: "true"' "$HERE/compose.yaml" || \
  fail "the proving-ground loopback Vault exception must be explicit"
grep -Fqx 'export RYUKI_AGENT_CP_URL="http://127.0.0.1:18081"' "$HERE/run-agent.sh" || \
  fail "the proving-ground agent control plane must stay on literal loopback"
grep -Fqx 'export RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK=true' "$HERE/run-agent.sh" || \
  fail "the proving-ground agent loopback HTTP exception must be explicit"
grep -Fq '"$AGENT_BIN" --enrollment-public-key' "$HERE/run-agent.sh" || \
  fail "agent enrollment must preprovision the exact persisted workload key"
grep -Fq '/api/admin/agents/enrollment-challenges' "$HERE/run-agent.sh" || \
  fail "agent enrollment must use the authenticated challenge endpoint"
grep -Fq -- '--disable --silent --show-error --fail-with-body' "$HERE/run-agent.sh" || \
  fail "agent enrollment curl must ignore ambient user configuration"
grep -Fq 'expires_in_seconds: 900' "$HERE/run-agent.sh" || \
  fail "proving-ground enrollment challenges must remain short-lived"
grep -Fq 'status --porcelain=v1 --untracked-files=all' "$HERE/run-agent.sh" || \
  fail "agent runner must reject every tracked or untracked checkout change"
grep -Fq 'verify-commit "$ACCEPTANCE_REVISION"' "$HERE/run-agent.sh" || \
  fail "agent runner must verify the accepted commit signature"
grep -Fq '"$CARGO_BIN" build --locked --offline --release -p ryuki-agent' \
  "$HERE/run-agent.sh" || \
  fail "agent runner must use the locked offline release build"
grep -Fq 'source_manifest_sha256=$SOURCE_MANIFEST_SHA256' "$HERE/run-agent.sh" || \
  fail "agent runner must record the accepted source-manifest digest"
grep -Fq 'source_archive_sha256=$SOURCE_ARCHIVE_SHA256' "$HERE/run-agent.sh" || \
  fail "agent runner must record the materialized accepted-source digest"
grep -Fq 'cargo_lock_sha256=$DEPENDENCY_LOCK_SHA256' "$HERE/run-agent.sh" || \
  fail "agent runner must record the dependency-lock digest"
grep -Fq 'agent_sha256=$AGENT_ARTIFACT_SHA256' "$HERE/run-agent.sh" || \
  fail "agent runner must record the built-artifact digest"
[[ "$(grep -Fc 'verify_agent_trust_binding' "$HERE/run-agent.sh")" -ge 6 ]] || \
  fail "agent runner must recheck trust at every credential-bearing execution boundary"
PROTOCOL_TYPES="$HERE/../../sources/ryuki-protocol/src/types.rs"
grep -Fqx 'pub const PROTOCOL_VERSION: u32 = 8;' "$PROTOCOL_TYPES" || \
  fail "the proving ground requires the shared protocol-v8 wire contract"
grep -Fqx 'pub const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[8];' "$PROTOCOL_TYPES" || \
  fail "legacy protocol peers must remain outside the shared acceptance set"
grep -Fq 'export RYUKI_LIVE_PROVIDER_AUTHORITY_ID="$PG_PROVIDER_AUTHORITY_ID"' \
  "$HERE/run-agent.sh" || \
  fail "the proving-ground agent must receive the reviewed provider authority id"
grep -Fq 'export RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION="$PG_PROVIDER_AUTHORITY_VERSION"' \
  "$HERE/run-agent.sh" || \
  fail "the proving-ground agent must receive the reviewed provider authority version"
grep -Fq 'export RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID="$PG_BACKEND_CREDENTIAL_AUTHORITY_ID"' \
  "$HERE/run-agent.sh" || \
  fail "the proving-ground agent must receive the reviewed backend credential authority id"
grep -Fq 'export RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION="$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION"' \
  "$HERE/run-agent.sh" || \
  fail "the proving-ground agent must receive the reviewed backend credential authority revision"
if grep -Fq 'RYUKI_AGENT_ENROLLMENT_CHALLENGE' \
    "$HERE/env.example" "$HERE/compose.yaml"; then
  fail "a reusable enrollment challenge must never ship in static configuration"
fi
[[ "$(grep -Fc 'network_mode: "service:vault"' "$HERE/compose.yaml")" -eq 1 ]] || \
  fail "only the trusted API may share Vault's loopback network namespace"
[[ "$(grep -Ec '^[[:space:]]+pull_policy: never$' "$HERE/compose.yaml")" -eq 4 ]] || \
  fail "every proving-ground image must prohibit implicit registry pulls"
if grep -Eq '^[[:space:]]+build:' "$HERE/compose.yaml"; then
  fail "proving-ground startup must consume prevalidated images, not build implicitly"
fi
for binding in \
  '127.0.0.1:15432:5432' '127.0.0.1:18081:8081' \
  '127.0.0.1:18001:8080'; do
  grep -Fq -- "\"$binding\"" "$HERE/compose.yaml" || \
    fail "published proving-ground port must stay loopback-only: $binding"
done
if grep -Eq '127\.0\.0\.1:[0-9]+:8200|0\.0\.0\.0:[0-9]+:8200' "$HERE/compose.yaml"; then
  fail "Vault must not publish its cleartext dev listener to the host"
fi
command -v docker >/dev/null 2>&1 || fail "docker is required for Compose validation"

# env.example intentionally leaves the database value empty. Supply a temporary
# process-local placeholder only while validating the committed template.
if [[ "$ENV_FILE" == "$HERE/env.example" ]]; then
  printf -v PG_DB_PASSWORD '%s' 'local-placeholder'
  printf -v PG_SESSION_CREDENTIAL_HMAC_KEY '%032d' 0
  printf -v PG_CERTIFICATE_CURSOR_HMAC_KEY '%032d' 1
  printf -v PG_ACCEPTANCE_REVISION '%040d' 0
else
  PG_ACCEPTANCE_REVISION="$ACCEPTANCE_REVISION"
fi
export PG_DB_PASSWORD PG_SESSION_CREDENTIAL_HMAC_KEY PG_CERTIFICATE_CURSOR_HMAC_KEY
export PG_ACCEPTANCE_REVISION
export PG_DEPLOYMENT_SECURITY_PROFILE_PATH
export PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST PG_EXPECTED_DEPLOYMENT_ID
export PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH
export PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST
export PG_SECURITY_PROFILE

COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$HERE/compose.yaml")
"${COMPOSE[@]}" config --quiet
RENDERED_CONFIG_JSON="$("${COMPOSE[@]}" config --format json)" || \
  fail "cannot render proving-ground Compose JSON"

jq -e \
  --arg profile_path "$PG_DEPLOYMENT_SECURITY_PROFILE_PATH" \
  --arg profile_digest "$PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST" \
  --arg trust_registry_path "$PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH" \
  --arg trust_registry_digest "$PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST" \
  --arg deployment_id "$PG_EXPECTED_DEPLOYMENT_ID" \
  --arg security_profile "$PG_SECURITY_PROFILE" '
  .services["platform-api"].environment.RYUKI_SECURITY_CONTRACT_ROOT
    == "/app/security-contract"
  and .services["platform-api"].environment.RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH
    == $profile_path
  and .services["platform-api"].environment.RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST
    == $profile_digest
  and .services["platform-api"].environment.RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH
    == $trust_registry_path
  and .services["platform-api"].environment.RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST
    == $trust_registry_digest
  and .services["platform-api"].environment.RYUKI_EXPECTED_DEPLOYMENT_ID
    == $deployment_id
  and .services["platform-api"].environment.RYUKI_SECURITY_PROFILE
    == $security_profile
' >/dev/null <<< "$RENDERED_CONFIG_JSON" || \
  fail "rendered API security admission root or exact profile pins changed"

jq -e '
  .services["platform-api"].network_mode == "service:vault"
  and ((.services["portal-ui"].network_mode // "") == "")
  and ((.services["portal-ui"].networks | keys) == ["portal-net"])
  and ((.services["platform-db"].networks | keys) == ["pg-net"])
  and ((.services.vault.networks | keys | sort) == ["pg-net", "portal-net"])
  and (.services.vault.networks["portal-net"].aliases == ["platform-api"])
' >/dev/null <<< "$RENDERED_CONFIG_JSON" || \
  fail "rendered networks must isolate the portal from Vault and PostgreSQL"

for service in platform-api portal-ui; do
  jq -e --arg service "$service" '
    .services[$service].user == "10001:10001"
    and .services[$service].cap_drop == ["ALL"]
    and (.services[$service].security_opt | index("no-new-privileges:true") != null)
  ' >/dev/null <<< "$RENDERED_CONFIG_JSON" || \
    fail "rendered application service must be non-root with all capabilities dropped: $service"
done

jq -e '
  .services.vault.user == "vault"
  and .services.vault.cap_drop == ["ALL"]
  and .services.vault.cap_add == ["IPC_LOCK"]
  and (.services.vault.security_opt | index("no-new-privileges:true") != null)
  and .services.vault.environment.VAULT_DEV_LISTEN_ADDRESS == "127.0.0.1:8200"
  and .services["platform-api"].environment.VAULT_ADDR == "http://127.0.0.1:8200"
  and .services["portal-ui"].environment.RYUKI_API_URL == "http://127.0.0.1:18082"
  and .services["portal-ui"].entrypoint == ["/bin/sh", "-ec"]
  and ((.services["portal-ui"].command | join("\n"))
    | contains("/usr/bin/socat TCP-LISTEN:18082,bind=127.0.0.1,reuseaddr,fork TCP:platform-api:8081"))
' >/dev/null <<< "$RENDERED_CONFIG_JSON" || \
  fail "rendered Vault/API boundary lost its private-loopback or capability contract"

jq -e '
  ([.services[] | .ports[]? | "\(.host_ip):\(.published):\(.target)"] | sort)
  == ([
    "127.0.0.1:15432:5432",
    "127.0.0.1:18001:8080",
    "127.0.0.1:18081:8081"
  ] | sort)
' >/dev/null <<< "$RENDERED_CONFIG_JSON" || \
  fail "rendered host ports must be the exact loopback-only DB, portal, and API set"

RENDERED_IMAGE_TEXT="$("${COMPOSE[@]}" config --images)" || \
  fail "cannot enumerate rendered proving-ground images"
RENDERED_IMAGES=()
while IFS= read -r rendered_image; do
  RENDERED_IMAGES[${#RENDERED_IMAGES[@]}]="$rendered_image"
done <<< "$RENDERED_IMAGE_TEXT"
[[ "${#RENDERED_IMAGES[@]}" -eq 4 ]] || \
  fail "rendered proving ground must contain exactly four image-backed services"

PLATFORM_API_REF="ryuki/platform-api:${PG_ACCEPTANCE_REVISION}"
PORTAL_REF="ryuki/portal-ui:${PG_ACCEPTANCE_REVISION}"
PLATFORM_API_COUNT=0
PORTAL_COUNT=0
DIGEST_IMAGE_COUNT=0
for image_ref in "${RENDERED_IMAGES[@]}"; do
  case "$image_ref" in
    "$PLATFORM_API_REF")
      PLATFORM_API_COUNT=$((PLATFORM_API_COUNT + 1))
      if [[ "$ENV_FILE" != "$HERE/env.example" ]]; then
        verify_local_revision_image "$image_ref" "$PLATFORM_API_IMAGE_ID" "$ACCEPTANCE_REVISION"
      fi
      ;;
    "$PORTAL_REF")
      PORTAL_COUNT=$((PORTAL_COUNT + 1))
      if [[ "$ENV_FILE" != "$HERE/env.example" ]]; then
        verify_local_revision_image "$image_ref" "$PORTAL_IMAGE_ID" "$ACCEPTANCE_REVISION"
      fi
      ;;
    *@sha256:*)
      DIGEST_IMAGE_COUNT=$((DIGEST_IMAGE_COUNT + 1))
      if [[ "$ENV_FILE" != "$HERE/env.example" ]]; then
        verify_local_digest_image "$image_ref"
      fi
      ;;
    *)
      fail "rendered proving ground contains an unapproved mutable image: $image_ref"
      ;;
  esac
done
[[ "$PLATFORM_API_COUNT" -eq 1 && "$PORTAL_COUNT" -eq 1 && "$DIGEST_IMAGE_COUNT" -eq 2 ]] || \
  fail "rendered image set does not match two revision-bound apps and two digest-bound dependencies"

printf 'proving-ground validation passed (%s)\n' "$ENV_FILE"
