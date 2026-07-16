#!/usr/bin/env bash
# Guarded out-of-band cleanup after any possibly mutating proving-ground apply.
set -euo pipefail

# Re-exec once before reading .env so inherited TF_* controls, credentials, and
# unrelated secrets cannot influence cleanup. Secret values are loaded only on
# the isolated second pass and reach Terraform through its environment, never
# through an `env NAME=value` wrapper argv.
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
ENV_FILE="$HERE/.env"

STATE_KEY=""
OFFERING=""
REQUEST_ID=""
VM_NAME=""
SITE=""
ENVIRONMENT=""
CPU=""
MEMORY_GB=""
DISK_SIZE_GB=""
DATACENTER=""
CLUSTER=""
DATASTORE=""
NETWORK=""
TEMPLATE=""
ASSUME_YES=false
PREFLIGHT_ONLY=false
SELF_TEST=false
readonly -a TERRAFORM_INIT_ARGS=(init -input=false -lockfile=readonly -reconfigure)

usage() {
  cat <<'EOF'
Usage: destroy-state.sh [--env-file PATH] --state-key KEY --offering OFFERING
       --request-id UUID --vm-name NAME --site SITE --environment ENV
       --cpu COUNT --memory-gb COUNT --disk-size-gb COUNT
       --datacenter NAME --cluster NAME --datastore NAME --network NAME
       --template NAME [--preflight | --yes]
       destroy-state.sh --self-test

Supported offerings: linux-server-deployment, windows-server-deployment

The values must exactly match the applied job. By default the script shows a
saved destroy plan and requires the exact state key as confirmation. --yes
applies that saved plan without the interactive confirmation.

--preflight validates the exact arguments, environment, backend rendering,
tools, and Terraform input file without initializing Terraform or contacting
the provider. It is the required pre-apply cleanup rehearsal.
EOF
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

state_has_only_expected_resources() {
  local resources="$1"
  local expected_vm="$2"
  local line
  local managed_count=0
  local seen_data=' '

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    case "$line" in
      "$expected_vm")
        managed_count=$((managed_count + 1))
        ;;
      data.vsphere_compute_cluster.cluster | data.vsphere_datacenter.dc | \
        data.vsphere_datastore.ds | data.vsphere_network.net | \
        data.vsphere_virtual_machine.template)
        case "$seen_data" in
          *" $line "*) return 1 ;;
        esac
        seen_data="${seen_data}${line} "
        ;;
      *) return 1 ;;
    esac
  done <<< "$resources"

  [[ "$managed_count" -eq 1 ]]
}

state_has_no_managed_resources() {
  local resources="$1"
  local line
  local seen_data=' '

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    case "$line" in
      data.vsphere_compute_cluster.cluster | data.vsphere_datacenter.dc | \
        data.vsphere_datastore.ds | data.vsphere_network.net | \
        data.vsphere_virtual_machine.template)
        case "$seen_data" in
          *" $line "*) return 1 ;;
        esac
        seen_data="${seen_data}${line} "
        ;;
      *) return 1 ;;
    esac
  done <<< "$resources"
}

state_vm_matches_inputs() {
  local address="$1"
  local vm_name="$2"
  local num_cpus="$3"
  local memory_mb="$4"
  local disk_size_gb="$5"

  jq -e \
    --arg address "$address" \
    --arg vm_name "$vm_name" \
    --argjson num_cpus "$num_cpus" \
    --argjson memory_mb "$memory_mb" \
    --argjson disk_size_gb "$disk_size_gb" \
    '[.values.root_module.resources[]? | select(.mode == "managed")] as $managed
     | ($managed | length) == 1
       and $managed[0].address == $address
       and $managed[0].values.name == $vm_name
       and $managed[0].values.num_cpus == $num_cpus
       and $managed[0].values.memory == $memory_mb
       and any($managed[0].values.disk[]?;
         .label == "disk0" and .size == $disk_size_gb)' \
    >/dev/null
}

need_option_value() {
  [[ "$#" -ge 2 && -n "${2-}" ]] || die "$1 requires a value"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --env-file)
      need_option_value "$@"
      ENV_FILE="$2"
      shift 2
      ;;
    --state-key)
      need_option_value "$@"
      STATE_KEY="$2"
      shift 2
      ;;
    --offering)
      need_option_value "$@"
      OFFERING="$2"
      shift 2
      ;;
    --request-id)
      need_option_value "$@"
      REQUEST_ID="$2"
      shift 2
      ;;
    --vm-name)
      need_option_value "$@"
      VM_NAME="$2"
      shift 2
      ;;
    --site)
      need_option_value "$@"
      SITE="$2"
      shift 2
      ;;
    --environment)
      need_option_value "$@"
      ENVIRONMENT="$2"
      shift 2
      ;;
    --cpu)
      need_option_value "$@"
      CPU="$2"
      shift 2
      ;;
    --memory-gb)
      need_option_value "$@"
      MEMORY_GB="$2"
      shift 2
      ;;
    --disk-size-gb)
      need_option_value "$@"
      DISK_SIZE_GB="$2"
      shift 2
      ;;
    --datacenter)
      need_option_value "$@"
      DATACENTER="$2"
      shift 2
      ;;
    --cluster)
      need_option_value "$@"
      CLUSTER="$2"
      shift 2
      ;;
    --datastore)
      need_option_value "$@"
      DATASTORE="$2"
      shift 2
      ;;
    --network)
      need_option_value "$@"
      NETWORK="$2"
      shift 2
      ;;
    --template)
      need_option_value "$@"
      TEMPLATE="$2"
      shift 2
      ;;
    --yes)
      ASSUME_YES=true
      shift
      ;;
    --preflight)
      PREFLIGHT_ONLY=true
      shift
      ;;
    --self-test)
      SELF_TEST=true
      shift
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if [[ "$SELF_TEST" == "true" ]]; then
  [[ " ${TERRAFORM_INIT_ARGS[*]} " == *" -lockfile=readonly "* ]] || \
    die "Terraform init must enforce the embedded dependency lock"
  expected='vsphere_virtual_machine.linux_server'
  normal_state=$'data.vsphere_compute_cluster.cluster\ndata.vsphere_datacenter.dc\ndata.vsphere_datastore.ds\ndata.vsphere_network.net\ndata.vsphere_virtual_machine.template\nvsphere_virtual_machine.linux_server'
  state_has_only_expected_resources "$normal_state" "$expected" || \
    die "normal-state self-test failed"
  state_has_only_expected_resources "$expected" "$expected" || \
    die "managed-only state self-test failed"
  ! state_has_only_expected_resources "$normal_state"$'\nvsphere_tag.extra' "$expected" || \
    die "multi-resource state self-test failed"
  ! state_has_only_expected_resources "$normal_state"$'\ndata.vsphere_tag.extra' "$expected" || \
    die "unexpected-data state self-test failed"
  ! state_has_only_expected_resources 'data.vsphere_datacenter.dc' "$expected" || \
    die "missing-managed-resource state self-test failed"
  data_only_state=$'data.vsphere_compute_cluster.cluster\ndata.vsphere_datacenter.dc\ndata.vsphere_datastore.ds\ndata.vsphere_network.net\ndata.vsphere_virtual_machine.template'
  state_has_no_managed_resources "$data_only_state" || \
    die "data-only post-destroy state self-test failed"
  state_has_no_managed_resources '' || die "empty post-destroy state self-test failed"
  ! state_has_no_managed_resources "$normal_state" || \
    die "managed post-destroy state self-test failed"
  ! state_has_no_managed_resources 'data.vsphere_tag.extra' || \
    die "unexpected post-destroy data self-test failed"
  state_fixture='{"values":{"root_module":{"resources":[{"address":"vsphere_virtual_machine.linux_server","mode":"managed","values":{"name":"first-test-vm","num_cpus":2,"memory":4096,"disk":[{"label":"disk0","size":80}]}}]}}}'
  printf '%s' "$state_fixture" | \
    state_vm_matches_inputs "$expected" first-test-vm 2 4096 80 || \
    die "VM identity state self-test failed"
  ! printf '%s' "$state_fixture" | \
    state_vm_matches_inputs "$expected" wrong-vm 2 4096 80 || \
    die "VM identity mismatch state self-test failed"
  printf 'cleanup state guard self-test passed\n'
  exit 0
fi

if [[ "$ASSUME_YES" == "true" && "$PREFLIGHT_ONLY" == "true" ]]; then
  die "--preflight and --yes are mutually exclusive"
fi

for required_name in STATE_KEY OFFERING REQUEST_ID VM_NAME SITE ENVIRONMENT CPU \
  MEMORY_GB DISK_SIZE_GB DATACENTER CLUSTER DATASTORE NETWORK TEMPLATE; do
  [[ -n "${!required_name}" ]] || die "missing required option for $required_name"
done

case "$OFFERING" in
  linux-server-deployment | windows-server-deployment) ;;
  *) die "unsupported offering: $OFFERING" ;;
esac

UUID_PATTERN='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
[[ "$REQUEST_ID" =~ ^$UUID_PATTERN$ ]] || die "request ID must be a UUID"
[[ "$STATE_KEY" =~ ^(request|step)-$UUID_PATTERN$ ]] || \
  die "state key must be request-<UUID> or step-<UUID>"
if [[ "$STATE_KEY" == request-* && "$STATE_KEY" != "request-$REQUEST_ID" ]]; then
  die "request state key does not match --request-id"
fi

for numeric_name in CPU MEMORY_GB DISK_SIZE_GB; do
  numeric_value="${!numeric_name}"
  [[ "$numeric_value" =~ ^[1-9][0-9]*$ ]] || die "$numeric_name must be a positive integer"
  [[ "${#numeric_value}" -le 10 ]] || die "$numeric_name exceeds the request input limit"
  ((numeric_value <= 4294967295)) || die "$numeric_name exceeds the request input limit"
done

[[ -r "$ENV_FILE" ]] || die "cannot read environment file: $ENV_FILE"
command -v jq >/dev/null 2>&1 || die "jq is required"
command -v shasum >/dev/null 2>&1 || die "shasum is required"

# shellcheck source=deploy/proving-ground/agent-env.sh
source "$HERE/agent-env.sh"
validate_private_agent_env_file "$ENV_FILE"
load_agent_env "$ENV_FILE"
validate_agent_env
validate_private_agent_state_dir "$STATE_DIR"
stage_approved_executable terraform "$PG_TERRAFORM_EXECUTABLE" \
  "$PG_TERRAFORM_EXPECTED_VERSION" "$PG_TERRAFORM_EXECUTABLE_SHA256" \
  "$STATE_DIR"
TERRAFORM_BIN="$APPROVED_EXECUTABLE_PATH"
[[ "$PG_AGENT_PLATFORM" == "DEFRA" ]] || die "PG_AGENT_PLATFORM must be DEFRA"
EXPECTED_BACKEND_HCL='terraform { backend "local" { path = "{STATE_DIR}/terraform-{STATE_KEY}.tfstate" } }'
[[ "$PG_AGENT_BACKEND_HCL" == "$EXPECTED_BACKEND_HCL" ]] || \
  die "cleanup requires the bundled isolated local backend template"
[[ "$PG_AGENT_ALLOW_LIVE" == "true" ]] || \
  die "PG_AGENT_ALLOW_LIVE must be true for out-of-band destroy"
[[ -n "$PG_VSPHERE_USER" ]] || die "PG_VSPHERE_USER is missing"
[[ -n "$PG_VSPHERE_PASSWORD" ]] || die "PG_VSPHERE_PASSWORD is missing"
[[ -n "$PG_VSPHERE_SERVER" ]] || die "PG_VSPHERE_SERVER is missing"
[[ -n "$PG_PROVIDER_AUTHORITY_ID" ]] || die "PG_PROVIDER_AUTHORITY_ID is missing"
[[ -n "$PG_PROVIDER_AUTHORITY_VERSION" ]] || die "PG_PROVIDER_AUTHORITY_VERSION is missing"
PROVIDER_AUTHORITY_FILE="$STATE_DIR/provider-authority.ref"
[[ -r "$PROVIDER_AUTHORITY_FILE" ]] || \
  die "pinned provider authority is missing; refusing cleanup against an unbound authority"
PINNED_PROVIDER_AUTHORITY="$(cat "$PROVIDER_AUTHORITY_FILE")"
CURRENT_PROVIDER_AUTHORITY="$(provider_authority_record \
  "$PG_PROVIDER_AUTHORITY_ID" "$PG_PROVIDER_AUTHORITY_VERSION")"
[[ "$PINNED_PROVIDER_AUTHORITY" == "$CURRENT_PROVIDER_AUTHORITY" ]] || \
  die "provider authority reference/version differs from the authority pinned before live execution"

BACKEND_HCL="$(render_agent_backend_hcl "$PG_AGENT_BACKEND_HCL" "$STATE_DIR")"
BACKEND_HCL="${BACKEND_HCL//\{STATE_KEY\}/$STATE_KEY}"
[[ "$BACKEND_HCL" != *'{STATE_DIR}'* && "$BACKEND_HCL" != *'{STATE_KEY}'* ]] || \
  die "backend template contains an unresolved placeholder"

BUNDLE_DIR="$REPO/sources/ryuki-runner/src/iac/$OFFERING"
[[ -r "$BUNDLE_DIR/main.tf" ]] || die "offering Terraform bundle is missing"
[[ -r "$BUNDLE_DIR/.terraform.lock.hcl" ]] || \
  die "offering Terraform dependency lock is missing"

umask 077
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-destroy.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
cp "$BUNDLE_DIR/main.tf" "$WORK_DIR/main.tf"
cp "$BUNDLE_DIR/.terraform.lock.hcl" "$WORK_DIR/.terraform.lock.hcl"
printf '%s\n' "$BACKEND_HCL" > "$WORK_DIR/backend.tf"

MEMORY_MB=$((MEMORY_GB * 1024))
jq -n \
  --arg vm_name "$VM_NAME" \
  --argjson num_cpus "$CPU" \
  --argjson memory_mb "$MEMORY_MB" \
  --argjson disk_size_gb "$DISK_SIZE_GB" \
  --arg site "$SITE" \
  --arg environment "$ENVIRONMENT" \
  --arg request_id "$REQUEST_ID" \
  --arg datacenter "$DATACENTER" \
  --arg cluster "$CLUSTER" \
  --arg datastore "$DATASTORE" \
  --arg network "$NETWORK" \
  --arg template "$TEMPLATE" \
  '{vm_name: $vm_name, num_cpus: $num_cpus, memory_mb: $memory_mb,
    disk_size_gb: $disk_size_gb, site: $site, environment: $environment,
    request_id: $request_id, datacenter: $datacenter, cluster: $cluster,
    datastore: $datastore, network: $network, template: $template}' \
  > "$WORK_DIR/ryuki.auto.tfvars.json"

if [[ "$PREFLIGHT_ONLY" == "true" ]]; then
  printf 'Cleanup preflight passed for isolated state %s; Terraform was not initialized and no provider was contacted.\n' \
    "$STATE_KEY"
  exit 0
fi

# HOME/TMPDIR are pinned to the disposable workspace. The initial re-exec left
# only PATH/HOME/TMPDIR/locale, and these are the only new exported values.
export HOME="$WORK_DIR" TMPDIR="$WORK_DIR"
export TF_VAR_vsphere_user="$PG_VSPHERE_USER"
export TF_VAR_vsphere_password="$PG_VSPHERE_PASSWORD" # secret-scan-allow: reviewed env reference
export TF_VAR_vsphere_server="$PG_VSPHERE_SERVER"
unset RYUKI_PG_ENV_ISOLATED
unset PG_AGENT_PLATFORM PG_AGENT_ALLOW_LIVE PG_AGENT_BACKEND_HCL
unset PG_TERRAFORM_EXECUTABLE PG_TERRAFORM_EXPECTED_VERSION \
  PG_TERRAFORM_EXECUTABLE_SHA256
unset PG_ANSIBLE_PLAYBOOK_EXECUTABLE PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION \
  PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256
unset PG_VSPHERE_USER PG_VSPHERE_PASSWORD PG_VSPHERE_SERVER
unset PG_PROVIDER_AUTHORITY_ID PG_PROVIDER_AUTHORITY_VERSION
unset PG_DB_PASSWORD PG_VAULT_TOKEN PG_LOCAL_USERS

printf 'Initializing isolated state %s for out-of-band cleanup.\n' "$STATE_KEY"
"$TERRAFORM_BIN" -chdir="$WORK_DIR" "${TERRAFORM_INIT_ARGS[@]}"
INITIAL_RESOURCES="$("$TERRAFORM_BIN" -chdir="$WORK_DIR" state list)"
[[ -n "$INITIAL_RESOURCES" ]] || \
  die "isolated state has no managed resources; refusing an unprovable cleanup"
case "$OFFERING" in
  linux-server-deployment) EXPECTED_VM_ADDRESS='vsphere_virtual_machine.linux_server' ;;
  windows-server-deployment) EXPECTED_VM_ADDRESS='vsphere_virtual_machine.windows_server' ;;
esac
state_has_only_expected_resources "$INITIAL_RESOURCES" "$EXPECTED_VM_ADDRESS" || \
  die "isolated state contains an unexpected address or not exactly one expected server resource"
if ! "$TERRAFORM_BIN" -chdir="$WORK_DIR" show -json | \
  state_vm_matches_inputs "$EXPECTED_VM_ADDRESS" "$VM_NAME" "$CPU" "$MEMORY_MB" "$DISK_SIZE_GB"; then
  die "isolated state VM identity does not match the approved original inputs"
fi
"$TERRAFORM_BIN" -chdir="$WORK_DIR" plan -destroy -input=false -out=destroy.tfplan
"$TERRAFORM_BIN" -chdir="$WORK_DIR" show -no-color destroy.tfplan

if [[ "$ASSUME_YES" != "true" ]]; then
  printf 'Type the exact state key to apply this destroy plan: '
  IFS= read -r confirmation
  [[ "$confirmation" == "$STATE_KEY" ]] || die "confirmation did not match; nothing applied"
fi

"$TERRAFORM_BIN" -chdir="$WORK_DIR" apply -input=false destroy.tfplan
REMAINING_RESOURCES="$("$TERRAFORM_BIN" -chdir="$WORK_DIR" state list)"
state_has_no_managed_resources "$REMAINING_RESOURCES" || \
  die "destroy completed but isolated state still has a managed or unexpected address"
unset TF_VAR_vsphere_user TF_VAR_vsphere_password TF_VAR_vsphere_server

EVIDENCE_FILE="$STATE_DIR/cleanup-$STATE_KEY-$(date -u +%Y%m%dT%H%M%SZ).txt"
{
  printf 'cleanup_mode=out-of-band-terraform\n'
  printf 'state_key=%s\n' "$STATE_KEY"
  printf 'offering=%s\n' "$OFFERING"
  printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'managed_resources=0\n'
  printf 'provider_verification=pending\n'
  printf 'provider_verified_by=\n'
  printf 'provider_verified_at=\n'
} > "$EVIDENCE_FILE"

printf 'Terraform state has no managed resources. Record direct provider verification in %s\n' \
  "$EVIDENCE_FILE"
