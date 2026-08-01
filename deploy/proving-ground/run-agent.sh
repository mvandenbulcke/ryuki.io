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

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$HERE/../.." && pwd -P)"
STATE_DIR="$HERE/agent-state"
RUSTC_GUARD="$REPO/scripts/cargo-rustc-disk-guard.sh"
HARD_MAX_BUILD_GIB=12
HARD_MIN_FREE_GIB=30
BUILD_TEST_MODE="${RYUKI_PG_BUILD_TEST_MODE:-0}"
BUILD_PREFLIGHT_ONLY="${RYUKI_PG_BUILD_PREFLIGHT_ONLY:-0}"
BUILD_TEST_STATE_BASE="${RYUKI_PG_BUILD_TEST_STATE_BASE:-}"
BUILD_TEST_MAX_KIB="${RYUKI_PG_BUILD_TEST_MAX_KIB:-}"
BUILD_TEST_COMMAND="${RYUKI_PG_BUILD_TEST_COMMAND:-}"
BUILD_TEST_CONTROL_FILE="${RYUKI_PG_BUILD_TEST_CONTROL_FILE:-}"
SUPERVISED_BUILD_PID=""
SUPERVISED_BUILD_PGID=""
BUILD_SUPERVISOR_PID=""
SUPERVISOR_ACTUAL_PID=""
BUILD_COMMAND_CONTROL_FILE=""
BUILD_COMMAND_CONTROL_TEMP=""
BUILD_COMMAND_RELEASE_FILE=""
BUILD_COMMAND_RELEASE_TEMP=""

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

require_positive_integer() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|0|0*|*[!0-9]*) fail "$name must be a positive integer" ;;
  esac
  (( ${#value} <= 9 )) || fail "$name is outside the supported integer range"
}

case "$BUILD_TEST_MODE" in
  0|1) ;;
  *) fail "RYUKI_PG_BUILD_TEST_MODE must be 0 or 1" ;;
esac
case "$BUILD_PREFLIGHT_ONLY" in
  0|1) ;;
  *) fail "RYUKI_PG_BUILD_PREFLIGHT_ONLY must be 0 or 1" ;;
esac
if [[ "$BUILD_TEST_MODE" != "1" && \
  ( "$BUILD_PREFLIGHT_ONLY" != "0" || -n "$BUILD_TEST_STATE_BASE" || \
    -n "$BUILD_TEST_MAX_KIB" || -n "$BUILD_TEST_COMMAND" || \
    -n "$BUILD_TEST_CONTROL_FILE" ) ]]; then
  fail "proving-ground build test controls require RYUKI_PG_BUILD_TEST_MODE=1"
fi
if [[ "$BUILD_TEST_MODE" == "1" && "$BUILD_PREFLIGHT_ONLY" != "1" ]]; then
  fail "proving-ground build test mode is restricted to preflight-only execution"
fi
if [[ -n "$BUILD_TEST_MAX_KIB" ]]; then
  require_positive_integer RYUKI_PG_BUILD_TEST_MAX_KIB "$BUILD_TEST_MAX_KIB"
  (( BUILD_TEST_MAX_KIB <= HARD_MAX_BUILD_GIB * 1024 * 1024 )) || \
    fail "RYUKI_PG_BUILD_TEST_MAX_KIB cannot weaken the production build ceiling"
fi
if [[ -n "$BUILD_TEST_COMMAND" || -n "$BUILD_TEST_CONTROL_FILE" ]]; then
  [[ -n "$BUILD_TEST_COMMAND" && -n "$BUILD_TEST_CONTROL_FILE" ]] || \
    fail "build test command and control file must be provided together"
fi

SHASUM_BIN="$(command -v shasum)" || fail "shasum is required to bind build ownership"

build_repository_id() {
  local output digest remainder
  output="$(printf '%s' "$REPO" | "$SHASUM_BIN" -a 256)" || \
    fail "cannot derive the proving-ground build namespace"
  read -r digest remainder <<< "$output"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid proving-ground repository digest"
  printf '%s' "$digest"
}

build_sentinel_contents() {
  local run_id="$1"
  printf '%s\n' \
    'version=1' \
    "repository_id=$BUILD_REPOSITORY_ID" \
    "run_id=$run_id" \
    "workspace=$REPO" \
    'disposition=disposable'
}

valid_build_run_id() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$ ]]
}

valid_build_sentinel() {
  local sentinel="$1"
  local run_id="$2"
  local expected_output actual_output expected_digest actual_digest remainder
  [[ -f "$sentinel" && ! -L "$sentinel" && -O "$sentinel" ]] || return 1
  valid_build_run_id "$run_id" || return 1
  expected_output="$(build_sentinel_contents "$run_id" | "$SHASUM_BIN" -a 256)" || \
    return 1
  read -r expected_digest remainder <<< "$expected_output"
  [[ "$expected_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  actual_output="$("$SHASUM_BIN" -a 256 -- "$sentinel")" || return 1
  read -r actual_digest remainder <<< "$actual_output"
  [[ "$actual_digest" =~ ^[0-9a-f]{64}$ && \
    "$actual_digest" == "$expected_digest" ]]
}

managed_build_dir() {
  local candidate="$1"
  local parent base run_id
  parent="$(dirname "$candidate")"
  base="$(basename "$candidate")"
  [[ "$parent" == "$BUILD_TARGET_ROOT" && "$base" == run.* ]] || return 1
  run_id="${base#run.}"
  valid_build_run_id "$run_id"
}

prepare_build_namespace() {
  local state_base_raw
  state_base_raw="${TMPDIR:-/tmp}"
  if [[ "$BUILD_TEST_MODE" == "1" ]]; then
    [[ -n "$BUILD_TEST_STATE_BASE" ]] || \
      fail "RYUKI_PG_BUILD_TEST_STATE_BASE is required in build test mode"
    state_base_raw="$BUILD_TEST_STATE_BASE"
  fi
  [[ -d "$state_base_raw" && -w "$state_base_raw" && -x "$state_base_raw" ]] || \
    fail "proving-ground build state base must be an existing writable directory"
  BUILD_STATE_BASE="$(cd "$state_base_raw" && pwd -P)" || \
    fail "cannot canonicalize the proving-ground build state base"
  [[ "$BUILD_STATE_BASE" != "/" ]] || \
    fail "filesystem root is not a safe proving-ground build state base"
  case "$BUILD_STATE_BASE/" in
    "$REPO/"|"$REPO/"*)
      fail "proving-ground build state must be outside the checkout"
      ;;
  esac

  BUILD_REPOSITORY_ID="$(build_repository_id)"
  BUILD_NAMESPACE="$BUILD_STATE_BASE/ryuki-proving-ground-build-$(id -u)"
  BUILD_TARGET_ROOT="$BUILD_NAMESPACE/$BUILD_REPOSITORY_ID"
  BUILD_LOCK_FILE="$BUILD_NAMESPACE/$BUILD_REPOSITORY_ID.lock"
  case "$BUILD_TARGET_ROOT/" in
    "$REPO/"*) fail "proving-ground build target must be outside the checkout" ;;
  esac

  if [[ -L "$BUILD_NAMESPACE" ]]; then
    fail "proving-ground build namespace must not be a symlink"
  fi
  if [[ ! -e "$BUILD_NAMESPACE" ]]; then
    mkdir -m 700 "$BUILD_NAMESPACE" || fail "cannot create proving-ground build namespace"
  fi
  [[ -d "$BUILD_NAMESPACE" && ! -L "$BUILD_NAMESPACE" && \
    -O "$BUILD_NAMESPACE" && -w "$BUILD_NAMESPACE" && -x "$BUILD_NAMESPACE" ]] || \
    fail "proving-ground build namespace is not a private owned directory"
  chmod 700 "$BUILD_NAMESPACE"

  if [[ -L "$BUILD_TARGET_ROOT" ]]; then
    fail "proving-ground build target root must not be a symlink"
  fi
  if [[ ! -e "$BUILD_TARGET_ROOT" ]]; then
    mkdir -m 700 "$BUILD_TARGET_ROOT" || \
      fail "cannot create proving-ground build target root"
  fi
  [[ -d "$BUILD_TARGET_ROOT" && ! -L "$BUILD_TARGET_ROOT" && \
    -O "$BUILD_TARGET_ROOT" && -w "$BUILD_TARGET_ROOT" && -x "$BUILD_TARGET_ROOT" ]] || \
    fail "proving-ground build target root is not a private owned directory"
  chmod 700 "$BUILD_TARGET_ROOT"
  [[ ! -L "$BUILD_LOCK_FILE" ]] || fail "proving-ground build lock must not be a symlink"
}

acquire_build_lock() {
  if ! { exec 9>>"$BUILD_LOCK_FILE"; }; then
    fail "cannot open proving-ground build lock"
  fi
  [[ -f "$BUILD_LOCK_FILE" && ! -L "$BUILD_LOCK_FILE" && -O "$BUILD_LOCK_FILE" ]] || \
    fail "proving-ground build lock is unsafe"
  chmod 600 "$BUILD_LOCK_FILE"
  if command -v flock >/dev/null 2>&1; then
    flock -n 9 || fail "another proving-ground agent build is already running"
  elif command -v lockf >/dev/null 2>&1; then
    lockf -s -t 0 9 || fail "another proving-ground agent build is already running"
  else
    fail "flock or lockf is required to serialize proving-ground agent builds"
  fi
}

run_without_build_lock() (
  exec 9>&-
  exec "$@"
)

pause_without_build_lock() (
  exec 9>&-
  sleep "$1"
)

command_control_contents() {
  local run_id="$1"
  local supervisor_pid="$2"
  local command_pid="$3"
  local command_pgid="$4"
  printf '%s\n' \
    'version=1' \
    "repository_id=$BUILD_REPOSITORY_ID" \
    "run_id=$run_id" \
    "supervisor_pid=$supervisor_pid" \
    "command_pid=$command_pid" \
    "command_pgid=$command_pgid"
}

command_control_value() {
  local control_file="$1"
  local wanted="$2"
  exec 9>&-
  awk -F= -v wanted="$wanted" '
    $1 == wanted {
      sub(/^[^=]*=/, "")
      print
      exit
    }
  ' "$control_file"
}

valid_command_control() {
  local control_file="$1"
  local run_id="$2"
  local expected_supervisor_pid="${3:-}"
  local supervisor_pid command_pid command_pgid
  local expected_output actual_output expected_digest actual_digest remainder

  [[ -f "$control_file" && ! -L "$control_file" && -O "$control_file" ]] || return 1
  supervisor_pid="$(command_control_value "$control_file" supervisor_pid)"
  command_pid="$(command_control_value "$control_file" command_pid)"
  command_pgid="$(command_control_value "$control_file" command_pgid)"
  [[ "$supervisor_pid" =~ ^[1-9][0-9]{0,9}$ && \
    "$command_pid" =~ ^[1-9][0-9]{0,9}$ && \
    "$command_pgid" =~ ^[1-9][0-9]{0,9}$ && \
    "$command_pid" == "$command_pgid" ]] || return 1
  [[ -z "$expected_supervisor_pid" || \
    "$supervisor_pid" == "$expected_supervisor_pid" ]] || return 1
  expected_output="$(exec 9>&-; command_control_contents "$run_id" "$supervisor_pid" \
    "$command_pid" "$command_pgid" | "$SHASUM_BIN" -a 256)" || return 1
  read -r expected_digest remainder <<< "$expected_output"
  [[ "$expected_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  actual_output="$(exec 9>&-; "$SHASUM_BIN" -a 256 -- "$control_file")" || return 1
  read -r actual_digest remainder <<< "$actual_output"
  [[ "$actual_digest" =~ ^[0-9a-f]{64}$ && \
    "$actual_digest" == "$expected_digest" ]]
}

publish_command_control() {
  local supervisor_pid="$1"
  local command_pid="$2"
  local command_pgid="$3"
  [[ ! -e "$BUILD_COMMAND_CONTROL_FILE" && ! -L "$BUILD_COMMAND_CONTROL_FILE" && \
    ! -e "$BUILD_COMMAND_CONTROL_TEMP" && ! -L "$BUILD_COMMAND_CONTROL_TEMP" ]] || \
    return 1
  (exec 9>&-; set -o noclobber; command_control_contents "$BUILD_RUN_ID" "$supervisor_pid" \
    "$command_pid" "$command_pgid" > "$BUILD_COMMAND_CONTROL_TEMP") || return 1
  run_without_build_lock chmod 600 "$BUILD_COMMAND_CONTROL_TEMP" || return 1
  run_without_build_lock mv -- "$BUILD_COMMAND_CONTROL_TEMP" \
    "$BUILD_COMMAND_CONTROL_FILE" || return 1
  valid_command_control "$BUILD_COMMAND_CONTROL_FILE" "$BUILD_RUN_ID" \
    "$supervisor_pid"
}

publish_command_release() {
  [[ ! -e "$BUILD_COMMAND_RELEASE_FILE" && ! -L "$BUILD_COMMAND_RELEASE_FILE" && \
    ! -e "$BUILD_COMMAND_RELEASE_TEMP" && ! -L "$BUILD_COMMAND_RELEASE_TEMP" ]] || \
    return 1
  (exec 9>&-; set -o noclobber; : > "$BUILD_COMMAND_RELEASE_TEMP") || return 1
  run_without_build_lock chmod 600 "$BUILD_COMMAND_RELEASE_TEMP" || return 1
  run_without_build_lock mv -- "$BUILD_COMMAND_RELEASE_TEMP" \
    "$BUILD_COMMAND_RELEASE_FILE"
}

clear_command_control() {
  local supervisor_pid="$1"
  if [[ -e "$BUILD_COMMAND_CONTROL_FILE" || -L "$BUILD_COMMAND_CONTROL_FILE" ]]; then
    valid_command_control "$BUILD_COMMAND_CONTROL_FILE" "$BUILD_RUN_ID" \
      "$supervisor_pid" || return 1
  fi
  run_without_build_lock rm -f -- "$BUILD_COMMAND_RELEASE_FILE" \
    "$BUILD_COMMAND_RELEASE_TEMP" \
    "$BUILD_COMMAND_CONTROL_TEMP"
  run_without_build_lock rm -f -- "$BUILD_COMMAND_CONTROL_FILE"
}

recover_command_control() {
  local build_root="$1"
  local run_id="$2"
  local expected_supervisor_pid="${3:-}"
  local control_file control_temp release_file release_temp
  local supervisor_pid command_pgid
  control_file="$build_root/.ryuki-proving-ground-command-owner"
  control_temp="$build_root/.ryuki-proving-ground-command-owner.next"
  release_file="$build_root/.ryuki-proving-ground-command-release"
  release_temp="$build_root/.ryuki-proving-ground-command-release.next"

  if [[ ! -e "$control_file" && ! -L "$control_file" ]]; then
    if [[ -e "$control_temp" || -L "$control_temp" || \
      -e "$release_file" || -L "$release_file" || \
      -e "$release_temp" || -L "$release_temp" ]]; then
      printf 'error: refusing malformed proving-ground command ownership state\n' >&2
      return 75
    fi
    return 0
  fi
  valid_command_control "$control_file" "$run_id" "$expected_supervisor_pid" || {
    printf 'error: refusing malformed proving-ground command ownership control\n' >&2
    return 75
  }
  supervisor_pid="$(command_control_value "$control_file" supervisor_pid)"
  command_pgid="$(command_control_value "$control_file" command_pgid)"
  if [[ -z "$expected_supervisor_pid" ]]; then
    if kill -0 "$supervisor_pid" 2>/dev/null || process_group_alive "$command_pgid"; then
      printf 'error: stale proving-ground command ownership still references live processes; refusing unsafe PID reuse recovery\n' >&2
      return 75
    fi
    run_without_build_lock rm -f -- "$release_file" "$release_temp" "$control_temp"
    run_without_build_lock rm -f -- "$control_file"
    return 0
  fi
  if process_group_alive "$command_pgid"; then
    printf 'recovering proving-ground Cargo process group after supervisor exit: %s\n' \
      "$command_pgid" >&2
    terminate_process_group "$command_pgid" || return $?
  fi
  run_without_build_lock rm -f -- "$release_file" "$release_temp" "$control_temp"
  run_without_build_lock rm -f -- "$control_file"
}

remove_owned_build_dir() {
  local candidate="$1"
  local run_id="$2"
  local sentinel deletion_sentinel
  sentinel="$candidate/.ryuki-proving-ground-build-owner"
  deletion_sentinel="$BUILD_TARGET_ROOT/.run.$run_id.delete.owner"
  managed_build_dir "$candidate" && [[ -d "$candidate" && ! -L "$candidate" && \
    -O "$candidate" ]] && valid_build_sentinel "$sentinel" "$run_id" || return 1
  recover_command_control "$candidate" "$run_id" || return 1
  [[ ! -e "$deletion_sentinel" && ! -L "$deletion_sentinel" ]] || return 1

  # Publish ownership outside the tree before recursively deleting it. If this
  # process is SIGKILLed during rm, the next locked start can still prove that
  # the partially removed, now-unmarked directory is ours and retry safely.
  mv -- "$sentinel" "$deletion_sentinel" || return 1
  rm -rf -- "$candidate" || return 1
  rm -f -- "$deletion_sentinel"
}

reclaim_stale_build_dirs() {
  local setup deletion candidate sentinel base run_id paired
  local remaining_entries=()

  for setup in "$BUILD_TARGET_ROOT"/.run.*.owner.tmp; do
    [[ -e "$setup" || -L "$setup" ]] || continue
    base="$(basename "$setup")"
    run_id="${base#.run.}"
    run_id="${run_id%.owner.tmp}"
    valid_build_sentinel "$setup" "$run_id" || \
      fail "refusing malformed proving-ground build setup sentinel: $setup"
    paired="$BUILD_TARGET_ROOT/run.$run_id"
    if [[ -e "$paired" || -L "$paired" ]]; then
      [[ -d "$paired" && ! -L "$paired" && -O "$paired" ]] || \
        fail "refusing malformed proving-ground build setup directory: $paired"
      rm -rf -- "$paired"
    fi
    rm -f -- "$setup"
  done

  for deletion in "$BUILD_TARGET_ROOT"/.run.*.delete.owner; do
    [[ -e "$deletion" || -L "$deletion" ]] || continue
    base="$(basename "$deletion")"
    run_id="${base#.run.}"
    run_id="${run_id%.delete.owner}"
    valid_build_sentinel "$deletion" "$run_id" || \
      fail "refusing malformed proving-ground deletion sentinel: $deletion"
    paired="$BUILD_TARGET_ROOT/run.$run_id"
    if [[ -e "$paired" || -L "$paired" ]]; then
      managed_build_dir "$paired" && [[ -d "$paired" && ! -L "$paired" && \
        -O "$paired" ]] || \
        fail "refusing malformed proving-ground build deletion directory: $paired"
      rm -rf -- "$paired"
    fi
    rm -f -- "$deletion"
  done

  for candidate in "$BUILD_TARGET_ROOT"/run.*; do
    [[ -e "$candidate" || -L "$candidate" ]] || continue
    managed_build_dir "$candidate" && [[ -d "$candidate" && ! -L "$candidate" && \
      -O "$candidate" ]] || \
      fail "refusing malformed proving-ground build entry: $candidate"
    run_id="${candidate##*/run.}"
    sentinel="$candidate/.ryuki-proving-ground-build-owner"
    valid_build_sentinel "$sentinel" "$run_id" || \
      fail "refusing unmarked or malformed proving-ground build entry: $candidate"
    printf 'removing stale proving-ground build from interrupted run: %s\n' \
      "$candidate" >&2
    remove_owned_build_dir "$candidate" "$run_id" || \
      fail "cannot reclaim owned proving-ground build entry: $candidate"
  done

  shopt -s nullglob dotglob
  remaining_entries=("$BUILD_TARGET_ROOT"/*)
  shopt -u nullglob dotglob
  (( ${#remaining_entries[@]} == 0 )) || \
    fail "refusing unrecognized proving-ground build namespace entry: ${remaining_entries[0]}"
}

measure_build_tree_kib() {
  local path="$1"
  local allocated_output allocated_kib apparent_output apparent_kib
  allocated_output="$(du -s -k "$path" 2>/dev/null)" || return 1
  allocated_kib="$(printf '%s\n' "$allocated_output" | awk 'END {print $1}')"
  if du --apparent-size --count-links -s -k /dev/null >/dev/null 2>&1; then
    apparent_output="$(du --apparent-size --count-links -s -k "$path" 2>/dev/null)" || \
      return 1
  elif du -A -l -s -k /dev/null >/dev/null 2>&1; then
    apparent_output="$(du -A -l -s -k "$path" 2>/dev/null)" || return 1
  else
    return 1
  fi
  apparent_kib="$(printf '%s\n' "$apparent_output" | awk 'END {print $1}')"
  [[ "$allocated_kib" =~ ^[0-9]+$ && "$apparent_kib" =~ ^[0-9]+$ ]] || return 1
  if (( apparent_kib > allocated_kib )); then
    printf '%s\n' "$apparent_kib"
  else
    printf '%s\n' "$allocated_kib"
  fi
}

check_build_disk_bounds() {
  local target_kib free_kib max_target_kib min_free_kib
  if ! target_kib="$(exec 9>&-; measure_build_tree_kib "$BUILD_TARGET_ROOT")"; then
    printf 'error: cannot measure proving-ground build namespace size\n' >&2
    return 75
  fi
  free_kib="$(exec 9>&-; df -Pk "$BUILD_TARGET_ROOT" | awk 'END {print $4}')"
  if [[ ! "$target_kib" =~ ^[0-9]+$ || ! "$free_kib" =~ ^[0-9]+$ ]]; then
    printf 'error: cannot measure proving-ground build disk headroom\n' >&2
    return 75
  fi
  max_target_kib=$((HARD_MAX_BUILD_GIB * 1024 * 1024))
  min_free_kib=$((HARD_MIN_FREE_GIB * 1024 * 1024))
  if [[ "$BUILD_TEST_MODE" == "1" && -n "$BUILD_TEST_MAX_KIB" ]]; then
    max_target_kib="$BUILD_TEST_MAX_KIB"
  fi
  if (( target_kib > max_target_kib )); then
    printf 'error: proving-ground builds exceed the %s GiB aggregate ceiling\n' \
      "$HARD_MAX_BUILD_GIB" >&2
    return 75
  fi
  if (( free_kib < min_free_kib )); then
    printf 'error: proving-ground build refused with less than %s GiB free\n' \
      "$HARD_MIN_FREE_GIB" >&2
    return 75
  fi
}

process_group_alive() {
  local pgid="${1:-}"
  [[ -n "$pgid" ]] || return 1
  kill -0 -- "-$pgid" 2>/dev/null
}

terminate_process_group() {
  local pgid="$1"
  local attempt
  process_group_alive "$pgid" || return 0
  kill -TERM -- "-$pgid" 2>/dev/null || true
  # The pinned rustc guard may need its full two-second TERM window to stop a
  # separately grouped compiler/linker. Keep the outer Cargo grace strictly
  # longer so we never KILL that guard before it can reap its nested group.
  for attempt in {1..50}; do
    process_group_alive "$pgid" || return 0
    pause_without_build_lock 0.1
  done
  kill -KILL -- "-$pgid" 2>/dev/null || true
  for attempt in {1..20}; do
    process_group_alive "$pgid" || return 0
    pause_without_build_lock 0.1
  done
  return 75
}

stop_supervised_build() {
  local pid="${SUPERVISED_BUILD_PID:-}"
  local pgid="${SUPERVISED_BUILD_PGID:-}"
  local status=0
  if [[ -n "$pgid" ]] && process_group_alive "$pgid"; then
    terminate_process_group "$pgid" || status=$?
  elif [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
  [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true
  SUPERVISED_BUILD_PID=""
  SUPERVISED_BUILD_PGID=""
  return "$status"
}

supervisor_signal() {
  local status="$1"
  trap '' HUP INT TERM
  stop_supervised_build || true
  [[ -z "$SUPERVISOR_ACTUAL_PID" ]] || \
    clear_command_control "$SUPERVISOR_ACTUAL_PID" || true
  exit "$status"
}

supervise_build_command() {
  local wrapper_pid="$1"
  local command_status_file command_status_tmp
  local command_pid command_pgid command_status command_wait_status
  local guard_status stop_status release_attempt released supervisor_pid_probe
  shift

  trap - EXIT HUP INT TERM
  trap 'supervisor_signal 129' HUP
  trap 'supervisor_signal 130' INT
  trap 'supervisor_signal 143' TERM
  supervisor_pid_probe="$BUILD_ROOT/.supervisor-pid-probe.$BUILD_RUN_ID"
  [[ ! -e "$supervisor_pid_probe" && ! -L "$supervisor_pid_probe" ]] || return 75
  set -o noclobber
  if ! run_without_build_lock /bin/sh -c 'printf "%s\n" "$PPID"' \
    > "$supervisor_pid_probe"; then
    set +o noclobber
    return 75
  fi
  set +o noclobber
  read -r SUPERVISOR_ACTUAL_PID < "$supervisor_pid_probe" || \
    SUPERVISOR_ACTUAL_PID=""
  run_without_build_lock rm -f -- "$supervisor_pid_probe"
  [[ "$SUPERVISOR_ACTUAL_PID" =~ ^[1-9][0-9]{0,9}$ ]] || return 75
  check_build_disk_bounds || return $?
  command_status_file="$BUILD_ROOT/.cargo-command-status.$BUILD_RUN_ID"
  command_status_tmp="$command_status_file.tmp"
  set -m
  (
    trap - EXIT HUP INT TERM
    exec 9>&-
    released=0
    for release_attempt in {1..100}; do
      if [[ -e "$BUILD_COMMAND_RELEASE_FILE" || -L "$BUILD_COMMAND_RELEASE_FILE" ]]; then
        [[ -f "$BUILD_COMMAND_RELEASE_FILE" && ! -L "$BUILD_COMMAND_RELEASE_FILE" && \
          -O "$BUILD_COMMAND_RELEASE_FILE" ]] || exit 75
        rm -f -- "$BUILD_COMMAND_RELEASE_FILE"
        released=1
        break
      fi
      kill -0 "$SUPERVISOR_ACTUAL_PID" 2>/dev/null || exit 75
      sleep 0.05
    done
    (( released == 1 )) || exit 75
    set +e
    "$@"
    command_status=$?
    printf '%s\n' "$command_status" > "$command_status_tmp"
    mv -f -- "$command_status_tmp" "$command_status_file"
    exit "$command_status"
  ) &
  command_pid=$!
  command_pgid="$command_pid"
  set +m
  SUPERVISED_BUILD_PID="$command_pid"
  SUPERVISED_BUILD_PGID="$command_pgid"
  if ! publish_command_control "$SUPERVISOR_ACTUAL_PID" "$command_pid" \
    "$command_pgid" || ! publish_command_release; then
    stop_supervised_build || true
    clear_command_control "$SUPERVISOR_ACTUAL_PID" || true
    return 75
  fi

  while process_group_alive "$command_pgid"; do
    if ! kill -0 "$wrapper_pid" 2>/dev/null; then
      printf 'error: stopping proving-ground Cargo build after its runner was interrupted\n' >&2
      stop_supervised_build || true
      run_without_build_lock rm -f -- "$command_status_file" "$command_status_tmp"
      clear_command_control "$SUPERVISOR_ACTUAL_PID" || true
      return 75
    fi
    pause_without_build_lock 1
    if ! kill -0 "$wrapper_pid" 2>/dev/null; then
      printf 'error: stopping proving-ground Cargo build after its runner was interrupted\n' >&2
      stop_supervised_build || true
      run_without_build_lock rm -f -- "$command_status_file" "$command_status_tmp"
      clear_command_control "$SUPERVISOR_ACTUAL_PID" || true
      return 75
    fi
    if check_build_disk_bounds; then
      :
    else
      guard_status=$?
      printf 'error: stopping proving-ground Cargo build before it can exhaust the disk\n' >&2
      stop_supervised_build || true
      run_without_build_lock rm -f -- "$command_status_file" "$command_status_tmp"
      clear_command_control "$SUPERVISOR_ACTUAL_PID" || true
      return "$guard_status"
    fi
    [[ ! -f "$command_status_file" ]] || break
  done

  if wait "$command_pid"; then
    command_wait_status=0
  else
    command_wait_status=$?
  fi
  SUPERVISED_BUILD_PID=""
  if [[ -f "$command_status_file" ]]; then
    read -r command_status < "$command_status_file" || command_status=""
  else
    command_status="$command_wait_status"
  fi
  if [[ ! "$command_status" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
    printf 'error: proving-ground Cargo build did not publish a valid status\n' >&2
    command_status=75
  fi
  run_without_build_lock rm -f -- "$command_status_file" "$command_status_tmp"

  stop_status=0
  if process_group_alive "$command_pgid"; then
    printf 'stopping surviving proving-ground Cargo descendants after command exit\n' >&2
  fi
  SUPERVISED_BUILD_PGID="$command_pgid"
  stop_supervised_build || stop_status=$?
  (( stop_status == 0 )) || return "$stop_status"
  clear_command_control "$SUPERVISOR_ACTUAL_PID" || return 75
  check_build_disk_bounds || return $?
  return "$command_status"
}

stop_build_supervisor() {
  local pid="${BUILD_SUPERVISOR_PID:-}"
  local recovery_status=0
  [[ -n "$pid" ]] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  recover_command_control "$BUILD_ROOT" "$BUILD_RUN_ID" "$pid" || \
    recovery_status=$?
  BUILD_SUPERVISOR_PID=""
  return "$recovery_status"
}

run_supervised_build_command() {
  local wrapper_pid="$$"
  local supervisor_status supervisor_pid recovery_status control_remained
  (
    supervise_build_command "$wrapper_pid" "$@"
  ) &
  BUILD_SUPERVISOR_PID=$!
  supervisor_pid="$BUILD_SUPERVISOR_PID"
  if wait "$BUILD_SUPERVISOR_PID"; then
    supervisor_status=0
  else
    supervisor_status=$?
  fi
  control_remained=0
  if [[ -e "$BUILD_COMMAND_CONTROL_FILE" || -L "$BUILD_COMMAND_CONTROL_FILE" ]]; then
    control_remained=1
  fi
  recovery_status=0
  recover_command_control "$BUILD_ROOT" "$BUILD_RUN_ID" "$supervisor_pid" || \
    recovery_status=$?
  BUILD_SUPERVISOR_PID=""
  (( recovery_status == 0 )) || return "$recovery_status"
  if (( supervisor_status == 0 && control_remained == 1 )); then
    printf 'error: proving-ground build supervisor left command ownership published\n' >&2
    return 75
  fi
  return "$supervisor_status"
}

initialize_build_workspace() {
  prepare_build_namespace
  acquire_build_lock
  reclaim_stale_build_dirs
  check_build_disk_bounds || fail "proving-ground build disk preflight failed"
}

create_build_root() {
  local sentinel_temp
  BUILD_RUN_ID="$$.$RANDOM.$RANDOM"
  BUILD_ROOT="$BUILD_TARGET_ROOT/run.$BUILD_RUN_ID"
  BUILD_COMMAND_CONTROL_FILE="$BUILD_ROOT/.ryuki-proving-ground-command-owner"
  BUILD_COMMAND_CONTROL_TEMP="$BUILD_ROOT/.ryuki-proving-ground-command-owner.next"
  BUILD_COMMAND_RELEASE_FILE="$BUILD_ROOT/.ryuki-proving-ground-command-release"
  BUILD_COMMAND_RELEASE_TEMP="$BUILD_ROOT/.ryuki-proving-ground-command-release.next"
  sentinel_temp="$BUILD_TARGET_ROOT/.run.$BUILD_RUN_ID.owner.tmp"
  [[ ! -e "$BUILD_ROOT" && ! -L "$BUILD_ROOT" && \
    ! -e "$sentinel_temp" && ! -L "$sentinel_temp" ]] || \
    fail "proving-ground build ownership path already exists"
  (set -o noclobber; build_sentinel_contents "$BUILD_RUN_ID" > "$sentinel_temp") || \
    fail "cannot stage proving-ground build ownership sentinel"
  chmod 600 "$sentinel_temp"
  mkdir -m 700 "$BUILD_ROOT" || fail "cannot create private proving-ground build root"
  mv "$sentinel_temp" "$BUILD_ROOT/.ryuki-proving-ground-build-owner" || \
    fail "cannot publish proving-ground build ownership sentinel"
}

if [[ "$BUILD_PREFLIGHT_ONLY" == "1" ]]; then
  initialize_build_workspace
  if [[ -n "$BUILD_TEST_COMMAND" ]]; then
    [[ "$BUILD_TEST_COMMAND" == /* && -f "$BUILD_TEST_COMMAND" && \
      ! -L "$BUILD_TEST_COMMAND" && -x "$BUILD_TEST_COMMAND" ]] || \
      fail "build test command must be an absolute regular executable"
    [[ "$BUILD_TEST_CONTROL_FILE" == /* ]] || \
      fail "build test control file must be absolute"
    create_build_root
    test_status=0
    run_supervised_build_command "$BUILD_TEST_COMMAND" "$BUILD_ROOT" \
      "$BUILD_TEST_CONTROL_FILE" || test_status=$?
    stop_build_supervisor || true
    remove_owned_build_dir "$BUILD_ROOT" "$BUILD_RUN_ID" || \
      fail "cannot remove proving-ground build test root"
    exit "$test_status"
  fi
  printf 'proving-ground build preflight passed\n'
  exit 0
fi

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
[[ -f "$RUSTC_GUARD" && ! -L "$RUSTC_GUARD" && -x "$RUSTC_GUARD" ]] || \
  fail "repository Cargo rustc guard is missing or unsafe: $RUSTC_GUARD"
initialize_build_workspace
create_build_root
STAGED_AGENT="$STATE_DIR/.ryuki-agent.$$"
MANIFEST_TEMP=""
cleanup_build() {
  local status=0
  stop_build_supervisor || status=$?
  if [[ -e "$BUILD_ROOT" || -L "$BUILD_ROOT" ]]; then
    if ! remove_owned_build_dir "$BUILD_ROOT" "$BUILD_RUN_ID"; then
      printf 'error: refusing to remove unsafe proving-ground build root: %s\n' \
        "$BUILD_ROOT" >&2
      status=1
    fi
  fi
  rm -f "$STAGED_AGENT"
  [[ -z "$MANIFEST_TEMP" ]] || rm -f "$MANIFEST_TEMP"
  return "$status"
}
handle_build_signal() {
  local status="$1"
  trap - EXIT
  trap '' HUP INT TERM
  stop_build_supervisor || true
  cleanup_build || true
  exit "$status"
}
trap cleanup_build EXIT
trap 'handle_build_signal 129' HUP
trap 'handle_build_signal 130' INT
trap 'handle_build_signal 143' TERM

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
CARGO_TARGET_ROOT="$BUILD_ROOT/target"
CARGO_BUILD_ROOT="$CARGO_TARGET_ROOT/build"
mkdir -m 700 "$CARGO_TARGET_ROOT" "$CARGO_BUILD_ROOT"
cargo_build_command() (
  cd "$BUILD_SOURCE"
  exec env -i \
    "PATH=${PATH:?PATH is required}" \
    "HOME=${HOME:-/tmp}" \
    "TMPDIR=${TMPDIR:-/tmp}" \
    "CARGO_TARGET_DIR=$CARGO_TARGET_ROOT" \
    "CARGO_BUILD_TARGET_DIR=$CARGO_TARGET_ROOT" \
    "CARGO_BUILD_BUILD_DIR=$CARGO_BUILD_ROOT" \
    "RUSTC_WRAPPER=$RUSTC_GUARD" \
    "CARGO_BUILD_RUSTC_WRAPPER=$RUSTC_GUARD" \
    'CARGO_INCREMENTAL=0' \
    'CARGO_PROFILE_RELEASE_INCREMENTAL=false' \
    'CARGO_PROFILE_RELEASE_DEBUG=0' \
    "RYUKI_CARGO_MAX_TARGET_GIB=$HARD_MAX_BUILD_GIB" \
    "RYUKI_CARGO_MIN_FREE_GIB=$HARD_MIN_FREE_GIB" \
    'RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1' \
    "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    "$CARGO_BIN" build --locked --offline --release -p ryuki-agent \
      --target-dir "$CARGO_TARGET_ROOT"
)
run_supervised_build_command cargo_build_command || \
  fail "locked proving-ground Cargo build failed or exceeded its disk boundary"
verify_signed_clean_checkout
BUILT_AGENT="$CARGO_TARGET_ROOT/release/ryuki-agent"
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
cleanup_build || fail "cannot remove the disposable proving-ground build root"
trap - EXIT HUP INT TERM
exec 9>&-

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
unset RYUKI_AGENT_DEPLOYMENT_ID RYUKI_AGENT_TRUST_DOMAIN_ID
if [[ "$RYUKI_AGENT_ALLOW_LIVE" == "true" ]]; then
  export RYUKI_AGENT_DEPLOYMENT_ID="${PG_AGENT_DEPLOYMENT_ID:?PG_AGENT_DEPLOYMENT_ID missing in .env}"
  export RYUKI_AGENT_TRUST_DOMAIN_ID="${PG_AGENT_TRUST_DOMAIN_ID:?PG_AGENT_TRUST_DOMAIN_ID missing in .env}"
fi
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
unset PG_AGENT_DEPLOYMENT_ID PG_AGENT_TRUST_DOMAIN_ID
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
