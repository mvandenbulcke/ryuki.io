#!/usr/bin/env bash
set -Eeuo pipefail

# One-shot workspace verification with a bounded, disposable Cargo cache.
#
# Cargo's normal `target/` directory is intentionally persistent and has no
# automatic eviction policy. That is useful during interactive development,
# but a full workspace/SSR/WASM verification wave can retain many toolchain and
# feature combinations. This wrapper isolates those objects, disables the two
# largest one-shot cache multipliers, serializes verification across worktrees,
# checks disk headroom between gates, and removes its target on success, failure,
# interruption, or the next run after an untrappable process death.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROOT_PARENT="$(cd "${ROOT_DIR}/.." && pwd -P)"
RUSTC_GUARD="${ROOT_DIR}/scripts/cargo-rustc-disk-guard.sh"
HARD_MAX_TARGET_GIB=24
HARD_MIN_FREE_GIB=30
HARD_MAX_WATCH_INTERVAL_SECONDS=2
# Bash `ulimit -f` uses 1024-byte blocks. Cap every supervised command at an
# 8 GiB regular file so a single malformed artifact cannot consume the disk
# between watcher samples.
HARD_MAX_FILE_KIB=8388608
HARD_CARGO_BUILD_JOBS=1
HARD_STOP_PHASE_ATTEMPTS=10
TEST_MODE="${RYUKI_VERIFY_TEST_MODE:-0}"
TEST_MAX_KIB="${RYUKI_VERIFY_TEST_MAX_KIB:-}"
TEST_FILE_LIMIT_KIB="${RYUKI_VERIFY_TEST_FILE_LIMIT_KIB:-}"
TEST_REGROUPED_PGID_FILE="${RYUKI_VERIFY_TEST_REGROUPED_PGID_FILE:-}"
STATE_BASE_INPUT="${RYUKI_VERIFY_STATE_BASE:-/tmp}"
if [[ ! -f "$RUSTC_GUARD" || -L "$RUSTC_GUARD" || ! -x "$RUSTC_GUARD" ]]; then
  echo "error: repository Cargo rustc guard is missing or unsafe: ${RUSTC_GUARD}" >&2
  exit 75
fi
if [[ -n "${RYUKI_VERIFY_STATE_BASE:-}" && "$TEST_MODE" != "1" ]]; then
  echo "error: RYUKI_VERIFY_STATE_BASE is reserved for verify-clean regression tests" >&2
  exit 64
fi
STATE_BASE_ROOT="$(cd "$STATE_BASE_INPUT" && pwd -P)"
GIT_COMMON_DIR_RAW="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)"
GIT_COMMON_DIR="$(cd "$GIT_COMMON_DIR_RAW" && pwd -P)"
REPOSITORY_ID="$(printf '%s' "$GIT_COMMON_DIR" | git -C "$ROOT_DIR" hash-object --stdin)"
MIN_FREE_GIB="${RYUKI_VERIFY_MIN_FREE_GIB:-30}"
MAX_TARGET_GIB="${RYUKI_VERIFY_MAX_TARGET_GIB:-24}"
KEEP_TARGET="${RYUKI_VERIFY_KEEP_TARGET:-0}"
WATCH_INTERVAL_SECONDS="${RYUKI_VERIFY_WATCH_INTERVAL_SECONDS:-2}"
ACTIVE_GATE_PID=""
SUPERVISED_COMMAND_PID=""
SUPERVISED_COMMAND_PGID=""
GATE_SUPERVISOR_ACTUAL_PID=""
FROZEN_ROOT_PGID=""
REGROUPED_PROCESS_PGIDS=()
RETAIN_CURRENT_TARGET=0
WRAPPER_PID="$$"
VERIFY_NAMESPACE="${STATE_BASE_ROOT}/ryuki-verify-$(id -u)"
VERIFY_TARGET_ROOT="${VERIFY_NAMESPACE}/${REPOSITORY_ID}"
VERIFY_LOCK_FILE="${VERIFY_NAMESPACE}/${REPOSITORY_ID}.lock"
RUN_ID="$$.$RANDOM.$RANDOM"
VERIFY_DIR="${VERIFY_TARGET_ROOT}/run.${RUN_ID}"
VERIFY_DIR_CREATED=0
SENTINEL_TMP="${VERIFY_TARGET_ROOT}/.run.${RUN_ID}.owner.tmp"
SENTINEL_TMP_CREATED=0
SENTINEL_PUBLISHED=0
VERIFY_GATE_CONTROL_FILE="${VERIFY_DIR}/.ryuki-verify-command-owner"
VERIFY_GATE_CONTROL_TEMP="${VERIFY_GATE_CONTROL_FILE}.next"
VERIFY_GATE_RELEASE_FILE="${VERIFY_DIR}/.ryuki-verify-command-release"
VERIFY_GATE_RELEASE_TEMP="${VERIFY_GATE_RELEASE_FILE}.next"

# Dedicated Cargo environment variables override checked-in configuration.
# Do not let an inherited IDE, sccache, or caller configuration redirect the
# target or replace the repository guard inside this bounded verification.
unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR CARGO_BUILD_BUILD_DIR
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
unset CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
unset CARGO_BUILD_INCREMENTAL
unset CARGO_BUILD_JOBS
unset CARGO_PROFILE_DEV_INCREMENTAL CARGO_PROFILE_TEST_INCREMENTAL
unset RYUKI_CARGO_GUARD_TEST_MODE RYUKI_CARGO_GUARD_TEST_MAX_KIB
unset RYUKI_CARGO_MAX_TARGET_GIB RYUKI_CARGO_MIN_FREE_GIB
unset RYUKI_CARGO_GUARD_INTERVAL_SECONDS
unset RYUKI_CARGO_OUTER_CONTROL_FILE
unset RYUKI_VERIFY_TEST_FILE_LIMIT_KIB
export CARGO_TARGET_DIR="${VERIFY_DIR}/target"
export CARGO_BUILD_BUILD_DIR="${CARGO_TARGET_DIR}/build-cache"
export RUSTC_WRAPPER="$RUSTC_GUARD"
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="$HARD_CARGO_BUILD_JOBS"
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RYUKI_CARGO_MAX_TARGET_GIB="$MAX_TARGET_GIB"
export RYUKI_CARGO_MIN_FREE_GIB="$MIN_FREE_GIB"
export RYUKI_CARGO_GUARD_INTERVAL_SECONDS=2

require_positive_integer() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|0|0*|*[!0-9]*)
      echo "error: ${name} must be a positive integer (got '${value}')" >&2
      exit 64
      ;;
  esac
  if (( ${#value} > 9 )); then
    echo "error: ${name} is outside the supported integer range" >&2
    exit 64
  fi
}

require_positive_integer RYUKI_VERIFY_MIN_FREE_GIB "$MIN_FREE_GIB"
require_positive_integer RYUKI_VERIFY_MAX_TARGET_GIB "$MAX_TARGET_GIB"
require_positive_integer RYUKI_VERIFY_WATCH_INTERVAL_SECONDS "$WATCH_INTERVAL_SECONDS"

case "$TEST_MODE" in
  0|1) ;;
  *)
    echo "error: RYUKI_VERIFY_TEST_MODE must be 0 or 1" >&2
    exit 64
    ;;
esac

if [[ "$TEST_MODE" == "1" ]]; then
  if [[ -z "${RYUKI_VERIFY_STATE_BASE:-}" ]]; then
    echo "error: verify-clean test mode requires an explicit external RYUKI_VERIFY_STATE_BASE" >&2
    exit 64
  fi
  case "$STATE_BASE_ROOT" in
    "$ROOT_PARENT"|"$ROOT_PARENT"/*)
      echo "error: verify-clean test state must be outside the repository and its parent" >&2
      exit 64
      ;;
  esac
  if [[ -L "$STATE_BASE_INPUT" || ! -d "$STATE_BASE_ROOT" \
    || ! -O "$STATE_BASE_ROOT" || ! -w "$STATE_BASE_ROOT" ]]; then
    echo "error: verify-clean test state must be a canonical, owned, writable directory" >&2
    exit 64
  fi
fi

if [[ -n "$TEST_MAX_KIB" && "$TEST_MODE" != "1" ]]; then
  echo "error: RYUKI_VERIFY_TEST_MAX_KIB is reserved for regression tests" >&2
  exit 64
fi
if [[ -n "$TEST_MAX_KIB" ]]; then
  require_positive_integer RYUKI_VERIFY_TEST_MAX_KIB "$TEST_MAX_KIB"
  if (( TEST_MAX_KIB > MAX_TARGET_GIB * 1024 * 1024 )); then
    echo "error: RYUKI_VERIFY_TEST_MAX_KIB must not exceed the configured verification target ceiling" >&2
    exit 64
  fi
fi

FILE_LIMIT_KIB="$HARD_MAX_FILE_KIB"
if [[ -n "$TEST_FILE_LIMIT_KIB" && "$TEST_MODE" != "1" ]]; then
  echo "error: RYUKI_VERIFY_TEST_FILE_LIMIT_KIB is reserved for regression tests" >&2
  exit 64
fi
if [[ -n "$TEST_REGROUPED_PGID_FILE" && "$TEST_MODE" != "1" ]]; then
  echo "error: RYUKI_VERIFY_TEST_REGROUPED_PGID_FILE is reserved for regression tests" >&2
  exit 64
fi
if [[ -n "$TEST_FILE_LIMIT_KIB" ]]; then
  require_positive_integer RYUKI_VERIFY_TEST_FILE_LIMIT_KIB "$TEST_FILE_LIMIT_KIB"
  if (( TEST_FILE_LIMIT_KIB >= HARD_MAX_FILE_KIB )); then
    echo "error: RYUKI_VERIFY_TEST_FILE_LIMIT_KIB must be stricter than ${HARD_MAX_FILE_KIB} KiB" >&2
    exit 64
  fi
  FILE_LIMIT_KIB="$TEST_FILE_LIMIT_KIB"
fi

if (( MAX_TARGET_GIB > HARD_MAX_TARGET_GIB )); then
  echo "error: RYUKI_VERIFY_MAX_TARGET_GIB must not exceed ${HARD_MAX_TARGET_GIB}" >&2
  exit 64
fi
if (( MIN_FREE_GIB < HARD_MIN_FREE_GIB )); then
  echo "error: RYUKI_VERIFY_MIN_FREE_GIB must not be less than ${HARD_MIN_FREE_GIB}" >&2
  exit 64
fi
if (( WATCH_INTERVAL_SECONDS > HARD_MAX_WATCH_INTERVAL_SECONDS )); then
  echo "error: RYUKI_VERIFY_WATCH_INTERVAL_SECONDS must not exceed ${HARD_MAX_WATCH_INTERVAL_SECONDS}" >&2
  exit 64
fi

case "$KEEP_TARGET" in
  0|1) ;;
  *)
    echo "error: RYUKI_VERIFY_KEEP_TARGET must be 0 or 1 (got '${KEEP_TARGET}')" >&2
    exit 64
    ;;
esac

if du --apparent-size --count-links -s -k /dev/null >/dev/null 2>&1; then
  APPARENT_DU_STYLE=gnu
elif du -A -l -s -k /dev/null >/dev/null 2>&1; then
  APPARENT_DU_STYLE=bsd
else
  echo "error: du cannot measure apparent file size on this host" >&2
  exit 69
fi

measure_tree_kib() {
  local path="$1"
  local allocated_output="" allocated_kib=""
  local apparent_output="" apparent_kib=""

  if ! allocated_output="$(du -s -k "$path" 2>/dev/null)"; then
    return 1
  fi
  allocated_kib="$(printf '%s\n' "$allocated_output" | awk 'END {print $1}')"

  if [[ "$APPARENT_DU_STYLE" == "gnu" ]]; then
    if ! apparent_output="$(du --apparent-size --count-links -s -k "$path" 2>/dev/null)"; then
      return 1
    fi
  else
    if ! apparent_output="$(du -A -l -s -k "$path" 2>/dev/null)"; then
      return 1
    fi
  fi
  apparent_kib="$(printf '%s\n' "$apparent_output" | awk 'END {print $1}')"

  [[ "$allocated_kib" =~ ^[0-9]+$ && "$apparent_kib" =~ ^[0-9]+$ ]] || return 1
  if (( apparent_kib > allocated_kib )); then
    printf '%s\n' "$apparent_kib"
  else
    printf '%s\n' "$allocated_kib"
  fi
}

sentinel_value() {
  local state_file="$1"
  local key="$2"
  awk -F= -v key="$key" '
    $1 == key {
      sub(/^[^=]*=/, "")
      print
      exit
    }
  ' "$state_file"
}

is_managed_verify_dir() {
  local candidate="${1:-}"
  local parent base
  [[ -n "$candidate" ]] || return 1
  parent="$(dirname "$candidate")"
  base="$(basename "$candidate")"
  [[ "$parent" == "$VERIFY_TARGET_ROOT" && "$base" == run.* ]]
}

write_verify_sentinel() {
  local destination="$1"
  local keep_target="$2"
  {
    printf 'version=1\n'
    printf 'repository_id=%s\n' "$REPOSITORY_ID"
    printf 'run_id=%s\n' "$RUN_ID"
    printf 'workspace=%s\n' "$ROOT_DIR"
    printf 'keep_target=%s\n' "$keep_target"
  } > "$destination"
}

write_verify_sentinel_temp() {
  # A run is disposable until every requested gate has succeeded. This keeps
  # an interrupted `KEEP_TARGET=1` run reclaimable after an untrappable death.
  write_verify_sentinel "$SENTINEL_TMP" 0
  SENTINEL_TMP_CREATED=1
}

mark_current_target_retained() {
  local sentinel="${VERIFY_DIR}/.ryuki-verify-owner"
  local replacement="${VERIFY_DIR}/.ryuki-verify-owner.next"

  [[ "$KEEP_TARGET" == "1" ]] || return 0
  write_verify_sentinel "$replacement" 1
  mv -f -- "$replacement" "$sentinel"
  RETAIN_CURRENT_TARGET=1
}

prepare_verify_namespace() {
  if [[ -L "$VERIFY_NAMESPACE" ]]; then
    echo "error: verification namespace must not be a symlink: ${VERIFY_NAMESPACE}" >&2
    return 75
  fi
  if [[ ! -d "$VERIFY_NAMESPACE" ]]; then
    if ! mkdir -m 700 "$VERIFY_NAMESPACE" 2>/dev/null; then
      echo "error: unable to create verification namespace: ${VERIFY_NAMESPACE}" >&2
      return 75
    fi
  fi
  if [[ ! -d "$VERIFY_NAMESPACE" || -L "$VERIFY_NAMESPACE" || ! -w "$VERIFY_NAMESPACE" ]]; then
    echo "error: verification namespace is not a private writable directory: ${VERIFY_NAMESPACE}" >&2
    return 75
  fi
  chmod 700 "$VERIFY_NAMESPACE"
  if [[ -L "$VERIFY_LOCK_FILE" ]]; then
    echo "error: verification lock file must not be a symlink: ${VERIFY_LOCK_FILE}" >&2
    return 75
  fi
}

acquire_verify_lock() {
  prepare_verify_namespace
  exec 9>>"$VERIFY_LOCK_FILE"
  if command -v flock >/dev/null 2>&1; then
    if ! flock -n 9; then
      echo "error: verification is already running for this repository" >&2
      return 75
    fi
  elif command -v lockf >/dev/null 2>&1; then
    if ! lockf -s -t 0 9; then
      echo "error: verification is already running for this repository" >&2
      return 75
    fi
  else
    echo "error: verify-clean requires flock or lockf for repository-wide serialization" >&2
    return 69
  fi
}

run_without_verify_lock() (
  exec 9>&-
  exec "$@"
)

pause_without_verify_lock() (
  exec 9>&-
  sleep "$1"
)

verify_gate_control_contents() {
  local run_id="$1"
  local supervisor_pid="$2"
  local command_pid="$3"
  local command_pgid="$4"
  printf '%s\n' \
    'version=1' \
    "repository_id=$REPOSITORY_ID" \
    "run_id=$run_id" \
    "supervisor_pid=$supervisor_pid" \
    "command_pid=$command_pid" \
    "command_pgid=$command_pgid"
}

safe_process_id() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
  (( 10#$pid > 1 ))
}

VERIFY_CONTROL_SUPERVISOR_PID=""
VERIFY_CONTROL_COMMAND_PID=""
VERIFY_CONTROL_COMMAND_PGID=""

load_verify_gate_control() {
  local control_file="$1"
  local run_id="$2"
  local expected_supervisor_pid="${3:-}"
  local key value version="" repository_id="" parsed_run_id=""
  local seen_version=0 seen_repository_id=0 seen_run_id=0
  local seen_supervisor_pid=0 seen_command_pid=0 seen_command_pgid=0

  [[ -f "$control_file" && ! -L "$control_file" && -O "$control_file" ]] || return 1

  VERIFY_CONTROL_SUPERVISOR_PID=""
  VERIFY_CONTROL_COMMAND_PID=""
  VERIFY_CONTROL_COMMAND_PGID=""
  # Parse the owned control exactly once. Reopening after validation would
  # create an avoidable validation/use race even inside the private namespace.
  while IFS='=' read -r key value; do
    case "$key" in
      version)
        (( seen_version == 0 )) || return 1
        seen_version=1
        version="$value"
        ;;
      repository_id)
        (( seen_repository_id == 0 )) || return 1
        seen_repository_id=1
        repository_id="$value"
        ;;
      run_id)
        (( seen_run_id == 0 )) || return 1
        seen_run_id=1
        parsed_run_id="$value"
        ;;
      supervisor_pid)
        (( seen_supervisor_pid == 0 )) || return 1
        seen_supervisor_pid=1
        VERIFY_CONTROL_SUPERVISOR_PID="$value"
        ;;
      command_pid)
        (( seen_command_pid == 0 )) || return 1
        seen_command_pid=1
        VERIFY_CONTROL_COMMAND_PID="$value"
        ;;
      command_pgid)
        (( seen_command_pgid == 0 )) || return 1
        seen_command_pgid=1
        VERIFY_CONTROL_COMMAND_PGID="$value"
        ;;
      *) return 1 ;;
    esac
  done < "$control_file"

  (( seen_version == 1 && seen_repository_id == 1 && seen_run_id == 1 \
    && seen_supervisor_pid == 1 && seen_command_pid == 1 \
    && seen_command_pgid == 1 )) || return 1
  [[ "$version" == "1" && "$repository_id" == "$REPOSITORY_ID" \
    && "$parsed_run_id" == "$run_id" ]] || return 1
  safe_process_id "$VERIFY_CONTROL_SUPERVISOR_PID" || return 1
  safe_process_id "$VERIFY_CONTROL_COMMAND_PID" || return 1
  safe_process_id "$VERIFY_CONTROL_COMMAND_PGID" || return 1
  [[ "$VERIFY_CONTROL_COMMAND_PID" == "$VERIFY_CONTROL_COMMAND_PGID" ]] || return 1
  [[ -z "$expected_supervisor_pid" \
    || "$VERIFY_CONTROL_SUPERVISOR_PID" == "$expected_supervisor_pid" ]] || return 1
}

valid_verify_gate_control() {
  load_verify_gate_control "$@"
}

publish_verify_gate_control() {
  local supervisor_pid="$1"
  local command_pid="$2"
  local command_pgid="$3"
  [[ ! -e "$VERIFY_GATE_CONTROL_FILE" && ! -L "$VERIFY_GATE_CONTROL_FILE" \
    && ! -e "$VERIFY_GATE_CONTROL_TEMP" && ! -L "$VERIFY_GATE_CONTROL_TEMP" ]] \
    || return 1
  (exec 9>&-; set -o noclobber; verify_gate_control_contents "$RUN_ID" \
    "$supervisor_pid" "$command_pid" "$command_pgid" \
    > "$VERIFY_GATE_CONTROL_TEMP") || return 1
  run_without_verify_lock chmod 600 "$VERIFY_GATE_CONTROL_TEMP" || return 1
  run_without_verify_lock mv -- "$VERIFY_GATE_CONTROL_TEMP" \
    "$VERIFY_GATE_CONTROL_FILE" || return 1
  valid_verify_gate_control "$VERIFY_GATE_CONTROL_FILE" "$RUN_ID" "$supervisor_pid"
}

publish_verify_gate_release() {
  [[ ! -e "$VERIFY_GATE_RELEASE_FILE" && ! -L "$VERIFY_GATE_RELEASE_FILE" \
    && ! -e "$VERIFY_GATE_RELEASE_TEMP" && ! -L "$VERIFY_GATE_RELEASE_TEMP" ]] \
    || return 1
  (exec 9>&-; set -o noclobber; : > "$VERIFY_GATE_RELEASE_TEMP") || return 1
  run_without_verify_lock chmod 600 "$VERIFY_GATE_RELEASE_TEMP" || return 1
  run_without_verify_lock mv -- "$VERIFY_GATE_RELEASE_TEMP" \
    "$VERIFY_GATE_RELEASE_FILE"
}

clear_verify_gate_control() {
  local supervisor_pid="$1"
  if [[ -e "$VERIFY_GATE_CONTROL_FILE" || -L "$VERIFY_GATE_CONTROL_FILE" ]]; then
    valid_verify_gate_control "$VERIFY_GATE_CONTROL_FILE" "$RUN_ID" \
      "$supervisor_pid" || return 1
  fi
  run_without_verify_lock rm -f -- "$VERIFY_GATE_RELEASE_FILE" \
    "$VERIFY_GATE_RELEASE_TEMP" "$VERIFY_GATE_CONTROL_TEMP"
  run_without_verify_lock rm -f -- "$VERIFY_GATE_CONTROL_FILE"
}

recover_verify_gate_control() {
  local verify_dir="$1"
  local run_id="$2"
  local expected_supervisor_pid="${3:-}"
  local control_file control_temp release_file release_temp
  local supervisor_pid command_pid command_pgid
  control_file="$verify_dir/.ryuki-verify-command-owner"
  control_temp="${control_file}.next"
  release_file="$verify_dir/.ryuki-verify-command-release"
  release_temp="${release_file}.next"

  if [[ ! -e "$control_file" && ! -L "$control_file" ]]; then
    if [[ -e "$control_temp" || -L "$control_temp" \
      || -e "$release_file" || -L "$release_file" \
      || -e "$release_temp" || -L "$release_temp" ]]; then
      echo "error: refusing malformed verification command ownership state" >&2
      return 75
    fi
    return 0
  fi
  load_verify_gate_control "$control_file" "$run_id" \
    "$expected_supervisor_pid" || {
    echo "error: refusing malformed verification command ownership control" >&2
    return 75
  }
  supervisor_pid="$VERIFY_CONTROL_SUPERVISOR_PID"
  command_pid="$VERIFY_CONTROL_COMMAND_PID"
  command_pgid="$VERIFY_CONTROL_COMMAND_PGID"

  if [[ -z "$expected_supervisor_pid" ]]; then
    if kill -0 "$supervisor_pid" 2>/dev/null || process_group_alive "$command_pgid"; then
      echo "error: stale verification ownership still references live processes; refusing unsafe PID reuse recovery" >&2
      return 75
    fi
  elif process_group_alive "$command_pgid"; then
    echo "recovering verification process group after supervisor exit: ${command_pgid}" >&2
    SUPERVISED_COMMAND_PID="$command_pid"
    SUPERVISED_COMMAND_PGID="$command_pgid"
    supervisor_stop_command || return $?
  fi
  run_without_verify_lock rm -f -- "$release_file" "$release_temp" "$control_temp"
  run_without_verify_lock rm -f -- "$control_file"
}

reclaim_stale_verify_dirs() {
  local candidate sentinel version repository_id run_id keep_target expected_run_id sentinel_tmp

  [[ -d "$VERIFY_TARGET_ROOT" ]] || return 0
  if [[ -L "$VERIFY_TARGET_ROOT" ]]; then
    echo "error: verification target root must not be a symlink: ${VERIFY_TARGET_ROOT}" >&2
    return 75
  fi

  for sentinel_tmp in "${VERIFY_TARGET_ROOT}"/.run.*.owner.tmp; do
    [[ -e "$sentinel_tmp" || -L "$sentinel_tmp" ]] || continue
    if [[ ! -f "$sentinel_tmp" || -L "$sentinel_tmp" ]]; then
      echo "error: refusing malformed verification setup sentinel: ${sentinel_tmp}" >&2
      return 75
    fi
    rm -f -- "$sentinel_tmp"
  done

  for candidate in "${VERIFY_TARGET_ROOT}"/run.*; do
    [[ -e "$candidate" || -L "$candidate" ]] || continue
    if [[ ! -d "$candidate" || -L "$candidate" ]] || ! is_managed_verify_dir "$candidate"; then
      echo "error: refusing malformed verification target entry: ${candidate}" >&2
      return 75
    fi

    sentinel="${candidate}/.ryuki-verify-owner"
    if [[ ! -e "$sentinel" ]]; then
      if [[ -z "$(find "$candidate" -mindepth 1 -print -quit)" ]]; then
        rmdir "$candidate"
        continue
      fi
      echo "error: refusing non-empty unmarked verification target: ${candidate}" >&2
      return 75
    fi
    if [[ ! -f "$sentinel" || -L "$sentinel" ]]; then
      echo "error: refusing malformed verification target sentinel: ${sentinel}" >&2
      return 75
    fi

    version="$(sentinel_value "$sentinel" version)"
    repository_id="$(sentinel_value "$sentinel" repository_id)"
    run_id="$(sentinel_value "$sentinel" run_id)"
    keep_target="$(sentinel_value "$sentinel" keep_target)"
    expected_run_id="${candidate##*/run.}"
    if [[ "$version" != "1" || "$repository_id" != "$REPOSITORY_ID" \
      || "$run_id" != "$expected_run_id" || ! "$keep_target" =~ ^[01]$ ]]; then
      echo "error: refusing verification target with invalid sentinel: ${candidate}" >&2
      return 75
    fi

    recover_verify_gate_control "$candidate" "$run_id" || return $?

    if [[ "$keep_target" == "1" ]]; then
      echo "preserving explicitly retained verification target: ${candidate}" >&2
      continue
    fi
    echo "removing stale verification target from interrupted run: ${candidate}" >&2
    rm -rf -- "$candidate"
  done
}

if [[ "${RYUKI_VERIFY_ALLOW_DATABASE:-0}" != "1" ]]; then
  unset RYUKI_DATABASE_URL
  unset RYUKI_REQUIRE_DB
fi

cleanup() {
  local status=$?
  local gate_cleanup_status=0 safe_to_remove=1
  trap - EXIT
  trap '' HUP INT TERM
  stop_active_gate || gate_cleanup_status=$?
  if (( gate_cleanup_status != 0 )); then
    echo "error: refusing verification target cleanup until command ownership is safely recovered" >&2
    status="$gate_cleanup_status"
    safe_to_remove=0
  fi
  if [[ "$SENTINEL_TMP_CREATED" == "1" && -f "$SENTINEL_TMP" && ! -L "$SENTINEL_TMP" ]]; then
    rm -f -- "$SENTINEL_TMP" || status=75
  fi
  if [[ "$VERIFY_DIR_CREATED" == "1" && "$SENTINEL_PUBLISHED" == "1" \
    && "$RETAIN_CURRENT_TARGET" == "1" ]]; then
    echo "verification target retained at ${CARGO_TARGET_DIR}" >&2
  elif [[ "$VERIFY_DIR_CREATED" == "1" && -e "$VERIFY_DIR" \
    && "$safe_to_remove" == "1" ]]; then
    if is_managed_verify_dir "$VERIFY_DIR"; then
      if ! rm -rf -- "$VERIFY_DIR"; then
        echo "error: unable to remove disposable verification target: ${VERIFY_DIR}" >&2
        status=75
      fi
    else
      echo "error: refusing to remove unmanaged verification path: ${VERIFY_DIR}" >&2
      status=75
    fi
  elif [[ "$VERIFY_DIR_CREATED" == "1" && -e "$VERIFY_DIR" ]]; then
    echo "verification target preserved for fail-closed recovery: ${VERIFY_DIR}" >&2
  fi
  exit "$status"
}

disk_guard() {
  local announce="${1:-1}"
  local free_kib target_kib min_free_kib max_target_kib
  free_kib="$(df -Pk "$CARGO_TARGET_DIR" | awk 'END {print $4}')"
  # Bound the complete repository verification namespace, including any
  # explicitly retained successful run, rather than just this invocation.
  target_kib="$(measure_tree_kib "$VERIFY_TARGET_ROOT")" || target_kib=""
  min_free_kib=$((MIN_FREE_GIB * 1024 * 1024))
  max_target_kib=$((MAX_TARGET_GIB * 1024 * 1024))
  if [[ -n "$TEST_MAX_KIB" ]]; then
    max_target_kib="$TEST_MAX_KIB"
  fi

  if [[ ! "$free_kib" =~ ^[0-9]+$ || ! "$target_kib" =~ ^[0-9]+$ ]]; then
    echo "error: verification target allocated/apparent size or free space could not be measured" >&2
    return 75
  fi

  if (( free_kib < min_free_kib )); then
    echo "error: verification stopped: less than ${MIN_FREE_GIB} GiB remains free" >&2
    return 75
  fi
  if (( target_kib > max_target_kib )); then
    echo "error: verification stopped: managed targets exceeded ${MAX_TARGET_GIB} GiB" >&2
    return 75
  fi

  if [[ "$announce" == "1" ]]; then
    echo "disk guard: $((free_kib / 1024 / 1024)) GiB free; managed targets $((target_kib / 1024 / 1024)) GiB"
  fi
}

collect_process_tree() {
  local pid="$1"
  local child children="" status=0

  safe_process_id "$pid" || return 75
  if children="$(pgrep -P "$pid" 2>/dev/null)"; then
    status=0
  else
    status=$?
  fi
  # pgrep(1) returns 1 for an authoritative empty child set. Any larger
  # status means process inspection itself failed, so callers must not claim
  # that a partial tree is complete.
  (( status <= 1 )) || return 75
  while IFS= read -r child; do
    [[ -n "$child" ]] || continue
    safe_process_id "$child" || return 75
    collect_process_tree "$child" || return $?
  done <<< "$children"
  printf '%s\n' "$pid"
}

terminate_process_tree() {
  local root_pid="$1"
  local original_root_pid="$1"
  local pid attempt alive snapshot extra collection_status=0
  local tree_pids=()

  safe_process_id "$root_pid" || return 75
  snapshot="$(collect_process_tree "$root_pid")" || return $?
  while IFS= read -r pid; do
    [[ -n "$pid" ]] && tree_pids+=("$pid")
  done <<< "$snapshot"

  for pid in "${tree_pids[@]}"; do
    safe_process_id "$pid" || return 75
    kill -TERM "$pid" 2>/dev/null || true
  done

  for ((attempt = 0; attempt < HARD_STOP_PHASE_ATTEMPTS; attempt++)); do
    alive=0
    for pid in "${tree_pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        alive=1
        break
      fi
    done
    (( alive == 0 )) && return 0
    sleep 0.1
  done

  # Capture any descendants created during graceful shutdown before forcing
  # the original tree down. Duplicates are harmless.
  for root_pid in "${tree_pids[@]}"; do
    if ! extra="$(collect_process_tree "$root_pid")"; then
      collection_status=75
      continue
    fi
    while IFS= read -r pid; do
      [[ -n "$pid" ]] && tree_pids+=("$pid")
    done <<< "$extra"
  done
  for pid in "${tree_pids[@]}"; do
    safe_process_id "$pid" || return 75
    kill -KILL "$pid" 2>/dev/null || true
  done
  wait "$original_root_pid" 2>/dev/null || true
  for ((attempt = 0; attempt < HARD_STOP_PHASE_ATTEMPTS; attempt++)); do
    alive=0
    for pid in "${tree_pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        alive=1
        break
      fi
    done
    (( alive == 0 )) && return "$collection_status"
    pause_without_verify_lock 0.1
  done
  return 75
}

process_group_alive() {
  local pgid="${1:-}"
  safe_process_id "$pgid" || return 1
  kill -0 -- "-$pgid" 2>/dev/null
}

record_regrouped_process_group() {
  local pgid="$1" recorded
  safe_process_id "$pgid" || return 75
  [[ "$pgid" != "${SUPERVISED_COMMAND_PGID:-}" ]] || return 75
  for recorded in "${REGROUPED_PROCESS_PGIDS[@]-}"; do
    [[ -n "$recorded" ]] || continue
    [[ "$recorded" == "$pgid" ]] && return 0
  done
  REGROUPED_PROCESS_PGIDS+=("$pgid")
  # Start fail-closed shutdown without SIGSTOP; an untrappable supervisor
  # death must not leave a regrouped descendant suspended forever.
  kill -TERM -- "-$pgid" 2>/dev/null || process_group_alive "$pgid" || return 0
}

reject_regrouped_descendants() {
  local root_pid="${SUPERVISED_COMMAND_PID:-}"
  local root_pgid="${SUPERVISED_COMMAND_PGID:-}"
  local snapshot pid ppid pgid known changed mismatch=0 index round
  local pids=() ppids=() pgids=()

  safe_process_id "$root_pid" || return 75
  safe_process_id "$root_pgid" || return 75
  if [[ "$TEST_MODE" == "1" ]]; then
    if [[ -n "$TEST_REGROUPED_PGID_FILE" \
      && -f "$TEST_REGROUPED_PGID_FILE" ]]; then
      read -r pgid < "$TEST_REGROUPED_PGID_FILE" || return 75
      if safe_process_id "$pgid" && [[ "$pgid" != "$root_pgid" ]] \
        && process_group_alive "$pgid"; then
        record_regrouped_process_group "$pgid" || return $?
        echo "error: supervised descendant changed process group: ${pgid}" >&2
        return 75
      fi
    fi
    return 0
  fi

  snapshot="$(/bin/ps -axo pid=,ppid=,pgid= 2>/dev/null)" || return 75
  while read -r pid ppid pgid; do
    [[ -z "$pid" ]] && continue
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$ppid" =~ ^[0-9]+$ \
      && "$pgid" =~ ^[1-9][0-9]*$ ]] || return 75
    pids+=("$pid")
    ppids+=("$ppid")
    pgids+=("$pgid")
  done <<< "$snapshot"
  known=" $root_pid "
  for ((round = 0; round <= ${#pids[@]}; round++)); do
    changed=0
    for index in "${!pids[@]}"; do
      [[ "$known" == *" ${pids[$index]} "* ]] && continue
      [[ "$known" == *" ${ppids[$index]} "* ]] || continue
      known+="${pids[$index]} "
      changed=1
      if [[ "${pgids[$index]}" != "$root_pgid" ]]; then
        record_regrouped_process_group "${pgids[$index]}" || return $?
        mismatch=1
      fi
    done
    (( changed == 1 )) || break
  done
  if (( mismatch == 1 )); then
    echo "error: supervised descendant changed process group" >&2
    return 75
  fi
  # Portable Bash cannot atomically bind every same-user PID start identity or
  # catch a descendant that detaches and exits between process-table samples.
  # The supported Cargo/rustc contract is therefore one durable root group;
  # every regrouping that is observed is rejected and terminated fail closed.
}

terminate_regrouped_process_groups() {
  local pgid attempt status=0
  [[ -n "${REGROUPED_PROCESS_PGIDS[*]-}" ]] || return 0
  for pgid in "${REGROUPED_PROCESS_PGIDS[@]}"; do
    safe_process_id "$pgid" || { status=75; continue; }
    process_group_alive "$pgid" || continue
    kill -TERM -- "-$pgid" 2>/dev/null || true
    for ((attempt = 0; attempt < HARD_STOP_PHASE_ATTEMPTS; attempt++)); do
      process_group_alive "$pgid" || break
      pause_without_verify_lock 0.1
    done
    process_group_alive "$pgid" && kill -KILL -- "-$pgid" 2>/dev/null || true
    for ((attempt = 0; attempt < HARD_STOP_PHASE_ATTEMPTS; attempt++)); do
      process_group_alive "$pgid" || break
      pause_without_verify_lock 0.1
    done
    process_group_alive "$pgid" && status=75
  done
  (( status == 0 )) && REGROUPED_PROCESS_PGIDS=()
  return "$status"
}

resume_frozen_process_tree() {
  local pgid="${FROZEN_ROOT_PGID:-}"

  [[ -n "$pgid" ]] || return 0
  safe_process_id "$pgid" || return 75
  if kill -CONT -- "-$pgid" 2>/dev/null; then
    FROZEN_ROOT_PGID=""
    return 0
  fi
  if process_group_alive "$pgid"; then
    # Retain the recorded identity so cleanup can retry or kill it. Never
    # discard live frozen ownership merely because thawing failed.
    return 75
  fi
  FROZEN_ROOT_PGID=""
}

freeze_supervised_process_tree() {
  local pid="${SUPERVISED_COMMAND_PID:-}"
  local pgid="${SUPERVISED_COMMAND_PGID:-}"

  [[ -z "$FROZEN_ROOT_PGID" ]] || return 75
  safe_process_id "$pid" || return 75
  safe_process_id "$pgid" || return 75
  [[ "$pid" == "$pgid" ]] || return 75
  valid_verify_gate_control "$VERIFY_GATE_CONTROL_FILE" "$RUN_ID" \
    "$GATE_SUPERVISOR_ACTUAL_PID" || return 75
  # The group may disappear normally between the loop's liveness test and
  # this function. That means there is nothing to freeze; the command's wait
  # path and post-gate guard still determine its result.
  process_group_alive "$pgid" || return 0
  if ! kill -STOP -- "-$pgid" 2>/dev/null; then
    if ! process_group_alive "$pgid"; then
      return 0
    fi
    return 75
  fi
  # The successful stop pins the group identity until this supervisor thaws
  # it. The rustc wrapper is required to keep compiler/linker descendants in
  # this group while outer supervision is active.
  FROZEN_ROOT_PGID="$pgid"
}

disk_guard_while_frozen() {
  local guard_status=0 resume_status=0 stage_status=0

  if reject_regrouped_descendants; then
    :
  else
    stage_status=$?
    echo "error: disk guard could not validate the supervised process group" >&2
    return "$stage_status"
  fi
  if freeze_supervised_process_tree; then
    :
  else
    stage_status=$?
    echo "error: disk guard could not freeze the supervised process group" >&2
    return "$stage_status"
  fi
  if disk_guard 0; then
    :
  else
    guard_status=$?
    echo "error: disk guard measurement or configured ceiling failed" >&2
  fi
  if resume_frozen_process_tree; then
    :
  else
    resume_status=$?
    echo "error: disk guard could not resume the supervised process group" >&2
  fi
  (( resume_status == 0 )) || return "$resume_status"
  return "$guard_status"
}

terminate_process_group() {
  local pgid="$1"
  local attempt

  safe_process_id "$pgid" || return 75
  process_group_alive "$pgid" || return 0
  kill -TERM -- "-$pgid" 2>/dev/null || true
  for ((attempt = 0; attempt < HARD_STOP_PHASE_ATTEMPTS; attempt++)); do
    process_group_alive "$pgid" || return 0
    pause_without_verify_lock 0.1
  done

  kill -KILL -- "-$pgid" 2>/dev/null || true
  for ((attempt = 0; attempt < HARD_STOP_PHASE_ATTEMPTS; attempt++)); do
    process_group_alive "$pgid" || return 0
    pause_without_verify_lock 0.1
  done
  return 75
}

stop_active_gate() {
  local pid="${ACTIVE_GATE_PID:-}"
  local recovery_status=0
  [[ -n "$pid" ]] || return 0
  safe_process_id "$pid" || return 75

  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  recover_verify_gate_control "$VERIFY_DIR" "$RUN_ID" "$pid" || \
    recovery_status=$?
  (( recovery_status == 0 )) && ACTIVE_GATE_PID=""
  return "$recovery_status"
}

handle_signal() {
  local status="$1"
  local cleanup_status=0
  trap '' HUP INT TERM
  stop_active_gate || cleanup_status=$?
  (( cleanup_status == 0 )) || status="$cleanup_status"
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

acquire_verify_lock
reclaim_stale_verify_dirs
if [[ -L "$VERIFY_TARGET_ROOT" ]]; then
  echo "error: verification target root must not be a symlink: ${VERIFY_TARGET_ROOT}" >&2
  exit 75
fi
if [[ ! -d "$VERIFY_TARGET_ROOT" ]]; then
  mkdir -m 700 "$VERIFY_TARGET_ROOT"
fi
chmod 700 "$VERIFY_TARGET_ROOT"
write_verify_sentinel_temp
mkdir -m 700 "$VERIFY_DIR"
VERIFY_DIR_CREATED=1
mv -f -- "$SENTINEL_TMP" "${VERIFY_DIR}/.ryuki-verify-owner"
SENTINEL_TMP_CREATED=0
SENTINEL_PUBLISHED=1
mkdir -p "$CARGO_TARGET_DIR"

supervisor_stop_command() {
  local pid="${SUPERVISED_COMMAND_PID:-}"
  local pgid="${SUPERVISED_COMMAND_PGID:-}"
  local regroup_status=0 tree_status=0 group_status=0 thaw_status=0 status=0

  [[ -n "$pid" || -n "$pgid" ]] || return 0
  [[ -z "$pid" ]] || safe_process_id "$pid" || return 75
  [[ -z "$pgid" ]] || safe_process_id "$pgid" || return 75
  [[ -z "$pid" || -z "$pgid" || "$pid" == "$pgid" ]] || return 75
  # A stopped group cannot run a TERM handler. Thaw recorded ownership first,
  # then capture the live ancestry before killing the durable root group so a
  # child that deliberately moved to another process group is still stopped.
  resume_frozen_process_tree || thaw_status=$?
  terminate_regrouped_process_groups || regroup_status=$?
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    terminate_process_tree "$pid" || tree_status=$?
  fi
  if [[ -n "$pgid" ]] && process_group_alive "$pgid"; then
    terminate_process_group "$pgid" || group_status=$?
  fi
  [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true
  (( thaw_status == 0 )) || status="$thaw_status"
  (( regroup_status == 0 )) || status="$regroup_status"
  (( tree_status == 0 )) || status="$tree_status"
  (( group_status == 0 )) || status="$group_status"
  if (( status != 0 )); then
    echo "error: verification cleanup failed (thaw=${thaw_status}, regroup=${regroup_status}, tree=${tree_status}, group=${group_status})" >&2
  fi
  if (( status == 0 )); then
    SUPERVISED_COMMAND_PID=""
    SUPERVISED_COMMAND_PGID=""
  fi
  return "$status"
}

supervisor_signal() {
  local status="$1"
  local stop_status=0 clear_status=0
  trap '' HUP INT TERM
  supervisor_stop_command || stop_status=$?
  if (( stop_status == 0 )) && [[ -n "$GATE_SUPERVISOR_ACTUAL_PID" ]]; then
    clear_verify_gate_control "$GATE_SUPERVISOR_ACTUAL_PID" || clear_status=$?
  fi
  (( stop_status == 0 )) || status="$stop_status"
  (( clear_status == 0 )) || status="$clear_status"
  exit "$status"
}

apply_file_size_limit() {
  local limit_kib="$FILE_LIMIT_KIB"
  local current_soft current_hard observed

  current_soft="$(ulimit -S -f)" || return 75
  current_hard="$(ulimit -H -f)" || return 75
  if [[ "$current_soft" =~ ^[0-9]+$ ]] && (( current_soft < limit_kib )); then
    limit_kib="$current_soft"
  fi
  if [[ "$current_hard" =~ ^[0-9]+$ ]] && (( current_hard < limit_kib )); then
    limit_kib="$current_hard"
  fi
  ulimit -S -f "$limit_kib" || return 75
  # Lowering the inherited hard limit in this command subshell prevents a
  # child process from raising the soft limit again.
  ulimit -H -f "$limit_kib" || return 75
  observed="$(ulimit -S -f)" || return 75
  [[ "$observed" =~ ^[0-9]+$ && "$observed" -le "$FILE_LIMIT_KIB" ]] || return 75
}

run_gate_command() {
  local wrapper_pid="$1"
  local label="$2"
  local process_group_policy="$3"
  local command_pid command_pgid command_status command_wait_status guard_status
  local regroup_status
  local command_status_file command_status_tmp stop_status
  local release_attempt released supervisor_pid_probe
  shift 3

  case "$process_group_policy" in
    strict|containment-regression) ;;
    *) return 75 ;;
  esac

  # This supervisor retains the repository lock and the disk watcher if the
  # outer wrapper is killed. It then stops the actual gate within one watch
  # interval, so an orphaned Cargo process cannot grow without a ceiling.
  trap - EXIT HUP INT TERM
  trap 'supervisor_signal 129' HUP
  trap 'supervisor_signal 130' INT
  trap 'supervisor_signal 143' TERM

  supervisor_pid_probe="${VERIFY_DIR}/.gate-supervisor-pid.${RUN_ID}"
  [[ ! -e "$supervisor_pid_probe" && ! -L "$supervisor_pid_probe" ]] || return 75
  set -o noclobber
  if ! run_without_verify_lock /bin/sh -c 'printf "%s\n" "$PPID"' \
    > "$supervisor_pid_probe"; then
    set +o noclobber
    return 75
  fi
  set +o noclobber
  read -r GATE_SUPERVISOR_ACTUAL_PID < "$supervisor_pid_probe" || \
    GATE_SUPERVISOR_ACTUAL_PID=""
  run_without_verify_lock rm -f -- "$supervisor_pid_probe"
  [[ "$GATE_SUPERVISOR_ACTUAL_PID" =~ ^[1-9][0-9]{0,9}$ ]] || return 75
  command_status_file="${VERIFY_DIR}/.gate-status.${RUN_ID}.$RANDOM"
  command_status_tmp="${command_status_file}.tmp"
  set -m
  (
    trap - EXIT HUP INT TERM
    exec 9>&-
    released=0
    for release_attempt in {1..100}; do
      if [[ -e "$VERIFY_GATE_RELEASE_FILE" || -L "$VERIFY_GATE_RELEASE_FILE" ]]; then
        [[ -f "$VERIFY_GATE_RELEASE_FILE" && ! -L "$VERIFY_GATE_RELEASE_FILE" \
          && -O "$VERIFY_GATE_RELEASE_FILE" ]] || exit 75
        rm -f -- "$VERIFY_GATE_RELEASE_FILE"
        released=1
        break
      fi
      kill -0 "$GATE_SUPERVISOR_ACTUAL_PID" 2>/dev/null || exit 75
      sleep 0.05
    done
    (( released == 1 )) || exit 75
    if [[ "$process_group_policy" == "containment-regression" ]]; then
      # These fixed test harnesses create their own disposable targets and
      # supervision records. Do not let the outer Cargo environment turn a
      # standalone guard fixture into a forged nested-verifier invocation.
      unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR CARGO_BUILD_BUILD_DIR
      unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
      unset CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
      unset RYUKI_CARGO_OUTER_CONTROL_FILE
    else
      # Cargo propagates this private, target-local ownership record to rustc.
      # The rustc guard validates it before inheriting this process group,
      # which keeps the durable root PGID as the only compiler/linker boundary.
      export RYUKI_CARGO_OUTER_CONTROL_FILE="$VERIFY_GATE_CONTROL_FILE"
    fi
    if ! apply_file_size_limit; then
      echo "error: unable to enforce the ${FILE_LIMIT_KIB} KiB file-size limit" >&2
      exit 75
    fi
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
  safe_process_id "$command_pid" || return 75
  SUPERVISED_COMMAND_PID="$command_pid"
  SUPERVISED_COMMAND_PGID="$command_pgid"
  if ! publish_verify_gate_control "$GATE_SUPERVISOR_ACTUAL_PID" \
    "$command_pid" "$command_pgid" || ! publish_verify_gate_release; then
    stop_status=0
    supervisor_stop_command || stop_status=$?
    (( stop_status == 0 )) || return "$stop_status"
    clear_verify_gate_control "$GATE_SUPERVISOR_ACTUAL_PID" || return 75
    return 75
  fi
  while process_group_alive "$command_pgid"; do
    [[ ! -f "$command_status_file" ]] || break
    if ! kill -0 "$wrapper_pid" 2>/dev/null; then
      echo "error: stopping ${label}: verification wrapper no longer exists" >&2
      stop_status=0
      supervisor_stop_command || stop_status=$?
      (( stop_status == 0 )) || return "$stop_status"
      run_without_verify_lock rm -f -- "$command_status_file" "$command_status_tmp"
      clear_verify_gate_control "$GATE_SUPERVISOR_ACTUAL_PID" || return 75
      return 75
    fi

    pause_without_verify_lock "$WATCH_INTERVAL_SECONDS"
    [[ ! -f "$command_status_file" ]] || break
    if ! kill -0 "$wrapper_pid" 2>/dev/null; then
      echo "error: stopping ${label}: verification wrapper no longer exists" >&2
      stop_status=0
      supervisor_stop_command || stop_status=$?
      (( stop_status == 0 )) || return "$stop_status"
      run_without_verify_lock rm -f -- "$command_status_file" "$command_status_tmp"
      clear_verify_gate_control "$GATE_SUPERVISOR_ACTUAL_PID" || return 75
      return 75
    fi
    guard_status=0
    if [[ "$process_group_policy" == "containment-regression" ]]; then
      # The fixed containment regressions intentionally establish subordinate
      # process groups. Keep the outer supervisor, global free-space watcher,
      # and inherited file-size limit; each harness enforces its own fixture
      # target caps and cleanup contract. Do not mistake its test-owned groups
      # for escaping Cargo descendants or freeze only their parent group.
      disk_guard 0 || guard_status=$?
    else
      disk_guard_while_frozen || guard_status=$?
    fi
    if (( guard_status == 0 )); then
      continue
    fi
    echo "error: stopping ${label} before it can exhaust the disk" >&2
    stop_status=0
    supervisor_stop_command || stop_status=$?
    (( stop_status == 0 )) || return "$stop_status"
    run_without_verify_lock rm -f -- "$command_status_file" "$command_status_tmp"
    clear_verify_gate_control "$GATE_SUPERVISOR_ACTUAL_PID" || return 75
    return "$guard_status"
  done

  regroup_status=0
  if [[ "$process_group_policy" == "strict" ]] \
    && process_group_alive "$command_pgid"; then
    reject_regrouped_descendants || regroup_status=$?
  fi
  if (( regroup_status != 0 )); then
    echo "error: stopping ${label}: descendant process-group invariant failed" >&2
    stop_status=0
    supervisor_stop_command || stop_status=$?
    (( stop_status == 0 )) || return "$stop_status"
    run_without_verify_lock rm -f -- "$command_status_file" "$command_status_tmp"
    clear_verify_gate_control "$GATE_SUPERVISOR_ACTUAL_PID" || return 75
    return "$regroup_status"
  fi

  if wait "$command_pid"; then
    command_wait_status=0
  else
    command_wait_status=$?
  fi
  SUPERVISED_COMMAND_PID=""
  if [[ -f "$command_status_file" ]]; then
    read -r command_status < "$command_status_file" || command_status=""
  else
    command_status="$command_wait_status"
  fi
  if [[ ! "$command_status" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
    echo "error: ${label} did not publish a valid command status" >&2
    command_status=75
  fi
  run_without_verify_lock rm -f -- "$command_status_file" "$command_status_tmp"

  stop_status=0
  if process_group_alive "$command_pgid"; then
    echo "stopping surviving ${label} descendants after command exit" >&2
  fi
  supervisor_stop_command || stop_status=$?
  if (( stop_status != 0 )); then
    echo "error: unable to stop every ${label} process-group member" >&2
    return "$stop_status"
  fi
  clear_verify_gate_control "$GATE_SUPERVISOR_ACTUAL_PID" || return 75
  return "$command_status"
}

run_gate_with_process_group_policy() {
  local process_group_policy="$1"
  local label="$2"
  local command_pid command_status recovery_status control_remained
  shift 2
  case "$process_group_policy" in
    strict|containment-regression) ;;
    *) return 75 ;;
  esac
  disk_guard
  echo "==> ${label}"

  run_gate_command "$WRAPPER_PID" "$label" "$process_group_policy" "$@" &
  command_pid=$!
  ACTIVE_GATE_PID="$command_pid"
  if wait "$command_pid"; then
    command_status=0
  else
    command_status=$?
  fi
  control_remained=0
  if [[ -e "$VERIFY_GATE_CONTROL_FILE" || -L "$VERIFY_GATE_CONTROL_FILE" ]]; then
    control_remained=1
  fi
  recovery_status=0
  recover_verify_gate_control "$VERIFY_DIR" "$RUN_ID" "$command_pid" || \
    recovery_status=$?
  (( recovery_status == 0 )) || return "$recovery_status"
  ACTIVE_GATE_PID=""
  if (( command_status == 0 && control_remained == 1 )); then
    echo "error: ${label} supervisor left command ownership published" >&2
    return 75
  fi
  if (( command_status != 0 )); then
    return "$command_status"
  fi
  disk_guard
}

run_gate() {
  local label="$1"
  shift
  run_gate_with_process_group_policy strict "$label" "$@"
}

run_containment_regression_gate() {
  local regression="$1" label script

  # This policy is deliberately not selectable through the environment, a
  # label, a path, or a focused command. Only this closed list of checked-in
  # containment harnesses may establish subordinate test process groups.
  case "$regression" in
    verifier)
      label="verification cleanup regression"
      script="./scripts/regressions/verify-workspace-clean.sh"
      ;;
    rustc-guard)
      label="repository Cargo disk guard regression"
      script="./scripts/regressions/cargo-rustc-disk-guard.sh"
      ;;
    dev-guard)
      label="persistent Cargo dev guard regression"
      script="./scripts/regressions/cargo-dev-guard.sh"
      ;;
    proving-ground)
      label="proving-ground build cleanup regression"
      script="./scripts/regressions/proving-ground-build-cleanup.sh"
      ;;
    *) return 75 ;;
  esac
  [[ -f "$script" && ! -L "$script" && -x "$script" && -O "$script" ]] || {
    echo "error: containment regression is missing or unsafe: ${script}" >&2
    return 75
  }
  run_gate_with_process_group_policy containment-regression \
    "$label" "$script"
}

validate_focused_cargo_command() {
  local argument subcommand

  if [[ "${1:-}" != "cargo" ]]; then
    echo "error: focused verification accepts only a direct cargo command" >&2
    return 64
  fi

  subcommand="${2:-}"
  if [[ "$subcommand" == +* ]]; then
    subcommand="${3:-}"
  fi
  case "$subcommand" in
    build|check|clippy|run|test) ;;
    *)
      echo "error: focused verification accepts only cargo build, check, clippy, run, or test" >&2
      return 64
      ;;
  esac

  for argument in "$@"; do
    if [[ "$argument" == "--target-dir" || "$argument" == --target-dir=* ]]; then
      echo "error: focused verification forbids overriding CARGO_TARGET_DIR" >&2
      return 64
    fi
    if [[ "$argument" == "--config" || "$argument" == --config=* ]]; then
      echo "error: focused verification forbids Cargo --config overrides" >&2
      return 64
    fi
    if [[ "$argument" == "-j" || "$argument" == -j* \
      || "$argument" == "--jobs" || "$argument" == --jobs=* ]]; then
      echo "error: focused verification forbids overriding the pinned Cargo job count" >&2
      return 64
    fi
  done
}

cd "$ROOT_DIR"
disk_guard

if [[ "${RYUKI_VERIFY_PREFLIGHT_ONLY:-0}" == "1" ]]; then
  echo "verification preflight passed; no build commands were run"
  exit 0
fi

# Focused coding checks need the same serialization, disk ceiling, signal
# cleanup, and disposable target as the complete verification wave. Accept an
# explicit command only after `--`; this keeps normal `make verify-clean`
# behavior unchanged while avoiding ad-hoc CARGO_TARGET_DIR trees.
if (( $# > 0 )); then
  if [[ "$1" != "--" ]]; then
    echo "usage: $0 [-- command [args...]]" >&2
    exit 64
  fi
  shift
  if (( $# == 0 )); then
    echo "error: focused verification requires a command after --" >&2
    exit 64
  fi
  validate_focused_cargo_command "$@"
  run_gate "focused verification" "$@"
  mark_current_target_retained
  echo "focused verification passed; disposable Cargo target will now be removed"
  exit 0
fi

run_containment_regression_gate verifier
run_containment_regression_gate rustc-guard
run_containment_regression_gate dev-guard
run_containment_regression_gate proving-ground
run_gate "format" cargo fmt --check --all
run_gate "workspace build" cargo build --workspace
run_gate "workspace tests" cargo test --workspace
run_gate "workspace clippy" cargo clippy --workspace --all-targets -- -D warnings
run_gate "Vault chart release" ./deploy/kubernetes/vault/test-release-approved-chart.sh
run_gate "validator" cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all --root .
run_gate "dependency audit" ./scripts/dependency-audit.sh
run_gate "secret scan" ./scripts/no-secret-scan.sh
run_gate "patch hygiene" git diff --check

mark_current_target_retained
echo "workspace verification passed; disposable Cargo target will now be removed"
