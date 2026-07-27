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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${RYUKI_VERIFY_STATE_BASE:-}" && "${RYUKI_VERIFY_TEST_MODE:-0}" != "1" ]]; then
  echo "error: RYUKI_VERIFY_STATE_BASE is reserved for verify-clean regression tests" >&2
  exit 64
fi
STATE_BASE_ROOT="$(cd "${RYUKI_VERIFY_STATE_BASE:-/tmp}" && pwd -P)"
GIT_COMMON_DIR_RAW="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)"
GIT_COMMON_DIR="$(cd "$GIT_COMMON_DIR_RAW" && pwd -P)"
REPOSITORY_ID="$(printf '%s' "$GIT_COMMON_DIR" | git -C "$ROOT_DIR" hash-object --stdin)"
MIN_FREE_GIB="${RYUKI_VERIFY_MIN_FREE_GIB:-30}"
MAX_TARGET_GIB="${RYUKI_VERIFY_MAX_TARGET_GIB:-64}"
KEEP_TARGET="${RYUKI_VERIFY_KEEP_TARGET:-0}"
WATCH_INTERVAL_SECONDS="${RYUKI_VERIFY_WATCH_INTERVAL_SECONDS:-5}"
ACTIVE_GATE_PID=""
SUPERVISED_COMMAND_PID=""
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
export CARGO_TARGET_DIR="${VERIFY_DIR}/target"

require_positive_integer() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|*[!0-9]*|0)
      echo "error: ${name} must be a positive integer (got '${value}')" >&2
      exit 64
      ;;
  esac
}

require_positive_integer RYUKI_VERIFY_MIN_FREE_GIB "$MIN_FREE_GIB"
require_positive_integer RYUKI_VERIFY_MAX_TARGET_GIB "$MAX_TARGET_GIB"
require_positive_integer RYUKI_VERIFY_WATCH_INTERVAL_SECONDS "$WATCH_INTERVAL_SECONDS"

case "$KEEP_TARGET" in
  0|1) ;;
  *)
    echo "error: RYUKI_VERIFY_KEEP_TARGET must be 0 or 1 (got '${KEEP_TARGET}')" >&2
    exit 64
    ;;
esac

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

    if [[ "$keep_target" == "1" ]]; then
      echo "preserving explicitly retained verification target: ${candidate}" >&2
      continue
    fi
    echo "removing stale verification target from interrupted run: ${candidate}" >&2
    rm -rf -- "$candidate"
  done
}

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
export CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}"

if [[ "${RYUKI_VERIFY_ALLOW_DATABASE:-0}" != "1" ]]; then
  unset RYUKI_DATABASE_URL
  unset RYUKI_REQUIRE_DB
fi

cleanup() {
  local status=$?
  trap - EXIT
  trap '' INT TERM
  stop_active_gate
  if [[ "$SENTINEL_TMP_CREATED" == "1" && -f "$SENTINEL_TMP" && ! -L "$SENTINEL_TMP" ]]; then
    rm -f -- "$SENTINEL_TMP" || status=75
  fi
  if [[ "$VERIFY_DIR_CREATED" == "1" && "$SENTINEL_PUBLISHED" == "1" \
    && "$RETAIN_CURRENT_TARGET" == "1" ]]; then
    echo "verification target retained at ${CARGO_TARGET_DIR}" >&2
  elif [[ "$VERIFY_DIR_CREATED" == "1" && -e "$VERIFY_DIR" ]]; then
    if is_managed_verify_dir "$VERIFY_DIR"; then
      if ! rm -rf -- "$VERIFY_DIR"; then
        echo "error: unable to remove disposable verification target: ${VERIFY_DIR}" >&2
        status=75
      fi
    else
      echo "error: refusing to remove unmanaged verification path: ${VERIFY_DIR}" >&2
      status=75
    fi
  fi
  exit "$status"
}

disk_guard() {
  local announce="${1:-1}"
  local free_kib target_kib min_free_kib max_target_kib
  free_kib="$(df -Pk "$CARGO_TARGET_DIR" | awk 'END {print $4}')"
  # Bound the complete repository verification namespace, including any
  # explicitly retained successful run, rather than just this invocation.
  target_kib="$(du -sk "$VERIFY_TARGET_ROOT" 2>/dev/null | awk '{print $1}')"
  target_kib="${target_kib:-0}"
  min_free_kib=$((MIN_FREE_GIB * 1024 * 1024))
  max_target_kib=$((MAX_TARGET_GIB * 1024 * 1024))

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
  local child
  while IFS= read -r child; do
    [[ -n "$child" ]] && collect_process_tree "$child"
  done < <(pgrep -P "$pid" 2>/dev/null || true)
  printf '%s\n' "$pid"
}

terminate_process_tree() {
  local root_pid="$1"
  local pid attempt alive
  local tree_pids=()

  while IFS= read -r pid; do
    [[ -n "$pid" ]] && tree_pids+=("$pid")
  done < <(collect_process_tree "$root_pid")

  for pid in "${tree_pids[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done

  for attempt in {1..20}; do
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
    while IFS= read -r pid; do
      [[ -n "$pid" ]] && tree_pids+=("$pid")
    done < <(collect_process_tree "$root_pid")
  done
  for pid in "${tree_pids[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done
}

stop_active_gate() {
  local pid="${ACTIVE_GATE_PID:-}"
  [[ -n "$pid" ]] || return 0

  if kill -0 "$pid" 2>/dev/null; then
    terminate_process_tree "$pid"
  fi
  wait "$pid" 2>/dev/null || true
  ACTIVE_GATE_PID=""
}

handle_signal() {
  local status="$1"
  trap '' INT TERM
  stop_active_gate
  exit "$status"
}

trap cleanup EXIT
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
  [[ -n "$pid" ]] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    terminate_process_tree "$pid"
  fi
  wait "$pid" 2>/dev/null || true
  SUPERVISED_COMMAND_PID=""
}

supervisor_signal() {
  local status="$1"
  trap - INT TERM
  supervisor_stop_command
  exit "$status"
}

run_gate_command() {
  local wrapper_pid="$1"
  local label="$2"
  local command_pid command_status guard_status
  shift 2

  # This supervisor retains the repository lock and the disk watcher if the
  # outer wrapper is killed. It then stops the actual gate within one watch
  # interval, so an orphaned Cargo process cannot grow without a ceiling.
  trap - EXIT
  trap 'supervisor_signal 130' INT
  trap 'supervisor_signal 143' TERM

  "$@" &
  command_pid=$!
  SUPERVISED_COMMAND_PID="$command_pid"
  while kill -0 "$command_pid" 2>/dev/null; do
    if ! kill -0 "$wrapper_pid" 2>/dev/null; then
      echo "error: stopping ${label}: verification wrapper no longer exists" >&2
      supervisor_stop_command
      return 75
    fi

    sleep "$WATCH_INTERVAL_SECONDS"
    if ! kill -0 "$command_pid" 2>/dev/null; then
      break
    fi
    if disk_guard 0; then
      continue
    else
      guard_status=$?
      echo "error: stopping ${label} before it can exhaust the disk" >&2
      supervisor_stop_command
      return "$guard_status"
    fi
  done

  if wait "$command_pid"; then
    command_status=0
  else
    command_status=$?
  fi
  SUPERVISED_COMMAND_PID=""
  return "$command_status"
}

run_gate() {
  local label="$1"
  local command_pid command_status
  shift
  disk_guard
  echo "==> ${label}"

  run_gate_command "$WRAPPER_PID" "$label" "$@" &
  command_pid=$!
  ACTIVE_GATE_PID="$command_pid"
  if wait "$command_pid"; then
    command_status=0
  else
    command_status=$?
  fi
  ACTIVE_GATE_PID=""
  if (( command_status != 0 )); then
    return "$command_status"
  fi
  disk_guard
}

validate_focused_cargo_command() {
  local argument previous=""

  if [[ "${1:-}" != "cargo" ]]; then
    echo "error: focused verification accepts only a direct cargo command" >&2
    return 64
  fi

  for argument in "$@"; do
    if [[ "$argument" == "--target-dir" || "$argument" == --target-dir=* ]]; then
      echo "error: focused verification forbids overriding CARGO_TARGET_DIR" >&2
      return 64
    fi
    if [[ "$previous" == "--config" && "$argument" == *target-dir* ]]; then
      echo "error: focused verification forbids target-dir Cargo configuration" >&2
      return 64
    fi
    if [[ "$argument" == --config=*target-dir* ]]; then
      echo "error: focused verification forbids target-dir Cargo configuration" >&2
      return 64
    fi
    previous="$argument"
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

run_gate "verification cleanup regression" ./scripts/regressions/verify-workspace-clean.sh
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
