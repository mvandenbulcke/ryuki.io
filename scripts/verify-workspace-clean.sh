#!/usr/bin/env bash
set -Eeuo pipefail

# One-shot workspace verification with a bounded, disposable Cargo cache.
#
# Cargo's normal `target/` directory is intentionally persistent and has no
# automatic eviction policy. That is useful during interactive development,
# but a full workspace/SSR/WASM verification wave can retain many toolchain and
# feature combinations. This wrapper isolates those objects, disables the two
# largest one-shot cache multipliers, checks disk headroom between gates, and
# removes its target on success, failure, or interruption.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIN_FREE_GIB="${RYUKI_VERIFY_MIN_FREE_GIB:-30}"
MAX_TARGET_GIB="${RYUKI_VERIFY_MAX_TARGET_GIB:-64}"
KEEP_TARGET="${RYUKI_VERIFY_KEEP_TARGET:-0}"
WATCH_INTERVAL_SECONDS="${RYUKI_VERIFY_WATCH_INTERVAL_SECONDS:-5}"
ACTIVE_GATE_PID=""

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

VERIFY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-verify.XXXXXX")"
export CARGO_TARGET_DIR="${VERIFY_DIR}/target"
mkdir -p "$CARGO_TARGET_DIR"
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
  if [[ "$KEEP_TARGET" == "1" ]]; then
    echo "verification target retained at ${CARGO_TARGET_DIR}" >&2
  else
    cargo clean --target-dir "$CARGO_TARGET_DIR" >/dev/null 2>&1 \
      || rm -rf -- "$CARGO_TARGET_DIR"
    rmdir "$VERIFY_DIR" 2>/dev/null || true
  fi
  exit "$status"
}

disk_guard() {
  local announce="${1:-1}"
  local free_kib target_kib min_free_kib max_target_kib
  free_kib="$(df -Pk "$CARGO_TARGET_DIR" | awk 'END {print $4}')"
  target_kib="$(du -sk "$CARGO_TARGET_DIR" 2>/dev/null | awk '{print $1}')"
  target_kib="${target_kib:-0}"
  min_free_kib=$((MIN_FREE_GIB * 1024 * 1024))
  max_target_kib=$((MAX_TARGET_GIB * 1024 * 1024))

  if (( free_kib < min_free_kib )); then
    echo "error: verification stopped: less than ${MIN_FREE_GIB} GiB remains free" >&2
    return 75
  fi
  if (( target_kib > max_target_kib )); then
    echo "error: verification stopped: disposable target exceeded ${MAX_TARGET_GIB} GiB" >&2
    return 75
  fi

  if [[ "$announce" == "1" ]]; then
    echo "disk guard: $((free_kib / 1024 / 1024)) GiB free; target $((target_kib / 1024 / 1024)) GiB"
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

run_gate() {
  local label="$1"
  local command_pid command_status guard_status
  shift
  disk_guard
  echo "==> ${label}"

  "$@" &
  command_pid=$!
  ACTIVE_GATE_PID="$command_pid"
  while kill -0 "$command_pid" 2>/dev/null; do
    sleep "$WATCH_INTERVAL_SECONDS"
    if ! kill -0 "$command_pid" 2>/dev/null; then
      break
    fi
    if disk_guard 0; then
      continue
    else
      guard_status=$?
      echo "error: stopping ${label} before it can exhaust the disk" >&2
      stop_active_gate
      return "$guard_status"
    fi
  done

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

cd "$ROOT_DIR"
disk_guard

if [[ "${RYUKI_VERIFY_PREFLIGHT_ONLY:-0}" == "1" ]]; then
  echo "verification preflight passed; no build commands were run"
  exit 0
fi

run_gate "format" cargo fmt --check --all
run_gate "workspace build" cargo build --workspace
run_gate "workspace tests" cargo test --workspace
run_gate "workspace clippy" cargo clippy --workspace --all-targets -- -D warnings
run_gate "Vault chart release" ./deploy/kubernetes/vault/test-release-approved-chart.sh
run_gate "validator" cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all --root .
run_gate "dependency audit" ./scripts/dependency-audit.sh
run_gate "secret scan" ./scripts/no-secret-scan.sh
run_gate "patch hygiene" git diff --check

echo "workspace verification passed; disposable Cargo target will now be removed"
