#!/usr/bin/env bash
set -Eeuo pipefail

# Repository-wide Cargo target ceiling.
#
# `verify-workspace-clean.sh` gives coding-agent checks a disposable target and
# active watcher. This rustc wrapper is the second line of defence for Cargo
# entry points that bypass that workflow (direct Cargo, Make, cargo-leptos, an
# IDE, or a future script). Cargo invokes the wrapper as:
#
#   cargo-rustc-disk-guard.sh /path/to/rustc <rustc arguments...>
#
# The effective target is located from rustc's `--out-dir`, so `--target-dir`,
# target triples, and the disposable verification target are all covered.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MAX_TARGET_GIB="${RYUKI_CARGO_MAX_TARGET_GIB:-48}"
MIN_FREE_GIB="${RYUKI_CARGO_MIN_FREE_GIB:-30}"
CHECK_INTERVAL_SECONDS="${RYUKI_CARGO_GUARD_INTERVAL_SECONDS:-2}"
TEST_MODE="${RYUKI_CARGO_GUARD_TEST_MODE:-0}"
TEST_MAX_KIB="${RYUKI_CARGO_GUARD_TEST_MAX_KIB:-}"

require_positive_integer() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|*[!0-9]*|0)
      echo "error: ${name} must be a positive integer" >&2
      exit 64
      ;;
  esac
}

require_positive_integer RYUKI_CARGO_MAX_TARGET_GIB "$MAX_TARGET_GIB"
require_positive_integer RYUKI_CARGO_MIN_FREE_GIB "$MIN_FREE_GIB"
require_positive_integer RYUKI_CARGO_GUARD_INTERVAL_SECONDS "$CHECK_INTERVAL_SECONDS"

if [[ -n "$TEST_MAX_KIB" && "$TEST_MODE" != "1" ]]; then
  echo "error: RYUKI_CARGO_GUARD_TEST_MAX_KIB is reserved for regression tests" >&2
  exit 64
fi
if [[ -n "$TEST_MAX_KIB" ]]; then
  require_positive_integer RYUKI_CARGO_GUARD_TEST_MAX_KIB "$TEST_MAX_KIB"
fi

out_dir=""
arguments=("$@")
for ((index = 0; index < ${#arguments[@]}; index++)); do
  argument="${arguments[$index]}"
  if [[ "$argument" == "--out-dir" && $((index + 1)) -lt ${#arguments[@]} ]]; then
    out_dir="${arguments[$((index + 1))]}"
    break
  fi
  if [[ "$argument" == --out-dir=* ]]; then
    out_dir="${argument#--out-dir=}"
    break
  fi
done

find_target_root() {
  local candidate parent attempt configured_target

  if [[ -n "$out_dir" ]]; then
    candidate="$out_dir"
    for attempt in {1..10}; do
      if [[ -f "$candidate/CACHEDIR.TAG" ]]; then
        (cd "$candidate" && pwd -P)
        return 0
      fi
      parent="$(dirname "$candidate")"
      [[ "$parent" != "$candidate" ]] || break
      candidate="$parent"
    done
  fi

  configured_target="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
  if [[ "$configured_target" != /* ]]; then
    configured_target="$PWD/$configured_target"
  fi
  if [[ -d "$configured_target" ]]; then
    (cd "$configured_target" && pwd -P)
    return 0
  fi
  return 1
}

# Cargo also uses the wrapper for compiler capability probes that have no
# output directory. Delegate those immediately when no target exists yet.
if ! target_root="$(find_target_root)"; then
  exec "$@"
fi

state_dir="$target_root/.ryuki-cargo-disk-guard"
lock_dir="$state_dir/check.lock"
stamp_file="$state_dir/last-check"
trip_file="$state_dir/target-limit-tripped"
mkdir -p "$state_dir"

max_target_kib=$((MAX_TARGET_GIB * 1024 * 1024))
min_free_kib=$((MIN_FREE_GIB * 1024 * 1024))
if [[ -n "$TEST_MAX_KIB" ]]; then
  max_target_kib="$TEST_MAX_KIB"
fi

trip_guard() {
  local temporary="${trip_file}.$$.$RANDOM"
  printf 'tripped\n' > "$temporary"
  mv -f -- "$temporary" "$trip_file"
}

# One concurrent wrapper pays for `du`; every wrapper remains alive to watch
# the shared trip marker for the full lifetime of its compiler. A fresh forced
# check can clear a prior trip only after the target has actually returned
# below both limits (normally after `make clean`).
guard_check() (
  local force="${1:-0}"
  local now last_check lock_timestamp target_kib free_kib

  now="$(date +%s)"
  last_check=0
  if [[ -f "$stamp_file" ]]; then
    read -r last_check < "$stamp_file" || last_check=0
  fi
  [[ "$last_check" =~ ^[0-9]+$ ]] || last_check=0

  if [[ "$force" != "1" && -f "$trip_file" ]]; then
    return 75
  fi
  if [[ "$force" != "1" ]] && (( now - last_check < CHECK_INTERVAL_SECONDS )); then
    return 0
  fi

  # A dead checker's lock is reclaimable; lock contention never disables
  # supervision because the other wrappers still observe `trip_file`.
  if ! mkdir "$lock_dir" 2>/dev/null; then
    lock_timestamp=0
    if [[ -f "$lock_dir/timestamp" ]]; then
      read -r lock_timestamp < "$lock_dir/timestamp" || lock_timestamp=0
    fi
    if [[ "$lock_timestamp" =~ ^[0-9]+$ ]] \
      && (( now - lock_timestamp > CHECK_INTERVAL_SECONDS * 2 )); then
      rm -rf -- "$lock_dir"
      mkdir "$lock_dir" 2>/dev/null || {
        [[ ! -f "$trip_file" ]]
        return
      }
    else
      [[ ! -f "$trip_file" ]]
      return
    fi
  fi
  printf '%s\n' "$now" > "$lock_dir/timestamp"
  trap 'rm -rf -- "$lock_dir"' EXIT INT TERM

  target_kib="$(du -sk "$target_root" | awk '{print $1}')"
  free_kib="$(df -Pk "$target_root" | awk 'END {print $4}')"

  if (( target_kib > max_target_kib )); then
    trip_guard
    echo "error: Cargo target exceeded the ${MAX_TARGET_GIB} GiB repository ceiling" >&2
    return 75
  fi
  if (( free_kib < min_free_kib )); then
    trip_guard
    echo "error: Cargo target stopped because less than ${MIN_FREE_GIB} GiB remains free" >&2
    return 75
  fi

  rm -f -- "$trip_file"
  printf '%s\n' "$now" > "$stamp_file"
)

collect_process_tree() {
  local pid="$1"
  local child
  if command -v pgrep >/dev/null 2>&1; then
    while IFS= read -r child; do
      [[ -n "$child" ]] && collect_process_tree "$child"
    done < <(pgrep -P "$pid" 2>/dev/null || true)
  fi
  printf '%s\n' "$pid"
}

compiler_pid=""

stop_compiler_tree() {
  local pid="${compiler_pid:-}"
  local child attempt alive
  local tree_pids=()
  [[ -n "$pid" ]] || return 0

  while IFS= read -r child; do
    [[ -n "$child" ]] && tree_pids+=("$child")
  done < <(collect_process_tree "$pid")
  for child in "${tree_pids[@]}"; do
    kill -TERM "$child" 2>/dev/null || true
  done
  for attempt in {1..20}; do
    alive=0
    for child in "${tree_pids[@]}"; do
      if kill -0 "$child" 2>/dev/null; then
        alive=1
        break
      fi
    done
    (( alive == 0 )) && break
    sleep 0.1
  done
  if (( alive != 0 )); then
    for child in "${tree_pids[@]}"; do
      kill -KILL "$child" 2>/dev/null || true
    done
  fi
  wait "$pid" 2>/dev/null || true
  compiler_pid=""
}

handle_signal() {
  local status="$1"
  trap - INT TERM
  stop_compiler_tree
  exit "$status"
}

if ! guard_check 1; then
  echo "error: Cargo compilation refused by the repository disk guard" >&2
  echo "error: run 'make clean' or use the disposable verification wrapper" >&2
  exit 75
fi

"$@" &
compiler_pid=$!
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

next_guard_check=$((SECONDS + CHECK_INTERVAL_SECONDS))
while kill -0 "$compiler_pid" 2>/dev/null; do
  # Poll child completion separately from the relatively expensive aggregate
  # size check so short compiler probes do not inherit a multi-second delay.
  sleep 0.2
  kill -0 "$compiler_pid" 2>/dev/null || break
  if (( SECONDS < next_guard_check )); then
    continue
  fi
  next_guard_check=$((SECONDS + CHECK_INTERVAL_SECONDS))
  if guard_check 0; then
    continue
  fi
  echo "error: stopping Cargo compiler processes before they can exhaust the disk" >&2
  stop_compiler_tree
  exit 75
done

if wait "$compiler_pid"; then
  compiler_status=0
else
  compiler_status=$?
fi
compiler_pid=""
trap - INT TERM
exit "$compiler_status"
