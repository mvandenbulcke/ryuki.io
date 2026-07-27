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
CHECK_INTERVAL_SECONDS="${RYUKI_CARGO_GUARD_INTERVAL_SECONDS:-15}"
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
mkdir -p "$state_dir"

now="$(date +%s)"
last_check=0
if [[ -f "$stamp_file" ]]; then
  read -r last_check < "$stamp_file" || last_check=0
fi
if [[ ! "$last_check" =~ ^[0-9]+$ ]]; then
  last_check=0
fi

if (( now - last_check < CHECK_INTERVAL_SECONDS )); then
  exec "$@"
fi

# Only one concurrent rustc wrapper pays for `du`. A dead checker's lock is
# reclaimed after twice the check interval so it cannot disable the ceiling.
if ! mkdir "$lock_dir" 2>/dev/null; then
  lock_timestamp=0
  if [[ -f "$lock_dir/timestamp" ]]; then
    read -r lock_timestamp < "$lock_dir/timestamp" || lock_timestamp=0
  fi
  if [[ "$lock_timestamp" =~ ^[0-9]+$ ]] \
    && (( now - lock_timestamp > CHECK_INTERVAL_SECONDS * 2 )); then
    rm -rf -- "$lock_dir"
    mkdir "$lock_dir" 2>/dev/null || exec "$@"
  else
    exec "$@"
  fi
fi
printf '%s\n' "$now" > "$lock_dir/timestamp"

release_lock() {
  rm -rf -- "$lock_dir"
}
trap release_lock EXIT INT TERM

target_kib="$(du -sk "$target_root" | awk '{print $1}')"
free_kib="$(df -Pk "$target_root" | awk 'END {print $4}')"
max_target_kib=$((MAX_TARGET_GIB * 1024 * 1024))
min_free_kib=$((MIN_FREE_GIB * 1024 * 1024))
if [[ -n "$TEST_MAX_KIB" ]]; then
  max_target_kib="$TEST_MAX_KIB"
fi

if (( target_kib > max_target_kib )); then
  echo "error: Cargo compilation refused: target exceeds the ${MAX_TARGET_GIB} GiB repository ceiling" >&2
  echo "error: run 'make clean' or use the disposable verification wrapper" >&2
  exit 75
fi
if (( free_kib < min_free_kib )); then
  echo "error: Cargo compilation refused: less than ${MIN_FREE_GIB} GiB remains free" >&2
  echo "error: run 'make clean' or free disk capacity" >&2
  exit 75
fi

printf '%s\n' "$now" > "$stamp_file"
release_lock
trap - EXIT INT TERM
exec "$@"
