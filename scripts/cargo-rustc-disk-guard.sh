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
  local candidate parent attempt configured_target configured_real out_real

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
    configured_real="$(cd "$configured_target" && pwd -P)"
    if [[ -z "$out_dir" ]]; then
      printf '%s\n' "$configured_real"
      return 0
    fi
    if [[ -d "$out_dir" ]]; then
      out_real="$(cd "$out_dir" && pwd -P)"
      case "$out_real/" in
        "$configured_real/"*)
          printf '%s\n' "$configured_real"
          return 0
          ;;
      esac
    fi
  fi
  return 1
}

# Cargo also uses the wrapper for compiler capability probes that have no
# output directory. Only those probes may run without a target supervisor. A
# real compiler invocation with `--out-dir` fails closed if its target cannot
# be identified, rather than writing into an unmonitored tree.
if ! target_root="$(find_target_root)"; then
  if [[ -n "$out_dir" ]]; then
    echo "error: Cargo compilation refused: unable to identify the target root" >&2
    exit 75
  fi
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
  local now last_check target_kib free_kib owner_pid lock_attempt max_lock_attempts
  local lock_acquired=0

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

  # A dead checker's lock is reclaimable by owner PID. Never age out a live
  # `du`: traversing a near-limit target can legitimately take longer than the
  # normal monitor interval. Forced pre/postflight checks wait briefly for a
  # live checker and fail closed if it cannot finish; background checks defer
  # to that live checker and keep observing the shared trip marker.
  max_lock_attempts=1
  [[ "$force" == "1" ]] && max_lock_attempts=100
  for ((lock_attempt = 0; lock_attempt < max_lock_attempts; lock_attempt++)); do
    if mkdir "$lock_dir" 2>/dev/null; then
      # Bash 3.2 has no BASHPID and keeps `$$` unchanged in a subshell. A
      # short-lived child reports its actual parent, which is this checker.
      /bin/sh -c 'printf "%s\n" "$PPID"' > "$lock_dir/owner-pid"
      lock_acquired=1
      break
    fi

    [[ ! -f "$trip_file" ]] || return 75
    owner_pid=""
    if [[ -f "$lock_dir/owner-pid" ]]; then
      read -r owner_pid < "$lock_dir/owner-pid" || owner_pid=""
    fi
    if [[ "$owner_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$owner_pid" 2>/dev/null; then
      rm -rf -- "$lock_dir"
      continue
    fi
    [[ "$force" == "1" ]] || return 0
    sleep 0.1
  done
  if (( lock_acquired == 0 )) && [[ "$force" == "1" ]]; then
    owner_pid=""
    if [[ -f "$lock_dir/owner-pid" ]]; then
      read -r owner_pid < "$lock_dir/owner-pid" || owner_pid=""
    fi
    # A checker killed between mkdir and owner publication can leave an
    # ownerless lock. Reclaim only that invalid form after the bounded wait;
    # a numeric live owner always wins and makes this check fail closed.
    if [[ ! "$owner_pid" =~ ^[0-9]+$ ]]; then
      rm -rf -- "$lock_dir"
      if mkdir "$lock_dir" 2>/dev/null; then
        /bin/sh -c 'printf "%s\n" "$PPID"' > "$lock_dir/owner-pid"
        lock_acquired=1
      fi
    fi
  fi
  (( lock_acquired == 1 )) || return 75
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

compiler_pid=""
compiler_pgid=""

stop_compiler_tree() {
  local pid="${compiler_pid:-}"
  local pgid="${compiler_pgid:-}"
  local attempt
  [[ -n "$pid" ]] || return 0

  if [[ -n "$pgid" ]]; then
    kill -TERM -- "-$pgid" 2>/dev/null || true
  else
    kill -TERM "$pid" 2>/dev/null || true
  fi
  for attempt in {1..20}; do
    if [[ -n "$pgid" ]]; then
      kill -0 -- "-$pgid" 2>/dev/null || break
    else
      kill -0 "$pid" 2>/dev/null || break
    fi
    sleep 0.1
  done
  if [[ -n "$pgid" ]] && kill -0 -- "-$pgid" 2>/dev/null; then
    kill -KILL -- "-$pgid" 2>/dev/null || true
  elif kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  compiler_pid=""
  compiler_pgid=""
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

# Monitor mode gives this one compiler and every inherited linker/descendant a
# dedicated process group. Turning monitor mode off immediately preserves the
# wrapper's normal non-interactive behavior while retaining group ownership.
set -m
"$@" &
compiler_pid=$!
compiler_pgid="$compiler_pid"
set +m
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

next_guard_check=$((SECONDS + CHECK_INTERVAL_SECONDS))
while kill -0 -- "-$compiler_pgid" 2>/dev/null; do
  # Poll child completion separately from the relatively expensive aggregate
  # size check so short compiler probes do not inherit a multi-second delay.
  sleep 0.2
  kill -0 -- "-$compiler_pgid" 2>/dev/null || break
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
compiler_pgid=""
trap - INT TERM
if ! guard_check 1; then
  echo "error: Cargo compiler output crossed the repository disk ceiling" >&2
  exit 75
fi
exit "$compiler_status"
