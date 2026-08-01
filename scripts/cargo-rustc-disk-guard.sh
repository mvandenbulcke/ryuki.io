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
# The rustc `--out-dir` must resolve inside the configured target. Repository
# launchers pin `CARGO_TARGET_DIR`; an unexported CLI `--target-dir` is refused
# rather than trusting a cache marker from an unrelated directory.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEFAULT_TARGET_DIR="$(cd "$ROOT_DIR/.." && pwd -P)/.ryuki-target-ryuki.io"
HARD_MAX_TARGET_GIB=24
HARD_MIN_FREE_GIB=30
HARD_MAX_CHECK_INTERVAL_SECONDS=2
HARD_MAX_TARGET_KIB=$((HARD_MAX_TARGET_GIB * 1024 * 1024))
MAX_TARGET_GIB="${RYUKI_CARGO_MAX_TARGET_GIB:-24}"
MIN_FREE_GIB="${RYUKI_CARGO_MIN_FREE_GIB:-30}"
CHECK_INTERVAL_SECONDS="${RYUKI_CARGO_GUARD_INTERVAL_SECONDS:-2}"
TEST_MODE="${RYUKI_CARGO_GUARD_TEST_MODE:-0}"
TEST_MAX_KIB="${RYUKI_CARGO_GUARD_TEST_MAX_KIB:-}"

if du --apparent-size --count-links -s -k /dev/null >/dev/null 2>&1; then
  APPARENT_DU_STYLE=gnu
elif du -A -l -s -k /dev/null >/dev/null 2>&1; then
  APPARENT_DU_STYLE=bsd
else
  echo "error: du cannot measure apparent file size on this host" >&2
  exit 69
fi

# Return the larger of allocated blocks and logical/apparent bytes, in KiB.
# Allocated size protects the filesystem; apparent size also catches sparse
# files and matches macOS Finder's directory-size accounting. Count hard-linked
# directory entries for the apparent total so a cache cannot hide logical
# growth behind aliases while retaining normal once-per-inode allocated usage.
measure_tree_kib() {
  local path="$1"
  local allocated_output="" allocated_kib=""
  local apparent_output="" apparent_kib=""

  if ! allocated_output="$(du -s -k "$path" 2>/dev/null)"; then
    : # Concurrent Cargo renames may make du nonzero while retaining its total.
  fi
  allocated_kib="$(printf '%s\n' "$allocated_output" | awk 'END {print $1}')"

  if [[ "$APPARENT_DU_STYLE" == "gnu" ]]; then
    if ! apparent_output="$(du --apparent-size --count-links -s -k "$path" 2>/dev/null)"; then
      :
    fi
  else
    if ! apparent_output="$(du -A -l -s -k "$path" 2>/dev/null)"; then
      :
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

require_positive_integer() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|0|0*|*[!0-9]*)
      echo "error: ${name} must be a positive integer" >&2
      exit 64
      ;;
  esac
  if (( ${#value} > 9 )); then
    echo "error: ${name} is outside the supported integer range" >&2
    exit 64
  fi
}

require_positive_integer RYUKI_CARGO_MAX_TARGET_GIB "$MAX_TARGET_GIB"
require_positive_integer RYUKI_CARGO_MIN_FREE_GIB "$MIN_FREE_GIB"
require_positive_integer RYUKI_CARGO_GUARD_INTERVAL_SECONDS "$CHECK_INTERVAL_SECONDS"

case "$TEST_MODE" in
  0|1) ;;
  *)
    echo "error: RYUKI_CARGO_GUARD_TEST_MODE must be 0 or 1" >&2
    exit 64
    ;;
esac

# These environment variables are tunable only toward a stricter posture.
# Test mode may select a smaller KiB ceiling for cheap regression fixtures, but
# it never weakens the repository's production size, free-space, or sampling
# bounds.
if (( MAX_TARGET_GIB > HARD_MAX_TARGET_GIB )); then
  echo "error: RYUKI_CARGO_MAX_TARGET_GIB must not exceed ${HARD_MAX_TARGET_GIB}" >&2
  exit 64
fi
if (( MIN_FREE_GIB < HARD_MIN_FREE_GIB )); then
  echo "error: RYUKI_CARGO_MIN_FREE_GIB must not be less than ${HARD_MIN_FREE_GIB}" >&2
  exit 64
fi
if (( CHECK_INTERVAL_SECONDS > HARD_MAX_CHECK_INTERVAL_SECONDS )); then
  echo "error: RYUKI_CARGO_GUARD_INTERVAL_SECONDS must not exceed ${HARD_MAX_CHECK_INTERVAL_SECONDS}" >&2
  exit 64
fi

if [[ -n "$TEST_MAX_KIB" && "$TEST_MODE" != "1" ]]; then
  echo "error: RYUKI_CARGO_GUARD_TEST_MAX_KIB is reserved for regression tests" >&2
  exit 64
fi
if [[ -n "$TEST_MAX_KIB" ]]; then
  require_positive_integer RYUKI_CARGO_GUARD_TEST_MAX_KIB "$TEST_MAX_KIB"
  if (( TEST_MAX_KIB > HARD_MAX_TARGET_KIB )); then
    echo "error: RYUKI_CARGO_GUARD_TEST_MAX_KIB must not exceed ${HARD_MAX_TARGET_KIB}" >&2
    exit 64
  fi
  configured_max_target_kib=$((MAX_TARGET_GIB * 1024 * 1024))
  if (( TEST_MAX_KIB > configured_max_target_kib )); then
    echo "error: RYUKI_CARGO_GUARD_TEST_MAX_KIB must not exceed the configured target ceiling of ${configured_max_target_kib} KiB" >&2
    exit 64
  fi
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

canonicalize_directory_destination() {
  local input="$1"
  local absolute_path resolved component candidate
  local -a components

  if [[ "$input" == /* ]]; then
    absolute_path="$input"
  else
    absolute_path="$PWD/$input"
  fi

  # Resolve every existing path component physically. Missing trailing
  # components are normalized without creating them, so a configured build
  # directory can be checked before Cargo creates it while symlink escapes in
  # any existing ancestor still fail containment.
  resolved="/"
  IFS='/' read -r -a components <<< "$absolute_path"
  for component in "${components[@]}"; do
    case "$component" in
      ''|.)
        continue
        ;;
      ..)
        if [[ "$resolved" != "/" ]]; then
          resolved="${resolved%/*}"
          [[ -n "$resolved" ]] || resolved="/"
        fi
        continue
        ;;
    esac

    if [[ "$resolved" == "/" ]]; then
      candidate="/$component"
    else
      candidate="$resolved/$component"
    fi

    if [[ -L "$candidate" ]]; then
      [[ -d "$candidate" ]] || return 1
      resolved="$(cd "$candidate" && pwd -P)" || return 1
    elif [[ -e "$candidate" && ! -d "$candidate" ]]; then
      return 1
    elif [[ -d "$candidate" ]]; then
      resolved="$(cd "$candidate" && pwd -P)" || return 1
    else
      resolved="$candidate"
    fi
  done

  printf '%s\n' "$resolved"
}

find_target_root() {
  local configured_target configured_real out_real

  configured_target="${CARGO_TARGET_DIR:-$DEFAULT_TARGET_DIR}"
  if [[ "$configured_target" != /* ]]; then
    configured_target="$PWD/$configured_target"
  fi
  [[ -d "$configured_target" ]] || return 1
  configured_real="$(cd "$configured_target" && pwd -P)" || return 1

  if [[ -n "$out_dir" ]]; then
    # Compare physical paths only. A lexical `$target/debug` path may cross a
    # symlink, and no CACHEDIR.TAG outside the configured target may redefine
    # which directory the guard supervises.
    [[ -d "$out_dir" ]] || return 1
    out_real="$(cd "$out_dir" && pwd -P)" || return 1
    case "$out_real/" in
      "$configured_real/"*) ;;
      *) return 1 ;;
    esac
  fi

  printf '%s\n' "$configured_real"
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

case "$target_root" in
  "$ROOT_DIR"|"$ROOT_DIR"/*)
    echo "error: Cargo compilation refused: target root must be outside the repository checkout" >&2
    exit 75
    ;;
esac

if [[ "${CARGO_BUILD_BUILD_DIR+x}" == "x" ]]; then
  if [[ -z "$CARGO_BUILD_BUILD_DIR" ]] \
    || ! build_dir_real="$(canonicalize_directory_destination "$CARGO_BUILD_BUILD_DIR")"; then
    echo "error: Cargo compilation refused: CARGO_BUILD_BUILD_DIR is not a resolvable directory destination" >&2
    exit 75
  fi
  case "$build_dir_real/" in
    "$target_root/"*) ;;
    *)
      echo "error: Cargo compilation refused: CARGO_BUILD_BUILD_DIR must resolve inside the target root" >&2
      exit 75
      ;;
  esac
fi

if [[ "$TEST_MODE" == "1" ]]; then
  test_tmp="${TMPDIR:-/tmp}"
  if [[ ! -d "$test_tmp" ]]; then
    echo "error: Cargo disk-guard test mode requires a safe temporary directory" >&2
    exit 75
  fi
  test_tmp="$(cd "$test_tmp" && pwd -P)"
  case "$test_tmp" in
    "$ROOT_DIR"|"$ROOT_DIR"/*)
      echo "error: Cargo disk-guard test mode temporary directory must be outside the repository checkout" >&2
      exit 75
      ;;
  esac
  case "$target_root" in
    "$test_tmp"/ryuki-cargo-guard.*/*) ;;
    *)
      echo "error: Cargo disk-guard test mode target must remain inside its private regression fixture" >&2
      exit 75
      ;;
  esac
fi

state_dir="$target_root/.ryuki-cargo-disk-guard"
lock_path="$state_dir/check.lock"
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
  local owner_token owner_dir current_token current_owner_dir
  local lock_acquired=0

  release_guard_lock() {
    local published_token=""
    if [[ -L "$lock_path" ]]; then
      published_token="$(readlink "$lock_path" 2>/dev/null || true)"
    fi
    if [[ -n "${owner_token:-}" && "$published_token" == "$owner_token" ]]; then
      rm -f -- "$lock_path"
    fi
    if [[ -n "${owner_dir:-}" ]]; then
      rm -rf -- "$owner_dir"
    fi
  }

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

  # The published lock is one atomic symlink to an owner-specific directory.
  # Releasing it is one unlink, so an exiting checker cannot recursively delete
  # a successor's lock. Never age out a live `du`: traversing a near-limit
  # target can legitimately take longer than the normal monitor interval.
  max_lock_attempts=1
  [[ "$force" == "1" ]] && max_lock_attempts=100
  for ((lock_attempt = 0; lock_attempt < max_lock_attempts; lock_attempt++)); do
    owner_token="check-owner.$$.$RANDOM.$RANDOM"
    owner_dir="$state_dir/$owner_token"
    if ! mkdir "$owner_dir" 2>/dev/null; then
      [[ "$force" == "1" ]] || return 0
      sleep 0.1
      continue
    fi
    # Bash 3.2 has no BASHPID and keeps `$$` unchanged in a subshell. A
    # short-lived child reports its actual parent, which is this checker.
    /bin/sh -c 'printf "%s\n" "$PPID"' > "$owner_dir/owner-pid"
    if ln -s "$owner_token" "$lock_path" 2>/dev/null; then
      lock_acquired=1
      break
    fi
    rm -rf -- "$owner_dir"
    owner_dir=""

    [[ ! -f "$trip_file" ]] || return 75
    owner_pid=""
    current_token=""
    current_owner_dir=""
    if [[ -L "$lock_path" ]]; then
      current_token="$(readlink "$lock_path" 2>/dev/null || true)"
      case "$current_token" in
        check-owner.*)
          if [[ "$current_token" != */* ]]; then
            current_owner_dir="$state_dir/$current_token"
          fi
          ;;
      esac
    fi
    if [[ -n "$current_owner_dir" && -f "$current_owner_dir/owner-pid" ]]; then
      read -r owner_pid < "$current_owner_dir/owner-pid" || owner_pid=""
    fi
    if [[ -L "$lock_path" && ( ! "$owner_pid" =~ ^[0-9]+$ || ! -d "$current_owner_dir" ) ]]; then
      rm -f -- "$lock_path"
      [[ -z "$current_owner_dir" ]] || rm -rf -- "$current_owner_dir"
      continue
    fi
    if [[ "$owner_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$owner_pid" 2>/dev/null; then
      if [[ -L "$lock_path" && "$(readlink "$lock_path" 2>/dev/null || true)" == "$current_token" ]]; then
        rm -f -- "$lock_path"
      fi
      [[ -z "$current_owner_dir" ]] || rm -rf -- "$current_owner_dir"
      continue
    fi
    [[ "$force" == "1" ]] || return 0
    sleep 0.1
  done
  (( lock_acquired == 1 )) || return 75
  trap release_guard_lock EXIT INT TERM

  target_kib=""
  target_kib="$(measure_tree_kib "$target_root")" || target_kib=""
  free_kib="$(df -Pk "$target_root" | awk 'END {print $4}')"

  if [[ ! "$target_kib" =~ ^[0-9]+$ || ! "$free_kib" =~ ^[0-9]+$ ]]; then
    trip_guard
    echo "error: Cargo target allocated/apparent size or free space could not be measured" >&2
    return 75
  fi

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
