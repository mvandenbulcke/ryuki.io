#!/usr/bin/env bash
set -Eeuo pipefail

# Guard persistent local-development Cargo commands. Unlike verify-clean, this
# cache survives successful commands, but it must always remain outside the
# checkout and below the repository disk ceiling.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROOT_PARENT="$(cd "$ROOT_DIR/.." && pwd -P)"
RUSTC_GUARD="$ROOT_DIR/scripts/cargo-rustc-disk-guard.sh"
GIT_COMMON_DIR_RAW="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)"
GIT_COMMON_DIR="$(cd "$GIT_COMMON_DIR_RAW" && pwd -P)"
REPOSITORY_ID="$(printf '%s' "$GIT_COMMON_DIR" | git -C "$ROOT_DIR" hash-object --stdin)"
HARD_MAX_TARGET_GIB=24
HARD_MIN_FREE_GIB=30
WATCH_INTERVAL_SECONDS=2
TARGET_INPUT="${RYUKI_DEV_TARGET_DIR:-$ROOT_PARENT/.ryuki-target-ryuki.io}"
SITE_INPUT="${RYUKI_LEPTOS_SITE_ROOT:-$TARGET_INPUT/leptos-site}"
DEV_SUPERVISOR_PID=""
SUPERVISED_COMMAND_PID=""
SUPERVISED_COMMAND_PGID=""
SUPERVISOR_CONTROL_FILE=""

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 64
}

canonical_destination() {
  local input="$1"
  local label="$2"
  local parent base resolved_parent resolved

  [[ -n "$input" ]] || fail "$label path must not be empty"
  if [[ "$input" != /* ]]; then
    input="$ROOT_DIR/$input"
  fi
  [[ ! -L "$input" ]] || fail "$label path must not be a symlink"

  if [[ -e "$input" ]]; then
    [[ -d "$input" ]] || fail "$label path must be a directory"
    resolved="$(cd "$input" && pwd -P)" || fail "cannot canonicalize $label path"
  else
    parent="$(dirname "$input")"
    base="$(basename "$input")"
    [[ "$base" != "." && "$base" != ".." && -n "$base" ]] || \
      fail "$label path has an unsafe final component"
    [[ -d "$parent" && ! -L "$parent" ]] || \
      fail "$label parent must be an existing non-symlink directory"
    resolved_parent="$(cd "$parent" && pwd -P)" || \
      fail "cannot canonicalize $label parent"
    resolved="$resolved_parent/$base"
  fi

  [[ "$resolved" != "/" && "$resolved" != "$ROOT_PARENT" ]] || \
    fail "$label path is too broad"
  case "$resolved" in
    "$ROOT_DIR"|"$ROOT_DIR"/*) fail "$label path must be outside the repository checkout" ;;
  esac
  printf '%s\n' "$resolved"
}

prepare_paths() {
  local mode="$1"
  local sentinel expected actual
  [[ -f "$RUSTC_GUARD" && ! -L "$RUSTC_GUARD" && -x "$RUSTC_GUARD" ]] || \
    fail "repository Cargo rustc guard is missing or unsafe: $RUSTC_GUARD"
  TARGET_DIR="$(canonical_destination "$TARGET_INPUT" "Cargo target")"
  [[ "$(basename "$TARGET_DIR")" == ".ryuki-target-ryuki.io" ]] || \
    fail "Cargo target must use the dedicated .ryuki-target-ryuki.io cache basename"
  if [[ ! -e "$TARGET_DIR" ]]; then
    if [[ "$mode" == "status" ]]; then
      TARGET_PRESENT=0
      return 0
    fi
    mkdir -m 700 "$TARGET_DIR" || fail "cannot create external Cargo target"
  fi
  TARGET_PRESENT=1
  [[ -d "$TARGET_DIR" && ! -L "$TARGET_DIR" && -O "$TARGET_DIR" \
    && -w "$TARGET_DIR" && -x "$TARGET_DIR" ]] || \
    fail "external Cargo target must be a private owned writable directory"

  sentinel="$TARGET_DIR/.ryuki-cargo-dev-owner"
  expected="$(printf 'version=1\nrepository_id=%s\n' "$REPOSITORY_ID")"
  if [[ ! -e "$sentinel" && -z "$(find "$TARGET_DIR" -mindepth 1 -print -quit)" ]]; then
    [[ "$mode" != "status" ]] || \
      fail "external Cargo target is unmarked; status will not claim it"
    (set -o noclobber; printf '%s\n' "$expected" > "$sentinel") || \
      fail "cannot publish Cargo target ownership sentinel"
    chmod 600 "$sentinel"
  fi
  [[ -f "$sentinel" && ! -L "$sentinel" ]] || \
    fail "external Cargo target is missing its ownership sentinel"
  actual="$(<"$sentinel")" || fail "cannot read Cargo target ownership sentinel"
  [[ "$actual" == "$expected" ]] || fail "external Cargo target ownership sentinel is invalid"

  if [[ "$mode" == "status" ]]; then
    return 0
  fi
  reclaim_stale_supervisor_controls
  chmod 700 "$TARGET_DIR"

  BUILD_DIR="$TARGET_DIR/build-cache"
  [[ ! -L "$BUILD_DIR" ]] || fail "Cargo build path must not be a symlink"
  if [[ ! -e "$BUILD_DIR" ]]; then
    mkdir -m 700 "$BUILD_DIR" || fail "cannot create external Cargo build directory"
  fi
  [[ -d "$BUILD_DIR" && ! -L "$BUILD_DIR" && -O "$BUILD_DIR" \
    && -w "$BUILD_DIR" && -x "$BUILD_DIR" ]] || \
    fail "external Cargo build path must be a private owned writable directory"
  chmod 700 "$BUILD_DIR"

  if [[ "$mode" == "run-portal" ]]; then
    SITE_ROOT="$(canonical_destination "$SITE_INPUT" "Leptos site")"
    case "$SITE_ROOT" in
      "$TARGET_DIR"/*) ;;
      *) fail "Leptos site path must remain inside the external Cargo target" ;;
    esac
  fi
}

sanitize_cargo_environment() {
  unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR CARGO_BUILD_BUILD_DIR
  unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
  unset CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
  unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
  unset CARGO_BUILD_INCREMENTAL
  unset CARGO_PROFILE_DEV_INCREMENTAL CARGO_PROFILE_TEST_INCREMENTAL
  unset RYUKI_CARGO_GUARD_TEST_MODE RYUKI_CARGO_GUARD_TEST_MAX_KIB
  unset RYUKI_CARGO_MAX_TARGET_GIB RYUKI_CARGO_MIN_FREE_GIB
  unset RYUKI_CARGO_GUARD_INTERVAL_SECONDS

  export CARGO_TARGET_DIR="$TARGET_DIR"
  export CARGO_BUILD_BUILD_DIR="$BUILD_DIR"
  export RUSTC_WRAPPER="$RUSTC_GUARD"
  export RUSTC_WORKSPACE_WRAPPER=""
  export CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=""
  export CARGO_INCREMENTAL=0
  export RYUKI_CARGO_MAX_TARGET_GIB="$HARD_MAX_TARGET_GIB"
  export RYUKI_CARGO_MIN_FREE_GIB="$HARD_MIN_FREE_GIB"
  export RYUKI_CARGO_GUARD_INTERVAL_SECONDS="$WATCH_INTERVAL_SECONDS"
}

if du --apparent-size --count-links -s -k /dev/null >/dev/null 2>&1; then
  APPARENT_DU_STYLE=gnu
elif du -A -l -s -k /dev/null >/dev/null 2>&1; then
  APPARENT_DU_STYLE=bsd
else
  fail "du cannot measure apparent file size on this host"
fi

measure_tree_kib() {
  local path="$1"
  local allocated_output="" allocated_kib=""
  local apparent_output="" apparent_kib=""

  allocated_output="$(du -s -k "$path" 2>/dev/null)" || return 1
  allocated_kib="$(printf '%s\n' "$allocated_output" | awk 'END {print $1}')"
  if [[ "$APPARENT_DU_STYLE" == "gnu" ]]; then
    apparent_output="$(du --apparent-size --count-links -s -k "$path" 2>/dev/null)" \
      || return 1
  else
    apparent_output="$(du -A -l -s -k "$path" 2>/dev/null)" || return 1
  fi
  apparent_kib="$(printf '%s\n' "$apparent_output" | awk 'END {print $1}')"
  [[ "$allocated_kib" =~ ^[0-9]+$ && "$apparent_kib" =~ ^[0-9]+$ ]] || return 1
  if (( apparent_kib > allocated_kib )); then
    printf '%s\n' "$apparent_kib"
  else
    printf '%s\n' "$allocated_kib"
  fi
}

disk_guard() {
  local target_kib free_kib
  local max_target_kib=$((HARD_MAX_TARGET_GIB * 1024 * 1024))
  local min_free_kib=$((HARD_MIN_FREE_GIB * 1024 * 1024))

  if ! target_kib="$(measure_tree_kib "$TARGET_DIR")"; then
    printf 'error: cannot measure external Cargo target size\n' >&2
    return 75
  fi
  free_kib="$(df -Pk "$TARGET_DIR" | awk 'END {print $4}')"
  if [[ ! "$free_kib" =~ ^[0-9]+$ ]]; then
    printf 'error: cannot measure Cargo target free space\n' >&2
    return 75
  fi
  if (( target_kib > max_target_kib )); then
    printf 'error: external Cargo target exceeds the %s GiB ceiling\n' \
      "$HARD_MAX_TARGET_GIB" >&2
    return 75
  fi
  if (( free_kib < min_free_kib )); then
    printf 'error: Cargo command refused with less than %s GiB free\n' \
      "$HARD_MIN_FREE_GIB" >&2
    return 75
  fi
}

process_group_alive() {
  local pgid="${1:-}"
  [[ -n "$pgid" ]] || return 1
  kill -0 -- "-$pgid" 2>/dev/null
}

reclaim_stale_supervisor_controls() {
  local control_file suffix
  for control_file in "$TARGET_DIR"/.cargo-command-control.*; do
    [[ -e "$control_file" || -L "$control_file" ]] || continue
    suffix="${control_file##*.cargo-command-control.}"
    [[ "$suffix" =~ ^[1-9][0-9]*$ ]] || \
      fail "Cargo target contains a malformed supervisor control entry"
    if ! read_supervisor_control "$control_file"; then
      fail "Cargo target contains an invalid supervisor control file"
    fi
    [[ "$CONTROL_LAUNCHER_PID" == "$suffix" ]] || \
      fail "Cargo supervisor control file has an invalid launcher identity"
    if kill -0 "$CONTROL_SUPERVISOR_PID" 2>/dev/null; then
      fail "another guarded Cargo command is already active for this target"
    fi
    if process_group_alive "$SUPERVISED_COMMAND_PGID"; then
      fail "stale Cargo control references a live process group; refusing unsafe PID reuse recovery"
    fi
    rm -f -- "$control_file"
  done
  SUPERVISED_COMMAND_PID=""
  SUPERVISED_COMMAND_PGID=""
}

stop_supervised_command() {
  local pgid="${SUPERVISED_COMMAND_PGID:-}"
  local pid="${SUPERVISED_COMMAND_PID:-}"
  local attempt

  if [[ -n "$pgid" ]] && process_group_alive "$pgid"; then
    kill -TERM -- "-$pgid" 2>/dev/null || true
    for attempt in {1..20}; do
      process_group_alive "$pgid" || break
      sleep 0.1
    done
    if process_group_alive "$pgid"; then
      kill -KILL -- "-$pgid" 2>/dev/null || true
    fi
  elif [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
  [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true
  SUPERVISED_COMMAND_PID=""
  SUPERVISED_COMMAND_PGID=""
}

supervisor_signal() {
  local status="$1"
  trap '' HUP INT TERM
  stop_supervised_command
  exit "$status"
}

read_supervisor_control() {
  local control_file="$1"
  local expected_launcher="${2:-}" expected_supervisor="${3:-}"
  local key value version="" launcher_pid="" supervisor_pid="" pid="" pgid=""

  [[ -f "$control_file" && ! -L "$control_file" && -O "$control_file" ]] || return 1
  while IFS='=' read -r key value; do
    case "$key" in
      version) [[ -z "$version" ]] || return 1; version="$value" ;;
      launcher_pid) [[ -z "$launcher_pid" ]] || return 1; launcher_pid="$value" ;;
      supervisor_pid) [[ -z "$supervisor_pid" ]] || return 1; supervisor_pid="$value" ;;
      pid) [[ -z "$pid" ]] || return 1; pid="$value" ;;
      pgid) [[ -z "$pgid" ]] || return 1; pgid="$value" ;;
      *) return 1 ;;
    esac
  done < "$control_file"
  [[ "$version" == "1" && "$launcher_pid" =~ ^[1-9][0-9]*$ \
    && "$supervisor_pid" =~ ^[1-9][0-9]*$ && "$pid" =~ ^[1-9][0-9]*$ \
    && "$pgid" =~ ^[1-9][0-9]*$ && "$pid" == "$pgid" ]] \
    || return 1
  [[ -z "$expected_launcher" || "$launcher_pid" == "$expected_launcher" ]] || return 1
  [[ -z "$expected_supervisor" || "$supervisor_pid" == "$expected_supervisor" ]] \
    || return 1
  CONTROL_LAUNCHER_PID="$launcher_pid"
  CONTROL_SUPERVISOR_PID="$supervisor_pid"
  SUPERVISED_COMMAND_PID="$pid"
  SUPERVISED_COMMAND_PGID="$pgid"
}

recover_supervisor_command() {
  local control_file="${SUPERVISOR_CONTROL_FILE:-}"
  local expected_launcher="${1:-}" expected_supervisor="${2:-}"
  local release_file release_tmp control_tmp
  [[ -n "$control_file" && -e "$control_file" ]] || return 0
  release_file="${control_file/.cargo-command-control./.cargo-command-release.}"
  release_tmp="${release_file}.tmp"
  control_tmp="${control_file}.tmp"
  if ! read_supervisor_control "$control_file" "$expected_launcher" "$expected_supervisor"; then
    printf 'error: refusing malformed Cargo supervisor control file: %s\n' \
      "$control_file" >&2
    return 75
  fi
  if process_group_alive "$SUPERVISED_COMMAND_PGID"; then
    printf 'stopping Cargo command after its disk supervisor exited\n' >&2
    stop_supervised_command
  fi
  rm -f -- "$control_file" "$control_tmp" "$release_file" "$release_tmp"
}

supervise_command() {
  local wrapper_pid="$1"
  local status_file status_tmp control_tmp release_file release_tmp
  local command_pid command_pgid command_status command_wait_status
  local guard_status=0 stop_status=0 supervisor_pid released release_attempt
  shift

  trap - EXIT HUP INT TERM
  trap 'supervisor_signal 129' HUP
  trap 'supervisor_signal 130' INT
  trap 'supervisor_signal 143' TERM
  disk_guard || return $?
  status_file="$TARGET_DIR/.cargo-command-status.$wrapper_pid.$RANDOM"
  status_tmp="${status_file}.tmp"
  SUPERVISOR_CONTROL_FILE="$TARGET_DIR/.cargo-command-control.$wrapper_pid"
  control_tmp="${SUPERVISOR_CONTROL_FILE}.tmp"
  release_file="$TARGET_DIR/.cargo-command-release.$wrapper_pid"
  release_tmp="${release_file}.tmp"
  supervisor_pid="$(/bin/sh -c 'printf "%s\n" "$PPID"')"
  [[ "$supervisor_pid" =~ ^[1-9][0-9]*$ ]] || return 75
  [[ ! -e "$release_file" && ! -L "$release_file" \
    && ! -e "$release_tmp" && ! -L "$release_tmp" ]] || return 75
  set -m
  (
    trap - EXIT HUP INT TERM
    exec 9>&-
    released=0
    for release_attempt in {1..100}; do
      if [[ -e "$release_file" || -L "$release_file" ]]; then
        [[ -f "$release_file" && ! -L "$release_file" && -O "$release_file" ]] \
          || exit 75
        rm -f -- "$release_file"
        released=1
        break
      fi
      kill -0 "$supervisor_pid" 2>/dev/null || exit 75
      sleep 0.05
    done
    (( released == 1 )) || exit 75
    set +e
    "$@"
    command_status=$?
    printf '%s\n' "$command_status" > "$status_tmp"
    mv -f -- "$status_tmp" "$status_file"
    exit "$command_status"
  ) &
  command_pid=$!
  command_pgid="$command_pid"
  set +m
  SUPERVISED_COMMAND_PID="$command_pid"
  SUPERVISED_COMMAND_PGID="$command_pgid"
  [[ ! -e "$control_tmp" && ! -L "$control_tmp" \
    && ! -e "$SUPERVISOR_CONTROL_FILE" && ! -L "$SUPERVISOR_CONTROL_FILE" ]] || {
    stop_supervised_command
    return 75
  }
  {
    printf 'version=1\n'
    printf 'launcher_pid=%s\n' "$wrapper_pid"
    printf 'supervisor_pid=%s\n' "$supervisor_pid"
    printf 'pid=%s\n' "$command_pid"
    printf 'pgid=%s\n' "$command_pgid"
  } > "$control_tmp"
  chmod 600 "$control_tmp"
  mv -f -- "$control_tmp" "$SUPERVISOR_CONTROL_FILE"
  (set -o noclobber; : > "$release_tmp") || {
    stop_supervised_command
    rm -f -- "$SUPERVISOR_CONTROL_FILE" "$control_tmp" "$release_tmp"
    return 75
  }
  chmod 600 "$release_tmp"
  mv -- "$release_tmp" "$release_file"

  while process_group_alive "$command_pgid"; do
    [[ ! -f "$status_file" ]] || break
    if ! kill -0 "$wrapper_pid" 2>/dev/null; then
      printf 'error: stopping Cargo command after its launcher was interrupted\n' >&2
      stop_supervised_command
      rm -f -- "$status_file" "$status_tmp" "$SUPERVISOR_CONTROL_FILE" \
        "$control_tmp" "$release_file" "$release_tmp"
      return 75
    fi
    sleep "$WATCH_INTERVAL_SECONDS"
    [[ ! -f "$status_file" ]] || break
    if ! kill -0 "$wrapper_pid" 2>/dev/null; then
      printf 'error: stopping Cargo command after its launcher was interrupted\n' >&2
      stop_supervised_command
      rm -f -- "$status_file" "$status_tmp" "$SUPERVISOR_CONTROL_FILE" \
        "$control_tmp" "$release_file" "$release_tmp"
      return 75
    fi
    guard_status=0
    disk_guard || guard_status=$?
    if (( guard_status != 0 )); then
      printf 'error: stopping Cargo command before it can exhaust the disk\n' >&2
      stop_supervised_command
      rm -f -- "$status_file" "$status_tmp" "$SUPERVISOR_CONTROL_FILE" \
        "$control_tmp" "$release_file" "$release_tmp"
      return "$guard_status"
    fi
  done

  if wait "$command_pid"; then
    command_wait_status=0
  else
    command_wait_status=$?
  fi
  SUPERVISED_COMMAND_PID=""
  if [[ -f "$status_file" ]]; then
    read -r command_status < "$status_file" || command_status=""
  else
    command_status="$command_wait_status"
  fi
  if [[ ! "$command_status" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
    printf 'error: Cargo command did not publish a valid status\n' >&2
    command_status=75
  fi
  rm -f -- "$status_file" "$status_tmp"

  if process_group_alive "$command_pgid"; then
    printf 'stopping surviving Cargo-command descendants\n' >&2
  fi
  SUPERVISED_COMMAND_PGID="$command_pgid"
  stop_supervised_command || stop_status=$?
  rm -f -- "$SUPERVISOR_CONTROL_FILE" "$control_tmp" "$release_file" "$release_tmp"
  (( stop_status == 0 )) || return "$stop_status"
  disk_guard || return $?
  return "$command_status"
}

stop_dev_supervisor() {
  local pid="${DEV_SUPERVISOR_PID:-}"
  local status=0
  [[ -n "$pid" ]] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || status=$?
  recover_supervisor_command "$$" "$pid" || status=$?
  DEV_SUPERVISOR_PID=""
  return "$status"
}

launcher_signal() {
  local status="$1"
  trap '' HUP INT TERM
  stop_dev_supervisor || true
  exit "$status"
}

run_supervised() {
  local wrapper_pid="$$" supervisor_pid supervisor_status=0
  disk_guard || return $?
  SUPERVISOR_CONTROL_FILE="$TARGET_DIR/.cargo-command-control.$wrapper_pid"
  trap 'stop_dev_supervisor' EXIT
  trap 'launcher_signal 129' HUP
  trap 'launcher_signal 130' INT
  trap 'launcher_signal 143' TERM
  (
    supervise_command "$wrapper_pid" "$@"
  ) &
  DEV_SUPERVISOR_PID=$!
  supervisor_pid="$DEV_SUPERVISOR_PID"
  if wait "$supervisor_pid"; then
    supervisor_status=0
  else
    supervisor_status=$?
  fi
  if (( supervisor_status != 0 )) && [[ -e "$SUPERVISOR_CONTROL_FILE" ]]; then
    recover_supervisor_command "$wrapper_pid" "$supervisor_pid" \
      || supervisor_status=$?
  fi
  DEV_SUPERVISOR_PID=""
  trap - EXIT HUP INT TERM
  return "$supervisor_status"
}

usage() {
  printf 'usage: %s {status|clean|run-api|run-portal}\n' "${0##*/}" >&2
  exit 64
}

(( $# == 1 )) || usage
action="$1"
case "$action" in
  status|clean|run-api|run-portal) ;;
  *) usage ;;
esac

prepare_paths "$action"
cd "$ROOT_DIR"

case "$action" in
  status)
    printf 'development Cargo target: %s\n' "$TARGET_DIR"
    if [[ "$TARGET_PRESENT" == "1" ]]; then
      du -sh "$TARGET_DIR"
      printf 'allocated/apparent KiB: %s\n' "$(measure_tree_kib "$TARGET_DIR")"
    else
      printf 'development target: absent\n'
    fi
    df -h "$ROOT_PARENT" | tail -1
    ;;
  clean)
    sanitize_cargo_environment
    cargo clean
    ;;
  run-api)
    sanitize_cargo_environment
    export RYUKI_MIGRATION_MODE=local-auto
    run_supervised cargo run --manifest-path "$ROOT_DIR/sources/ryuki-api/Cargo.toml"
    ;;
  run-portal)
    sanitize_cargo_environment
    export LEPTOS_SITE_ROOT="$SITE_ROOT"
    run_supervised cargo leptos serve --manifest-path "$ROOT_DIR/portal/portal-ui/Cargo.toml"
    ;;
esac
