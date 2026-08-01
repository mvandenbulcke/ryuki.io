#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
LAUNCHER="$ROOT_DIR/scripts/cargo-dev-guard.sh"
FIXTURE="$ROOT_DIR/scripts/regressions/fixtures/cargo-dev-fake-cargo.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-cargo-dev-guard.XXXXXX")"
FAKE_BIN="$WORK_DIR/bin"
FAKE_CARGO="$FAKE_BIN/cargo"
TARGET="$WORK_DIR/.ryuki-target-ryuki.io"
SITE_ROOT="$TARGET/leptos-site"
CAPTURE="$WORK_DIR/cargo-env"
OUTPUT="$WORK_DIR/output"
READY="$WORK_DIR/ready"
PID_FILE="$WORK_DIR/cargo.pid"
LAUNCHER_PID=""
SUPERVISOR_PID=""

cleanup() {
  local pid=""
  for pid in "${SUPERVISOR_PID:-}" "${LAUNCHER_PID:-}"; do
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  done
  if [[ -f "$PID_FILE" ]]; then
    pid="$(sed -n '1p' "$PID_FILE")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

fail() {
  printf 'cargo-dev-guard regression failed: %s\n' "$1" >&2
  if [[ -s "$OUTPUT" ]]; then
    sed 's/^/  | /' "$OUTPUT" >&2
  fi
  exit 1
}

wait_for_file() {
  local path="$1"
  local attempt
  for attempt in {1..200}; do
    [[ -e "$path" ]] && return 0
    sleep 0.05
  done
  return 1
}

wait_for_exit() {
  local pid="$1"
  local attempt
  for attempt in {1..200}; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.05
  done
  return 1
}

wait_for_absence() {
  local path="$1"
  local attempt
  for attempt in {1..200}; do
    [[ ! -e "$path" && ! -L "$path" ]] && return 0
    sleep 0.05
  done
  return 1
}

mkdir -p "$FAKE_BIN"
cp "$FIXTURE" "$FAKE_CARGO"
chmod 700 "$FAKE_CARGO"

STATUS_PARENT="$WORK_DIR/status"
STATUS_TARGET="$STATUS_PARENT/.ryuki-target-ryuki.io"
mkdir -p "$STATUS_PARENT"
PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$STATUS_TARGET" \
  "$LAUNCHER" status > "$OUTPUT" 2>&1 \
  || fail "status rejected an absent dedicated target"
[[ ! -e "$STATUS_TARGET" ]] || fail "status created an absent Cargo target"

UNMARKED_PARENT="$WORK_DIR/unmarked"
UNMARKED_TARGET="$UNMARKED_PARENT/.ryuki-target-ryuki.io"
mkdir -p "$UNMARKED_TARGET"
printf 'preserve\n' > "$UNMARKED_TARGET/user-data"
if PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$UNMARKED_TARGET" \
  "$LAUNCHER" run-api > "$OUTPUT" 2>&1; then
  fail "non-empty unmarked dedicated target was adopted"
fi
grep -q 'missing its ownership sentinel' "$OUTPUT" \
  || fail "unmarked target refusal was not reported"
grep -Fxq 'preserve' "$UNMARKED_TARGET/user-data" \
  || fail "unmarked target contents were modified"

PATH="$FAKE_BIN:$PATH" \
  RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" \
  RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  CARGO_TARGET_DIR="$ROOT_DIR" \
  CARGO_BUILD_TARGET_DIR="$ROOT_DIR" \
  CARGO_BUILD_BUILD_DIR="$ROOT_DIR" \
  RUSTC_WRAPPER= \
  RUSTC_WORKSPACE_WRAPPER="$WORK_DIR/hostile-workspace-wrapper" \
  CARGO_BUILD_RUSTC_WRAPPER="$WORK_DIR/hostile-config-wrapper" \
  CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER="$WORK_DIR/hostile-config-workspace-wrapper" \
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=999999999 \
  RYUKI_CARGO_MAX_TARGET_GIB=999 \
  RYUKI_CARGO_MIN_FREE_GIB=1 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=999 \
  "$LAUNCHER" run-api > "$OUTPUT" 2>&1 \
  || fail "safe fake-Cargo run was rejected"

TARGET_REAL="$(cd "$TARGET" && pwd -P)"
grep -Fxq "CARGO_TARGET_DIR=$TARGET_REAL" "$CAPTURE" \
  || fail "Cargo target was not pinned to the external cache"
grep -Fxq "CARGO_BUILD_BUILD_DIR=$TARGET_REAL/build-cache" "$CAPTURE" \
  || fail "Cargo build-dir was not pinned beneath the external target"
grep -Fxq "RUSTC_WRAPPER=$ROOT_DIR/scripts/cargo-rustc-disk-guard.sh" "$CAPTURE" \
  || fail "absolute repository rustc guard was not restored"
for cleared in CARGO_BUILD_TARGET_DIR RUSTC_WORKSPACE_WRAPPER \
  CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER \
  RYUKI_CARGO_GUARD_TEST_MODE RYUKI_CARGO_GUARD_TEST_MAX_KIB; do
  grep -Fxq "${cleared}=" "$CAPTURE" || fail "hostile $cleared survived sanitization"
done
grep -Fxq 'RYUKI_CARGO_MAX_TARGET_GIB=24' "$CAPTURE" \
  || fail "Cargo target hard ceiling was not pinned"
grep -Fxq 'RYUKI_CARGO_MIN_FREE_GIB=30' "$CAPTURE" \
  || fail "Cargo free-space floor was not pinned"
grep -Fxq 'RYUKI_CARGO_GUARD_INTERVAL_SECONDS=2' "$CAPTURE" \
  || fail "Cargo guard interval was not pinned"
grep -Fxq 'FD9=closed' "$CAPTURE" \
  || fail "fake Cargo inherited serialization descriptor 9"
grep -Fxq 'ARG=run' "$CAPTURE" || fail "run-api did not invoke Cargo run"
grep -Fxq "ARG=--manifest-path" "$CAPTURE" \
  || fail "run-api did not provide an explicit manifest"
grep -Fxq "ARG=$ROOT_DIR/sources/ryuki-api/Cargo.toml" "$CAPTURE" \
  || fail "run-api used the wrong manifest"

if PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$ROOT_DIR" \
  RYUKI_LEPTOS_SITE_ROOT="$ROOT_DIR/leptos-site" \
  RYUKI_DEV_TEST_CAPTURE="$CAPTURE" "$LAUNCHER" run-api > "$OUTPUT" 2>&1; then
  fail "checkout-local Cargo target was accepted"
fi
grep -q 'Cargo target path must be outside the repository checkout' "$OUTPUT" \
  || fail "checkout-local target refusal was not reported"

ln -s "$TARGET" "$WORK_DIR/.ryuki-target-link"
if PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$WORK_DIR/.ryuki-target-link" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  "$LAUNCHER" run-api > "$OUTPUT" 2>&1; then
  fail "symlinked Cargo target was accepted"
fi
grep -q 'Cargo target path must not be a symlink' "$OUTPUT" \
  || fail "symlinked target refusal was not reported"

if PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$WORK_DIR/arbitrary-cache" \
  RYUKI_LEPTOS_SITE_ROOT="$WORK_DIR/arbitrary-cache/site" \
  RYUKI_DEV_TEST_CAPTURE="$CAPTURE" "$LAUNCHER" run-api > "$OUTPUT" 2>&1; then
  fail "broad arbitrary Cargo cache path was accepted"
fi
grep -q 'dedicated .ryuki-target-ryuki.io cache basename' "$OUTPUT" \
  || fail "dedicated cache basename refusal was not reported"

if PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$WORK_DIR/site-escape" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  "$LAUNCHER" run-portal > "$OUTPUT" 2>&1; then
  fail "Leptos site escape was accepted"
fi
grep -q 'Leptos site path must remain inside the external Cargo target' "$OUTPUT" \
  || fail "Leptos site escape refusal was not reported"

if PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  "$LAUNCHER" run-api --config build.target-dir="$ROOT_DIR" > "$OUTPUT" 2>&1; then
  fail "custom Cargo config escape was accepted"
fi
grep -q '^usage:' "$OUTPUT" || fail "custom Cargo argument refusal was not reported"

rm -f "$READY" "$PID_FILE"
if PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  RYUKI_DEV_TEST_BEHAVIOR=grow RYUKI_DEV_TEST_READY="$READY" \
  RYUKI_DEV_TEST_PID="$PID_FILE" "$LAUNCHER" run-api > "$OUTPUT" 2>&1; then
  fail "runtime target growth above 24 GiB was accepted"
fi
wait_for_file "$PID_FILE" || fail "target grower did not publish its pid"
grower_pid="$(sed -n '1p' "$PID_FILE")"
wait_for_exit "$grower_pid" || fail "target grower survived the disk ceiling"
grep -q 'stopping Cargo command before it can exhaust the disk' "$OUTPUT" \
  || fail "runtime target growth stop was not reported"
rm -f "$TARGET/guard-growth.bin" "$READY" "$PID_FILE"

PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  RYUKI_DEV_TEST_BEHAVIOR=detach RYUKI_DEV_TEST_READY="$READY" \
  RYUKI_DEV_TEST_PID="$PID_FILE" "$LAUNCHER" run-api > "$OUTPUT" 2>&1 \
  || fail "detached-child fake Cargo run failed"
wait_for_file "$PID_FILE" || fail "detached child did not publish its pid"
detached_pid="$(sed -n '1p' "$PID_FILE")"
wait_for_exit "$detached_pid" || fail "detached Cargo child survived command exit"
grep -q 'stopping surviving Cargo-command descendants' "$OUTPUT" \
  || fail "detached Cargo child cleanup was not reported"

rm -f "$READY" "$PID_FILE"
PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  RYUKI_DEV_TEST_BEHAVIOR=hold RYUKI_DEV_TEST_READY="$READY" \
  RYUKI_DEV_TEST_PID="$PID_FILE" "$LAUNCHER" run-api > "$OUTPUT" 2>&1 &
LAUNCHER_PID=$!
LAUNCHER_CONTROL_FILE="$TARGET/.cargo-command-control.$LAUNCHER_PID"
wait_for_file "$PID_FILE" || fail "launcher-SIGKILL fake Cargo did not start"
hold_pid="$(sed -n '1p' "$PID_FILE")"
kill -KILL "$LAUNCHER_PID"
wait "$LAUNCHER_PID" 2>/dev/null || true
LAUNCHER_PID=""
wait_for_exit "$hold_pid" || fail "Cargo survived launcher SIGKILL"
wait_for_absence "$LAUNCHER_CONTROL_FILE" \
  || fail "orphan disk supervisor did not clear launcher ownership"
grep -q 'stopping Cargo command after its launcher was interrupted' "$OUTPUT" \
  || fail "launcher SIGKILL shutdown was not reported"

rm -f "$READY" "$PID_FILE"
PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  RYUKI_DEV_TEST_BEHAVIOR=hold RYUKI_DEV_TEST_READY="$READY" \
  RYUKI_DEV_TEST_PID="$PID_FILE" "$LAUNCHER" run-api > "$OUTPUT" 2>&1 &
LAUNCHER_PID=$!
wait_for_file "$PID_FILE" || fail "supervisor-SIGKILL fake Cargo did not start"
hold_pid="$(sed -n '1p' "$PID_FILE")"
CONTROL_FILE="$TARGET/.cargo-command-control.$LAUNCHER_PID"
wait_for_file "$CONTROL_FILE" || fail "Cargo supervisor control file was not published"
SUPERVISOR_PID="$(sed -n 's/^supervisor_pid=//p' "$CONTROL_FILE")"
[[ "$SUPERVISOR_PID" =~ ^[0-9]+$ ]] || fail "Cargo disk supervisor pid was not found"
kill -KILL "$SUPERVISOR_PID"
SUPERVISOR_PID=""
if wait "$LAUNCHER_PID" 2>/dev/null; then
  fail "launcher accepted a killed Cargo disk supervisor"
fi
LAUNCHER_PID=""
wait_for_exit "$hold_pid" || fail "Cargo survived disk supervisor SIGKILL"
grep -q 'stopping Cargo command after its disk supervisor exited' "$OUTPUT" \
  || fail "supervisor SIGKILL recovery was not reported"

PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  RYUKI_DEV_TEST_BEHAVIOR=clean-target "$LAUNCHER" clean > "$OUTPUT" 2>&1 \
  || fail "fake Cargo clean was rejected"
[[ ! -e "$TARGET" ]] || fail "fake Cargo clean did not remove the target root"
PATH="$FAKE_BIN:$PATH" RYUKI_DEV_TARGET_DIR="$TARGET" \
  RYUKI_LEPTOS_SITE_ROOT="$SITE_ROOT" RYUKI_DEV_TEST_CAPTURE="$CAPTURE" \
  "$LAUNCHER" run-api > "$OUTPUT" 2>&1 \
  || fail "launcher did not recreate an ownership sentinel after Cargo clean"
[[ -f "$TARGET/.ryuki-cargo-dev-owner" \
  && ! -L "$TARGET/.ryuki-cargo-dev-owner" ]] \
  || fail "recreated Cargo target lacks a safe ownership sentinel"

printf 'cargo dev guard regression passed\n'
