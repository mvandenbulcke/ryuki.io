#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_AGENT="$ROOT_DIR/deploy/proving-ground/run-agent.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-pg-build-regression.XXXXXX")"
STATE_BASE="$WORK_DIR/state"
OUTPUT_FILE="$WORK_DIR/output"
OUTSIDE_DIR="$WORK_DIR/outside"
FAKE_CARGO="$WORK_DIR/fake-cargo"
FAKE_NESTED_CARGO="$WORK_DIR/fake-nested-cargo"
FAKE_CHILD_PID_FILE="$WORK_DIR/fake-cargo-child.pid"
FAKE_HOLD_PID_FILE="$WORK_DIR/fake-cargo-hold-child.hold.pid"
FAKE_SUPERVISOR_KILL_PID_FILE="$WORK_DIR/fake-supervisor-kill-child.hold.pid"
FAKE_NESTED_PID_FILE="$WORK_DIR/fake-cargo-nested-child.pid"
SIGKILL_OUTPUT="$WORK_DIR/sigkill-output"
SUPERVISOR_KILL_OUTPUT="$WORK_DIR/supervisor-kill-output"
RUN_AGENT_PID=""
NESTED_PID=""
RECOVERY_PGID=""

cleanup() {
  if [[ -n "$RUN_AGENT_PID" ]] && kill -0 "$RUN_AGENT_PID" 2>/dev/null; then
    kill -KILL "$RUN_AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n "$NESTED_PID" ]] && kill -0 "$NESTED_PID" 2>/dev/null; then
    kill -KILL -- "-$NESTED_PID" 2>/dev/null || kill -KILL "$NESTED_PID" 2>/dev/null || true
  fi
  if [[ -n "$RECOVERY_PGID" ]] && kill -0 -- "-$RECOVERY_PGID" 2>/dev/null; then
    kill -KILL -- "-$RECOVERY_PGID" 2>/dev/null || true
  fi
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

fail() {
  printf 'proving-ground build cleanup regression failed: %s\n' "$*" >&2
  if [[ -s "$OUTPUT_FILE" ]]; then
    sed 's/^/  | /' "$OUTPUT_FILE" >&2
  fi
  exit 1
}

wait_for_file() {
  local path="$1"
  local attempt
  for attempt in {1..100}; do
    [[ -f "$path" ]] && return 0
    sleep 0.05
  done
  return 1
}

wait_for_exit() {
  local pid="$1"
  local attempt
  for attempt in {1..100}; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.05
  done
  return 1
}

mkdir -m 700 "$STATE_BASE" "$OUTSIDE_DIR"
STATE_BASE="$(cd "$STATE_BASE" && pwd -P)"
REPOSITORY_ID="$(printf '%s' "$ROOT_DIR" | shasum -a 256 | awk '{print $1}')"
[[ "$REPOSITORY_ID" =~ ^[0-9a-f]{64}$ ]] || fail "could not derive repository id"
TARGET_ROOT="$STATE_BASE/ryuki-proving-ground-build-$(id -u)/$REPOSITORY_ID"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -Eeuo pipefail'
  printf '%s\n' 'build_root="${1:?build root required}"'
  printf '%s\n' 'child_pid_file="${2:?child pid file required}"'
  printf '%s\n' 'if [[ -e /dev/fd/9 || -e /proc/self/fd/9 ]]; then'
  printf '%s\n' '  touch "${child_pid_file}.fd9-open"'
  printf '%s\n' '  exit 97'
  printf '%s\n' 'fi'
  printf '%s\n' 'touch "${child_pid_file}.fd9-closed"'
  printf '%s\n' '('
  printf '%s\n' '  trap "exit 0" HUP INT TERM'
  printf '%s\n' '  dd if=/dev/zero of="$build_root/detached-build-output" bs=1 count=0 seek=1048576 2>/dev/null'
  printf '%s\n' '  while :; do sleep 1; done'
  printf '%s\n' ') &'
  printf '%s\n' 'child_pid="$!"'
  printf '%s\n' 'printf "%s\n" "$child_pid" > "$child_pid_file"'
  printf '%s\n' 'case "$child_pid_file" in'
  printf '%s\n' '  *.hold.pid) wait "$child_pid" ;;'
  printf '%s\n' '  *) exit 0 ;;'
  printf '%s\n' 'esac'
} > "$FAKE_CARGO"
chmod 700 "$FAKE_CARGO"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -Eeuo pipefail'
  printf '%s\n' 'build_root="${1:?build root required}"'
  printf '%s\n' 'nested_pid_file="${2:?nested pid file required}"'
  printf '%s\n' 'if [[ -e /dev/fd/9 || -e /proc/self/fd/9 ]]; then'
  printf '%s\n' '  touch "${nested_pid_file}.fd9-open"'
  printf '%s\n' '  exit 97'
  printf '%s\n' 'fi'
  printf '%s\n' 'touch "${nested_pid_file}.fd9-closed"'
  printf '%s\n' 'set -m'
  printf '%s\n' '('
  printf '%s\n' '  trap "" HUP INT TERM'
  printf '%s\n' '  dd if=/dev/zero of="$build_root/nested-build-output" bs=1 count=0 seek=1048576 2>/dev/null'
  printf '%s\n' '  while :; do sleep 1; done'
  printf '%s\n' ') &'
  printf '%s\n' 'nested_pid="$!"'
  printf '%s\n' 'set +m'
  printf '%s\n' 'printf "%s\n" "$nested_pid" > "$nested_pid_file"'
  printf '%s\n' 'shutdown_nested() {'
  printf '%s\n' '  trap - HUP INT TERM'
  printf '%s\n' '  kill -TERM -- "-$nested_pid" 2>/dev/null || true'
  printf '%s\n' '  for _ in {1..25}; do sleep 0.1; done'
  printf '%s\n' '  kill -KILL -- "-$nested_pid" 2>/dev/null || true'
  printf '%s\n' '  wait "$nested_pid" 2>/dev/null || true'
  printf '%s\n' '  exit 0'
  printf '%s\n' '}'
  printf '%s\n' 'trap shutdown_nested HUP INT TERM'
  printf '%s\n' 'while :; do sleep 1; done'
} > "$FAKE_NESTED_CARGO"
chmod 700 "$FAKE_NESTED_CARGO"

run_preflight() {
  RYUKI_PG_ENV_ISOLATED=1 \
    RYUKI_PG_BUILD_TEST_MODE=1 \
    RYUKI_PG_BUILD_PREFLIGHT_ONLY=1 \
    RYUKI_PG_BUILD_TEST_STATE_BASE="$STATE_BASE" \
    "$RUN_AGENT"
}

write_sentinel() {
  local destination="$1"
  local run_id="$2"
  local repository_id="${3:-$REPOSITORY_ID}"
  printf '%s\n' \
    'version=1' \
    "repository_id=$repository_id" \
    "run_id=$run_id" \
    "workspace=$ROOT_DIR" \
    'disposition=disposable' > "$destination"
}

run_preflight > "$OUTPUT_FILE" 2>&1 || fail "initial preflight failed"
[[ -d "$TARGET_ROOT" && ! -L "$TARGET_ROOT" ]] || \
  fail "preflight did not create a private external target root"
case "$TARGET_ROOT/" in
  "$ROOT_DIR/"*) fail "preflight placed its target inside the checkout" ;;
esac

if RYUKI_PG_ENV_ISOLATED=1 \
  RYUKI_PG_BUILD_TEST_MODE=1 \
  RYUKI_PG_BUILD_PREFLIGHT_ONLY=1 \
  RYUKI_PG_BUILD_TEST_STATE_BASE="$STATE_BASE" \
  RYUKI_PG_BUILD_TEST_MAX_KIB=64 \
  RYUKI_PG_BUILD_TEST_COMMAND="$FAKE_CARGO" \
  RYUKI_PG_BUILD_TEST_CONTROL_FILE="$FAKE_CHILD_PID_FILE" \
  "$RUN_AGENT" > "$OUTPUT_FILE" 2>&1; then
  fail "supervised fake Cargo growth was accepted"
fi
grep -q 'proving-ground builds exceed the 12 GiB aggregate ceiling' "$OUTPUT_FILE" || \
  fail "live aggregate ceiling trip was not reported"
grep -q 'stopping proving-ground Cargo build before it can exhaust the disk' \
  "$OUTPUT_FILE" || fail "fake Cargo process-group stop was not reported"
[[ -e "${FAKE_CHILD_PID_FILE}.fd9-closed" && \
  ! -e "${FAKE_CHILD_PID_FILE}.fd9-open" ]] || \
  fail "fake Cargo inherited the proving-ground build lock descriptor"
[[ -f "$FAKE_CHILD_PID_FILE" ]] || fail "fake Cargo did not report its detached child"
read -r fake_child_pid < "$FAKE_CHILD_PID_FILE"
[[ "$fake_child_pid" =~ ^[0-9]+$ ]] || fail "fake Cargo reported an invalid child pid"
for _ in {1..100}; do
  kill -0 "$fake_child_pid" 2>/dev/null || break
  sleep 0.05
done
if kill -0 "$fake_child_pid" 2>/dev/null; then
  fail "supervisor left a detached fake Cargo child running"
fi
if [[ -n "$(find "$TARGET_ROOT" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit)" ]]; then
  fail "aggregate trip left a disposable build root"
fi

if RYUKI_PG_ENV_ISOLATED=1 \
  RYUKI_PG_BUILD_TEST_MODE=1 \
  RYUKI_PG_BUILD_PREFLIGHT_ONLY=1 \
  RYUKI_PG_BUILD_TEST_STATE_BASE="$STATE_BASE" \
  RYUKI_PG_BUILD_TEST_MAX_KIB=64 \
  RYUKI_PG_BUILD_TEST_COMMAND="$FAKE_NESTED_CARGO" \
  RYUKI_PG_BUILD_TEST_CONTROL_FILE="$FAKE_NESTED_PID_FILE" \
  "$RUN_AGENT" > "$OUTPUT_FILE" 2>&1; then
  fail "nested process-group growth was accepted"
fi
[[ -f "$FAKE_NESTED_PID_FILE" ]] || fail "nested fake Cargo did not report its child"
[[ -e "${FAKE_NESTED_PID_FILE}.fd9-closed" && \
  ! -e "${FAKE_NESTED_PID_FILE}.fd9-open" ]] || \
  fail "nested fake Cargo inherited the proving-ground build lock descriptor"
read -r NESTED_PID < "$FAKE_NESTED_PID_FILE"
[[ "$NESTED_PID" =~ ^[0-9]+$ ]] || fail "nested fake Cargo reported an invalid pid"
wait_for_exit "$NESTED_PID" || \
  fail "outer supervisor killed the nested guard before it reaped its compiler group"
NESTED_PID=""
grep -q 'stopping proving-ground Cargo build before it can exhaust the disk' \
  "$OUTPUT_FILE" || fail "nested aggregate trip was not reported"

rm -f "$FAKE_HOLD_PID_FILE"
RYUKI_PG_ENV_ISOLATED=1 \
  RYUKI_PG_BUILD_TEST_MODE=1 \
  RYUKI_PG_BUILD_PREFLIGHT_ONLY=1 \
  RYUKI_PG_BUILD_TEST_STATE_BASE="$STATE_BASE" \
  RYUKI_PG_BUILD_TEST_COMMAND="$FAKE_CARGO" \
  RYUKI_PG_BUILD_TEST_CONTROL_FILE="$FAKE_HOLD_PID_FILE" \
  "$RUN_AGENT" > "$SIGKILL_OUTPUT" 2>&1 &
RUN_AGENT_PID=$!
wait_for_file "$FAKE_HOLD_PID_FILE" || fail "SIGKILL fixture did not start fake Cargo"
[[ -e "${FAKE_HOLD_PID_FILE}.fd9-closed" && \
  ! -e "${FAKE_HOLD_PID_FILE}.fd9-open" ]] || \
  fail "SIGKILL fake Cargo inherited the proving-ground build lock descriptor"
read -r fake_child_pid < "$FAKE_HOLD_PID_FILE"
[[ "$fake_child_pid" =~ ^[0-9]+$ ]] || fail "SIGKILL fixture reported an invalid child pid"
kill -KILL "$RUN_AGENT_PID"
wait "$RUN_AGENT_PID" 2>/dev/null || true
RUN_AGENT_PID=""
wait_for_exit "$fake_child_pid" || \
  fail "orphan supervisor did not stop fake Cargo after runner SIGKILL"
grep -q 'stopping proving-ground Cargo build after its runner was interrupted' \
  "$SIGKILL_OUTPUT" || fail "runner SIGKILL shutdown was not reported"
for _ in {1..50}; do
  if run_preflight > "$OUTPUT_FILE" 2>&1; then
    break
  fi
  sleep 0.1
done
run_preflight > "$OUTPUT_FILE" 2>&1 || fail "SIGKILL build root was not reclaimable"
if [[ -n "$(find "$TARGET_ROOT" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit)" ]]; then
  fail "runner SIGKILL left an unreclaimed disposable build root"
fi

rm -f "$FAKE_SUPERVISOR_KILL_PID_FILE"
RYUKI_PG_ENV_ISOLATED=1 \
  RYUKI_PG_BUILD_TEST_MODE=1 \
  RYUKI_PG_BUILD_PREFLIGHT_ONLY=1 \
  RYUKI_PG_BUILD_TEST_STATE_BASE="$STATE_BASE" \
  RYUKI_PG_BUILD_TEST_COMMAND="$FAKE_CARGO" \
  RYUKI_PG_BUILD_TEST_CONTROL_FILE="$FAKE_SUPERVISOR_KILL_PID_FILE" \
  "$RUN_AGENT" > "$SUPERVISOR_KILL_OUTPUT" 2>&1 &
RUN_AGENT_PID=$!
wait_for_file "$FAKE_SUPERVISOR_KILL_PID_FILE" || \
  fail "supervisor SIGKILL fixture did not start fake Cargo"
read -r fake_child_pid < "$FAKE_SUPERVISOR_KILL_PID_FILE"
[[ "$fake_child_pid" =~ ^[0-9]+$ ]] || \
  fail "supervisor SIGKILL fixture reported an invalid child pid"
command_control_file="$(find "$TARGET_ROOT" -mindepth 2 -maxdepth 2 \
  -name '.ryuki-proving-ground-command-owner' -print -quit)"
[[ -n "$command_control_file" && -f "$command_control_file" && \
  ! -L "$command_control_file" ]] || fail "supervisor command ownership was not published"
supervisor_pid="$(sed -n 's/^supervisor_pid=//p' "$command_control_file")"
RECOVERY_PGID="$(sed -n 's/^command_pgid=//p' "$command_control_file")"
[[ "$supervisor_pid" =~ ^[1-9][0-9]+$ && \
  "$RECOVERY_PGID" =~ ^[1-9][0-9]+$ && \
  "$supervisor_pid" != "$RUN_AGENT_PID" ]] || \
  fail "published supervisor command ownership was invalid"
kill -KILL "$supervisor_pid"
wait_for_exit "$RUN_AGENT_PID" || fail "run-agent did not recover a killed supervisor"
wait "$RUN_AGENT_PID" 2>/dev/null || true
RUN_AGENT_PID=""
wait_for_exit "$fake_child_pid" || \
  fail "parent did not stop fake Cargo after supervisor SIGKILL"
if kill -0 -- "-$RECOVERY_PGID" 2>/dev/null; then
  fail "Cargo process group survived supervisor SIGKILL recovery"
fi
RECOVERY_PGID=""
grep -q 'recovering proving-ground Cargo process group after supervisor exit' \
  "$SUPERVISOR_KILL_OUTPUT" || fail "supervisor SIGKILL recovery was not reported"
run_preflight > "$OUTPUT_FILE" 2>&1 || \
  fail "supervisor SIGKILL did not release the build lock"
if [[ -n "$(find "$TARGET_ROOT" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit)" ]]; then
  fail "supervisor SIGKILL left an unreclaimed disposable build root"
fi

if RYUKI_PG_ENV_ISOLATED=1 \
  RYUKI_PG_BUILD_TEST_MODE=1 \
  RYUKI_PG_BUILD_PREFLIGHT_ONLY=1 \
  RYUKI_PG_BUILD_TEST_STATE_BASE="$STATE_BASE" \
  RYUKI_PG_BUILD_TEST_MAX_KIB=12582913 \
  "$RUN_AGENT" > "$OUTPUT_FILE" 2>&1; then
  fail "build test controls increased the production ceiling"
fi
grep -q 'cannot weaken the production build ceiling' "$OUTPUT_FILE" || \
  fail "weakened test ceiling refusal was not reported"

mkdir -m 700 "$TARGET_ROOT/run.stale"
write_sentinel "$TARGET_ROOT/run.stale/.ryuki-proving-ground-build-owner" stale
touch "$TARGET_ROOT/run.stale/interrupted-build-object"
run_preflight > "$OUTPUT_FILE" 2>&1 || fail "valid stale build reclamation failed"
[[ ! -e "$TARGET_ROOT/run.stale" ]] || fail "valid stale build was not removed"
grep -q 'removing stale proving-ground build from interrupted run' "$OUTPUT_FILE" || \
  fail "valid stale build removal was not reported"

mkdir -m 700 "$TARGET_ROOT/run.setup"
write_sentinel "$TARGET_ROOT/.run.setup.owner.tmp" setup
run_preflight > "$OUTPUT_FILE" 2>&1 || fail "interrupted setup reclamation failed"
[[ ! -e "$TARGET_ROOT/run.setup" && ! -e "$TARGET_ROOT/.run.setup.owner.tmp" ]] || \
  fail "interrupted marker publication was not reclaimed"

mkdir -m 700 "$TARGET_ROOT/run.deleting"
touch "$TARGET_ROOT/run.deleting/partial-build-object"
write_sentinel "$TARGET_ROOT/.run.deleting.delete.owner" deleting
run_preflight > "$OUTPUT_FILE" 2>&1 || fail "interrupted deletion reclamation failed"
[[ ! -e "$TARGET_ROOT/run.deleting" && \
  ! -e "$TARGET_ROOT/.run.deleting.delete.owner" ]] || \
  fail "interrupted recursive deletion was not reclaimed"

mkdir -m 700 "$TARGET_ROOT/run.unmarked"
touch "$TARGET_ROOT/run.unmarked/payload"
if run_preflight > "$OUTPUT_FILE" 2>&1; then
  fail "unmarked build directory was accepted"
fi
grep -q 'refusing unmarked or malformed proving-ground build entry' "$OUTPUT_FILE" || \
  fail "unmarked build refusal was not reported"
[[ -e "$TARGET_ROOT/run.unmarked/payload" ]] || \
  fail "unmarked build directory was modified"
rm -rf -- "$TARGET_ROOT/run.unmarked"

mkdir -m 700 "$TARGET_ROOT/run.malformed"
write_sentinel "$TARGET_ROOT/run.malformed/.ryuki-proving-ground-build-owner" \
  malformed "$(printf '%064d' 0)"
touch "$TARGET_ROOT/run.malformed/payload"
if run_preflight > "$OUTPUT_FILE" 2>&1; then
  fail "malformed ownership sentinel was accepted"
fi
grep -q 'refusing unmarked or malformed proving-ground build entry' "$OUTPUT_FILE" || \
  fail "malformed ownership refusal was not reported"
[[ -e "$TARGET_ROOT/run.malformed/payload" ]] || \
  fail "malformed build directory was modified"
rm -rf -- "$TARGET_ROOT/run.malformed"

touch "$OUTSIDE_DIR/payload"
ln -s "$OUTSIDE_DIR" "$TARGET_ROOT/run.symlink"
if run_preflight > "$OUTPUT_FILE" 2>&1; then
  fail "symlinked build directory was accepted"
fi
grep -q 'refusing malformed proving-ground build entry' "$OUTPUT_FILE" || \
  fail "symlinked build refusal was not reported"
[[ -e "$OUTSIDE_DIR/payload" ]] || fail "symlink target was modified"
rm "$TARGET_ROOT/run.symlink"

if RYUKI_PG_ENV_ISOLATED=1 \
  RYUKI_PG_BUILD_TEST_MODE=1 \
  RYUKI_PG_BUILD_PREFLIGHT_ONLY=1 \
  RYUKI_PG_BUILD_TEST_STATE_BASE="$ROOT_DIR" \
  "$RUN_AGENT" > "$OUTPUT_FILE" 2>&1; then
  fail "checkout-local build state base was accepted"
fi
grep -q 'proving-ground build state must be outside the checkout' "$OUTPUT_FILE" || \
  fail "checkout-local state refusal was not reported"

printf 'proving-ground build cleanup regression passed\n'
