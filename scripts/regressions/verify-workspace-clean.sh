#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_SCRIPT="${ROOT_DIR}/scripts/verify-workspace-clean.sh"
SOURCE_GUARD="${ROOT_DIR}/scripts/cargo-rustc-disk-guard.sh"
BLOCKING_GATE_FIXTURE="${ROOT_DIR}/scripts/regressions/fixtures/verify-workspace-clean-blocking-gate.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-verify-regression.XXXXXX")"
FIXTURE_ROOT="${WORK_DIR}/repo"
STATE_BASE="${WORK_DIR}/state"
TMP_A="${WORK_DIR}/tmp-a"
TMP_B="${WORK_DIR}/tmp-b"
OUTPUT_FILE="${WORK_DIR}/output"
READY_FILE="${WORK_DIR}/ready"
RELEASE_FILE="${WORK_DIR}/release"
BLOCKER_PID_FILE="${WORK_DIR}/blocker.pid"
WRAPPER_PID=""
FAKE_BIN="${WORK_DIR}/bin"
FAKE_CARGO="${FAKE_BIN}/cargo"
CARGO_ENV_CAPTURE="${WORK_DIR}/cargo-env"

cleanup() {
  local blocker_pid=""
  if [[ -n "$WRAPPER_PID" ]] && kill -0 "$WRAPPER_PID" 2>/dev/null; then
    kill -KILL "$WRAPPER_PID" 2>/dev/null || true
  fi
  if [[ -f "$BLOCKER_PID_FILE" ]]; then
    blocker_pid="$(sed -n '1p' "$BLOCKER_PID_FILE")"
    if [[ "$blocker_pid" =~ ^[0-9]+$ ]] && kill -0 "$blocker_pid" 2>/dev/null; then
      kill -KILL "$blocker_pid" 2>/dev/null || true
    fi
  fi
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

fail() {
  echo "verify-workspace-clean regression failed: $*" >&2
  if [[ -s "$OUTPUT_FILE" ]]; then
    sed 's/^/  | /' "$OUTPUT_FILE" >&2
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

mkdir -p "${FIXTURE_ROOT}/scripts/regressions" "$STATE_BASE" "$TMP_A" "$TMP_B" "$FAKE_BIN"
FIXTURE_ROOT="$(cd "$FIXTURE_ROOT" && pwd -P)"
STATE_BASE="$(cd "$STATE_BASE" && pwd -P)"
cp "$SOURCE_SCRIPT" "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh"
chmod 700 "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh"
cp "$SOURCE_GUARD" "${FIXTURE_ROOT}/scripts/cargo-rustc-disk-guard.sh"
chmod 700 "${FIXTURE_ROOT}/scripts/cargo-rustc-disk-guard.sh"
git -C "$FIXTURE_ROOT" init -q

cp "$BLOCKING_GATE_FIXTURE" "${FIXTURE_ROOT}/scripts/regressions/verify-workspace-clean.sh"
chmod 700 "${FIXTURE_ROOT}/scripts/regressions/verify-workspace-clean.sh"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -Eeuo pipefail'
  printf '%s\n' ': "${RYUKI_VERIFY_TEST_CARGO_ENV:?missing capture path}"'
  printf '%s\n' '{'
  printf '%s\n' '  printf "CARGO_TARGET_DIR=%s\n" "${CARGO_TARGET_DIR-}"'
  printf '%s\n' '  printf "CARGO_BUILD_TARGET_DIR=%s\n" "${CARGO_BUILD_TARGET_DIR-}"'
  printf '%s\n' '  printf "RUSTC_WRAPPER=%s\n" "${RUSTC_WRAPPER-}"'
  printf '%s\n' '  printf "RUSTC_WORKSPACE_WRAPPER=%s\n" "${RUSTC_WORKSPACE_WRAPPER-}"'
  printf '%s\n' '  printf "CARGO_BUILD_RUSTC_WRAPPER=%s\n" "${CARGO_BUILD_RUSTC_WRAPPER-}"'
  printf '%s\n' '  printf "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=%s\n" "${CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER-}"'
  printf '%s\n' '  printf "RUSTFLAGS=%s\n" "${RUSTFLAGS-}"'
  printf '%s\n' '  printf "CARGO_ENCODED_RUSTFLAGS=%s\n" "${CARGO_ENCODED_RUSTFLAGS-}"'
  printf '%s\n' '  printf "CARGO_BUILD_RUSTFLAGS=%s\n" "${CARGO_BUILD_RUSTFLAGS-}"'
  printf '%s\n' '  printf "CARGO_BUILD_INCREMENTAL=%s\n" "${CARGO_BUILD_INCREMENTAL-}"'
  printf '%s\n' '  printf "CARGO_PROFILE_DEV_INCREMENTAL=%s\n" "${CARGO_PROFILE_DEV_INCREMENTAL-}"'
  printf '%s\n' '  printf "CARGO_PROFILE_TEST_INCREMENTAL=%s\n" "${CARGO_PROFILE_TEST_INCREMENTAL-}"'
  printf '%s\n' '  printf "CARGO_INCREMENTAL=%s\n" "${CARGO_INCREMENTAL-}"'
  printf '%s\n' '  printf "CARGO_PROFILE_DEV_DEBUG=%s\n" "${CARGO_PROFILE_DEV_DEBUG-}"'
  printf '%s\n' '  printf "CARGO_PROFILE_TEST_DEBUG=%s\n" "${CARGO_PROFILE_TEST_DEBUG-}"'
  printf '%s\n' '} > "$RYUKI_VERIFY_TEST_CARGO_ENV"'
} > "$FAKE_CARGO"
chmod 700 "$FAKE_CARGO"

GIT_COMMON_DIR="$(git -C "$FIXTURE_ROOT" rev-parse --path-format=absolute --git-common-dir)"
REPOSITORY_ID="$(printf '%s' "$GIT_COMMON_DIR" | git -C "$FIXTURE_ROOT" hash-object --stdin)"
VERIFY_NAMESPACE="${STATE_BASE}/ryuki-verify-$(id -u)"
VERIFY_TARGET_ROOT="${VERIFY_NAMESPACE}/${REPOSITORY_ID}"

run_preflight() {
  local tmp_dir="$1"
  TMPDIR="$tmp_dir" \
    RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
    RYUKI_VERIFY_TEST_MODE=1 \
    RYUKI_VERIFY_KEEP_TARGET=0 \
    RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
    "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh"
}

wait_for_preflight() {
  local tmp_dir="$1"
  local attempt
  for attempt in {1..200}; do
    if run_preflight "$tmp_dir" > "$OUTPUT_FILE" 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

create_managed_target() {
  local run_id="$1"
  local keep_target="$2"
  local target="${VERIFY_TARGET_ROOT}/run.${run_id}"
  mkdir -p "$target"
  {
    printf 'version=1\n'
    printf 'repository_id=%s\n' "$REPOSITORY_ID"
    printf 'run_id=%s\n' "$run_id"
    printf 'workspace=%s\n' "$FIXTURE_ROOT"
    printf 'keep_target=%s\n' "$keep_target"
  } > "${target}/.ryuki-verify-owner"
  touch "${target}/payload"
}

run_preflight "$TMP_A" > "$OUTPUT_FILE" 2>&1
if [[ -d "$VERIFY_TARGET_ROOT" \
  && -n "$(find "$VERIFY_TARGET_ROOT" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit)" ]]; then
  fail "normal preflight left a disposable target"
fi

if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  RYUKI_VERIFY_MAX_TARGET_GIB=65 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "verification accepted a target ceiling above the repository maximum"
fi
grep -q "RYUKI_VERIFY_MAX_TARGET_GIB must not exceed 64" "$OUTPUT_FILE" \
  || fail "oversized verification target ceiling refusal was not reported"

if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  RYUKI_VERIFY_MIN_FREE_GIB=29 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "verification accepted a free-space floor below the repository minimum"
fi
grep -q "RYUKI_VERIFY_MIN_FREE_GIB must not be less than 30" "$OUTPUT_FILE" \
  || fail "weakened verification free-space refusal was not reported"

if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  RYUKI_VERIFY_WATCH_INTERVAL_SECONDS=6 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "verification accepted a watcher interval above the repository maximum"
fi
grep -q "RYUKI_VERIFY_WATCH_INTERVAL_SECONDS must not exceed 5" "$OUTPUT_FILE" \
  || fail "weakened verification watcher refusal was not reported"

hostile_target="${WORK_DIR}/hostile-target"
PATH="${FAKE_BIN}:$PATH" \
  TMPDIR="$TMP_A" \
  RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 \
  RYUKI_VERIFY_KEEP_TARGET=0 \
  RYUKI_VERIFY_TEST_CARGO_ENV="$CARGO_ENV_CAPTURE" \
  CARGO_TARGET_DIR="$hostile_target" \
  CARGO_BUILD_TARGET_DIR="${hostile_target}-config" \
  RUSTC_WRAPPER="${WORK_DIR}/hostile-rustc-wrapper" \
  RUSTC_WORKSPACE_WRAPPER="${WORK_DIR}/hostile-workspace-wrapper" \
  CARGO_BUILD_RUSTC_WRAPPER="${WORK_DIR}/hostile-config-wrapper" \
  CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER="${WORK_DIR}/hostile-config-workspace-wrapper" \
  RUSTFLAGS='-Cdebuginfo=2' \
  CARGO_ENCODED_RUSTFLAGS='-Cdebuginfo=2' \
  CARGO_BUILD_RUSTFLAGS='-Cdebuginfo=2' \
  CARGO_BUILD_INCREMENTAL=true \
  CARGO_PROFILE_DEV_INCREMENTAL=true \
  CARGO_PROFILE_TEST_INCREMENTAL=true \
  CARGO_INCREMENTAL=1 \
  CARGO_PROFILE_DEV_DEBUG=2 \
  CARGO_PROFILE_TEST_DEBUG=2 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" -- cargo check \
  > "$OUTPUT_FILE" 2>&1 \
  || fail "focused verification failed while sanitizing inherited Cargo overrides"

captured_target="$(sed -n 's/^CARGO_TARGET_DIR=//p' "$CARGO_ENV_CAPTURE")"
case "$captured_target" in
  "${VERIFY_TARGET_ROOT}"/run.*/target) ;;
  *) fail "focused verification did not replace the inherited Cargo target" ;;
esac
grep -Fxq "RUSTC_WRAPPER=${FIXTURE_ROOT}/scripts/cargo-rustc-disk-guard.sh" \
  "$CARGO_ENV_CAPTURE" \
  || fail "focused verification did not install the absolute repository rustc guard"
for cleared in CARGO_BUILD_TARGET_DIR RUSTC_WORKSPACE_WRAPPER \
  CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER RUSTFLAGS \
  CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_BUILD_INCREMENTAL \
  CARGO_PROFILE_DEV_INCREMENTAL CARGO_PROFILE_TEST_INCREMENTAL; do
  grep -Fxq "${cleared}=" "$CARGO_ENV_CAPTURE" \
    || fail "focused verification retained inherited ${cleared}"
done
for pinned in CARGO_INCREMENTAL CARGO_PROFILE_DEV_DEBUG CARGO_PROFILE_TEST_DEBUG; do
  grep -Fxq "${pinned}=0" "$CARGO_ENV_CAPTURE" \
    || fail "focused verification did not pin ${pinned} to zero"
done
[[ ! -e "$hostile_target" && ! -e "${hostile_target}-config" ]] \
  || fail "focused verification wrote to an inherited Cargo target"

TMPDIR="$TMP_A" \
  RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 \
  RYUKI_VERIFY_KEEP_TARGET=0 \
  RYUKI_VERIFY_PREFLIGHT_ONLY=0 \
  RYUKI_VERIFY_WATCH_INTERVAL_SECONDS=1 \
  RYUKI_VERIFY_TEST_BLOCKER_PID="$BLOCKER_PID_FILE" \
  RYUKI_VERIFY_TEST_READY="$READY_FILE" \
  RYUKI_VERIFY_TEST_RELEASE="$RELEASE_FILE" \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" \
  > "$OUTPUT_FILE" 2>&1 &
WRAPPER_PID=$!
wait_for_file "$READY_FILE" || fail "blocking gate did not start"

if run_preflight "$TMP_B" > "$OUTPUT_FILE" 2>&1; then
  fail "concurrent verification was admitted"
fi
grep -q "verification is already running" "$OUTPUT_FILE" \
  || fail "concurrent verification did not report the repository lock"

kill -KILL "$WRAPPER_PID"
wait "$WRAPPER_PID" 2>/dev/null || true
WRAPPER_PID=""
blocker_pid="$(sed -n '1p' "$BLOCKER_PID_FILE")"
wait_for_exit "$blocker_pid" \
  || fail "supervisor did not stop the gate child after wrapper death"
rm -f "$BLOCKER_PID_FILE"
wait_for_preflight "$TMP_B" \
  || fail "repository lock was not released after supervised shutdown"
grep -q "removing stale verification target" "$OUTPUT_FILE" \
  || fail "interrupted target was not reported as reclaimed"
if [[ -d "$VERIFY_TARGET_ROOT" \
  && -n "$(find "$VERIFY_TARGET_ROOT" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit)" ]]; then
  fail "interrupted target was not reclaimed after the gate child exited"
fi

create_managed_target stale-one 0
create_managed_target stale-two 0
create_managed_target retained 1
run_preflight "$TMP_A" > "$OUTPUT_FILE" 2>&1
[[ ! -e "${VERIFY_TARGET_ROOT}/run.stale-one" \
  && ! -e "${VERIFY_TARGET_ROOT}/run.stale-two" \
  && -d "${VERIFY_TARGET_ROOT}/run.retained" ]] \
  || fail "multi-target reclamation or explicit retention failed"
grep -q "preserving explicitly retained verification target" "$OUTPUT_FILE" \
  || fail "retained target handling was not reported"

mkdir -p "${VERIFY_TARGET_ROOT}/run.interrupted-setup"
touch "${VERIFY_TARGET_ROOT}/.run.interrupted-setup.owner.tmp"
run_preflight "$TMP_B" > "$OUTPUT_FILE" 2>&1
[[ ! -e "${VERIFY_TARGET_ROOT}/run.interrupted-setup" \
  && ! -e "${VERIFY_TARGET_ROOT}/.run.interrupted-setup.owner.tmp" ]] \
  || fail "interrupted empty setup state was not reclaimed"

mkdir -p "${VERIFY_TARGET_ROOT}/run.unmarked"
touch "${VERIFY_TARGET_ROOT}/run.unmarked/payload"
if run_preflight "$TMP_B" > "$OUTPUT_FILE" 2>&1; then
  fail "non-empty unmarked target was accepted"
fi
grep -q "refusing non-empty unmarked verification target" "$OUTPUT_FILE" \
  || fail "non-empty unmarked target refusal was not reported"
[[ -e "${VERIFY_TARGET_ROOT}/run.unmarked/payload" ]] \
  || fail "non-empty unmarked target was modified"
rm -rf -- "${VERIFY_TARGET_ROOT}/run.unmarked"

unmanaged_target="${WORK_DIR}/unmanaged"
mkdir -p "$unmanaged_target"
ln -s "$unmanaged_target" "${VERIFY_TARGET_ROOT}/run.symlink"
if run_preflight "$TMP_A" > "$OUTPUT_FILE" 2>&1; then
  fail "symlinked target entry was accepted"
fi
grep -q "refusing malformed verification target entry" "$OUTPUT_FILE" \
  || fail "symlinked target refusal was not reported"
[[ -d "$unmanaged_target" ]] || fail "symlink target was modified"
rm "${VERIFY_TARGET_ROOT}/run.symlink"

ln -s "${WORK_DIR}/missing" "${VERIFY_TARGET_ROOT}/run.dangling-symlink"
if run_preflight "$TMP_B" > "$OUTPUT_FILE" 2>&1; then
  fail "dangling symlink target entry was accepted"
fi
grep -q "refusing malformed verification target entry" "$OUTPUT_FILE" \
  || fail "dangling symlink target refusal was not reported"
rm "${VERIFY_TARGET_ROOT}/run.dangling-symlink"

if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 \
  RYUKI_VERIFY_KEEP_TARGET=2 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "invalid keep-target value was accepted"
fi
grep -q "RYUKI_VERIFY_KEEP_TARGET must be 0 or 1" "$OUTPUT_FILE" \
  || fail "invalid keep-target value was not reported"

unmanaged_target="${WORK_DIR}/unmanaged-cargo-target"
if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_KEEP_TARGET=0 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" \
  -- cargo test --target-dir "$unmanaged_target" > "$OUTPUT_FILE" 2>&1; then
  fail "focused verification accepted a Cargo target override"
fi
grep -q "forbids overriding CARGO_TARGET_DIR" "$OUTPUT_FILE" \
  || fail "focused target override refusal was not reported"
[[ ! -e "$unmanaged_target" ]] \
  || fail "focused target override created an unmanaged target"

if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_KEEP_TARGET=0 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" \
  -- env CARGO_TARGET_DIR="$unmanaged_target" cargo test > "$OUTPUT_FILE" 2>&1; then
  fail "focused verification accepted an environment wrapper"
fi
grep -q "accepts only a direct cargo command" "$OUTPUT_FILE" \
  || fail "focused environment-wrapper refusal was not reported"
[[ ! -e "$unmanaged_target" ]] \
  || fail "focused environment wrapper created an unmanaged target"

if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_KEEP_TARGET=0 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" \
  -- cargo test --config=build.target-dir="$unmanaged_target" \
  > "$OUTPUT_FILE" 2>&1; then
  fail "focused verification accepted target-dir Cargo configuration"
fi
grep -q "forbids Cargo --config overrides" "$OUTPUT_FILE" \
  || fail "focused Cargo configuration refusal was not reported"
[[ ! -e "$unmanaged_target" ]] \
  || fail "focused Cargo configuration created an unmanaged target"

config_override="${WORK_DIR}/cargo-config.toml"
printf '[build]\ntarget-dir = "%s"\n' "$unmanaged_target" > "$config_override"
if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_KEEP_TARGET=0 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" \
  -- cargo test --config "$config_override" > "$OUTPUT_FILE" 2>&1; then
  fail "focused verification accepted a Cargo configuration file"
fi
grep -q "forbids Cargo --config overrides" "$OUTPUT_FILE" \
  || fail "focused Cargo configuration-file refusal was not reported"
[[ ! -e "$unmanaged_target" ]] \
  || fail "focused Cargo configuration file created an unmanaged target"

if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_KEEP_TARGET=0 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" \
  -- cargo untrusted-plugin > "$OUTPUT_FILE" 2>&1; then
  fail "focused verification accepted an unapproved Cargo subcommand"
fi
grep -q "accepts only cargo build, check, clippy, or test" "$OUTPUT_FILE" \
  || fail "focused Cargo subcommand refusal was not reported"

echo "verify-workspace-clean regression passed"
