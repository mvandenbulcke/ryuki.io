#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SOURCE_SCRIPT="${ROOT_DIR}/scripts/verify-workspace-clean.sh"
SOURCE_GUARD="${ROOT_DIR}/scripts/cargo-rustc-disk-guard.sh"
SOURCE_CARGO_CONFIG="${ROOT_DIR}/.cargo/config.toml"
SOURCE_TARGET_BLOCKER="${ROOT_DIR}/target"
SOURCE_DEBUG_BLOCKER="${ROOT_DIR}/debug"
BLOCKING_GATE_FIXTURE="${ROOT_DIR}/scripts/regressions/fixtures/verify-workspace-clean-blocking-gate.sh"
DETACHED_CARGO_FIXTURE="${ROOT_DIR}/scripts/regressions/fixtures/verify-workspace-clean-detached-cargo.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-verify-regression.XXXXXX")"
FIXTURE_ROOT="${WORK_DIR}/checkout/repo"
STATE_BASE="${WORK_DIR}/state"
TMP_A="${WORK_DIR}/tmp-a"
TMP_B="${WORK_DIR}/tmp-b"
OUTPUT_FILE="${WORK_DIR}/output"
READY_FILE="${WORK_DIR}/ready"
RELEASE_FILE="${WORK_DIR}/release"
BLOCKER_PID_FILE="${WORK_DIR}/blocker.pid"
WRAPPER_PID=""
SUPERVISOR_PID=""
SUPERVISOR_KILL_OUTPUT="${WORK_DIR}/supervisor-kill-output"
FAKE_BIN="${WORK_DIR}/bin"
FAKE_CARGO="${FAKE_BIN}/cargo"
CARGO_ENV_CAPTURE="${WORK_DIR}/cargo-env"
OUTSIDE_CWD="${WORK_DIR}/outside-cwd"
MANIFEST_TARGET_PROBE="${WORK_DIR}/manifest-target-probe"
DETACHED_PID_FILE="${WORK_DIR}/detached.pid"
DETACHED_READY_FILE="${WORK_DIR}/detached.ready"
DETACHED_ATTEMPTED_FILE="${WORK_DIR}/detached-attempted"
DETACHED_TARGET_CAPTURE="${WORK_DIR}/detached-target"
DU_FAILURE_COUNT="${WORK_DIR}/du-failure-count"
DU_FAILURE_PID_FILE="${WORK_DIR}/du-failure.pid"
DU_FAILURE_READY_FILE="${WORK_DIR}/du-failure.ready"
RENAME_PID_FILE="${WORK_DIR}/rename.pid"
REAL_DU="$(command -v du)"

cleanup() {
  local blocker_pid=""
  local detached_pid=""
  local du_failure_pid=""
  local rename_pid=""
  if [[ -n "$WRAPPER_PID" ]] && kill -0 "$WRAPPER_PID" 2>/dev/null; then
    kill -KILL "$WRAPPER_PID" 2>/dev/null || true
  fi
  if [[ -n "$SUPERVISOR_PID" ]] && kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
    kill -KILL "$SUPERVISOR_PID" 2>/dev/null || true
  fi
  if [[ -f "$BLOCKER_PID_FILE" ]]; then
    blocker_pid="$(sed -n '1p' "$BLOCKER_PID_FILE")"
    if [[ "$blocker_pid" =~ ^[0-9]+$ ]] && kill -0 "$blocker_pid" 2>/dev/null; then
      kill -KILL "$blocker_pid" 2>/dev/null || true
    fi
  fi
  if [[ -f "$DETACHED_PID_FILE" ]]; then
    detached_pid="$(sed -n '1p' "$DETACHED_PID_FILE")"
    if [[ "$detached_pid" =~ ^[0-9]+$ ]] && kill -0 "$detached_pid" 2>/dev/null; then
      kill -KILL "$detached_pid" 2>/dev/null || true
    fi
  fi
  if [[ -f "$DU_FAILURE_PID_FILE" ]]; then
    du_failure_pid="$(sed -n '1p' "$DU_FAILURE_PID_FILE")"
    if [[ "$du_failure_pid" =~ ^[0-9]+$ ]] \
      && kill -0 "$du_failure_pid" 2>/dev/null; then
      kill -KILL "$du_failure_pid" 2>/dev/null || true
    fi
  fi
  if [[ -f "$RENAME_PID_FILE" ]]; then
    rename_pid="$(sed -n '1p' "$RENAME_PID_FILE")"
    if [[ "$rename_pid" =~ ^[0-9]+$ ]] && kill -0 "$rename_pid" 2>/dev/null; then
      kill -KILL "$rename_pid" 2>/dev/null || true
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

for member_target in \
  sources/ryuki-core/target \
  sources/ryuki-api/target \
  sources/ryuki-engine/target \
  sources/ryuki-runner/target \
  sources/ryuki-protocol/target \
  sources/ryuki-agent/target \
  portal/portal-ui/target \
  scripts/validator-rs/target; do
  [[ -f "${ROOT_DIR}/${member_target}" && ! -L "${ROOT_DIR}/${member_target}" ]] \
    || fail "workspace member target blocker is missing or is not a regular file: ${member_target}"
done
[[ -f "$SOURCE_DEBUG_BLOCKER" && ! -L "$SOURCE_DEBUG_BLOCKER" ]] \
  || fail "checkout debug blocker is missing or is not a regular file"
grep -Fqx 'build-dir = "../.ryuki-target-ryuki.io/build-cache"' \
  "$SOURCE_CARGO_CONFIG" \
  || fail "Cargo config does not pin build-dir beneath the external cache"
grep -Fqx 'jobs = 1' "$SOURCE_CARGO_CONFIG" \
  || fail "Cargo config does not serialize direct and CI rustc work"

mkdir -p "${FIXTURE_ROOT}/scripts/regressions" "${FIXTURE_ROOT}/.cargo" \
  "$STATE_BASE" "$TMP_A" "$TMP_B" "$FAKE_BIN" "$OUTSIDE_CWD"
FIXTURE_ROOT="$(cd "$FIXTURE_ROOT" && pwd -P)"
STATE_BASE="$(cd "$STATE_BASE" && pwd -P)"
cp "$SOURCE_SCRIPT" "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh"
chmod 700 "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh"
cp "$SOURCE_GUARD" "${FIXTURE_ROOT}/scripts/cargo-rustc-disk-guard.sh"
chmod 700 "${FIXTURE_ROOT}/scripts/cargo-rustc-disk-guard.sh"
cp "$SOURCE_CARGO_CONFIG" "${FIXTURE_ROOT}/.cargo/config.toml"
cp "$SOURCE_TARGET_BLOCKER" "${FIXTURE_ROOT}/target"
git -C "$FIXTURE_ROOT" init -q
printf '[workspace]\nmembers = []\n' > "${FIXTURE_ROOT}/Cargo.toml"

cp "$BLOCKING_GATE_FIXTURE" "${FIXTURE_ROOT}/scripts/regressions/verify-workspace-clean.sh"
chmod 700 "${FIXTURE_ROOT}/scripts/regressions/verify-workspace-clean.sh"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -Eeuo pipefail'
  printf '%s\n' ': "${RYUKI_VERIFY_TEST_CARGO_ENV:?missing capture path}"'
  printf '%s\n' '{'
  printf '%s\n' '  printf "CARGO_TARGET_DIR=%s\n" "${CARGO_TARGET_DIR-}"'
  printf '%s\n' '  printf "CARGO_BUILD_TARGET_DIR=%s\n" "${CARGO_BUILD_TARGET_DIR-}"'
  printf '%s\n' '  printf "CARGO_BUILD_BUILD_DIR=%s\n" "${CARGO_BUILD_BUILD_DIR-}"'
  printf '%s\n' '  printf "CARGO_BUILD_JOBS=%s\n" "${CARGO_BUILD_JOBS-}"'
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
  printf '%s\n' '  printf "RYUKI_CARGO_GUARD_TEST_MODE=%s\n" "${RYUKI_CARGO_GUARD_TEST_MODE-}"'
  printf '%s\n' '  printf "RYUKI_CARGO_GUARD_TEST_MAX_KIB=%s\n" "${RYUKI_CARGO_GUARD_TEST_MAX_KIB-}"'
  printf '%s\n' '  printf "RYUKI_CARGO_MAX_TARGET_GIB=%s\n" "${RYUKI_CARGO_MAX_TARGET_GIB-}"'
  printf '%s\n' '  printf "RYUKI_CARGO_MIN_FREE_GIB=%s\n" "${RYUKI_CARGO_MIN_FREE_GIB-}"'
  printf '%s\n' '  printf "RYUKI_CARGO_GUARD_INTERVAL_SECONDS=%s\n" "${RYUKI_CARGO_GUARD_INTERVAL_SECONDS-}"'
  printf '%s\n' '  printf "FILE_SIZE_SOFT_KIB=%s\n" "$(ulimit -S -f)"'
  printf '%s\n' '  printf "FILE_SIZE_HARD_KIB=%s\n" "$(ulimit -H -f)"'
  printf '%s\n' '  if [[ -e /dev/fd/9 || -e /proc/self/fd/9 ]]; then printf "FD9=open\n"; else printf "FD9=closed\n"; fi'
  printf '%s\n' '} > "$RYUKI_VERIFY_TEST_CARGO_ENV"'
  printf '%s\n' 'if [[ "${RYUKI_VERIFY_TEST_FILE_LIMIT_ATTEMPT:-0}" == "1" ]]; then'
  printf '%s\n' '  dd if=/dev/zero of="$CARGO_TARGET_DIR/file-limit.bin" bs=1024 count=128 2>/dev/null'
  printf '%s\n' 'elif [[ "${RYUKI_VERIFY_TEST_RENAME:-0}" == "1" ]]; then'
  printf '%s\n' '  : "${RYUKI_VERIFY_TEST_RENAME_PID:?missing renamer pid path}"'
  printf '%s\n' '  mkdir -p "$CARGO_TARGET_DIR/rename-race"'
  printf '%s\n' '  touch "$CARGO_TARGET_DIR/rename-race/a"'
  printf '%s\n' '  ('
  printf '%s\n' '    for _ in {1..350}; do'
  printf '%s\n' '      mv "$CARGO_TARGET_DIR/rename-race/a" "$CARGO_TARGET_DIR/rename-race/b"'
  printf '%s\n' '      mv "$CARGO_TARGET_DIR/rename-race/b" "$CARGO_TARGET_DIR/rename-race/a"'
  printf '%s\n' '      sleep 0.01'
  printf '%s\n' '    done'
  printf '%s\n' '  ) &'
  printf '%s\n' '  printf "%s\n" "$!" > "$RYUKI_VERIFY_TEST_RENAME_PID"'
  printf '%s\n' '  wait "$!"'
  printf '%s\n' 'fi'
} > "$FAKE_CARGO"
chmod 700 "$FAKE_CARGO"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -Eeuo pipefail'
  printf '%s\n' 'manifest_path=""'
  printf '%s\n' 'while (( $# > 0 )); do'
  printf '%s\n' '  if [[ "$1" == "--manifest-path" ]]; then'
  printf '%s\n' '    shift'
  printf '%s\n' '    manifest_path="${1:-}"'
  printf '%s\n' '    break'
  printf '%s\n' '  fi'
  printf '%s\n' '  shift'
  printf '%s\n' 'done'
  printf '%s\n' '[[ -n "$manifest_path" ]]'
  printf '%s\n' 'mkdir "$(cd "$(dirname "$manifest_path")" && pwd -P)/target"'
} > "$MANIFEST_TARGET_PROBE"
chmod 700 "$MANIFEST_TARGET_PROBE"

[[ -f "${FIXTURE_ROOT}/target" && ! -L "${FIXTURE_ROOT}/target" ]] \
  || fail "checkout target blocker is not a regular file"
grep -Fqx 'target-dir = "../.ryuki-target-ryuki.io"' \
  "${FIXTURE_ROOT}/.cargo/config.toml" \
  || fail "Cargo config does not place the development target outside the checkout"
if (cd "$OUTSIDE_CWD" && "$MANIFEST_TARGET_PROBE" check \
  --manifest-path "${FIXTURE_ROOT}/Cargo.toml") > "$OUTPUT_FILE" 2>&1; then
  fail "outside-cwd manifest invocation could create a checkout target directory"
fi
[[ -f "${FIXTURE_ROOT}/target" && ! -L "${FIXTURE_ROOT}/target" ]] \
  || fail "outside-cwd manifest probe replaced the checkout target blocker"

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
  RYUKI_VERIFY_MAX_TARGET_GIB=25 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "verification accepted a target ceiling above the repository maximum"
fi
grep -q "RYUKI_VERIFY_MAX_TARGET_GIB must not exceed 24" "$OUTPUT_FILE" \
  || fail "oversized verification target ceiling refusal was not reported"

if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  RYUKI_VERIFY_TEST_MAX_KIB=25165825 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "test-only target ceiling could weaken the 24 GiB repository maximum"
fi
grep -q "RYUKI_VERIFY_TEST_MAX_KIB must not exceed the configured verification target ceiling" \
  "$OUTPUT_FILE" \
  || fail "inflated test-only target ceiling refusal was not reported"

if RYUKI_VERIFY_TEST_FILE_LIMIT_KIB=64 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "verification accepted the test file limit outside test mode"
fi
grep -q "RYUKI_VERIFY_TEST_FILE_LIMIT_KIB is reserved for regression tests" \
  "$OUTPUT_FILE" \
  || fail "production test file-limit refusal was not reported"
if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  RYUKI_VERIFY_TEST_FILE_LIMIT_KIB=8388608 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "verification accepted a non-stricter test file limit"
fi
grep -q "RYUKI_VERIFY_TEST_FILE_LIMIT_KIB must be stricter than 8388608 KiB" \
  "$OUTPUT_FILE" \
  || fail "weakened verification file-limit refusal was not reported"

UNSAFE_STATE_BASE="${FIXTURE_ROOT}/unsafe-state"
mkdir -p "$UNSAFE_STATE_BASE"
if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$UNSAFE_STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "test mode accepted verification state inside the repository"
fi
grep -q "verify-clean test state must be outside the repository and its parent" \
  "$OUTPUT_FILE" \
  || fail "unsafe checkout-local test state refusal was not reported"
[[ ! -e "${UNSAFE_STATE_BASE}/ryuki-verify-$(id -u)" ]] \
  || fail "unsafe test state created a checkout-local verification namespace"

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
  RYUKI_VERIFY_WATCH_INTERVAL_SECONDS=3 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "verification accepted a watcher interval above the repository maximum"
fi
grep -q "RYUKI_VERIFY_WATCH_INTERVAL_SECONDS must not exceed 2" "$OUTPUT_FILE" \
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
  CARGO_BUILD_BUILD_DIR="${hostile_target}-build-dir" \
  CARGO_BUILD_JOBS=999 \
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
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=999999999 \
  RYUKI_CARGO_MAX_TARGET_GIB=999 \
  RYUKI_CARGO_MIN_FREE_GIB=1 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=999 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" -- cargo check \
  > "$OUTPUT_FILE" 2>&1 \
  || fail "focused verification failed while sanitizing inherited Cargo overrides"

captured_target="$(sed -n 's/^CARGO_TARGET_DIR=//p' "$CARGO_ENV_CAPTURE")"
captured_build_dir="$(sed -n 's/^CARGO_BUILD_BUILD_DIR=//p' "$CARGO_ENV_CAPTURE")"
case "$captured_target" in
  "${VERIFY_TARGET_ROOT}"/run.*/target) ;;
  *) fail "focused verification did not replace the inherited Cargo target" ;;
esac
[[ "$captured_build_dir" == "${captured_target}/build-cache" ]] \
  || fail "focused verification did not pin Cargo build-dir beneath its disposable target"
grep -Fxq "RUSTC_WRAPPER=${FIXTURE_ROOT}/scripts/cargo-rustc-disk-guard.sh" \
  "$CARGO_ENV_CAPTURE" \
  || fail "focused verification did not install the absolute repository rustc guard"
for cleared in CARGO_BUILD_TARGET_DIR RUSTC_WORKSPACE_WRAPPER \
  CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER RUSTFLAGS \
  CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_BUILD_INCREMENTAL \
  CARGO_PROFILE_DEV_INCREMENTAL CARGO_PROFILE_TEST_INCREMENTAL \
  RYUKI_CARGO_GUARD_TEST_MODE RYUKI_CARGO_GUARD_TEST_MAX_KIB; do
  grep -Fxq "${cleared}=" "$CARGO_ENV_CAPTURE" \
    || fail "focused verification retained inherited ${cleared}"
done
grep -Fxq 'RYUKI_CARGO_MAX_TARGET_GIB=24' "$CARGO_ENV_CAPTURE" \
  || fail "focused verification did not pin the rustc target ceiling"
grep -Fxq 'RYUKI_CARGO_MIN_FREE_GIB=30' "$CARGO_ENV_CAPTURE" \
  || fail "focused verification did not pin the rustc free-space floor"
grep -Fxq 'RYUKI_CARGO_GUARD_INTERVAL_SECONDS=2' "$CARGO_ENV_CAPTURE" \
  || fail "focused verification did not pin the rustc watcher interval"
grep -Fxq 'CARGO_BUILD_JOBS=1' "$CARGO_ENV_CAPTURE" \
  || fail "focused verification did not pin Cargo build jobs to one"
soft_file_limit="$(sed -n 's/^FILE_SIZE_SOFT_KIB=//p' "$CARGO_ENV_CAPTURE")"
hard_file_limit="$(sed -n 's/^FILE_SIZE_HARD_KIB=//p' "$CARGO_ENV_CAPTURE")"
[[ "$soft_file_limit" =~ ^[1-9][0-9]*$ && "$soft_file_limit" -le 8388608 ]] \
  || fail "focused Cargo command did not inherit the 8 GiB soft file-size ceiling"
[[ "$hard_file_limit" =~ ^[1-9][0-9]*$ && "$hard_file_limit" -le 8388608 ]] \
  || fail "focused Cargo command could raise its hard file-size ceiling"
grep -Fxq 'FD9=closed' "$CARGO_ENV_CAPTURE" \
  || fail "focused Cargo command inherited repository lock descriptor 9"
for pinned in CARGO_INCREMENTAL CARGO_PROFILE_DEV_DEBUG CARGO_PROFILE_TEST_DEBUG; do
  grep -Fxq "${pinned}=0" "$CARGO_ENV_CAPTURE" \
    || fail "focused verification did not pin ${pinned} to zero"
done
[[ ! -e "$hostile_target" && ! -e "${hostile_target}-config" \
  && ! -e "${hostile_target}-build-dir" ]] \
  || fail "focused verification wrote to an inherited Cargo target"

if PATH="${FAKE_BIN}:$PATH" TMPDIR="$TMP_A" \
  RYUKI_VERIFY_STATE_BASE="$STATE_BASE" RYUKI_VERIFY_TEST_MODE=1 \
  RYUKI_VERIFY_KEEP_TARGET=0 RYUKI_VERIFY_TEST_FILE_LIMIT_KIB=64 \
  RYUKI_VERIFY_TEST_CARGO_ENV="$CARGO_ENV_CAPTURE" \
  RYUKI_VERIFY_TEST_FILE_LIMIT_ATTEMPT=1 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" -- cargo check \
  > "$OUTPUT_FILE" 2>&1; then
  fail "fake Cargo created a file beyond the test RLIMIT_FSIZE"
fi
grep -Fxq 'FILE_SIZE_SOFT_KIB=64' "$CARGO_ENV_CAPTURE" \
  || fail "test-only soft file-size limit was not inherited"
grep -Fxq 'FILE_SIZE_HARD_KIB=64' "$CARGO_ENV_CAPTURE" \
  || fail "test-only hard file-size limit was not inherited"
limited_target="$(sed -n 's/^CARGO_TARGET_DIR=//p' "$CARGO_ENV_CAPTURE")"
[[ -n "$limited_target" && ! -e "$limited_target" ]] \
  || fail "file-size failure cleanup left its disposable Cargo target"

PATH="${FAKE_BIN}:$PATH" TMPDIR="$TMP_A" \
  RYUKI_VERIFY_STATE_BASE="$STATE_BASE" RYUKI_VERIFY_TEST_MODE=1 \
  RYUKI_VERIFY_KEEP_TARGET=0 RYUKI_VERIFY_WATCH_INTERVAL_SECONDS=1 \
  RYUKI_VERIFY_TEST_CARGO_ENV="$CARGO_ENV_CAPTURE" \
  RYUKI_VERIFY_TEST_RENAME=1 RYUKI_VERIFY_TEST_RENAME_PID="$RENAME_PID_FILE" \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" -- cargo check \
  > "$OUTPUT_FILE" 2>&1 \
  || fail "focused verification false-aborted during continuous artifact renames"
rename_target="$(sed -n 's/^CARGO_TARGET_DIR=//p' "$CARGO_ENV_CAPTURE")"
[[ -n "$rename_target" && ! -e "$rename_target" ]] \
  || fail "rename-race verification left its disposable Cargo target"

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

rm -f "$READY_FILE" "$RELEASE_FILE" "$BLOCKER_PID_FILE"
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
  > "$SUPERVISOR_KILL_OUTPUT" 2>&1 &
WRAPPER_PID=$!
wait_for_file "$READY_FILE" || fail "supervisor-SIGKILL gate did not start"
VERIFY_CONTROL_FILE=""
for _ in {1..200}; do
  for candidate in "$VERIFY_TARGET_ROOT"/run.*/.ryuki-verify-command-owner; do
    [[ -f "$candidate" && ! -L "$candidate" ]] || continue
    VERIFY_CONTROL_FILE="$candidate"
    break
  done
  [[ -n "$VERIFY_CONTROL_FILE" ]] && break
  sleep 0.05
done
[[ -n "$VERIFY_CONTROL_FILE" ]] \
  || fail "verify supervisor ownership control was not published"
SUPERVISOR_PID="$(sed -n 's/^supervisor_pid=//p' "$VERIFY_CONTROL_FILE")"
[[ "$SUPERVISOR_PID" =~ ^[1-9][0-9]*$ ]] \
  || fail "verify supervisor ownership control has an invalid pid"
kill -KILL "$SUPERVISOR_PID"
if wait "$WRAPPER_PID" 2>/dev/null; then
  fail "verification accepted a killed gate supervisor"
fi
WRAPPER_PID=""
blocker_pid="$(sed -n '1p' "$BLOCKER_PID_FILE")"
wait_for_exit "$blocker_pid" \
  || fail "gate command survived its verify supervisor being killed"
SUPERVISOR_PID=""
grep -q 'recovering verification process group after supervisor exit' \
  "$SUPERVISOR_KILL_OUTPUT" \
  || fail "verify supervisor-SIGKILL parent recovery was not reported"
run_preflight "$TMP_B" > "$OUTPUT_FILE" 2>&1 \
  || fail "verification lock was not immediately reusable after supervisor SIGKILL"
if [[ -d "$VERIFY_TARGET_ROOT" \
  && -n "$(find "$VERIFY_TARGET_ROOT" -mindepth 1 -maxdepth 2 \
    -name '.ryuki-verify-command-*' -print -quit)" ]]; then
  fail "verify supervisor-SIGKILL left command ownership state"
fi
if [[ -d "$VERIFY_TARGET_ROOT" \
  && -n "$(find "$VERIFY_TARGET_ROOT" -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit)" ]]; then
  fail "verify supervisor-SIGKILL left a disposable target"
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

# The verifier must apply its cap to apparent size as well as allocated blocks.
# A sparse retained target keeps the fixture cheap while reproducing the
# Finder-visible growth that previously escaped allocated-block accounting.
dd if=/dev/zero of="${VERIFY_TARGET_ROOT}/run.retained/sparse.bin" \
  bs=1 count=0 seek=1048576 2>/dev/null
sparse_allocated_kib="$(du -s -k "${VERIFY_TARGET_ROOT}/run.retained" | awk 'END {print $1}')"
if du --apparent-size --count-links -s -k "${VERIFY_TARGET_ROOT}/run.retained" \
  >/dev/null 2>&1; then
  sparse_apparent_kib="$(du --apparent-size --count-links -s -k \
    "${VERIFY_TARGET_ROOT}/run.retained" | awk 'END {print $1}')"
else
  sparse_apparent_kib="$(du -A -l -s -k \
    "${VERIFY_TARGET_ROOT}/run.retained" | awk 'END {print $1}')"
fi
[[ "$sparse_allocated_kib" -le 128 && "$sparse_apparent_kib" -gt 128 ]] \
  || fail "verifier sparse fixture did not separate allocated and apparent size"
if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_PREFLIGHT_ONLY=1 \
  RYUKI_VERIFY_TEST_MAX_KIB=128 \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" > "$OUTPUT_FILE" 2>&1; then
  fail "verification accepted a sparse target over the apparent-size ceiling"
fi
grep -q "managed targets exceeded" "$OUTPUT_FILE" \
  || fail "sparse verification target refusal was not reported"
rm -f "${VERIFY_TARGET_ROOT}/run.retained/sparse.bin"

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

for jobs_override in --jobs=99 -j99; do
  if TMPDIR="$TMP_A" RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
    RYUKI_VERIFY_TEST_MODE=1 RYUKI_VERIFY_KEEP_TARGET=0 \
    "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" \
    -- cargo test "$jobs_override" > "$OUTPUT_FILE" 2>&1; then
    fail "focused verification accepted Cargo job override ${jobs_override}"
  fi
  grep -q "forbids overriding the pinned Cargo job count" "$OUTPUT_FILE" \
    || fail "focused Cargo job override refusal was not reported"
done

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
grep -q "accepts only cargo build, check, clippy, run, or test" "$OUTPUT_FILE" \
  || fail "focused Cargo subcommand refusal was not reported"

# A nonzero du result may still contain a plausible partial total while Cargo
# concurrently renames artifacts. The verifier must reject that total and stop
# the complete command process group instead of allowing descendants to run.
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -Eeuo pipefail'
  printf '%s\n' ': "${RYUKI_VERIFY_TEST_DU_COUNT:?missing du counter}"'
  printf '%s\n' 'for argument in "$@"; do'
  printf '%s\n' '  if [[ "$argument" == "/dev/null" ]]; then exec '"$(printf '%q' "$REAL_DU")"' "$@"; fi'
  printf '%s\n' 'done'
  printf '%s\n' 'count=0'
  printf '%s\n' '[[ ! -f "$RYUKI_VERIFY_TEST_DU_COUNT" ]] || read -r count < "$RYUKI_VERIFY_TEST_DU_COUNT"'
  printf '%s\n' 'count=$((count + 1))'
  printf '%s\n' 'printf "%s\n" "$count" > "$RYUKI_VERIFY_TEST_DU_COUNT"'
  printf '%s\n' 'if (( count > 4 )); then'
  printf '%s\n' '  printf "1\\t%s\\n" "${!#}"'
  printf '%s\n' '  exit 1'
  printf '%s\n' 'fi'
  printf '%s\n' 'exec '"$(printf '%q' "$REAL_DU")"' "$@"'
} > "$FAKE_BIN/du"
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -Eeuo pipefail'
  printf '%s\n' ': "${RYUKI_VERIFY_TEST_DU_FAILURE_PID:?missing descendant pid path}"'
  printf '%s\n' ': "${RYUKI_VERIFY_TEST_DU_FAILURE_READY:?missing ready path}"'
  printf '%s\n' '('
  printf '%s\n' '  touch "$RYUKI_VERIFY_TEST_DU_FAILURE_READY"'
  printf '%s\n' '  while :; do sleep 1; done'
  printf '%s\n' ') &'
  printf '%s\n' 'descendant_pid=$!'
  printf '%s\n' 'printf "%s\n" "$descendant_pid" > "$RYUKI_VERIFY_TEST_DU_FAILURE_PID"'
  printf '%s\n' 'wait "$descendant_pid"'
} > "$FAKE_CARGO"
chmod 700 "$FAKE_BIN/du" "$FAKE_CARGO"
set +e
PATH="$FAKE_BIN:$PATH" \
  TMPDIR="$TMP_A" \
  RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 \
  RYUKI_VERIFY_KEEP_TARGET=0 \
  RYUKI_VERIFY_WATCH_INTERVAL_SECONDS=1 \
  RYUKI_VERIFY_TEST_DU_COUNT="$DU_FAILURE_COUNT" \
  RYUKI_VERIFY_TEST_DU_FAILURE_PID="$DU_FAILURE_PID_FILE" \
  RYUKI_VERIFY_TEST_DU_FAILURE_READY="$DU_FAILURE_READY_FILE" \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" -- cargo check \
  > "$OUTPUT_FILE" 2>&1
du_failure_status=$?
set -e
[[ "$du_failure_status" -eq 75 ]] \
  || fail "focused verification accepted a nonzero partial du measurement"
wait_for_file "$DU_FAILURE_READY_FILE" \
  || fail "du-failure command descendant did not start"
du_failure_pid="$(sed -n '1p' "$DU_FAILURE_PID_FILE")"
[[ "$du_failure_pid" =~ ^[0-9]+$ ]] \
  || fail "du-failure command published an invalid descendant pid"
wait_for_exit "$du_failure_pid" \
  || fail "du-failure command descendant survived fail-closed measurement"
grep -q "allocated/apparent size or free space could not be measured" "$OUTPUT_FILE" \
  || fail "nonzero partial du measurement failure was not reported"
grep -q "stopping focused verification before it can exhaust the disk" "$OUTPUT_FILE" \
  || fail "du measurement failure did not report process-group shutdown"
rm -f "$FAKE_BIN/du" "$DU_FAILURE_COUNT" "$DU_FAILURE_PID_FILE" \
  "$DU_FAILURE_READY_FILE"

cp "$DETACHED_CARGO_FIXTURE" "$FAKE_CARGO"
chmod 700 "$FAKE_CARGO"
set +e
PATH="${FAKE_BIN}:$PATH" \
  TMPDIR="$TMP_A" \
  RYUKI_VERIFY_STATE_BASE="$STATE_BASE" \
  RYUKI_VERIFY_TEST_MODE=1 \
  RYUKI_VERIFY_TEST_REGROUPED_PGID_FILE="$DETACHED_PID_FILE" \
  RYUKI_VERIFY_KEEP_TARGET=0 \
  RYUKI_VERIFY_WATCH_INTERVAL_SECONDS=1 \
  RYUKI_VERIFY_TEST_DETACHED_PID="$DETACHED_PID_FILE" \
  RYUKI_VERIFY_TEST_DETACHED_READY="$DETACHED_READY_FILE" \
  RYUKI_VERIFY_TEST_DETACHED_ATTEMPTED="$DETACHED_ATTEMPTED_FILE" \
  RYUKI_VERIFY_TEST_DETACHED_TARGET="$DETACHED_TARGET_CAPTURE" \
  "${FIXTURE_ROOT}/scripts/verify-workspace-clean.sh" -- cargo check \
  > "$OUTPUT_FILE" 2>&1
detached_status=$?
set -e
[[ "$detached_status" -eq 75 ]] \
  || fail "focused verification accepted a regrouped command descendant"
wait_for_file "$DETACHED_PID_FILE" \
  || fail "detached command fixture did not publish its descendant pid"
detached_pid="$(sed -n '1p' "$DETACHED_PID_FILE")"
[[ "$detached_pid" =~ ^[0-9]+$ ]] \
  || fail "detached command fixture published an invalid descendant pid"
wait_for_exit "$detached_pid" \
  || fail "focused verification left a detached command descendant running"
detached_target="$(sed -n '1p' "$DETACHED_TARGET_CAPTURE")"
case "$detached_target" in
  "${VERIFY_TARGET_ROOT}"/run.*/target) ;;
  *) fail "detached command fixture did not receive the managed Cargo target" ;;
esac
[[ ! -e "$detached_target" ]] \
  || fail "detached command descendant recreated the disposable Cargo target"
[[ ! -e "$DETACHED_ATTEMPTED_FILE" ]] \
  || fail "detached command descendant survived long enough to attempt target recreation"
grep -q "supervised descendant changed process group" "$OUTPUT_FILE" \
  || fail "regrouped command descendant rejection was not reported"

echo "verify-workspace-clean regression passed"
