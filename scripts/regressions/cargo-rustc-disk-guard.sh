#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
GUARD="$ROOT_DIR/scripts/cargo-rustc-disk-guard.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-cargo-guard.XXXXXX")"
TARGET="$TEST_ROOT/target"
OUT_DIR="$TARGET/debug/deps"
export CARGO_TARGET_DIR="$TARGET"
MARKER="$TEST_ROOT/rustc-called"
FAKE_RUSTC="$TEST_ROOT/fake-rustc"
GROWER_STARTED="$TEST_ROOT/grower-started"
GROWER_FINISHED="$TEST_ROOT/grower-finished"
PEER_STARTED="$TEST_ROOT/peer-started"
PEER_FINISHED="$TEST_ROOT/peer-finished"
FAKE_GROWER="$TEST_ROOT/fake-growing-rustc"
FAKE_PEER="$TEST_ROOT/fake-peer-rustc"
FAST_GROWER_FINISHED="$TEST_ROOT/fast-grower-finished"
FAKE_FAST_GROWER="$TEST_ROOT/fake-fast-growing-rustc"
SPARSE_TARGET="$TEST_ROOT/sparse-target"
SPARSE_OUT_DIR="$SPARSE_TARGET/debug/deps"
BUILD_ESCAPE="$TEST_ROOT/build-escape"
SYMLINK_TARGET="$TEST_ROOT/symlink-target"
SYMLINK_OUTSIDE="$TEST_ROOT/symlink-output"
SYMLINK_OUT_DIR="$SYMLINK_TARGET/debug/deps"

cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

mkdir -p "$OUT_DIR"
printf 'Signature: 8a477f597d28d172789f06886806bc55\n' > "$TARGET/CACHEDIR.TAG"
printf '#!/usr/bin/env bash\nset -Eeuo pipefail\nprintf called > %q\n' "$MARKER" > "$FAKE_RUSTC"
chmod +x "$FAKE_RUSTC"
printf '#!/usr/bin/env bash\nset -Eeuo pipefail\nprintf started > %q\ndd if=/dev/zero of=%q bs=1024 count=128 status=none\nsleep 10\nprintf finished > %q\n' \
  "$GROWER_STARTED" "$TARGET/runtime-oversized.bin" "$GROWER_FINISHED" > "$FAKE_GROWER"
printf '#!/usr/bin/env bash\nset -Eeuo pipefail\nprintf started > %q\nsleep 10\nprintf finished > %q\n' \
  "$PEER_STARTED" "$PEER_FINISHED" > "$FAKE_PEER"
printf '#!/usr/bin/env bash\nset -Eeuo pipefail\ndd if=/dev/zero of=%q bs=1024 count=128 status=none\nprintf finished > %q\n' \
  "$TARGET/fast-oversized.bin" "$FAST_GROWER_FINISHED" > "$FAKE_FAST_GROWER"
chmod +x "$FAKE_GROWER" "$FAKE_PEER" "$FAKE_FAST_GROWER"

if RYUKI_CARGO_MAX_TARGET_GIB=25 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/max-target.log"; then
  echo "error: production guard accepted a target ceiling above 24 GiB" >&2
  exit 1
fi
grep -q "RYUKI_CARGO_MAX_TARGET_GIB must not exceed 24" "$TEST_ROOT/max-target.log"

if RYUKI_CARGO_MIN_FREE_GIB=29 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/min-free.log"; then
  echo "error: production guard accepted a free-space floor below 30 GiB" >&2
  exit 1
fi
grep -q "RYUKI_CARGO_MIN_FREE_GIB must not be less than 30" "$TEST_ROOT/min-free.log"

if RYUKI_CARGO_GUARD_INTERVAL_SECONDS=3 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/interval.log"; then
  echo "error: production guard accepted a sampling interval above 2 seconds" >&2
  exit 1
fi
grep -q "RYUKI_CARGO_GUARD_INTERVAL_SECONDS must not exceed 2" "$TEST_ROOT/interval.log"

if RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_MAX_TARGET_GIB=25 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/test-max-target.log"; then
  echo "error: test mode weakened the production target ceiling" >&2
  exit 1
fi
grep -q "RYUKI_CARGO_MAX_TARGET_GIB must not exceed 24" "$TEST_ROOT/test-max-target.log"

if RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=25165825 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/test-max-kib.log"; then
  echo "error: test mode accepted a KiB ceiling above 24 GiB" >&2
  exit 1
fi
grep -q "RYUKI_CARGO_GUARD_TEST_MAX_KIB must not exceed 25165824" \
  "$TEST_ROOT/test-max-kib.log"

if RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_MAX_TARGET_GIB=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1048577 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/test-configured-max-kib.log"; then
  echo "error: test mode weakened a stricter configured target ceiling" >&2
  exit 1
fi
grep -q "must not exceed the configured target ceiling of 1048576 KiB" \
  "$TEST_ROOT/test-configured-max-kib.log"

if CARGO_TARGET_DIR="$ROOT_DIR" \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$ROOT_DIR" 2>"$TEST_ROOT/in-repo-target.log"; then
  echo "error: repository-local Cargo target was accepted" >&2
  exit 1
fi
grep -q "target root must be outside the repository checkout" \
  "$TEST_ROOT/in-repo-target.log"

if TMPDIR="$ROOT_DIR" \
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/unsafe-test-root.log"; then
  echo "error: test mode accepted a repository-local temporary root" >&2
  exit 1
fi
grep -q "temporary directory must be outside the repository checkout" \
  "$TEST_ROOT/unsafe-test-root.log"

if CARGO_BUILD_BUILD_DIR=. \
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/root-build-dir.log"; then
  echo "error: checkout-root Cargo build directory was accepted" >&2
  exit 1
fi
grep -q "CARGO_BUILD_BUILD_DIR must resolve inside the target root" \
  "$TEST_ROOT/root-build-dir.log"

mkdir -p "$BUILD_ESCAPE"
ln -s "$BUILD_ESCAPE" "$TARGET/build-link"
if CARGO_BUILD_BUILD_DIR="$TARGET/build-link" \
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/symlink-build-dir.log"; then
  echo "error: symlinked Cargo build directory escaped the target" >&2
  exit 1
fi
grep -q "CARGO_BUILD_BUILD_DIR must resolve inside the target root" \
  "$TEST_ROOT/symlink-build-dir.log"

# A lexical target ancestor carrying CACHEDIR.TAG is not sufficient when an
# output path crosses a symlink. The guard must canonicalize the rustc output
# directory before looking for its target root.
mkdir -p "$SYMLINK_TARGET" "$SYMLINK_OUTSIDE/deps"
printf 'Signature: 8a477f597d28d172789f06886806bc55\n' \
  > "$SYMLINK_TARGET/CACHEDIR.TAG"
printf 'Signature: 8a477f597d28d172789f06886806bc55\n' \
  > "$SYMLINK_OUTSIDE/CACHEDIR.TAG"
ln -s "$SYMLINK_OUTSIDE" "$SYMLINK_TARGET/debug"
if CARGO_TARGET_DIR="$SYMLINK_TARGET" \
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$SYMLINK_OUT_DIR" 2>"$TEST_ROOT/symlink-out-dir.log"; then
  echo "error: symlinked rustc output escaped physical target containment" >&2
  exit 1
fi
grep -q "unable to identify the target root" "$TEST_ROOT/symlink-out-dir.log"

if CARGO_TARGET_DIR="$TEST_ROOT/missing-target" \
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/missing-target.log"; then
  echo "error: absent configured target was replaced by an out-dir marker" >&2
  exit 1
fi
grep -q "unable to identify the target root" "$TEST_ROOT/missing-target.log"

[[ ! -e "$MARKER" ]] || {
  echo "error: rustc ran while a weakened production guard was rejected" >&2
  exit 1
}

# Use real allocated blocks so the same `du -sk` semantics are exercised.
dd if=/dev/zero of="$TARGET/oversized.bin" bs=1024 count=32 status=none
if RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=8 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/refused.log"; then
  echo "error: oversized target was not refused" >&2
  exit 1
fi
grep -q "Cargo compilation refused" "$TEST_ROOT/refused.log"
[[ ! -e "$MARKER" ]] || {
  echo "error: rustc ran after the target ceiling was exceeded" >&2
  exit 1
}

# A sparse file consumes few allocated blocks while presenting a large logical
# size in Finder and other apparent-size accounting. The guard must enforce the
# larger measurement rather than allowing sparse growth through the ceiling.
mkdir -p "$SPARSE_OUT_DIR"
printf 'Signature: 8a477f597d28d172789f06886806bc55\n' > "$SPARSE_TARGET/CACHEDIR.TAG"
dd if=/dev/zero of="$SPARSE_TARGET/sparse.bin" bs=1 count=0 seek=1048576 2>/dev/null
sparse_allocated_kib="$(du -s -k "$SPARSE_TARGET" | awk 'END {print $1}')"
if du --apparent-size --count-links -s -k "$SPARSE_TARGET" >/dev/null 2>&1; then
  sparse_apparent_kib="$(du --apparent-size --count-links -s -k "$SPARSE_TARGET" | awk 'END {print $1}')"
else
  sparse_apparent_kib="$(du -A -l -s -k "$SPARSE_TARGET" | awk 'END {print $1}')"
fi
[[ "$sparse_allocated_kib" -le 128 && "$sparse_apparent_kib" -gt 128 ]] || {
  echo "error: sparse-file fixture did not separate allocated and apparent size" >&2
  exit 1
}
if RYUKI_CARGO_GUARD_TEST_MODE=1 \
  CARGO_TARGET_DIR="$SPARSE_TARGET" \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=128 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$SPARSE_OUT_DIR" 2>"$TEST_ROOT/sparse-refused.log"; then
  echo "error: sparse target escaped the apparent-size ceiling" >&2
  exit 1
fi
grep -q "Cargo target exceeded" "$TEST_ROOT/sparse-refused.log"
grep -q "Cargo compilation refused" "$TEST_ROOT/sparse-refused.log"
[[ ! -e "$MARKER" ]] || {
  echo "error: rustc ran after sparse target growth exceeded the ceiling" >&2
  exit 1
}

# An output directory outside the configured target, with no Cargo target tag,
# must never fall back to supervising some other existing target.
UNMARKED_OUT_DIR="$TEST_ROOT/unmarked/debug/deps"
mkdir -p "$UNMARKED_OUT_DIR"
if CARGO_TARGET_DIR="$TARGET" \
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$UNMARKED_OUT_DIR" 2>"$TEST_ROOT/unidentified.log"; then
  echo "error: unidentified compiler output ran without its own target supervisor" >&2
  exit 1
fi
grep -q "unable to identify the target root" "$TEST_ROOT/unidentified.log"
[[ ! -e "$MARKER" ]] || {
  echo "error: unidentified compiler output was allowed to run" >&2
  exit 1
}

# A healthy preflight is not enough: one compiler can grow the target after it
# starts while another compiler is still running. The first monitor to observe
# the aggregate breach must trip both wrapper-owned process trees.
rm -f "$TARGET/oversized.bin"
rm -rf "$TARGET/.ryuki-cargo-disk-guard"
set +e
RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=32 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_PEER" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/peer.log" &
peer_wrapper_pid=$!
for _ in {1..20}; do
  [[ -f "$PEER_STARTED" ]] && break
  sleep 0.1
done
[[ -f "$PEER_STARTED" ]] || {
  echo "error: peer compiler did not start" >&2
  kill "$peer_wrapper_pid" 2>/dev/null || true
  wait "$peer_wrapper_pid" 2>/dev/null || true
  exit 1
}
RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=32 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_GROWER" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/grower.log" &
grower_wrapper_pid=$!
wait "$grower_wrapper_pid"
grower_status=$?
wait "$peer_wrapper_pid"
peer_status=$?
set -e

[[ "$grower_status" -eq 75 && "$peer_status" -eq 75 ]] || {
  echo "error: runtime target breach did not stop every compiler wrapper" >&2
  exit 1
}
[[ -f "$GROWER_STARTED" && ! -e "$GROWER_FINISHED" ]] || {
  echo "error: growing compiler was not stopped during execution" >&2
  exit 1
}
[[ ! -e "$PEER_FINISHED" ]] || {
  echo "error: peer compiler ignored the shared target-limit trip" >&2
  exit 1
}
grep -q "stopping Cargo compiler processes" "$TEST_ROOT/grower.log"
grep -q "stopping Cargo compiler processes" "$TEST_ROOT/peer.log"

# Removing the generated target growth must clear the trip on the next forced
# preflight so normal compilation can resume without deleting source state.
TRIP_FILE="$TARGET/.ryuki-cargo-disk-guard/target-limit-tripped"
[[ -f "$TRIP_FILE" ]] || {
  echo "error: runtime breach did not persist the shared trip marker" >&2
  exit 1
}
rm -f "$TARGET/runtime-oversized.bin"
RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR"
[[ -f "$MARKER" ]] || {
  echo "error: healthy target did not delegate to rustc" >&2
  exit 1
}
[[ ! -e "$TRIP_FILE" ]] || {
  echo "error: healthy forced preflight did not clear the prior trip" >&2
  exit 1
}

# A compiler can cross the cap and exit successfully before the first periodic
# sample. The wrapper's forced postflight must still turn that apparent success
# into a disk-guard failure.
set +e
RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=64 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_FAST_GROWER" --out-dir "$OUT_DIR" 2>"$TEST_ROOT/fast-grower.log"
fast_grower_status=$?
set -e
[[ "$fast_grower_status" -eq 75 && -f "$FAST_GROWER_FINISHED" ]] || {
  echo "error: short-lived target growth escaped the postflight ceiling" >&2
  exit 1
}
grep -q "compiler output crossed" "$TEST_ROOT/fast-grower.log"
[[ -f "$TRIP_FILE" ]] || {
  echo "error: short-lived target breach did not persist its trip" >&2
  exit 1
}

rm -f "$TARGET/fast-oversized.bin"
RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  RYUKI_CARGO_MIN_FREE_GIB=30 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR"
[[ ! -e "$TRIP_FILE" ]] || {
  echo "error: target cleanup did not recover from a postflight trip" >&2
  exit 1
}

# Stress the atomic checker handoff with many short compilers. A recursive
# lock-directory release can delete its successor under this exact workload;
# the owner-token symlink must leave every wrapper successful and no lock
# artifacts behind.
stress_pids=()
for index in {1..32}; do
  RYUKI_CARGO_GUARD_TEST_MODE=1 \
    RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
    RYUKI_CARGO_MIN_FREE_GIB=30 \
    RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
    "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR" \
    2>"$TEST_ROOT/stress-${index}.log" &
  stress_pids+=("$!")
done
for stress_pid in "${stress_pids[@]}"; do
  wait "$stress_pid"
done
if grep -q "No such file or directory" "$TEST_ROOT"/stress-*.log; then
  echo "error: concurrent checker handoff deleted live lock state" >&2
  exit 1
fi
[[ ! -e "$TARGET/.ryuki-cargo-disk-guard/check.lock" \
  && ! -L "$TARGET/.ryuki-cargo-disk-guard/check.lock" ]] || {
  echo "error: checker lock remained after concurrent compilers exited" >&2
  exit 1
}
if find "$TARGET/.ryuki-cargo-disk-guard" -maxdepth 1 -name 'check-owner.*' -print -quit \
  | grep -q .; then
  echo "error: checker owner state remained after concurrent compilers exited" >&2
  exit 1
fi

echo "cargo rustc disk guard regression passed"
