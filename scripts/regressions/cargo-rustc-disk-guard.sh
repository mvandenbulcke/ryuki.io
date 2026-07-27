#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
GUARD="$ROOT_DIR/scripts/cargo-rustc-disk-guard.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-cargo-guard.XXXXXX")"
TARGET="$TEST_ROOT/target"
OUT_DIR="$TARGET/debug/deps"
MARKER="$TEST_ROOT/rustc-called"
FAKE_RUSTC="$TEST_ROOT/fake-rustc"
GROWER_STARTED="$TEST_ROOT/grower-started"
GROWER_FINISHED="$TEST_ROOT/grower-finished"
PEER_STARTED="$TEST_ROOT/peer-started"
PEER_FINISHED="$TEST_ROOT/peer-finished"
FAKE_GROWER="$TEST_ROOT/fake-growing-rustc"
FAKE_PEER="$TEST_ROOT/fake-peer-rustc"

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
chmod +x "$FAKE_GROWER" "$FAKE_PEER"

# Use real allocated blocks so the same `du -sk` semantics are exercised.
dd if=/dev/zero of="$TARGET/oversized.bin" bs=1024 count=32 status=none
if RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=8 \
  RYUKI_CARGO_MIN_FREE_GIB=1 \
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

# A healthy preflight is not enough: one compiler can grow the target after it
# starts while another compiler is still running. The first monitor to observe
# the aggregate breach must trip both wrapper-owned process trees.
rm -f "$TARGET/oversized.bin"
rm -rf "$TARGET/.ryuki-cargo-disk-guard"
set +e
RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=32 \
  RYUKI_CARGO_MIN_FREE_GIB=1 \
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
  RYUKI_CARGO_MIN_FREE_GIB=1 \
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
grep -q "stopping Cargo compiler processes" "$TEST_ROOT/grower.log" "$TEST_ROOT/peer.log"

# Removing the generated target growth must clear the trip on the next forced
# preflight so normal compilation can resume without deleting source state.
rm -f "$TARGET/runtime-oversized.bin"
rm -rf "$TARGET/.ryuki-cargo-disk-guard"
RYUKI_CARGO_GUARD_TEST_MODE=1 \
  RYUKI_CARGO_GUARD_TEST_MAX_KIB=1024 \
  RYUKI_CARGO_MIN_FREE_GIB=1 \
  RYUKI_CARGO_GUARD_INTERVAL_SECONDS=1 \
  "$GUARD" "$FAKE_RUSTC" --out-dir "$OUT_DIR"
[[ -f "$MARKER" ]] || {
  echo "error: healthy target did not delegate to rustc" >&2
  exit 1
}

echo "cargo rustc disk guard regression passed"
