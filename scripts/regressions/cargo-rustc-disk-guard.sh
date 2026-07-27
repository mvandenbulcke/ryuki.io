#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
GUARD="$ROOT_DIR/scripts/cargo-rustc-disk-guard.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-cargo-guard.XXXXXX")"
TARGET="$TEST_ROOT/target"
OUT_DIR="$TARGET/debug/deps"
MARKER="$TEST_ROOT/rustc-called"
FAKE_RUSTC="$TEST_ROOT/fake-rustc"

cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

mkdir -p "$OUT_DIR"
printf 'Signature: 8a477f597d28d172789f06886806bc55\n' > "$TARGET/CACHEDIR.TAG"
printf '#!/usr/bin/env bash\nset -Eeuo pipefail\nprintf called > %q\n' "$MARKER" > "$FAKE_RUSTC"
chmod +x "$FAKE_RUSTC"

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

rm -f "$TARGET/oversized.bin"
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
