#!/usr/bin/env bash
set -Eeuo pipefail

: "${RYUKI_DEV_TEST_CAPTURE:?missing Cargo environment capture path}"

{
  printf 'CARGO_TARGET_DIR=%s\n' "${CARGO_TARGET_DIR-}"
  printf 'CARGO_BUILD_TARGET_DIR=%s\n' "${CARGO_BUILD_TARGET_DIR-}"
  printf 'CARGO_BUILD_BUILD_DIR=%s\n' "${CARGO_BUILD_BUILD_DIR-}"
  printf 'RUSTC_WRAPPER=%s\n' "${RUSTC_WRAPPER-}"
  printf 'RUSTC_WORKSPACE_WRAPPER=%s\n' "${RUSTC_WORKSPACE_WRAPPER-}"
  printf 'CARGO_BUILD_RUSTC_WRAPPER=%s\n' "${CARGO_BUILD_RUSTC_WRAPPER-}"
  printf 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=%s\n' \
    "${CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER-}"
  printf 'RYUKI_CARGO_GUARD_TEST_MODE=%s\n' "${RYUKI_CARGO_GUARD_TEST_MODE-}"
  printf 'RYUKI_CARGO_GUARD_TEST_MAX_KIB=%s\n' "${RYUKI_CARGO_GUARD_TEST_MAX_KIB-}"
  printf 'RYUKI_CARGO_MAX_TARGET_GIB=%s\n' "${RYUKI_CARGO_MAX_TARGET_GIB-}"
  printf 'RYUKI_CARGO_MIN_FREE_GIB=%s\n' "${RYUKI_CARGO_MIN_FREE_GIB-}"
  printf 'RYUKI_CARGO_GUARD_INTERVAL_SECONDS=%s\n' \
    "${RYUKI_CARGO_GUARD_INTERVAL_SECONDS-}"
  if [[ -e /dev/fd/9 || -e /proc/self/fd/9 ]]; then
    printf 'FD9=open\n'
  else
    printf 'FD9=closed\n'
  fi
  for argument in "$@"; do
    printf 'ARG=%s\n' "$argument"
  done
} > "$RYUKI_DEV_TEST_CAPTURE"

case "${RYUKI_DEV_TEST_BEHAVIOR:-capture}" in
  capture)
    exit 0
    ;;
  grow)
    : "${RYUKI_DEV_TEST_READY:?missing grower ready path}"
    : "${RYUKI_DEV_TEST_PID:?missing grower pid path}"
    printf '%s\n' "$$" > "$RYUKI_DEV_TEST_PID"
    dd if=/dev/zero of="$CARGO_TARGET_DIR/guard-growth.bin" \
      bs=1 count=0 seek=27262976000 2>/dev/null
    touch "$RYUKI_DEV_TEST_READY"
    while :; do sleep 1; done
    ;;
  detach)
    : "${RYUKI_DEV_TEST_READY:?missing detached ready path}"
    : "${RYUKI_DEV_TEST_PID:?missing detached pid path}"
    (
      trap 'exit 0' INT TERM
      touch "$RYUKI_DEV_TEST_READY"
      while :; do sleep 1; done
    ) &
    printf '%s\n' "$!" > "$RYUKI_DEV_TEST_PID"
    exit 0
    ;;
  hold)
    : "${RYUKI_DEV_TEST_READY:?missing hold ready path}"
    : "${RYUKI_DEV_TEST_PID:?missing hold pid path}"
    printf '%s\n' "$$" > "$RYUKI_DEV_TEST_PID"
    touch "$RYUKI_DEV_TEST_READY"
    trap 'exit 0' HUP INT TERM
    while :; do sleep 1; done
    ;;
  clean-target)
    rm -rf -- "$CARGO_TARGET_DIR"
    ;;
  *)
    printf 'error: unsupported fake Cargo behavior\n' >&2
    exit 64
    ;;
esac
