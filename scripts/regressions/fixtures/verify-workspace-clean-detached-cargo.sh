#!/usr/bin/env bash
set -Eeuo pipefail

: "${RYUKI_VERIFY_TEST_DETACHED_PID:?missing descendant pid path}"
: "${RYUKI_VERIFY_TEST_DETACHED_READY:?missing descendant ready path}"
: "${RYUKI_VERIFY_TEST_DETACHED_ATTEMPTED:?missing recreation attempt path}"
: "${RYUKI_VERIFY_TEST_DETACHED_TARGET:?missing target capture path}"

printf '%s\n' "$CARGO_TARGET_DIR" > "$RYUKI_VERIFY_TEST_DETACHED_TARGET"
set -m
(
  trap '' HUP
  trap 'exit 0' INT TERM
  touch "$RYUKI_VERIFY_TEST_DETACHED_READY"
  while [[ -e "$CARGO_TARGET_DIR" ]]; do
    sleep 0.05
  done
  mkdir -p "$CARGO_TARGET_DIR"
  touch "${CARGO_TARGET_DIR}/detached-recreated"
  touch "$RYUKI_VERIFY_TEST_DETACHED_ATTEMPTED"
  while :; do
    sleep 1
  done
) &
descendant_pid=$!
set +m
printf '%s\n' "$descendant_pid" > "$RYUKI_VERIFY_TEST_DETACHED_PID"

for _ in {1..200}; do
  [[ -e "$RYUKI_VERIFY_TEST_DETACHED_READY" ]] && break
  sleep 0.01
done
[[ -e "$RYUKI_VERIFY_TEST_DETACHED_READY" ]] || exit 75
wait "$descendant_pid"
