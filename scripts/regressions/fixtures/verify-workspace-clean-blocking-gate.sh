#!/usr/bin/env bash
set -Eeuo pipefail

printf '%s\n' "$$" > "$RYUKI_VERIFY_TEST_BLOCKER_PID"
touch "$RYUKI_VERIFY_TEST_READY"
while [[ ! -e "$RYUKI_VERIFY_TEST_RELEASE" ]]; do
  sleep 0.05
done
