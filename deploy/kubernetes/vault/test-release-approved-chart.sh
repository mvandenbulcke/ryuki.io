#!/usr/bin/env bash
set -Eeuo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
subject="$here/release-approved-chart.sh"
fixture="$here/tests/fake-helm.sh"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-vault-chart-test.XXXXXX")"

cleanup() {
  rm -rf "$test_dir"
}
trap cleanup EXIT INT TERM

fail() {
  echo "test failure: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

assert_fails() {
  local expected="$1"
  shift
  local output="$test_dir/failure-output"
  if "$@" >"$output" 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
  grep -F "$expected" "$output" >/dev/null \
    || fail "failure output did not contain: $expected"
}

mkdir -p "$test_dir/bin"
ln -s "$fixture" "$test_dir/bin/helm"
export PATH="$test_dir/bin:$PATH"
export FAKE_CHART_VERSION="1.18.3"

if grep -E 'helm[[:space:]]+(repo|pull)' "$subject" >/dev/null; then
  fail "release wrapper must not resolve a repository name or tag"
fi

original="$test_dir/approved-vault-chart.tgz"
log="$test_dir/helm.log"
printf 'independently-approved-chart-bytes\n' >"$original"
approved_digest="$(sha256_file "$original")"
export FAKE_ORIGINAL_ARCHIVE="$original"
export FAKE_HELM_LOG="$log"

VAULT_HELM_CHART_ARCHIVE="$original" \
VAULT_HELM_CHART_VERSION="$FAKE_CHART_VERSION" \
VAULT_HELM_CHART_SHA256="$approved_digest" \
  "$subject" install >"$test_dir/install-output"

[[ "$(sed -n '$=' "$log")" == "4" ]] || fail "install must make exactly four Helm calls"
[[ "$(cut -d'|' -f1 "$log" | paste -sd, -)" == "show,template,lint,upgrade" ]] \
  || fail "Helm calls must be show, template, lint, then upgrade"
[[ "$(cut -d'|' -f2 "$log" | sort -u | sed -n '$=')" == "1" ]] \
  || fail "all Helm consumers must receive one snapshot path"
[[ "$(cut -d'|' -f3 "$log" | sort -u | sed -n '$=')" == "1" ]] \
  || fail "all Helm consumers must receive identical bytes"
grep -F "|$approved_digest" "$log" >/dev/null \
  || fail "Helm consumers did not receive the approved digest"
grep -F "|$original|" "$log" >/dev/null \
  && fail "the mutable source archive reached Helm"
grep -Fx 'mutated-untrusted-source' "$original" >/dev/null \
  || fail "the mutation probe did not change the source archive"

: >"$log"
printf 'independently-approved-chart-bytes\n' >"$original"
VAULT_HELM_CHART_ARCHIVE="$original" \
VAULT_HELM_CHART_VERSION="$FAKE_CHART_VERSION" \
VAULT_HELM_CHART_SHA256="$approved_digest" \
  "$subject" verify >"$test_dir/verify-output"
[[ "$(cut -d'|' -f1 "$log" | paste -sd, -)" == "show,template,lint" ]] \
  || fail "verify mode must not install"

: >"$log"
printf 'independently-approved-chart-bytes\n' >"$original"
assert_fails "chart SHA-256 mismatch" \
  env VAULT_HELM_CHART_ARCHIVE="$original" \
      VAULT_HELM_CHART_VERSION="$FAKE_CHART_VERSION" \
      VAULT_HELM_CHART_SHA256="$(printf '0%.0s' {1..64})" \
      "$subject" install
[[ ! -s "$log" ]] || fail "digest mismatch must fail before Helm"

: >"$log"
printf 'independently-approved-chart-bytes\n' >"$original"
assert_fails "chart archive version does not match" \
  env FAKE_CHART_VERSION="1.18.4" \
      VAULT_HELM_CHART_ARCHIVE="$original" \
      VAULT_HELM_CHART_VERSION="1.18.3" \
      VAULT_HELM_CHART_SHA256="$approved_digest" \
      "$subject" install
[[ "$(cut -d'|' -f1 "$log" | paste -sd, -)" == "show" ]] \
  || fail "version mismatch must fail before render, lint, or install"

: >"$log"
printf 'independently-approved-chart-bytes\n' >"$original"
assert_fails "chart SHA-256 mismatch" \
  env FAKE_TAMPER_SNAPSHOT_ON="template" \
      VAULT_HELM_CHART_ARCHIVE="$original" \
      VAULT_HELM_CHART_VERSION="$FAKE_CHART_VERSION" \
      VAULT_HELM_CHART_SHA256="$approved_digest" \
      "$subject" install
[[ "$(cut -d'|' -f1 "$log" | paste -sd, -)" == "show,template" ]] \
  || fail "snapshot tampering must stop before lint or install"

assert_fails "chart version must be exact MAJOR.MINOR.PATCH" \
  env VAULT_HELM_CHART_ARCHIVE="$original" \
      VAULT_HELM_CHART_VERSION="latest" \
      VAULT_HELM_CHART_SHA256="$approved_digest" \
      "$subject" verify

symlink_archive="$test_dir/approved-vault-chart-link.tgz"
ln -s "$original" "$symlink_archive"
assert_fails "regular non-symlink file" \
  env VAULT_HELM_CHART_ARCHIVE="$symlink_archive" \
      VAULT_HELM_CHART_VERSION="$FAKE_CHART_VERSION" \
      VAULT_HELM_CHART_SHA256="$approved_digest" \
      "$subject" verify

echo "approved Vault chart release tests passed"
