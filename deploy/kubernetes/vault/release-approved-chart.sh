#!/usr/bin/env bash
set -Eeuo pipefail

# Validate, render, lint, and optionally install one private copy of an
# independently approved Vault chart archive. The source archive is never
# passed to Helm: every consumer receives the same digest-checked snapshot.

fail() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  echo "usage: $0 verify|install" >&2
  exit 64
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

mode="${1:-}"
case "$mode" in
  verify|install) ;;
  *) usage ;;
esac

: "${VAULT_HELM_CHART_ARCHIVE:?set to the approved local chart archive}"
: "${VAULT_HELM_CHART_VERSION:?set the exact approved MAJOR.MINOR.PATCH version}"
: "${VAULT_HELM_CHART_SHA256:?set the approved lowercase SHA-256 digest}"

[[ "$VAULT_HELM_CHART_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
  || fail "chart version must be exact MAJOR.MINOR.PATCH"
[[ "$VAULT_HELM_CHART_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || fail "chart SHA-256 must contain 64 lowercase hex characters"
[[ -f "$VAULT_HELM_CHART_ARCHIVE" && ! -L "$VAULT_HELM_CHART_ARCHIVE" ]] \
  || fail "approved chart archive must be a regular non-symlink file"
command -v helm >/dev/null 2>&1 || fail "helm is required"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
values_file="$root_dir/deploy/kubernetes/vault/values-ha-raft.yaml"
[[ -f "$values_file" ]] || fail "Vault values file is missing"

umask 077
snapshot_dir="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-vault-chart.XXXXXX")"
chart_snapshot="$snapshot_dir/vault-chart.tgz"

cleanup() {
  rm -rf "$snapshot_dir"
}
trap cleanup EXIT INT TERM

cp "$VAULT_HELM_CHART_ARCHIVE" "$chart_snapshot"
chmod 0400 "$chart_snapshot"

assert_snapshot() {
  local actual
  [[ -f "$chart_snapshot" && ! -L "$chart_snapshot" ]] \
    || fail "private chart snapshot is no longer a regular file"
  actual="$(sha256_file "$chart_snapshot")"
  [[ "$actual" == "$VAULT_HELM_CHART_SHA256" ]] \
    || fail "chart SHA-256 mismatch"
}

assert_snapshot
chart_metadata="$(helm show chart "$chart_snapshot")"
grep -Fx "version: $VAULT_HELM_CHART_VERSION" <<<"$chart_metadata" >/dev/null \
  || fail "chart archive version does not match VAULT_HELM_CHART_VERSION"
assert_snapshot

helm template vault "$chart_snapshot" \
  --namespace vault \
  -f "$values_file"
assert_snapshot

helm lint "$chart_snapshot" -f "$values_file"
assert_snapshot

if [[ "$mode" == "install" ]]; then
  helm upgrade --install vault "$chart_snapshot" \
    --namespace vault \
    --create-namespace \
    -f "$values_file"
  assert_snapshot
fi

echo "approved Vault chart $mode completed for version $VAULT_HELM_CHART_VERSION ($VAULT_HELM_CHART_SHA256)"
