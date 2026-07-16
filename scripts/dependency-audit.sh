#!/usr/bin/env bash
set -euo pipefail

required_audit_version="0.22.2"
policy_path=".cargo/vulnerability-exceptions.json"
audit_config_path=".cargo/audit.toml"
policy_validator="scripts/validate-vulnerability-policy.py"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to validate vulnerability exception policy" >&2
  exit 1
fi
python3 "$policy_validator" exceptions \
  --policy "$policy_path" \
  --audit-config "$audit_config_path"

if ! audit_version="$(cargo audit --version 2>/dev/null)"; then
  echo "cargo-audit is required: cargo install cargo-audit --version 0.22.2 --locked" >&2
  exit 1
fi
if [ "$audit_version" != "cargo-audit-audit $required_audit_version" ]; then
  echo "cargo-audit $required_audit_version is required (found: $audit_version)" >&2
  exit 1
fi

lockfiles=()
while IFS= read -r -d '' lockfile; do
  lockfiles+=("$lockfile")
done < <(git ls-files -z -- '*Cargo.lock')
if [ "${#lockfiles[@]}" -eq 0 ]; then
  echo "error: no tracked Cargo.lock files found" >&2
  exit 1
fi

# The admitted RSA exception is scoped to the root lockfile. Cargo records the
# unused sqlx MySQL driver there even though Ryuki enables only PostgreSQL. A
# second lockfile containing RSA must not inherit the root exception.
if ! grep -q '^name = "rsa"$' Cargo.lock; then
  echo "error: the RSA exception is stale because Cargo.lock no longer contains rsa" >&2
  exit 1
fi
for lockfile in "${lockfiles[@]}"; do
  if [ "$lockfile" != "Cargo.lock" ] && grep -q '^name = "rsa"$' "$lockfile"; then
    echo "error: RSA exception is not admitted for $lockfile" >&2
    exit 1
  fi
done
if ! active_rsa_tree="$(cargo tree --locked --workspace --all-features --target all -i rsa 2>/dev/null)"; then
  echo "error: could not verify the locked workspace dependency graph" >&2
  exit 1
fi
if printf '%s\n' "$active_rsa_tree" | grep -q '^rsa v'; then
  echo "error: advisory-affected rsa crate is active in the locked workspace graph" >&2
  exit 1
fi

# Fetch into a new private directory for every gate. All lockfiles are then
# audited against that one revision with network refresh disabled, so their
# results cannot straddle advisory-database updates.
advisory_tmp="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-advisory-db.XXXXXX")"
advisory_db="$advisory_tmp/database"
cleanup() {
  rm -rf "$advisory_tmp"
}
trap cleanup EXIT INT TERM

for index in "${!lockfiles[@]}"; do
  lockfile="${lockfiles[$index]}"
  printf 'Auditing tracked lockfile: %s\n' "$lockfile"
  if [ "$index" -eq 0 ]; then
    cargo audit --db "$advisory_db" --file "$lockfile"

    revision="$(git -C "$advisory_db" rev-parse HEAD)"
    commit_epoch="$(git -C "$advisory_db" show -s --format=%ct HEAD)"
    remote_url="$(git -C "$advisory_db" remote get-url origin)"
    fetch_epoch="$(date +%s)"
    python3 "$policy_validator" advisory-db \
      --policy "$policy_path" \
      --revision "$revision" \
      --commit-epoch "$commit_epoch" \
      --fetch-epoch "$fetch_epoch" \
      --remote-url "$remote_url"
  else
    cargo audit --db "$advisory_db" --no-fetch --file "$lockfile"
  fi
done
