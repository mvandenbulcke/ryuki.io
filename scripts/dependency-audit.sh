#!/usr/bin/env bash
set -euo pipefail

required_audit_version="0.22.2"
if ! audit_version="$(cargo audit --version 2>/dev/null)"; then
  echo "cargo-audit is required: cargo install cargo-audit --version 0.22.2 --locked" >&2
  exit 1
fi
if [ "$audit_version" != "cargo-audit-audit $required_audit_version" ]; then
  echo "cargo-audit $required_audit_version is required (found: $audit_version)" >&2
  exit 1
fi

# Cargo.lock includes jsonwebtoken's disabled optional RustCrypto backend.
# Keep its no-fix RSA advisory ignored only while the crate is unreachable.
if ! active_rsa_tree="$(cargo tree --workspace --all-features --target all -i rsa 2>/dev/null)"; then
  echo "error: could not verify the active workspace dependency graph" >&2
  exit 1
fi
if printf '%s\n' "$active_rsa_tree" | grep -q '^rsa v'; then
  echo "error: advisory-affected rsa crate is active in the workspace graph" >&2
  exit 1
fi

cargo audit
cargo audit --file portal/portal-ui/Cargo.lock
cargo audit --file sources/ryuki-engine/Cargo.lock
