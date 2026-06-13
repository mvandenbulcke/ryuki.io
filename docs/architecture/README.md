# Architecture

This directory holds the cross-cutting architecture references for the Ryuki
platform. Each page describes a platform-wide invariant that individual slices,
contracts, and deploy manifests are expected to honour.

## Security Baseline

The platform's non-negotiable security rules are defined in
[security-baseline.md](security-baseline.md) and mirrored by the static
`/api/platform/security-baseline-contract` endpoint: no committed secrets, an
ordered execution lifecycle, browser isolation, deny-all network policy, evidence
redaction, and adapter least privilege.

## Vault foundation

The committed Vault configuration is a static skeleton: the repository does not
contain initialized Vault data, and no unseal keys or root tokens are stored.
Azure Key Vault auto-unseal remains an environment overlay applied per
environment at deploy-time, never committed to the repository.
