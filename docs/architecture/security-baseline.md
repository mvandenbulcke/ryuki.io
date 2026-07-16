# Security Baseline

The security baseline is the set of non-negotiable rules every Ryuki component
must satisfy. It is mirrored by the static `/api/platform/security-baseline-contract`
endpoint and enforced by the `security-baseline` validator slice. The platform is
evidence-first and provider-safe: nothing here enables live execution on its own.

## One platform security boundary

Every human, service, agent, webhook, callback, and internal worker must cross
the same normalized admission, authorization, transition, and audit boundary.
No portal check, route-local role test, signed payload, development identity, or
network location grants authority on its own. Production must fail closed on
invalid configuration and missing identity, database, secret, or signing-key
dependencies.

The complete target-state invariants and implementation gates are defined in the
[Platform Security Boundary Specification](platform-security-boundary.md). The
specification is normative for production acceptance and intentionally
distinguishes required behavior from what is already implemented.

## No committed secrets

Secrets must never be committed. Credentials, tokens, private keys, and
connection material live in the secret provider and are injected at deploy- and
run-time; manifests and source reference them by name only. The `no-secret-scan`
script gates every change against access-key, private-key, and token patterns.

## Dependency and cryptographic implementation integrity

Every tracked lockfile is checked against current RustSec advisory data. An
advisory may be ignored only with a documented applicability decision and an
executable guard that fails if the affected crate or feature becomes reachable;
an unverified blanket allowlist is not acceptable. The
`scripts/dependency-audit.sh` gate enforces this rule for the workspace and
standalone lockfiles. Cryptographic providers are selected explicitly and must
pass the same authentication negative tests after a backend change.

## Execution lifecycle

Live execution requires validation, approval, locking, execution, verification, evidence, and status callback. Each request advances through these gates in order; skipping a gate is a blocking error, and every gate writes a redacted evidence record before the next one can begin.

## Browser isolation

Browser code must call only `portal-ui` and `platform-api`. The portal never
talks to adapters, providers, the database, or the secret store directly; all
privileged work is brokered server-side behind the typed boundary.

## Network policy

Network policy starts from deny-all. Every allowed flow is an explicit,
least-privilege exception scoped to the two components that need it; there is no
default-allow egress or ingress anywhere in the platform.

## Evidence redaction

Evidence must be redacted before storage, export, display, or indexing. Raw
provider payloads, raw rows, identifiers, and credential material are stripped by
the evidence pipeline so that no downstream surface can leak sensitive detail.

## Adapter least privilege

Each adapter must use its own identity. Adapter credentials are scoped to a single
provider integration, fail closed when missing, and are never shared across
adapters or reused by the platform control plane.
