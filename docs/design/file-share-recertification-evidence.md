# File-share recertification evidence boundary

Status: implemented locally for security finding
`csf_c42dc76098d8a30d7e7249f1` (`R01-MB-C140`). Runtime verification remains
part of the repository-wide remediation wave.

## Invariant

A file share may be represented as `Compliant` only when an immutable
`AuthoritativeProviderSnapshot` proves a trusted collector principal and
attestation reference, the exact locked share version and site, provider ACL
snapshot version and SHA-256 digest, owner attestation and evidence reference,
authenticated reviewer and evidence reference, separate approver, completed
group, NTFS ACL, share-permission and stale-access reviews, freshness window,
evidence manifest, and zero unresolved findings.

Missing, partial, stale, foreign, version-mismatched, or static-fixture evidence
is `Indeterminate`. It never advances recertification dates and never writes a
Compliant share state.

## API contract

`POST /api/identity/shares/recertify/{id}` accepts only:

```json
{"evidenceId":"<immutable evidence UUID>"}
```

The reviewer is always `AuthSession.user_id`; a client-supplied reviewer is an
unknown field and is rejected. Missing or malformed evidence identifiers fail
closed. An evidence identifier bound to another share is indistinguishable from
missing evidence. Scope is checked against the share row after it is locked.

The decision response names the decision and evidence references, exact share
version/site, provider ACL snapshot version/digest, authenticated reviewer,
database-owned review time, evidence source, result and reason. It never returns
raw ACL rows or provider payloads.

## Durable lifecycle

Migration `179_file_share_recertification_evidence.sql` adds:

- `file_shares.governance_version`, advanced whenever protected share metadata
  or an NTFS permission row changes;
- an append-only evidence table;
- an append-only decision table with a unique evidence id (the idempotency key);
- a database-owned decision timestamp and exact 8760-hour due window, neither
  of which an alternate caller can extend;
- a database guard that forbids creating or rewriting a
  `file_shares.status = 'Compliant'` state without a referenced, unexpired
  immutable decision whose review and due timestamps exactly match the share
  row.

The request transaction locks the share, returns an existing decision on retry,
evaluates new evidence, appends one decision, conditionally advances the share,
and appends one actor-attributed hash-chain audit event. Any failure rolls the
whole transaction back. An `Indeterminate` decision is persisted as review
history but does not overwrite an earlier still-valid compliant decision.

Raw database writers remain a restricted trusted boundary. PostgreSQL enforces
the evidence-to-decision-to-share projection, while atomic audit append is
enforced by the sole application write path's caller-owned transaction; direct
write privileges must not be exposed as an alternate recertification API.

Existing `Compliant` rows predate this evidence boundary. The migration marks
them `NeedsRecertification` and makes them due rather than grandfathering an
unsupported compliance claim.

## Provider and fixture boundary

Provider calls, worker execution, live share changes and live ACL changes remain
disabled. There is deliberately no public evidence-ingestion route. A trusted
collector may later insert `AuthoritativeProviderSnapshot` rows through a
separately approved capability. Until that integration and its operational
identity are configured, no new live compliant decision is possible.

`StaticFixture` rows remain useful for deterministic development, but the policy
always evaluates them as `Indeterminate`; fixture state is never described as
live compliance.

## Focused proof

Engine regression coverage includes missing, partial, stale, foreign-share,
foreign-scope, stale-version, reviewer-mismatch, maker/checker-reuse and static
fixture negatives, plus a complete authoritative positive. The database test
exercises the real transaction, proves exact idempotent replay, verifies the
Compliant row references its decision, asserts exactly one audit append, keeps
Indeterminate share-state audit fields truthful, and directly probes forged
decision timestamps, extended share due dates and StaticFixture promotion.
