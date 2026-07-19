# Certificate inventory and expiry query bounds

Status: implemented. C278/C279 replaced the original fetch-all and offset
inventory paths with fixed, signed keysets whose database work is bounded by
the requested page and authorized site count.

## API contract

`GET /api/maintain/certificates/inventory` returns a bare JSON array in one
fixed order: `(created_at DESC, id DESC)`. It accepts `limit` and an opaque
`cursor`, defaults to 50 rows, caps the page at 100, fetches one lookahead row,
and emits `X-Next-Cursor` only when another page exists. It never computes or
emits an exact total.

The old `offset`, `include_total`, `status`, `hostname`, `q`, `sort`, and
`direction` names remain deserializable only to provide an explicit migration
error. A non-zero offset, `include_total=true`, nonblank filter, alternate sort,
or ascending direction returns 400 before database work. Blank legacy fields,
`sort=created_at`, and descending direction do not alter the fixed query.

The inventory cursor is an HMAC-SHA256-authenticated envelope containing its
version, a digest of the normalized authorized site set, and the last
`(created_at,id)` tuple. It is rejected if malformed, oversized, modified, or
replayed under a different scope. The production signing key is the validated
`RYUKI_SECURITY__CERTIFICATE_CURSOR_HMAC_KEY`, which must not equal the
persisted-session verifier key. Credential-free, loopback-only mock/static
dry-run modes use one CSPRNG-generated process-ephemeral key, so their
continuations remain valid until restart without relying on a default secret;
persisted auth modes and enabled generic OIDC fail closed when the configured
key is unavailable or malformed. Rotating the dedicated key invalidates
outstanding continuations. Tests use a fixed non-production key and separately
exercise the production key selector.

`GET /api/maintain/certificates/expiring` likewise accepts `limit` and an
authenticated opaque cursor. It defaults to 100 rows, caps at 200, and orders
by `(valid_to ASC, id ASC)`. Its signed claims bind the normalized site, days
window, first-page `expires_before` timestamp, and last tuple. Non-zero legacy
offset is rejected, the days range is checked before date arithmetic, and no
count query runs.

Expiry traversal is bounded and at-least-once, not a cross-request MVCC
snapshot. `expires_before` is fixed by the first cursor, but `valid_to` is a
mutable renewal field. A certificate whose deadline moves from before to after
the last emitted tuple can therefore appear again; clients must deduplicate by
certificate `id`. Unchanged rows are visited exactly once in keyset order.

## Enforcement boundary

Certificate records are site-only. The handler resolves authorization before
the repository call:

- `Empty` returns an empty page without reading certificate rows;
- `All` uses the global keyset index;
- `Sites` sorts and deduplicates at most 64 authorized sites, takes at most B+1
  indexed rows per site with a LATERAL probe, and merges only those bounded
  candidates into the global order.

The per-site merge prevents a sparse authorized scope from walking past an
unbounded foreign population in a global index. Cursor claims bind the exact
normalized scope, so a continuation cannot widen or switch authorization.
Authorization scopes above 64 sites fail before repository work, and any
nonempty site authority outside the 1-32 UTF-8-octet envelope is rejected.

Migration 172 creates exact, named indexes for the four leaf probes:

- inventory: `(created_at DESC, id DESC)` and
  `(site, created_at DESC, id DESC)`;
- expiry: `(valid_to ASC, id ASC)` and
  `(site, valid_to ASC, id ASC)`.

The original schema allowed an unbounded `certificates.site`. Migration 172
adds the named `certificates_site_query_bounds` check as `NOT VALID`, which
rejects every new direct write outside 1-32 octets without scanning or mutating
legacy data. All four indexes are partial on that identical predicate, and all
inventory/expiry queries include it, so a pre-existing oversized row cannot
abort btree creation and remains quarantined from list traversal. Operators
review rows matching `NOT (octet_length(site) BETWEEN 1 AND 32)`, then explicitly
normalize, delete, or move them to an approved quarantine before validating the
constraint. No site is silently truncated or hash-rewritten.

The index statements do not use name-only `IF NOT EXISTS`, preventing an
incorrect pre-existing definition from silently satisfying the migration.

## Verification coverage

Focused tests cover default and maximum page sizes, equal-timestamp UUID ties,
signed cursor round trips, tampering and scope mismatch, legacy option
rejection, multi-site merge order across pages, environment-scope fail-closed
behavior, the exact 64/65-site boundary, a 2B+1 authenticated expiry traversal
amid foreign/out-of-window rows, mutable-key at-least-once behavior, invalid
days/sites, catalog definitions, and JSON plans for scoped/global inventory,
the real scoped LATERAL merge, and scoped/global expiry indexes. A transactional
rollout probe installs migration 172 over a 3,000-octet legacy site, proves the
row is preserved but excluded, and rolls the schema/data fixture back; direct
writer coverage asserts the named constraint and SQLSTATE.

## Compatibility change

Inventory filtering, exact totals, alternate sorting, and numeric offsets are
intentionally unavailable because their prior shapes admitted population-sized
work. Clients traverse the fixed newest-first keyset through `X-Next-Cursor`.
The routes and bare-array response shape remain unchanged.
