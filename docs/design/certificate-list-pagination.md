# Certificate list — pagination + filtering on /inventory

Status: implemented (codex plan APPROVE; 4 MINORs folded in — (1) trim params, blank→absent,
invalid sort/direction → 400, invalid status → no-match; (2) parse rfc3339→DateTime for
date-column sorts; (3) stable sort over repo-ordered input = deterministic ties; (4) tests
isolate via a unique CN prefix + q, deterministic sort assertions, env-scoped
X-Total-Count==0). Verify-first swarm 2026-06-29 finding #8.
VERIFIED: certificate routes are request/validate/approve/install/verify/renew/revoke +
`/expiring` + `/inventory` + `/{id}`. `certificates_inventory` (contracts.rs:24435) is the
flat list — it loads `repos::certificates::list(pool)` (ORDER BY created_at DESC, id DESC),
`retain_site_scoped`s, and returns a BARE ARRAY with NO limit/offset, NO filtering, NO
X-Total-Count.

## Design decision — ENHANCE /inventory in place (DIVERGES from the swarm's "new endpoint")
The swarm recommended a NEW `GET /api/maintain/certificates`. But `/inventory` ALREADY IS
the cert list; a second parallel list endpoint would duplicate it. The codebase precedent
is `requests_list` (15184): it added limit/offset/filters + an `X-Total-Count` header to
the EXISTING `GET /api/requests` while keeping the bare-array body backward-compatible. So
this enhances `/inventory` the same way — no new route, no duplication.

## Scope — reuse `retain_site_scoped` VERBATIM (no SQL-scope re-derivation)
Certs are SITE-ONLY: `retain_site_scoped` (contracts.rs:23228) returns EMPTY for any
environment-scoped principal (fail-closed — certs have no environment) and filters the rest
by `site_scope`. `requests_list`'s dual-axis `enforce_scope_filters` (SQL `enforce`) is the
WRONG model here and re-deriving site scope in SQL risks a multi-site leak. So filtering +
pagination are applied IN-HANDLER, AFTER `retain_site_scoped` — the endpoint already loads
all + scope-filters in memory, so this adds NO new scalability concern, and the proven
scope boundary is untouched.

## Handler change (certificates_inventory)
Add `Query(params): Query<CertListParams>` where ALL fields are `Option` (opt-in):
`{ limit, offset, status, hostname, q, sort, direction }`. Flow:
1. Load `list(pool)` → `retain_site_scoped(&session, ...)` (UNCHANGED).
2. Opt-in, case-insensitive filters (a blank/absent param = no filter):
   - `status`: `r.status.to_string().eq_ignore_ascii_case(s)` (CertificateStatus has Display:
     Active/Expiring/Expired/Revoked).
   - `hostname`: substring on `r.hostname`.
   - `q`: substring on `r.common_name` OR `r.subject`.
3. `total = filtered.len()` (BEFORE limit/offset) → `total_count_headers(total)` (the existing
   `X-Total-Count` helper, additive — harmless to current callers).
4. Sort: ONLY if `sort` is given — allowlisted column
   (common_name/valid_from/valid_to/status/hostname/site/created_at) + direction (asc/desc,
   default desc). If `sort` is ABSENT, PRESERVE the repo order (created_at DESC, id DESC) —
   so the no-param response is byte-for-byte the current one. (Date fields are rfc3339
   strings → lexicographic sort = chronological.)
5. Paginate: `offset` default 0; `limit` is `Option` — **None = return ALL** (backward-compat:
   `/inventory` is currently unbounded; a default page size would TRUNCATE existing callers).
   An explicit `limit` only REDUCES the result (the endpoint was already unbounded, so no new
   DoS surface). `skip(offset).take(limit_or_all)`.
6. Return `(headers, Json(bare array of the page))`.

BACKWARD-COMPAT: with NO query params the body is identical to today (all scoped certs,
newest-first); only an additive `X-Total-Count` header is new.

## Tests (contracts.rs cert db-tests, single-threaded; + a no-DB shape test)
1. **no params = unchanged**: seed certs; GET → all scoped certs, newest-first; `X-Total-Count`
   == count; body is a bare array.
2. **status filter**: `?status=active` → only Active; X-Total-Count == active count.
3. **q search**: `?q=<cn-substring>` → CN/subject matches only (case-insensitive).
4. **hostname filter**: `?hostname=<sub>` → matches.
5. **pagination**: `?limit=1&offset=1` → exactly one item (the 2nd), X-Total-Count == FULL
   filtered total (not the page length).
6. **sort**: `?sort=common_name&direction=asc` → ordered ascending by CN.
7. **scope**: a site-scoped session → only its site's certs; an environment-scoped session →
   empty (retain_site_scoped fail-closed preserved).
Use fresh-UUID cert ids + per-id assertions (shared DB); cleanup each seeded cert.

## Files
- sources/ryuki-api/src/contracts.rs (CertListParams + the certificates_inventory body +
  a cert_sort_column allowlist + tests). NO new route, NO migration, NO engine change, NO
  repo change (reuses list()).

## Out of scope
- A separate `GET /api/maintain/certificates` collection path (the swarm's framing) —
  `/inventory` is the list; a parallel path would duplicate it.
- SQL-level pagination (the endpoint already loads-all; cert counts are modest, and
  in-handler keeps the proven scope semantics).
- The `{items,total}` envelope (kept a bare array, like requests_list, for client compat).
- CORS `Access-Control-Expose-Headers: X-Total-Count` for cross-origin browser clients
  (codex impl note) — an integration/config follow-up if/when a JS client must read the
  header cross-origin; not a handler concern.

## Codex review (both rounds APPROVE)
Plan APPROVE (4 MINORs folded in); impl APPROVE, no BLOCKER/MAJOR. Two accepted
non-blocking impl MINORs: (1) `cert_sort_cmp`'s parse-fallback is not a perfect total
order IF malformed + non-UTC-offset rows coexist — but the repo always emits well-formed
UTC RFC3339 (from `DateTime<Utc>`), so the invariant holds; (2) no dedicated date-sort
fixture — the sort machinery is proven by the common_name sort test and the date branch is
the same `sort_by` path with a parsed compare.
