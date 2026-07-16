# CMDB CI GET — read a configuration item from the real table

Status: SHIPPED (plan NEEDS-CHANGES → 2 MAJOR + 2 MINOR folded in; implementation
APPROVE, no findings). Verify-first swarm 2026-06-29 finding #18.
VERIFIED: the `configuration_items` table (mig 014: id UUID PK, ci_name TEXT UNIQUE, ci_type
CHECK(Server/Application/Database/Network/Storage), criticality CHECK(Low/Medium/High/
Critical), site, owner, created_at, updated_at) is SEEDED (13 CIs) but NO API or repo reads
it — there is no `repos/configuration_items.rs`. Every existing `/api/cmdb/*` endpoint is an
UNAUTHENTICATED mock/contract read: the impact endpoints (`/api/cmdb/impact/upstream/
{ci_name}` etc.) read an in-memory `cmdb_impact::seeded_graph` (NOT the table), and
`/api/cmdb/export` reads `cmdb_engine::import_cmdb_records` (hardcoded mock). So this GET is
the FIRST authenticated, DB-backed, site-scoped CMDB read. Additive: NO migration, NO engine
change.

## Endpoint — GET /api/cmdb/cis/{ci_name}
By the UNIQUE `ci_name` (DIVERGES from the swarm's `{id}` framing): clients know the CI name
(it is the human key used across the impact endpoints, e.g. `/api/cmdb/impact/upstream/
{ci_name}`), and there is no CI list endpoint to discover the UUID. By-name is the practical,
consistent choice; a by-UUID variant is a trivial follow-up.

`cmdb_ci_get(AuthExtractor(session), Path(ci_name))`:
1. `get_db()` → 503 if absent.
2. `repos::configuration_items::get_by_name(pool, &ci_name)` → `None` ⇒ 404.
3. `scope_guard_or_404(&session, &ci.site, "", &ci_name)` — SITE-only (CIs have a `site`, no
   environment), exactly like `certificates_get`: an out-of-scope CI 404s like a missing one
   (no oracle).
4. Return the CI as JSON.

AUTH: AuthExtractor requires a valid session (unlike the unauthenticated mock endpoints).
The central read gate maps `/api/cmdb/...` (not a sensitive-read prefix) to the `audit` read
tier; the handler adds the site-scope guard — mirroring `certificates_get` (a valid
audit-holder, in scope, reads it).

## Repo — repos/configuration_items.rs (new module)
Register `pub mod configuration_items;` in repos/mod.rs.
```rust
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct ConfigurationItem {
    pub id: String,        // id::text
    pub ci_name: String,
    pub ci_type: String,
    pub criticality: String,
    pub site: String,
    pub owner: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
pub async fn get_by_name(pool: &PgPool, ci_name: &str) -> Result<Option<ConfigurationItem>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id::text AS id, ci_name, ci_type, criticality, site, owner, created_at, updated_at \
         FROM configuration_items WHERE ci_name = $1",
    ).bind(ci_name).fetch_optional(pool).await
}
```
(No FK from configuration_items to anything that would need joining; `ci_relationships` is a
separate concern surfaced by the impact endpoints, out of scope here.) The serialized JSON
exposes id/ci_name/ci_type/criticality/site/owner/timestamps — infra metadata, no secrets.

## Route
`.route("/api/cmdb/cis/{ci_name}", get(cmdb_ci_get))` — `cis` is a new segment (no collision
with import/reconcile/export/impact).

## Tests (contracts.rs cmdb db-tests + a no-DB shape test)
1. **happy** (DB): seed a CI (fresh unique ci_name, site GBLON, ci_type Server, criticality
   High, owner X); GET by name → 200 with all fields (ci_name/ci_type/criticality/site/owner)
   matching.
2. **404** (DB): an unknown ci_name → 404.
3. **scope** (DB): the seeded GBLON CI; a DEFRA-scoped session → 404 (no oracle); a
   GBLON-scoped (or unscoped) session → 200.
4. **no-DB**: GET with no DB → 503 (mirrors certificates_get's no-DB 404? — certificates_get
   returns 404 with no DB; for CMDB I 503 since the table is the source of truth and there is
   no in-memory CI store — confirm in plan review).
Seed via a direct INSERT with a unique ci_name; clean up.

## Files
- sources/ryuki-api/src/repos/configuration_items.rs (new) + repos/mod.rs (register).
- sources/ryuki-api/src/contracts.rs (cmdb_ci_get + route + tests). NO migration, NO engine.

## Out of scope
- A CI LIST endpoint (and a by-UUID variant) — follow-ups.
- Migrating the impact graph from the in-memory mock to the DB table (a larger, separate
  change; this slice just exposes the table by name).
- ci_relationships traversal (the impact endpoints' concern).

## Plan-review fixes (SUPERSEDE the body where they conflict)
- **MAJOR 1 — AUDIT-only (explicit handler check).** The central read gate authorizes
  `audit OR request` (read_authorized), so without a handler check this would be
  REQUESTER-readable. CI criticality/owner are real inventory signals, so the handler adds
  an explicit `check_permission(&session, "audit")` → 403 otherwise. AUDIT-only is the
  conservative, defensible default (a Requester can already see CI NAMES via the impact
  endpoints, but not criticality/owner — those stay audit-grade). Now the binding RBAC is
  IN the handler, so it is handler-testable.
- **MAJOR 2 — RBAC tests.** Handler-direct tests prove the binding checks: a `request`-only
  session → 403; an `audit` session → 200; out-of-scope → 404; unknown → 404. The
  unauthenticated 401 is `AuthExtractor`'s generic invariant (it rejects a missing session
  for EVERY handler — covered by the auth tests, not re-tested per endpoint, per the
  codebase's handler-direct convention).
- **MINOR 1 — use `site_scope_guard_or_404(&session, &ci.site, &ci_name)`** (the dedicated
  site-only helper), not `scope_guard_or_404(..., "", ...)`.
- **MINOR 2 — ci_name path-safety.** `ci_name` is free text; a name containing a `/` will
  not route as a single matchit segment (it would 404). The body returns `id` so a by-UUID
  variant can be added later for such names. Documented limitation.
- **no-DB → 503** (`status_503_no_db()`), confirmed: the table is the only CI source (no
  in-memory fallback).
