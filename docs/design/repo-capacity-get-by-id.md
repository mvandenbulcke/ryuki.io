# repository-capacity GET-by-id + deny_unknown_fields hardening

Status: design — plan-review round 1 NEEDS-CHANGES, fixed below (no-DB GET →
404 not 503; flat `/{id}` safe because repo ids are seed-only `repo-*` non-reserved;
deny_unknown_fields test = unknown-EXTRA-field). Small read-completeness + hardening
slice (fresh narrow analysis). Same domain, no secrets, no live calls.

## Goal
`/api/protect/repository-capacity` has list (GET) + update/{id} (POST) +
forecast/{id} + trend/{id} + recommendations/{id} + at-risk + report (all GET), but
NO `GET /api/protect/repository-capacity/{id}` to fetch ONE repository — operators
must scan the list. Add it. Also harden the update body against typo'd fields.

## 1. `GET /api/protect/repository-capacity/{id}` → `repo_capacity_get`
Mirror the by-id READ pattern of `repo_capacity_forecast` (NOT the update's write
guard):
```rust
async fn repo_capacity_get(AuthExtractor(session), Path(id)) -> ApiResult {
    // REVIEW FIX (major): no-DB maps to 404 (NOT 503) for read consistency with the
    // other by-id reads (forecast resolves None -> 404), not the update's 503.
    let repo = match get_db() {
        Some(pool) => repos::repository_capacity::get(pool, &id).await.map_err(db_error)?,
        None => None,
    }
    .ok_or_else(|| status_404(&id))?;
    // #2: a by-id READ uses site_scope_guard_or_404 — an out-of-scope repo 404s
    // like a missing one (NO existence oracle), exactly like forecast/trend.
    site_scope_guard_or_404(&session, &repo.site, &id)?;
    Ok(Json(json!({
        "repository_id": repo.id, "name": repo.name,
        "used_capacity_tb": repo.used_capacity_tb,
        "days_until_full": repository_capacity::repo_days(&repo),
        "status": repository_capacity::repo_status(&repo),
        "last_forecast": repo.last_forecast,
    })))
}
```
Response shape mirrors `repo_capacity_update`'s return (the single-repo view). The
`repos::repository_capacity::get` fn already exists (used by update/forecast). Auth:
the central `/api/protect`→`execute` gate + the per-handler site-scope.

## 2. Route — collision care (matchit static-vs-param)
Add `.route("/api/protect/repository-capacity/{id}", get(repo_capacity_get))`. At
the segment after `/repository-capacity/`, the existing routes use STATIC segments
(`at-risk`, `report`, `forecast`, `trend`, `update`, `recommendations`); the new
`/{id}` is a PARAM at that level. matchit (axum 0.8) allows static + param siblings
with STATIC taking precedence (verified), so `GET …/at-risk` still hits
`repo_capacity_at_risk` and `GET …/{id}` hits the new handler; no build panic.
RESERVED-WORD safety (review minor): a flat `/{id}` would make an id EQUAL to a
static sibling unreachable — but that cannot happen here: repository ids are
seed-only (NO create endpoint) and `repo-*`-formatted (e.g.
`repo-defra-storeonce-01`, mig 037/038), so none can equal `at-risk`/`report`/etc.
Flat `/{id}` is therefore safe. A test still asserts the router BUILDS and that
`GET …/at-risk` + `…/report` are NOT shadowed by `/{id}` (still hit their handlers),
via the existing `oneshot` harness.

## 3. `#[serde(deny_unknown_fields)]` on `RepoCapacityUpdateBody`
The update body lacks it (every sibling mutation body has it). REVIEW NOTE: the
hardening case is a VALID body carrying an UNKNOWN EXTRA field (e.g.
`{"used_capacity_tb":1.2,"junk":true}`) — that silently succeeds today, ignoring the
typo'd/extra key. (A missing required `used_capacity_tb` already 400s.) Add the
attribute. KEEP the existing `#[serde(alias = "used_tb")]` — aliases are KNOWN field
names, so the legacy key still deserializes; only truly-unknown fields are rejected
(axum 0.8 → 422).

## Tests (contracts.rs db tests + a router test)
1. **GET-by-id happy** (DB): seed a repo, `repo_capacity_get` → 200 with
   repository_id/name/used_capacity_tb/days_until_full/status; matches the update
   handler's projection.
2. **404**: unknown id → 404; AND no-DB mode → 404 (read consistency, not
   503).
3. **Out-of-scope** (DB): a site-scoped session reading a repo in another site →
   404 (site_scope_guard_or_404, no oracle) — mirror the forecast scope test.
4. **Route not shadowed** (router oneshot, no DB): `GET …/at-risk` and `…/report`
   still route to their handlers (not the new `/{id}`); the router builds.
5. **deny_unknown_fields** (router or unit): `{"used_capacity_tb":1.2,"junk":true}`
   → 422 (unknown extra field rejected); `{"used_tb":1.2}` still deserializes (the
   alias is preserved).

## Files
- sources/ryuki-api/src/contracts.rs (`repo_capacity_get` + route +
  `deny_unknown_fields` + tests). NO migration, NO engine change.

## Out of scope (further small wins for follow-up)
- `GET /api/admin/tokens/{id}` and `GET /api/admin/agents/{id}` (secret-hygiene:
  must mirror each list's secret-safe projection + scope guard) — separate slice.
