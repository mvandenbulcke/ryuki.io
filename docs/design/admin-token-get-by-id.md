# GET /api/admin/tokens/{id} — token read-by-id

Status: design (pre-plan-review). Small read-completeness win (narrow scan).

## Goal
`/api/admin/tokens` has create (POST), list (GET), revoke (DELETE /{id}), but no
GET-by-id — an operator can revoke a token by id but can't INSPECT it first (roles,
owner, expiry, validity) without scanning the full list. Add `GET
/api/admin/tokens/{id}`.

## Handler `admin_tokens_get` (mirror admin_tokens_list EXACTLY)
- `require_admin_permission(&session)?` — same explicit defense-in-depth re-check
  the list uses (the `/api/admin` prefix is also centrally admin-gated).
- `get_db()` else `api_token_db_required()` (same as the list).
- SELECT the SAME secret-safe column list the list uses, scoped to the id:
  ```sql
  SELECT id, name, owner_principal, roles, site_scope, environment_scope,
         token_valid, created_at, expires_at, last_used_at, revoked_at
  FROM api_tokens WHERE id = $1
  ```
  (reuse `TokenListRow` via `fetch_optional`). NOTE: `token_hash` is DELIBERATELY
  excluded — the secret is NEVER returned (identical to the list's projection).
- `None` ⇒ a GENERIC token-not-found 404 (review note: NOT revoke's "no active token"
  message — revoke filters `revoked_at IS NULL`, but this GET uses `WHERE id = $1`
  only, so a REVOKED token is still readable like the list; 404 means genuinely
  absent). `Some(row)` ⇒ the SAME per-row JSON the list builds — factor the
  row→Value mapping (incl. its `"token_hash": Value::Null`) into a shared helper so
  list + get cannot drift.
- NO caller-scope guard: token admin is unrestricted (the list returns ALL tokens;
  a token's own `site_scope`/`environment_scope` are returned DATA, not a caller
  filter). The `/api/admin`→admin gate + `require_admin_permission` are the controls.

## Route
`.route("/api/admin/tokens/{id}", get(admin_tokens_get))` — merges the GET method
onto the existing `/api/admin/tokens/{id}` path (which has DELETE), so NO new path
and NO matchit collision (method-routing on the same path).

## Tests
1. **No-secret projection** (the load-bearing one): assert the GET-by-id
   response carries `token_hash == null` (the list's deliberate shape) and NEVER a
   real hash/plaintext — only the metadata fields. (The shared helper guarantees
   parity with the list.)
1b. **Revoked token is readable**: a soft-revoked token (revoked_at set) is
   still returned by GET-by-id (200, with revoked_at) — NOT 404 — matching the list
   (the GET does not filter revoked_at).
2. **By-id happy** (DB, if a token-seed/insert helper exists): create/seed a token,
   GET it by id → 200 with id/name/owner/roles/expiry; matches one list element.
3. **404**: unknown id → the api-token 404; no-DB → the db-required error (same as
   the list).
4. **Admin-gated**: a non-admin session → 403 (mirror the list's
   require_admin_permission test if present).

## Files
- sources/ryuki-api/src/contracts.rs (`admin_tokens_get` + route + a shared
  row→Value helper if needed + tests). NO migration, NO engine change.

## Out of scope (follow-up)
- `GET /api/admin/agents/{id}` (same pattern; needs the agent list's projection +
  secret-hygiene verified — its own small slice).
