# Operator triage list for shift_queue

Status: design (pre-codex-plan-review). Additive read-only operator view over the
`shift_queue` work-item table. NO migration, NO engine change. Picked by the fresh
analysis swarm (S effort, low risk, CI-verifiable).

## Goal
The shift queue (mig 029: `failed-operation`, `blocked-request`, `pending-approval`,
`active-incident`, `veeam-failure`/`backup-failure`, `monitoring-problem`,
`handover-note`, plus the #52 `restore-test-*` producers) is the ops work surface.
Today it has `/summary` (aggregates only), `/my-items?user=X` (hardcoded
`assigned_to`), and `/stale` (hardcoded `resolved=false AND acknowledged=false AND
age>4h`) — NO general filtered/paginated list. An operator cannot triage by type /
priority / status / owner. Add `GET /api/ops/shift/items`.

## Repo (repos/shift_queue.rs — the owner's chosen repos/ layer, not inline get_db)
Add a focused projection row + an injection-safe filtered query. The repo today has
only the `enqueue_if_absent` writer; this is its first reader.
```rust
#[derive(sqlx::FromRow)]
pub struct ShiftQueueListRow {
    pub id: String, // id::text
    pub item_type: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub assigned_to: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub acknowledged: bool,
    pub escalated: bool,
    pub resolved: bool,
}

#[derive(Debug, Default)]
pub struct ShiftQueueFilter<'a> {
    pub item_type: Option<&'a str>,
    pub priority: Option<&'a str>,
    pub assigned_to: Option<&'a str>,
    pub resolved: Option<bool>,
    pub acknowledged: Option<bool>,
    pub escalated: Option<bool>,
    /// codex MINOR: triage UNASSIGNED work. Some(true) => assigned_to IS NULL;
    /// Some(false) => IS NOT NULL; None => no filter.
    pub unassigned: Option<bool>,
}

/// Filtered + paginated triage list. EVERY filter is a BOUND param via the
/// `($N IS NULL OR col = $N)` pattern (injection-safe; an unset filter matches all —
/// no SQL string-building from user input). Fetches `limit + 1` so the caller derives
/// has_more without a COUNT. Sorted P1<P2<P3 then newest-first (triage order).
pub async fn list_filtered(pool, filter, limit: i64, offset: i64)
    -> Result<Vec<ShiftQueueListRow>, sqlx::Error>
```
SQL:
```sql
SELECT id::text AS id, item_type, title, description, priority, assigned_to,
       created_at, acknowledged, escalated, resolved
FROM shift_queue
WHERE ($1::text IS NULL OR item_type = $1)
  AND ($2::text IS NULL OR priority = $2)
  AND ($3::text IS NULL OR assigned_to = $3)
  AND ($4::bool IS NULL OR resolved = $4)
  AND ($5::bool IS NULL OR acknowledged = $5)
  AND ($6::bool IS NULL OR escalated = $6)
  AND ($7::bool IS NULL OR (assigned_to IS NULL) = $7)   -- codex MINOR: unassigned
ORDER BY priority ASC, created_at ASC, id ASC            -- codex MAJOR: id tiebreak
LIMIT $8 OFFSET $9
```
ORDER: `priority ASC` (P1<P2<P3) then `created_at ASC` (OLDEST-waiting first — the
triage backlog order, matching the existing `/my-items` + `/stale` `created_at`
ordering, NOT newest-first) then `id ASC` as the IMMUTABLE tiebreaker so offset
pagination is deterministic (no dup/skip when priority+created_at tie, e.g. rows
seeded in one tx).
NOTE: `metadata` (jsonb) is DELIBERATELY excluded from the projection — the
shift-contract rule `no-raw-provider-payloads` / `rawProviderPayloadsAllowed:false`,
and `/my-items` already omits it. `shift_queue` has NO site/environment COLUMNS (site
lives in `metadata->>'site'`), so site-scope filtering is OUT OF SCOPE for this slice
(a follow-up could filter on `metadata->>'site'`).

## Handler + route (contracts.rs)
```rust
#[derive(Debug, Deserialize, Default)]
struct ShiftListParams {
    item_type: Option<String>, priority: Option<String>, assigned_to: Option<String>,
    resolved: Option<bool>, acknowledged: Option<bool>, escalated: Option<bool>,
    limit: Option<i64>, offset: Option<i64>,
}
async fn shift_list(Query(p): Query<ShiftListParams>) -> ApiResult {
    let pool = get_db().ok_or_else(status_503_no_db)?;     // DB-only (503 in no-DB),
                                                            // matching dr_plans_list / #52.
    let limit = p.limit.unwrap_or(50).clamp(1, 200);
    let offset = p.offset.unwrap_or(0).max(0);
    let filter = repos::shift_queue::ShiftQueueFilter { item_type: p.item_type.as_deref(), ... };
    let mut rows = repos::shift_queue::list_filtered(pool, &filter, limit + 1, offset).await.map_err(db_error)?;
    let has_more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let items = rows.iter().map(|r| json!({ id,item_type,title,description,priority,
        assigned_to, "created_at": r.created_at.to_rfc3339(), acknowledged,escalated,resolved })).collect();
    Ok(Json(json!({ "source":"database", "items": items, "count": items.len(),
        "limit": limit, "offset": offset, "has_more": has_more })))
}
```
Route `.route("/api/ops/shift/items", get(shift_list))` beside the other 2-segment
shift statics (`summary`/`handover`/`my-items`/`stale`) — all static siblings, NO
matchit collision with the 3-segment `/shift/{verb}/{id}` mutations. Auth: the
central `/api/ops` → `execute` gate (main.rs:555) applies (no per-handler check, like
the other shift reads). Over-fetch `limit+1` drives `has_more` (the #15 portal
pagination pattern) — no COUNT query.

## Tests (shift_queue_db_tests — mirror seed_item(pool,id,item_type,priority,assigned_to))
1. **filters + order**: seed varied items (types/priorities/owners/resolved) → no
   filter returns all sorted P1<P2<P3 then created_at DESC; `item_type=` returns only
   that type; `priority=P1` only P1; `resolved=false` only open; `assigned_to=` only
   that owner; combined filters AND together.
2. **pagination + has_more**: seed 3 matching → `limit=2` → 2 items + `has_more=true`;
   `offset=2` → 1 item + `has_more=false`.
3. **clamp**: `limit=999` → response `limit` is 200; `limit=0` → 1.
4. **injection-safe**: an `assigned_to` containing `' OR 1=1 --` returns 0 rows (bound
   param, not interpolated) — proves filters are parameterized.
5. no-DB → 503 (the `get_db().ok_or_else(status_503_no_db)` pattern; noted, covered by
   the shared pattern).

## Files
- sources/ryuki-api/src/repos/shift_queue.rs (`ShiftQueueListRow`, `ShiftQueueFilter`,
  `list_filtered` + the repo test).
- sources/ryuki-api/src/contracts.rs (`ShiftListParams`, `shift_list` + route + db tests).
NO migration, NO engine change.

## AUTHZ (codex MAJOR, rounds 1-2)
SAFE-method reads are gated by `read_permission_for`/`read_authorized`, NOT
`route_permission_for` (whose `/api/ops`→`execute` applies to UNSAFE methods only) —
so an ordinary GET defaults to the `audit` tier (`audit || request`). The shift queue
is OPERATOR working data (open-item descriptions + assignees), so:
- CENTRAL gate: a new `execute`-read tier — `is_execute_read_path` matches
  `/api/ops/shift/...`, `read_permission_for` returns `"execute"`, `read_authorized`
  enforces it. This covers the WHOLE per-item shift read family (summary / handover /
  my-items / stale / items) and any future shift read — closing the equivalent
  `/handover` leak codex found, not just `/items`. The static `/api/ops/shift-contract`
  (not under `/shift/`) stays ordinary-readable.
- DEFENSE-IN-DEPTH: `shift_list` ALSO does an in-handler `check_permission(execute)`
  (belt-and-suspenders; covered by its own auditor-403 test).
Handler-direct tests bypass the middleware, so the central gate change breaks none of
them; a dedicated `test_shift_queue_reads_require_execute` proves the gate (operator
reads; auditor + requester 403; contract stays audit; admin superuser reads).

## Out of scope (follow-ups)
- Site/environment scope filtering (needs first-class columns or a `metadata->>'site'`
  filter + the scope guard).
- A no-DB (in-memory engine store) fallback (the engine exposes only specific views;
  a generic filtered list there is a separate change). This endpoint is DB-only.
- Free-text search over title/description.
