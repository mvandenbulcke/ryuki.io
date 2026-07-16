# `requests (status, created_at DESC)` index — measure-first decision

Status: **DECIDED — DO NOT ADD NOW (defer).** This closes the measure-first task
`task_53bc69da` that migration 138 deferred (the `(status, created_at)` requests index
flagged during review as the highest write-amplification risk). The measurement below does not
justify the index at the current access pattern, and a hard sequencing dependency
(`task_02ed10ce`) blocks it regardless. Re-evaluate only when the two criteria at the
bottom are both met.

## What was deferred and why
Migration 138 (`138_list_query_indexes.sql`) added `idx_requests_site_env_created_at`
`(site, environment, created_at DESC)` — the scoped-principal list, the documented
"hottest authenticated read path". The same review **deliberately deferred** a
sibling `(status, created_at DESC)` index:

> A status-only index was deliberately deferred (status changes on every lifecycle
> transition = write amplification; ship the scoped index first and measure).
> — `migrations/138_list_query_indexes.sql:30`

Tracked in `docs/design/swarm-findings-2026-06-30-run7.md:44` as deferral (a),
`task_53bc69da` ("measure first"), paired with deferral (b) `task_02ed10ce` (the OR-NULL
dynamic-SQL rewrite). This doc is the resolution of (a).

## Measure: who actually hits the un-indexed path?
The list query and its COUNT share one WHERE clause (`REQUESTS_LIST_WHERE`,
`contracts.rs:15215`), whose leading predicate is `($1::text IS NULL OR status = $1)`,
with `ORDER BY created_at DESC` as the default (`contracts.rs:15264`). A status filter
with **no site** therefore scans `requests` (archived, never pruned — unbounded) and
sorts. But the population that can reach that path is narrow:

- **A site-scoped principal never reaches it.** `requests_list` runs every list through
  `enforce_scope_filters` (`contracts.rs:15254`), which resolves `site_scope` and
  `environment_scope` **independently** (`contracts.rs:23550-23558`). A site-scoped user
  passing `?status=failed` has a concrete `site` injected, so the planner uses the
  **138** `(site, env, created_at)` index — not a status index.
- **But "no site" is not only the fully-unrestricted principal.** Because the two scopes
  are independent vectors, an **environment-only-scoped** principal (empty `site_scope`,
  non-empty `environment_scope`) that omits `?site=` resolves site to `None` and
  environment to a concrete value. So the un-indexed status-without-site path is reached
  by principals **with no site scope** — fully unrestricted *or* environment-only-scoped.
  An env-only filter (`site` NULL, `environment` concrete) also cannot seek the 138
  index, whose leading column is `site`.
- **Either way it is an operator/admin minority path, not the dominant read.** It is
  reachable — the portal exposes `status` as an independent facet (`STATUS_FILTER_OPTIONS`,
  `portal/portal-ui/src/views/requests.rs:33`; the facet builder omits unset facets, so
  status-without-site is a valid URL). But the dominant, documented hot path is the
  site-scoped list, already covered by 138.
- **No telemetry proves it is hot.** There is no per-endpoint access-count metric on the
  list route in the codebase, so "common enough" cannot be shown empirically. The
  structural conclusion stands on its own: this is a global-operator convenience query
  ("all FAILED across every site"), not a per-request or per-scoped-user hot path.

## Cost: write amplification here is maximal *and* asymmetric to 138
The reason this index is uniquely expensive — and the reason it was singled out — is
not generic "indexes cost writes". It is that the leading column **mutates on the
table's most frequent write**, while 138's columns never mutate:

- **138 is write-stable.** `site` and `environment` are set at intake and **never
  UPDATEd** (no `UPDATE requests SET … site/environment …` exists anywhere in
  `contracts.rs`). `created_at` is immutable. So `idx_requests_site_env_created_at`
  takes exactly **one** index entry per row, at INSERT, and that entry never moves.
- **A status-leading index is maximally write-unstable.** `status` changes on every
  lifecycle transition. The *persisted* happy path is intake → validated → planned →
  approved → locked → executing → verifying → completed → protecting → operational →
  retired — ~10 transitions (`executed`/`verified` are decode-only legacy aliases:
  `request_status_to_db` never emits them and `from_db` folds them into
  `executing`/`verifying`, `contracts.rs:14822` & `:14835`). A `(status, created_at DESC)`
  index re-positions the row in the btree on **every** one of those ~10 transitions —
  a fresh index tuple plus a dead tuple to vacuum each time — versus 138's single
  never-moving entry. That asymmetry is the whole point.
- **The table already pays non-HOT cost on every status transition — so this would be a
  SECOND status-sensitive index, not a fresh HOT regression.** `status` is *already* a
  HOT-blocking attribute: migration 119's partial index
  `idx_requests_next_maintain_review ON requests (next_maintain_review_at) WHERE status =
  'operational'` (`119_maintain_review.sql:24`) references `status` in its predicate, and
  Postgres includes partial-index predicate columns (and the mutable indexed key
  `next_maintain_review_at`, advanced by the scheduler at `scheduler.rs:284`) in the
  HOT-blocking set. So a status-transition UPDATE (`SET status, stage, stages,
  updated_at …`, `contracts.rs:14313`) is **already non-HOT today**. Adding
  `(status, created_at DESC)` therefore does **not** newly destroy HOT — but it adds a
  second index keyed *directly* on the mutable `status`, so every transition must now
  maintain *two* status-sensitive indexes (119's narrow partial + this broad btree)
  instead of one, with this one churning on **all** ~10 transitions rather than only the
  operational boundary 119 touches.

Net: 138 = one stable entry per row, forever. A status index = ~10 churns per row on a
table that is *already* doing non-HOT updates on those transitions, for a read benefit
that is narrow (no-site-scope principals only) and unproven. The cost/benefit asymmetry
holds; the earlier framing of a "fresh HOT regression" did not, and is corrected here.

## Blocking dependency: the OR-NULL caveat is LIVE
Even setting cost aside, adding the index **now** risks paying that full cost for an
index the planner may not use. The shared WHERE keeps the OR-NULL shape
(`($1::text IS NULL OR status = $1)`, `contracts.rs:15215`). Under a **generic prepared
plan** Postgres cannot assume `$1` is non-NULL, so it must plan for "predicate matches
everything" and falls back to a seq scan — the index goes unused in exactly the steady
state where generic plans take over. The real fix is the dynamic-SQL rewrite that emits
only the active predicates — tracked separately as **`task_02ed10ce`**, and it **has NOT
landed** (the static `REQUESTS_LIST_WHERE` constant is still in place). The same caveat
the migration-138 comment raises for the scoped index (`:26-29`) applies here.

Adding a write-amplifying index whose own query shape can't reliably use it is the worst
outcome: all cost, contingent benefit. Sequencing matters — the predicate must become
sargable first.

## Decision
**Do not add `idx_requests_status_created_at`.** Confirm the original review decision with
the added rigor above (the write-amplification asymmetry + the live OR-NULL dependency).
Close `task_53bc69da`.

Re-evaluate **only when both** hold:
1. **`task_02ed10ce` has landed** — the list query emits only active predicates, so a
   concrete `status` filter is directly sargable (no OR-NULL generic-plan fallback).
2. **A measured global-operator status-only-no-site read path is shown hot** — e.g. an
   auto-refreshing cross-site operations dashboard, evidenced by endpoint telemetry or a
   concrete product surface, not a hypothetical.

If both hold, prefer the **narrowest** form that covers the proven query (e.g. a partial
index on only the operationally-hot statuses, or a covering index that turns the COUNT
into an index-only scan) over a full `(status, created_at DESC)` btree, and verify with
`EXPLAIN` that the concrete-value plan uses it before shipping — exactly as 138 did.

## Files
- `docs/design/requests-status-index-decision.md` (this doc). **No migration, no schema,
  no code change** — the decision is to *not* add the index.

## Out of scope
- The OR-NULL dynamic-SQL rewrite itself (`task_02ed10ce`) — separate change; this doc
  only depends on it.
- The 138 indexes (shipped, EXPLAIN-verified) — unchanged.
