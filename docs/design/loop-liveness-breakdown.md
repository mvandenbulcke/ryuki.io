# Per-loop background-loop liveness breakdown

Status: design (pre-codex-plan-review). Additive read-only observability over the
shipped heartbeat registry + aggregate probe. NO migration, NO new state, pure core.
Picked by the fresh analysis swarm (S effort, low risk, CI-verifiable).

## Goal
`GET /api/platform/health/dependencies` exposes ONLY the AGGREGATE
`classify_loop_liveness` verdict ("N background loop(s) wedged: <names>"). When a
loop wedges, an operator must know WHICH loop, how long it has been silent, and
against WHAT threshold — to diagnose. Add `GET /api/platform/health/loops` returning
the per-loop breakdown. (`background-loop-liveness.md` listed this as an explicit
follow-up.)

## Pure core (background.rs — keep the threshold a SINGLE source of truth)
The overdue threshold (`2*iteration_timeout(interval) + 2*interval`, all saturating)
is currently computed INLINE inside `classify_loop_liveness`. Extract it so the
per-loop view and the aggregate cannot drift:

```rust
/// Silence budget: a loop is overdue once age_secs exceeds this (two full timed
/// iterations + the inter-attempt waits). Saturating. The SINGLE source of truth
/// shared by classify_loop_liveness (aggregate) and loop_status_report (per-loop).
pub fn loop_overdue_threshold(interval_secs: u64) -> u64 {
    2u64.saturating_mul(iteration_timeout(interval_secs).as_secs())
        .saturating_add(2u64.saturating_mul(interval_secs))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LoopStatus {
    pub name: &'static str,
    pub interval_secs: u64,
    pub age_secs: u64,
    pub threshold_secs: u64,
    pub overdue: bool,
}

/// Per-loop breakdown (pure): maps each snapshot to its threshold + overdue verdict,
/// sorted by name for a stable response. Same threshold + same `age > threshold`
/// rule as classify_loop_liveness, so the per-loop view and the aggregate agree.
pub fn loop_status_report(entries: &[LoopLiveness]) -> Vec<LoopStatus> { ... }

/// Aggregate verdict derived from the breakdown (kept consistent with
/// classify_loop_liveness): no loops -> "degraded"; any overdue -> "down"; else
/// "healthy".
pub fn loop_overall_status(report: &[LoopStatus]) -> &'static str { ... }
```
`classify_loop_liveness` is refactored to call `loop_overdue_threshold` (behavior
identical; its existing tests still pass). `Serialize` derive on `LoopStatus`
(background.rs is in ryuki-api, not the pure engine, so serde is fine).

## Handler + route (main.rs — beside /api/platform/health/dependencies)
The (status-code, body) construction is a PURE fn in background.rs so the 200/503
logic is deterministically testable WITHOUT the process-global registry (codex MAJOR
— the handler test cannot assert a fixed code against global state):
```rust
// background.rs (pure)
pub fn loop_liveness_payload(report: Vec<LoopStatus>) -> (u16, serde_json::Value) {
    let overall = loop_overall_status(&report);
    let overdue = report.iter().filter(|l| l.overdue).count();
    // Alerting-safe + consistent with the sibling dependencies probe: a wedged loop
    // maps to 503 (else 200). The body always carries the full breakdown.
    let code = if overall == "down" { 503 } else { 200 };
    (code, json!({
        "loops": report, "overall": overall,
        "overdue_count": overdue, "registered_count": report.len(),
    }))
}
// main.rs (thin)
async fn platform_loop_liveness() -> (StatusCode, Json<Value>) {
    let report = crate::background::loop_status_report(&crate::background::loop_liveness());
    let (code, body) = crate::background::loop_liveness_payload(report);
    (StatusCode::from_u16(code).unwrap_or(StatusCode::OK), Json(body))
}
```
No `AuthExtractor` / no in-handler permission check — mirrors `platform_self_health`
EXACTLY (registered in the SAME human-gated router, so the auth middleware requires a
session; the loop names are already exposed by the aggregate to that same audience,
so no new disclosure). Route: `.route("/api/platform/health/loops",
get(platform_loop_liveness))` next to `/api/platform/health/dependencies`
(main.rs:~2305).

## Tests
PURE (deterministic — synthetic `LoopLiveness` entries, NO global registry, so no
wall-clock flakiness):
1. `loop_overdue_threshold` equals the formula for representative intervals (10, 30,
   3600) and saturates (does not overflow) at `u64::MAX`.
2. `loop_status_report`: an entry with `age_secs <= threshold` → `overdue=false`; one
   with `age_secs > threshold` → `overdue=true`; each `threshold_secs ==
   loop_overdue_threshold(interval)`; the result is sorted by name.
3. `loop_overall_status`: `[]` → "degraded"; any overdue → "down"; all fresh →
   "healthy".
4. Regression: `classify_loop_liveness` still classifies identically after the
   threshold extraction (the existing tests cover this; add one cross-check that the
   per-loop `overdue` set matches classify's `down` membership for the same entries).
5. `loop_liveness_payload` (PURE — codex MAJOR): a report with an overdue loop →
   code 503 + overall "down"; an all-fresh report → 200 + "healthy"; an EMPTY report
   → 200 + "degraded". Body carries loops/overall/overdue_count/registered_count.
HANDLER (light, no DB, registry-tolerant):
6. Register a uniquely-named fresh loop, call `platform_loop_liveness`, assert the
   loop appears in `loops` with `overdue=false` and `threshold_secs > 0`, and the
   status is 200 OR 503 (NOT a fixed code — the process-global registry + wall-clock
   make `overall`/other loops non-deterministic across the suite; the deterministic
   200/503 logic is covered by the pure `loop_liveness_payload` test).

## Files
- sources/ryuki-api/src/background.rs (`loop_overdue_threshold`, `LoopStatus`,
  `loop_status_report`, `loop_overall_status`, refactor `classify_loop_liveness`,
  pure tests).
- sources/ryuki-api/src/main.rs (`platform_loop_liveness` handler + route + handler
  test). NO migration, NO engine change.

## Out of scope
- Historical loop-liveness time series (the registry is in-memory, current-only).
- Per-loop alerting (the aggregate already drives the #6 self-health 503 + alerts).
