# run-7 analysis swarm — 2026-06-30

A discovery sweep angled at LESS-SWEPT surfaces (concurrency-races / input-validation-panics /
resilience-errors / schema-migration / protocol-contract / execution-agent-seam / portal-frontend),
each finder pipelined into a default-refute adversarial verifier.

## Run caveat (transient platform instability)
- First attempt: ALL 7 finders STALLED (no tool-call progress for 180s × 6 retries; 0 candidates,
  ~73 min wasted). A single narrow probe Explore agent run immediately afterward worked fine, so the
  stall was a transient platform/load blip, not a design issue. Hardened the script with an explicit
  READ-BUDGET rule (never Read contracts.rs/agents.rs/main.rs whole; rg → targeted <=400-line windows;
  ~25 tool-call cap) and re-ran.
- Second attempt: 5 of 7 finders + 2 verifiers failed with "Failed to authenticate. API Error: Access
  Notification" (transient auth blips). Only the **input-validation-panics** dimension completed →
  2 confirmed findings (below). The other dimensions (concurrency-races, resilience-errors,
  schema-migration, protocol-contract, execution-agent-seam, portal-frontend) did NOT complete and
  remain UN-SWEPT — a run-8 should re-run them when the platform is stable.

## Confirmed + shipped
- ✅ **IpamSubnetRow::to_engine() unchecked i32→unsigned casts (read path)** (contracts.rs ~29947).
  The READ path cast `self.vlan_id as u16` / `self.total_ips as u32` etc. raw, while the UPDATE
  handler already CLAMPs ("so a corrupt DB value cannot wrap") — a read/write asymmetry. A corrupt /
  out-of-band DB row (negative or out-of-range) would silently WRAP into a plausible-but-wrong API
  value (total_ips -1 → 4_294_967_295, misreporting capacity). Re-verified the nuance: vlan_id is
  CHECK-constrained since migration 099 (1..=4094) so its read cast is DEFENSE-IN-DEPTH/consistency;
  the IP counts have NO DB CHECK (migration 050 INTEGER NOT NULL, 099 didn't constrain them), so they
  are the genuine unguarded gap. FIX: mirror the write-path clamp in to_engine() — `vlan_id.clamp(1,
  4094)`, `total_ips/used_ips/available_ips.max(0)`. + pure unit test (corrupt → clamped, valid →
  unchanged). rg confirmed this was the ONLY `self.X as uN` read-path cast (no siblings). codex review
  pending.

## Schema-migration sweep (single targeted agent — the parallel swarm was auth-degraded)
Ran a single Explore agent on schema/migration integrity (single agents stayed reliable while the
parallel fan-out failed). 3 confirmed missing-index findings; codex reviewed the index DESIGN before
implementation.
- ✅ **Missing list-query indexes** — SHIPPED migration 138 (idx_requests_site_env_created_at;
  idx_domain_events_to_status_occurred_id partial-expr; idx_agent_jobs_dead_lettered_updated_at
  partial). The `requests` list (hottest authenticated read path) + its per-page COUNT(*), the
  append-only `domain_events` alert feed, and the `agent_jobs` dead-letter admin list all full/large
  scanned a growing table. Verified on a fresh DB: migration applies, all 3 indexes created with the
  intended defs, and EXPLAIN (seqscan off) confirms each is USED (requests + agent_jobs = ordered
  index scan no-sort; domain_events = bitmap scan of only the alert rows + a small sort, since a
  multi-value `= ANY` can't be an ordered btree scan).
- **Deferred (codex)**: (a) the `(status, created_at)` requests index — highest write-amplification
  (status changes every transition), uncertain benefit → measure first (task_53bc69da). (b) the
  OR-NULL predicate (`$n IS NULL OR col=$n`) in requests_list can defeat idx_requests_site_env on a
  generic prepared plan; the real fix is dynamic SQL emitting only active predicates (task_02ed10ce).

## Resilience sweep (single targeted agent, on retry after the opus-unavailable blip)
1 confirmed finding (with a thorough "checked but sound" list — timeouts on all reqwest clients +
subprocess loops, exponential backoff via background::run_bounded, audit/event inserts use `?` in-tx
so no partial commit, etc.):
- ✅ **Silenced idempotency seal write** — SHIPPED: idempotency.rs sealed the dedup record after a
  successful handler with `let _ = UPDATE ... .await;` (and the cleanup DELETE on a buffer failure)
  — error fully dropped, no log. On a DB error the record stays IN-FLIGHT (response_status NULL), so a
  client RETRY of the same key gets a 409 InFlight until ~IN_FLIGHT_TTL_SECS (5 min) even though the
  resource was created — invisibly to operators. FIX: `if let Err(error) = ... { tracing::warn!(...) }`
  on BOTH writes — log-not-fail (the response is already buffered; the Ok-0-rows claim_id reclaim fence
  stays silent). Behavior-preserving; 13/13 idempotency tests green. codex review pending.

## Not yet swept (run-8 — platform was unstable)
concurrency-races, protocol-contract, execution-agent-seam, portal-frontend.
(schema-migration + resilience-errors now done above.)
(schema-migration now done above. A quick manual probe of scheduler.rs concurrency found only
low-severity nuances — a refresh-UPDATE that runs every scan, and a once-per-scan now_ms snapshot
causing ≤1-interval classification delay — neither compelling enough to action. The resilience-errors
single-agent attempt hit the same transient "opus temporarily unavailable" platform blip — retry.)
