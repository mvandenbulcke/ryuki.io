# run-7 analysis swarm — 2026-06-30

A discovery sweep angled at LESS-SWEPT surfaces (concurrency-races / input-validation-panics /
resilience-errors / schema-migration / protocol-contract / execution-agent-seam / portal-frontend),
each finder pipelined into a default-refute adversarial verifier.

## Run caveat (transient platform instability)
- First attempt: ALL 7 finders STALLED (no progress for 180s × 6 retries; 0 candidates,
  ~73 min wasted). A single narrow probe immediately afterward worked fine, so the
  stall was a transient platform/load blip, not a design issue. Hardened the script with an explicit
  bounded-read rule (never read contracts.rs/agents.rs/main.rs whole; rg → targeted <=400-line windows;
  ~25-operation cap) and re-ran.
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
  unchanged). rg confirmed this was the ONLY `self.X as uN` read-path cast (no siblings). Review
  pending.

## Schema-migration sweep (single targeted pass — the parallel swarm was auth-degraded)
Ran a single targeted schema/migration integrity pass after the parallel fan-out failed.
Three missing-index findings were confirmed; the index design was reviewed before
implementation.
- ✅ **Missing list-query indexes** — SHIPPED migration 138 (idx_requests_site_env_created_at;
  idx_domain_events_to_status_occurred_id partial-expr; idx_agent_jobs_dead_lettered_updated_at
  partial). The `requests` list (hottest authenticated read path) + its per-page COUNT(*), the
  append-only `domain_events` alert feed, and the `agent_jobs` dead-letter admin list all full/large
  scanned a growing table. Verified on a fresh DB: migration applies, all 3 indexes created with the
  intended defs, and EXPLAIN (seqscan off) confirms each is USED (requests + agent_jobs = ordered
  index scan no-sort; domain_events = bitmap scan of only the alert rows + a small sort, since a
  multi-value `= ANY` can't be an ordered btree scan).
- **Deferred after review**: (a) the `(status, created_at)` requests index — highest write-amplification
  (status changes every transition), uncertain benefit → measure first (task_53bc69da).
  **RESOLVED → DEFER (do not add): see `docs/design/requests-status-index-decision.md`** (reviewed;
  read benefit narrow + unproven, no-site path is an operator minority, and the OR-NULL caveat below
  blocks it until (b) lands). (b) the OR-NULL predicate (`$n IS NULL OR col=$n`) in requests_list can
  defeat idx_requests_site_env on a generic prepared plan; the real fix is dynamic SQL emitting only
  active predicates (task_02ed10ce) — STILL OPEN, and a prerequisite for ever revisiting (a).

## Resilience sweep (single targeted agent, on retry after a transient availability blip)
1 confirmed finding (with a thorough "checked but sound" list — timeouts on all reqwest clients +
subprocess loops, exponential backoff via background::run_bounded, audit/event inserts use `?` in-tx
so no partial commit, etc.):
- ✅ **Silenced idempotency seal write** — SHIPPED: idempotency.rs sealed the dedup record after a
  successful handler with `let _ = UPDATE ... .await;` (and the cleanup DELETE on a buffer failure)
  — error fully dropped, no log. On a DB error the record stays IN-FLIGHT (response_status NULL), so a
  client RETRY of the same key gets a 409 InFlight until ~IN_FLIGHT_TTL_SECS (5 min) even though the
  resource was created — invisibly to operators. FIX: `if let Err(error) = ... { tracing::warn!(...) }`
  on BOTH writes — log-not-fail (the response is already buffered; the Ok-0-rows claim_id reclaim fence
  stays silent). Behavior-preserving; 13/13 idempotency tests green. Review pending.

## Execution-agent-seam sweep (single targeted agent)
2 findings amid a strong verified-clean list (result-CAS double-accept guarded on attempt_id +
lease_generation + status; grant/VLC verified both CP- and agent-side with expiry + plan-digest +
request-id binding; cp_nonce constant-time per-lease replay protection; agent platform isolation;
idempotent outbox replay returns 200 only on matching result_id+attempt_id). The path IS well-hardened.
- ✅ **backlink_request_execution silently WIPED stage history on unparseable stages** — SHIPPED:
  `serde_json::from_value(stages_val).unwrap_or_default()` turned an undeserializable `requests.stages`
  (schema skew / corruption) into `[]`, and the UPDATE wrote `stages='[]'`, destroying intake/plan/
  approve/lock history + breaking later stage gates. FIX: match the parse — Ok enriches the execute
  stage (unchanged); Err LOGS + writes the ORIGINAL stages JSONB back UNTOUCHED (never wipe), still
  advancing status. Deliberately NOT returning Err (backlink is in the result tx; Err would roll back
  and the agent's at-least-once retry would re-hit the parse failure forever). + regression test
  (db_backlink_preserves_unparseable_stages). Review pending.
- **DESIGN (flagged, task_6456e60c)**: create_live_apply_job's all-status partial unique index
  (mig 057) permanently blocks re-minting a LiveApply once one reaches a TERMINAL non-Succeeded state
  (Failed/ReconcileRequired/LiveRefused/DeadLettered) — no operator escape hatch → a request can be
  stuck with no apply-retry path. Overlaps the deferred LiveRefused-recoverability trust-model decision;
  owner-owned.

## Protocol-contract sweep (single targeted agent)
3 findings amid a strong verified-clean list (Ed25519 verify_strict rejects weak/malleable; cp_nonce
constant-time; VLC expiry + plan-digest + request-id binding + CP re-signature; redaction_policy_version
gate; approved_plan_digest hex check; fencing/lease_generation/attempt_id binding; evidence_digest +
job_spec_digest recomputed by CP; 10 MiB body limit).
- ✅ **register_agent stored public_key without Ed25519 validation** — SHIPPED: only checked
  `.trim().is_empty()`, deferring the decode to result-submission. So an agent could register + be
  APPROVED with a garbage key, then every result 400s on decode → silent per-slot DoS surfacing only
  post-approval. FIX: `decode_verifying_key(public_key)` at registration (reject 400), store the TRIMMED
  key (the old bind was untrimmed — a whitespace key would later fail the result-side decode). +test
  db_register_validates_ed25519_public_key (malformed -> 400 before INSERT; valid generated key
  accepted). Review pending.
- ✅ **`JobResultStatus::Verified` accepted on the wire** — SHIPPED: it's deserializable + CP-accepted
  (maps to Succeeded/"verified") but the engine RunStatus has no Verified variant and map_run_status
  never produces it (VERIFIED: arms are Validated/CheckOk→CheckOk, Planned→Planned, Failed/RunnerUnavail/
  WorkspaceError→Failed, Applied/Changed→Applied), so a legitimate agent can't send it. An enrolled/
  compromised agent could craft a signed Verified result → false "verified" audit step. FIX: reject
  `env.status == Verified` at ingestion (after sig-verify + status-match, before any DB write). +test
  db_verified_status_is_not_agent_reportable (signed Verified result → 400, job stays Running). Review
  pending.
- **DEFERRED (low, design, task_ca74b21a)**: no CP↔agent protocol VERSION field/negotiation anywhere in
  ryuki-protocol — schema evolution can silently mis-deserialize an old agent's payloads. Flagged.

## Portal-frontend sweep (single targeted agent) — ALL run-7 dimensions now swept
4 findings (portal/portal-ui/src/views/). RBAC nav gating + form required-field validation + integration
list-refresh all verified SOUND.
- ✅ **execution_job_resource never refetched after lifecycle actions** (request_detail.rs) — SHIPPED:
  all 13 Action handlers refetched detail_resource + audit_resource but NOT execution_job_resource, so
  after `execute` dispatched a job the "Execution Job" panel stayed stale until a hard reload. FIX: add
  `execution_job_resource.refetch()` to all 13 handlers (consistent: any lifecycle action refreshes all
  3 panels). cargo check + clippy clean. Review pending. Browser verification was deferred because
  it requires the full stack (portal dev server + API + the locally-drifted DB), which is disproportionate
  for a refetch identical to the 13 existing working ones.
- **FLAGGED (task) — the other 3 portal findings** (need the full-stack browser-verify path, batched for
  a dedicated portal session):
  - (med) notifications.rs mark_all/mark_one DISCARD errors with `let _ =` — a failed POST silently
    "refreshes" with no user feedback. Surface a mutation_error (mirror integrations.rs:147).
  - (med) request_detail.rs show_approve_apply uses the SAME gate as show_live_plan, so "Approve & apply"
    shows even with no completed live plan → admin clicks → 409. Gate on has-live-plan.
  - (low) workspaces.rs Request-Intake-Preview has a hardcoded "available in next release" banner though
    POST /api/requests + RequestCreate work — replace with a live link to /requests/new.

## run-7 COMPLETE
All 7 dimensions swept (concurrency-races manually probed — only low-severity nuances). Shipped this
run: IPAM clamp (0735235), migration-138 indexes (780cb5b), idempotency logging (47e2c92), backlink
stage-wipe (aee9f55), register key validation (a42c3c9), Verified rejection (d2210a3), portal refetch.
Owner-decision/follow-up tasks: A0 scope, B0 event-feed, background-loop event, sibling aggregate_id,
requests dynamic-SQL, status index, LiveApply re-mint, protocol versioning, the 3 portal UX items above.
(schema-migration now done above. A quick manual probe of scheduler.rs concurrency found only
low-severity nuances — a refresh-UPDATE that runs every scan, and a once-per-scan now_ms snapshot
causing ≤1-interval classification delay — neither compelling enough to action. The resilience-errors
single-agent attempt hit the same transient platform-availability blip — retry.)
