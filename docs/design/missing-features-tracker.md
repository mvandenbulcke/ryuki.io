# Missing-features execution tracker

A 9-area analysis swarm (2026-06-24) produced 66 ranked missing features
(deduped from 69 raw, every claim spot-checked against code). The owner approved
implementing **all 66**. This file tracks execution.

## Execution model

- **Serial, dependency-ordered.** Each feature lands as one slice: design →
  migration (sequential number) → engine/API/portal → tests → gate → Codex
  review → commit + push. Features are NOT built in parallel — they collide on
  migration numbers and on the hot shared files (`contracts.rs`, `main.rs`).
- **Gate per slice:** `cargo fmt --all`; `cargo clippy --workspace --all-targets
  -- -D warnings`; `cargo test -p ryuki-api --bins`; the relevant `*_db_tests`
  with `RYUKI_DATABASE_URL`; `bash scripts/no-secret-scan.sh`. Then a GPT-5 Codex
  review before commit.
- **Engines stay pure** (validator-enforced no-IO); credit Codex as co-author.

## Key dependencies (drive ordering)

- **#1 scheduler** unblocks #31, #39, #40, #45, #52 (and feeds #19, #22).
- **#2 administrable/scoped RBAC** precedes #48 (recert revocation).
- **Analytics chain (strict):** #34 metric history → #35 detection → #36
  generation → #37 what-if → #53/#54 budgets/commitment.
- **#14 API list/pagination** precedes #15 / #59 (portal faceting/scope).
- **require-key rollout (idempotency 2b+)** precedes requiring keys on
  portal-called routes — needs `UpstreamClient` to send keys first.

## Backlog (rank order; `[x]` = shipped)

| # | ✓ | Feature | Area | E | V | 📋 |
|---|---|---|---|---|---|---|
| 1 | [x] | Durable scheduler / background job engine | Roadmap | L | H | ✓ |
| 2 | [x] | Administrable, site/env-scoped RBAC | Security | L | H | ✓ |
| 3 | [x] | Separation-of-duties on approval (no self-approve) | Security | S | H | ✓ |
| 4 | [x] | Multi-role approval quorum | Security | M | H | ENFORCED `1fc0e6d` (mig 118 requests.required_approval_roles DEFAULT 1; FOR UPDATE-locked quorum eval in apply_approval_decision_audited; engine unchanged; codex-approved over 3 rounds — caught lost-completion + lost-evidence races + a 409/400 regression). Deferred follow-up: policy SOURCE that raises required_approval_roles above 1 from the offering/criticality at plan time (today the column defaults to 1, so enforcement is wired + tested but exercised only when a request sets it) |
| 5 | [x] | Tamper-evident audit hash chain + verify | Security | M | H | ✓ |
| 6 | [x] | Dependency-backed platform self-health probes | Roadmap | L | H | ✓ |
| 7 | [x] | Protect/Publish/Retire actions in portal | Portal | M | H | ✓ |
| 8 | [x] | Agent enrollment approve/revoke from portal | Portal | M | H | `0edc1ea`+`14e8e87` — revoke (API+portal): terminal revocation, atomic audit on approve+revoke, admin re-check, idempotent; approve was already shipped `6d6fb5b` |
| 9 | [ ] | Outbound notifications (email/webhook/callback/chat) | Roadmap | L | H | ✓ |
| 10 | [ ] | Destroy/teardown execution mode (live decommission) | Exec | L | H | — |
| 11 | [x] | Pre-dispatch policy gate for unsafe IaC | Exec | M | H | SHIPPED — pure `ryuki_engine::iac_policy::evaluate_iac_bundle` (no-IO) refuses live-mode IaC with unsafe constructs: TF `provisioner` blocks + `data "external"` (line-based HCL scan, comment/block-comment aware); Ansible `check_mode` non-truthy override + legacy `always_run`, `raw`/`script` (incl. FQCN + `action`/`local_action` first-token resolution), external `include/import_*`/`roles`/`import_playbook` (fail-closed as Unscannable), YAML merge-keys resolved via `apply_merge` before scan, non-`.tf`/`.yml` files fail-closed. Wired into all 4 runner live entry points (TF+Ansible plan/apply) BEFORE init/providers → `RunStatus::Failed` + `POLICY-REFUSED` summary. Conformance test: every bundled offering passes. GPT-5.5 Codex (xhigh) found 5 Ansible bypasses on round 1 (check_mode `0`/`"n"`, action-mapping inline args, action-wrapped includes, `<<` merge keys, top-level import_playbook) — ALL fixed + regression-tested; round 2 re-review confirmed closed |
| 12 | [ ] | Agent-side vault-backed secret resolution | Exec | L | H | ✓ |
| 13 | [~] | Request rework/fail/soft-delete transitions | API | M | H | ✓ |
| 14 | [~] | List filtering/search + pagination envelope (API) | API | M | H | ✓ |
| 15 | [x] | Faceted request filtering/sort/pagination (portal) | Portal | M | H | facets `3a32da0` (env/request_type/created_by) + pagination `a62a80b` (offset/limit page-nav, over-fetch has_next since the portal can't read X-Total-Count, offset clamp, pure tested helpers; codex APPROVED). exact total via X-Total-Count `2535fee` (UpstreamResponse now carries the header; "Showing X-Y of N", inverted-label guarded). FULLY complete |
| 16 | [x] | Enforced site degradation mode (write gating) | Resil | L | H | — |
| 17 | [x] | Bulk / batch operations | API | M | H | slice 1 `requests_batch_cancel`; slice 2 batch REJECT shipped — POST /api/requests/batch/reject mirrors batch-cancel (dedupe, cap 100, shared reason, per-item independent tx, partial success, HTTP 200). Factored `reject_one` core shared by single+batch; closed a latent no-DB scope gap in single reject (now scoped like cancel + the DB path); batch-only ≤2000 reason cap (single unchanged); denial audited once via non-id sentinel. codex plan(rd2)+impl APPROVE. slice 3 rework+fail shipped — POST /api/requests/batch/{rework,fail} mirror the reject template; extracted `rework_one`/`fail_one` cores (shared single+batch) and closed the SAME latent no-DB scope gap in single rework + fail; rework→approve, fail→execute (segment-gate auto-maps both); fail records each item's OWN current stage (per-item proven). codex plan+impl reviewed. slice 4 (FINAL) batch APPROVE shipped — POST /api/requests/batch/approve. Extracted `approve_one` (shared single+batch) reusing `apply_approval_decision_audited`, so a batch CANNOT bypass the #4 multi-role quorum: each id gets THIS approver's ONE decision; a required_approval_roles>1 request stays Planned (quorum_met=false) until N distinct roles+approvers — PROVEN by a no-bypass test (one approver → planned + decision recorded; distinct 2nd approver → approved). Per-id result carries request_status + quorum_met; SoD/scope per-item inside the core. codex plan+impl reviewed. #17 COMPLETE (cancel/reject/rework/fail/approve). POST-SHIP HARDENING (verify-first swarm 2026-06-29): `approve_one` was the LONE batch-mutation core missing the NO-DB scope guard its siblings have — a scoped approver in dry-run could approve an out-of-scope request (cross-scope mutation + existence oracle). Added the exact sibling guard (`is_scoped && !row_scope_permits` → 404) to approve_one's first no-DB lock block (404 precedes SoD/engine, mirroring the DB ordering) + a `batch_approve_no_db_is_site_scoped` test asserting the out-of-scope item's EXACT per-result 404 (no-oracle proof). codex plan(MINOR-folded)+impl APPROVE. See approve-one-nodb-scope-guard.md |
| 18 | [x] | Inbound integration webhook receivers | Integ | L | H | `b60b7d0`/`630d287`/`c364794` — pure constant-time HMAC verifier (webhook_receipt) → dedicated per-connection webhook secret (mig 149, admin-set) → public auth-bypass receiver verifying the signature over the raw body, uniform-401 no-oracle, records integration.webhook-received (NO auto-trigger). Codex-xhigh reviewed each slice. Follow-up: owner-gated auto-triggering of platform actions from a verified webhook |
| 19 | [x] | Connection health monitoring (scheduled + history) | Integ | M | H | scheduled sweep shipped — durable-scheduler `connection_health_sweep` (leader-elected, #40 safe-internal-write recipe): lists ALL connections, runs the pure `test_connection_stub` (NO live resolve_credentials), appends a `connection_health_checks` row + refreshes `last_test_*` on the tick tx, deterministic stub credential verdict, aggregate-only detail, no dedup (time series). mig 120 seeds the schedule only (mig 102 already had the index). codex APPROVED round 2 (3 test-quality fixes folded in: restore-seeded-sweep, full seed-contract idempotency, exact-message branch coverage). On-demand probe + history read already existed |
| 20 | [ ] | Step-up / MFA re-auth for high-risk actions | Security | M | H | — |
| 21 | [ ] | Live secret rotation (Vault) + break-glass | Security | L | H | ✓ |
| 22 | [x] | Domain-event alert generation | Observ | M | H | — |
| 23 | [x] | CP-side poison-job cap / dead-letter | Resil | M | H | shipped — `expire_leases` now caps non-mutating (OfflineDryRun/LivePlan) lease-expiry redispatches at `MAX_REDISPATCHES=5` via a `delivery_attempts` counter (mig 121); at the cap the job becomes terminal `DeadLettered` and emits ONE alert-worthy `job.dead_lettered` domain event (to_status='dead-lettered', `event_alerts` → Critical), all in one tx. Per-replica-safe (row-lock predicate recheck). LiveApply (→ReconcileRequired) unchanged. codex plan + impl both APPROVE; tests incl. concurrency + mixed-count + migration idempotency. Follow-up SHIPPED — operator list + requeue: GET /api/admin/agents/dead-lettered-jobs (admin, secret-safe projection: no spec/live_context) + POST .../{job_id}/requeue (DeadLettered→Pending, delivery_attempts reset to 0 + lease cleared, audited). Requeue GUARDS the parent-request lifecycle (locks the request FOR UPDATE in requests→agent_jobs order; refuses if is_concluded()/orphan/unknown — fail-closed) so it can't re-dispatch stale work for a closed request. codex plan(rd2)+impl reviewed. Remaining follow-up: bulk requeue + portal view |
| 24 | [x] | Audit-trail export / streaming to SIEM | Observ | M | H | — |
| 25 | [x] | SLO / error-budget tracking | Observ | M | H | — |
| 26 | [x] | CP database backup/restore + DR runbook | Roadmap | M | H | ✓ |
| 27 | [~] | Bidirectional CMDB reconciliation + drift | Integ | L | H | `393caad`/`ee98640` — the "+ drift" half: pure detect_attribute_drift (owner/site/environment/criticality divergence for CIs matched in both sources) wired into the live cmdb_run_reconciliation endpoint (real platform inventory today). Follow-ups (external-gated): live CMDB fetch (import_cmdb_records is still demo data) + write-back to resolve drift |
| 28 | [ ] | Active Directory / Entra integration adapter | Integ | L | H | — |
| 29 | [ ] | DR failover orchestration (runbook-driven) | Resil | L | H | — |
| 30 | [x] | Circuit breaker for provider/adapter calls | Resil | M | H | — |
| 31 | [x] | Scheduled/recurring agent jobs (drift-scan) | Exec | L | H | `02ab45f`/`688561d`/`c86fb0b`/`06fbf03`/`6d8339a` — overdue-flag scan → classify_plan_json → CP drift event → cadence reset → scheduler dispatches read-only LivePlan rechecks (first agent_job-creating scan; mig 145-148). Reuses #43 machinery. Codex-xhigh reviewed, live-DB verified |
| 32 | [x] | Per-notification mark-read + deep-link | Portal | S | M | — |
| 33 | [x] | CMDB import/export/reconcile actions in portal | Portal | M | M | ✓ |
| 34 | [x] | Time-series metric history + forecasting | AIOps | L | H | ✓ |
| 35 | [x] | Anomaly / waste detection engine | AIOps | M | H | — |
| 36 | [x] | AIOps suggestion-generation engine | AIOps | M | H | — |
| 37 | [x] | What-if capacity & cost planning | AIOps | M | H | — |
| 38 | [x] | Storage array registration / lifecycle | API | M | M | — |
| 39 | [x] | Maintain lifecycle stage (recurring review) | Roadmap | M | M | `9e1d425` — scheduled maintain_review_scan flags due Operational requests via request.maintain-review-due domain events (atomic FOR UPDATE SKIP LOCKED claim+advance, 90d, mig 119); reuses #40 pattern; codex-approved plan+impl. Follow-ups: alert-feed promotion + per-criticality interval |
| 40 | [x] | Scheduled/recurring synthetic health checks | Observ | S | M | `715f126` — durable scheduler runs synthetic_health_run (first safe-internal-write kind: job_is_schedulable allowlist); hourly seed (mig 116) + tx-aware result writes |
| 41 | [x] | Integration credential rotation / expiry | Integ | M | M | — |
| 42 | [~] | Multi-step orchestration / job dependencies | Exec | L | M | Slice 1 `5459724` (pure ryuki-engine::job_orchestration: validate_plan/ready_steps/cycle-detect). Slice 2a `4473f68` — job_steps table (mig 151) + requests_execute materializes a plan's INITIAL ready steps (OfflineDryRun-only, non-offline rejected 400; single-job path unchanged; in the CAS tx). Slice 2b `26f35a9` — step-success backlink dispatches next-ready steps + gates request→verifying on ALL steps terminal, →failed on any step failure; concurrency-serialized via job_steps FOR UPDATE + fail_inflight_steps reconciliation of in-flight steps on request-fail. Engine end-to-end DONE + GPT-5.5-Codex-xhigh clean both slices. Remaining: public plan-AUTHORING endpoint (plans are test-seeded only today → feature dormant until authored) |
| 43 | [x] | Post-apply verification (re-plan → Verified) | Exec | M | M | `349b152`/`e5c7b52`/`2f5ee2b` — engine classifier (post_apply.rs) → runner re-plan verdict in RunOutcome → CP derives verdict from digest-verified evidence, transitions Applied→Verified + emits scoped request.post-apply-drift (Critical). All Codex-xhigh reviewed |
| 44 | [x] | Agent liveness sweep + offline detection | Exec | M | M | ALREADY DONE — spawn_agent_offline_scan (main.rs, 60s/180s) + agent_offline_scan_once emits agent.offline/agent.online on state transitions, deduped via offline_alerted (mig 114), with notifications + to_status warning alert. (A durable-scheduler port was scoped but abandoned as redundant — codex plan-review caught the existing emitter.) |
| 45 | [x] | Per-site / per-tenant usage metering | Observ | M | M | — |
| 46 | [x] | Chargeback / showback cost allocation | AIOps | M | M | — |
| 47 | [x] | Backup verification + restore-test recency | Resil | M | M | — |
| 48 | [ ] | Enforced access recertification w/ revocation | Security | L | M | — |
| 49 | [x] | Secret update & deregistration | API | S | M | — |
| 50 | [x] | Evidence pack file download / export | Portal | S | M | — |
| 51 | [x] | Per-vendor connection capability catalog | Integ | M | M | — |
| 52 | [x] | Route DR-overdue/failed tests into work queue | Resil | S | M | FULLY shipped — slice 1 (overdue/never-tested) + slice 2 (FAILED-latest). `restore_overdue_scan` reuses the #47 recency classifier (`is_at_risk()`=Overdue/NeverTested → `restore-test-overdue`) AND `latest_failed_systems` (DISTINCT ON, latest-is-Failed → `restore-test-failed`), each deduped via `enqueue_if_absent`(item_type) + a per-type partial unique index (mig 122/123); combined aggregate detail; blank keys skipped per-row in Rust. codex plan(rd2)+impl(rd2) APPROVE both slices. Follow-ups: DR-plan drill overdue, auto-priority |
| 53 | [x] | Cost/capacity budget thresholds + alerts | AIOps | M | M | — |
| 54 | [x] | Reserved-capacity / commitment cost modeling | AIOps | M | M | — |
| 55 | [x] | DNS record update endpoint | API | S | M | — |
| 56 | [x] | IPAM subnet CRUD | API | M | M | — |
| 57 | [x] | Load-balancer virtual-server delete/update | API | M | M | — |
| 58 | [x] | Connection usage audit trail | Integ | M | M | shipped — `integration_test` (the one CP-side credential-resolution site) now records ONE durable hash-chained `audit_log` row per access (`integration.connection.tested`, actor from the session, AUTHORITATIVE in DB mode → 500 on audit-write failure, local store in no-DB), recorded whether resolution succeeds or fails, BEFORE the best-effort telemetry writes. detail carries connection_id/vendor_type/`cred_source`/endpoint_status — NEVER the ref/secret/CredError text. Reuses audit.rs as-is (no migration). codex plan + impl both APPROVE; 7 tests incl. redaction-survival (cred_source key avoids the `credential` redaction pattern). Follow-ups: live-execution credential-use audit (owner-domain), per-connection usage read view |
| 59 | [~] | Scope (site/env) selector + user preferences | Portal | M | M | ✓ |
| 60 | [~] | Evidence blob store for large artifacts | Exec | M | M | `178466c`/`26fef32` — WRITE side shipped: pure size-threshold core (evidence_store, 64 KiB) + content-addressed evidence_blobs table (mig 150) + ingest offload keyed by the verified digest (dedup, same-tx, small reference inline; also durably persists raw evidence that was previously discarded). Codex-xhigh clean, live-DB verified. READ endpoint is a design-gated follow-up (reopens the deferred evidence-redaction concern; resolver must validate a ref vs agent_jobs.evidence_digest, not trust JSON shape) |
| 61 | [x] | On-call / escalation contact registry | Observ | M | M | — |
| 62 | [~] | audit_log retention / partitioning / archival | Resil | M | M | ✓ |
| 63 | [x] | Observability deploy wiring | Roadmap | M | M | ✓ |
| 64 | [~] | OpenAPI / machine-readable API spec | Roadmap | M | M | `21241af`/`48ccf9a` — OpenAPI 3.1 spec served at public GET /api/agents/openapi.json covering the integration-relevant surface: 6 agent-protocol + 6 public + 4 ops-read endpoints (16 total), hand-maintained (no utoipa dep), with union drift-guard tests (documented paths == AGENT_ROUTE_PATHS ∪ PUBLIC_ROUTE_PATHS ∪ OPS_READ_ROUTE_PATHS). Follow-ups: full human/admin surface (needs utoipa/schemars annotation-driven sync — hand-maintaining hundreds of routes is impractical) + a Swagger-UI viewer |
| 65 | [ ] | Optional gated AI narrative adapter | AIOps | M | M | — |
| 66 | [x] | Release engineering (versioning/tags/changelog) | Roadmap | M | M | ✓ |

_Legend: E = effort (S/M/L), V = value (H/M), 📋 = in `missing-features.md`.
`[x]` shipped · `[~]` partial (core shipped; follow-up tracked) · `[ ]` not started._

## Goal-session review + hardening (2026-07-03/04)

A Fable 5 goal-session ran a 5-agent adversarial review (api / engine / live-exec
/ db / portal), fixed every confirmed finding, shipped missing-feature **#11**
(pre-dispatch IaC policy gate, above), browser-verified the portal, and did a
live-infra test (real terraform + a docker-provider apply/destroy). **24 commits**
(`bab5c13..6268f26`), each GPT-5.5 Codex (xhigh/high) reviewed and pushed:

- **Live-exec integrity:** `aee5b3e` full-plan digest (32 KiB-truncation hole);
  `f163f2b` `ack_job` cross-agent state oracle; `5ddc5be` `software_execute`
  audit attribution + tx-release.
- **Secret/compliance:** `d00eb14` `should_redact` `Password=` asymmetry;
  `ab25d76` audit reads propagate DB errors (no false-empty 200).
- **Correctness:** `4bc3d4c` `domain_events` dynamic WHERE + idx (mig 144);
  `a4ad803` `maintenance_calendar.get_active`; `ac4c0bc`+`0ffdbd6` anomaly
  non-finite/overflow; `67abf56` noise-suppression resurrection.
- **Portal:** `7538ded` id-slice WASM panic; `4023ad8` fail-closed session
  fallback; `fab04c5` no fabricated live-context freshness; `ff6fce8` stale-panel
  reset on nav; `8680de5` bell refetch; `8400cc3` double-click-disable;
  `3da4be8`/`7af40ad`/`6268f26` two-click confirm for Approve&apply / Retire /
  agent Revoke.
- Housekeeping: `2633b13` rustfmt-normalize ryuki-api/engine/runner; `f412759`
  test-build repair.

The loop was then run to CONVERGENCE with three more adversarial passes:
- **Pass 2** (session diff / scheduler+loops / live-exec lifecycle / engine math /
  authz+data): **0** new confirmed defects.
- **Pass 3** (protocol crypto / ryuki-core / ~19 engine domains / integration.rs /
  deploy manifests): **7** confirmed — `ea033b2` secrets-rotation TTL overflow
  panic; `aa86852` outbox parent-dir fsync (crash durability); `6589e10` the
  secret-scan's own quoted-secret blind spot; and the highest-value find of the
  session, `9f43803` **integration.rs cross-scope BAC** — the integration adapter
  had ZERO site-scope enforcement, so a scoped admin token could read / enumerate /
  mutate / credential-test ANY other site's connections; now guarded across all 8
  by-id handlers, all 3 list surfaces, the write-side create/update, and error
  hygiene (3 Codex rounds).
- **Pass 4** (migrations SQL / remaining ~40 engine modules / runner IaC + tf-ansible
  arg construction / portal server-boundary): **1** confirmed — `73697c1` the same
  chrono `+Days` overflow class in `dns_ipam::build_reservation` (IPAM reserve TTL).

Marginal finding rate tapered 0 → 7 → 1 (the last a known-class repeat), so the
review-and-fix loop is **converged/exhausted** for the current surface (~16 distinct
defects fixed, **31 commits** `bab5c13..73697c1`). Remaining `[ ]` rows above are
greenfield features (destroy mode #10, post-apply verify #43, drift-scan #31,
multi-step orchestration #42, inbound webhooks #18, CMDB reconcile #27, AD adapter
#28, DR failover #29, access recert #48, evidence blob store #60, OpenAPI #64, AI
narrative #65), each best built in a focused SDD session. Open design call:
`software_approve` SoD. Recurring class to watch in new code: chrono
`+Days`/`+Duration` on a caller-supplied count — bound it (36_500) + checked_add.

## Swarm review (2026-06-25)

After the clean/additive items above were shipped, a 61-agent multi-lens swarm
review surfaced **41 confirmed new gaps** (real + not-already-covered) — see
[swarm-findings-2026-06-25.md](swarm-findings-2026-06-25.md). These are the
refreshed work queue; the cleanest (High/Small/CI-validatable) are being worked
first. Top: dead `site_status`/`component_status` persistence (#8),
`requests_list` pagination envelope (swarm #9), degradation-mode enforcement.

**Swarm findings shipped:** swarm #4 false-healthy health gauge —
`ryuki_platform_health` db component is now a real timeout-bounded `SELECT 1`
probe with a `source` label (`69b260a`); swarm #5 security-ops audit trail —
token create/revoke, session revoke, secret rotate/rotate-all now write durable
hash-chained `audit_log` rows atomically (`03e532d`); swarm #6 config-mutation
audit — platform settings update/reset now write durable audit rows atomically
(`376f724`); **swarm #7 operational resource-mutation audit trail — COMPLETE in
20 reviewed slices (`3c6a481`→`<final>`): every resource mutation (DNS, IPAM,
firewall, LB, secrets, certificates, gMSA/AD, storage/hw/k8s, DR, backup,
runbook, decommission, emergency, shift, deployments, ServiceNow, etc.) now
writes a durable hash-chained audit_log row atomically; repo fns refactored to
share the caller's tx; ~126 handlers; high-volume telemetry excluded by design**.
Notifications deferred for #5/#6. Swarm #8 degradation persistence — `site_status`/
`component_status` are now DB-backed and survive restart via `repos/degradation.rs`
(`af46a7d`); swarm #9 requests-list total — exposed via `X-Total-Count` header,
backward-compatible (`2f86602`); swarm #12 query safety — per-statement (30s) +
per-lock (10s) timeouts on every pool connection (`6602e57`); **swarm #10
degradation ENFORCEMENT (tracker #16) — `enforce_site_operational` returns 503
when the target site is degraded/unreachable, gating BOTH live-apply grant paths
(`requests_approve_live_apply` + admin `admin_approve_live_apply_job`) before the
CP-signed grant is minted (`5ae1430`)**.

**Swarm wave 2026-06-27 (continued):** #23 degradation-contract typo fix
(`faidefrar`→`failover`, `05d4a21`); #37 readiness-probe symmetric logging
(`92f9619`); #39 GET-by-name AD computer (`32efbf0`); #18 timeout-log enrichment
(request_id + elapsed, `93192e3`); #38 GET-by-id browser session (`e051687`);
#19+#20 PUT update for metric budgets + SLOs (CRUD complete, `4811f40`); #26
scheduler per-tick timeout + skip-missed backpressure (`8738fb2`); #31
exponential backoff on lease/idempotency sweeps (`42606ea`); #40 control-char
rejection on free-text reason/justification fields (`00edcdc`); #29+#36 live
monitoring-review-queue read (`492110a`); #41 live failure-pattern KB read
(`e3b0081`); #28 platform-settings change-history endpoint (`442308b`); #32
(partial) Retry-After on rate-limit 429s (`9d92311`); **#11 (slice 1) operational
domain-event stream — `domain_events` table (mig 110) + emit in
`apply_transition_audited` + scoped `GET /api/events` (`d9b11f0`); alert
generation is the follow-up slice (tracker #22 → `[~]`)**. Already-closed by
prior work: #14 (deny_unknown_fields present), #24 (scope via #2), #25 (DB-backed
via #8), #35 (audited via #5). Remaining findings deferred-with-rationale — see
the triage close-out in [swarm-findings-2026-06-25.md](swarm-findings-2026-06-25.md).

**Swarm wave 2026-06-28:** fresh post-batch analysis (after #19/#23/#58/#52/#17
shipped). Top finding implemented — **per-iteration timeouts for the 5 standalone
background loops** (#26 follow-on): the durable scheduler bounds each tick with a
`tokio::time::timeout`, but `spawn_{lease_expiry,agent_offline,idempotency,slo_breach,budget_breach}`
did not — a stall beyond the pool's 30s statement timeout pinned the loop forever.
New `background.rs` (`iteration_timeout`/`loop_backoff`/`note_failure`/`run_bounded`,
all unit-tested) wraps every loop iteration; a timeout counts as a failure driving
the existing #31 backoff; `MissedTickBehavior::Skip` unified across all 5. codex
plan(rd2)+impl APPROVE. See [background-loop-timeouts.md](background-loop-timeouts.md).
**Background-loop liveness** shipped — a per-loop last-success heartbeat registry in
background.rs (register_loop/record_loop_success/loop_liveness + a pure
classify_loop_liveness) wired into all 5 loops + a 4th `background_loops` probe in
platform_self_health; overdue past a timeout-AND-backoff-aware budget
(2*iteration_timeout(interval)+2*interval) ⇒ down (a page on the status endpoint,
not a k8s drain). codex plan (3 rounds) + impl APPROVE. See
[background-loop-liveness.md](background-loop-liveness.md).
**DR-plan general update (PUT)** shipped — `PUT /api/protect/dr/plans/{id}` mirrors
the rpo-rto handler (pure `update_dr_plan_pure`, xmin CAS, site/status immutable via
deny_unknown_fields→422, scalar `name` synced in `transition`, central
/api/protect→execute gate + site-scope); codex plan(rd2)+impl APPROVE. See
[dr-plan-update-delete.md](dr-plan-update-delete.md). DELETE deferred (needs an
ON DELETE RESTRICT FK reconciled with dr_test_start's store-based resolution).
Integration-connection CRUD was a FALSE POSITIVE — already built in integration.rs
(create/list/get/update/delete/test at /api/integrations).
**repository-capacity GET-by-id + deny_unknown_fields** shipped (small narrow-scan
win) — `GET /api/protect/repository-capacity/{id}` (mirrors forecast's by-id read:
get→404, site_scope_guard_or_404 no-oracle, the update projection) + the update
body now rejects unknown fields (422); codex plan(rd2)+impl APPROVE; router tests
prove the route builds, static siblings (at-risk/report) aren't shadowed, and the
alias survives. Further small wins for follow-up: GET-by-id for /api/admin/tokens
and /api/admin/agents (secret-hygiene: mirror each list's secret-safe projection).
**DR-plan DELETE** SHIPPED — `DELETE /api/protect/dr/plans/{id}` completes DR-plan
CRUD. Included the prerequisite refactor making the DR store DB-authoritative
(`replace_plans` reconcile at startup instead of upsert-on-top, so a deleted plan
can't resurrect on restart) + a scoped `ON DELETE RESTRICT` FK on
`dr_test_runs.plan_id` (mig 124) that blocks deleting a plan with history AND
orphaning a run against a deleted plan, with the `dr_test_start` insert mapping the
FK 23503 to 409. xmin CAS + NOT-EXISTS precheck in `repos::dr_plans::delete`
(`DeleteOutcome`). Codex plan review 3 rounds + impl review 4 rounds. See
dr-plan-delete.md.

**Patch-wave DELETE** SHIPPED — `DELETE /api/maintain/patch/waves/{id}` completes
patch-wave CRUD. VERIFY-FIRST corrected the swarm's "patch-wave CRUD" candidate:
CREATE (`POST /api/maintain/patch/plan`) and UPDATE (the validate/approve/execute/
verify lifecycle transitions) ALREADY existed — only DELETE was missing. Boundary
(codex MAJOR): only an UNAPPROVED draft (`Draft`|`Validated`) is deletable —
`Approved`/`Scheduled` (approver-reviewed; deleting them would cancel approve-tier
work from the execute tier) and `InProgress`/`Completed`/`Failed` (executed; carry
evidence) are blocked 409. The pure `patch_wave_status_deletable` classifier is the
SINGLE source of truth, used by BOTH the handler 409 AND a repo-level `BlockedStatus`
guard (codex MINOR, defense-in-depth). Status-CAS delete (`WHERE id=$1 AND
status=$2`) closes the load→delete race; 0-row re-read disambiguates NotFound vs
StaleStatus. `patch_wave_servers` cascade away (mig 010 ON DELETE CASCADE — plan
membership, not execution evidence). execute-tier via the central gate (method-
agnostic) + per-wave site/env scope guard (out-of-scope → 404, no oracle).
Tombstone-rich audit. Codex plan(rd2)+impl APPROVE; impl-review MINORs both closed
(audit before/after delta assertion; explicit DELETE route-gate test). See
patch-wave-delete.md.

**Certificate DELETE** SHIPPED — `DELETE /api/maintain/certificates/{id}` completes cert
CRUD (verify-first swarm 2026-06-29 #14). Clones the patch-wave-delete pattern, simpler:
certs are a LEAF table (no FK references them → no cascade) and SITE-only scoped. Boundary
(patch-wave lesson): only TERMINAL certs (Expired/Revoked) deletable; Active/Expiring are
LIVE → 409 (revoke first → Revoked → then deletable). Repo `delete` does a status+SITE CAS
(`WHERE id AND status=$2 AND site=$3` — codex caveat: `transition` rewrites site, so the
site guard closes the concurrent-scope-change window) with a 0-row re-read (NotFound vs
StaleStatus) + a `certificate_status_deletable` single-source-of-truth classifier (handler
409 + repo BlockedStatus). execute-tier (method-agnostic /api/maintain gate) + site
scope_guard_or_404 (404, no oracle). Tombstone audit (no key/CSR — leaf table has none).
codex plan+impl APPROVE. See certificate-delete.md.

**Certificate list pagination/filtering** SHIPPED — `GET /api/maintain/certificates/
inventory` enhanced in place (verify-first swarm 2026-06-29 #8). DIVERGED from the swarm's
"new endpoint" rec: /inventory ALREADY IS the cert list, so it gained opt-in q/status/
hostname filters + allowlisted sort + limit/offset pagination + an additive X-Total-Count
header, mirroring requests_list — backward-compatible (no params = unchanged bare array,
newest-first). Scope is UNCHANGED (filtering/sort/pagination applied AFTER retain_site_scoped
so they can only reduce the authorized set; env-scoped → empty + X-Total-Count 0). Invalid
sort/direction → 400; in-handler (no SQL-scope re-derivation = no multi-site leak). codex
plan+impl APPROVE. See certificate-list-pagination.md.

**Auth-gate fix: alert-ack + audit-verify were accidentally admin-only** SHIPPED (2nd
verify-first analysis swarm, 2026-06-29 run 2 — an INTEGRATION-bug audit of this session's
work). The auth middleware gates UNSAFE non-self-service methods via `route_permission_for`,
which fail-closes to `admin` for any path family NOT in `ROUTE_PERMISSIONS`. `/api/events`
and `/api/audit` (bare) were unclassified, so `POST /api/events/alerts/{id}/ack` + `/batch/ack`
(handlers check `request`) and `POST /api/audit/log/verify` (handler checks `audit`) all
resolved to `admin` at the gate — a non-admin principal was 403'd at the middleware and never
reached the handler. Masked because handler-direct tests use the admin `static_dry_run` (which
bypasses the middleware) and the routes weren't in MUTATING_ROUTES. The single-ack bug PREDATES
this session's bulk-alert-ack. Fix: a tight SHAPE matcher `unclassified_family_mutation_
permission` (mirrors `approval_signoff_permission`; NOT a method-agnostic prefix, so other
`/api/events`/`/api/audit` mutations stay fail-closed) → acks `request`, verify `audit`. Tests:
the explicit route_permission_for == assertions + fail-closed assertions (a non-ack/non-verify
path still → admin) + the 3 paths added to MUTATING_ROUTES. codex (round 2 of the analysis)
plan+impl APPROVE; codex swept for the same bug class and found NO others. See
events-route-permission-fix.md.

**Agent queue-depth visibility** SHIPPED — `GET /api/admin/agents/queue-depth` (verify-first
swarm 2026-06-29 #6 READ slice; also the pending-jobs view deferred from #15). Operators had
no view of the pending agent-job backlog per platform (admin_list_agents shows LEASED jobs).
New admin-only aggregate read: per platform with pending work, the `pending_count`,
`oldest_pending_at`, and `top_priority` (`COUNT/MIN/MAX ... WHERE status='Pending' GROUP BY
platform`). Explicit in-handler `check_permission("admin")` (GET routes under /api/admin/ may
not be RBAC-gated). Exposes ONLY aggregates + platform name (no spec/live_context/request_id/
agent ids). The WRITE half of #6 — a MAX_PENDING cap + reject-on-create backpressure (touches
the job-creation critical path) — is DEFERRED. codex plan+impl APPROVE. See agent-queue-depth.md.

**Job prioritization** SHIPPED — priority-weighted agent-job dispatch (verify-first swarm
2026-06-29 #15). Dispatch was strict FIFO by created_at, so a critical job queued behind a
backlog waited. mig 127 adds `priority INT NOT NULL DEFAULT 5 CHECK (0..=9)` + a partial
dispatch index `(platform, priority DESC, created_at, id) WHERE status='Pending'`; the
poll_job ORDER BY is now `priority DESC, created_at, id` (higher first, ties FIFO, id as a
deterministic tie-breaker — codex MINOR). Every existing INSERT omits priority → inherits
the default (no insert changes). New admin endpoint POST /api/admin/agents/jobs/{job_id}/
priority (Extension<AuthSession>, admin-tier, audited) reprioritizes a PENDING job via a
status CAS (a leased/terminal job's queue priority is moot → 409; missing → 404; out-of-
range → 400). Deferred: a pending-jobs-by-platform view exposing priorities (the existing
admin list shows LEASED jobs). codex plan+impl APPROVE. See job-prioritization.md.

**CMDB CI GET** SHIPPED — `GET /api/cmdb/cis/{ci_name}` (verify-first swarm 2026-06-29
#18). The `configuration_items` table (mig 014) was SEEDED but NO API/repo read it — every
`/api/cmdb/*` endpoint served an in-memory mock (the impact graph) or a hardcoded export.
This is the FIRST authenticated, DB-backed CMDB read. New `repos/configuration_items.rs`
(get_by_name by the UNIQUE ci_name — consistent with the impact endpoints' {ci_name}). codex
MAJOR: the central read gate is `audit OR request`, so the handler adds an EXPLICIT
`check_permission("audit")` → audit-only (CI criticality/owner are inventory signals). Site-
scoped via `site_scope_guard_or_404` (out-of-scope → 404, no oracle); 503 with no DB (the
table is the only CI source). A ci_name with a `/` won't route as one matchit segment
(documented; the body returns `id` for a future by-UUID variant). codex plan(NEEDS-CHANGES→
fixed)+impl APPROVE. See cmdb-ci-get.md.

**Bulk alert acknowledge** SHIPPED — `POST /api/events/alerts/batch/ack` (verify-first
swarm 2026-06-29 #19). Only single-event ack existed (operators cleared alerts one-by-one).
Mirrors the #17 requests_batch_* pattern: extracted an `ack_alert_one` core (the per-event
scope-visibility check + ack upsert) shared by the single + batch handlers (behavior-
preserving refactor); the batch checks the `request` capability ONCE, caps at 100, dedups
(order-preserving), runs the SAME per-item scope/ack core (so a batch can NEVER ack an
out-of-scope alert — out-of-scope → per-item 404, no oracle), partial success, HTTP 200
always with {results, succeeded, failed}. Static `/batch/ack` coexists with `/{event_id}/ack`
(matchit static-wins, route-smoke confirms). codex plan+impl APPROVE (MINORs: whole-batch
403 test w/ ack-specific body; dedup proven by the RESPONSE contract not the upsert row;
embedded-control-char note test). See bulk-alert-ack.md.

**Metric series aggregation** SHIPPED — `GET /api/metrics/series/aggregated` (verify-first
swarm 2026-06-29 #10). The raw /metrics/series returned only the most-recent 10k raw
samples; multi-month trend analysis forced client-side aggregation. New endpoint returns
time-bucketed (hourly/daily/weekly/monthly) MIN/MAX/MEAN/COUNT rollups. codex caught two
real defects: (impl MAJOR) the bounded-scan window (`observed_at >= now - span*limit`, added
for the plan MAJOR so it doesn't aggregate all history) is NOT bucket-aligned, so it can
straddle > limit labels — the LIMIT must run NEWEST-first (`ORDER BY bucket DESC LIMIT`
subquery, re-sorted ASC) or the newest buckets get dropped; (impl MINOR) the non-UTC test
must `SET LOCAL TIME ZONE` in a tx so it doesn't leak onto the pooled connection.
UTC-deterministic via the 3-arg `date_trunc(field, observed_at, 'UTC')` (proven under a
non-UTC session); allowlisted+bound granularity; coherent scope via enforce_scope_filters +
IS NOT DISTINCT FROM; request-tier (matches raw /series). SQL aggregation, no migration, no
engine change. codex plan(NEEDS-CHANGES→fixed)+impl(NEEDS-CHANGES→rd2 APPROVE). See
metric-series-aggregated.md.

**Legal-hold expiry scan** SHIPPED — `legal_hold_expiry_scan` durable-scheduler job
(verify-first swarm 2026-06-29 #17). Mirrors `secret_rotation_due_scan` but SIMPLER
(`legal_holds.expiry_date` is a real TIMESTAMPTZ — no parse/malformed signal). Daily
SAFE-INTERNAL-WRITE scan enumerates Active holds within 30 days of (or past) expiry — the
SAME predicate as GET /legal-hold/expiring — classifies via pure
`legal_hold::classify_legal_hold_expiry` and enqueues ONE deduped shift_queue item per
hold; NEVER mutates hold state (release/expire is a deliberate audited human action).
codex MAJOR (boundary/clock): classifier upper bound INCLUSIVE to match the SQL `<=`, PLUS
an `is_actionable` guard so a clock-skew row never yields an `active`-verdict item.
SECRET-HYGIENE: NEVER selects/surfaces the sensitive `reason`/`audit_trail`; the verdict is
keyed `expiry_state` (not `reason`, to avoid the column collision). Cross-tier: shift-queue
reads are execute-tier ⊆ legal-hold audit-tier readers (now pinned by a pure
`execute_holders_also_hold_audit` invariant test). mig 126 seeds the schedule + a partial
unique index. codex plan(NEEDS-CHANGES→all folded)+impl APPROVE. See legal-hold-expiry-scan.md.

**Secret-rotation-due scan** SHIPPED — `secret_rotation_due_scan` durable-scheduler job
(verify-first swarm 2026-06-29 #7). `managed_secrets.next_rotation_due` existed but only
the on-demand `GET /secrets/due` surfaced overdue secrets. New daily SAFE-INTERNAL-WRITE
scan (mirrors `restore_overdue_scan`) enumerates secrets WHERE status NOT IN
('retired','rotating'), classifies via pure `secrets_rotation::
classify_secret_rotation_recency` (millis), and enqueues ONE deduped shift_queue item per
OVERDUE secret. TWO-signal (codex MAJOR): a malformed `next_rotation_due` is SURFACED as a
separate `secret-rotation-invalid-due` item (not silently skipped — no blind spot), and a
bad row never aborts the tick. Secret-hygiene: NEVER selects/surfaces `vault_path`/
`secret_type`; scheduler `detail` is aggregate-only. mig 125 seeds the schedule + two
partial unique indexes. codex plan(NEEDS-CHANGES: 3 MAJOR+3 MINOR all folded in)+impl
APPROVE. See secret-rotation-due-scan.md.

**Approval-decisions ledger read** SHIPPED — `GET /api/requests/{id}/approval-decisions`
(verify-first swarm 2026-06-29 #2). The audit-tier quorum endpoint returns only breadth
AGGREGATES; the per-decision ledger (`request_approval_decisions`: role/decision/actor/
decided_at/reason) was never surfaced. New audit-tier read returns the full ordered
ledger (DETERMINISTIC `ORDER BY decided_at ASC, id ASC` — Postgres now() is tx-scoped, so
the BIGSERIAL id is the tie-breaker for same-tx decisions, not exposed). DIVERGED from the
swarm's approve-tier recommendation (FALSE premise: every approve-holder ALSO holds audit,
and approve-tier would wrongly exclude the audit-only Auditor from an audit ledger). Guard
order mirrors quorum: permission → uuid → no-DB empty → existence+scope (404, no oracle) →
ledger. `reason` documented as audit-visible free text (write-side redaction is the
mitigation). codex plan+impl APPROVE. See approval-decisions-read.md.

**Shipped (clean/additive + tracker features):** #2 site/env-scoped RBAC
(33-commit sweep), #3 SoD (`aa0e188`), #5 audit hash chain (`6bcb231`),
#8 agent approve — revoke deferred (`6d6fb5b`), #63 observability deploy
(`0ce0ed3`).

**#14 slice 1** (`fa1df10`): server-side filters (status/site/environment/
request_type/created_by/q) + allowlisted sort/direction on GET /api/requests,
backward-compatible (bare-array response unchanged). Follow-up slice 2 =
`{items,total}` envelope, paired with the portal #15 faceting work.

**#1** (`29564f5`): durable leader-elected scheduler/job engine — `schedules`
+ `job_executions` (mig 095), pure `ryuki_engine::scheduler`, a 60s
advisory-lock-elected tick (savepoint-isolated per schedule, clock_timestamp
advance, read-only job boundary), seeded hourly self-health probe, and
read-only `/api/ops/scheduler` views. UNBLOCKS #31/#39/#40/#45/#52 (and feeds
#19/#22): each adds its own job kind + seeded schedule. Follow-up (non-blocking):
operator CRUD endpoints to create/enable/disable schedules from the API/portal.

**#34** (`4a6be3c`): general time-series substrate — `metric_samples` (mig 096,
finite-CHECKed) + pure `ryuki_engine::metric_forecast` (least-squares fit,
summary, trend, centered projection) + POST /api/metrics/samples (record) and
GET /api/metrics/series (series+summary+trend+forecast, single-scope via IS NOT
DISTINCT FROM, recent-10k window). ROOTS the AIOps chain #35→#36→#37→#53/#54:
each consumes the series summary (mean/stddev) and/or the forecast.

**#35** (`7b55563`): `ryuki_engine::metric_anomaly` (leave-one-out z-score
anomalies — avoids the in-sample sqrt(n-1) ceiling that would mute small-series
detection — + waste detection Idle/Underutilized) and GET /api/metrics/insights.
Feeds #36 (suggestions) and #53/#54 (budgets).

**#36** (`8392ac7`): `ryuki_engine::metric_suggestions` (waste→RightSizing/
CostOptimization, anomalies→RiskReduction) + POST /api/metrics/insights/generate
persisting into the existing `aiops_suggestions` table — stable dedup key
(scope+type+metric_key, NOT title), transactional batch, scope-label folds in
environment, metric_key charset locked to `[A-Za-z0-9._:-]` (HTML-safe).

**#15** (`1ff463d`, swarm: worktree agent + Codex integration review): portal
faceted filter bar (name search/status/site + Clear) + sortable columns, URL as
single source of truth, wired to the #14 API. Integration review fixed a `q`
name-only/5-field mismatch (would break old `?q=` deep links) + whitespace-only
facets. Follow-up [~]: surface environment/request_type/created_by + pagination.

**#37** (`dfb77c0`): `ryuki_engine::metric_planning::what_if` (project + growth
factor + ceiling-breach) + GET /api/metrics/what-if. Overflow registers as a
breach (not silently dropped); headroom/timestamps null-guarded. AIOps chain
now #34→#35→#36→#37 all shipped; remaining links #53/#54 (budgets) consume the
forecast/what-if vs a threshold.

**#53** (`e3a97c2`): `ryuki_engine::metric_budget` (above/below threshold,
breach now + projected) + budgets CRUD + GET /api/metrics/budgets/status
(alerting-safe: per-budget `error` status + `degraded`, never false-OK). Fixed
a Postgres `NaN=NaN`-is-true CHECK bug in 096/097 (mig 098 back-corrects 096).

**#54** (`22dc496`): `ryuki_engine::metric_commitment::model_commitment`
(committed vs on-demand cost, savings, recommendation) + GET
/api/metrics/commitment. Numerically-stable savings (committed-scale, not
usage-scale cancellation); rejects overflow. **AIOps theme COMPLETE:
#34→#35→#36→#37→#53→#54 all shipped.** The whole `metric_*` engine family is
PURE; all IO is in thin `/api/metrics/*` handlers over one shared injection-safe
query helper.
