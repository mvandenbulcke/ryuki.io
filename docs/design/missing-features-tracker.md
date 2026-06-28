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
| 11 | [ ] | Pre-dispatch policy gate for unsafe IaC | Exec | M | H | — |
| 12 | [ ] | Agent-side vault-backed secret resolution | Exec | L | H | ✓ |
| 13 | [~] | Request rework/fail/soft-delete transitions | API | M | H | ✓ |
| 14 | [~] | List filtering/search + pagination envelope (API) | API | M | H | ✓ |
| 15 | [x] | Faceted request filtering/sort/pagination (portal) | Portal | M | H | facets `3a32da0` (env/request_type/created_by) + pagination `a62a80b` (offset/limit page-nav, over-fetch has_next since the portal can't read X-Total-Count, offset clamp, pure tested helpers; codex APPROVED). exact total via X-Total-Count `2535fee` (UpstreamResponse now carries the header; "Showing X-Y of N", inverted-label guarded). FULLY complete |
| 16 | [x] | Enforced site degradation mode (write gating) | Resil | L | H | — |
| 17 | [~] | Bulk / batch operations | API | M | H | — |
| 18 | [ ] | Inbound integration webhook receivers | Integ | L | H | — |
| 19 | [x] | Connection health monitoring (scheduled + history) | Integ | M | H | scheduled sweep shipped — durable-scheduler `connection_health_sweep` (leader-elected, #40 safe-internal-write recipe): lists ALL connections, runs the pure `test_connection_stub` (NO live resolve_credentials), appends a `connection_health_checks` row + refreshes `last_test_*` on the tick tx, deterministic stub credential verdict, aggregate-only detail, no dedup (time series). mig 120 seeds the schedule only (mig 102 already had the index). codex APPROVED round 2 (3 test-quality fixes folded in: restore-seeded-sweep, full seed-contract idempotency, exact-message branch coverage). On-demand probe + history read already existed |
| 20 | [ ] | Step-up / MFA re-auth for high-risk actions | Security | M | H | — |
| 21 | [ ] | Live secret rotation (Vault) + break-glass | Security | L | H | ✓ |
| 22 | [x] | Domain-event alert generation | Observ | M | H | — |
| 23 | [ ] | CP-side poison-job cap / dead-letter | Resil | M | H | — |
| 24 | [x] | Audit-trail export / streaming to SIEM | Observ | M | H | — |
| 25 | [x] | SLO / error-budget tracking | Observ | M | H | — |
| 26 | [x] | CP database backup/restore + DR runbook | Roadmap | M | H | ✓ |
| 27 | [ ] | Bidirectional CMDB reconciliation + drift | Integ | L | H | ✓ |
| 28 | [ ] | Active Directory / Entra integration adapter | Integ | L | H | — |
| 29 | [ ] | DR failover orchestration (runbook-driven) | Resil | L | H | — |
| 30 | [x] | Circuit breaker for provider/adapter calls | Resil | M | H | — |
| 31 | [ ] | Scheduled/recurring agent jobs (drift-scan) | Exec | L | H | ✓ |
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
| 42 | [ ] | Multi-step orchestration / job dependencies | Exec | L | M | ✓ |
| 43 | [ ] | Post-apply verification (re-plan → Verified) | Exec | M | M | — |
| 44 | [x] | Agent liveness sweep + offline detection | Exec | M | M | ALREADY DONE — spawn_agent_offline_scan (main.rs, 60s/180s) + agent_offline_scan_once emits agent.offline/agent.online on state transitions, deduped via offline_alerted (mig 114), with notifications + to_status warning alert. (A durable-scheduler port was scoped but abandoned as redundant — codex plan-review caught the existing emitter.) |
| 45 | [x] | Per-site / per-tenant usage metering | Observ | M | M | — |
| 46 | [x] | Chargeback / showback cost allocation | AIOps | M | M | — |
| 47 | [x] | Backup verification + restore-test recency | Resil | M | M | — |
| 48 | [ ] | Enforced access recertification w/ revocation | Security | L | M | — |
| 49 | [x] | Secret update & deregistration | API | S | M | — |
| 50 | [x] | Evidence pack file download / export | Portal | S | M | — |
| 51 | [x] | Per-vendor connection capability catalog | Integ | M | M | — |
| 52 | [ ] | Route DR-overdue/failed tests into work queue | Resil | S | M | — |
| 53 | [x] | Cost/capacity budget thresholds + alerts | AIOps | M | M | — |
| 54 | [x] | Reserved-capacity / commitment cost modeling | AIOps | M | M | — |
| 55 | [x] | DNS record update endpoint | API | S | M | — |
| 56 | [x] | IPAM subnet CRUD | API | M | M | — |
| 57 | [x] | Load-balancer virtual-server delete/update | API | M | M | — |
| 58 | [ ] | Connection usage audit trail | Integ | M | M | — |
| 59 | [~] | Scope (site/env) selector + user preferences | Portal | M | M | ✓ |
| 60 | [ ] | Evidence blob store for large artifacts | Exec | M | M | — |
| 61 | [x] | On-call / escalation contact registry | Observ | M | M | — |
| 62 | [~] | audit_log retention / partitioning / archival | Resil | M | M | ✓ |
| 63 | [x] | Observability deploy wiring | Roadmap | M | M | ✓ |
| 64 | [ ] | OpenAPI / machine-readable API spec | Roadmap | M | M | ✓ |
| 65 | [ ] | Optional gated AI narrative adapter | AIOps | M | M | — |
| 66 | [x] | Release engineering (versioning/tags/changelog) | Roadmap | M | M | ✓ |

_Legend: E = effort (S/M/L), V = value (H/M), 📋 = in `missing-features.md`.
`[x]` shipped · `[~]` partial (core shipped; follow-up tracked) · `[ ]` not started._

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
