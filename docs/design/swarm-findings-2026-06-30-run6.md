# run-6 analysis swarm — 2026-06-30

A 7-finder evidence-grounded discovery sweep (request-lifecycle / agent-execution / correctness /
security-authz / data-retention / observability-ops / api-completeness) → 1 default-refute
adversarial verifier per candidate. **13 candidates → 12 confirmed.** The orchestrator (Opus)
independently re-triaged every confirmed item before acting — and DOWNGRADED several (see triage),
because the verifier confirmed some items that are actually blocked on a deferred decision or whose
proposed fix would BREAK an existing recovery path. ALWAYS re-verify swarm output.

## Orchestrator triage (what to actually do)

### SHIPPED
- **C. No-LIMIT list reads (the two run-5 missed)** — `GET /api/ops/runbook/executions`
  (`repos::runbook_executions::list`) and `GET /api/ops/incident/active`
  (`repos::incident_contexts::list_active`) fetched UNBOUNDED rows. The run-5 no-LIMIT sweep capped
  the INLINE-SQL handlers (slo_list/noise_detect/alert_routes_list/runbook_active) but missed these
  two because they route through REPO list fns. FIX: threaded `limit: i64` through both repo fns
  (bound `LIMIT $N`), handlers pass the shared `MAX_LIST_ROWS=1000`; +2 cap-assertion tests. codex
  impl review pending/approve. (The non-active `incident_contexts::list` is dead_code, no endpoint —
  left unchanged.)

### NEXT (clean, actionable, NOT blocked)
- ✅ **Agent-job admin domain events** (observability) — SHIPPED: `admin_requeue_dead_lettered_job`
  (`job.requeued`) and `admin_set_job_priority` (`job.reprioritized`) now emit a NON-alerting
  domain event atomically (inside the tx, after audit, before commit), mirroring the cancel/
  force-fail pattern. `to_status` sentinels 'admin-requeued'/'admin-reprioritized' are NOT in
  alert_worthy_statuses() so they never page (codex verified vs the `to_status = ANY($1)` prefilter
  + classify). Platform-global (site/env None → no B0 leak). aggregate_id is the CANONICAL uuid
  (codex Low finding — raw path string could miss /api/events lookups; siblings flagged as a
  follow-up task). priority UPDATE RETURNING extended to include platform. +event assertions on the
  requeue/reprioritize happy tests. codex impl APPROVE (1 Low fixed); green on a fresh DB.
- **Stage completion timestamps** (request-lifecycle, high) — `completed_request_stage()`
  (contracts.rs ~14856) sets `started_at: None, completed_at: None`, so post-completion stages
  (verify/protect/publish/retire + validate/execute) persist NULL timestamps in the stages JSONB,
  unlike the engine which always stamps them. Audit/temporal-ordering gap. FIX: stamp both to
  `Utc::now().to_rfc3339()` in the helper. RE-VERIFY first: confirm no caller relies on None and the
  engine-vs-handler asymmetry is unintended (the swarm says it is).

### SUSPECT — do NOT implement as proposed (re-verify / likely false or harmful)
- **Dead-lettered job leaves parent request stuck `executing`** (agent-execution, claimed high/bug).
  The proposed fix (auto-fail the parent request in the dead-letter branch) would BREAK the
  dead-letter→requeue RECOVERY path: `admin_requeue_dead_lettered_job` REFUSES a concluded request,
  so "stuck executing" is plausibly DELIBERATE to keep requeue possible. The real gap (if any) is
  observability, not auto-conclusion. NEEDS a design decision, not a blind fix. → flag, don't ship.

### BLOCKED on the B0 event-feed scope decision (already flagged to owner)
- **integration_update / integration_delete / integration_set_credential_expiry missing domain
  events** (observability, med/med/low). These are `integration_connection` = SITE-SCOPED aggregates
  (site=Some, env=NULL) → they would hit the EXACT B0 leak (env-NULL permissive policy leaks
  site-only events to env-only-scoped principals) that BLOCKED the decommission events. The verifier
  missed this. Do NOT ship until B0 is resolved. (Audit rows already exist for these mutations; only
  the domain-event feed is missing.)

### DESIGN DECISION — owner-owned (trust model), do NOT guess
- **LiveRefused marks request `failed` instead of recoverable** + **no operator re-approve control
  for LiveRefused jobs** (agent-execution, high/med). When an agent refuses a LiveApply (missing
  grant / plan divergence / no --allow-live), the request is terminal-failed and there is no API to
  correct the cause and retry the same job. Whether LiveRefused SHOULD be recoverable vs terminal is
  a deliberate trust-model decision (the live path was GPT-hardened). Flag to owner.

### NON-FINDING
- **Empty audit `detail` for protect/publish/retire** — the verifier itself concluded this is a
  DELIBERATE design pattern (detail for decision/exception handlers; transition evidence lives in the
  `stages` field via TransitionArtifacts). Audit trail is complete. No action.

## Cross-cutting decisions still open for the owner (unchanged from run-5)
- **A0**: execution-plane admin surface (agents.rs) not site-scoped — only matters if scoped-admin
  tokens are a real deployment (admin-with-no-scope is superuser).
- **B0**: /api/events feed scope leak for site-only aggregates (env-NULL permissive policy) — blocks
  ALL site-scoped lifecycle domain events (decommission/AD/incident/integration).
- **Background scheduler loop-wedge** emits no domain event.
- **F (run-5)**: audit redaction is key-pattern-only — scope EXTREMELY tightly (high false-positive).
