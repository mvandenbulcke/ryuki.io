# run-5 analysis swarm — 2026-07-01

A 7-finder discovery+correctness sweep (request-lifecycle / agent-execution / correctness /
security-authz-secrets / data-retention / observability-ops / api-completeness) → 1 adversarial
verifier per candidate (default NOT-confirmed). **28 of 40 confirmed**, ranked
backend-verifiable-first. ALL items here were confirmed by the verifier; the orchestrator (Opus)
independently re-verifies before implementing — and ALREADY corrected one (the scope cluster is
8 handlers, not the 4 the verifiers found; see below).

## Clusters (confirmed)

### A0. NEW (codex, force-fail review): execution-plane admin surface is NOT site-scoped
`agents.rs` does not import `scope_guard_or_404`; NONE of its ~13 admin handlers (reconcile, cancel,
priority, dead-letter requeue, queue-depth, result, force-fail, …) scope-guard the parent request —
admin is treated as platform-global. A SCOPED admin (admin role + a `site_scope`) can mutate/
state-oracle an out-of-scope job. DESIGN DECISION: is the execution-plane admin surface meant to be
site-scoped? If yes → a dedicated sweep across ALL agent-job admin handlers (incl. the shipped
cancel/reconcile/force-fail), resolving the parent request from `spec.request_id` + `scope_guard_or_404`.
HIGH value if scoped-admin tokens are a real deployment. (Deferred from the force-fail slice — fixing
one handler in isolation is inconsistent.)

### A. No-DB-branch scope guard (the IN-PROGRESS sweep)
Request-lifecycle mutation handlers whose **no-DB** branch lacks the scope guard their DB branch has
(cross-scope mutation in DB-less mode). Hand audit: **8** handlers (validate/plan/lock/execute/verify
/protect/publish/retire), NOT the 4 the verifier reported (verify/protect were wrongly called
guarded). See no-db-scope-guard-sweep.md. MEDIUM (no-DB-only). → **being fixed now.**
- Integration mutations (delete/set-credential-expiry/circuit_reset) + agent-job mutations "bypass
  site-scope" — LIKELY MOOT: those are admin-only and admin-with-no-scope is unrestricted. VERIFY the
  admin=superuser assumption before acting (the run-3 doc already flagged the integration one moot).

### B0. NEW (codex, decommission-event review): event-feed scope leak for site-only aggregates
The /api/events feed scope predicate (repos/domain_events.rs:82-83) makes `environment IS NULL` rows
visible to ANY env-scoped principal (the deliberate permissive policy). A SITE-ONLY aggregate's
events (site=Some, env=NULL — e.g. decommission, and site-only SLO/budget) therefore leak to an
env-ONLY-scoped principal (site_scope=[], env_scope=[…]) who is UNRESTRICTED on site and passes the
env axis via NULL — even though the site-only handlers (site_scope_guard_or_404) FAIL CLOSED for that
principal. The decommission observability events (B below) were implemented + REVERTED for this
reason. Resolving it is a cross-cutting decision (the deliberate permissive policy vs site-only-handler
strictness; affects SLO/budget too) — flagged as a spawn_task. Until then, the decommission/AD/incident
lifecycle events (B) are BLOCKED on this decision (they'd hit the same leak).

### B. Observability — lifecycle transitions emitting NO domain event (can't alert/observe)
NOTE: decommission/AD/incident are site-scoped aggregates → their events hit the B0 leak → BLOCKED on
the B0 scope-policy decision. Do NOT ship these events until B0 is resolved.
- **Background scheduler loop wedge emits no domain event** (CRITICAL/M) — a wedged loop only shows
  a 503 on /api/platform/health/loops; no queryable/acknowledgeable event. event_alerts has no
  `background_loop`/`platform` aggregate. HIGH real-world impact (silent scheduling stop).
- Decommission lifecycle (quarantine/execute/rollback) emits no domain events (high/S).
- AD-computer lifecycle (disable/enable/delete/move) emits no domain events (high/M).
- Incident-context lifecycle (resolve/add-ci/escalate) emits no domain events (high/M).
- Lease-expiry transitions: no audit trail + no event visibility (medium/M).

### C. Unbounded growth / no-LIMIT reads
- `shift_queue` grows unbounded — no prune (the 3 prunes covered job_executions/connection_health
  /check_results but NOT shift_queue). (high/M) — note: resolved items accumulate.
- No-LIMIT list reads: `noise_detect()` noisy_triggers, `alert_routes_list()`, `slo_list()`,
  `runbook_active()` — fetch ALL rows (medium-high/S-M). ✅ SHIPPED: `MAX_LIST_ROWS=1000` cap
  (defense-in-depth) on all 4; runbook_active ALSO pushes the active (non-terminal) filter into SQL
  (`WHERE status NOT IN ('completed','failed','rolled-back')`) so it no longer fetches the unbounded
  terminal-execution history. codex plan+impl APPROVE.

### D. Unclamped numeric inputs → 500 / overflow (the validity_days bug class)
- Unclamped `offset` → negative OFFSET 500 in requests_list + "various SQL queries" (high-medium/S).
  (Same class as the admin_platform_settings_history fix in 49979a0 — sweep ALL `?offset=` handlers.)
- ~~Unclamped `duration_minutes` → unbounded time arithmetic~~ FALSE POSITIVE (verified): the
  field is `u32` (max ~8167 years of minutes, within chrono's TimeDelta range) AND noise_suppress
  uses `checked_add_signed` (returns None on overflow, no panic). Unlike validity_days (plain `+`,
  `days` reaching year >262143). NOT a bug.
- ~~subnet `total_ips` i32 without complete overflow guard~~ FALSE POSITIVE (verified): `usable_hosts`
  computes in `u64` (`1u64 << 32` safe) + clamps to u32::MAX; validate_subnet_fields guards the
  prefix==0 shift-by-32; the API guards `total_ips > i32::MAX` before the i32 bind. NOT a bug.
  (Two false positives → the swarm verifier's confidence is imperfect; ALWAYS re-verify type bounds.)

### E. Admin/operator capabilities + API completeness
- No admin capability to manually trigger/expedite the lease-expiry sweep (high/S).
- No admin force-fail / force-complete for a stuck Running/Leased job (high/M) — complements the
  Pending-cancel just shipped (covers the OTHER end of the lifecycle).
- No operator inspection endpoint for Leased/Running job state (only result retrieval) (high/M).
- ✅ Compliance controls + findings missing individual GET endpoints (medium/S) — SHIPPED:
  controls already had `compliance_control_get`; findings now have `GET /api/audit/compliance/findings/{id}`
  (`compliance_finding_get` + repo `get_finding`), scoped on the parent report's site (findings have no
  own site column), out-of-scope 404s like missing (no oracle). codex impl APPROVE; ran green on a fresh DB.

### F. Security — redaction
- Audit redaction is key-pattern-only — free-text `reason`/`detail` values could carry a secret a
  user typed (medium/M). (Careful: high false-positive risk; scope tightly.)

## Suggested order (backend-verifiable, impact × confidence)
1. ✅ No-DB scope guard sweep (A) — SHIPPED a08f1ac (6 handlers).
2. Background-loop wedge domain event (B, CRITICAL).
3. ✅ Offset-clamp sweep (D) — SHIPPED 9f6b8ab (clamp_offset_usize at 3 sites).
4. ✅ shift_queue prune (C) — SHIPPED: resolved+age prune (a NEW shape — open items never pruned),
   90-day retention, daily, capped; mig 137 (seed ffff + retention index). codex plan+impl APPROVE.
5. Lifecycle domain events (B: decommission/AD/incident) — proven event pattern.
6. ✅ Stuck-job force-fail (E) — SHIPPED (eed6c01): admin force-fail of a Leased non-LiveApply job
   (spec.mode authoritative; LiveApply → reconcile path).
7. ✅ Job inspection (E) — SHIPPED: GET /api/admin/agents/jobs/{job_id}/state (secret-safe lifecycle
   read; 5-seg path avoids the /jobs/approve 405 shadow; sentinel value-leak test + routing-dispatch
   regression). The A0 agent-job-admin scope-guard sweep + background-loop wedge event remain.
8. ✅ Compliance finding GET-by-id (E) — SHIPPED: GET /api/audit/compliance/findings/{id}
   (`compliance_finding_get` + repo `get_finding`); parent-report-site scope guard, out-of-scope 404s
   like missing. codex impl APPROVE; new test green on a fresh DB alongside the 26 compliance tests.
   Remaining run-5 backlog: A0 scope sweep (flagged), background-loop wedge event (flagged), B/B0
   lifecycle events (blocked on the B0 scope-policy decision, flagged), F redaction (scope tightly).
