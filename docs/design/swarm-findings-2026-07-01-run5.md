# run-5 analysis swarm — 2026-07-01

A 7-finder discovery+correctness sweep (request-lifecycle / agent-execution / correctness /
security-authz-secrets / data-retention / observability-ops / api-completeness) → 1 adversarial
verifier per candidate (default NOT-confirmed). **28 of 40 confirmed**, ranked
backend-verifiable-first. ALL items here were confirmed by the verifier; the orchestrator (Opus)
independently re-verifies before implementing — and ALREADY corrected one (the scope cluster is
8 handlers, not the 4 the verifiers found; see below).

## Clusters (confirmed)

### A. No-DB-branch scope guard (the IN-PROGRESS sweep)
Request-lifecycle mutation handlers whose **no-DB** branch lacks the scope guard their DB branch has
(cross-scope mutation in DB-less mode). Hand audit: **8** handlers (validate/plan/lock/execute/verify
/protect/publish/retire), NOT the 4 the verifier reported (verify/protect were wrongly called
guarded). See no-db-scope-guard-sweep.md. MEDIUM (no-DB-only). → **being fixed now.**
- Integration mutations (delete/set-credential-expiry/circuit_reset) + agent-job mutations "bypass
  site-scope" — LIKELY MOOT: those are admin-only and admin-with-no-scope is unrestricted. VERIFY the
  admin=superuser assumption before acting (the run-3 doc already flagged the integration one moot).

### B. Observability — lifecycle transitions emitting NO domain event (can't alert/observe)
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
  `runbook_active()` — fetch ALL rows (medium-high/S-M).

### D. Unclamped numeric inputs → 500 / overflow (the validity_days bug class)
- Unclamped `offset` → negative OFFSET 500 in requests_list + "various SQL queries" (high-medium/S).
  (Same class as the admin_platform_settings_history fix in 49979a0 — sweep ALL `?offset=` handlers.)
- Unclamped `duration_minutes` → unbounded time arithmetic (medium/M).
- subnet `total_ips` i32 without complete overflow guard (medium/M).

### E. Admin/operator capabilities + API completeness
- No admin capability to manually trigger/expedite the lease-expiry sweep (high/S).
- No admin force-fail / force-complete for a stuck Running/Leased job (high/M) — complements the
  Pending-cancel just shipped (covers the OTHER end of the lifecycle).
- No operator inspection endpoint for Leased/Running job state (only result retrieval) (high/M).
- Compliance controls + findings missing individual GET endpoints (medium/S).

### F. Security — redaction
- Audit redaction is key-pattern-only — free-text `reason`/`detail` values could carry a secret a
  user typed (medium/M). (Careful: high false-positive risk; scope tightly.)

## Suggested order (backend-verifiable, impact × confidence)
1. No-DB scope guard sweep (A) — IN PROGRESS.
2. Background-loop wedge domain event (B, CRITICAL).
3. Offset-clamp sweep (D) — quick, closes a 500 class.
4. shift_queue prune (C) — extends the proven prune pattern.
5. Lifecycle domain events (B: decommission/AD/incident) — proven event pattern.
6. Stuck-job force-fail/complete + job inspection (E) — completes the agent-job lifecycle.
