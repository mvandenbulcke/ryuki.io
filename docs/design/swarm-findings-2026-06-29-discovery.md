# Missing-features DISCOVERY swarm — 2026-06-29 (run 3)

A 6-finder multi-modal discovery sweep (lifecycle / observability / security / data-integrity /
scheduler-automation / portal) → 1 adversarial verifier per gap (17 candidates → 15 CONFIRMED).
These are NEW gaps beyond the run-1/run-2 backlog (swarm-findings-2026-06-29.md) + the items shipped
this session. `value`/`risk` are the ADVERSARIAL-adjusted figures.

## Shipped from this swarm
- ✅ **Fleet-wide circuit-breaker status list** (H/S) — `GET /api/integrations/circuits` (f667a63).
  The one durable failing-integration signal that had no aggregate operator view.

## CONFIRMED, open — agent/request lifecycle
- **ReconcileRequired resolution endpoint** (H/M, product-ambiguous): `expire_leases` sets LiveApply
  jobs to terminal-dead-end `ReconcileRequired` (agents.rs:1569) with NO route/handler to move them
  off it — the highest-risk job mode has no governed closure (the inverse of DeadLettered→requeue).
  Slice: `POST /api/admin/agents/jobs/{id}/reconcile` CAS `ReconcileRequired`→`Failed`, audited. ✅ SHIPPED — admin CAS→Failed + audited reason + a non-alerting `job.reconcile_resolved` event; parent request left Executing (operator /fails separately). codex plan+impl APPROVE. See reconcile-required-resolve.md.
- **ReconcileRequired emits no alert + strands the parent request** (H/S): unlike the dead-letter
  branch (emits a Critical `job.dead_lettered` event, agents.rs:1520), the ReconcileRequired branch
  emits NOTHING and never touches the requests row — the request sits in `Executing` silently.
  Slice: emit a `job.reconcile_required` event in that branch, mirroring the dead-letter block. ✅ SHIPPED — emits the event + made `reconcile-required` alert-worthy (Critical) so the alert feed surfaces it (parity with dead-letter). codex APPROVE.
- **Cancel/abort a Pending agent job** (M/M, needs a `Cancelled` status + 1-line CHECK migration):
  create/reprioritize/requeue exist but NO cancel — a job dispatched to a platform with no healthy
  agent sits Pending forever (parent stuck Executing). Slice: `POST .../jobs/{id}/cancel` CAS
  Pending→Cancelled, audited.

## CONFIRMED, open — security / audit (NON-hot-path)
- **Integration-connection MUTATION handlers write no audit_log row** (H/S): only `integration_test`
  audits (integration.rs:1114); create/update/delete/circuit_reset/set_credential_expiry mutate
  credential-bearing connections with NO forensic trail. ✅ DELETE SHIPPED (352c80b) — atomic
  DELETE+audit (tx + `DELETE … RETURNING` + record_audit_tx; engine `delete_connection_returning`
  fixes the no-DB TOCTOU; secret-safe detail). codex plan+impl APPROVE. See
  integration-delete-audit.md. ✅ CREATE / UPDATE / SET-CREDENTIAL-EXPIRY SHIPPED — atomic
  mutation+audit per branch (all `INSERT/UPDATE … RETURNING` so the detail reflects the persisted
  row; plain-update RETURNING also closed a latent TOCTOU); redaction-safe detail keys
  (`cred_source`/`cred_rotated`/`cred_expires_at` — the #58 convention, with a read-path-redaction
  test); 6 DB tests incl. no-secret-leak + read-path. codex plan+impl reviewed. See
  integration-mutation-audit.md. ✅ CIRCUIT_RESET SHIPPED — same atomic record_audit_tx-before-commit
  pattern (it already had the tx + FOR-UPDATE existence row + DELETE); audits the PRIOR state via
  `DELETE … RETURNING state` — `previous_state` + `breaker_cleared` (true only for a tripped prior
  state, since a healthy `closed` row can be persisted — codex). ✅ THEME COMPLETE: every integration mutation (create / update /
  delete / set-credential-expiry / circuit_reset) now writes an atomic, secret-safe audit row.
  (The companion "no site-scope guard" finding is MOOT: admin = superuser in this RBAC.)

## CONFIRMED, open — scheduled automation (the durable-scheduler scan pattern, now shipped 3×)
Each is an on-demand `…/expiring` endpoint with NO proactive scan job — the exact pattern
secret-rotation/legal-hold/recertification filled (engine classifier + run_job arm + seed migration
+ partial-unique-index dedup; instance-specific dedup key where the id may be reused):
- **TLS certificate expiry scan** (M/S) — `certificate_lifecycle`. ✅ SHIPPED (592942c) —
  `certificate_expiry_scan` (mig 130); predicate on valid_to (not stale status); priority-by-state
  (Expired→P1, ExpiringSoon→P2) + open-item REFRESH so soon→expired upgrades in place. codex
  plan+impl APPROVE. See certificate-expiry-scan.md.
- **OOB-management cert-endpoint expiry scan** (M/S) — `oob_endpoints`.
- **gMSA service-account expiry scan** (M/S) — `gmsa_lifecycle::get_expiring`.

## CONFIRMED, open — data retention (unbounded history once a sweep is scheduled)
- **scheduler `job_executions` history prune** (M/S) — ✅ SHIPPED (720a1d0): `job_executions_prune`
  (mig 131) keeps newest-N-per-schedule (keep 10000, sized to the 5-min cadence) + a per-run batch
  cap so a years-old backlog drains over days. codex plan+impl APPROVE. See job-executions-prune.md.
- **`connection_health_checks` history prune** (M/S) — ✅ SHIPPED: `connection_health_checks_prune`
  (mig 132) generalizes the prune helper (closed PruneTarget enum) for the fastest-growing table;
  runs HOURLY (so the per-run cap keeps up with per-connection growth) + a retention index
  (connection_id, checked_at DESC NULLS LAST, id DESC). codex plan+impl APPROVE. See
  connection-health-checks-prune.md.

## CONFIRMED, open — portal (Leptos; backend exists, no UI surface)
- **Request `rework`→Intake action absent from the portal** (H/S) — a near-twin of the already-wired
  reject button (both approve-tier, both →a non-running stage). Path: portal/portal-ui/src/.
- **Approval quorum + decision ledger has no portal surface** (M/S) — two shipped scope-guarded GETs
  (approval-decisions, approval-quorum) with no read-only UI panel.
- **Per-request policy-readiness (policy-eval) not shown in request detail** (M/S) — single
  scope-guarded GET, informational.

## Adversarially DOWNGRADED (do NOT pursue as framed)
- audit_retention "enforcement": audit_log/domain_events are append-only BY DESIGN (a BEFORE-DELETE
  trigger raises) — there is nothing to "enforce"; not a real gap.
- on-call contact global (NULL-site) lookup: changing the existing list filter is product-ambiguous
  (could alter current admin-UI behavior) — defer.
