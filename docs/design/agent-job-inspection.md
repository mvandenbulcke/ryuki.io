# Admin agent-job inspection endpoint (run-5)

## Problem

The agent-job admin surface lets an operator act on a job (cancel / force-fail / reconcile /
reprioritize), and read a TERMINAL job's attestation (`GET …/result`). But there is NO way to read
an IN-FLIGHT (`Leased`/`Running`) job's operational state. To decide whether to force-fail a stuck
job, an operator needs to SEE it: which agent holds it, when the lease expires, how many redispatch
attempts it has taken, how long it's been stuck. The queue-depth and dead-lettered list are
aggregates; there is no single-job state read.

## Approach

`GET /api/admin/agents/jobs/{job_id}/state` (admin-tier, read-only). Parses the id before `get_db`
(a malformed id 404s even during a DB outage — codex precedent from `…/result`). Projects only the
NON-SECRET operational/lifecycle columns:
`id, request_id, platform, mode, status, result_status, agent_id, lease_deadline,
delivery_attempts, evidence_digest, created_at, updated_at, completed_at`.

SECRET-SAFE — the projection DELIBERATELY excludes every secret/large column: `spec` (vars),
`fencing_token` + `cp_nonce` (the unguessable fencing material), `live_context` (the CP-signed
LiveApply grant), `evidence_json` (agent free-form), `signed_envelope` (the attestation, served only
by `…/result`), and the `attempt_id`/`lease_generation` fencing internals. `404` for a missing id.

Routing — `…/state` is a 5-segment path, the SAME shape as `/result` etc., NOT a bare 4-segment
`…/jobs/{job_id}`. A bare 4-segment route would share its segment count with
`…/agents/{agent_id}/approve|revoke`, and because matchit prioritizes the static `jobs` segment over
the `{agent_id}` param, `POST /api/admin/agents/jobs/approve` would resolve to `jobs/{job_id=approve}`
and (since the bare route is GET-only) return 405 — silently breaking approve/revoke for an agent
literally named "jobs" (codex). The 5-segment `…/state` avoids that 4-segment level entirely. (The
`full_app_route_tree_builds_without_panic` test only proves the tree BUILDS, not method dispatch — it
is necessary but not sufficient for this class of collision.)

## Scope note (A0)

Consistent with the rest of the execution-plane admin surface, this read gates only on
`check_permission("admin")` — it is NOT site-scoped, like the ~12 sibling agent-job admin handlers.
Whether that surface should be scoped is the deferred A0 design decision
(swarm-findings-2026-07-01-run5.md); if it is later swept, this endpoint is covered uniformly.

## Tests
- inspect a Leased job → 200 with the operational fields; the response body contains NONE of
  `spec` / `fencing_token` / `cp_nonce` / `live_context` / `signed_envelope` / `evidence_json`.
- unknown id → 404; non-admin → 403.

## Risk / rollback
Pure additive read: one handler + one route, a secret-safe projection. No mutation, no migration.
Rollback = revert.
