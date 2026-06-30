# run-8 focused deep-dive — AUTH / SESSION / TOKEN lifecycle — 2026-06-30

After run-5/6/7 swept 14 broad dimensions (diminishing returns), a FOCUSED single-agent deep-dive on
the security-critical auth/session/token lifecycle that the broad sweeps had not examined end-to-end.

## Result: the auth path is SOUND (verified-clean audit record)
Verified by reading the real code — recorded here so a future session does NOT re-audit:
- **OIDC id_token** (oidc_callback.rs ~377-448): RS256 pinned (header AND Validation), required claims
  {exp,nbf,iss,aud}, iss/aud pinned from config, nonce verified post-signature (single-use → no timing
  advantage). Alg-confusion (alg=none / HS256 downgrade) blocked.
- **OIDC state / CSRF / fixation** (oidc_callback.rs ~546-581, repos/oidc_login_states.rs): state is
  single-use via `DELETE ... RETURNING`, `expires_at > NOW()` enforced, login-CSRF HttpOnly binding
  cookie compared to a binding column (stolen state can't replay in a victim browser), session_id =
  server-generated Uuid::new_v4() (no fixation), no open redirect.
- **Entra JWT** (entra_auth.rs ~339-420): same RS256/iss/aud/exp/nbf pattern; JWKS RSA-only + use=sig +
  32-key cap + 1 MB body + 300s refresh cooldown; fail-closed (zero roles) on every failure.
- **Session lifecycle** (contracts.rs ~370-388): EVERY session lookup includes `AND expires_at > NOW()`
  — no path admits an expired session; Local mode further restricts `provider='local'`.
- **Logout / revocation** (contracts.rs ~12187, ~14043): server-side `DELETE FROM sessions`; admin
  force-revoke `DELETE /api/admin/sessions/{id}` is transactional + audited.
- **CSRF for mutations** (contracts.rs ~436-461, main.rs ~953): cookie-sourced sessions REFUSED for all
  unsafe methods; only X-Ryuki-Session-Id header or Authorization: Bearer authorizes mutations.
- **API token (ryk_)** (contracts.rs ~279-328): SHA-256 + `subtle::ConstantTimeEq`; query filters
  `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`.
- **RBAC / privilege** (main.rs ~899-1023): roles come ONLY from validated token claims or the
  persisted sessions.roles column — never client-supplied; route table fail-closed (default admin).
- **Local auth password compare** (ryuki-core/config.rs ~1081): constant-time, fixed-length, all-users
  iteration (no early-exit timing oracle). (Plaintext passwords in config = known dev-mode tradeoff.)

## Shipped
- ✅ **generate_agent_token() now uses OsRng** (agents.rs ~197) — was `rand::thread_rng()` while the
  rest of the auth/crypto surface uses OsRng. thread_rng IS a CSPRNG, so this is a CONSISTENCY /
  defense-in-depth alignment on the agent bearer token, not a vulnerability fix.

## Non-finding
- Agent-token query lacks a `revoked_at` filter — but the `status != 'approved'` check + DELETE-based
  revocation mean there is NO bypass (deleted row → fetch None → 403). Only a design asymmetry (no
  audit trail of post-revocation auth attempts); not a defect.

## Conclusion (auth)
The control plane's auth surface is thoroughly hardened.

---

# run-8b — NUMERIC / ANALYTICS correctness deep-dive

A second focused deep-dive on the analytics/aggregate math (the area that previously had the
mean-formula under-count). The math is otherwise SOUND (verified clean: per-VM utilization sum,
sane_pct NaN/Inf clamp, util_pct div-by-zero guard, SLO attainment/error-budget with all guards,
budget breach operators >/<, metric_series_step span/(n-1), leave-one-out variance, repository
TB→GB conversion, centered projection, commitment savings, compliance % div-by-zero guards).

## Shipped
- ✅ **forecast_capacity storage_at_risk was ALWAYS true** (cost_capacity.rs ~312) — SHIPPED:
  storage USAGE isn't tracked (VmUtilization has only provisioned storage_gb; get_site_capacity sets
  used_storage = total_storage), so current_storage_pct was always 100%, projected = 100+2.2*months
  always > 80, at_risk_storage always true → the recommendation ALWAYS said "Capacity expansion
  recommended" regardless of real CPU/memory. FIX (codex plan-reviewed — three states risky/not-risky/
  NOT-MEASURABLE): storage_at_risk=false + storage_risk_assessed=false + a storage_note, storage
  utilization %s set to null (no fabricated value), recommendation driven by cpu||mem ONLY, dead
  storage computation removed. +strengthened test (recommendation.contains("expansion") == cpu||mem).
  No portal/handler consumer of storage_at_risk. codex plan+impl reviewed.

---

# run-8c — LIFECYCLE STATE MACHINES deep-dive

Deep-dive on the non-request lifecycle machines. Decommission / AD-computer / certificate /
firmware-golden-image all VERIFIED CLEAN (hard-error decode on unknown status — NOT a fallback default;
two-token CAS — status + updated_at or valid_to; FOR UPDATE on golden-image promote; proper terminal
guards). Only the INCIDENT machine had a real gap.

## Shipped
- ✅ **Incident "resolved" was not a terminal state** (ryuki-engine/src/incident_context.rs) — SHIPPED:
  resolve_incident_pure / add_affected_ci_pure / escalate_pure had NO status guard, so a RESOLVED
  incident could be re-resolved (silently overwriting the resolution — the xmin CAS doesn't prevent it,
  xmin advances on every UPDATE) or have a CI appended / its escalation mutated post-closure
  (contaminating the compliance/review record). Unlike decommission/AD/cert, which all guard their
  terminal states. FIX: fail-closed guard `if ctx.status != "active" { Err }` in all three pure fns
  (only an active incident is mutable). +unit test test_resolved_incident_is_terminal_and_immutable.
  15 incident engine tests + 7 incident DB tests green. codex review pending.

## Flagged (low, task_7981ce77)
- secrets_deregister hardcodes audit from_status="active" regardless of the real prior status, and its
  UPDATE has no `WHERE status<>'retired'` guard (a re-deregister is a silent no-op that still writes a
  misleading audit row). Plus a latent ManagedSecretRow::to_engine() unknown-status → Active fallback
  (vs the fail-closed hard-error decode the AD/cert repos use). Not exploitable without a corrupt DB
  value.

## Conclusion (overall)
Combined with run-5/6/7, bug-discovery is at clear diminishing returns — most machines/subsystems verify
clean; the few remaining finds are isolated (the analytics always-expand recommendation, the incident
terminal-guard gap). Remaining high-value work is the owner-decision items (A0/B0 etc.) + larger
data/execution-plane feature build-out. SESSION: 16 codex-reviewed commits across run-5/6/7/8.
