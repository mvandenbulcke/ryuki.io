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

---

# run-8d — IPAM / DNS ALLOCATION deep-dive

HIGH-yield area (3 findings). usable_hosts /31//32//0 edges, gateway=network/broadcast rejection,
DNS TTL>i32::MAX rejection, record-type closed match, VLAN 4095 rejection, DB-path counter atomicity
all verified sound.

## Shipped
- ✅ **Double-allocation TOCTOU race in ipam_reserve_ip** (HIGH) — SHIPPED: the DB handler read the
  reservations + computed counters OUTSIDE the tx and only locked the subnet's `site` FOR UPDATE, so two
  concurrent reserves both picked the SAME IP (no UNIQUE on ip_reservations) AND both wrote
  available=N-1 (the second overwriting the first → duplicate IP + wrong counter). FIX: moved the FULL
  locked-subnet re-read + reservation re-read + build_reservation + counter compute INSIDE the tx under
  the subnet FOR UPDATE (the unlocked pre-read is now only a fast not-found/scope check); decrement via
  saturating_sub. +handler test (two reserves → distinct IPs, counters move by exactly 2). codex review
  pending.

## Flagged (task_3c4259be)
- **next_ip ignores the CIDR prefix** (high/med) — `for host in 10..255` on the first 3 octets, so for any
  non-/24 subnet it allocates IPs OUTSIDE the range (10.0.0.0/30 → "10.0.0.10") and misses valid IPs;
  skips .2-.9 always. Needs a proper CIDR-range rewrite. (Plus: release_ip uses non-saturating
  available_ips += 1, asymmetric with used_ips saturating_sub.)

---

# run-8e — PATCH / MAINTENANCE / REBOOT ORCHESTRATION deep-dive

Result: SOUND. No clean bug. Verified: CAS optimistic-lock on wave transitions (UPDATE ... WHERE
status=$ + rows_affected check); half-open `[)` overlap/conflict detection (engine `overlaps` + DB
`tstzrange '[)'`); draft-only validate / validated-only approve / approved-only execute chain enforced
in both the pure engine fns AND the DB CAS; reboot-policy guard (NoReboot/ScheduleOnly rejected); ISO
parse returns None → no false conflict.

The deep-dive's two "high" findings were RE-VERIFIED as DELIBERATE DESIGN (not bugs):
- get_active uses inclusive `<= end` while the conflict checker uses half-open `[)`. This is defensible:
  an inclusive "active" end is SAFER (the boundary instant is still treated as in-maintenance) while
  half-open conflict detection deliberately allows back-to-back window scheduling. Different purposes,
  not an inconsistency to "fix" (and the exact-end-instant edge has ~nil practical impact). LEFT.
- patch_reboot has no wave-status guard — but it is PLANNING-ONLY ("evidence-only, does NOT transition
  the wave") and is structurally IDENTICAL to the sibling planning endpoint patch_verify (also
  status-agnostic). Only the state-TRANSITIONING patch_execute guards status. So patch_reboot is
  consistent by design; the finder mis-compared it to execute. LEFT.

## Flagged (feature, not a bug — task)
- orchestrate_reboot emits ONE drain stage for ALL servers + per-server reboots + ONE final health
  check — no batched/rolling rollout with inter-batch health gates (the reboot-orchestration contract
  mentions rebootBatches). For a real rolling reboot this is all-at-once. It's a dry-run PLAN today, so
  this is a missing FEATURE (batched rollout plan), not a correctness bug.
- (minor) validate_patch_policy treats empty blackout_dates as INFO not FAIL — but it is NOT the
  authoritative path (validate_patch_wave re-implements checks inline); only an old test uses it. Low.

---

# run-8f — ALERT ROUTING / NOISE / SLO deep-dive

3 findings amid a strong verified-clean list (classify/alert_worthy union + per-aggregate rules locked by
test; resolve_alert_route is a unique 3-field key lookup — no precedence shadow; slo/budget breach-scan
dedup via the breaching flag flipped atomically with the event; Above `>` / Below `<` thresholds; ack
scope per-item; suppress_trigger CAS `WHERE status <> 'Suppressed'`; scheduler scans use enqueue_if_absent
+ prefilter-superset).

## Shipped
- ✅ **overall_status ignored breached_count** (slo_status + metrics_budget_status, contracts.rs ~21512 /
  ~21033) — SHIPPED: `overall_status = if errored_count>0 {"degraded"} else {"ok"}` reported "ok" while
  SLOs/budgets were actively breached (breached_count>0), so a health gate reading the field saw green.
  FIX: 3-way `errored>0 -> degraded; breached>0 -> breached; else ok`. +test (a breaching SLO ->
  breached_count>=1 AND overall_status != "ok"). codex review pending.

## Shipped (2/2 confirmed)
- ✅ **ack_alert accepts ANY domain_event id** (med) — SHIPPED (commit 1c5b367): no alert-worthy guard, so
  acking a non-alert ('completed'/'intake') event succeeded + wrote a dangling alert_acks row. FIX:
  ack_alert takes `alert_statuses: &[String]` + gates on `payload->>'to_status' = ANY($2)` (the same
  alert_worthy set list_alerts uses); a non-alert id 404s like a missing one. Both single + batch paths
  covered via ack_alert_one. +test (platform-wide non-alert event -> 404 + no alert_acks row). codex APPROVE.

## Re-verified FALSE POSITIVE (the finder's main claim was wrong)
- **"noise suppression never auto-expires -> hidden from detection forever"** — RE-VERIFIED FALSE on the
  detection claim. BOTH detect_noise (noise_remediation.rs:148) and the DB-path noise_detect
  (contracts.rs:10723) filter ONLY on `event_count_last_24h > 10` (+ site) with NO status filter — so a
  Suppressed trigger IS still returned by detection (noise-004 with event_count 89 is NOT hidden). The
  only residual is a stale STATUS LABEL: a Suppressed trigger's status never auto-reverts to Active past
  suppress_until, so noise_suppressed_list / the status-summary counts show it as still-suppressed. That
  is a LOW data-accuracy issue, cleanly fixable with a daily expiry SCAN JOB (flip Suppressed->Active when
  suppress_until <= NOW(), matching the established restore_overdue_scan / legal_hold_expiry_scan pattern).
  Flagged as a low-priority scan-job feature — NOT the high "hidden detection" bug the finder claimed.

## Conclusion (overall)
Combined with run-5/6/7, bug-discovery is tapering but still productive — focused deep-dives split between
isolated real bugs (analytics always-expand, incident terminal-guard, IPAM double-allocation race + the
next_ip CIDR bug, the overall_status health field) and SOUND results (patch/maintenance, most of auth,
the alerting CORE). The discipline of RE-VERIFYING every finding matters: across run-8, several "findings"
were deliberate design choices I correctly did NOT "fix". Remaining high-value: the owner-decision items
(A0/B0 etc.), the flagged follow-ups, + larger data/execution-plane build-out. SESSION: 19 codex-reviewed
commits across run-5/6/7/8.
