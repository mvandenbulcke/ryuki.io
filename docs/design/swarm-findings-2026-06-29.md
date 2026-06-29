# Missing-features analysis findings — 2026-06-29

A 29-agent verify-first analysis swarm (6 domain-cluster finders → an adversarial
verifier per candidate that tried to PROVE each already exists or is inert) over the
ryuki.io control plane, run after patch-wave DELETE shipped (`ca27de07`). **19 confirmed
gaps** of 23 raw candidates; **4 correctly refuted** (the verify-first discipline working).

Ranked: value (H→M), then effort (S→M). `verdict`: CONFIRMED_MISSING = truly absent;
PARTIAL = some exists, a specific additive slice is missing.

| # | Val | Eff | Verdict | Feature |
|---|-----|-----|---------|---------|
| 1 | H | S | PARTIAL | **approve_one no-DB scope guard** — lone batch-mutation core missing the no-DB scope 404 (cross-scope approve + oracle in dry-run). ✅ SHIPPED — codex plan+impl APPROVE; see approve-one-nodb-scope-guard.md. |
| 2 | H | S | PARTIAL | GET /api/requests/{id}/approval-decisions — quorum endpoint returns only aggregates; individual (role, decision, actor, decided_at, reason) never surfaced. ✅ SHIPPED (at AUDIT-tier, not the swarm's approve-tier: every approve-holder also holds audit, and approve-tier would wrongly exclude Auditor from an audit ledger). codex plan+impl APPROVE. See approval-decisions-read.md. |
| 3 | H | M | CONFIRMED | Approval decision withdrawal/recall (POST .../approval/{role}/withdraw) — own-role only, pre-quorum; no withdrawal path exists |
| 4 | H | M | CONFIRMED | Policy-driven required_approval_roles (the #4 quorum capstone) — needs a policy SOURCE; 2-part (criticality input + plan-time policy). See criticality-approval-policy-4.md (DEFERRED) |
| 5 | H | M | CONFIRMED | Operator-initiated failed-job retry (non-dead-lettered) — only DeadLettered requeue exists; a Failed request can't re-execute without full rework |
| 6 | H | M | CONFIRMED | Per-platform job-queue depth limit + backpressure — no queue-depth metric. ✅ READ SLICE SHIPPED — GET /api/admin/agents/queue-depth (admin: pending_count/oldest/top_priority per platform). Backpressure (cap + reject-on-create, critical path) DEFERRED. codex plan+impl APPROVE. See agent-queue-depth.md. |
| 7 | H | M | CONFIRMED | Scheduled scan for secret rotation due-dates — GET /secrets/due is on-demand only; no scheduler job kind. ✅ SHIPPED — `secret_rotation_due_scan` durable-scheduler job kind (two-signal: overdue + malformed-date), mig 125. codex plan(NEEDS-CHANGES→fixed)+impl APPROVE. See secret-rotation-due-scan.md. |
| 8 | H | M | CONFIRMED | Certificate LIST endpoint — only GET /{id}, /inventory, /expiring; no paginated/filtered list. ✅ SHIPPED — ENHANCED /inventory in place (not a new endpoint; /inventory already IS the list) with opt-in q/status/hostname filters + allowlisted sort + limit/offset + X-Total-Count, backward-compatible, scope preserved via retain_site_scoped. codex plan+impl APPROVE. See certificate-list-pagination.md. |
| 9 | H | M | CONFIRMED | Outbound alert notification delivery (email/webhook) — SmtpConfig is dead code; notifications are in-app read-receipts only; ~40 "notification-dispatch-disabled" blocked reasons |
| 10 | H | M | CONFIRMED | Metric series aggregation/rollup (daily/weekly/monthly buckets) — /metrics/series returns raw 10k window only. ✅ SHIPPED — GET /api/metrics/series/aggregated: UTC-deterministic date_trunc buckets (MIN/MAX/MEAN/COUNT), bounded scan window, newest-N-buckets, coherent scope. codex plan+impl(rd2) APPROVE. See metric-series-aggregated.md. |
| 11 | H | M | PARTIAL | Per-agent/per-principal rate limiting — rate limiter is IP/path-group keyed only; no principal_id in the key |
| 12 | H | M | CONFIRMED | Enforced access recertification w/ scheduled revocation — campaigns are read-only; no deadline-enforcement scheduler job; status never transitions to Completed |
| 13 | H | M | PARTIAL | API token per-usage audit trail + activity metrics — last_used_at is non-durable; no per-usage audit_log; no usage endpoint |
| 14 | M | S | CONFIRMED | Certificate DELETE endpoint — repos/certificates.rs has no delete(); mirror patch-wave-delete pattern. ✅ SHIPPED — DELETE /api/maintain/certificates/{id}, only TERMINAL (Expired/Revoked) deletable; status+site CAS; leaf table (no cascade); tombstone audit. codex plan+impl APPROVE. See certificate-delete.md. |
| 15 | M | M | CONFIRMED | Job prioritization / fair queuing per platform — dispatch is FIFO by created_at; no priority column. ✅ SHIPPED — priority column (mig 127, default 5, 0..=9) + dispatch ORDER BY priority DESC, created_at, id + POST /api/admin/agents/jobs/{id}/priority (admin, pending-only CAS, audited). codex plan+impl APPROVE. See job-prioritization.md. |
| 16 | M | M | CONFIRMED | Job execution deadline (distinct from lease TTL) + SLA tracking — only the 300s lease boundary exists |
| 17 | M | M | CONFIRMED | Scheduled scan for legal-hold expiry — GET /legal-hold/expiring is on-demand; no scheduler job kind. ✅ SHIPPED — `legal_hold_expiry_scan` durable-scheduler job (mig 126); inclusive-boundary classifier + is_actionable guard (no clock-skew 'active' item); secret-hygiene (NEVER surfaces the hold `reason`; cross-tier safe via execute⊆audit, now invariant-tested). codex plan(NEEDS-CHANGES→fixed)+impl APPROVE. See legal-hold-expiry-scan.md. |
| 18 | M | M | CONFIRMED | CMDB CI GET endpoint — configuration_items table seeded but no API/repo reads it. ✅ SHIPPED — GET /api/cmdb/cis/{ci_name}: the FIRST authenticated DB-backed CMDB read (audit-only, site-scoped, 503-no-DB). New repos/configuration_items.rs. codex plan+impl APPROVE. See cmdb-ci-get.md. |
| 19 | M | M | CONFIRMED | Bulk alert acknowledge (POST /api/events/alerts/batch/ack) — only single-event ack. ✅ SHIPPED — mirrors requests_batch_* (cap 100, dedup, per-item scope via the extracted ack_alert_one core, partial success, HTTP 200). Suppress/silence deferred. codex plan+impl APPROVE. See bulk-alert-ack.md. |

## Refuted (verify-first caught these — do NOT re-flag)
- **Verifying → Completed transition** — ALREADY EXISTS: POST /api/requests/{id}/verify (requests_verify, contracts.rs:16769) transitions Verifying→Completed via apply_transition_audited.
- **Legal-hold lifecycle handlers** (validate/extend/release/evidence) — ALREADY EXIST: routed at contracts.rs:1147-1163, fully implemented + tested.
- **Backup restore operations** (coverage-report/restore-plan/validate/approve/execute) — ALREADY EXIST: contracts.rs:1547-1566, repos restore_requests.rs + backup_coverage_reports.rs.
- **Firmware device UPDATE** — ALREADY EXISTS via the correct domain: POST /api/datacenter/hardware/update-firmware/{id} (hardware_assets); a PUT on firmware_records (compliance tracking) would be inert.

## Note on #4 (policy-driven required_approval_roles)
Still gated by the same 2-part constraint documented in criticality-approval-policy-4.md:
requests.criticality is hardcoded "standard", so a criticality→threshold policy alone is
inert. A dedicated change must add the create-side criticality input first. An
offering/approval_policies table is the alternative policy source.
