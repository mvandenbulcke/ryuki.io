# Missing-features execution tracker

A 9-area analysis swarm (2026-06-24) produced 66 ranked missing features
(deduped from 69 raw, every claim spot-checked against code). The owner approved
implementing **all 66**. This file tracks execution.

## Execution model

- **Serial, dependency-ordered.** Each feature lands as one slice: design →
  migration (sequential number) → engine/API/portal → tests → gate → adversarial
  review → commit + push. Features are NOT built in parallel — they collide on
  migration numbers and on the hot shared files (`contracts.rs`, `main.rs`).
- **Gate per slice:** `cargo fmt --all`; `cargo clippy --workspace --all-targets
  -- -D warnings`; `cargo test -p ryuki-api --bins`; the relevant `*_db_tests`
  with `RYUKI_DATABASE_URL`; `bash scripts/dependency-audit.sh`;
  `bash scripts/no-secret-scan.sh`. Then an adversarial review before commit.
- **Engines stay pure** (validator-enforced no-IO); record co-authorship
  where applicable.

## Key dependencies (drive ordering)

- **#1 scheduler** unblocks #31, #39, #40, #45, #52 (and feeds #19, #22).
- **#2 administrable/scoped RBAC** precedes #48 (recert revocation).
- **Analytics chain (strict):** #34 metric history → #35 detection → #36
  generation → #37 what-if → #53/#54 budgets/commitment.
- **#14 API list/pagination** precedes #15 / #59 (portal faceting/scope).
- **require-key rollout (idempotency 2b+)** precedes requiring keys on
  portal-called routes — needs `UpstreamClient` to send keys first.

## Platform security-boundary convergence (P0)

The repository-wide security review at revision
`8212748308372e92d9cf794907d85fe103afd1da` found that several individually
useful controls still have distributed ownership. The normative remediation is
the [Platform Security Boundary Specification](../architecture/platform-security-boundary.md).
It supersedes the assumption that completing isolated backlog rows such as #2,
#20, #21, or #48 is sufficient for production identity and authorization.

Track the convergence as one dependency-ordered P0 program:

| Package | State | Outcome |
| --- | --- | --- |
| SB-0 Contract, bootstrap, and fail-closed profiles | `[ ]` | Missing/unknown profiles and invalid production configuration fail before bind; production cannot start with development auth, mock dependencies, insecure transport/cookies, an open/reopened first-owner path, or a missing/stale/unreconciled external conformance trust checkpoint; the executable deployment-security-profile root and provider/action/resource/conformance/limit/checkpoint schemas, route coverage, privileged-domain separation, and versioned no-downgrade contracts are complete. |
| SB-1 Unified human identity and sessions | `[ ]` | A singular credential-admission classifier and versioned authenticator registry support multiple generic OIDC issuers, brokered SAML/LDAP/AD, separate ordinary and break-glass WebAuthn, native/device/service OAuth profiles, API/workload identities, one durable `SessionRepository`, CSRF, step-up, and lifecycle revocation. |
| SB-2 Typed authorization and scoping | `[ ]` | One default-deny action/resource registry issues unforgeable permits only after typed obligations pass; protected collection queries require kernel-issued query permits across all actor kinds, routes, owner/site/environment/tenant scope, and DB/no-DB paths. |
| SB-3 Approval, transition, and audit binding | `[ ]` | Principal lifecycle/authority versions, control-plane authority epoch, policy, actor/effective subject, scope, plan/provider identity, quorum, idempotency, transition, and outbox are bound atomically; audit is independently anchored and exported without silent gaps. |
| SB-4 Machine identity and key lifecycle | `[ ]` | Invite/key-bound enrollment, proof of possession, rotatable workload identity, signing keyring, and replay protection replace ambient bearer trust. |
| SB-5 Credential brokerage and bounded execution | `[ ]` | Capability-tested Vault/OpenBao/cloud/enterprise adapters issue job-scoped capabilities; governance records, runtime references, leases, material, resolution, dynamic issuance, lease control, key custody, certificate issuance, version publication, and CSI/ESO/VSO materialization remain separate; complete secret handling and bounded work obey the active security-limit profile. |
| SB-6 Deployment and supply-chain integrity | `[ ]` | Immutable privileged inputs, complete scan scope, safe build contexts, signed digest-bound SBOM/provenance, deployment admission, and an owned vulnerability/exception lifecycle cover every deployable and rollback artifact. |
| SB-7 Adapter, egress, and data boundary | `[ ]` | First-party adapters are provenance-bound; every plugin is out-of-process and capability-sandboxed; credential-bearing redirects fail closed; classification, executable retention, privacy/audit reconciliation, backups, and orthogonal deployment/tenancy/trust-topology gates are enforced. |
| SB-8 Distributed security operations and recovery | `[ ]` | Governed policy/config changes, cryptographic inventory, authority epochs/fencing, trusted time, fair distributed budgets, degraded modes, explicit RTO/RPO, authenticated recovery media, compromise response, and restore-without-resurrection are implemented and rehearsed, including separately governed strongly consistent trust-checkpoint custody and recovery reconciliation. |
| SB-9 Security-state migration, bypass retirement, and production acceptance | `[ ]` | Expand/migrate/verify/contract and rollback fencing are proven, legacy fallbacks are removed, and local plus operator-owned identity-provider, secret-manager/PKI, and live acceptance evidence passes. |

SB-2 now has a first permit-bearing instance slice for
`GET /api/requests/{id}`. Authentication middleware retains exact session or
federated credential evidence; the request repository revalidates it, resolves
only the minimal resource projection, reserves audit evidence, and consumes a
typed `AuthorizationPermit` in the same SQL transaction or local-store lease
before loading the full record. SB-2 remains open because collection reads,
mutations, remaining resources, machine actors, multi-tenant scope, and the
production registry/provider rollout have not yet converged on this boundary.

SB-1 now has an identity-epoch slice in migration 165 and an explicit
interactive-human assignment slice in migration 182. Local, OIDC, and Entra
carriers require a versioned provider/issuer/subject role and site/environment
assignment; Unknown/Revoked deny, Global is explicit, asserted authority is
intersected, and assignment updates delete older sessions. Direct Entra bearer
traffic uses the same database boundary. Local credential/role changes,
federated callback role changes, and delivered monotonic lifecycle events also
invalidate older persisted sessions; non-local sessions fail closed after the
bounded authority-freshness interval.
SB-1 remains incomplete because no authenticated SCIM, back-channel logout,
CAEP/RISC, or OIDC-broker lifecycle connector and no operator-owned IdP
disable/role-revocation/assignment-readback acceptance evidence exists yet.
Multi-replica Recreate/rollback rehearsal also remains trusted-access evidence.
Those residuals are not a reason to remove the provider-neutral OIDC, brokered
SAML/LDAP, passkey, or workload-identity boundary.

Centralized validation is complete for the pinned revision. Attack-path
analysis is complete for the 320 candidates that entered that phase: 232 remain
reportable (3 High, 169 Medium, and 60 Low) and 88 were rejected after
calibration; 48 candidates did not enter attack-path analysis. These interim
counts come from the strict attack-path aggregate. Until the
top-level manifest, finding/coverage records, and generated report are
finalized, that checksummed aggregate is the per-instance policy source; the
canonical report becomes authoritative only after finalization. Neither source
claims that a rendered production deployment was tested.

SB-0 gates every later package; SB-1 and SB-2 gate SB-3; SB-3 through SB-7 gate
any live pilot; SB-8 gates production; and SB-9 requires a machine-readable
zero-consumer/retired-bypass receipt. Every package emits a conformance-linked
exit receipt and cannot self-declare completion from this tracker row.

Cross-package acceptance also tracks these implementation artifacts rather than
leaving their behavior implicit:

- a machine-readable conformance ledger that separates evidence provenance tier
  from lifecycle state, maps every permanent acceptance-case id to its static
  control/applicability/package/owner/fixture/pass condition, and binds each
  evaluated provider/deployment evidence instance through a separate
  `ConformanceBundle`; it rejects missing, orphaned, duplicate, expired,
  downgraded, wrong-revision, insufficient-tier, or silently skipped controls;
- published schemas for the deployment-security-profile root, provider
  registry, closed action/resource/resolver registry, `ControlTrace`,
  `ConformanceBundle`, package exit receipt, external conformance trust-
  checkpoint response, and versioned
  `SecurityLimitProfile` as the sole owner of selected values, published
  defaults, platform hard bounds, and separate value-change and bound-change
  authority;
- a production-only external conformance trust-checkpoint authority keyed by
  deployment, trust domain, and registry id, authenticated from a separately
  governed workload/deployment channel. Startup is equality-only reconciliation
  of exact head version, raw digest, and locator under one linearizable head/
  acceptance sequence; it cannot auto-bootstrap or advance. Its live custody,
  trusted-time, minimum-epoch, compare-and-swap administration, and restore
  evidence remain open SB-8 work and cannot be satisfied by repository fixtures;
- explicit `site_registry.create` and `site_registry.lifecycle.toggle` actions:
  creation is unscoped-platform authority, while a toggle may admit only an
  unscoped admin or a matching canonical site-scoped admin with no environment
  scope; the typed authorized target must survive unchanged through repository,
  audit, and engine boundaries;
- versioned state machines for provider registration/removal, provider-qualified
  identity and explicit account linking/unlinking, browser sessions and step-up,
  API-token families/versions, and revocation;
- separate `SecretReferenceRecord`, runtime `SecretRef`, lease metadata,
  non-serializable material, resolver, issuer, lease, cryptographic-key,
  certificate, publisher, and materializer interfaces, with a pinned provider-
  capability/conformance baseline and negative tests for every enabled adapter
  and version;
- explicit delegation records that bind delegator, delegate, audience, action,
  resource/scope intersection, expiry, chain depth, and revocation, without
  converting a service or system actor into a human principal; and
- restore reconciliation against external IdP, secret-manager, PKI/KMS, and
  policy authority so a backup cannot resurrect externally revoked identity,
  delegation, credentials, leases, or keys before readiness reopens;
- externally anchored audit checkpoints and acknowledged transactional-outbox
  export so database rewrite or SIEM delivery gaps are independently detectable;
  and
- release admission that verifies artifact/SBOM/provenance subjects and signer,
  plus signed recovery-set manifests whose verification trust is separated from
  primary and backup-writer authority.

## Backlog (rank order; `[x]` = shipped)

| # | ✓ | Feature | Area | E | V | 📋 |
|---|---|---|---|---|---|---|
| 1 | [x] | Durable scheduler / background job engine | Roadmap | L | H | ✓ |
| 2 | [x] | Administrable, site/env-scoped RBAC | Security | L | H | ✓ |
| 3 | [x] | Separation-of-duties on approval (no self-approve) | Security | S | H | ✓ |
| 4 | [x] | Multi-role approval quorum | Security | M | H | ENFORCED `1fc0e6d` (mig 118 requests.required_approval_roles DEFAULT 1; FOR UPDATE-locked quorum eval in apply_approval_decision_audited; engine unchanged; approved after 3 review rounds that caught lost-completion + lost-evidence races + a 409/400 regression). Deferred follow-up: policy SOURCE that raises required_approval_roles above 1 from the offering/criticality at plan time (today the column defaults to 1, so enforcement is wired + tested but exercised only when a request sets it) |
| 5 | [x] | Tamper-evident audit hash chain + verify | Security | M | H | ✓ |
| 6 | [x] | Dependency-backed platform self-health probes | Roadmap | L | H | ✓ |
| 7 | [x] | Protect/Publish/Retire actions in portal | Portal | M | H | ✓ |
| 8 | [x] | Agent enrollment approve/revoke from portal | Portal | M | H | `0edc1ea`+`14e8e87` — revoke (API+portal): terminal revocation, atomic audit on approve+revoke, admin re-check, idempotent; approve was already shipped `6d6fb5b` |
| 9 | [ ] | Outbound notifications (email/webhook/callback/chat) | Roadmap | L | H | ✓ |
| 10 | [~] | Destroy/teardown execution mode (live decommission) | Exec | L | H | Terraform `LiveDestroy` is implemented for system-authorized reverse-order compensation after a failed multi-step live run. A successful request still has no operator-governed destroy endpoint; the first test therefore requires the reviewed state-keyed cleanup procedure in `docs/first-test.md`. |
| 11 | [x] | Pre-dispatch policy gate for unsafe IaC | Exec | M | H | SHIPPED — pure `ryuki_engine::iac_policy::evaluate_iac_bundle` (no-IO) refuses live-mode IaC with unsafe constructs: TF `provisioner` blocks + `data "external"` (line-based HCL scan, comment/block-comment aware); Ansible `check_mode` non-truthy override + legacy `always_run`, `raw`/`script` (incl. FQCN + `action`/`local_action` first-token resolution), external `include/import_*`/`roles`/`import_playbook` (fail-closed as Unscannable), YAML merge-keys resolved via `apply_merge` before scan, non-`.tf`/`.yml` files fail-closed. Wired into all 4 runner live entry points (TF+Ansible plan/apply) BEFORE init/providers → `RunStatus::Failed` + `POLICY-REFUSED` summary. Conformance test: every bundled offering passes. An adversarial review found 5 Ansible bypasses on round 1 (check_mode `0`/`"n"`, action-mapping inline args, action-wrapped includes, `<<` merge keys, top-level import_playbook) — ALL fixed + regression-tested; round 2 re-review confirmed closed |
| 12 | [ ] | Agent-side pluggable secret-store resolution | Exec | L | H | Target contract covers Vault, OpenBao, Azure Key Vault, AWS Secrets Manager, Google Secret Manager, and mounted-secret adapters with workload identity and honest lease/rotation capabilities; see SB-5. The control-plane compatibility seam now uses a provider-neutral `SecretResolver` with a fail-closed Vault adapter and explicit development adapter, but typed `SecretRef`, provider registry/versioning, workload identity, lease metadata, and agent-side resolution remain open. |
| 13 | [~] | Request rework/fail/soft-delete transitions | API | M | H | ✓ |
| 14 | [~] | List filtering/search + pagination envelope (API) | API | M | H | Slice 1: requests_list — filters (status/site/env/type/created_by/q) + allowlisted sort + limit/offset + X-Total-Count (`1f5ecfa`). Slice 2 `1bd4686` — bounded networking-inventory lists (dns_records/ipam_subnets/firewall_rules). Slice 3 `526ea96` — bounded security/admin lists (secrets_list site-scoped; admin_sessions_list + admin_tokens_list, which gained a shared all-Optional AdminListPage query, auth-gate preserved; + a unique `id` tie-breaker on the admin created_at ordering for stable pages). All non-breaking (existing keys kept, generous 500 default cap), scope-safe COUNT, independently reviewed, live-DB tested. Remaining: other unbounded lists (patch_waves, failure_patterns, …) — same pattern, piecemeal. NOT doing the breaking {items,total} envelope (bare-array/object + X-Total-Count is the chosen shape). Minor known nit: typed Query rejects malformed ?limit before in-body authz (400 not 403; no data exposed, authn still first) |
| 15 | [x] | Faceted request filtering/sort/pagination (portal) | Portal | M | H | facets `3a32da0` (env/request_type/created_by) + pagination `a62a80b` (offset/limit page-nav, over-fetch has_next since the portal can't read X-Total-Count, offset clamp, pure tested helpers; approved in review). Exact total via X-Total-Count `2535fee` (UpstreamResponse now carries the header; "Showing X-Y of N", inverted-label guarded). FULLY complete |
| 16 | [x] | Enforced site degradation mode (write gating) | Resil | L | H | — |
| 17 | [x] | Bulk / batch operations | API | M | H | Slice 1 `requests_batch_cancel`; slice 2 batch REJECT shipped — POST /api/requests/batch/reject mirrors batch-cancel (dedupe, cap 100, shared reason, per-item independent tx, partial success, HTTP 200). Factored `reject_one` core shared by single+batch; closed a latent no-DB scope gap in single reject (now scoped like cancel + the DB path); batch-only ≤2000 reason cap (single unchanged); denial audited once via non-id sentinel. Plan (round 2) + implementation approved. Slice 3 rework+fail shipped — POST /api/requests/batch/{rework,fail} mirror the reject template; extracted `rework_one`/`fail_one` cores (shared single+batch) and closed the SAME latent no-DB scope gap in single rework + fail; rework→approve, fail→execute (segment-gate auto-maps both); fail records each item's OWN current stage (per-item proven). Plan + implementation reviewed. Slice 4 (FINAL) batch APPROVE shipped — POST /api/requests/batch/approve. Extracted `approve_one` (shared single+batch) reusing `apply_approval_decision_audited`, so a batch CANNOT bypass the #4 multi-role quorum: each id gets THIS approver's ONE decision; a required_approval_roles>1 request stays Planned (quorum_met=false) until N distinct roles+approvers — PROVEN by a no-bypass test (one approver → planned + decision recorded; distinct 2nd approver → approved). Per-id result carries request_status + quorum_met; SoD/scope per-item inside the core. Plan + implementation reviewed. #17 COMPLETE (cancel/reject/rework/fail/approve). POST-SHIP HARDENING (verify-first swarm 2026-06-29): `approve_one` was the LONE batch-mutation core missing the NO-DB scope guard its siblings have — a scoped approver in dry-run could approve an out-of-scope request (cross-scope mutation + existence oracle). Added the exact sibling guard (`is_scoped && !row_scope_permits` → 404) to approve_one's first no-DB lock block (404 precedes SoD/engine, mirroring the DB ordering) + a `batch_approve_no_db_is_site_scoped` test asserting the out-of-scope item's EXACT per-result 404 (no-oracle proof). Plan (minor feedback folded in) + implementation approved. See approve-one-nodb-scope-guard.md |
| 18 | [x] | Inbound integration webhook receivers | Integ | L | H | `b60b7d0`/`630d287`/`c364794` plus migration 160 — constant-time HMAC over a versioned method/path, connection, timestamp, delivery-ID, and exact-body-digest envelope; five-minute dual-clock freshness; atomic durable replay receipts; uniform-401 no-oracle; and mandatory per-client/global/in-flight pre-auth admission. Records one `integration.webhook-received` event per delivery (NO auto-trigger). Partner senders must adopt the v1 signing contract; provider-native adapters remain follow-up where a vendor cannot emit it. |
| 19 | [x] | Connection health monitoring (scheduled + history) | Integ | M | H | scheduled sweep shipped — durable-scheduler `connection_health_sweep` (leader-elected, #40 safe-internal-write recipe): lists ALL connections, runs the pure `test_connection_stub` (NO live resolve_credentials), appends a `connection_health_checks` row + refreshes `last_test_*` on the tick tx, deterministic stub credential verdict, aggregate-only detail, no dedup (time series). mig 120 seeds the schedule only (mig 102 already had the index). Approved in review round 2 (3 test-quality fixes folded in: restore-seeded-sweep, full seed-contract idempotency, exact-message branch coverage). On-demand probe + history read already existed |
| 20 | [ ] | Step-up / MFA re-auth for high-risk actions | Security | M | H | — |
| 21 | [ ] | Live secret-manager rotation + break-glass | Security | L | H | Provider-neutral rotation/lease response plus audited emergency recovery; see SB-1 and SB-5. The non-live VSO skeleton now separates four secret-family identities and declares a bounded restart only for the repository-proven API `envFrom` consumer; rendered controller behavior, effective policies, credential overlap/revocation, broader consumers, and emergency recovery remain external gates. |
| 22 | [x] | Domain-event alert generation | Observ | M | H | — |
| 23 | [x] | CP-side poison-job cap / dead-letter | Resil | M | H | shipped — `expire_leases` now caps non-mutating (OfflineDryRun/LivePlan) lease-expiry redispatches at `MAX_REDISPATCHES=5` via a `delivery_attempts` counter (mig 121); at the cap the job becomes terminal `DeadLettered` and emits ONE alert-worthy `job.dead_lettered` domain event (to_status='dead-lettered', `event_alerts` → Critical), all in one tx. Per-replica-safe (row-lock predicate recheck). LiveApply (→ReconcileRequired) unchanged. Plan + implementation both approved; tests incl. concurrency + mixed-count + migration idempotency. Follow-up SHIPPED — operator list + requeue: GET /api/admin/agents/dead-lettered-jobs (admin, secret-safe projection: no spec/live_context) + POST .../{job_id}/requeue (DeadLettered→Pending, delivery_attempts reset to 0 + lease cleared, audited). Requeue GUARDS the parent-request lifecycle (locks the request FOR UPDATE in requests→agent_jobs order; refuses if is_concluded()/orphan/unknown — fail-closed) so it can't re-dispatch stale work for a closed request. Plan (round 2) + implementation reviewed. Remaining follow-up: bulk requeue + portal view |
| 24 | [x] | Audit-trail export / streaming to SIEM | Observ | M | H | — |
| 25 | [x] | SLO / error-budget tracking | Observ | M | H | — |
| 26 | [x] | CP database backup/restore + DR runbook | Roadmap | M | H | ✓ |
| 27 | [~] | Bidirectional CMDB reconciliation + drift | Integ | L | H | `393caad`/`ee98640` — the "+ drift" half: pure detect_attribute_drift (owner/site/environment/criticality divergence for CIs matched in both sources) wired into the live cmdb_run_reconciliation endpoint (real platform inventory today). Follow-ups (external-gated): live CMDB fetch (import_cmdb_records is still demo data) + write-back to resolve drift |
| 28 | [ ] | Active Directory / Entra integration adapter | Integ | L | H | — |
| 29 | [ ] | DR failover orchestration (runbook-driven) | Resil | L | H | — |
| 30 | [x] | Circuit breaker for provider/adapter calls | Resil | M | H | — |
| 31 | [x] | Scheduled/recurring agent jobs (drift-scan) | Exec | L | H | `02ab45f`/`688561d`/`c86fb0b`/`06fbf03`/`6d8339a` — overdue-flag scan → classify_plan_json → CP drift event → cadence reset → scheduler dispatches read-only LivePlan rechecks (first agent_job-creating scan; mig 145-148). Reuses #43 machinery. Independently reviewed, live-DB verified |
| 32 | [x] | Per-notification mark-read + deep-link | Portal | S | M | — |
| 33 | [x] | CMDB import/export/reconcile actions in portal | Portal | M | M | ✓ |
| 34 | [x] | Time-series metric history + forecasting | AIOps | L | H | ✓ |
| 35 | [x] | Anomaly / waste detection engine | AIOps | M | H | — |
| 36 | [x] | AIOps suggestion-generation engine | AIOps | M | H | — |
| 37 | [x] | What-if capacity & cost planning | AIOps | M | H | — |
| 38 | [x] | Storage array registration / lifecycle | API | M | M | — |
| 39 | [x] | Maintain lifecycle stage (recurring review) | Roadmap | M | M | `9e1d425` — scheduled maintain_review_scan flags due Operational requests via request.maintain-review-due domain events (atomic FOR UPDATE SKIP LOCKED claim+advance, 90d, mig 119); reuses #40 pattern; plan + implementation approved. Follow-ups: alert-feed promotion + per-criticality interval |
| 40 | [x] | Scheduled/recurring synthetic health checks | Observ | S | M | `715f126` — durable scheduler runs synthetic_health_run (first safe-internal-write kind: job_is_schedulable allowlist); hourly seed (mig 116) + tx-aware result writes |
| 41 | [x] | Integration credential rotation / expiry | Integ | M | M | — |
| 42 | [x] | Multi-step orchestration / job dependencies | Exec | L | M | REACHABLE end to end. The immutable `job_steps` DAG is materialized at request creation and surfaced in request detail. Offline steps dispatch by dependency. In live mode, each step runs `LivePlan`, parks at `AwaitingApproval`, receives its own admin-approved, exact-spec/step/state-bound `LiveApply` grant, and unlocks dependents only after apply. A later failure triggers reverse-order, system-authorized `LiveDestroy`; a destroy failure halts for reconciliation. The portal renders statuses and two-click per-step approval. See `docs/orchestration.md`. |
| 43 | [x] | Post-apply verification (re-plan → Verified) | Exec | M | M | `349b152`/`e5c7b52`/`2f5ee2b` — engine classifier (post_apply.rs) → runner re-plan verdict in RunOutcome → CP derives verdict from digest-verified evidence, transitions Applied→Verified + emits scoped request.post-apply-drift (Critical). All changes independently reviewed |
| 44 | [x] | Agent liveness sweep + offline detection | Exec | M | M | ALREADY DONE — spawn_agent_offline_scan (main.rs, 60s/180s) + agent_offline_scan_once emits agent.offline/agent.online on state transitions, deduped via offline_alerted (mig 114), with notifications + to_status warning alert. (A durable-scheduler port was scoped but abandoned as redundant — plan review caught the existing emitter.) |
| 45 | [x] | Per-site / per-tenant usage metering | Observ | M | M | — |
| 46 | [x] | Chargeback / showback cost allocation | AIOps | M | M | — |
| 47 | [x] | Backup verification + restore-test recency | Resil | M | M | — |
| 48 | [ ] | Enforced access recertification w/ revocation | Security | L | M | — |
| 49 | [x] | Secret update & deregistration | API | S | M | — |
| 50 | [x] | Evidence pack file download / export | Portal | S | M | — |
| 51 | [x] | Per-vendor connection capability catalog | Integ | M | M | — |
| 52 | [x] | Route DR-overdue/failed tests into work queue | Resil | S | M | FULLY shipped — slice 1 (overdue/never-tested) + slice 2 (FAILED-latest). `restore_overdue_scan` reuses the #47 recency classifier (`is_at_risk()`=Overdue/NeverTested → `restore-test-overdue`) AND `latest_failed_systems` (DISTINCT ON, latest-is-Failed → `restore-test-failed`), each deduped via `enqueue_if_absent`(item_type) + a per-type partial unique index (mig 122/123); combined aggregate detail; blank keys skipped per-row in Rust. Plan (round 2) + implementation (round 2) approved for both slices. Follow-ups: DR-plan drill overdue, auto-priority |
| 53 | [x] | Cost/capacity budget thresholds + alerts | AIOps | M | M | — |
| 54 | [x] | Reserved-capacity / commitment cost modeling | AIOps | M | M | — |
| 55 | [x] | DNS record update endpoint | API | S | M | — |
| 56 | [x] | IPAM subnet CRUD | API | M | M | — |
| 57 | [x] | Load-balancer virtual-server delete/update | API | M | M | — |
| 58 | [x] | Connection usage audit trail | Integ | M | M | shipped — `integration_test` (the one CP-side credential-resolution site) now records ONE durable hash-chained `audit_log` row per access (`integration.connection.tested`, actor from the session, AUTHORITATIVE in DB mode → 500 on audit-write failure, local store in no-DB), recorded whether resolution succeeds or fails, BEFORE the best-effort telemetry writes. detail carries connection_id/vendor_type/`cred_source`/endpoint_status — NEVER the ref/secret/CredError text. Reuses audit.rs as-is (no migration). Plan + implementation both approved; 7 tests incl. redaction-survival (cred_source key avoids the `credential` redaction pattern). Follow-ups: live-execution credential-use audit (owner-domain), per-connection usage read view |
| 59 | [~] | Scope (site/env) selector + user preferences | Portal | M | M | ✓ |
| 60 | [~] | Evidence blob store for large artifacts | Exec | M | M | `178466c`/`26fef32` — WRITE side shipped: pure size-threshold core (evidence_store, 64 KiB) + content-addressed evidence_blobs table (mig 150) + ingest offload keyed by the verified digest (dedup, same-tx, small reference inline; also durably persists raw evidence that was previously discarded). Independent review found no issues; live-DB verified. READ endpoint is a design-gated follow-up (reopens the deferred evidence-redaction concern; resolver must validate a ref vs agent_jobs.evidence_digest, not trust JSON shape) |
| 61 | [x] | On-call / escalation contact registry | Observ | M | M | — |
| 62 | [~] | audit_log retention / partitioning / archival | Resil | M | M | ✓ |
| 63 | [x] | Observability deploy wiring | Roadmap | M | M | ✓ |
| 64 | [~] | OpenAPI / machine-readable API spec | Roadmap | M | M | `21241af`/`48ccf9a` — OpenAPI 3.1 spec served at public GET /api/agents/openapi.json covering the integration-relevant surface: 6 agent-protocol + 6 public + 4 ops-read endpoints (16 total), hand-maintained (no utoipa dep), with union drift-guard tests (documented paths == AGENT_ROUTE_PATHS ∪ PUBLIC_ROUTE_PATHS ∪ OPS_READ_ROUTE_PATHS). Follow-ups: full human/admin surface (needs utoipa/schemars annotation-driven sync — hand-maintaining hundreds of routes is impractical) + a Swagger-UI viewer |
| 65 | [ ] | Optional gated AI narrative adapter | AIOps | M | M | — |
| 66 | [x] | Release engineering (versioning/tags/changelog) | Roadmap | M | M | ✓ |

_Legend: E = effort (S/M/L), V = value (H/M), 📋 = in `missing-features.md`.
`[x]` shipped · `[~]` partial (core shipped; follow-up tracked) · `[ ]` not started._

## Goal-session review + hardening (2026-07-03/04)

A goal-directed session ran a five-agent adversarial review (api / engine /
live-exec / db / portal), fixed every confirmed finding, shipped missing-feature **#11**
(pre-dispatch IaC policy gate, above), browser-verified the portal, and did a
live-infra test (real terraform + a docker-provider apply/destroy). **24 commits**
(`bab5c13..6268f26`), each independently reviewed and pushed:

This is historical evidence for that revision and provider, not acceptance of a
current vSphere test. In particular, the Docker-provider exercise did not prove
vSphere placement, per-request backend isolation, the current agent protocol,
or successful-request cleanup. Current readiness is defined only by
[First Test Acceptance](../first-test.md); a code/spec mismatch blocks its gate.

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
  hygiene (3 review rounds).
- **Pass 4** (migrations SQL / remaining ~40 engine modules / runner IaC + tf-ansible
  arg construction / portal server-boundary): **1** confirmed — `73697c1` the same
  chrono `+Days` overflow class in `dns_ipam::build_reservation` (IPAM reserve TTL).

Marginal finding rate tapered 0 → 7 → 1 (the last a known-class repeat), so that
review-and-fix loop was considered **converged/exhausted for the reviewed
revision** (~16 distinct defects fixed, **31 commits**
`bab5c13..73697c1`). It is not a claim that later changes or a different
provider path need no review. Several features listed as future work at that
time were subsequently implemented; the table above, not this historical
paragraph, carries their current tracker state. Open design call:
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
the existing #31 backoff; `MissedTickBehavior::Skip` unified across all 5. Plan
(round 2) + implementation approved. See [background-loop-timeouts.md](background-loop-timeouts.md).
**Background-loop liveness** shipped — a per-loop last-success heartbeat registry in
background.rs (register_loop/record_loop_success/loop_liveness + a pure
classify_loop_liveness) wired into all 5 loops + a 4th `background_loops` probe in
platform_self_health; overdue past a timeout-AND-backoff-aware budget
(2*iteration_timeout(interval)+2*interval) ⇒ down (a page on the status endpoint,
not a k8s drain). Plan (3 rounds) + implementation approved. See
[background-loop-liveness.md](background-loop-liveness.md).
**DR-plan general update (PUT)** shipped — `PUT /api/protect/dr/plans/{id}` mirrors
the rpo-rto handler (pure `update_dr_plan_pure`, xmin CAS, site/status immutable via
deny_unknown_fields→422, scalar `name` synced in `transition`, central
/api/protect→execute gate + site-scope); plan (round 2) + implementation approved. See
[dr-plan-update-delete.md](dr-plan-update-delete.md). DELETE deferred (needs an
ON DELETE RESTRICT FK reconciled with dr_test_start's store-based resolution).
Integration-connection CRUD was a FALSE POSITIVE — already built in integration.rs
(create/list/get/update/delete/test at /api/integrations).
**repository-capacity GET-by-id + deny_unknown_fields** shipped (small narrow-scan
win) — `GET /api/protect/repository-capacity/{id}` (mirrors forecast's by-id read:
get→404, site_scope_guard_or_404 no-oracle, the update projection) + the update
body now rejects unknown fields (422); plan (round 2) + implementation approved; router tests
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
(`DeleteOutcome`). Plan review ran 3 rounds + implementation review ran 4 rounds. See
dr-plan-delete.md.

**Patch-wave DELETE** SHIPPED — `DELETE /api/maintain/patch/waves/{id}` completes
patch-wave CRUD. VERIFY-FIRST corrected the swarm's "patch-wave CRUD" candidate:
CREATE (`POST /api/maintain/patch/plan`) and UPDATE (the validate/approve/execute/
verify lifecycle transitions) ALREADY existed — only DELETE was missing. Boundary
(major review finding): only an UNAPPROVED draft (`Draft`|`Validated`) is deletable —
`Approved`/`Scheduled` (approver-reviewed; deleting them would cancel approve-tier
work from the execute tier) and `InProgress`/`Completed`/`Failed` (executed; carry
evidence) are blocked 409. The pure `patch_wave_status_deletable` classifier is the
SINGLE source of truth, used by BOTH the handler 409 AND a repo-level `BlockedStatus`
guard (minor review finding, defense-in-depth). Status-CAS delete (`WHERE id=$1 AND
status=$2`) closes the load→delete race; 0-row re-read disambiguates NotFound vs
StaleStatus. `patch_wave_servers` cascade away (mig 010 ON DELETE CASCADE — plan
membership, not execution evidence). execute-tier via the central gate (method-
agnostic) + per-wave site/env scope guard (out-of-scope → 404, no oracle).
Tombstone-rich audit. Plan (round 2) + implementation approved; minor implementation-review findings both closed
(audit before/after delta assertion; explicit DELETE route-gate test). See
patch-wave-delete.md.

**Certificate DELETE** SHIPPED — `DELETE /api/maintain/certificates/{id}` completes cert
CRUD (verify-first swarm 2026-06-29 #14). Clones the patch-wave-delete pattern, simpler:
certs are a LEAF table (no FK references them → no cascade) and SITE-only scoped. Boundary
(patch-wave lesson): only TERMINAL certs (Expired/Revoked) deletable; Active/Expiring are
LIVE → 409 (revoke first → Revoked → then deletable). Repo `delete` does a status+SITE CAS
(`WHERE id AND status=$2 AND site=$3` — review caveat: `transition` rewrites site, so the
site guard closes the concurrent-scope-change window) with a 0-row re-read (NotFound vs
StaleStatus) + a `certificate_status_deletable` single-source-of-truth classifier (handler
409 + repo BlockedStatus). execute-tier (method-agnostic /api/maintain gate) + site
scope_guard_or_404 (404, no oracle). Tombstone audit (no key/CSR — leaf table has none).
Plan + implementation approved. See certificate-delete.md.

**Certificate list pagination/filtering** SHIPPED — C278/C279 narrow `GET /api/maintain/
certificates/inventory` to a fixed `(created_at DESC,id DESC)` keyset: default 50, maximum
100, B+1 lookahead, no exact total, and explicit rejection of legacy filters, alternate
sorts, and non-zero offsets. Signed HMAC cursors bind the normalized authorization scope and
last tuple. Scoped reads cap authorization at 64 sites, take B+1 rows from each matching
site index, and merge only that finite candidate set. Expiry similarly defaults to 100,
caps at 200, and authenticates the site, days, fixed threshold, and `(valid_to,id)` cursor.
Migration 172 adds a 1-32-octet NOT VALID new-write site constraint and four matching partial
indexes/read predicates, so oversized legacy sites are preserved for explicit reconciliation
but quarantined from list traversal and cannot abort index rollout; plan and transactional
3,000-octet legacy probes assert the definitions. Dry-run modes use a process-ephemeral cursor
key, while persisted auth still requires configured key material. Expiry is explicitly
at-least-once under concurrent renewal of its mutable `valid_to` key. Environment-scoped
principals still fail closed to an empty page. See
certificate-list-pagination.md.

**Audit-chain verification resource bound** SHIPPED — C232 replaced synchronous
fetch-all/hash work in `POST /api/audit/log/verify` with a durable singleton job (migration
173). POST only enqueues/joins and returns 202; a dedicated bounded worker captures a stable
tail, verifies 64-row pages from genesis with a 64-KiB per-detail/16-MiB per-slice envelope,
persists the predecessor checkpoint atomically, prunes terminal job history in bounded batches,
and stops after four pages per slice. `GET /api/audit/log/verify/{job_id}` returns safe
progress/terminal state without requester identity or chain hashes. Detail transfer is
fail-closed above the per-row byte budget; concurrent replicas converge through the partial
unique active-job index and `FOR UPDATE SKIP LOCKED`.

**Metric status fan-out bounds** SHIPPED — C234/C235 apply site/environment
authorization before a 101-row overflow probe, reject more than 100 visible enabled
definitions before metric work, cap scope probes at 64 values per axis/256 nullable tuples,
and replace definition rereads with server-built `UNNEST` snapshots. Budget status reads
250+1 newest samples per distinct series (25,100 maximum rows); a lookahead returns explicit
partial/indeterminate coverage and cannot drive a healthy or recovery transition. SLO status
reads 2,000+1 rows for each distinct closed-window counter (400,200 maximum), excludes old
and future tails, and likewise treats truncation as non-definitive. Background breach scans
share the same caps and preserve prior state on partial data. Migration 183 provides exact
scope/order/timestamp/id indexes after a fail-closed preflight: named 1-200-octet constraints
are added, exact legacy violation counts are reported, and validation completes before any
index DDL. Violating rows must be explicitly normalized, deleted, or moved to an approved
quarantine; the migration never truncates identifiers. Exact-boundary, direct-writer,
transactional failed-rollout, and JSON-plan coverage pin the envelope.

**Canonical noisy-trigger site authority** SHIPPED — C282 migration 181 persists a
server-maintained site resolved only from active canonical registry entries using exact
case-insensitive host tokens delimited by `.`, `_`, or `-` (longest token, then lexical), so
short codes cannot match substrings such as `RA` in `branch`. Registry changes bump a durable
authority generation under the same advisory-lock domain as trigger inserts (including a
TRUNCATE-specific fence). The singleton identity cannot be updated, deleted, or truncated;
its guarded generation is unchanged for progress updates or advances by exactly one for a
queue transition. The production application role has read-only table access and can invoke
only the bounded owner-executed reconciler, while trigger-internal queue writers are unavailable
to `PUBLIC` and direct runtime calls. Raw reset/jump/removal regressions prove transaction rollback
preserves the prior generation. Every API query
requires the current generation, making stale classifications invisible immediately. A
resumable worker reconciles at most 128 rows per pass (SQL hard maximum 256). Unmatched rows
remain quarantined. Interactive status mutations and suppression expiry acquire the authority
lock before their mutating statement so a completed registry cutover is observed in a fresh
snapshot; scoped/unscoped generation-prefixed indexes keep reports and stale-row repair bounded
while reclassification progresses.

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
path still → admin) + the 3 paths added to MUTATING_ROUTES. The second review round
approved the plan + implementation; a follow-up sweep found no others in the same bug class. See
events-route-permission-fix.md.

**Agent queue-depth visibility** SHIPPED — `GET /api/admin/agents/queue-depth` (verify-first
swarm 2026-06-29 #6 READ slice; also the pending-jobs view deferred from #15). Operators had
no view of the pending agent-job backlog per platform (admin_list_agents shows LEASED jobs).
New admin-only aggregate read: per platform with pending work, the `pending_count`,
`oldest_pending_at`, and `top_priority` (`COUNT/MIN/MAX ... WHERE status='Pending' GROUP BY
platform`). Explicit in-handler `check_permission("admin")` (GET routes under /api/admin/ may
not be RBAC-gated). Exposes ONLY aggregates + platform name (no spec/live_context/request_id/
agent ids). The WRITE half of #6 — a MAX_PENDING cap + reject-on-create backpressure (touches
the job-creation critical path) — is DEFERRED. Plan + implementation approved. See agent-queue-depth.md.

**Job prioritization** SHIPPED — priority-weighted agent-job dispatch (verify-first swarm
2026-06-29 #15). Dispatch was strict FIFO by created_at, so a critical job queued behind a
backlog waited. mig 127 adds `priority INT NOT NULL DEFAULT 5 CHECK (0..=9)` + a partial
dispatch index `(platform, priority DESC, created_at, id) WHERE status='Pending'`; the
poll_job ORDER BY is now `priority DESC, created_at, id` (higher first, ties FIFO, id as a
deterministic tie-breaker — minor review finding). Every existing INSERT omits priority → inherits
the default (no insert changes). New admin endpoint POST /api/admin/agents/jobs/{job_id}/
priority (Extension<AuthSession>, admin-tier, audited) reprioritizes a PENDING job via a
status CAS (a leased/terminal job's queue priority is moot → 409; missing → 404; out-of-
range → 400). Deferred: a pending-jobs-by-platform view exposing priorities (the existing
admin list shows LEASED jobs). Plan + implementation approved. See job-prioritization.md.

**CMDB CI GET** SHIPPED — `GET /api/cmdb/cis/{ci_name}` (verify-first swarm 2026-06-29
#18). The `configuration_items` table (mig 014) was SEEDED but NO API/repo read it — every
`/api/cmdb/*` endpoint served an in-memory mock (the impact graph) or a hardcoded export.
This is the FIRST authenticated, DB-backed CMDB read. New `repos/configuration_items.rs`
(get_by_name by the UNIQUE ci_name — consistent with the impact endpoints' {ci_name}). A
major review finding: the central read gate is `audit OR request`, so the handler adds an EXPLICIT
`check_permission("audit")` → audit-only (CI criticality/owner are inventory signals). Site-
scoped via `site_scope_guard_or_404` (out-of-scope → 404, no oracle); 503 with no DB (the
table is the only CI source). A ci_name with a `/` won't route as one matchit segment
(documented; the body returns `id` for a future by-UUID variant). Plan changes were
folded in and the implementation approved. See cmdb-ci-get.md.

**Bulk alert acknowledge** SHIPPED — `POST /api/events/alerts/batch/ack` (verify-first
swarm 2026-06-29 #19). Only single-event ack existed (operators cleared alerts one-by-one).
Mirrors the #17 requests_batch_* pattern: extracted an `ack_alert_one` core (the per-event
scope-visibility check + ack upsert) shared by the single + batch handlers (behavior-
preserving refactor); the batch checks the `request` capability ONCE, caps at 100, dedups
(order-preserving), runs the SAME per-item scope/ack core (so a batch can NEVER ack an
out-of-scope alert — out-of-scope → per-item 404, no oracle), partial success, HTTP 200
always with {results, succeeded, failed}. Static `/batch/ack` coexists with `/{event_id}/ack`
(matchit static-wins, route-smoke confirms). Plan + implementation approved (minor findings: whole-batch
403 test w/ ack-specific body; dedup proven by the RESPONSE contract not the upsert row;
embedded-control-char note test). See bulk-alert-ack.md.

**Metric series aggregation** SHIPPED — `GET /api/metrics/series/aggregated` (verify-first
swarm 2026-06-29 #10). The raw /metrics/series returned only the most-recent 10k raw
samples; multi-month trend analysis forced client-side aggregation. New endpoint returns
time-bucketed (hourly/daily/weekly/monthly) MIN/MAX/MEAN/COUNT rollups. Review caught two
real defects: (impl MAJOR) the bounded-scan window (`observed_at >= now - span*limit`, added
for the plan MAJOR so it doesn't aggregate all history) is NOT bucket-aligned, so it can
straddle > limit labels — the LIMIT must run NEWEST-first (`ORDER BY bucket DESC LIMIT`
subquery, re-sorted ASC) or the newest buckets get dropped; (impl MINOR) the non-UTC test
must `SET LOCAL TIME ZONE` in a tx so it doesn't leak onto the pooled connection.
UTC-deterministic via the 3-arg `date_trunc(field, observed_at, 'UTC')` (proven under a
non-UTC session); allowlisted+bound granularity; coherent scope via enforce_scope_filters +
IS NOT DISTINCT FROM; request-tier (matches raw /series). SQL aggregation, no migration, no
engine change. Plan feedback was addressed; implementation feedback was resolved and approved in round 2. See
metric-series-aggregated.md.

**Legal-hold expiry scan** SHIPPED — `legal_hold_expiry_scan` durable-scheduler job
(verify-first swarm 2026-06-29 #17). Mirrors `secret_rotation_due_scan` but SIMPLER
(`legal_holds.expiry_date` is a real TIMESTAMPTZ — no parse/malformed signal). Daily
SAFE-INTERNAL-WRITE scan enumerates Active holds within 30 days of (or past) expiry — the
SAME predicate as GET /legal-hold/expiring — classifies via pure
`legal_hold::classify_legal_hold_expiry` and enqueues ONE deduped shift_queue item per
hold; NEVER mutates hold state (release/expire is a deliberate audited human action).
Major review finding (boundary/clock): classifier upper bound INCLUSIVE to match the SQL `<=`, PLUS
an `is_actionable` guard so a clock-skew row never yields an `active`-verdict item.
SECRET-HYGIENE: NEVER selects/surfaces the sensitive `reason`/`audit_trail`; the verdict is
keyed `expiry_state` (not `reason`, to avoid the column collision). Cross-tier: shift-queue
reads are execute-tier ⊆ legal-hold audit-tier readers (now pinned by a pure
`execute_holders_also_hold_audit` invariant test). mig 126 seeds the schedule + a partial
unique index. All plan feedback was folded in + implementation approved. See legal-hold-expiry-scan.md.

**Secret-rotation-due scan** SHIPPED — `secret_rotation_due_scan` durable-scheduler job
(verify-first swarm 2026-06-29 #7). `managed_secrets.next_rotation_due` existed but only
the on-demand `GET /secrets/due` surfaced overdue secrets. New daily SAFE-INTERNAL-WRITE
scan (mirrors `restore_overdue_scan`) enumerates secrets WHERE status NOT IN
('retired','rotating'), classifies via pure `secrets_rotation::
classify_secret_rotation_recency` (millis), and enqueues ONE deduped shift_queue item per
OVERDUE secret. TWO-signal (major review finding): a malformed `next_rotation_due` is SURFACED as a
separate `secret-rotation-invalid-due` item (not silently skipped — no blind spot), and a
bad row never aborts the tick. Secret-hygiene: NEVER selects/surfaces `vault_path`/
`secret_type`; scheduler `detail` is aggregate-only. mig 125 seeds the schedule + two
partial unique indexes. Plan feedback (3 major + 3 minor findings) was fully folded in +
implementation approved. See secret-rotation-due-scan.md.

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
mitigation). Plan + implementation approved. See approval-decisions-read.md.

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

**#15** (`1ff463d`, swarm: worktree agent + integration review): portal
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
