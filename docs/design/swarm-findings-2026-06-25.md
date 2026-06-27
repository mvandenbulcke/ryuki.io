# Swarm review findings — 2026-06-25

A 61-agent multi-lens swarm review (5 dimension finders, each adversarially verified) of the ryuki.io codebase, run after the tracked missing-features backlog's clean/additive items were shipped. **41 confirmed** (real + not-already-covered) of 55 raw findings.

Ranked: High severity, then CI-validatable, then smaller effort first. `CI` = provable with `cargo` tests (no live external IO).

| # | Sev | Eff | CI | Kind | Title |
|---|-----|-----|----|------|-------|
| 1 | H | S | ✓ | data-integrity | Missing CHECK constraint on requests.request_type enum |
| 2 | H | S | ✓ | data-integrity | Missing CHECK constraint on requests.status enum |
| 3 | H | M | ✓ | missing-feature | Missing RBAC feature (scoped execute permission) blocks cross-tenant isolation |
| 4 | H | M | ✓ | latent-bug | False-healthy platform health checks (all hardcoded to Healthy) |
| 5 | H | M | ✓ | data-integrity | Security operations lack audit trail logging |
| 6 | H | M | ✓ | data-integrity | Configuration mutations unaudited and unnotified |
| 7 | H | M | ✓ | data-integrity | Operational resource deletions and updates lack audit trails |
| 8 | H | M | ✓ | dead-code-or-drift | site_status and component_status tables seeded but never read/written |
| 9 | H | M | ✓ | missing-feature | requests_list pagination envelope missing — feature #14 slice 2 incomplete |
| 10 | H | L | ✓ | missing-feature | No enforced degradation mode; write gates are static/advisory-only |
| 11 | H | L | ✓ | missing-feature | No domain event stream or alert generation from operational events |
| 12 | H | L | — | missing-feature | No per-statement query timeouts on database operations |
| 13 | H | L | — | missing-feature | OpenAPI specification not implemented (#64 mismarked as shipped) |
| 14 | M | S | ✓ | security-gap | Missing deny_unknown_fields on critical auth endpoints |
| 15 | M | S | ✓ | missing-feature | Audit logging missing on sensitive scope-related mutations |
| 16 | M | S | ✓ | data-integrity | Missing CHECK constraint on requests.criticality |
| 17 | M | S | ✓ | data-integrity | Missing CHECK constraint on requests.stage |
| 18 | M | S | ✓ | latent-bug | Request timeout middleware insufficient observability |
| 19 | M | S | ✓ | missing-feature | Missing DELETE and UPDATE endpoints for metric budgets |
| 20 | M | S | ✓ | missing-feature | Missing DELETE and UPDATE endpoints for SLO definitions |
| 21 | M | S | ✓ | missing-feature | API token operations not emitted to notifications |
| 22 | M | S | ✓ | data-integrity | component_status.adapter_name CHECK constraint is missing recent adapter types |
| 23 | M | S | ✓ | dead-code-or-drift | Typo/divergence in degradation_mode contract JSON field name |
| 24 | M | M | ✓ | security-gap | Missing scoped access control in metrics recording (cross-tenant bypass risk) |
| 25 | M | M | ✓ | dead-code-or-drift | Unused/dead-code table: site_status & component_status |
| 26 | M | M | ✓ | latent-bug | Scheduler tick can exceed interval without backpressure; no per-tick timeout |
| 27 | M | M | ✓ | data-integrity | Audit log append-only trigger does not guard against RESTART IDENTITY |
| 28 | M | M | ✓ | missing-feature | No observability for configuration drift or change history |
| 29 | M | M | ✓ | dead-code-or-drift | monitoring_review_queue table completely unused by API |
| 30 | M | M | — | latent-bug | Scheduler advisory lock election has no heartbeat/lease; hung leader not detected |
| 31 | M | M | — | latent-bug | Lease expiry and idempotency sweeps fail silently without backoff |
| 32 | M | M | — | latent-bug | Agent heartbeat poll has no rate limit or queue depth feedback |
| 33 | M | L | — | missing-feature | Agent job polling query missing composite index for fairness |
| 34 | L | S | ✓ | security-gap | ID exposed in error messages without encryption/hashing |
| 35 | L | S | ✓ | missing-feature | Admin token issuance prevents machine-to-machine escalation, but token revocation audit is missing |
| 36 | L | S | ✓ | dead-code-or-drift | Unused/dead-code table: monitoring_review_queue (API-only contract) |
| 37 | L | S | ✓ | latent-bug | Health check readiness probe insufficient validation of SELECT 1 result |
| 38 | L | S | ✓ | missing-feature | Missing GET-by-id endpoint for browser sessions |
| 39 | L | S | ✓ | missing-feature | Missing GET-by-id endpoint for AD computers |
| 40 | L | M | ✓ | security-gap | Insufficient input validation on free-form text fields (name, description, reason, justification) |
| 41 | L | M | ✓ | dead-code-or-drift | failure_patterns table seeded but never read or written |

## Evidence

### 1. Missing CHECK constraint on requests.request_type enum
- **area:** requests table / data validation · **kind:** data-integrity · **severity:** high · **effort:** S · **ci_validatable:** True
- **evidence:** Migration 003_requests.sql defines `request_type TEXT NOT NULL` with no CHECK constraint. The engine's ryuki_engine::models::RequestType enum (models.rs) has exactly 14 valid variants (ServerDeployment, PatchMaintenance, ... BackupCoverageReport). The DB allows ANY text value. Handlers parse/validate in code (contracts.rs line 12459 parse_request_type()) but malformed data can bypass or corrupt handlers. No DB-level constraint means orphaned/invalid request_type values can persist.
- **verified:** The requests.request_type column has no CHECK constraint despite the engine defining a fixed set of 14 enum variants. The migration 003 defines it as TEXT NOT NULL with no constraint. Handlers validate on CREATE (parse_request_type returns 400 on invalid), but on READ, corrupted values silently become RequestPreflight instead of failing. The codebase demonstrates the pattern is known (servicenow_queue has CHECK, with corresponding test). This gap is not tracked in the missing-features tracker and creates a data-integrity vulnerability where orphaned/corrupted values bypass detection. It's CI-v

### 2. Missing CHECK constraint on requests.status enum
- **area:** requests table / data validation · **kind:** data-integrity · **severity:** high · **effort:** S · **ci_validatable:** True
- **evidence:** Migration 003_requests.sql defines `status TEXT NOT NULL DEFAULT 'intake'` with no CHECK constraint. Valid values are fixed in the engine (request_lifecycle.rs, contracts.rs handlers): intake, validating, planned, locked, executing, verified, approved, rejected, cancelled, protected, published, retired. No DB constraint allows invalid status values. Coupled with missing request_type constraint, malformed requests can corrupt the request lifecycle state machine.
- **verified:** The requests table lacks CHECK constraints on both the status and request_type TEXT columns, despite these having fixed valid values in the engine (RequestStatus and RequestType enums with 14 variants each). Investigation confirmed: (1) Migration 003_requests.sql defines status as TEXT NOT NULL DEFAULT 'intake' with no constraint; (2) Migration 047_request_state.sql adds columns but no constraints; (3) No subsequent migration adds CHECK constraints to requests.status or requests.request_type; (4) Other critical tables in the codebase (migrations 032, 058, 059, 060, 043, etc.) all have CHECK co

### 3. Missing RBAC feature (scoped execute permission) blocks cross-tenant isolation
- **area:** ryuki-engine/auth.rs (AuthSession) and ryuki-api/src/main.rs (check_permission) · **kind:** missing-feature · **severity:** high · **effort:** M · **ci_validatable:** True
- **evidence:** Feature #2 in missing-features-tracker.md: 'Administrable, site/env-scoped RBAC' is marked as not started [ ]. Currently AuthSession carries only coarse roles (admin, execute, approve, audit, request) with NO scopes. All handlers that accept site/environment filters (metrics, alerts, observations, inventory queries) cannot enforce per-user scope restrictions. This allows a Site-A operator to view/modify Site-B data. Scope enforcement requires:(1) storing site_scope/environment_scope in the AuthSession, (2) auditing the scope on every handler that accepts site/environment filters, (3) rejecting requests that fall outside the user's authorized scope.
- **verified:** This is a GENUINE, CONCRETE, UNTRACKED gap in the codebase:

**Evidence of the gap:**

1. **AuthSession lacks scope fields** (/Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-engine/src/auth.rs lines 58-64):
   - The struct carries only: user_id, display_name, roles, token_valid, provider_mode
   - NO site_scope or environment_scope fields

2. **API token scopes exist in DB but are not enforced** (/Users/mvandenbulcke/Repos/ryuki.io/migrations/045_api_tokens.sql lines 6-7):
   - Migration comment states: "site_scope/environment_scope are persisted and shown but NOT yet enforced (scoped enforc

- **STATUS (2026-06-26) — first rollout shipped:** `AuthSession` now carries
  `site_scope`/`environment_scope`, populated in `resolve_api_token`. Pure engine
  primitives `scope_permits` + `resolve_scope_filter` (trim/dedup/narrow/deny),
  plus API helpers `enforce_scope_filters` (site+env) and `enforce_site_scope`
  (site-only, deny env-scoped). ENFORCED read surface: metrics_series/insights/
  generate_suggestions/what_if/commitment, metrics_budget_status + _list,
  slo_status + _list, metering_usage, chargeback_report, requests_list, and the
  analytics/capacity family (capacity, capacity_cluster, capacity_forecast,
  cost_summary, waste, rightsizing, trend, vmware_cluster_capacity_admission).
  Dual-reviewed (GPT-5 Codex + fresh-context agent): both SHIP the code; no leak
  in any enforced handler.

- **STATUS (2026-06-26) — slice 2 (request-by-id reads) shipped (commit d4c00b9):**
  Post-load scope guard (`scope_guard_or_404` / `row_scope_permits` /
  `request_site_env`) on requests_get, requests_policy_eval, requests_execution_job,
  request_evidence_pack, requests_approval_quorum, requests_audit. Out-of-scope is
  byte-indistinguishable from not-found (404, or the empty trail for audit) — no
  existence oracle. Codex caught + we fixed a fail-open (scope-lookup DB error fell
  through to serving the audit trail; now fails closed).

- **STATUS (2026-06-26) — COMPLETE:** All 116 site/env-filtered handlers from the
  inventory are now scope-guarded across 32 commits (354803b…8892e74): the metrics/
  analytics/metering/requests read surface, request-by-id reads, every create, every
  mutation (CAS, bare-by-id-with-FOR-UPDATE/RETURNING, atomic AND-site predicate),
  the per-row-list reads, the by-id reads, the list-all reads (per-row filter), all
  remaining single-site reads, and the 4 hardware all-site-load BUGS. Each slice
  fmt/clippy/no-DB-suite/secret-scan green + GPT-5-Codex-reviewed (the uniform
  enforce_site_scope read pattern was reviewed once then applied verbatim). Finding
  #2 (tracker) marked [x].

- **ARCHITECTURE DECISION (2026-06-26):** A 10-agent inventory/design workflow
  mapped the FULL remaining surface = **116 unenforced site/env handlers** (82 HIGH,
  30 MED, 4 LOW; 31 request-by-id, 41 single-site, 26 per-row-list, 18 write), in
  13 same-pattern buckets. Chose the **hybrid helper-layer** (typed scope extractors
  for param reads + post-load guard for by-id + body-scope validation for writes +
  an anti-fail-open lint) over transparent middleware (which is fail-open by
  construction and structurally blind to the mid-handler-loaded row + inconsistent
  omit-defaults). REMAINING after slice 2: the destructive writes (secrets_rotate_all,
  firewall apply/revoke + rule create/update/delete, dns/ipam create/update/delete,
  storage/k8s provision, metrics/slo writes), the by-id mutations, the single-site /
  per-row-list reads (maintenance/readiness/firewall/dr/log-forwarders/secrets/
  hardware/compliance/dns/ipam/storage/k8s/aiops/baseline/zabbix/outage/...), and the
  4 hardware hard-coded-''-load bugs. Severity-ordered, reviewable commits.

### 4. False-healthy platform health checks (all hardcoded to Healthy)
- **area:** ryuki-engine/src/health_monitor.rs (lines 102-181) · **kind:** latent-bug · **severity:** high · **effort:** M · **ci_validatable:** True
- **evidence:** All check_*_health() functions return hardcoded HealthStatus::Healthy with source=Simulated, never dependency-backed. check_api_health(), check_portal_health(), check_validator_health(), check_kubernetes_health(), check_vault_health(), check_database_health() all hardcoded to 'Healthy'. This means /api/platform/health/all (handler: platform_health_all_checks at contracts.rs:21622) returns false-OK even when real dependencies are down. Monitoring systems treating this as a truth signal (instead of advisory-only) will miss real outages. The 'Simulated' source should trigger alerting, but many operators check status==Healthy first.
- **verified:** The health check system in ryuki-engine/src/health_monitor.rs unconditionally returns HealthStatus::Healthy + HealthSource::Simulated for all seven component checks (API, portal, validator, Kubernetes, vault, database, adapters). Every function from check_api_health() through check_database_health() hardcodes these values with "DRY-RUN" message markers. The DependencyBacked enum variant exists (line 27) but is never produced by any check function. Tests explicitly assert the always-healthy stub behavior (test_all_checks_healthy_in_dry_run, lines 270-283). The missing-features-tracker.md marks 
- **STATUS (2026-06-26) — COMPLETE:** The dangerous false-healthy signal was the
  Prometheus `ryuki_platform_health{component="platform-db"}` gauge, hardcoded to
  `1` even during a total DB outage — an alert wired to it could never fire.
  Fixed: new pure engine helpers `database_health_from_probe(probe_ok)` (the
  first real `DependencyBacked` check; `Unhealthy` when the probe fails),
  `override_check()` (folds a real probe into the board + recomputes aggregates),
  and `metrics_text_from_health()` (emits a per-series `source` label so a
  scraper can scope alerts to `source="dependency-backed"`). API-side
  `database::live_platform_health()` runs a real `SELECT 1` when a pool exists
  and folds the verdict into `/metrics`, `/api/platform/health`,
  `/health/components`, and `/api/platform/health/metrics`. No-pool (dry-run)
  deployments stay simulated so they are not misreported as an outage; the
  authoritative readiness endpoint `/api/platform/health/dependencies` already
  reports no-pool as `down`. `/health/all` keeps its advisory marker. The five
  components we cannot probe (api/portal/validator/k8s/vault) remain honestly
  `source="simulated"`. Dual-reviewed (GPT-5 Codex + fresh-context agent), engine
  + api tests green.

### 5. Security operations lack audit trail logging
- **area:** ryuki-api/src/contracts.rs (lines 11752-11787, 11845-11878, 25691-25746) · **kind:** data-integrity · **severity:** high · **effort:** M · **ci_validatable:** True
- **evidence:** API token revocation (admin_tokens_revoke, line 11752), session revocation (admin_sessions_revoke, line 11845), and secret rotation (secrets_rotate, line 25691) all write ONLY to tracing logs, never to audit_log table. Compare with request lifecycle operations (line 12082) which call audit::record_audit_tx(). These are privileged admin/security operations; audit_log is the durable evidence table for compliance. Missing: (1) audit_log INSERTs for token/session/secret mutations, (2) matching notification drafts for these high-risk events.
- **verified:** This is a genuine, verifiable gap. Three security-sensitive admin operations (token revocation, session revocation, secret rotation) write ONLY to ephemeral tracing logs, never to the durable, append-only audit_log table. The audit_log infrastructure exists and is proven to work for request lifecycle transitions, but is not applied to these privileged operations. The design document (/docs/design/missing-features.md) explicitly mandates that "token create/revoke and session revoke write audit log entries" as part of the Authentication & Authorization completion feature. This is not tracked in 
- **STATUS (2026-06-26) — audit trail COMPLETE (notifications deferred):** All
  five privileged security mutations now write a DURABLE, hash-chained
  `audit_log` row ATOMICALLY with the mutation (wrapped in a tx; a 404/conflict
  rolls back and records nothing): `admin_tokens_create` (design-doc mandated),
  `admin_tokens_revoke`, `admin_sessions_revoke` (DELETE…RETURNING names the
  subject), `secrets_rotate`, `secrets_rotate_all` (one summary row). New
  `audit::security_audit()` constructor builds a non-lifecycle AuditRecord
  (request_id=None, to_stage="security"); `detail` carries references ONLY —
  never token plaintext/hash or secret values. DB-gated tests prove each path
  writes a correctly-attributed, non-leaking row (token create+revoke, session
  revoke, secret rotate), all green against the live DB. The finding's secondary
  ask — notification drafts for these events — is DEFERRED (audit is the
  compliance-critical durable evidence; notifications are a follow-up).

### 6. Configuration mutations unaudited and unnotified
- **area:** ryuki-api/src/contracts.rs (lines 11432-11479) · **kind:** data-integrity · **severity:** high · **effort:** M · **ci_validatable:** True
- **evidence:** admin_platform_settings_update (line 11432) and admin_platform_settings_reset (line 11465) persist to platform_config table via upsert_platform_config_entries (line 11387) and save_platform_config_file but emit NO audit record and NO notifications to approvers/admins. These are high-risk admin actions affecting auth_mode, branding, feature flags, etc. No tracing.info() equivalent. Compare to request.plan (line 12082) which emits audit + notifications.
- **verified:** Verified in code: admin_platform_settings_update (line 11432) and admin_platform_settings_reset (line 11465) in /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/contracts.rs persist to platform_config table but make zero calls to audit::record_audit_tx() or tracing::info(). Contrast: requests_plan() at line 13665 calls apply_transition_audited() which persists audit records; admin_tokens_create/revoke/sessions_revoke all have tracing::info() calls (lines 11665, 11782, 11870). The mutations affect sensitive fields like auth_mode, secret_provider, etc. No entry in missing-features-track
- **STATUS (2026-06-26) — audit COMPLETE (notifications deferred):**
  `admin_platform_settings_update` and `_reset` now write a DURABLE hash-chained
  `audit_log` row ATOMICALLY with the upsert: `upsert_platform_config_entries`
  was refactored to take `&mut Transaction`, and each handler opens a tx →
  upserts → `audit::record_audit_tx` (reusing the swarm-#5 `security_audit()`
  pattern; action `platform-settings-update`/`-reset`) → commit, then saves the
  config file outside the tx. detail records the new `PlatformConfig` values —
  verified to hold NO secret fields (identifiers/provider-names/retention/timeouts
  only; the OIDC client secret lives in env/managed_secrets), and these exact
  key/value pairs already persist to `platform_config.value`, so auditing adds no
  new exposure. DB-gated test (`test_platform_settings_update_writes_audit_log`,
  using a temp config store so the real gitignored `platform-config.json` is never
  touched) green against the live DB. Notifications to approvers/admins DEFERRED
  (same follow-up bucket as swarm #5).

### 7. Operational resource deletions and updates lack audit trails
- **area:** ryuki-api/src/contracts.rs (lines 15908-15923, 19321-19342, 23083-23107, 23381-23416, 23831-23841, 24426+) · **kind:** data-integrity · **severity:** high · **effort:** M · **ci_validatable:** True
- **evidence:** on_call_contact_delete (line 15908), alert_routes_delete (line 19321), alert_routes_create (line 19158), dns_record_delete (line 23083), dns_record_create (line 23027), ipam_subnet_delete (line 23381), firewall_rule_delete (line 23831), firewall_rule_create (line 23742), storage_array_delete, lb_vs_delete, etc. all execute DELETE/INSERT/UPDATE without any audit_log INSERT or tracing.info() call. ~92 DELETE operations found, none with audit. Even audit.rs comment (line 7) notes 'append-only audit trail' requirement — yet only request-lifecycle mutations are recorded.
- **verified:** This is a genuine, concrete gap: ~92 DELETE operations and numerous INSERT/UPDATE operations on operational resources (on-call contacts, alert routes, DNS records, firewall rules, IPAM subnets, etc.) in /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/contracts.rs execute without ANY audit trail or tracing. The audit.rs module (37KB) is explicitly scoped to request lifecycle transitions only (line 1: "Append-only audit trail recorder for request lifecycle transitions"). While the infrastructure exists (audit_log table, record_audit_tx functions), resource mutations simply do not call 
- **STATUS (2026-06-27) — COMPLETE (20 slices, ~126 handlers):** A verification
  scan revealed the surface was ~128 handlers (not the ~92 first estimated). The
  sweep shipped in 20 reviewed slices (commits `3c6a481`→`<this>`): firewall
  rules+rule-sets, DNS, IPAM, metrics SLO/budget, on-call, alert-routes, secrets
  (register/update/deregister/rotate), maintenance, noise, certificates,
  decommission, backup-restore, runbook, DR, outage, incident, network-release,
  load-balancer, gMSA/AD/shares, patch, compliance, storage/hardware/k8s,
  repo-capacity, legal-hold, snapshot, chargeback, site-registry, log-forwarders,
  emergency-change, shift-queue, linux/sql/software deployments, ServiceNow,
  OOB, secrets-rotation-fail, access-campaign. EVERY mutation now writes a
  durable hash-chained `audit_log` row ATOMICALLY with the mutation (same tx;
  404/409/guard returns roll back without an audit row), via the
  `audit::security_audit()` + `record_audit_tx` pattern. Repo-backed mutations
  were refactored to share the caller's tx (`impl PgExecutor` for single-query
  fns; `&mut PgConnection` for multi-query fns), with commit-every-caller
  verified by running each domain's DB module. Handlers lacking an actor gained
  `AuthExtractor`. detail carries references only — never secret/credential/key
  material (gMSA passwords, vault paths, cert keys, connection strings all
  excluded; legal-hold preserves its JSONB audit_trail column alongside the new
  row). EXCLUDED by design: high-volume telemetry inserts (metrics_record_sample,
  synthetic_run_all) — per-row auditing would flood the audit_log. Bonus: two
  pre-existing #2-RBAC site-scope gaps (storage_array_update, hardware_add) were
  fixed mid-sweep. Each slice was adversarially reviewed (fresh-context). Open
  follow-ups (flagged as tasks, non-blocking): k8s-namespace site-scope guard,
  firewall priority race, secrets_update TOCTOU, a few Extension→AuthExtractor
  consistency + 503→500 polish items.

### 8. site_status and component_status tables seeded but never read/written
- **area:** migrations/025_degradation_mode.sql + sources/ryuki-engine/src/degradation_mode.rs · **kind:** dead-code-or-drift · **severity:** high · **effort:** M · **ci_validatable:** True
- **evidence:** Migration 025 creates site_status and component_status tables with INSERT statements seeding DEFRA/GBLON/NLAMS sites. But degradation_mode.rs functions (get_site_statuses, enter_degradation_mode, exit_degradation_mode) all use seed_sites() to generate in-memory data — never query/update the database. API handlers in contracts.rs call these pure engine functions, never SELECT/UPDATE site_status. This causes state loss on restart.
- **verified:** The site_status and component_status tables are created and seeded in migration 025, but the degradation_mode.rs engine functions exclusively use in-memory seed_sites() to generate state rather than querying/updating the database. API handlers call these pure functions directly, never persisting changes. This causes guaranteed state loss on server restart. The missing-features tracker does not call out this gap — item #16 focuses on write-blocking behavior, not persistence. No repository layer touches these tables (grep returned 0 results). This is a concrete, CI-validatable drift: a test asse
- **STATUS (2026-06-27) — COMPLETE:** degradation status is now DB-backed
  (state survives restart). New `repos/degradation.rs` reads site_status +
  folds component_status rows into the engine's 13-field AdapterComponentStatus,
  and `enter`/`exit` UPDATE both tables. Engine gained pure
  `global_status_from(sites)` (get_global_status refactored to use it) +
  ComponentStatus/SiteDegradationState `from_str` (exact inverse of Display).
  Handlers: degradation_check/global/degraded read from the DB and fall back to
  the in-memory engine only when no pool is configured (a DB read ERROR now logs
  a tracing::warn instead of silently masking the outage); degradation_enter/
  exit gained AuthExtractor + write a durable audit_log row ATOMICALLY with the
  two UPDATEs (404 + rollback when the site is absent). rules/contract stay pure.
  DB-gated tests: seeded-state read + component mapping, and enter persists +
  audits (then restores DEFRA). Reviewed (fresh-context): component mapping,
  enum inverse, atomicity, and 404-rollback all confirmed clean.

### 9. requests_list pagination envelope missing — feature #14 slice 2 incomplete
- **area:** sources/ryuki-api/src/contracts.rs (requests_list function) · **kind:** missing-feature · **severity:** high · **effort:** M · **ci_validatable:** True
- **evidence:** Missing-features tracker marks feature #14 as [~] partial: slice 1 shipped with filters (status/site/environment/request_type/created_by/q) + sort + direction. But slice 2 envelope {items, total} is unimplemented. Current requests_list returns bare array Json(json!(summaries)) instead of {items: summaries, total: count}. Portal faceting feature #15 depends on this envelope.
- **verified:** Gap is REAL and UNIMPLEMENTED: requests_list() at lines 12697/12742 returns bare array Json(json!(summaries)) with no total count. Tracker marks #14 slice 2 as unshipped — the envelope {items, total} is documented but not coded. Portal's get_request_list() (line 2202) expects Vec<ApiRequestSummary>, will break when envelope is added. Function computes limit/offset but never queries COUNT(*) for the total. Tests assume array (line 28844 .as_array()). Marker in tracker: [~] partial = core shipped (slice 1, filters/sort), follow-up slice 2 tracked.
- **STATUS (2026-06-27) — total exposed via header (backward-compatible):** The
  core gap (no COUNT(*), no way to know the total for pagination) is closed:
  requests_list now runs `SELECT COUNT(*)` with the SAME filters (the WHERE was
  extracted to a shared `const REQUESTS_LIST_WHERE` so the page SELECT and the
  COUNT can never drift) and returns the filtered total in an `X-Total-Count`
  response header (no-DB path uses matched.len()). The body stays a bare array,
  so the Leptos portal consumer (portal/portal-ui) keeps working with NO
  cross-crate break — the verified concern that "Portal expects Vec, will break
  when envelope is added." DB-gated before/after-delta test + a no-DB
  exact-count test. The literal `{items,total}` ENVELOPE shape is intentionally
  DEFERRED to a coordinated portal change (the portal must switch from parsing a
  bare array to the envelope first); the header delivers the pagination total now
  without that risk. Reviewed (fresh-context): COUNT bound to $1..$6, body shape
  unchanged, injection-safe.

### 10. No enforced degradation mode; write gates are static/advisory-only
- **area:** ryuki-api/src (degradation mode referenced in contracts but no runtime enforcement) · **kind:** missing-feature · **severity:** high · **effort:** L · **ci_validatable:** True
- **evidence:** Tracker item #16 'Enforced site degradation mode (write gating)' is []. Contracts show degradation_mode references in JSON schemas (contracts.rs) but no actual handler that checks site_status.state and returns 503 or enforces read-only writes. If GBLON is marked 'degraded', the API will still accept mutations. site_status table is seeded but never read. Suggest: implement a middleware or per-handler check that reads site_status.state and if != 'healthy', return 503 Service Unavailable or enforce read-only (401 on POST/PUT/DELETE).
- **verified:** This is a genuine, concrete gap: a site_status table is created by migration 025, seeded with test data (GBLON marked degraded), and exists in the database. However, the API layer never reads from it. All mutation handlers (requests_create, requests_execute, requests_approve, etc.) skip degradation checks entirely. The pure degradation_mode engine functions only return hard-coded in-memory test data, never querying the persistent table. Read-only endpoints exist (/api/platform/degradation/*) but mutation paths ignore them. The gap is implementable: add a database query in a middleware or per-h
- **STATUS (2026-06-27) — COMPLETE:** the degradation rule is now ENFORCED at
  the live-write chokepoint. New `enforce_site_operational(pool, site)` reads the
  DB-backed `site_status` (swarm #8) and returns `503 Service Unavailable` when
  the target site is `Degraded` or `Unreachable`; `Healthy`/`Recovering`/no-row
  pass. Both grant-minting paths are gated BEFORE the CP-signed LiveApply grant
  is created: `requests_approve_live_apply` (plan query now selects `r.site`,
  gate after the 404/409/is_concluded checks) AND the admin endpoint
  `admin_approve_live_apply_job` (resolves site from `request_id`). A DB
  read error on the status itself is fail-open + logged (a status-store blip
  cannot block ALL live execution — matches the #8 read posture); the site
  resolution itself maps to `db_err`. DB-gated test asserts seeded
  GBLON/NLAMS → 503, DEFRA/unknown → allowed. Scope: this gates LIVE WRITE
  EXECUTION (the highest-leverage point); request creation and the non-live
  per-domain `*_execute` paths are intentionally out of scope (advisory-read
  endpoints remain for visibility). Fresh-context review caught the admin-path
  bypass before merge.

### 11. No domain event stream or alert generation from operational events
- **area:** ryuki-engine/src/ (lib.rs, alert_routing_engine.rs), migrations/ · **kind:** missing-feature · **severity:** high · **effort:** L · **ci_validatable:** True
- **evidence:** Feature #22 (missing-features-tracker.md, line 54) 'Domain-event alert generation' is marked [ ] (not started). No domain_event, domain_event_stream, or alert_generated table exists (grep of migrations/ confirms). Alert routing exists (alert_routing_engine.rs) but is for INBOUND alert routing only, not OUTBOUND event→alert generation. Notifications module (notifications.rs) only handles request.{plan,approve,reject,verify,cancel} — no domain events. Missing: (1) domain event table/stream, (2) trigger to emit events from major mutations (approve, revoke, decommission, capacity-breach, SLO-breach, etc.), (3) alert generation from events, (4) recipient lookup.
- **verified:** REAL GAP CONFIRMED. The missing-features tracker marks Feature #22 'Domain-event alert generation' as [ ] (not started). Verification shows: (1) No domain_event/domain_event_stream table exists (grep across all 108 migrations confirms); (2) alert_routing_engine.rs handles INBOUND alert routing only, not OUTBOUND event→alert generation; (3) notifications.rs emits only request-lifecycle transitions (plan/approve/reject/verify/cancel), not operational domain events (capacity_breach, SLO_breach, agent_offline, decommission, approval_denial, etc.); (4) route_decisions table is seeded in mig 008 but

### 12. No per-statement query timeouts on database operations
- **area:** ryuki-api/src/database.rs (try_connect_with_url, lines 104-129) · **kind:** missing-feature · **severity:** high · **effort:** L · **ci_validatable:** False
- **evidence:** Pool configured with acquire_timeout, idle_timeout, max_lifetime, but no statement_timeout or query timeout context. A slow query (e.g., missing index, full table scan, bad plan) will hang until the request-level timeout (configured via timeout_secs in main.rs, 60-300s typical) fires. This can saturate the pool waiting on that one slow query. Database should have statement_timeout set via SET statement_timeout or pool.execute('SET statement_timeout ...') at connection init. Suggest: add pool initialization step to set per-statement timeouts (e.g., 15s default, configurable per pool tier).
- **verified:** The gap is REAL and CONCRETE: ryuki-api/src/database.rs (lines 104-129) configures the sqlx PgPool with acquire_timeout, idle_timeout, and max_lifetime, but does NOT set any per-statement or query timeout. A slow database query (missing index, full table scan, bad plan) will block a connection indefinitely until the request-level timeout fires (60-300s typical), allowing pool saturation. SQLx 0.8 supports statement_timeout via connection initialization, but this is not implemented. This gap is NOT tracked in the 66-item missing-features-tracker.md. It is implementable via pool.after_connect() 
- **STATUS (2026-06-27) — COMPLETE:** `try_connect_with_url` now sets, via
  `PgPoolOptions::after_connect` (once per physical connection, all pools),
  `statement_timeout = '30s'` (bounds a runaway query below the 60-300s request
  timeout so it aborts first instead of pinning a connection) AND
  `lock_timeout = '10s'` (bounds a contended-lock wait — advisory-chain / row
  locks are held only briefly, so a longer wait is real pile-up and should fail
  fast + retry). 30s is generous for this control plane's small-table OLTP and
  its fast DDL migrations (all 109 verified to run single statements well under
  it), yet safely below the request timeout. DB-gated test asserts both values
  via SHOW; migrations + the audit-chain advisory-lock path verified unaffected.
  Reviewed (fresh-context): the lock_timeout was added specifically to address
  the reviewer's note that statement_timeout alone is a blunt instrument for lock
  waits.

### 13. OpenAPI specification not implemented (#64 mismarked as shipped)
- **area:** sources/ryuki-api/Cargo.toml, sources/ryuki-api/src/main.rs · **kind:** missing-feature · **severity:** high · **effort:** L · **ci_validatable:** False
- **evidence:** Tracker #64 'OpenAPI / machine-readable API spec' is marked [ ] (not shipped) but missing-features.md describes detailed implementation plan using utoipa + utoipa-swagger-ui. Zero grep hits for 'openapi', 'utoipa', or 'swagger' in sources/ or Cargo.toml. No GET /openapi.json endpoint. ~616 routes exist with no machine-readable contract. missing-features.md section 7 explicitly states implementation plan: annotate operational routes, programmatically register contract GETs, mount /docs (Swagger UI), generate endpoint documentation — none of which exist.
- **verified:** OpenAPI specification (#64) is marked [ ] (not shipped) in the missing-features-tracker.md. Verification confirms: (1) Cargo.toml has zero utoipa/swagger dependencies; (2) main.rs router construction has zero /openapi.json or /docs routes mounted; (3) ~727 actual routes (tracker claims ~616) exist with no machine-readable contract; (4) endpoints.md is hand-generated from validator scripts, not OpenAPI-derived; (5) missing-features.md section 7 details a specific 11-step implementation plan using utoipa + utoipa-swagger-ui to annotate 40 operational routes, programmatically register 580 contrac

### 14. Missing deny_unknown_fields on critical auth endpoints
- **area:** ryuki-api/src/contracts.rs (LocalLoginRequest, CreateTokenRequest, and ~95+ other request structs) · **kind:** security-gap · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** LocalLoginRequest (line ~10160) and CreateTokenRequest (line ~11545) lack #[serde(deny_unknown_fields)]. Only 17 of ~115 request/body structs have this attribute. Attackers can send typo'd fields that are silently dropped, potentially causing 'works as intended' failures to mask security logic. Example: sending 'passwrod' instead of 'password' on local login would be silently ignored, a sign of weak input validation. The attribute prevents this silent field-dropping by raising 422 Unprocessable Entity on unknown fields.
- **verified:** The claim is verified as technically accurate: LocalLoginRequest (line 9993) and CreateTokenRequest (line 11496) in sources/ryuki-api/src/contracts.rs lack #[serde(deny_unknown_fields)]. I confirmed 218 total Deserialize-derived request structs with only 17 having the attribute, matching the claim's ratio. However, the actual security risk is limited: (1) LocalLoginRequest has only required fields, so missing fields cause full rejection, not silent default-use. (2) CreateTokenRequest has optional fields with defaults; a typo like 'roles_typo' causes roles to default to empty vec, producing a z

### 15. Audit logging missing on sensitive scope-related mutations
- **area:** ryuki-api/src/contracts.rs (user_preferences_put, line 15228) · **kind:** missing-feature · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** user_preferences_put stores user's site and environment scope preferences but does NOT audit the mutation. If a user's preferences are changed (either by the user themselves or by admin), there is no audit trail. The handler should call audit::record_audit_local or similar after the INSERT...ON CONFLICT.
- **verified:** Verified real gap: The PUT /api/me/preferences endpoint (user_preferences_put, /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/contracts.rs:15232-15266) modifies user scope preferences (preferred_site, preferred_environment) without recording an audit trail. The handler receives an authenticated AuthSession with user_id, display_name, and roles, but after executing the INSERT...ON CONFLICT...UPDATE query (lines 15245-15259), it returns the response without calling audit::record_audit_local. This is a genuine security-authz gap: scope preferences determine which infrastructure sites/e
- **STATUS (2026-06-27) — COMPLETE:** `user_preferences_put` now wraps the
  upsert in a transaction and writes a durable hash-chained `audit_log` row
  (`audit::security_audit("user.preferences.update", …)` +
  `record_audit_tx`, committed atomically) — the same pattern as the swarm #7
  resource-mutation sweep. The detail carries only the new scope identifiers
  (subject_user_id, preferred_site, preferred_environment) — never credentials.
  DB-gated test `user_preferences_put_writes_audit_row` asserts exactly one
  row is appended for the acting principal (before/after delta; audit_log is
  append-only).

### 16. Missing CHECK constraint on requests.criticality
- **area:** requests table / data validation · **kind:** data-integrity · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** Migration 047_request_state.sql adds `criticality TEXT NOT NULL DEFAULT 'standard'` (line 35). Handlers use fixed values ('standard', implicitly 'high'/'emergency' for escalation). No CHECK constraint. Invalid criticality can be inserted, affecting SoD/escalation routing that keys on criticality.
- **verified:** Migration 047 adds requests.criticality as TEXT NOT NULL DEFAULT 'standard' without a CHECK constraint. Handlers hardcode 'standard' (no user input), but plan_patch_wave() accepts any criticality string without validation. Direct SQL or programmatic mutation could insert invalid values. Pattern of CHECK constraints exists in migration 107 (approval_decision_decisions) and migration 014 (configuration_items). Not tracked in missing-features-tracker.md. This is a genuine data-integrity gap matching the claimed calibre.

### 17. Missing CHECK constraint on requests.stage
- **area:** requests table / data validation · **kind:** data-integrity · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** Migration 003_requests.sql defines `stage TEXT NOT NULL DEFAULT 'intake'` with no CHECK constraint. Valid stage values are managed by engine's Stage struct (models.rs) but not enforced durably. Allows orphaned/invalid stage names in the DB, breaking the request lifecycle state machine expectations.
- **verified:** The requests.stage column (migration 003) has no CHECK constraint despite being part of the API response and having a well-defined set of valid values ('intake', 'validate', 'plan', 'approve', 'execute', 'verify', 'protect', 'publish', 'retire', 'rework', 'fail', 'cancel', 'logout'). The valid values are enforced only in application code (contracts.rs lines 13117, 14032, 14689, etc.) but not durably in the database. This is a genuine data-integrity gap: code bugs or direct SQL could persist invalid stage names, corrupting the denormalized cache. The gap is not mentioned in the tracked features

### 18. Request timeout middleware insufficient observability
- **area:** ryuki-api/src/main.rs (lines 1745-1763) · **kind:** latent-bug · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** Timeout middleware logs only 'request timeout' at WARN level with path + timeout_secs. Actual timeout duration (elapsed) is not logged; no request_id, no handler info, no indication which downstream call timed out (DB, external call, slow business logic). If timeouts cluster on a specific endpoint or pattern, operators have no drill-down path. Suggest: log request_id, handler (resolved from router), actual elapsed_ms, and a categorized hint (db_slow, external_slow, etc.) based on middleware context.
- **verified:** Request timeout middleware at sources/ryuki-api/src/main.rs lines 1745–1767 logs only path and configured timeout_secs in warn-level traces when a timeout occurs. Actual gaps: (1) request_id available via req.extensions() but never extracted despite being set by request_id_middleware (line 1738) before this layer; (2) _elapsed parameter explicitly ignored—no actual elapsed time measured or logged; (3) timeout responses bypass timing_middleware entirely (middleware order, line 1772 never executes for timeouts); (4) no categorization or handler context. Commit c1e228ef added this middleware 2026
- **STATUS (2026-06-27) — COMPLETE:** the timeout middleware's warn log now
  carries `request_id` (read from the `RequestId` extension set by the outer
  `request_id_middleware` — confirmed populated at this layer: the same
  extension is read by `timing_middleware`, which only works if request_id runs
  first), `method`, and the actual `elapsed_ms` (measured with `Instant`, since
  the timeout path bypasses `timing_middleware`), alongside the existing `path`
  + `timeout_secs`. Operators can now correlate a timed-out request with its
  other traces. Logging-only; the 504 response is unchanged. (Per-downstream
  categorization — db_slow vs external_slow — would need middleware-internal
  timing context and is left as a larger follow-up.)

### 19. Missing DELETE and UPDATE endpoints for metric budgets
- **area:** sources/ryuki-api/src/contracts.rs · **kind:** missing-feature · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** Lines 193-196 define routes POST /api/metrics/budgets (create) and GET /api/metrics/budgets{,/status}. No PUT, PATCH, or DELETE endpoints exist. Handlers: metrics_budget_create (line 16764) creates, metrics_budget_list (16834) reads all, metrics_budget_status (16877) evaluates. No async fn for update or delete. Migration creates metric_budgets table but API cannot remove or modify budgets after creation—incomplete CRUD.
- **verified:** This is a genuine, concrete gap verified against actual code. The metric_budgets table (migrations/097_metric_budgets.sql) is fully-featured with id, enabled toggle, and updated_at fields supporting CRUD operations. However, the API (sources/ryuki-api/src/contracts.rs lines 192-196) exposes only POST and GET endpoints for /api/metrics/budgets with zero support for PUT, PATCH, or DELETE. No handler functions for update/delete exist anywhere in contracts.rs. The table design intentionally supports soft-delete (enabled flag) and modification (updated_at), but clients have no API path to exercise 

### 20. Missing DELETE and UPDATE endpoints for SLO definitions
- **area:** sources/ryuki-api/src/contracts.rs · **kind:** missing-feature · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** Line 198 defines route POST /api/metrics/slo (create) and GET /api/metrics/slo{,/status}. No PUT, PATCH, or DELETE endpoints. Handlers: slo_create (line 17208) creates, slo_list (17268) reads all, slo_status (17312) evaluates. No async fn for update or delete. SLO definitions in slo_definitions table cannot be modified or removed after creation—incomplete CRUD.
- **verified:** Verified by code inspection: (1) migrations/103_slo_definitions.sql defines table with id, updated_at, enabled supporting updates; (2) routes (line 198-199) only expose POST/GET /api/metrics/slo and GET /api/metrics/slo/status — no /{id} variant; (3) no slo_update or slo_delete handler functions exist in contracts.rs; (4) SloCreateRequest struct exists but no SloUpdateRequest; (5) similar CRUD patterns confirmed elsewhere (on-call-contacts, DNS, firewall, IPAM, alert-routes); (6) feature #25 tracker lists SLO shipped [x] but includes no follow-up note about update/delete endpoints missing; (7)

### 21. API token operations not emitted to notifications
- **area:** ryuki-api/src/contracts.rs (lines 11568-11676, 11752-11789) · **kind:** missing-feature · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** admin_tokens_create (line 11568) and admin_tokens_revoke (line 11752) both have tracing.info() logs (lines 11665-11676, 11782-11787) but do NOT call emit_for_transition (used by request lifecycle at line 12136). Token creation/revocation should trigger notifications to the token owner and/or admins (similar to request.approve/request.reject). notifications.rs drafts_for_transition() (line 66) only handles request.* events, not security events.
- **verified:** API token create and revoke operations log to tracing.info() only, never calling emit_for_transition() or writing to audit_log. The notification engine's drafts_for_transition() only handles request.* events (line 129 returns empty vec for all others). Token operations are security-sensitive credentials that should be notifiable like request lifecycle events, but have zero integration with the portal notification or audit infrastructure. This gap is not tracked in missing-features-tracker.md (searched for "token", "notification", "security event" — found nothing related to token operation noti

### 22. component_status.adapter_name CHECK constraint is missing recent adapter types
- **area:** migrations/025_degradation_mode.sql · **kind:** data-integrity · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** Migration 025 line 14 CHECK constraint on adapter_name only allows 13 values: ('vmware', 'hyperv', 'proxmox', 'nutanix', 'xen', 'kvm', 'veeam', 'zabbix', 'servicenow', 'commvault', 'rubrik', 'cohesity', 'netbackup'). But sources/ryuki-engine/src/models.rs AdapterType enum has 18 variants including VeeamOne, Prometheus, Datadog, Grafana, SolarWinds. Any attempt to insert those adapter types will violate the CHECK constraint.
- **verified:** The CHECK constraint on component_status.adapter_name (migration 025 line 14) contains only 13 hardcoded values ('vmware', 'hyperv', 'proxmox', 'nutanix', 'xen', 'kvm', 'veeam', 'zabbix', 'servicenow', 'commvault', 'rubrik', 'cohesity', 'netbackup'), while AdapterType enum (sources/ryuki-engine/src/models.rs lines 418-438) defines 18 variants including VeeamOne, Prometheus, Datadog, Grafana, SolarWinds. Any explicit INSERT into component_status with these newer adapter types would violate the CHECK constraint. However, the component_status table is effectively dead code—it is seeded in the mig

### 23. Typo/divergence in degradation_mode contract JSON field name
- **area:** sources/ryuki-engine/src/degradation_mode.rs vs sources/ryuki-api/src/contracts.rs · **kind:** dead-code-or-drift · **severity:** medium · **effort:** S · **ci_validatable:** True
- **evidence:** degradation_mode.rs line 320 has faidefrarAutomationAllowed (nonsensical spelling) and line 333 rule id is 'no-automatic-faidefrar'. But contracts.rs line has the correct 'failoverAutomationAllowed'. Portal or client code consuming engine contract will get inconsistent JSON keys, breaking compatibility.
- **verified:** This is a real, verifiable gap: the `get_degradation_contract()` function in ryuki-engine/src/degradation_mode.rs (lines 304, 320, 333) produces JSON with the typo field name "faidefrarAutomationAllowed" and rule ID "no-automatic-faidefrar", while the API contracts.rs (line 6907) hardcodes the correct names "failoverAutomationAllowed" and "no-automatic-failover". The API endpoint /api/platform/degradation-contract directly calls the engine's function, meaning clients get inconsistent JSON. No integration test validates this consistency, and the bug is not mentioned in the 66-item missing-featu
- **STATUS (2026-06-27) — COMPLETE:** the typo `faidefrar` (a find/replace
  corruption of `failover`) is fixed in ryuki-engine/src/degradation_mode.rs —
  `failoverAutomationAllowed`, rule id `no-automatic-failover`, and the
  requirement text "automatic failover" — in BOTH the `get_degradation_contract()`
  JSON literal and the `DegradationRule` builder. `degradation_contract()`
  (GET /api/platform/degradation-contract) forwards this verbatim, so clients now
  receive the correct keys. This aligns the engine with the three sources that
  ALREADY used the correct spelling: `catalog/degradation-mode-contract.yaml`,
  `scripts/validator-rs/src/degradation_mode.rs`, and the second hardcoded API
  contract block (contracts.rs ~7395). Root cause the typo survived: the only
  coverage (engine tests at lines 443/456) asserted the typo'd names — those two
  assertions now assert the correct names, closing the regression gap. 23 engine
  degradation tests pass.

### 24. Missing scoped access control in metrics recording (cross-tenant bypass risk)
- **area:** ryuki-api/src/contracts.rs (metrics_record_sample, line 16134) · **kind:** security-gap · **severity:** medium · **effort:** M · **ci_validatable:** True
- **evidence:** metrics_record_sample accepts site and environment parameters from the request body without validating that the authenticated user is authorized to record metrics for those scopes. The middleware enforces execute-tier permission, but there is NO scoped access control (e.g., if a user has execute permission for site 'A' only, the handler does not prevent them from recording metrics for site 'B'). The handler should validate body.site and body.environment against the session's site_scope/environment_scope (see feature #2 'administrable, site/env-scoped RBAC' in missing-features-tracker.md).
- **verified:** This is a genuine, concrete security gap verified against the actual code. The metrics_record_sample handler at /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/contracts.rs:16134-16205 accepts site and environment from the request body without validating them against the authenticated session's scopes. The api_tokens table (migration 045_api_tokens.sql) includes site_scope and environment_scope columns, but the resolve_api_token function (main.rs:259-304) explicitly does NOT load these scopes into the AuthSession struct (line 257 comment: "scopes are persisted but not yet carried on 

### 25. Unused/dead-code table: site_status & component_status
- **area:** database schema / persistence · **kind:** dead-code-or-drift · **severity:** medium · **effort:** M · **ci_validatable:** True
- **evidence:** Migration 025_degradation_mode.sql creates site_status and component_status with full seed data (3 sites × 13 adapters = 39 rows). Zero references to FROM/UPDATE/INSERT site_status or component_status in /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src. Engine degradation_mode.rs (line 179) calls seed_sites() and seed component statuses in memory only, never reads the DB. Tables are seeded once, never touched again. Durable but unused persistence.
- **verified:** The gap is verified as real: Migration 025_degradation_mode.sql creates site_status and component_status tables with 39 seeded rows and 3 indexes, but no SQL queries anywhere in /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src or the engine ever SELECT/UPDATE/INSERT/DELETE from these tables. The degradation_mode.rs module uses only in-memory seed_sites() function, rebuilding data fresh on each call. The API handlers at /api/platform/degradation/* are routed to pure functions that never touch the database. The tables exist as orphaned persistence, durable but completely unmaintained at
- **STATUS (2026-06-27) — CLOSED by swarm #8 (`af46a7d`):** `repos/degradation.rs`
  now SELECTs `site_status`/`component_status` (list/get) and UPDATEs them
  (enter/exit); the degradation read handlers query the DB so state survives
  restart. The tables are no longer dead persistence. Duplicate of #8.

### 26. Scheduler tick can exceed interval without backpressure; no per-tick timeout
- **area:** ryuki-api/src/scheduler.rs (spawn_scheduler, lines 278-295) · **kind:** latent-bug · **severity:** medium · **effort:** M · **ci_validatable:** True
- **evidence:** spawn_scheduler loop: ticker.tick().await → match tick_once(pool).await. If tick_once() takes 70+ seconds on a 60-second interval, the next tick fires immediately (interval catches up) and ticks can overlap on the same deadline. No tokio::time::timeout() guards tick_once(). A long/hung DB query, a leader election stall, or MAX_BATCH=100 jobs taking too long can cause the loop to fall behind and fire rapid back-to-back ticks on same-deadline rows, re-running jobs. Suggest: wrap tick_once in tokio::time::timeout with interval - 5s buffer to ensure completion before next tick.
- **verified:** Verified in /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/scheduler.rs lines 278-295: spawn_scheduler loop uses tokio::time::interval(60s) calling tick_once(&pool).await without timeout guard. If tick_once() takes > 60 seconds, the interval catches up and ticks fire back-to-back with no backpressure, causing excessive CPU and DB pool saturation. Other background sweeps (agents.rs, idempotency.rs) have identical patterns. This is not tracked in the missing-features backlog. The duplicate-execution risk claimed is less severe than stated due to clock_timestamp() advancement guarantee

### 27. Audit log append-only trigger does not guard against RESTART IDENTITY
- **area:** migrations/046_audit_log.sql · **kind:** data-integrity · **severity:** medium · **effort:** M · **ci_validatable:** True
- **evidence:** Trigger audit_log_no_truncate raises error on TRUNCATE (line 58). Good. But RESTART IDENTITY on the sequence is NOT gated — an admin with ALTER TABLE permission can RESTART IDENTITY and reuse old IDs. No RLS, no cascade revocation, no audit record that identity was reset. Suggest: add explicit CHECK CONSTRAINT on sequence or add a separate 'identity_reset_log' table that records RESTART events; or remove RESTART IDENTITY from all DDL docs and enforce via IAM policy.
- **verified:** The audit_log append-only trigger (migration 046) prevents TRUNCATE, UPDATE, and DELETE via statement/row-level triggers, but does NOT guard against ALTER SEQUENCE/ALTER TABLE RESTART IDENTITY. A privileged operator with ALTER TABLE permission can reset the sequence counter, enabling ID reuse and breaking the append-only guarantee at the metadata level. This is undetected by the hash-chain verify endpoint (which checks entry_hash linkage, not ID collision). No RLS, no GRANT restrictions, and no runbook guidance prevent this. Not tracked in missing-features-tracker.md. This is a genuine, concre

### 28. No observability for configuration drift or change history
- **area:** ryuki-api/src/contracts.rs (admin_platform_settings_update, etc.), migrations/ · **kind:** missing-feature · **severity:** medium · **effort:** M · **ci_validatable:** True
- **evidence:** platform_config table (upserted at line 11387) stores live config but has no history/versioning. No config_audit or config_history table. When admin_platform_settings_update (line 11432) runs, prior state is lost. idempotency_records table (migration 093) exists for request replay, but platform_config has no equivalent. Missing: (1) config history table with (key, old_value, new_value, actor, timestamp), (2) audit log entries for config changes, (3) drift detection if in-memory config diverges from DB, (4) admin endpoint to view config change history.
- **verified:** No configuration history table exists (migration 001 creates platform_config with only key/value/updated_at; no config_history or config_audit table). The upsert at lines 11387-11388 in contracts.rs overwrites prior values silently—only latest state persists. admin_platform_settings_update (line 11432) does not call record_audit; platform config changes are not logged to audit_log despite the audit_log table existing. No endpoint (GET /api/admin/platform-settings/history) exposes config change history. No drift detection mechanism exists. Not explicitly tracked in missing-features-tracker.md (

### 29. monitoring_review_queue table completely unused by API
- **area:** migrations/031_monitoring_queue.sql + sources/ryuki-api/src/contracts.rs · **kind:** dead-code-or-drift · **severity:** medium · **effort:** M · **ci_validatable:** True
- **evidence:** Migration 031 creates monitoring_review_queue table and seeds multiple rows. But the handler observe_monitoring_review_queue() in contracts.rs returns only static json!({...contract...}) without any database query. The table is dead persistence with no consumer.
- **verified:** The monitoring_review_queue table (migration 031) is created and seeded with 5 rows, but the observe_monitoring_review_queue() handler at /api/observe/monitoring-review-queue-contract returns only static JSON metadata without any database query. Comprehensive grep across the entire codebase finds zero SELECT/UPDATE/DELETE operations on this table, zero repository functions, and zero other handlers referencing it. The table exists as dead persistence with no consumer. This gap is not tracked in missing-features-tracker.md, and the catalog marks the feature as "draft" with "static-seed" source, 

### 30. Scheduler advisory lock election has no heartbeat/lease; hung leader not detected
- **area:** ryuki-api/src/scheduler.rs (tick_once, lines 190-196) · **kind:** latent-bug · **severity:** medium · **effort:** M · **ci_validatable:** False
- **evidence:** tick_once() calls pg_try_advisory_xact_lock(SCHEDULER_TICK_LOCK_KEY) with COMMIT releasing the lock. If a leader is processing an extremely long tick (e.g., 10 min), other replicas will keep losing elections and not run. Unlike typical distributed locks with TTL, this advisory lock holds for the ENTIRE TRANSACTION. A stuck leader (e.g., DB memory exhaustion, slow I/O) will starve followers until the process crashes. Suggest: add a separate scheduled-health check that ensures at least one tick succeeds per interval; or convert to explicit lock_id + heartbeat update pattern.
- **verified:** Real: The scheduler uses pg_try_advisory_xact_lock held for the entire tick transaction (lines 190-196 in scheduler.rs). A hung leader transaction (e.g., blocked on slow DB I/O, network stall, or memory exhaustion) will hold the lock indefinitely, blocking all follower replicas from acquiring it. While a 2x-interval health probe exists (main.rs:2144-2158), it only triggers if a schedule is actually due and overdue—providing 2+ hour latency before detection. No timeout, heartbeat, or automatic lock recovery exists. Not already covered: The tracker marks #1 shipped but does not document the leas

### 31. Lease expiry and idempotency sweeps fail silently without backoff
- **area:** ryuki-api/src/agents.rs (spawn_lease_expiry_sweep, lines 1420-1431), ryuki-api/src/idempotency.rs (spawn_idempotency_sweep) · **kind:** latent-bug · **severity:** medium · **effort:** M · **ci_validatable:** False
- **evidence:** Both sweeps run on fixed intervals (30s, 3600s). If expire_leases() or the idempotency sweep fails (DB unavailable, lock contention), they log error and continue on the SAME interval. No exponential backoff or failure rate tracking. If DB connection pool is exhausted, both sweeps will fail every tick, spam logs with no adaptive behavior, and orphan leases/idempotency records. Suggest: add failure counter + exponential backoff (up to max retry interval) or circuit breaker state.
- **verified:** Confirmed real gap: both spawn_lease_expiry_sweep (agents.rs:1420-1431, 30s interval) and spawn_idempotency_sweep (idempotency.rs:423-434, 3600s interval) log errors and continue on fixed intervals with zero backoff. If expire_leases() or sweep_expired_records() fail (DB unavailable, connection pool exhausted, lock contention), they retry at the same interval forever, silently orphaning leases and idempotency records. Codebase has a circuit_breaker module but it is not used for sweeps. Not in the 66-item missing-features tracker, not in design docs, not implemented. Implementable: add failure 

### 32. Agent heartbeat poll has no rate limit or queue depth feedback
- **area:** ryuki-api/src/agents.rs (poll_job, ack_result, heartbeat handlers) · **kind:** latent-bug · **severity:** medium · **effort:** M · **ci_validatable:** False
- **evidence:** Agents poll for jobs at fixed intervals (typically 10-30s). If 1000 agents poll simultaneously every 30s, API receives 33 reqs/s. Request timeout is global (e.g., 60s). No per-agent rate limit, no per-request queue depth tracking, no adaptive backoff suggestion in response (e.g., 'retry after 60s'). If API is degraded, all agents will keep hammering the same endpoints. Suggest: add per-agent request rate limit (via Extension<LocalLoginThrottle> pattern) or return 429 with Retry-After when queue depth exceeds threshold.
- **verified:** This is a genuine, concrete gap: agent polling has IP-based rate limiting (path group `api`), but lacks: (1) per-agent rate limiting via bearer token, (2) Retry-After header in 429 responses (HTTP spec gap), (3) queue depth feedback in poll responses, (4) coarse path group for agents mixed with all API traffic. The missing-features tracker does not log this. The code in /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/main.rs lines 1302-1308 (rate_limit_path_group) and 1279-1295 (429 response) confirms: agent paths fall into the default `api` bucket with no agent-scoped override, and 

### 33. Agent job polling query missing composite index for fairness
- **area:** ryuki-api/src/agents.rs (lines 2450-2451, similar patterns) · **kind:** missing-feature · **severity:** medium · **effort:** L · **ci_validatable:** False
- **evidence:** Query: SELECT id FROM agent_jobs WHERE platform = $6 AND status = 'Pending' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1. Assumes an index on (platform, status, created_at). If index is missing or uses (platform, created_at, status), query will full-table-scan. With thousands of rows, this can cause lock contention and high CPU. Suggest: verify composite index (platform, status, created_at) exists; add explicit CHECK or comment in migration to ensure index is not dropped.
- **verified:** REAL GAP CONFIRMED: The claim is accurate and represents a genuine, implementable performance issue.

FINDINGS:
1. Query EXISTS & IS CRITICAL: The polling query (line 2450-2451 in /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/agents.rs) is:
   `SELECT id FROM agent_jobs WHERE platform = $6 AND status = 'Pending' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`
   This query is used in 7 locations across agents.rs (lines 446, 2450, 2509, 2566, 2630, 3060, 4377).

2. INDEX IS INCOMPLETE: Migration 054_agent_jobs.sql (line 34) defines:
   `CREATE INDEX idx_agent_jobs_platform_statu

### 34. ID exposed in error messages without encryption/hashing
- **area:** ryuki-api/src/contracts.rs (multiple handlers like dns_record_get, dns_record_delete, on_call_contact_get, etc.) · **kind:** security-gap · **severity:** low · **effort:** S · **ci_validatable:** True
- **evidence:** Handlers return client-supplied IDs directly in error messages: dns_record_get line 23075 returns format!("DNS record '{}' not found", id), dns_record_delete line 23095 does the same, on_call_contact_delete returns the id in successful responses. While these are not secrets, exposing verbatim user input in error text can facilitate information disclosure attacks (e.g., blind SQL injection detection via error messages). Best practice is to use opaque error codes or redact the input.
- **verified:** Found 72+ instances across /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/contracts.rs where handlers expose client-supplied IDs directly in error messages (e.g., format!("DNS record '{}' not found", id) at line 23075, on_call_contact_delete at line 15921 returns "id": id). This violates the stated security baseline ("Evidence must be redacted...identifiers...are stripped") and OWASP error-handling best practice. The ProblemDetails type exists but is inconsistently used; handlers use raw (StatusCode, Json<Value>) tuples. No error-code pattern (like ERR_NOT_FOUND) exists to provide o

### 35. Admin token issuance prevents machine-to-machine escalation, but token revocation audit is missing
- **area:** ryuki-api/src/contracts.rs (admin_tokens_revoke, line 11752) · **kind:** missing-feature · **severity:** low · **effort:** S · **ci_validatable:** True
- **evidence:** admin_tokens_revoke(Path(id), AuthExtractor) does not emit an audit log. Revoking an API token is a sensitive administrative action that affects access control, but it is not recorded in the audit trail. The handler should log: actor, action, token_id, token_name, and timestamp.
- **verified:** REAL GAP: Admin operations (token revocation at /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/contracts.rs:11752-11790, token creation at 11568-11699, session revocation at 11845-11878, platform settings updates at 11432-11462 and 11465-11479) only log via tracing::info() but do NOT call audit::record_audit() or audit::record_audit_local(). The audit_log table (migration 046) explicitly supports non-request audit (request_id is nullable with comment "nullable: non-request audit later"), and the hash-chain infrastructure (migration 094) is in place. The missing-features.md design do
- **STATUS (2026-06-27) — CLOSED by swarm #5 (`03e532d`):** `admin_tokens_create`,
  `admin_tokens_revoke`, and the session-revoke handler now write durable
  hash-chained audit rows (actions `api-token-create`, `api-token-revoke`,
  `session-revoke`) atomically with the mutation, covered by
  `test_token_create_and_revoke_write_audit_log`. Duplicate of #5. (Note: #21 —
  emitting these as portal NOTIFICATIONS — remains open; #5 deferred
  security-event notifications.)

### 36. Unused/dead-code table: monitoring_review_queue (API-only contract)
- **area:** database schema / persistence · **kind:** dead-code-or-drift · **severity:** low · **effort:** S · **ci_validatable:** True
- **evidence:** Migration 031_monitoring_queue.sql creates monitoring_review_queue (id, host_or_service_name, review_type, site, assigned_to, status, etc.) with seed data. Grep shows 2 references in contracts.rs: a route GET /api/observe/monitoring-review-queue-contract (line ~750, observe_monitoring_review_queue handler) and a static JSON response (no query to table). Table is seeded but never read/written; endpoint is pure contract/schema endpoint. Dead persistence.
- **verified:** REAL AND UNTRACKED GAP: The monitoring_review_queue table (created in migration 031_monitoring_queue.sql at /Users/mvandenbulcke/Repos/ryuki.io/migrations/031_monitoring_queue.sql) is seeded with 5 sample rows but NEVER read or written by the API. The only reference to this table in the Rust codebase is the contract endpoint GET /api/observe/monitoring-review-queue-contract (sources/ryuki-api/src/contracts.rs line ~1060), which returns a STATIC hardcoded JSON payload with no database query. Comparison: The shift_queue table (migration 029) is similarly seeded, but HAS working API endpoints (GE

### 37. Health check readiness probe insufficient validation of SELECT 1 result
- **area:** ryuki-api/src/main.rs (readiness_check, lines 1905-1915) · **kind:** latent-bug · **severity:** low · **effort:** S · **ci_validatable:** True
- **evidence:** Query: SELECT 1 → fetch_one(pool) → Ok(1) is considered ready. If a misconfigured DB driver or corrupted connection returns a different type (e.g., null, 0, out-of-range), Ok(_) case treats it as DatabaseUnusable (line 1910) — correct handling but the error path is silent (logs at WARN only). Better: validate result == 1 explicitly and return a distinct error for 'unexpected result type' to help ops distinguish DB corruption from simple unavailability.
- **verified:** The claimed gap IS real. The readiness_check function at lines 1905-1915 in /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/main.rs has asymmetric logging: the Ok(_) arm (line 1910) that catches unexpected return values produces no diagnostic log, while the Err(e) arm (lines 1911-1913) does log with tracing::warn. This is inconsistent with the parallel self-health probe (line 2089-2091) which explicitly logs "unexpected probe result" when Ok(_) is matched. While SELECT 1 should never return anything other than 1 in practice, this observability gap makes edge-case debugging harder. Th
- **STATUS (2026-06-27) — COMPLETE:** the readiness probe's `Ok(unexpected)` arm
  now logs a `tracing::warn!` ("readiness probe returned an unexpected result")
  carrying the actual value, symmetric with the `Err` arm and matching the
  self-health probe's diagnostic. Behavior unchanged (still `DatabaseUnusable`);
  this only closes the observability gap so ops can distinguish a corrupted
  connection from plain unavailability.

### 38. Missing GET-by-id endpoint for browser sessions
- **area:** sources/ryuki-api/src/contracts.rs · **kind:** missing-feature · **severity:** low · **effort:** S · **ci_validatable:** True
- **evidence:** Line 1320 defines GET /api/admin/sessions (list) and DELETE /api/admin/sessions/{id} (revoke). No GET /api/admin/sessions/{id} endpoint. Handlers: admin_sessions_list (10403 — returns all sessions), admin_sessions_revoke (11856). Operator cannot retrieve a single session record for inspection—violates REST conventions.
- **verified:** Code verification shows: (1) routes.rs line 1319-1320 define GET /api/admin/sessions (list) and DELETE /api/admin/sessions/{id} (revoke), but no GET {id}; (2) handler admin_sessions_list exists at line 11804 returning 7 fields per session; admin_sessions_revoke exists at 11845; no admin_sessions_get handler; (3) SessionListRow struct (11793) is defined with all needed columns; (4) parallel REST resources (alert-routes, sites) have GET-by-id endpoints showing this is the codebase's standard pattern; (5) untracked in missing-features-tracker.md. This is a genuine, concrete REST completeness gap 

### 39. Missing GET-by-id endpoint for AD computers
- **area:** sources/ryuki-api/src/contracts.rs · **kind:** missing-feature · **severity:** low · **effort:** S · **ci_validatable:** True
- **evidence:** Lines 361-366 define operations on AD computers: POST /api/identity/ad/{operation} handlers (prestage, validate, move, disable, enable, delete). Lines 369-370 define read endpoints ad_reconcile() and ad_orphaned() for scanning. No GET /api/identity/ad/{name} to retrieve a single computer's record. Operator cannot query an individual computer by name—query-only via reconcile/orphaned bulk scan.
- **verified:** Verified gap: No GET /api/identity/ad/{name} endpoint exists despite database layer (ad_computers::get_by_name) and active use by POST handlers. Reconcile/orphaned endpoints return aggregation results, not individual computer records. Not in missing-features tracker or API docs. Database function exists at /Users/mvandenbulcke/Repos/ryuki.io/sources/ryuki-api/src/repos/ad_computers.rs; implementation would be straightforward thin wrapper around get_by_name().
- **STATUS (2026-06-27) — COMPLETE:** new `GET /api/identity/ad/computer/{name}`
  → `ad_get` thin wrapper over `repos::ad_computers::get_by_name` (200 with the
  computer, 404 unknown, 503 no DB; authn-gated to match the AD surface). Path
  uses a distinct `/computer/` segment to avoid any conflict with the
  `/api/identity/ad/<verb>/{name}` POST routes (verified: all 20 router-build
  tests pass). DB test `ad_get_by_name_returns_computer_or_404` prestages then
  reads back, plus the 404 path. NOTE: a cross-cutting AD site-scope gate is a
  separate follow-up — the AD write-by-name handlers (move/disable/enable/delete)
  do not gate by site either, so this read deliberately matches that posture
  rather than becoming stricter than the writes.

### 40. Insufficient input validation on free-form text fields (name, description, reason, justification)
- **area:** ryuki-api/src/contracts.rs (multiple handlers) · **kind:** security-gap · **severity:** low · **effort:** M · **ci_validatable:** True
- **evidence:** Most text fields are validated for length and non-empty, but there is NO explicit control-character filtering or SQL-injection-resistant escaping verification at the API boundary (relying on parameterized queries only). While parameterized queries in sqlx prevent SQL injection, XSS vectors in JSON responses and LDAP injection in identity operations should be explicitly guarded. Example: on_call_contact_create validates name length but does NOT reject control characters or special HTML chars. Recommendation: apply consistent input sanitization (e.g., unicode normalization, control-char stripping) to all user-facing text fields.
- **verified:** Control character validation is implemented in on_call_contact_rejection (line 15659-15666) but is missing from multiple other text-field handlers: requests_reject, shift_escalate, access_review_approve, access_review_revoke, access_review_exempt. These unvalidated fields (reason, justification) are persisted to the database and returned in JSON responses, creating potential for log forging and header injection attacks. The gap is real, concrete, and implementable by applying the existing validation pattern consistently across all handlers accepting user text input.

### 41. failure_patterns table seeded but never read or written
- **area:** migrations/028_knowledge_suggestions.sql · **kind:** dead-code-or-drift · **severity:** low · **effort:** M · **ci_validatable:** True
- **evidence:** Migration 028 creates failure_patterns table (error type, message fragments, workflows, suggested articles) and INSERTs 4 seed rows. Zero references to failure_patterns in sources/ryuki-api or sources/ryuki-engine. This is orphaned persistence with no API handler or engine consumer.
- **verified:** The failure_patterns table (migration 028) is seeded with 4 rows but has zero references in ryuki-api or ryuki-engine source code. The knowledge_suggestion engine is pure/dry-run only and never reads the database. No repository module, handler, or engine function queries or mutates this table. The feature is not tracked in the missing-features-tracker.md. This is a concrete dead-persistence gap matching the calibre of the site_status example.

