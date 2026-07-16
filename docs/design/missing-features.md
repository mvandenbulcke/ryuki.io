# Ryuki — Missing Features: Analysis & Implementation Design

> ## Historical snapshot — do not use for current readiness
>
> This analysis is retained for design rationale and audit history. Its body,
> status table, gap counts, and file/line references describe older revisions
> and are not a current project assessment. For current first-test acceptance,
> use [`docs/first-test.md`](../first-test.md). For feature implementation
> status, use [`missing-features-tracker.md`](missing-features-tracker.md) and
> verify it against the current code and test gates.
>
> ## ⚠️ Reconciliation status — 2026-06-14, HEAD 408efd2
>
> This document was authored at `7172ea8` (2026-06-12). Approximately 65 commits have landed since
> on `main`, implementing substantial portions of every P0 theme. The "Current state" sections,
> file:line anchors, and gap counts in the body below are **largely stale** — they describe the
> codebase as it was on 2026-06-12. Treat this dated reconciliation as historical context too;
> it does not override the current acceptance specification or tracker.
>
> | # | Theme | Status | Evidence |
> |---|-------|--------|----------|
> | 1 | Live adapter execution & provider integration | **PARTIAL** | Vendor-integration framework + connections DB landed (`db8a678`, `052_integration_connections.sql`). Execution-runner library AND real dry-run wiring into the lifecycle: **6 offerings now run genuine `terraform plan` / `ansible --check`** with output persisted as stage evidence — patch-maintenance, request-preflight, zabbix-onboarding, linux/windows-server-deployment, controlled-restore-request (`763d4bb`/`0a80a0d`/`abfa3f5`/`c1225ab`); plus a `request_type→offering_id` OS-based resolver (`c1225ab`). Runner hardened — subprocess timeout, non-blocking `spawn_blocking`, atomic no-DB transitions (409 on concurrent change), and env hermeticity (`408efd2`). Remaining: live (non-dry-run) provider I/O, real secrets resolution, async execution jobs, and surfacing the new evidence in the portal (`plan_summary_text` still shows only the simulated `dry-run-plan` key). |
> | 2 | Authentication & authorization completion | **PARTIAL** | Real Entra ID RS256/JWKS validation (`f0c3d5e`, `entra_auth.rs`), coherent RBAC + route-level permission gates (`d14f589`), scoped API tokens + service accounts (`8e9f6e4`, `045_api_tokens.sql`), local credential-checking auth (`cf4985f`), and session persistence (`044_session_provider.sql`) all shipped. jsonwebtoken upgraded 9→10 with the `rust_crypto` backend (`f35ad8e`), and Entra validation now demands iss/aud/nbf claims are PRESENT (not just correct-when-present), closing a fail-open gap where a token omitting a pinned claim slipped past (`f3266df`). Remaining: not all 226+ mutating routes have been individually audited for RBAC coverage — some GET routes may still be effectively anonymous in non-Entra mode. |
> | 3 | Durable persistence & data model wiring | **PARTIAL** | Request lifecycle now fully durable — payload/stages/approvals persisted as JSONB (`496061b`, `047_request_state.sql`). DNS records (`048`), firewall rules (`049`), IPAM (`050`), secrets rotation (`051`), alert routes, legal holds, maintenance windows (`b49ebf5`), integration connections (`052`) all wired to DB. Engine state (61-table gap) is substantially closed for request-centric and most P1 data; inventory/metric tables (`046_inventory_state` design) and execution-job tables remain unbuilt. |
> | 4 | Request lifecycle & approval workflow completeness | **DONE** | `reject_request` / `cancel_request` with actor attribution and audit records implemented (`a4d9d72`); approver inbox endpoint + portal view shipped (`3f5118d`, `49f1275`); locking and request locking path improved; audit trail is durable and append-only (`046_audit_log.sql`). Approver is no longer the literal `"admin"`. |
> | 5 | Audit trail, evidence & compliance export | **DONE** | Durable append-only audit trail with real session identity (`68e61ff`, `046_audit_log.sql`); per-request digest-sealed compliance evidence pack (`e96e818`); secret-bearing free-text redacted in audit reads (`0b093cb`). |
> | 6 | Portal feature parity & functionality | **PARTIAL** | Portal now makes real HTTP calls to the API via `UpstreamClient` (`6b2d489`); login, requests list/create/detail, approvals inbox, integrations workspace, and admin settings are all live-wired. Mutations (approve/reject/cancel), execution progress, and several domain workspaces still have no portal surface or degrade to static/fallback. |
> | 7 | Deployability, CI/CD & release engineering | **DONE** | Both Dockerfiles fixed and building (`2956c72`); CI pipeline gating `main` with build/test/lint/secret-scan/validator/image jobs (`0dc9544`); K8s config + DB network policies + Vault VSO wiring (`62c5049`); Makefile targets added (`7587d30`). No DB is opened in CI (no Postgres service container) so DB-path tests remain skipped there. |
> | 8 | Lifecycle extension: Protect/Publish/Maintain/Retire & offering availability | **OPEN** | No post-completion lifecycle stages (Protect/Publish/Maintain/Retire) implemented in the engine or API. Catalog offerings remain `status: planned`. No Windows deployment engine. |
> | 9 | Notifications, webhooks & eventing | **OPEN** | No SMTP, no webhook outbox, no portal feed, no `statusCallback` dispatch. No commits touch this theme. |
> | 10 | Scheduling & background automation | **PARTIAL** | Maintenance windows are now durably persisted to DB (`b49ebf5`). No general job queue, timer worker, or scheduled-execution pipeline exists; `schedule` endpoints remain in-process statics for non-maintenance-window domains. |
> | 11 | Platform observability & self-monitoring | **PARTIAL** | Metrics mutex-poisoning crash fixed (`3c9771a`). Health checks still return `HealthSource::Simulated` for all seven subsystems (`sources/ryuki-engine/src/health_monitor.rs`); quantile fabrication unchanged; no scrape/alert/log-shipping wiring. |
> | 12 | Catalog, contract & documentation integrity | **DONE** | Validator driven to 119/119 green (`ba0827b`); deleted C# layout purged from all 120 slice modules; docs/workflows, docs/ui, docs/architecture, docs/source-inputs, new catalog YAMLs authored. Validator runs in CI (`0dc9544`) but still `continue-on-error: true` pending enforcement promotion. |
> | 13 | Test & verification depth | **PARTIAL** | CI now builds and runs `cargo test --workspace`; workspace-level integration tests exist (`tests/`). No test constructs the real Axum router against a live DB (no Postgres service in CI), no portal component render tests, and no provider mock layer. Engine unit tests and lifecycle tests are solid but coverage of the auth and API surface remains shallow. |
> | 14 | Adapter & vendor expansion | **PARTIAL** | Integration connections framework and credential-source model landed (`db8a678`, `052`); portal integrations workspace with CRUD shipped (`d90e650`, `bfa41c4`). All 17 adapters remain `static_dry_run()` only; no second vendor category has a real implementation behind it. |
>
> **Summary: 4 DONE · 8 PARTIAL · 2 OPEN** (themes 8 and 9 untouched).

**Date:** 2026-06-12

## Executive summary

This document consolidates a full-codebase gap analysis of Ryuki, the governed control plane for multi-site datacenter infrastructure automation. It was produced by a multi-agent survey: independent agents examined the domain engines (`sources/ryuki-engine`), the API layer (`sources/ryuki-api`), the Leptos/Axum portal (`portal/portal-ui`), the 116 catalog contracts (`catalog/`), the 42 PostgreSQL migrations (`migrations/`, numbered 001–043 with `002` never shipped), the docs site (`docs/`), the deploy artifacts (`deploy/`), and the test surfaces (workspace tests plus `scripts/validator-rs`). Every claimed gap was then adversarially verified against the repository — claims that did not survive verification were dropped or recorded in the refuted-claims appendix rather than silently discarded.

The headline: **96 features are confirmed missing or incomplete, organized into 14 themes — 7 at P0 and 7 at P1.** The P0 themes are disqualifying for production use, individually and jointly: the platform cannot execute a single live provider call (all 17 adapters are dry-run dead code), cannot authenticate (token validation is a stub, all 383 GET routes are anonymous), cannot persist (61 of 64 tables are dead schema; engine state lives in process-local statics), cannot say "no" in its approval workflow (no reject/cancel; the approver is the literal string `admin`), keeps no audit trail at all, ships a portal that performs zero HTTP requests against its own API, and cannot even be built as a container — both Dockerfiles fail at `cargo metadata` and no CI gates `main`.

P0 here means "production readiness is impossible until closed": each P0 theme blocks the platform's core value proposition (governed, evidence-first, approval-gated execution) rather than degrading it. The P1 themes — lifecycle extension to the advertised Protect/Publish/Maintain/Retire stages, notifications/webhooks, scheduling, platform self-observability, catalog/validator integrity, test depth, and adapter/vendor expansion — are the difference between a minimally credible platform and one an operations organization would actually adopt. Each theme section below carries a current-state assessment with file/line evidence, a concrete design, a sequenced implementation plan with size estimates, and explicit risks and open questions.

## Theme overview

| Theme | Priority | # Confirmed gaps | Summary |
|---|---|---|---|
| Live adapter execution & provider integration | P0 | 8 | All 17 provider adapters are dry-run-only dead code; no I/O substrate, secrets layer, execution jobs, or inventory ingestion exists. |
| Authentication & authorization completion | P0 | 8 | Token validation is a no-op stub, every GET route is anonymous, RBAC is enforced on ~6 of 226 mutating routes, and no machine credentials exist. |
| Durable persistence & data model wiring | P0 | 7 | 61 of 64 tables are dead schema; engine state lives in process-local statics and evaporates on restart; the `requests` table cannot represent 13 of 14 request types. |
| Request lifecycle & approval workflow completeness | P0 | 7 | No reject/cancel/rework transitions, approval records the literal `"admin"`, locking acquires no lock, execution is synchronous and unobservable. |
| Audit trail, evidence & compliance export | P0 | 4 | No audit data model at all; stages and evidence are discarded in DB mode; exports are non-durable strings with no digest or signature. |
| Portal feature parity & functionality | P0 | 10 | The portal performs zero HTTP calls to the API: all reads are hardcoded fallbacks, all mutations rejected, and entire domains of the ~616 real routes have no portal surface; allowlist/route parity holds today but is enforced by nothing. |
| Deployability, CI/CD & release engineering | P0 | 12 | Both Docker builds fail, no CI gates `main`, K8s pods cannot reach their database, and there are no releases, backups, restore paths, or migration tooling. |
| Lifecycle extension: Protect/Publish/Maintain/Retire & offering availability | P1 | 6 | The advertised post-completion lifecycle stages do not exist; all 12 catalog offerings are `status: planned`; the flagship Windows deployment offering has no engine. |
| Notifications, webhooks & eventing | P1 | 5 | The platform cannot tell anyone anything: SMTP config is dead code, the contract-required `statusCallback` is ignored, and no outbox, webhooks, or portal feed exists. |
| Scheduling & background automation | P1 | 5 | No timers, job queue, workers, or jobs schema anywhere; "schedule" endpoints push rows into in-process mutexes that never re-fire. |
| Platform observability & self-monitoring | P1 | 4 | All seven self-health checks hardcode Healthy/Simulated; metrics are hand-rolled, unauthenticated, and fabricate quantiles; no scrape/alert/log-shipping wiring ships. |
| Catalog, contract & documentation integrity | P1 | 8 | The validator fails 116 of 121 slices against a deleted C# layout; catalog YAML is never loaded at runtime; no OpenAPI spec covers the ~616 routes. |
| Test & verification depth | P1 | 8 | No test constructs the router, opens a database in CI, renders a portal view, or mocks a provider; the recently hardened security core sits at 0% executed coverage. |
| Adapter & vendor expansion | P1 | 4 | Ten of fourteen provider categories are config-only enums with no adapter behind them, and adapter registration is an ~11-surface hand edit that has already drifted; harden the mechanism, then add vendors in dry-run, blocked-by-default waves. |

---

## Live adapter execution & provider integration

Ryuki's core promise — governed execution of infrastructure changes against vCenter, Hyper-V, Proxmox, Veeam, Zabbix, ServiceNow and eleven other providers — does not exist in any form. All 17 adapter structs in `sources/ryuki-engine/src/adapter_framework.rs` expose exactly one constructor (`static_dry_run()`), point at `*.example.invalid`, and return canned `DRY-RUN:` strings; nothing in the codebase ever calls them (the only reference outside the file is the `pub mod` declaration in `sources/ryuki-engine/src/lib.rs:3`). The engine crate is structurally incapable of I/O — no tokio, no HTTP client anywhere in `Cargo.lock` — and the project's own validator (`scripts/validator-rs/src/ryuki_engine.rs:79-87`) *prohibits* adding one. The Executing/Verifying lifecycle stages are synchronous string formatting (`request_lifecycle.rs:386-480`), verification cannot fail, and there is no rollback, no job model, no progress tracking, no credential source (Vault is documented but unimplemented), and no ingestion path so all plans/approvals are computed over fabricated state. Going live is not a flag flip; it requires an execution substrate built alongside the existing pure-logic engine, with the dry-run posture preserved as the default and live calls gated by approval, per the repo's own governance conventions.

### Current state

- **Adapters**: `sources/ryuki-engine/src/adapter_framework.rs` (1,535 lines) defines a synchronous `ProviderAdapter` trait (`connect/health_check/sync_inventory/execute/disconnect`, `execute(&self, operation: &str, params: &HashMap<String, String>)`) and 17 impls. Every `execute()` returns `sanitized_dry_run_result()` (`"DRY-RUN: {adapter} operation '{op}' simulated"`); `connect`/`disconnect` are `Ok(())` no-ops; `health_check` always returns `AdapterStatus::Connected`; `sync_inventory` returns hardcoded mock items. Unit tests (lines 1490-1535) assert the dry-run strings, making simulation the spec.
- **Dead code**: no engine or API route constructs an adapter. `request_lifecycle::execute_request()` fabricates its own `EvidenceItem` inline; so do `vm_operations.rs`, `patch_engine.rs`, `snapshot_engine.rs`, `backup_engine.rs`, `inventory_sync.rs` (`mock_inventory_for_source()`), `zabbix_drift.rs`, and `servicenow_api.rs`. There is no dispatch seam.
- **No I/O capability, enforced by policy**: `sources/ryuki-engine/Cargo.toml` depends only on serde/serde_json/serde_yaml/chrono/uuid/thiserror/ryuki-core; zero `async fn` in the crate; no reqwest/ureq/isahc in `Cargo.lock`. `scripts/validator-rs/src/ryuki_engine.rs` fails validation if the engine references `reqwest`, `sqlx`, `PgPool`, `diesel`, `rusqlite`, or `hyper::Client` (`PROHIBITED_IMPORTS`, lines 79-87, enforced at 268-276) and *requires* `static_dry_run` constructors and `DRY-RUN` output (lines 242-259).
- **Lifecycle**: `request_lifecycle.rs:386-437` completes the execute stage synchronously with `started_at == completed_at` and exits already in `Verifying`; `verify_request()` (439-480) unconditionally returns three `(simulated)` evidence items and cannot fail; `fail_request()` (540-553) only flips status. API handlers `requests_execute`/`requests_verify` in `sources/ryuki-api/src/contracts.rs` (~7366-7475, routed at lines 116-117 as `POST /api/requests/{id}/execute|verify`) call these inline in the request handler and persist only `status`/`stage` columns to the `requests` table (`migrations/003_requests.sql` — no evidence, job, or step persistence).
- **Registry & catalog**: adapter inventory is seed JSON in `contracts.rs` (159 `providerCallsEnabled:false`, zero `true`). `catalog/adapter-readiness-catalog.yaml` has no live readiness state (enum tops out at `ready-dry-run`, lines 5-11) and models only 6 of 17 adapters. `models.rs` `ReadinessState` enum is just `Configured/Blocked/Stale`. No `adapter_configs` table exists in `migrations/`. No integrations view exists in `portal/portal-ui/src/views/` (only dashboard, login, requests, request_create, request_detail, workspaces).
- **Secrets**: `SecretProvider` in `sources/ryuki-core/src/config.rs:81` models hashicorp-vault/aws/azure/gcp/bitwarden but selecting Vault only emits a validation warning (line 1094); `health_monitor.rs:146-153` returns a hardcoded "vault is unsealed and healthy"; no vault client crate exists; the DB URL comes from env (`RYUKI_DATABASE_URL`), contradicting README.md:50-66 / docs/architecture.md:57.
- **Execution mode theater**: `sources/ryuki-api/Dockerfile` bakes `ENV RYUKI_API_EXECUTION_MODE=static-dry-run` but the var is read nowhere in `sources/ryuki-api/src`; the portal hardcodes `pub const WORKSPACE_EXECUTION_MODE: &str = "static-dry-run"` at compile time (`portal/portal-ui/src/workspace_catalog.rs:14`) even though `portal/portal-ui/src/server_boundary.rs` already carries an `execution_mode` field end-to-end.
- **ServiceNow**: `servicenow_api.rs:255-370` is a local queue simulation; `migrations/034_servicenow_queue.sql` already persists a `servicenow_queue` table with `external_ref`/`status` columns, but nothing transmits. Docs contradict each other on what unlocks live execution (`docs/architecture.md:56` vs `docs/configuration.md:54`; `docs/index.html:972,1361` and `README.md:76` overclaim live behavior).

### Design

The architectural keystone: **keep `ryuki-engine` pure and I/O-free** (it is the project's differentiator and the validator's purity policy is good), and introduce a new **`sources/ryuki-adapters`** crate as the execution substrate. Engines remain decision/validation logic operating on state passed in; `ryuki-adapters` performs provider I/O; `ryuki-api` orchestrates (it already has tokio `full` + sqlx). Dry-run remains the default everywhere; live execution requires *all* of: global `ExecutionMode::LiveApproved`, per-adapter `provider_calls_enabled = true` (admin-approved, recorded), a resolvable secret reference, and a request in `Locked` status.

#### 1. `ryuki-adapters` crate: async provider clients

- **Goal**: real `connect/health_check/sync_inventory/execute` against provider APIs (vSphere REST/SOAP, Hyper-V via WinRM/PowerShell gateway, Proxmox API, Veeam REST, Zabbix JSON-RPC, ServiceNow Table API, Prometheus/Grafana/Datadog HTTP APIs, etc.), without contaminating the pure engine.
- **Crate layout**: `sources/ryuki-adapters/` added to the workspace `members` in `/Cargo.toml`. Dependencies: `tokio`, `reqwest` (rustls, no default TLS), `serde`, `ryuki-core`, `ryuki-engine` (for `models::{AdapterType, InventoryItem, EvidenceItem}`). One module per provider family: `vmware.rs`, `hyperv.rs`, `proxmox.rs`, `nutanix.rs`, `xen.rs`, `kvm.rs`, `veeam.rs`, `commvault.rs`, `rubrik.rs`, `cohesity.rs`, `netbackup.rs`, `zabbix.rs`, `prometheus.rs`, `datadog.rs`, `grafana.rs`, `solarwinds.rs`, `servicenow.rs`, plus `dispatch.rs`, `operation.rs`, `secrets.rs`.
- **Trait**: a new async trait (Rust 2024 native async-in-trait, dispatched via an `AdapterDispatch` enum keyed by `AdapterType` rather than `dyn` to avoid dyn-compatibility issues):
  - `async fn connect(&self) -> Result<(), AdapterError>`
  - `async fn health_check(&self) -> Result<AdapterHealth, AdapterError>` (real status, latency, api_version — not always-`Connected`)
  - `async fn sync_inventory(&self) -> Result<Vec<InventoryItem>, AdapterError>`
  - `async fn execute(&self, op: &Operation) -> Result<OperationOutcome, AdapterError>` — `Operation` is a typed enum (`VmReconfigure { ci, cpu, memory_gb }`, `SnapshotCreate {…}`, `BackupJobRun {…}`, `PatchWaveStart {…}`, …) replacing `HashMap<String, String>`; `OperationOutcome` carries provider task id, raw response digest, and `Vec<EvidenceItem>`.
- **Constructors**: every adapter keeps `static_dry_run()` (the existing simulation behavior moves here or stays shared) and gains `live(config: AdapterConfig, secret: ResolvedSecret) -> Result<Self, AdapterError>`. Dry-run instances are constructible with no secret; live instances refuse `*.example.invalid` endpoints and require a resolved secret.
- **Engine adjustment**: `sources/ryuki-engine/src/adapter_framework.rs` shrinks to the shared *contract* (operation/evidence model, dry-run simulators used by validation and planning). Engines never gain async or I/O.

#### 2. Adapter registry: DB-backed configuration replacing seed JSON

- **Data model** — new migration `migrations/044_adapter_registry.sql`:
  - `adapter_configs(id UUID PK DEFAULT gen_random_uuid(), adapter_type TEXT NOT NULL CHECK (adapter_type IN ('vmware','hyperv','proxmox','nutanix-ahv','xen','kvm','veeam','veeam-one','commvault','rubrik','cohesity','netbackup','zabbix','prometheus','datadog','grafana','solarwinds','servicenow')), name TEXT NOT NULL, site TEXT NOT NULL, endpoint TEXT NOT NULL, secret_ref TEXT NOT NULL DEFAULT '', readiness_state TEXT NOT NULL DEFAULT 'missing-secret-reference', provider_calls_enabled BOOLEAN NOT NULL DEFAULT FALSE, approved_by TEXT, approved_at TIMESTAMPTZ, tls_verify BOOLEAN NOT NULL DEFAULT TRUE, timeout_ms INTEGER NOT NULL DEFAULT 30000, max_retries INTEGER NOT NULL DEFAULT 2, metadata JSONB NOT NULL DEFAULT '{}', created_at/updated_at TIMESTAMPTZ)` — `secret_ref` stores a *reference* (e.g. `vault:kv2:ryuki/adapters/vmware-gblon`), never a credential, honoring `requiresSecretReference: true` already modeled in the catalog.
  - `adapter_health_history(id UUID PK, adapter_id UUID REFERENCES adapter_configs(id), checked_at TIMESTAMPTZ, status TEXT, latency_ms INTEGER, api_version TEXT, detail TEXT)`.
- **Catalog**: extend `catalog/adapter-readiness-catalog.yaml` `readinessStates` with `ready-live` and `live-degraded`; add entries for the 11 unmodeled adapters (nutanix-ahv, xen, kvm, veeam-one, commvault, rubrik, cohesity, netbackup, prometheus, datadog, grafana, solarwinds — matching the `AdapterType` Display strings in `models.rs`). Extend the engine `ReadinessState` enum (`Configured/Blocked/Stale`) to align with the catalog enum so code and catalog stop diverging.
- **API endpoints** (in `contracts.rs`, following existing `/api/integrations/*` conventions):
  - `GET /api/integrations/adapters` — list from `adapter_configs` (replaces static seed listing over time; seeds remain as dev fallback when `get_db()` is `None`, matching the existing dual-path pattern in `requests_execute`).
  - `POST /api/integrations/adapters` / `PUT /api/integrations/adapters/{id}` — create/update (admin, verified session — reuse the verified-admin gate from commit `7172ea8`). Reject any body field that looks like a raw credential.
  - `POST /api/integrations/adapters/{id}/health-check` — runs the real `health_check()`, persists to `adapter_health_history`, updates `readiness_state`.
  - `POST /api/integrations/adapters/{id}/enable-live` — the approval gate: requires verified admin, a non-empty `secret_ref` that resolves, a passing health check; sets `provider_calls_enabled = true`, records `approved_by/approved_at`, emits an audit evidence record. `POST .../disable-live` is unconditional (kill switch).
- **Portal UI**: new `portal/portal-ui/src/views/integrations.rs` (registered in `views/mod.rs`, nav item in `workspace_catalog.rs`): adapter table (type, site, endpoint, readiness badge, last health check, live/dry-run pill), health-check button, and an enable-live flow that displays the blockedReasons checklist (`secret-reference-missing`, `provider-endpoint-unconfigured`, `approval-route-required`) from the catalog.
- **Validation & evidence**: every enable/disable transition writes an `EvidenceItem` (`evidence_type: ConfigChange`) into `adapter_configs.metadata` history and the audit trail; health checks are evidence-producing.
- **Safety**: rows default to `provider_calls_enabled = FALSE` and `readiness_state = 'missing-secret-reference'`; no migration seed ever sets `true`.

#### 3. Secrets layer: real Vault resolution behind `SecretProvider`

- **Goal**: give live adapters a credential source consistent with the documented architecture (README.md:50-66), keeping secrets out of env/config/DB.
- **Engine/core changes**: new `secrets` module in `sources/ryuki-core` (or in `ryuki-adapters` to keep `ryuki-core` dependency-light) implementing a `SecretResolver` trait with a `vaultrs`-backed `HashicorpVault` implementation first (KV v2 read by `secret_ref`, AppRole or token auth from a single bootstrap env var/file); `SecretProvider::{AwsSecretsManager, AzureKeyVault, GcpSecretManager, BitwardenSecretsManager}` stay `unimplemented` but now fail loudly at startup if selected, instead of warning (`config.rs:1094-1097`). `ResolvedSecret` zeroizes on drop and is never serialized (`#[serde(skip)]`, no `Debug` of contents).
- **API endpoints**: `GET /api/platform/secrets/health` — real Vault `sys/health` call (sealed/unsealed/latency), replacing the invented result; `sources/ryuki-engine/src/health_monitor.rs::check_vault_health()` becomes a pure evaluator that consumes a `VaultHealthSample` passed in by the API layer (engine stays I/O-free).
- **Validation & evidence**: validator gains a check that `adapter_configs` API handlers and `ryuki-adapters` never log or persist resolved secrets (extend the existing `password = "` / `secret = "` hardcoded-credential checks in `ryuki_engine.rs:260-266` to the new crate). Evidence items referencing credentials must use the existing `redacted`/`redacted_value` mechanism on `EvidenceItem`.
- **Safety/dry-run**: with `SecretProvider::None` (dev default), only `static_dry_run()` adapters are constructible; enable-live is impossible. Document the residual env-based DB credential (`RYUKI_DATABASE_URL` in `sources/ryuki-api/src/main.rs:613`) honestly in `docs/configuration.md`, or add optional Vault-sourced DB creds as a follow-up.

#### 4. Asynchronous execution jobs for the Executing/Verifying stages

- **Goal**: turn `Locked → Executing → Verifying → Completed` into a real, observable, failable, rollback-capable async pipeline.
- **Data model** — new migration `migrations/045_execution_jobs.sql`:
  - `execution_jobs(id UUID PK, request_id UUID NOT NULL REFERENCES requests(id), mode TEXT NOT NULL CHECK (mode IN ('static-dry-run','live')), status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','verifying','succeeded','failed','rolling-back','rolled-back','cancelled')), attempt INTEGER NOT NULL DEFAULT 1, queued_at/started_at/finished_at TIMESTAMPTZ, failure_reason TEXT, created_by TEXT)`.
  - `execution_steps(id UUID PK, job_id UUID REFERENCES execution_jobs(id), step_no INTEGER NOT NULL, name TEXT NOT NULL, adapter_id UUID REFERENCES adapter_configs(id), operation JSONB NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed','skipped','rolled-back')), evidence JSONB NOT NULL DEFAULT '[]', provider_task_ref TEXT, error TEXT, started_at/finished_at TIMESTAMPTZ)` — finally persisting the `EvidenceItem`s that today live only in in-memory `Request.stages`.
- **Engine changes** (`sources/ryuki-engine/src/request_lifecycle.rs`, staying pure):
  - `plan_execution(request) -> ExecutionPlan` — new pure function producing the ordered step list (operations + expected post-conditions + inverse operations) from the request type; this is what the worker executes.
  - `execute_request()` is re-scoped to a pure transition `Locked → Executing` that *requires a job id* in metadata; stage completion no longer happens here.
  - `verify_request(request, observed: &PostExecutionState) -> Result<Vec<EvidenceItem>, VerificationFailure>` — takes real observed state (post-change inventory snapshot + step outcomes) and *can fail*; the unconditional `(simulated)` items remain only for `mode = 'static-dry-run'`.
  - `rollback_request(request, reason)` — new transition `Executing/Verifying/Failed → RolledBack`, honoring the `rollback_notes` field already present at `models.rs:552`; `transition_status()`'s `valid_transitions` table (lines 483-492) gains `Executing → Failed`, `Verifying → Failed`, `Failed → RolledBack`.
- **API changes** (`sources/ryuki-api`):
  - `POST /api/requests/{id}/execute` now inserts an `execution_jobs` row (mode resolved from global execution mode + adapter flags) and returns **202** `{ job_id }` instead of completing inline.
  - New: `GET /api/requests/{id}/execution-job` (job + steps + evidence), `POST /api/requests/{id}/rollback`, `POST /api/execution-jobs/{id}/cancel`.
  - **Worker**: a tokio task spawned in `sources/ryuki-api/src/main.rs` polling `execution_jobs` with `SELECT ... FOR UPDATE SKIP LOCKED` (outbox pattern; safe for multiple API replicas), executing steps via the `ryuki-adapters` dispatcher, persisting evidence per step, then capturing post-state and calling `verify_request` to drive `Verifying → Completed` or `→ Failed`.
- **Portal UI**: `portal/portal-ui/src/views/request_detail.rs` gains a job/step progress panel (step list with status, timestamps, per-step evidence, failure reason, rollback button), polling the job endpoint via the existing same-origin server-function boundary.
- **Safety/dry-run**: dry-run jobs run through the identical pipeline (queue, steps, evidence, verify) using `static_dry_run()` adapters — so the governance trail is byte-for-byte comparable between modes; `started_at == completed_at` instant completion disappears in both modes.

#### 5. Inventory & telemetry ingestion: plans computed over real state

- **Goal**: stop planning/approving against hardcoded fiction (`vm_operations.rs:40-70` cpu=4/mem=16GB on `esx-host-01`; `patch_engine.rs:56-61` fixed window; `aiops.rs:90-160` static suggestions; `cost_capacity.rs:119-155` + `migrations/021_cost_capacity.sql:58-64` seeded fictional VMs).
- **Data model** — new migration `migrations/046_inventory_state.sql`: `inventory_items(id UUID PK, source_adapter_id UUID REFERENCES adapter_configs(id), external_id TEXT, name TEXT, item_type TEXT, owner TEXT, site TEXT, environment TEXT, criticality TEXT, state JSONB NOT NULL DEFAULT '{}', last_synced TIMESTAMPTZ, stale BOOLEAN NOT NULL DEFAULT TRUE, UNIQUE(source_adapter_id, external_id))` and `metric_samples(id UUID PK, item_id UUID REFERENCES inventory_items(id), metric TEXT, value DOUBLE PRECISION, sampled_at TIMESTAMPTZ)`.
- **Engine changes**: `inventory_sync.rs` drops `mock_inventory_for_source()` as the only path — it becomes a pure reconciler `reconcile_inventory(existing, fetched) -> InventoryDelta`; `plan_vm_day2_change` takes `current_state: &CiState` as a parameter resolved from `inventory_items` by the API instead of hardcoding; staleness marking (already a concept: `stale` flags exist on `InventoryItem`/`AdapterConfig`) drives a validation error when planning against stale CIs.
- **API endpoints**: `POST /api/integrations/{provider}/sync` (trigger adapter pull, runs `sync_inventory()` through the worker), `POST /api/ingest/inventory` and `POST /api/ingest/metrics` (push-based webhook ingestion for Zabbix/Prometheus-style sources, token-authenticated), `GET /api/inventory/items?site=&environment=`.
- **Portal UI**: dashboard inventory tiles read from real rows; stale CIs render the existing stale-data-marker treatment promised by the catalog's `safeCapabilities`.
- **Safety/dry-run**: demo seeds in `migrations/021_cost_capacity.sql` and `035_aiops.sql` move behind a dev-only seed script (they currently INSERT fictional VMs into every environment, including what would be production).

#### 6. ServiceNow live round-trip

- **Goal**: make the queue in `servicenow_api.rs:255-370` actually transmit; `migrations/034_servicenow_queue.sql` already has the right shape (`external_ref`, `status IN ('Draft','Ready','Pending','Submitted','Failed')`, `submitted_at`).
- **Engine/adapter changes**: a real ServiceNow Table API client in `sources/ryuki-adapters/src/servicenow.rs` (create incident/change/request, read sys_id/number back); `servicenow_api.rs` keeps validation/shaping logic pure but its submission worker (in the API, alongside the execution worker) drains `servicenow_queue` rows in `Ready`, transmits, writes back `external_ref` and `Submitted`/`Failed`, and reconciles status on a poll interval. CMDB publication (the Publish roadmap stage) reuses the same client against `cmdb_ci` tables later.
- **API endpoints**: `POST /api/itsm/queue/{id}/submit` (manual), `GET /api/itsm/queue` (status board); the worker handles automatic submission for approved requests.
- **Portal UI**: queue/status view showing local id ↔ `external_ref` linkage.
- **Safety/dry-run**: when the servicenow adapter is not live-enabled, submission keeps today's behavior (status `Pending`, explicit "live submission disabled" note) — the current strings become the genuine dry-run branch rather than the only branch.

#### 7. Execution mode as real runtime configuration

- **Goal**: kill the decorative env vars and compile-time constants; one authoritative mode surfaced consistently.
- **Changes**: add `ExecutionMode { StaticDryRun, LiveApproved }` to `sources/ryuki-core/src/config.rs`, parsed from `RYUKI_API_EXECUTION_MODE` (making the already-baked Dockerfile ENV real); expose it in the API boundary/status endpoint; delete `pub const WORKSPACE_EXECUTION_MODE` from `portal/portal-ui/src/workspace_catalog.rs:14` and source the value from `server_boundary.rs`'s existing `execution_mode` field (already plumbed at lines 263-437). Parameterize both Dockerfiles (`ARG RYUKI_EXECUTION_MODE=static-dry-run`) — the default image remains a non-executing artifact; `platform-config.json` gets an environment-overlay story.
- **Effective mode** is the AND of: global `ExecutionMode::LiveApproved` + per-adapter `provider_calls_enabled` + resolvable secret — matching `catalog/adapter-readiness-catalog.yaml`'s `blockedReasons` chain, and explicitly *not* `RYUKI_AUTH_MODE` (which gates auth only).

#### 8. Validator & docs alignment

- **Validator** (`scripts/validator-rs/src/`): keep `ryuki_engine.rs` purity policy intact — the engine *stays* I/O-free, so `PROHIBITED_IMPORTS` survives unchanged, which is the cleanest property of this design. The required-pattern checks for `static_dry_run`/`DRY-RUN` (lines 242-259) stay valid because dry-run constructors remain mandatory. Add a new `ryuki_adapters.rs` validator module: every adapter must expose *both* `static_dry_run()` and `live()`; `live()` must take a secret by reference type (no string credentials); no `*.example.invalid` endpoint may be accepted by `live()`; no `println!`/`tracing` of secret material; every `execute()` must return `OperationOutcome` with at least one `EvidenceItem`. Wire it into `scripts/validator-rs/src/main.rs` context plumbing (the same file-read mechanism at 3457-3859).
- **Docs**: fix `docs/architecture.md:56` (auth mode does not unlock provider calls), `docs/configuration.md:54` (document the real unlock chain), reword `docs/index.html:972` and `:1361` and the `README.md:76` network-policy row to tense-accurate dry-run posture until live ships, then document: secret reference → health check → verified-admin approval → `provider_calls_enabled` → live job mode.

### Implementation plan

1. **(S)** Execution-mode config: `ExecutionMode` in `ryuki-core/src/config.rs`, read `RYUKI_API_EXECUTION_MODE`, surface in boundary status, replace the portal const with the `server_boundary.rs` value, parameterize Dockerfiles. Docs corrections (architecture.md:56, configuration.md:54, index.html:972/1361, README.md:76).
2. **(M)** Migration `044_adapter_registry.sql` + DB-backed `/api/integrations/adapters` CRUD/list endpoints (verified-admin gated) + extend `ReadinessState` and `adapter-readiness-catalog.yaml` (add `ready-live`, model all 17 adapters).
3. **(M)** Portal `views/integrations.rs`: adapter list, readiness badges, health-check trigger, enable/disable-live flow with blockedReasons checklist.
4. **(L)** `sources/ryuki-adapters` crate scaffold: workspace membership, async `ProviderAdapter` trait, `Operation`/`OperationOutcome` model, `AdapterDispatch`, `static_dry_run()` parity for all 17, validator module `ryuki_adapters.rs` + main.rs wiring. No live client yet — this lands the seam.
5. **(M)** Secrets layer: `SecretResolver` + `vaultrs` KV v2 implementation, `secret_ref` resolution, real `GET /api/platform/secrets/health`, `health_monitor.rs::check_vault_health` converted to pure evaluator, loud failure for unimplemented providers.
6. **(L)** Execution jobs: migration `045_execution_jobs.sql`, `plan_execution`/reworked `execute_request`/failable `verify_request`/`rollback_request` in `request_lifecycle.rs`, transition-table updates, outbox worker in `ryuki-api/src/main.rs`, 202-returning `POST /api/requests/{id}/execute`, job/rollback/cancel endpoints, request_detail.rs progress UI. Dry-run jobs only at this stage — proves the pipeline before any live call.
7. **(L)** First live adapters, smallest blast radius first: Zabbix (read + ack), Prometheus (read-only), then VMware vCenter (the flagship: health, inventory sync, VM day-2 reconfigure with rollback), then Veeam. Health-check + `enable-live` end-to-end; `ready-live` readiness surfaced.
8. **(M)** Inventory/telemetry: migration `046_inventory_state.sql`, sync-through-worker, `POST /api/ingest/*` routes, rewire `vm_operations.rs`/`patch_engine.rs` to consume `inventory_items` state, gate `021`/`035` demo seeds to dev-only.
9. **(M)** ServiceNow round-trip: Table API client, submission worker over `servicenow_queue`, `external_ref` reconciliation, ITSM queue view.
10. **(M)** Remaining adapters (Hyper-V, Proxmox, Nutanix, backup/monitoring long tail) behind the now-proven seam; `aiops.rs`/`cost_capacity.rs` rewired to real metric samples.

### Risks & open questions

- **Dyn-async ergonomics**: async fns in traits are not dyn-compatible in Rust 2024; the design uses enum dispatch (`AdapterDispatch`) over 17 variants, which is verbose but avoids `async_trait` boxing in the hot path. Decide before step 4 — changing later cascades through every impl.
- **Hyper-V and KVM have no clean HTTPS API**: Hyper-V realistically needs WinRM/PowerShell remoting and KVM needs libvirt — both pull in significantly heavier dependencies than reqwest. Open question: gateway/agent pattern (a small executor near the hypervisor) vs. direct protocol support; affects whether `ryuki-adapters` stays a single crate.
- **Worker topology**: a tokio task inside `ryuki-api` is the smallest step (matches "Axum state + extractors, no global mutable state"), but couples API availability to execution. `FOR UPDATE SKIP LOCKED` makes multi-replica safe, yet long-running provider tasks (storage vMotion, patch waves) may exceed pod lifecycles — execution_steps must be resumable/idempotent (provider task refs + reconcile-on-restart), which is real design work in step 6.
- **Verification semantics per request type**: `verify_request` taking observed state requires per-operation post-condition definitions (what does "verified" mean for a snapshot vs. a patch wave?). The `ExecutionPlan` carries expected post-conditions, but defining them for all 58 engines is a long tail; scope step 6 to the request types the first live adapters serve.
- **Validator policy churn**: scripts/validator-rs asserts exact source patterns (e.g. `impl {Adapter} {\n    pub fn static_dry_run`); refactoring adapter_framework.rs while keeping CI green requires updating validator and engine in the same change — sequence step 4 as one atomic PR.
- **Rollback honesty**: not every operation is reversible (deletions, patches). The model needs an explicit `irreversible` flag per step so the portal can show "rollback unavailable" instead of implying safety that does not exist — consistent with the project's evidence-first ethos.
- **Open question — secret_ref for DB credentials**: README claims secrets are "never in environment", but `RYUKI_DATABASE_URL` is env-sourced. Decide whether to extend Vault sourcing to the DB DSN (bootstrap-order complexity) or amend the docs to scope the Vault claim to adapter credentials only.
- **Open question — catalog as source of truth**: once `adapter_configs` is DB-backed, `catalog/adapter-readiness-catalog.yaml` becomes seed/contract documentation. Define the reconciliation rule (catalog seeds on first boot; DB wins thereafter) so the two cannot drift silently.

---

## Authentication & authorization completion

Ryuki currently has the *shape* of an authentication system but not the substance: the documented Entra ID SSO flow terminates in a stub that discards its token, every one of the 383 GET routes is served without any credential check, the mock login mints persisted `PlatformAdmin` sessions for anonymous callers, the portal hardcodes `is_authenticated() = true`, and role-based enforcement exists on roughly 6 of 226 mutating endpoints. There is no credential mechanism for machine callers at all. For a governed control plane whose value proposition is approval-gated, evidence-first execution against datacenter infrastructure, this is the single largest credibility gap: none of the lifecycle gates (Approved, Locked, Executing) mean anything if any unauthenticated caller can mint an admin session, and none of the read surfaces (secrets inventory metadata, gMSA inventory, emergency change history, platform settings) are protected.

### Current state

- **Token validation is a no-op.** `validate_token(_token)` in `sources/ryuki-engine/src/auth.rs:215-217` ignores its argument and returns `AuthSession::unverified_entra()` (zero roles, `token_valid = false`). No JWT/OIDC/JWKS crate or HTTP client exists in the dependency tree (`Cargo.lock` has no `jsonwebtoken`, `openidconnect`, or `reqwest`). In `EntraId` mode, `auth_session_for_request` (`sources/ryuki-api/src/main.rs:69-78`) routes every bearer token through this stub, so a real signed Entra token can never produce a verified session. The 141-line `docs/entra-app-registration.md` manifest, plus README and `docs/configuration.md` SSO sections, document a flow the code cannot honor.
- **GET is never authenticated.** `auth_middleware` (`sources/ryuki-api/src/main.rs:169-208`) only rejects when `is_unsafe_method` (POST/PUT/PATCH/DELETE, `main.rs:154-159`) and the session fails `auth_session_allows_unsafe_method`. All 383 GET routes registered in `sources/ryuki-api/src/contracts.rs` are anonymous, including `/api/admin/platform-settings`, gMSA and secrets inventory, and evidence export.
- **Anonymous admin minting.** `auth_login` (`sources/ryuki-api/src/contracts.rs:6100-6140`) is auth-exempt (`main.rs:161-163`) and, in mock mode or whenever `entra_tenant_id` is empty, inserts a session row carrying `PlatformAdmin` + `VMwareOperator` (`static_login_roles()`, `contracts.rs:6093-6098`) into the `sessions` table (`migrations/004_sessions.sql`) for any caller. `auth_session_from_persisted_session` (`main.rs:129-152`) then treats that UUID as a fully verified session.
- **RBAC enforcement is nearly absent.** `check_permission` is called at exactly five sites (`contracts.rs:6538, 7274, 7323, 7370, 7417` — admin settings, approve, lock/execute/verify). The other ~220 mutating handlers (e.g. `ad_delete`, `secrets_rotate_all`, `emergency_execute`, `dns_record_delete`) pass with any verified-or-static session via `AuthExtractor` (`contracts.rs:6843-6876`).
- **RBAC is static and unadministrable.** `get_rbac_roles()` (`sources/ryuki-engine/src/auth.rs:88-157`) returns a fixed 12-role list with a 5-word permission vocabulary (`admin/approve/execute/audit/request`). No `users`/`principals` or `role_assignments` table exists in any of the 42 migrations; sessions denormalize roles as `TEXT[]`. The only RBAC route is read-only `GET /api/admin/rbac-roles` (`contracts.rs:1120`); `admin_approval_groups`/`admin_delegation_boundary` (`contracts.rs:6006-6016`) are static JSON that self-declare `roleAssignmentMutationAllowed: false`. No site/environment scoping exists despite multi-site being the core premise (the richer scoped model in `auth_local_roles`, `contracts.rs:6018-6022`, is decorative JSON).
- **No machine credentials, no session admin.** The only credential is the browser-session UUID; there are no API token / service-account routes and no `api_tokens` table. `auth_logout` (`contracts.rs:6142-6177`) deletes only the caller-supplied session id; there is no list/revoke capability.
- **Portal bypass.** `portal/portal-ui/src/shell.rs:8-10` hardcodes `is_authenticated() = true`, so the `LoginView` gate in `app.rs:31,40` is dead code. `perform_login`/`perform_logout` (`portal/portal-ui/src/server_boundary.rs:1097-1131`) return mock data without calling the API; `perform_logout` has no view caller. `auth_session_fallback()` (`portal/portal-ui/src/models.rs:758-764`) grants `PlatformAdmin`, and `role_satisfies` (`portal/portal-ui/src/workspace_catalog.rs:39-53`) short-circuits on it. The Admin panel renders static "Roles are managed in Entra ID" text (`views/workspaces.rs:1549`).
- **Circular onboarding.** `views/login.rs:29-88` shows the Entra button only if `entra_tenant_id` is set, but `platform_settings_summary_fallback()` (`models.rs:849-857`) hardcodes it empty, and `save_platform_settings` (`server_boundary.rs:1055-1066`) always returns the static-preview rejection — while the API-side `PUT /api/admin/platform-settings` requires a verified external admin (`require_verified_external_admin_permission`, `contracts.rs:6548-6562`) that the stubbed validator can never produce.
- **Rate limiting keys on spoofable input.** `rate_limit_middleware` (`main.rs:411-449`) keys on client-supplied `X-Forwarded-For`, falling back to a shared `"unknown"` bucket.

### Design

#### 1. Real Entra ID token validation (OIDC + JWKS)

- **Goal:** A signed Entra access token produces a verified `AuthSession` with the roles claim; everything else is rejected. This unblocks every downstream gate including `require_verified_external_admin_permission`.
- **Data model:** none required for validation. Issuer/audience derive from existing `platform_config` keys (`entra_tenant_id`, `entra_client_id`, `entra_authority`) already round-tripped by `apply_platform_config_entry`/`platform_config_entries` (`contracts.rs:6564-6691`).
- **Engine changes (`sources/ryuki-engine/src/auth.rs`):** add `jsonwebtoken` and `reqwest` (rustls) to `ryuki-engine`. New `EntraTokenValidator` struct holding `EntraConfig` plus a cached JWKS keyset (fetched from `{instance}/{tenant_id}/discovery/v2.0/keys`, refreshed on unknown `kid` with a cooldown, ~24h TTL). `validate_token` becomes `async fn validate_token(&self, token: &str) -> AuthSession`: verify signature (RS256), `iss` (`{instance}/{tenant_id}/v2.0`), `aud` (`entra_client_id` or `api://{client_id}`), `exp`/`nbf` with small leeway; extract `roles`, `oid`/`sub`, `name`, `preferred_username`. On success return `token_valid: true`, `provider_mode: "entra-id"`; on any failure return the existing `unverified_entra()` (preserving the rejection contract the `test_validate_token_rejects_unsigned_roles_claim` test encodes — extend tests with a locally-generated RSA keypair signing valid/expired/wrong-aud tokens against an injected keyset).
- **API changes (`sources/ryuki-api/src/main.rs`):** `auth_session_for_request` becomes async; `auth_middleware` already is. Construct the validator once in app state (Axum state per repo convention, no global mutable state) from `config_store::get_app_config()` and rebuild on settings change. Keep the existing safe-logging rule (`resolve_auth_metadata`): never log token contents.
- **Portal UI:** none in this feature (consumed by feature 6).
- **Validation & evidence:** log a structured auth event (presence, mode, validation outcome, never the token) per request; the existing `auth middleware` tracing line gains `token_valid` and failure-reason fields.
- **Safety/dry-run:** mock/static/local modes are unchanged; only the `EntraId` arm changes behavior. JWKS fetch failures fail closed (unverified session).

#### 2. Authenticate reads — close the 383-route GET hole

- **Goal:** No endpoint is reachable without a session; reads require at least `audit`-tier access.
- **Engine changes:** none beyond feature 1; the `Auditor → audit` mapping (`auth.rs:142-145`) already provides the read permission concept.
- **API changes (`main.rs`):** drop the `is_unsafe_method` precondition in `auth_middleware`. New gate: every non-exempt request requires a session passing `auth_session_allows_unsafe_method` (rename to `auth_session_is_authenticated`); unsafe methods additionally pass through the per-route permission map of feature 4. Expand `is_auth_exempt_path` to exactly: `/api/auth/login`, `/api/auth/logout`, `/api/auth/status` (the portal needs it pre-login to render the SSO button), `/health`-style liveness, and the OIDC callback added in feature 6.
- **Portal UI:** the portal's server functions must attach the session credential (cookie-forwarded session id header) on every API call — covered in feature 6.
- **Validation & evidence:** add an integration test asserting a credential-less `GET /api/admin/platform-settings` and `GET /api/protect/secrets/...` return 401; add a route-coverage test that walks the `Router` and fails if any non-exempt route is reachable anonymously.
- **Safety/dry-run:** in mock/static modes `auth_session_for_request` still yields `static_dry_run()`, so local dev and the static demo keep working without behavior change; the gate only bites in `EntraId`/persisted-session mode. This is deliberate: dry-run remains zero-friction, production fails closed.

#### 3. API tokens, service accounts, and session administration

- **Goal:** Non-interactive callers (CI/CD, validators, ServiceNow integration) get scoped, revocable credentials; admins can see and revoke live sessions.
- **Data model:** new migration `migrations/044_api_tokens.sql`:
  - `api_tokens(id UUID PK, name TEXT NOT NULL, owner_principal TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, roles TEXT[] NOT NULL DEFAULT '{}', site_scope TEXT, environment_scope TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ)`.
  - Token format `ryk_<base62 random 32 bytes>`; store only an HMAC-SHA256/argon2 hash, show plaintext once at creation (never persisted — repo rule: never commit secrets extends to never store them).
- **Engine changes (`ryuki-engine/auth.rs`):** `AuthSession` gains `provider_mode: "api-token"`; token rows resolve to sessions with the row's roles/scopes.
- **API endpoints (`contracts.rs::routes()`):**
  - `POST /api/admin/tokens` (create, admin-gated, returns plaintext once), `GET /api/admin/tokens` (list, hash redacted), `DELETE /api/admin/tokens/{id}` (sets `revoked_at`).
  - `GET /api/admin/sessions` and `DELETE /api/admin/sessions/{id}` over the existing `sessions` table (admin-gated), fixing the "logout-self-only" gap in `auth_logout`.
  - `auth_session_from_persisted_session` (`main.rs:129-152`) branches: bearer values starting `ryk_` are hashed and looked up in `api_tokens` (checking `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`, updating `last_used_at`); UUID values keep the sessions path.
- **Portal UI:** token management panel in the Admin workspace (`portal/portal-ui/src/views/workspaces.rs`): list, create (one-time secret display), revoke; sessions list with revoke.
- **Validation & evidence:** token create/revoke and session revoke write audit log entries (actor, token name, scopes — never the secret). `scripts/validator-rs` gains a check that no migration or fixture contains a `ryk_` literal.
- **Safety/dry-run:** token creation is allowed in dry-run (it mutates only platform state, not infrastructure), but tokens minted in dry-run mode carry `token_valid: false` semantics equivalent to static sessions so they can never satisfy `require_verified_external_admin_permission`.

#### 4. Route-level RBAC enforcement on all mutating endpoints

- **Goal:** Every one of the 226 POST/PUT/DELETE routes is gated by an explicit permission, not "any session".
- **Data model:** none (enforcement only; scoping uses feature 5's tables when present).
- **Engine changes (`ryuki-engine/auth.rs`):** extend the permission vocabulary from `admin/approve/execute/audit/request` to domain-qualified strings — `execute:virtualization`, `execute:backup`, `execute:monitoring`, `execute:os`, `execute:network`, `execute:identity`, `admin:platform`, `admin:emergency`, plus the existing coarse verbs as unions. Map them onto the existing 12 roles consistent with the `executionDomains` already declared in `auth_local_roles` (e.g. `BackupOperator → execute:backup`, `BreakGlassAdmin → admin:emergency`). `check_permission` keeps its signature; a domain permission is satisfied by the matching role or `PlatformAdmin`.
- **API changes (`contracts.rs`):** introduce a static `ROUTE_PERMISSIONS: &[(&Method-ish, &str path-prefix, &str permission)]` table applied centrally in `auth_middleware` after session resolution — a single enforcement point beats editing ~220 handlers and cannot drift when new routes are added. Prefix mapping follows the existing URL taxonomy: `/api/identity/* → execute:identity`, `/api/protect/secrets/* → execute:backup`-adjacent (`admin:platform` for `rotate-all`), `/api/ops/emergency/* → admin:emergency`, `/api/network/* → execute:network`, `/api/requests/{id}/approve → approve` (handler-level `check_permission` calls at `contracts.rs:7274-7417` remain as defense in depth). Routes not matched by the table default to `admin:platform` (fail closed, not open). A unit test enumerates the router and asserts every mutating route resolves to a permission.
- **Portal UI:** none required; the portal already models `required_role` per workspace (`workspace_catalog.rs:36`) and will align labels with the new vocabulary.
- **Validation & evidence:** 403 responses use the existing `ApiError` ProblemDetails shape with the missing permission named; denied attempts are logged with actor + route + permission.
- **Safety/dry-run:** static-dry-run sessions carry `PlatformAdmin` today and would pass everything; keep that for the demo, but add a `RYUKI_DRY_RUN_ROLES` override (config, not env-only) so role behavior is testable locally.

#### 5. DB-backed RBAC administration with site/environment scoping

- **Goal:** Principals and role assignments become data, administrable through governed endpoints, scoped to sites/environments — replacing the hardcoded 12-role `Vec` as the source of assignment truth (role *definitions* stay code-defined; *assignments* move to the DB).
- **Data model:** new migration `migrations/045_principals_role_assignments.sql`:
  - `principals(id UUID PK, external_id TEXT UNIQUE NOT NULL /* Entra oid or token owner */, display_name TEXT NOT NULL, email TEXT, kind TEXT NOT NULL CHECK (kind IN ('user','service')), status TEXT NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`
  - `role_assignments(id UUID PK, principal_id UUID NOT NULL REFERENCES principals(id), role TEXT NOT NULL, site_scope TEXT /* NULL = all sites */, environment_scope TEXT, granted_by TEXT NOT NULL, granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ)`
- **Engine changes:** `AuthSession` gains `scopes: Vec<RoleScope>`; `check_permission` gains an optional `scope: Option<(&str /*site*/, &str /*env*/)>` argument used by handlers that know their target site (request lifecycle handlers already carry site context). Effective roles = intersection of token-asserted Entra roles and active DB assignments when assignments exist for the principal; Entra-only roles remain valid for tenants that manage everything in Entra (configurable `rbac_assignment_mode: entra-only | db-scoped` in `platform_config`).
- **API endpoints:** `GET/POST /api/admin/principals`, `GET /api/admin/principals/{id}`, `POST /api/admin/principals/{id}/assignments`, `DELETE /api/admin/assignments/{id}` (revoke, sets `revoked_at` — never hard-delete, evidence-first). All gated `admin:platform`. `admin_approval_groups`/`admin_delegation_boundary` summaries start reporting real counts instead of static `roleAssignmentMutationAllowed:false`.
- **Portal UI:** replace the static "Roles are managed in Entra ID" panel (`views/workspaces.rs:1549`) and `rbac_role_summary_fallbacks` (`models.rs:773-838`) with live data: principal list, assignment grant/revoke with site/env scope pickers and expiry. Remove the `PlatformAdmin` short-circuit in `role_satisfies` (`workspace_catalog.rs:49-51`) in favor of permission strings from the session, and delete `auth_session_fallback()`'s hardcoded `PlatformAdmin` (`models.rs:758-764`).
- **Validation & evidence:** assignment grant/revoke produce audit entries (grantor, grantee, role, scope, expiry); a recurring access-review hook can reuse the existing `access_reviews` table (`migrations/030_access_reviews.sql`).
- **Safety/dry-run:** assignment mutations are platform-state writes and permitted in dry-run, but flagged `source: dry-run` in evidence; expiry defaults (e.g. 180 days) enforced unless explicitly overridden.

#### 6. Real portal authentication: login, session cookie, logout, 401 handling

- **Goal:** The portal actually authenticates: unauthenticated visitors see `LoginView`, login round-trips to the API, sessions expire, logout works.
- **Data model:** none (uses `sessions`).
- **Portal changes (`portal/portal-ui`):**
  - `shell.rs::is_authenticated()` stops returning `true`; it becomes a server-checked signal: a Leptos server function `get_auth_session()` reads the production `__Host-ryuki_session` HttpOnly+Secure+SameSite=Lax cookie (with unprefixed `ryuki_session` compatibility only for explicit non-Secure loopback development), validates it against `GET /api/auth/session`, and returns the real session or `None`. `app.rs`'s existing `if authenticated { Shell } else { LoginView }` gate then works as designed.
  - `server_boundary.rs::perform_login` calls `POST /api/auth/login` (mock modes) or, for Entra, initiates the auth-code+PKCE redirect to `{authority}/{tenant}/oauth2/v2.0/authorize`; a new portal route `/auth/callback` exchanges the code server-side, calls the API to persist the session, and sets the cookie. `perform_logout` calls `POST /api/auth/logout`, clears the cookie, and is wired to a sign-out control in the shell header (it currently has no caller).
  - All portal server functions forward the session id to the API via `X-Ryuki-Session-Id` (already accepted by `session_id_from_headers`, `main.rs:111-127`). Any 401 from the API clears local state and redirects to `LoginView`.
- **API changes:** add the OIDC callback exchange endpoint or keep exchange entirely portal-side (preferred: portal SSR exchanges the code, then calls a new `POST /api/auth/sessions/from-token` carrying the validated bearer, which persists a session bound to the verified claims — reusing feature 1's validator).
- **Validation & evidence:** login/logout events logged with principal and provider mode; session rows already carry `expires_at` (24h default) — honor it in the cookie.
- **Safety/dry-run:** in mock/static modes the login button performs the existing mock flow but now actually round-trips to `POST /api/auth/login` so portal and API agree on the session; the "Static dry-run preview" banner remains.

#### 7. Break the onboarding circle: bootstrap path for configuring SSO

- **Goal:** A fresh install can reach a configured-SSO state through a governed path, without the current deadlock (settings save requires verified external admin; verified admin requires SSO; SSO requires settings save).
- **Design:** first-run bootstrap mode: when `auth_mode != entra-id` **and** no verified-admin principal exists, `PUT /api/admin/platform-settings` accepts a local-mode admin session (relax `require_verified_external_admin_permission` to `require_admin_permission` only under this detectable bootstrap condition, and record a `bootstrap-mode-settings-write` audit event). Once `auth_mode` flips to `entra-id` and a first verified admin has logged in, the relaxation closes permanently. Portal side: `save_platform_settings`/`reset_platform_settings` (`server_boundary.rs:1037-1077`) stop returning the unconditional static-preview rejection and proxy to the API (the API already upserts `platform_config`, `contracts.rs:6744-6764`); the preview rejection remains only when the portal is built in static-demo mode. `platform_settings_summary_fallback` is replaced by a real `GET /api/admin/platform-settings` fetch so `views/login.rs` gating reflects actual config.
- **Validation & evidence:** bootstrap writes are loudly audited and surfaced on the Admin dashboard until SSO is verified end-to-end ("Setup incomplete" banner mirroring the existing `auth_status` endpoint fields).
- **Safety/dry-run:** alternatively/additionally support config-file + env bootstrap (already exists via `config_store`) as the documented headless path; the portal flow is a convenience, not the only door.

#### 8. Trustworthy rate-limit client identity

- **Goal:** Per-client limits that cannot be evaded by header forgery and do not collapse all direct clients into one bucket.
- **API changes (`main.rs:411-457`):** serve the router with `into_make_service_with_connect_info::<SocketAddr>()`; `rate_limit_middleware` keys on `ConnectInfo<SocketAddr>` by default. Add `trusted_proxies: Vec<IpAddr/CIDR>` to the rate-limit config in `ryuki-core` (`RateLimitConfig`); only when the peer is a trusted proxy, take the rightmost non-trusted entry of `X-Forwarded-For`. Remove the `"unknown"` fallback. After feature 3, authenticated callers can be keyed by principal/token id instead of IP for fairer limits.
- **Validation & evidence:** unit tests for forged-header scenarios; the existing `rate limit exceeded` warn log gains the resolved key source (`peer` vs `forwarded`).
- **Safety/dry-run:** behavior identical in all modes; this is pure transport hygiene.

### Implementation plan

1. **(S)** Feature 8 — `ConnectInfo`-based rate-limit keying with trusted-proxy config. Self-contained, no auth dependencies, immediate hardening.
2. **(M)** Feature 1 — `EntraTokenValidator` in `ryuki-engine` (jsonwebtoken + reqwest JWKS cache), async `auth_session_for_request`, signed-token test fixtures. This is the keystone every other feature leans on.
3. **(S)** Feature 2 — flip `auth_middleware` to authenticate all methods; tighten `is_auth_exempt_path`; add the anonymous-401 integration tests. Do this immediately after 1 so EntraId deployments aren't locked out of reads.
4. **(M)** Feature 3 — `migrations/044_api_tokens.sql`, token hash verify path in `auth_session_from_persisted_session`, `/api/admin/tokens` + `/api/admin/sessions` routes, portal token panel.
5. **(M)** Feature 4 — domain-qualified permission vocabulary in `ryuki-engine/auth.rs`, central `ROUTE_PERMISSIONS` table in `auth_middleware`, fail-closed default, router-coverage test.
6. **(L)** Feature 5 — `migrations/045_principals_role_assignments.sql`, scoped `check_permission`, principal/assignment CRUD routes, portal RBAC administration UI, removal of portal `PlatformAdmin` short-circuits.
7. **(L)** Feature 6 — portal login/logout/cookie/401 flow, OIDC code exchange, session forwarding on all portal server functions, wire `perform_logout` to the shell.
8. **(S)** Feature 7 — bootstrap-mode settings write + portal settings save proxy, closing the onboarding circle.
9. **(S)** Docs pass — update `docs/entra-app-registration.md`, `docs/getting-started.md`, `docs/configuration.md`, and README auth sections to match the now-real flow; document token issuance for machine callers.

Sequencing rationale: 1→2 establishes "nothing is anonymous"; 3→4 establishes "every write needs the right role, machines included"; 5→6 makes it administrable and visible; 7 makes it installable.

### Risks & open questions

- **Breaking the static demo.** The GitHub Pages/static dry-run experience depends on permissive defaults (`static_dry_run()` sessions, mock login). Every gate must branch on `AuthMode` so demo friction stays zero — the route-coverage and 401 tests should run in both modes to prevent regressions in either direction.
- **`auth_login`'s anonymous-admin behavior in mock mode** is arguably intentional for dev but is a footgun if a production deploy leaves `entra_tenant_id` empty: the current condition (`contracts.rs:6102`) falls back to minting admin sessions. Decision needed: refuse mock login when `auth_mode == entra-id` regardless of tenant config (recommended), and emit a startup warning when running non-Entra mode bound to a non-loopback address.
- **Permission vocabulary granularity.** Domain-qualified strings (feature 4) versus full resource-action pairs: the 58 engines could justify finer grain, but the 12-role model caps useful granularity. Starting with ~10 domain permissions mirroring `executionDomains` keeps the mapping reviewable; revisit only if real tenants need custom roles.
- **Entra roles vs DB assignments precedence** (feature 5): intersection is safest but means an Entra-only tenant must seed principals; the proposed `rbac_assignment_mode` config handles this, but the default needs a decision (recommend `entra-only` default for backward compatibility with the documented app-registration manifest).
- **JWKS availability.** Failing closed on JWKS fetch errors is correct but means an Entra/network outage locks out the control plane — exactly when operators may need it. `BreakGlassAdmin` exists as a role but has no credential path that survives IdP outage; a sealed local break-glass credential (single-use, heavily audited) is a likely follow-up requirement and should be designed alongside feature 3.
- **Session fixation / cookie scope** for the portal: portal SSR and API may be deployed on different origins; the `X-Ryuki-Session-Id` forwarding pattern works server-side, but CSRF posture for the portal's own `/portal/api` server functions needs review once cookies carry real authority.
- **Migration numbering contention:** 044/045 assume no concurrent migrations land first; renumber at implementation time.
- **`get_untrusted_roles_from_token` is currently `#[cfg(test)]`** — feature 1 must not promote it into any production path; roles must only ever be read from a signature-verified claim set.

---

## Durable persistence & data model wiring

Ryuki ships 42 migrations (numbered to 043) creating 64 tables, but the running system persists almost nothing: application SQL touches only `requests`, `sessions`, and `platform_config`. Every other table is dead schema, and all 58 domain engines keep their state in process-local `OnceLock`/`LazyLock<Mutex<...>>` statics (47 stores across 40 modules) seeded with demo data — patch waves, legal holds, runbook executions, site activations, secrets rotations all evaporate on restart and silently diverge under more than one replica. Worse, the one table that *is* used (`requests`) is VM-shaped (`cpu`/`memory_gb` columns, no payload, no stages) and cannot faithfully represent 13 of the 14 accepted request types; on read-back the API fabricates stage history and a fake `DRY-RUN:` plan-evidence string (`db_row_to_request`, contracts.rs:6975-7020). For a platform whose pitch is "evidence-first governed automation", state that cannot survive a pod restart is disqualifying. This theme wires the schema that exists to the code that runs, adds schema for the 13+ domains that have none, and makes the request lifecycle round-trip losslessly.

### Current state

- **DB plumbing exists and works**: `sources/ryuki-api/src/database.rs` builds a `PgPool` (`get_db()`, line 28), runs `sqlx::migrate!("../../migrations")` (line 70), and tracks migration status. But on connection failure it logs `"database unavailable, falling back to in-memory stores"` (line 95) and the API runs indefinitely without any DB.
- **Engine is DB-free by design**: `scripts/validator-rs/src/ryuki_engine.rs:79-87` lists `sqlx`, `PgPool`, `diesel`, `rusqlite` in `PROHIBITED_IMPORTS` for the engine crate, and `sources/ryuki-engine/Cargo.toml` has no sqlx. Persistence can only live in `ryuki-api` — and it never was wired beyond `requests`/`sessions`/`platform_config`.
- **In-memory stores everywhere**: e.g. `PATCH_WAVE_STORE` (`sources/ryuki-engine/src/patch_engine.rs:9-13`), seeded AIOps suggestions (`aiops.rs:74-81`), `SITE_STORE` (`site_registry.rs:787-788`), plus API-side fallbacks `REQUEST_STORE` (`contracts.rs:2418`) and `DECOMMISSION_STORE` (`contracts.rs:7836`) — the latter despite `decommission_requests` existing in `migrations/012_decommissions.sql`.
- **VM-shaped requests**: `migrations/003_requests.sql` has fixed `cpu`/`memory_gb INTEGER`, free-text `status`/`stage`, no JSONB payload/plan/validation/approval columns; no migration ever runs `ALTER TABLE`. `CreateRequest` (contracts.rs:2389-2397) accepts only cpu/memory/justification while `parse_request_type` (contracts.rs:6906-6927) accepts 14 types. `db_row_to_request` synthesizes empty `approval_route`, empty `metadata`, and a fabricated `"DRY-RUN: Planned execution..."` evidence item.
- **Sites**: no `sites` table; `site_registry.rs` mutates only memory in `activate_site`/`deactivate_site` (lines ~830/846); `const VALID_SITES = ["DEBER","DEFRA","FRPAR","GBLON","NLAMS"]` is duplicated in **16** engine modules (request_lifecycle.rs:6, vm_operations.rs:5, patch_engine.rs:7, backup_engine.rs:5, linux_deployment.rs:5, os_baseline.rs:6, legal_hold.rs:74, zabbix_drift.rs:8, log_forwarder.rs:4, maintenance_calendar.rs:9, ad_computer_lifecycle.rs:6, server_decommission.rs:5, software_deployment.rs:6, app_environment.rs:6, noise_remediation.rs:132, immutability_compliance.rs:73), so activating a new site in the registry changes nothing. `docs/site-management.md`'s claim of "zero site-specific data in the repository" is false.
- **Schema-less domains**: 13+ route surfaces with full lifecycles have no tables at all — DNS/IPAM (`dns_ipam.rs:83`), firewall rules (`firewall_rules.rs:126`), load balancer (`load_balancer.rs:105`), storage provisioning (`storage_provisioning.rs:156`), k8s namespaces (`container_namespace.rs:92`), DR plans/tests (contracts.rs:10721-10748), secrets rotation (`secrets_rotation.rs:97`), runbook execution (`runbook_execution.rs:66`), incidents, compliance frameworks/findings, evidence artifacts, inventory, and `/api/admin/sites/*` (contracts.rs:9551-9597).
- **Dead-on-arrival schema**: `failure_patterns` (`migrations/028_knowledge_suggestions.sql`, full status workflow + 4 seeded runbook articles) and `monitoring_review_queue` (`migrations/031_monitoring_queue.sql`, 4 indexes + 5 seeded rows) have zero consuming code — only static contract descriptors at contracts.rs:762-763 and 1011-1012.
- **No indexes on hot paths**: zero `CREATE INDEX` in migrations 003-013; `requests` is paginated `ORDER BY created_at DESC` (contracts.rs:7079) and every authenticated call hits `sessions WHERE id = $1 AND expires_at > NOW()` (main.rs:139) unindexed. Index discipline begins at `014_cmdb_impact.sql`.
- **Numbering oddity**: migration `002` never existed in any of the 161 commits; `sessions` (004) stores denormalized `user_id`/`display_name`/`roles` TEXT with no `users` table anywhere.

### Design

The architectural rule stays: **engines stay pure (validator-enforced), persistence lives in ryuki-api.** We introduce a repository layer in `sources/ryuki-api/src/repos/` and convert engines from "stateful module with hidden store" to "pure functions over passed-in state".

#### 1. Repository layer and engine state extraction

- **Goal**: every domain whose tables exist (≈25 domains: `010_patch_waves`, `011_certificates`, `006_snapshots`, `026_legal_holds`, `035_aiops`, `012_decommissions`, `017_maintenance_windows`, `030_access_reviews`, ...) reads/writes Postgres; engine statics become test-only or are deleted.
- **Data model**: no new tables for this feature — the point is consuming the 61 dead ones. One cleanup migration may normalize column drift found during wiring (e.g. enum CHECK constraints matching engine model variants).
- **Engine changes**: in each of the 40 stateful modules, replace `pub(crate) fn xxx_store()` accessors with pure signatures. Pattern, using patch_engine as the template: `plan_patch_wave_from_servers(&[Server]) -> Result<PatchWave, String>` already returns a value; functions that today mutate the store (e.g. approve/advance wave) become `fn approve_wave(wave: PatchWave, approver: &str) -> Result<PatchWave, String>`. The store statics are deleted (or moved behind `#[cfg(test)]`).
- **API**: new `sources/ryuki-api/src/repos/mod.rs` with one module per domain (`repos/patch_waves.rs`, `repos/snapshots.rs`, `repos/legal_holds.rs`, ...). Each exposes `list/get/insert/update` functions taking `&PgPool`, using `sqlx::query_as` with explicit row structs (same style as `DbRequestRow`, contracts.rs:2399). Handlers in `contracts.rs` follow the existing dual-path shape used by `requests_create` (contracts.rs:7047): load state via repo → call pure engine function → persist result → return JSON. Delete `DECOMMISSION_STORE` (contracts.rs:7836) and back it with the existing `decommission_requests` table first, as the proof-of-pattern.
- **Degraded-mode policy**: keep the `get_db() == None` in-memory fallback for demo mode, but (a) `/api/health`/readiness reports `persistence: "in-memory (volatile)"`, (b) the portal shell shows a degradation banner, and (c) **live execution is refused without a database** — evidence-first means no irreversible action may be taken if its evidence cannot be durably recorded.
- **Validation & evidence**: extend `scripts/validator-rs/src/platform_database_readiness.rs` with a table-consumption check: every `CREATE TABLE` name in `migrations/` must appear in at least one SQL string in `sources/ryuki-api/src/` (allowlist for intentionally-deferred tables, which must shrink each release). Keep `PROHIBITED_IMPORTS` unchanged. Add per-domain integration tests against a Postgres testcontainer (`sources/ryuki-api/tests/`), asserting state survives a simulated restart (new pool, same DB).
- **Safety/dry-run**: dry-run results are themselves evidence and are persisted with their `source: "dry-run"` markers as columns/JSON, not implied by absence of data.

#### 2. Lossless request lifecycle persistence

- **Goal**: any of the 14 request types round-trips through Postgres without losing payload, stages, approvals, or evidence; `db_row_to_request` stops fabricating history.
- **Data model** — `migrations/045_requests_lifecycle.sql`:
  - `ALTER TABLE requests ADD COLUMN payload JSONB NOT NULL DEFAULT '{}'`, `plan JSONB`, `validation_results JSONB`, `approval_route JSONB NOT NULL DEFAULT '[]'`, `criticality TEXT NOT NULL DEFAULT 'standard'`, `requester TEXT`, `owner TEXT`, `dry_run_required BOOLEAN NOT NULL DEFAULT true`, `evidence_manifest_id TEXT`, `metadata JSONB NOT NULL DEFAULT '{}'`. Keep `cpu`/`memory_gb` for backward compatibility; new writes put sizing inside `payload`.
  - `CREATE TABLE request_stages (id UUID PK DEFAULT gen_random_uuid(), request_id UUID NOT NULL REFERENCES requests(id) ON DELETE CASCADE, name TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('pending','in_progress','completed','failed','blocked')), started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, evidence JSONB NOT NULL DEFAULT '[]', metadata JSONB NOT NULL DEFAULT '{}', sequence INT NOT NULL, UNIQUE (request_id, name))` — a direct projection of `ryuki_engine::models::Stage` (models.rs:132-140) and `EvidenceItem` (models.rs:265-271).
- **Engine changes**: none to the model; `Request`/`Stage`/`EvidenceItem` already carry everything. `request_lifecycle.rs` transition functions become the single source of stage truth (they already are; the DB just finally stores their output).
- **API**: extend `CreateRequest` (contracts.rs:2389) with `params: serde_json::Value` validated per request type against the corresponding `catalog/` contract; rewrite `DbRequestRow` and all `requests_*` handlers (contracts.rs:~7034-7460, binds at 7047-7423) to serialize/deserialize the full model; delete the synthesis in `db_row_to_request` and `completed_request_stage`. Stage transitions write `request_stages` rows inside the same transaction as the `requests.status` update.
- **Portal UI**: `portal/portal-ui/src/views/request_detail.rs` gains real stage history (timestamps, per-stage evidence) instead of synthesized entries; `request_create.rs` gains a type-specific params form (can land later; JSON shape is unchanged for existing fields).
- **Validation & evidence**: validator check asserting `request_stages` statuses match the engine's `StageStatus` variants; integration test creating one request of each of the 14 types and asserting byte-equal round-trip of the `Request` JSON.
- **Safety/dry-run**: `dry_run_required` is now persisted, so the approval-gated live-execution check can no longer be bypassed by a restart.

#### 3. Sites as data: `sites` table and validity injection

- **Goal**: site activation is durable and actually governs which sites engines accept; the 16 duplicated `VALID_SITES` constants disappear.
- **Data model** — `migrations/046_sites.sql`: `CREATE TABLE sites (unlocode TEXT PRIMARY KEY CHECK (char_length(unlocode) = 5), name TEXT NOT NULL, country TEXT NOT NULL, country_code TEXT NOT NULL, timezone TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT false, activated_at TIMESTAMPTZ, activated_by TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`, seeded from `reference_sites()` (site_registry.rs:19+). Follow-up migration adds FKs (or a documented soft reference) from the `site TEXT` columns in `patch_waves`, `site_status` (025), `site_capacity` (021) etc., reconciling their divergent hardcoded seeds (DEFRA/GBLON/NLAMS only) with the registry.
- **Engine changes**: delete all 16 `const VALID_SITES` and `SITE_STORE`; engine functions gain an explicit parameter — `fn create_request(..., active_sites: &[String])` or a small `SiteCatalog<'a>` struct — keeping the engine DB-free per validator rules. `site_registry.rs` shrinks to pure validation/formatting helpers over passed-in `SiteEntry` values.
- **API**: `repos/sites.rs`; rewrite `/api/admin/sites`, `/api/admin/sites/{unlocode}`, `.../activate`, `.../deactivate`, `/api/admin/sites/search` handlers (contracts.rs:9551-9597) to hit the table; handlers that call site-validating engine functions resolve `active_sites` from the repo (per-request query; cacheable later).
- **Portal UI**: future site-admin view can list/activate sites; no change required initially (same JSON shape, `source` field changes from `"dry-run"` to `"database"`).
- **Validation & evidence**: validator check that `VALID_SITES` no longer appears in `sources/ryuki-engine/src/` (grep-based, like existing lint checks); activation/deactivation writes an audit row (see feature 7). Fix the false claims in `docs/site-management.md:47-81`.
- **Safety/dry-run**: deactivating a site must not orphan in-flight requests — deactivation is refused (409) while open requests reference the site, or requires an explicit `force` with evidence.

#### 4. Schema for the 13+ schema-less domains

- **Goal**: every route surface with CRUD/lifecycle semantics has tables behind it.
- **Data model** — grouped migrations, next free numbers:
  - `047_network_core.sql`: `dns_records`, `ipam_subnets`, `ipam_reservations`, `firewall_rule_sets`, `firewall_rules`, `lb_virtual_servers`, `lb_pool_members`. (Note: `vlans`/`switch_ports`/`port_reservations` from 019 belong to network-readiness and stay separate.)
  - `048_storage_containers.sql`: `storage_arrays`, `storage_volumes`, `k8s_namespaces`.
  - `049_resilience_secrets.sql`: `dr_plans`, `dr_tests`, `managed_secrets` (metadata + rotation policy only — **never secret material**, per the never-commit-secrets rule; values stay in the vault component), `secret_rotations`.
  - `050_operations.sql`: `runbook_catalog`, `runbook_executions` (with approver/rollback columns matching the approve/complete/rollback routes), `incidents`.
  - `051_governance_inventory.sql`: `compliance_frameworks`, `compliance_controls`, `compliance_findings`, `compliance_reports`, `evidence_artifacts`, `inventory_items`.
  - Each table: UUID PK, `site TEXT REFERENCES sites(unlocode)` where applicable, status CHECK constraints mirroring engine enums, `created_at`/`updated_at`, and indexes from day one.
- **Engine changes**: same pure-function extraction as feature 1 for `dns_ipam.rs`, `firewall_rules.rs`, `load_balancer.rs`, `storage_provisioning.rs`, `container_namespace.rs`, `secrets_rotation.rs`, `runbook_execution.rs`, dr_testing.
- **API**: repos wired into the existing handler blocks — `/api/network/dns/records`, `/api/network/ipam/*`, `/api/network/firewall/rules` (+ rule-sets/apply/revoke), `/api/network/loadbalancer/vs/{id}/drain|enable|member`, `/api/datacenter/storage/volumes/{id}/extend|map|retire`, `/api/build/k8s/namespaces/{id}/quota|suspend|terminate`, `/api/protect/secrets/*`, `/api/ops/runbook/*`, `/api/ops/incident/*`, `/api/audit/compliance/*`, `/api/evidence/*`, `/api/inventory/*`. JSON shapes unchanged, so portal and API consumers gain durability transparently.
- **Portal UI**: none required initially (these domains have no views yet under `portal/portal-ui/src/views/` — only dashboard/login/requests/workspaces exist).
- **Validation & evidence**: the table-consumption validator check (feature 1) prevents these from becoming dead schema; lifecycle actions (apply/revoke, drain, terminate) persist evidence JSON on the row.
- **Safety/dry-run**: mutating verbs remain dry-run by default; the persisted row records both the dry-run plan and, post-approval, the (future) live result.

#### 5. Activate dead schema: knowledge suggestions and monitoring review queue

- **Goal**: turn `failure_patterns` (028) and `monitoring_review_queue` (031) from seeded-but-orphaned tables into working review workflows.
- **Data model**: tables already exist and are well-designed (status workflows, dedup key `UNIQUE (error_type, affected_workflow)`, 4 indexes on 031). At most a small migration to add missing indexes on `failure_patterns(status)`.
- **Engine changes**: new pure modules `sources/ryuki-engine/src/knowledge_suggestions.rs` (pattern dedup by error_type+workflow, occurrence increment, transitions New→UnderReview→Approved/Rejected with mandatory `rejection_reason`) and `monitoring_review_queue.rs` (claim/resolve transitions, SLA-overdue derivation from `sla_deadline`). Register both in the validator's required-module list.
- **API**: `/api/operations/knowledge/suggestions` (GET list, POST `{id}/review|approve|reject`) and `/api/observe/monitoring-review-queue` (GET list, POST `{id}/claim|resolve`), backed by `repos/knowledge_suggestions.rs` and `repos/monitoring_queue.rs`; the static descriptors at contracts.rs:762-763 and 1011-1012 gain `endpoints` arrays. Failure-pattern **ingestion**: request execution failures in the lifecycle handlers upsert into `failure_patterns` (increment `occurrence_count`, update `last_seen`).
- **Portal UI**: two new review-queue views under `portal/portal-ui/src/views/` (list + approve/reject and claim/resolve actions), linked from dashboard.
- **Validation & evidence**: approval/rejection records reviewer + timestamp; rejected patterns keep `rejection_reason` (column exists).
- **Safety/dry-run**: read/review workflows are inherently safe; approving a suggestion only publishes a draft article record, never touches providers.

#### 6. Hot-path indexes

- **Goal**: stop shipping unindexed hot queries before tables grow beyond demo size.
- **Data model** — `migrations/052_indexes.sql` (no code changes): `CREATE INDEX idx_requests_created_at ON requests (created_at DESC); CREATE INDEX idx_requests_status ON requests (status); CREATE INDEX idx_requests_site ON requests (site); CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);` plus, as 005-013 tables gain consumers in feature 1: `patch_waves(site, status)`, `certificates(expires_at)`, `snapshots(vm_name)`, `decommission_requests(status)`.
- **Validation**: validator heuristic — any `ORDER BY`/`WHERE` column appearing in API SQL must have a matching index or an allowlist entry.

#### 7. `users`/`audit_log` and migration-numbering hygiene

- **Goal**: close the phantom-`002` confusion and give `sessions` a real anchor.
- **Data model** — `migrations/044_users.sql`: `users (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, roles TEXT[] NOT NULL DEFAULT '{}', active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ)` and `audit_log (id UUID PK, actor TEXT, action TEXT NOT NULL, subject_type TEXT, subject_id TEXT, detail JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())` with indexes on `(actor, created_at)` and `(subject_type, subject_id)`. `sessions.user_id` gains a soft reference now, FK after backfill. Add a one-line note in a `migrations/README.md`: `002` was reserved and never shipped; numbering continues from 044.
- **API**: session creation upserts the `users` row; site activation, request approval, and settings writes (cf. recent commits `6afe852`, `7172ea8`) append `audit_log` rows.
- **Safety**: audit rows are insert-only; no UPDATE/DELETE statements permitted by the repo layer (validator-checkable).

### Implementation plan

1. **(S)** Ship `044_users.sql` + `052_indexes.sql`-style index migration and the `migrations/README.md` numbering note. Zero code risk, immediate wins.
2. **(M)** Proof-of-pattern: delete `DECOMMISSION_STORE` (contracts.rs:7836), add `repos/decommissions.rs` against the existing 012 tables, plus the first testcontainer integration test and the repo-layer scaffolding (`repos/mod.rs`, error mapping).
3. **(L)** Request lifecycle: `045_requests_lifecycle.sql`, rewrite `DbRequestRow`/`CreateRequest`/all `requests_*` handlers for lossless round-trip, delete synthesis in `db_row_to_request`, update `portal/portal-ui/src/views/request_detail.rs`, round-trip tests for all 14 types.
4. **(M)** Sites: `046_sites.sql`, `repos/sites.rs`, rewrite `/api/admin/sites/*` handlers, replace 16 `VALID_SITES` constants with injected site lists, fix `docs/site-management.md`, validator grep-check.
5. **(L)** Wire the ~25 existing-table domains (feature 1) in priority order: patch_waves → snapshots → backup/restore → certificates → legal_holds → maintenance_windows → aiops → remainder. Convert each engine module to pure functions as its repo lands; one PR per domain.
6. **(L)** Schema-less domains (feature 4): migrations 047-051 plus repos and handler wiring, network core first (DNS/IPAM/firewall/LB), then storage/k8s, then resilience/secrets, then ops/governance.
7. **(M)** Knowledge suggestions + monitoring review queue: engine modules, routes, repos, ingestion hook, two portal views.
8. **(M)** Platform hardening: degraded-mode policy (readiness reporting, portal banner, refuse live execution without DB), validator table-consumption and audit-insert-only checks in `scripts/validator-rs/src/platform_database_readiness.rs`.

### Risks & open questions

- **Engine API churn**: converting 40 modules from hidden statics to pure functions touches every handler in the 11k-line `contracts.rs`; doing it per-domain (step 5) keeps PRs reviewable but means months of mixed-mode operation. Mitigation: the dual-path `get_db()` pattern already models this.
- **Fate of the in-memory fallback**: keeping it preserves the zero-dependency demo experience but doubles every handler's code paths and is the root cause of this theme. Recommendation: keep it only for GET surfaces and demo mode, refuse mutations of governed objects without a DB. Needs a product decision.
- **Seeded demo data in migrations**: 010/028/031 etc. seed demo rows in *schema* migrations, which will pollute production databases. Should seeds move to a dev-only fixture path (e.g. gated by `platform_config` demo flag)? Affects how the table-consumption validator treats "empty but wired" tables.
- **Multi-replica concurrency**: moving state to Postgres fixes durability but introduces write conflicts the `Mutex` previously serialized. Stage transitions need optimistic locking (a `version` column or `WHERE status = $expected` guards) — proposed for `requests`/`request_stages` first.
- **`cpu`/`memory_gb` legacy columns**: drop them after payload migration, or keep indefinitely for the VM offering? Dropping requires a data backfill into `payload`.
- **`sessions` denormalized roles**: migrating role authority from `sessions.roles` to `users.roles` changes the authorization source of truth mid-session; needs an explicit cutover plan (out of scope here, overlaps the RBAC theme).
- **sqlx style**: the codebase uses runtime `query_as` strings, not compile-time `query!` macros — fine, but it makes the testcontainer integration suite (not just the validator greps) the real safety net; CI needs a Postgres service container.

---

## Request lifecycle & approval workflow completeness

The platform's central promise is a governed request lifecycle (Draft → Intake → Validated → Planned → Approved → Locked → Executing → Verifying → Completed), and the forward happy path of that machine exists and is tested. But a workflow is defined by what happens when the happy path doesn't apply, and today nothing does: an approver cannot reject, a requester cannot cancel, a failed request can never be reworked or removed, "approval" is a single bodyless POST that records the literal string `admin`, the Locked state acquires no actual lock, execution is a synchronous in-process state flip with no job record, and both the list and detail surfaces the workflow depends on are fed hardcoded fallback data. Until these close, Ryuki is a lifecycle demo, not an approval workflow — no real organization can run change governance on a system where "no" is unrepresentable.

### Current state

- **State machine is forward-only.** `RequestStatus` (sources/ryuki-engine/src/models.rs:101-112) has the 9 forward states plus `Failed` — no `Rejected`, no `Cancelled`. `transition_status` (sources/ryuki-engine/src/request_lifecycle.rs:483-499) lists only the 8 forward edges. The engine contradicts itself: `validate_request`'s remediation text says "Move request back to Draft or Intake before validation" (request_lifecycle.rs:109), a transition that does not exist. `fail_request` (request_lifecycle.rs:540-553) exists but is never referenced anywhere in sources/ryuki-api, so even `Failed` is unreachable over HTTP. There is no `DELETE /api/requests/{id}` — the only request routes are create/list/get plus the six forward transitions (sources/ryuki-api/src/contracts.rs:109-117).
- **Approval is a single hardcoded yes.** `requests_approve` (contracts.rs:7270-7317) takes no body and calls `approve_request(&request, "admin")` — approver identity is the literal `"admin"`, ignoring the authenticated `AuthSession` it already extracts. Catalog offerings require multi-role routes (e.g. `windows-server-deployment` requires Datacenter Approver + Application owner + Wintel/Linux Operator, catalog/offering-catalog.yaml:37-40), but the first approve call flips the whole request to Approved. No migration (001–043) creates an approval-decisions table. The only approvals endpoint, `GET /api/approvals/decision-readiness-contract` (contracts.rs:3588-3615), is a static seed that declares `approvalDecisionMutationAllowed: false` while listing decision states (`rejected`, `delegated`, `expired`) nothing implements.
- **Locking is fiction.** `lock_request` (request_lifecycle.rs:342-384) clones the request, mints a random id, and records evidence labeled "DRY-RUN: Lock … (simulated, no live lock)". No locks table exists in migrations/, no conflict check against other Locked requests in the same `{site}/{environment}` scope, and no release/expiry anywhere. `lock-conflict` appears only as static contract text (contracts.rs:4459, 4698).
- **Execution is synchronous and unobservable.** `requests_execute` (contracts.rs:7366-7411) is SELECT → engine call → UPDATE → return. `execute_request` sets `Executing` then immediately overwrites it with `Verifying` before returning (request_lifecycle.rs:395, 434), so `Executing` is never observable. There is no operations/jobs resource among the API's routes, no `tokio::spawn` in ryuki-api or ryuki-engine, and no idempotency, SSE, or WebSocket anywhere in sources/. Non-lifecycle actions like `gmsa_lifecycle::rotate_password` (sources/ryuki-engine/src/gmsa_lifecycle.rs:237-254) unconditionally re-apply on retry.
- **List/detail surfaces are stubs.** `PaginationParams` (contracts.rs:22-26) is consumed by exactly one handler, `requests_list` (contracts.rs:7073-7119), which supports no status/site/type/requester filters, fixed `ORDER BY created_at DESC`, and returns a bare JSON array with no total. The portal never calls it: `get_request_list` (portal/portal-ui/src/server_boundary.rs:1133-1140) returns `request_summary_fallbacks()` hardcoded in portal/portal-ui/src/models.rs, and `get_request_detail` (server_boundary.rs:1142-1151) returns `request_detail_fallback()` with a fabricated timeline stamped 2026-06-05 (models.rs:1088-1124). All portal lifecycle actions are rejected by `reject_static_preview_request_action` (server_boundary.rs:1163-1172). The list view's `status_label` (portal/portal-ui/src/views/requests.rs:21-30) maps only 5 of the 10 engine statuses; the detail stepper hardcodes 7 stage names including `executed`/`verified` that don't match the engine's `executing`/`verifying` strings and renders `failed` as all-steps-pending (portal/portal-ui/src/views/request_detail.rs:238-250). Even a wired portal couldn't show real context: `requests` (migrations/003_requests.sql) stores no stages/evidence/approval columns, and `db_row_to_request` (contracts.rs:6975-7020) fabricates synthetic stages from the single `stage` TEXT column, losing all evidence.

### Design

#### 1. Persist stage and evidence history (foundation for everything below)

**Goal:** the DB-backed path stores the same `Vec<Stage>` (with `EvidenceItem`s) the in-memory engine produces, so every later feature has somewhere durable to write decisions, lock records, and execution logs.

- **Data model:** migration `migrations/044_request_stages.sql` — `ALTER TABLE requests ADD COLUMN stages JSONB NOT NULL DEFAULT '[]'::jsonb;` plus `ADD COLUMN criticality TEXT NOT NULL DEFAULT 'standard'` and `ADD COLUMN approval_route JSONB NOT NULL DEFAULT '[]'::jsonb` (currently dropped on persistence). JSONB is chosen over a normalized `request_stages` table because `Stage`/`EvidenceItem` are already `Serialize`/`Deserialize` in sources/ryuki-engine/src/models.rs:131-148 and the engine treats stages as a document; approval decisions get their own normalized table (feature 3) because they need uniqueness constraints and queryability.
- **Engine:** none — the engine model is already correct; the DB path simply stops discarding it.
- **API:** every transition handler in sources/ryuki-api/src/contracts.rs (`requests_validate` :7157, `requests_plan` :7227, `requests_approve` :7270, `requests_lock` :7319, `requests_execute` :7366, `requests_verify` :7413) persists `serde_json::to_value(&updated.stages)` in its UPDATE. `requests_get` (contracts.rs:7121-7155) returns the stored stages. Retire the lossy reconstruction in `db_row_to_request` (contracts.rs:6975-7020): deserialize `row.stages` instead of synthesizing from `row.stage`.
- **Validation & evidence:** the existing `require_completed_stage_for_transition` guards (request_lifecycle.rs:17-29) now operate on real history in DB mode instead of synthesized stages — this also closes the current hole where DB mode fakes a completed `plan` stage on every read.
- **Safety/dry-run:** evidence items keep their `redacted`/`redacted_value` fields end to end; the redaction conventions from catalog evidence contracts apply at render time, not storage time.

#### 2. Terminal and backward transitions: reject, cancel, rework, fail, delete

**Goal:** every non-happy outcome is representable, evidenced, and reachable over HTTP.

- **Data model:** migration `migrations/045_request_terminal_states.sql` — add `terminal_reason TEXT`, `terminal_actor TEXT`, `terminal_at TIMESTAMPTZ` to `requests`, and a `CHECK (status IN ('draft','intake','validated','planned','approved','locked','executing','verifying','completed','failed','rejected','cancelled'))` (the column is free TEXT today).
- **Engine (sources/ryuki-engine/src/request_lifecycle.rs):**
  - Add `Rejected` and `Cancelled` to `RequestStatus` (models.rs:101-112) with `as_str` values `"rejected"`/`"cancelled"`; add both to `BLOCKED_STATUSES` (request_lifecycle.rs:8).
  - `reject_request(request, approver, reason)` — valid from `Planned`; pushes an `approve` stage with `StageStatus::Failed` and an `EvidenceType::ApprovalDecision` item "Rejected by {approver}: {reason}". Reason is mandatory.
  - `cancel_request(request, actor, reason)` — valid from `Draft|Intake|Validated|Planned|Approved|Locked` (requester or admin); not valid once `Executing` (see open questions). Records a `Summary` evidence item with actor + reason.
  - `rework_request(request, actor, reason)` — backward edge `Validated|Planned|Rejected|Failed → Intake`, resetting downstream stages to `Pending` and making the request_lifecycle.rs:109 remediation text ("Move request back to Draft or Intake") finally true.
  - Extend `transition_status`'s table (request_lifecycle.rs:483-499) with these edges, and add lock-release hooks on all terminal transitions (feature 4).
- **API (sources/ryuki-api/src/contracts.rs):** new routes next to the existing block at :109-117 — `POST /api/requests/{id}/reject` and `/cancel` and `/rework` with `{ "reason": "..." }` bodies, `POST /api/requests/{id}/fail` (finally exposing `fail_request`), and `DELETE /api/requests/{id}` restricted to `draft|intake|rejected|cancelled` (evidence-first: implement as soft delete via a `deleted_at` column rather than row removal). Permissions via the existing `check_permission` (sources/ryuki-engine/src/auth.rs:219): reject requires `approve`; cancel requires the session `user_id` to match `created_by` or the `admin` capability; fail requires `execute`. Extend `db_status_to_request_status`/`request_status_to_db` (contracts.rs:6929-6958).
- **Portal:** extend `action_label` and the dispatch match in portal/portal-ui/src/views/request_detail.rs:34-44 and :316-333 with reject (with confirm + reason field), cancel, rework; fix `actions_available` in portal/portal-ui/src/models.rs:1126-1135 so `failed` offers `rework`/`cancel` instead of the currently-impossible `validate`/`plan`; add `rejected`/`cancelled` to `status_label`/`status_badge_class` in views/requests.rs:10-30 and request_detail.rs:9-31.
- **Validation & evidence:** terminal transitions always record actor, reason, timestamp as stage evidence; `scripts/validator-rs` gains a check that every catalog offering's lifecycle contract includes reject/cancel handling.
- **Safety/dry-run:** reject/cancel/rework are state-only operations — safe in dry-run mode; DELETE never destroys evidence (soft delete).

#### 3. Approval decisions and an approvals inbox

**Goal:** per-role decision recording with quorum against the catalog's approval route, real approver identity, comments, and a "pending my approval" queue.

- **Data model:** migration `migrations/046_approval_decisions.sql`:
  ```sql
  CREATE TABLE approval_decisions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      request_id UUID NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
      approver_role TEXT NOT NULL,
      approver_identity TEXT NOT NULL,
      decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')),
      comment TEXT,
      decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (request_id, approver_role)
  );
  CREATE INDEX approval_decisions_request_idx ON approval_decisions (request_id);
  ```
- **Engine:** populate `Request.approval_route` at create time from the offering's `approvals:` list in catalog/offering-catalog.yaml (today it's only mutated as a side effect of approving, request_lifecycle.rs:335-337). Change `approve_request` (request_lifecycle.rs:301) into `record_decision(request, role, identity, decision, comment) -> DecisionOutcome` where outcome is `RoutePending(remaining_roles)`, `RouteSatisfied` (transition to `Approved`), or `Rejected` (transition to `Rejected` via feature 2). First rejection short-circuits the route. Each decision appends `EvidenceType::ApprovalDecision` evidence to the `approve` stage: "Approved by {identity} as {role}: {comment}".
- **API (sources/ryuki-api/src/contracts.rs):**
  - `POST /api/requests/{id}/decisions` with body `{ "decision": "approve"|"reject", "comment": "..." }`. Identity comes from the `AuthSession` (`session.user_id`, sources/ryuki-engine/src/auth.rs:58-64) — deleting the hardcoded `"admin"` at contracts.rs:7290 and :7312. Role is resolved by intersecting `session.roles` with the request's unsatisfied route roles; ambiguity (user holds several pending roles) is resolved with an optional `"role"` field. Returns the route status (decided/remaining roles).
  - `GET /api/approvals/pending` — requests in `planned` status with at least one route role held by the session and no decision row for that role; supports the feature-6 pagination envelope.
  - Keep `POST /api/requests/{id}/approve` as a thin shim over `decisions` for one release, then remove.
  - Update the static `approvals_decision_readiness` seed (contracts.rs:3588-3615) so `approvalDecisionMutationAllowed`/`approvalQueueMutationAllowed` reflect actual configuration instead of constants.
- **Portal:** new `portal/portal-ui/src/views/approvals.rs` (inbox table: request, offering, site/env, requester, my pending role, waiting-since) registered in views/mod.rs with a `PRIMARY_NAV_ITEMS` entry in portal/portal-ui/src/shell.rs gated by `required_role`; a decision panel in views/request_detail.rs (approve/reject buttons, mandatory comment on reject, per-role decision list with identity + timestamp); new server functions `get_pending_approvals`/`submit_decision` in server_boundary.rs calling the live API (see feature 7 for the boundary change).
- **Validation & evidence:** separation of duties enforced server-side — a session whose `user_id` equals `requests.created_by` cannot decide; the unique `(request_id, approver_role)` constraint makes double-decisions impossible at the storage layer.
- **Safety/dry-run:** decisions are governance metadata, not provider actions — allowed in dry-run mode; the readiness contract continues to gate live execution behind a fully satisfied route.

#### 4. A real lock registry with conflict detection, release, and expiry

**Goal:** `Locked` means an exclusive, queryable, releasable claim on a scope; overlapping requests cannot both execute.

- **Data model:** migration `migrations/047_request_locks.sql`:
  ```sql
  CREATE TABLE request_locks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      request_id UUID NOT NULL REFERENCES requests(id),
      scope TEXT NOT NULL,                      -- "{site}/{environment}" today
      acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      released_at TIMESTAMPTZ
  );
  CREATE UNIQUE INDEX request_locks_active_scope
      ON request_locks (scope) WHERE released_at IS NULL;
  ```
  The partial unique index makes acquisition atomic — no SELECT-then-INSERT race.
- **Engine:** new `sources/ryuki-engine/src/lock_registry.rs` with `acquire(scope, request_id, ttl)`, `release(request_id)`, `active(scope)`; an in-memory `HashMap` implementation backs store mode. `lock_request` (request_lifecycle.rs:342-384) takes the acquired lock id instead of minting a random one, and the evidence drops the "(simulated, no live lock)" label when registry-backed — it stays a DRY-RUN with respect to providers but the lock itself is real. Terminal transitions (`Completed`, `Failed`, `Rejected`, `Cancelled`) release.
- **API:** `requests_lock` (contracts.rs:7319-7363) performs the `INSERT` and maps the unique-violation to `409 Conflict` using the existing `ProblemDetails` type with the `lock-conflict` reason — turning the static contract string at contracts.rs:4459/:4698 into evaluated behavior, including the holder's request id so the caller can find the blocker. `requests_verify`/`fail`/`cancel`/`reject` handlers release. `POST /api/requests/{id}/unlock` as an `admin`-gated override for stuck locks (evidence-recorded).
- **Portal:** views/request_detail.rs shows the active lock (scope, acquired/expires) and renders a 409 as "Blocked by request {id} holding lock on {scope}" with a link.
- **Validation & evidence:** lock acquire/release each append a `LockRecord` evidence item with lock id, scope, and TTL.
- **Safety/dry-run:** default-deny on conflict; `expires_at` (default e.g. 4h) plus a sweep in the feature-5 worker prevents permanent wedges; expiry events are evidenced, not silent.

#### 5. Async operations, job tracking, and idempotency

**Goal:** execute-class work returns immediately with a pollable operation, `Executing` becomes an observable state, and retried POSTs are safe before live adapters land.

- **Data model:** migration `migrations/048_operations.sql` — `operations` table: `id UUID PK`, `request_id UUID REFERENCES requests(id)`, `kind TEXT` (`execute`, `verify`, later `rotate`/`deploy`), `state TEXT CHECK (state IN ('queued','running','succeeded','failed'))`, `progress INTEGER DEFAULT 0`, `idempotency_key TEXT UNIQUE`, `result JSONB`, `error TEXT`, `created_at`/`started_at`/`finished_at TIMESTAMPTZ`.
- **Engine:** split `execute_request` (request_lifecycle.rs:386-437) into `start_execution` (`Locked → Executing`, marks the execute stage `InProgress`) and `complete_execution` (`Executing → Verifying`, completes the stage with the execution log) so the `Executing` status actually exists on the wire instead of being overwritten at :434 before anyone sees it.
- **API:** `requests_execute` (contracts.rs:7366-7411) inserts a `queued` operation, returns `202 Accepted` with `{ "operation_id": ... }`, and runs the work in `tokio::spawn` with a cloned pool handle (consistent with the no-global-mutable-state rule — state flows through the task closure, and the existing `get_db()` pool is already process-shared). New routes `GET /api/operations/{id}` and `GET /api/operations?request_id=`. An `Idempotency-Key` middleware in sources/ryuki-api/src/main.rs applies to lifecycle and action POSTs: a replayed key returns the stored operation/result instead of re-executing — which also fixes the inverse problem where a timed-out client currently *cannot* retry `/execute` (the state machine has already moved on) and closes the unguarded double-apply on action endpoints like `gmsa_lifecycle::rotate_password` (gmsa_lifecycle.rs:237-254) before real adapters are wired.
- **Portal:** lifecycle `Action`s in views/request_detail.rs poll the operation until terminal instead of one-shot feedback; show state/progress inline. SSE (`/api/operations/{id}/events`) is a follow-up, not required for v1 — polling at 2s is fine at this scale.
- **Validation & evidence:** operation results embed the evidence items produced by the execution; operation rows are the audit trail for *attempts*, complementing stages which record *outcomes*.
- **Safety/dry-run:** dry-run executions go through the identical queue → running → succeeded path (completing in milliseconds), so live-mode behavior is exercised continuously rather than being a divergent code path.

#### 6. List filtering, pagination envelope, and a live portal list

**Goal:** an approver or operator can answer "what's waiting on me / what's executing in DEFRA production" from the API and the portal.

- **Data model:** migration `migrations/049_requests_indexes.sql` — indexes on `requests(status)`, `requests(site)`, `requests(created_by)`, `requests(created_at DESC)`.
- **API:** extend `requests_list` (contracts.rs:7073-7119): a `RequestListParams` struct adding `status`, `site`, `environment`, `request_type`, `created_by`, `q` (name substring), `sort` (`created_at|updated_at` + direction) to the existing `PaginationParams`; build the WHERE clause with bound parameters; return an envelope `{ "items": [...], "total": n, "limit": l, "offset": o }` (with `COUNT(*)` under the same filters). This is a breaking change to the bare array, but the portal — the only consumer — never calls it today, so the cost is zero now and grows later. Apply the same envelope + `PaginationParams` to other unbounded domain list handlers as a follow-up convention.
- **Engine:** none.
- **Portal:** wire `get_request_list` (server_boundary.rs:1133-1140) to `GET /api/requests` with filter pass-through; in views/requests.rs add a toolbar (status select covering all 12 statuses, site select sourced from the site registry, search box, sortable created/updated columns, prev/next pager driven by `total`); complete `status_label`/`status_badge_class` (views/requests.rs:10-30) for `planned|locked|executing|verifying|completed|rejected|cancelled` — five of which currently render as "Unknown". Add a "Pending my approval" quick filter that routes to the feature-3 inbox.
- **Validation & evidence:** n/a (read path); add an API test asserting the envelope shape and filter combinations.
- **Safety/dry-run:** read-only.

#### 7. Request detail with real plan, evidence, and approval context

**Goal:** the detail page shows what an approver actually needs to decide — dry-run plan output, validation results, evidence, per-role decisions — derived from live data, with a stepper that matches the engine's actual states.

- **Data model:** covered by features 1 (stages JSONB) and 3 (approval_decisions).
- **API:** `requests_get` (contracts.rs:7121-7155) returns the flat row plus `stages` (deserialized JSONB), `approvals` (join on `approval_decisions` with route satisfaction summary), `lock` (active `request_locks` row if any), and `operations` (latest per kind).
- **Engine:** none beyond features 1–5.
- **Portal:**
  - Extend `RequestDetail` in portal/portal-ui/src/models.rs with `stages: Vec<StageView>` (name, status, timestamps, evidence items with redaction flags), `approvals`, `lock`, `operation`; delete the fabricated timeline in `request_detail_fallback` (models.rs:1088-1124) once live-wired, keeping a clearly-labeled minimal fallback for SSR error paths only.
  - In views/request_detail.rs, replace the hardcoded 7-stage array at :238 with a stepper derived from `RequestStatus::as_str` order (`draft, intake, validated, planned, approved, locked, executing, verifying, completed`) using the real status strings — fixing the `executed`/`verified` vs `executing`/`verifying` mismatch at :20-32 — with distinct terminal styling for `failed`/`rejected`/`cancelled` (today `failed` renders as all-steps-pending, :249).
  - New panels: "Plan" (the `dry-run-plan` evidence value), "Validation" (errors/warnings/failed rules/remediation from the last validate stage), "Approvals" (per-role decision rows with identity, comment, timestamp + remaining roles), "Evidence" (all items, honoring `redacted_value`), "Lock", "Operation".
  - Wire `get_request_detail` (server_boundary.rs:1142-1151) to the live endpoint. This requires the deliberate portal decision: `PortalServerBoundary::static_dry_run` currently rejects all mutations (server_boundary.rs:1163-1172). Introduce an execution-mode configuration (surfaced already as `data-execution-mode` in shell.rs) with `static-preview` and `live-api` modes; in `live-api` mode server functions proxy same-origin to ryuki-api with the session cookie, in `static-preview` they keep current behavior. Styles for stepper terminal states, decision rows, and evidence panels in portal/portal-ui/styles.css.
- **Validation & evidence:** the detail page becomes the primary evidence-pack reader; redacted items render the redaction placeholder, never the raw value.
- **Safety/dry-run:** read panels work in both modes; mutation buttons render disabled with the preview explanation in `static-preview` mode instead of failing after click as they do today.

### Implementation plan

1. **(S)** Migration 044 + persist/read `stages` JSONB; delete the synthetic-stage logic in `db_row_to_request` (contracts.rs:6975-7020). Unblocks everything else.
2. **(M)** Engine terminal/backward transitions: `Rejected`/`Cancelled` variants, `reject_request`/`cancel_request`/`rework_request`, extended `transition_status` table, `BLOCKED_STATUSES`, tests mirroring the existing suite in request_lifecycle.rs:555-829.
3. **(M)** Migration 045 + API routes reject/cancel/rework/fail/DELETE with permission checks and status-mapping updates (contracts.rs:6929-6958).
4. **(M)** Migration 046 + engine `record_decision` with catalog-route quorum + `POST /api/requests/{id}/decisions` + `GET /api/approvals/pending`; remove hardcoded `"admin"` (contracts.rs:7290, :7312).
5. **(M)** Migration 047 + `lock_registry` module + 409 conflict in `requests_lock` + release hooks on terminal transitions + admin unlock.
6. **(L)** Migration 048 + operations table, split `start_execution`/`complete_execution`, 202 + `tokio::spawn` in `requests_execute`, `GET /api/operations/{id}`, `Idempotency-Key` middleware in sources/ryuki-api/src/main.rs.
7. **(M)** Migration 049 + `requests_list` filters/sort/envelope; API tests.
8. **(M)** Portal execution-mode boundary: `live-api` mode in server_boundary.rs proxying `get_request_list`/`get_request_detail`/lifecycle actions to ryuki-api. Prerequisite for steps 9–10.
9. **(M)** Portal list: toolbar (filters/search/sort/pager), complete status maps in views/requests.rs.
10. **(L)** Portal detail rework (live stepper, plan/validation/evidence/approvals/lock/operation panels, reject/cancel actions with reason input, operation polling) + new approvals inbox view + shell.rs nav entry + styles.css.
11. **(S)** Truth-up contracts and validators: make `approvals_decision_readiness` flags configuration-driven; add a scripts/validator-rs check that lifecycle contracts declare reject/cancel coverage.

Suggested sequencing: 1–3 land together (state machine honesty), 4–5 together (approval + lock are the governance core), 6–7 next, 8–11 as the portal tranche. Steps 1–7 are independently shippable API improvements even before the portal is live-wired.

### Risks & open questions

- **Dual persistence paths.** Every handler maintains both a DB and an in-memory `request_store()` branch; each feature here doubles that cost. Recommend extracting a `RequestRepository` trait (DB + in-memory impls) early, or declaring the in-memory path test-only and trimming it.
- **Role-name mapping.** Catalog approval routes use display names ("Datacenter Approver", catalog/offering-catalog.yaml:37-40) while RBAC uses slugs (`datacenter-approver`, contracts.rs:3626) and the mock portal session uses neither (`platform-engineer`, server_boundary.rs:1108-1112). Feature 3 needs one canonical role identifier and a mapping table; proposal: RBAC slugs canonical, catalog migrates. Who owns this decision?
- **ID scheme mismatch.** DB mode uses UUIDs; in-memory engine mode mints `req-xxxx` ids (request_lifecycle.rs:59-66). Approval/lock/operation FKs assume UUIDs — another argument for resolving the dual-path question first.
- **Breaking the bare-array list response.** Acceptable now (no consumers), but decide whether the envelope convention is versioned (`Accept` header vs path) before applying it to the other ~600 routes' list handlers.
- **Cancel semantics during Executing.** v1 forbids cancel once `Executing`; real adapter execution will need cooperative cancellation through the operations table (`cancel_requested` flag). Deferred, but the operations schema should not preclude it.
- **Lock scope granularity.** `{site}/{environment}` serializes all work in an environment — likely too coarse once volume grows. Resource-level scopes require plan output to declare touched resources; keep `scope` as TEXT so it can carry finer-grained values without a schema change.
- **Portal live-mode security.** Wiring server_boundary.rs to the live API deliberately punctures the static dry-run boundary; the `live-api` mode must forward the authenticated session (recent commits 6afe852/7172ea8 hardened session binding — reuse that path) and must remain default-off until reviewed.
- **Idempotency middleware scope.** Storing replayed response bodies in `operations.result` is fine for lifecycle actions; decide a size cap and retention before extending to evidence-heavy endpoints.
- **Soft delete vs purge.** Evidence-first argues all deletes are soft; if a hard-purge path is ever needed (GDPR-style), it should be a separate admin workflow with its own evidence — out of scope here.

---

## Audit trail, evidence & compliance export

Ryuki's entire pitch is "governed, evidence-first automation," yet the platform has no audit data model at all. None of the 42 migrations creates an audit log, approvals, or state-transition table; every lifecycle `UPDATE` in `sources/ryuki-api/src/contracts.rs` persists only `status`, `stage`, `updated_at` — never the actor. The approver is hardcoded to the string `"admin"` in both code paths of `requests_approve`, so approval attribution — the core governance artifact — is fabricated regardless of who clicked. The engine's `Stage`/`EvidenceItem` model is computed per-request and then discarded in DB mode, evidence collect/export operate on a synthetic hardcoded request, exports are non-durable strings with no digest or signature, and the Auditor persona's portal workspace renders two hardcoded badges with no actionable content. Until a request's history (who did what, when, with what justification) survives in the database and can be exported as a tamper-evident artifact, the governance story is hollow. This section makes the audit trail real end-to-end: schema, write path, attribution, durable evidence packs, and an Auditor workspace that can actually browse and export them.

### Current state

- **No audit schema.** `migrations/003_requests.sql` stores only `status`/`stage`/`created_by`/timestamps. Grep across `migrations/*.sql` finds no `audit_log`, `approvals`, `request_events`, or execution-artifact table. The only audit-flavored schema is per-domain demo columns populated exclusively by seed `INSERT`s: `decommissions.approvals_collected` (`migrations/012_decommissions.sql:13`), `legal_holds.audit_trail` (`migrations/026_legal_holds.sql:14`), `emergency_changes.approved_by`/`audit_evidence` (`migrations/036_emergency_changes.sql:7,10`), and the access-review log JSONB in `030_access_reviews.sql`. No handler writes to any of them.
- **Actor-less lifecycle writes.** All six lifecycle handlers (`requests_validate`/`plan`/`approve`/`lock`/`execute`/`verify`, `sources/ryuki-api/src/contracts.rs:7157–7477`; routes at `contracts.rs:112–117`) run `UPDATE requests SET status = $1, stage = '…', updated_at = NOW()` (lines 7178, 7244, 7294, 7342, 7389, 7445). No actor, no event row, no before/after.
- **Stages/evidence discarded in DB mode.** `db_row_to_request` (`contracts.rs:6975–7019`) reconstructs *synthetic* stages from the `stage` string and sets `evidence_manifest_id: None` (line 6993). `requests_approve` builds the `approve` stage with its `approval-decision` `EvidenceItem` via `request_lifecycle::approve_request` (`sources/ryuki-engine/src/request_lifecycle.rs:301–340`), returns it in the HTTP response, and persists none of it.
- **Hardcoded approver.** `approve_request(&request, "admin")` at `contracts.rs:7290` (DB path) and `:7312` (in-memory path), even though `AuthExtractor(session)` is already bound at `:7272` and `AuthSession` carries `user_id`/`display_name`/`roles` (`sources/ryuki-engine/src/auth.rs:58–64`). The engine bakes `"Approved by admin"` into evidence (`request_lifecycle.rs:324–331`).
- **Synthetic, non-durable evidence.** `evidence_collect` hardcodes `Request::new("req-evidence-001", …)` (`contracts.rs:9453–9468`); `evidence_export` hardcodes `"req-evidence-export"` (`:9485–9504`). Neither accepts a request id or touches the DB. `export_evidence` (`sources/ryuki-engine/src/evidence_pipeline.rs:121–133`) returns a JSON/YAML `String`; the only `fs::write` in either crate is `ryuki-api/src/config_store.rs`. No sha256, no signature, no hash chain. WORM enforcement is explicitly simulated (`sources/ryuki-engine/src/immutability_compliance.rs:290–331`).
- **Catalog intent without implementation.** `catalog_evidence_manifest` (`contracts.rs:3539–3553`) and `catalog/evidence-manifest-catalog.yaml` already define `requiredManifestFields` (evidenceId, requestReference, exporter, createdAt, redactionState, exportReadiness, retentionClass), `exportReadiness` states, and `retentionClasses` — nothing produces them.
- **Display-only Auditor workspace.** `load_portal_evidence_summary_status` (`portal/portal-ui/src/server_boundary.rs:962–967`) returns `PortalEvidenceSummarySnapshot::static_dry_run()` with `evidence_export_allowed: false` hardcoded (`:738`) and data from `evidence_summary_fallbacks()` (`portal/portal-ui/src/models.rs:577–590`: two hardcoded entries). `EvidenceWorkspaceDetail` (`portal/portal-ui/src/views/workspaces.rs:898–1039`) renders redaction/export badges and static API paths as `data-` attributes; there is no pack list, manifest viewer, download, or audit search. The Auditor role gating exists (`portal/portal-ui/src/workspace_catalog.rs:96,225`) but gates nothing actionable. The `audit` permission already exists on nearly every RBAC role (`sources/ryuki-engine/src/auth.rs:88+`).

### Design

#### Feature 1: Core audit schema and append-only write path

**Goal.** Every state-changing action on the platform produces a durable, queryable, tamper-evident record: who, what, when, before/after.

**Data model.** New migration `migrations/044_audit_events.sql`:

```sql
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,                 -- AuthSession.user_id
    actor_display TEXT,                  -- AuthSession.display_name
    actor_roles TEXT[] NOT NULL DEFAULT '{}',
    provider_mode TEXT NOT NULL,         -- 'entra-id' | 'static-dry-run'
    action TEXT NOT NULL,                -- 'request.approve', 'evidence.export', ...
    entity_type TEXT NOT NULL,           -- 'request', 'evidence_pack', 'platform_config'
    entity_id TEXT NOT NULL,
    request_id UUID REFERENCES requests(id),
    before JSONB,
    after JSONB,
    detail JSONB NOT NULL DEFAULT '{}',
    prev_hash TEXT,                      -- entry_hash of previous row (chain)
    entry_hash TEXT NOT NULL             -- sha256(canonical(row fields || prev_hash))
);
CREATE INDEX idx_audit_log_request ON audit_log (request_id, occurred_at);
CREATE INDEX idx_audit_log_actor ON audit_log (actor, occurred_at);

CREATE TABLE request_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES requests(id),
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    stage TEXT NOT NULL,
    actor TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detail JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES requests(id),
    approver TEXT NOT NULL,
    approver_display TEXT,
    approver_roles TEXT[] NOT NULL DEFAULT '{}',
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    justification TEXT,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

All three tables get append-only triggers (`BEFORE UPDATE OR DELETE … RAISE EXCEPTION 'audit tables are append-only'`) so even the application role cannot rewrite history; this is the cheap, in-database half of tamper evidence, with the hash chain as the verifiable half.

**Engine changes.** None required for the write path; the audit recorder lives API-side because it needs the pool and `AuthSession`. Add `pub mod audit;` types (`AuditAction`, `AuditEntry`) to `ryuki-engine` only if the portal needs shared serde types — otherwise keep them in the API crate.

**API.** New module `sources/ryuki-api/src/audit.rs` exposing `record_audit(pool, &session, action, entity_type, entity_id, request_id, before, after, detail)`. It computes `entry_hash = sha256(canonical_json(fields) || prev_hash)` reading the chain head inside the same transaction (`SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE` via a single-row chain-head table or `pg_advisory_xact_lock` to serialize inserts). Wire calls into every lifecycle handler in `contracts.rs` (`requests_create` plus the six transitions, ~7020–7477), into `platform_config` writes (the `check_permission(session, "admin")` path at `:6538`), and later into evidence export (Feature 3). Each lifecycle handler also inserts a `request_events` row in the same transaction as its `UPDATE requests` statement — wrap the existing `UPDATE … RETURNING` plus the event insert in `pool.begin()`.

New read endpoints, gated on the existing `audit` permission via `check_permission` (`sources/ryuki-engine/src/auth.rs:219`):
- `GET /api/requests/{id}/events` — ordered transition history for one request.
- `GET /api/audit/log?actor=&action=&entity_type=&request_id=&from=&to=&limit=&offset=` — filtered audit search.
- `POST /api/audit/log/verify` — enqueues or joins one durable singleton verification job and returns `202` while it is active; `GET /api/audit/log/verify/{job_id}` exposes safe progress/terminal state. The worker captures a stable tail and verifies fixed-size id pages from genesis, committing an atomic predecessor checkpoint after every page. Request handling never transfers or hashes audit rows.

These sit naturally next to the existing `/api/audit/compliance/*` routes (`contracts.rs:355–370`).

**Portal UI.** Covered in Feature 4.

**Validation & evidence.** sqlx integration tests asserting: every lifecycle transition writes exactly one `request_events` row and one `audit_log` row; the append-only triggers reject `UPDATE`/`DELETE`; chain verification detects a manually corrupted row. Add a validator rule in `scripts/validator-rs/src/` (alongside the existing `app_skeleton.rs` checks) asserting each `requests_*` lifecycle handler in `contracts.rs` contains a `record_audit` call, so new transitions cannot silently skip the trail.

**Safety/dry-run.** Audit writes are metadata-only — no provider calls, so they are safe in every mode. In the no-DB in-memory fallback, append to a process-local `Vec<AuditEntry>` behind the existing `request_store()`-style mutex and serve it from the same endpoints with `"source": "dry-run", "durable": false`, matching the repo's dry-run-honesty convention.

#### Feature 2: Real approver attribution and approval records

**Goal.** The approval record names the human (or service principal) who approved, with justification, and survives in the database.

**Data model.** Uses the `approvals` table from Feature 1.

**Engine changes.** None — `request_lifecycle::approve_request(request, approver)` (`request_lifecycle.rs:301`) already takes the approver and threads it into the `approval-decision` `EvidenceItem` and `approval_route`. The bug is entirely in the wiring.

**API.** In `requests_approve` (`contracts.rs:7270`):
- Replace both `"admin"` literals (`:7290`, `:7312`) with `&session.user_id` (fall back to `display_name` for the evidence string if preferred — pick one and use it consistently).
- Accept an optional body `Json(ApproveBody { justification: Option<String>, decision: Option<String> })` so approvers can record why; default decision `approved`. A rejection decision transitions the request back to `Draft`/`Validated` per existing `transition_status` rules rather than inventing a new status.
- In the DB path, insert the `approvals` row (approver, display, roles, decision, justification) in the same transaction as the status `UPDATE`, and call `record_audit` with `action = "request.approve"`.
- Optional separation-of-duties guard: reject when `session.user_id == row.created_by` unless the session holds `BreakGlassAdmin` (roles in `auth.rs:3–14`); flagged as an open question below.

**Portal UI.** The approve action surface (request workspace) gains a justification text field; the request timeline (Feature 4) renders the `approvals` row with approver display name and justification.

**Validation & evidence.** Engine test already covers approver threading; add API tests asserting the persisted `approvals.approver` equals the session user for both a static-dry-run session and a verified Entra session, and that the `403` path (`check_permission(&session, "approve")`, `:7274`) writes a `request.approve.denied` audit event (denied attempts are audit-relevant too).

**Safety/dry-run.** No behavior change to gating; `AuthExtractor` already rejects unverified tokens (`contracts.rs:6845–6876`). In static-dry-run mode the actor is honestly recorded as `static-user` with `provider_mode = "static-dry-run"`, so demo data can never be mistaken for a real approval.

#### Feature 3: Persisted stages and durable, tamper-evident evidence packs

**Goal.** The engine's per-stage evidence survives the request lifecycle, evidence collect/export operate on real requests, and an exported pack is a durable artifact with a verifiable digest — satisfying the manifest contract the catalog already publishes.

**Data model.** Migration `migrations/045_request_stages.sql`:

```sql
ALTER TABLE requests ADD COLUMN stages JSONB NOT NULL DEFAULT '[]';
ALTER TABLE requests ADD COLUMN evidence_manifest_id TEXT;
```

A JSONB column (rather than a normalized `request_stages` table) matches the engine's `Vec<Stage>` (`sources/ryuki-engine/src/models.rs:132`) exactly and avoids a lossy mapping; querying inside stages is not a hot path. Migration `migrations/046_evidence_packs.sql`:

```sql
CREATE TABLE evidence_packs (
    id TEXT PRIMARY KEY,                  -- engine 'ev-…' id
    request_id UUID NOT NULL REFERENCES requests(id),
    payload JSONB NOT NULL,               -- safe-export pack (post build_safe_export_pack)
    item_digests JSONB NOT NULL,          -- key -> sha256 per item
    pack_digest TEXT NOT NULL,            -- sha256 over canonical payload
    signature TEXT,                       -- detached signature, NULL in dry-run
    export_readiness TEXT NOT NULL,       -- catalog exportReadiness states
    retention_class TEXT NOT NULL DEFAULT 'audit-retained',
    redacted BOOLEAN NOT NULL,
    format TEXT NOT NULL DEFAULT 'json',
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Append-only trigger as in Feature 1.

**Engine changes** (`sources/ryuki-engine/src/evidence_pipeline.rs`):
- Add `sha2` to `ryuki-engine` and implement `hash_evidence_pack(pack) -> PackDigest { item_digests, pack_digest }` using a canonical serialization (serialize via `BTreeMap`-keyed structure or sort keys explicitly — `serde_json` insertion order is not canonical).
- Extend the manifest emitted by `build_safe_export_pack` (`evidence_pipeline.rs:138–163`) to carry the catalog's `requiredManifestFields`: `evidenceId`, `requestReference`, `exporter`, `createdAt`, `redactionState`, `exportReadiness`, `retentionClass`, plus `packDigest` and `itemDigests` — aligning code with `catalog/evidence-manifest-catalog.yaml` and `catalog_evidence_manifest` (`contracts.rs:3539`).
- Add `verify_pack_digest(pack, expected) -> Result<(), String>` for the verify endpoint. Optional phase-2 signing hook: `sign_digest(digest, key) -> String` (HMAC-SHA256 first; key sourced from env/Vault reference per the never-commit-secrets rule, absent in dry-run).

**API** (`contracts.rs`, evidence routes currently at `:372–381`):
- `POST /api/requests/{id}/evidence/collect` — replaces the synthetic `evidence_collect`: load the real row via `get_db()`, build the request with `db_row_to_request` *now hydrated from the persisted `stages` JSONB* (delete the synthetic stage reconstruction at `contracts.rs:6997–7017`), run `collect_evidence`, hash, and insert into `evidence_packs` with `created_by = session.user_id`; set `requests.evidence_manifest_id = pack.id` (fixing the hardcoded `None` at `:6993`). Requires the `audit` or `execute` permission.
- `GET /api/requests/{id}/evidence/packs` and `GET /api/evidence/packs/{pack_id}` — list/fetch persisted packs.
- `GET /api/evidence/packs/{pack_id}/export?format=json|yaml` — replaces the synthetic `evidence_export`: serializes the *stored* payload via `export_evidence`, sets `X-Ryuki-Pack-Digest` header, records a `evidence.export` audit event (exporter, pack, format — exports themselves are auditable events).
- `POST /api/evidence/packs/{pack_id}/verify` — recomputes digests against `payload` and returns pass/fail per item.
- Keep the old `/api/evidence/collect|export` routes returning the synthetic demo pack but explicitly labeled `"source": "dry-run", "durable": false`, or delete them once the portal no longer references the paths — decided in the implementation plan.

Also persist stages on every lifecycle transition: each handler's `UPDATE` gains `stages = $n` with the engine-computed stages serialized to JSONB, so the approve/lock/verify evidence finally has a durable counterpart.

**Portal UI.** Covered in Feature 4.

**Validation & evidence.** Engine tests: digest stability across serialization round-trips; tamper detection (mutate one item value, verify fails); the existing redaction tests (`evidence_pipeline.rs:439–521`) extended to assert digests are computed over the *safe* export, never the raw values. API tests: collect→export→verify round-trip against a migrated test DB; export of a pack whose request never completed `approve` yields `export_readiness = "redaction-pending"`/blocked per the catalog gate. Validator rule: the manifest emitted by the API contains every field listed in `catalog/evidence-manifest-catalog.yaml` `requiredManifestFields`.

**Safety/dry-run.** `export_evidence` already refuses unredacted packs (`evidence_pipeline.rs:122–124`); collection always redacts before sealing, and only the safe-export payload is ever persisted — raw sensitive values never reach `evidence_packs.payload`. No provider calls anywhere in this feature. True WORM/immutability of the underlying storage stays out of scope (the `immutability_compliance` engine remains simulated); the hash chain plus append-only triggers provide tamper *evidence*, not tamper *proofing* — stated plainly in docs.

#### Feature 4: Actionable Auditor workspace (timeline, pack browser, export)

**Goal.** The Auditor persona can browse real evidence packs, inspect manifests with redaction markers, download exports, search the audit log, and view per-request timelines — replacing the two hardcoded badges.

**Data model.** None beyond Features 1–3.

**Engine changes.** None.

**API.** Uses the endpoints from Features 1 and 3. One addition: `GET /api/audit/compliance/summary` (existing, `contracts.rs:10916`) is left as-is; the portal consumes the new `/api/audit/log` and `/api/evidence/packs` endpoints instead.

**Portal UI.**
- `portal/portal-ui/src/server_boundary.rs`: replace the body of `load_portal_evidence_summary_status` (`:962–967`) — and add `load_portal_evidence_packs`, `load_portal_audit_log`, `load_portal_request_timeline` server functions — with loaders that call the ryuki-api over the same-origin boundary, following the existing `PortalServerBoundary::plan_platform_api_read` pattern (`:718–748`) for path planning, and falling back to the current static snapshot when the API is unreachable (preserving today's behavior in static demo mode). `evidence_export_allowed` becomes derived from the API response instead of the hardcoded `false` at `:738`.
- `portal/portal-ui/src/api.rs` / `api_client.rs`: add path constants and `ApiResource`s for `/api/evidence/packs`, `/api/audit/log`, `/api/requests/{id}/events`, next to `evidence_summary_resource()` (`api_client.rs:109`).
- `portal/portal-ui/src/models.rs`: add `EvidencePackSummary`, `EvidencePackManifestView` (items with `redacted` flags and digests), `AuditEventRow`, `RequestTimelineEntry` view models; keep `evidence_summary_fallbacks()` (`:577–590`) as the offline fallback.
- `portal/portal-ui/src/views/workspaces.rs` `EvidenceWorkspaceDetail` (`:898–1039`): three panels — (1) pack list (request ref, created_by, created_at, export readiness, digest prefix), (2) manifest viewer showing items with redaction markers and per-item digest status, (3) audit-log search with actor/action/date filters. Export is a download link to `/api/evidence/packs/{id}/export`, rendered only when the session holds the Auditor role per the existing gating (`workspace_catalog.rs:96,225`).
- Request detail view: render the `request_events` timeline (transition, actor, timestamp) and the `approvals` record inline.

**Validation & evidence.** Leptos SSR snapshot/integration tests for the new server functions in fallback mode (no API) and live mode (mocked API); validator-rs `app_skeleton.rs` already asserts boundary-helper usage (`:430, :1564–:1684, :1923`) — extend the expected-helpers lists with the new evidence/audit paths so the skeleton check covers them.

**Safety/dry-run.** Server functions keep the same-origin boundary; no browser-direct API calls. In static demo mode everything degrades to the current read-only badges with `export_allowed: false`, so the public GitHub Pages build behaves exactly as today.

### Implementation plan

1. **(S)** Migration `044_audit_events.sql`: `audit_log`, `request_events`, `approvals`, append-only triggers, indexes.
2. **(M)** `sources/ryuki-api/src/audit.rs` recorder with hash chain; wire `record_audit` + `request_events` inserts (transactional) into `requests_create` and all six lifecycle handlers in `contracts.rs`; in-memory fallback store for no-DB mode.
3. **(S)** Approver attribution: replace `"admin"` at `contracts.rs:7290/:7312` with the session identity; accept justification body; insert `approvals` row; audit denied attempts.
4. **(M)** Migration `045_request_stages.sql`; persist engine stages JSONB in every lifecycle `UPDATE`; rewrite `db_row_to_request` to hydrate from persisted stages and `evidence_manifest_id`; delete the synthetic stage reconstruction.
5. **(M)** Engine: `sha2` dependency, canonical serialization, `hash_evidence_pack`, manifest fields per catalog contract, `verify_pack_digest`; unit tests including tamper detection.
6. **(M)** Migration `046_evidence_packs.sql`; request-scoped `collect`/`packs`/`export`/`verify` endpoints; set `requests.evidence_manifest_id`; audit events on export; retire or demote the synthetic `/api/evidence/collect|export` handlers.
7. **(S)** Read APIs: `GET /api/requests/{id}/events`, `GET /api/audit/log` with filters, `POST /api/audit/log/verify`, all gated on the `audit` permission.
8. **(L)** Portal: API-backed server functions in `server_boundary.rs` with static fallback; new view models in `models.rs`; pack browser, manifest viewer, audit search, and export download in `EvidenceWorkspaceDetail`; request timeline in the request workspace.
9. **(M)** Validation hardening: validator-rs rules (lifecycle handlers must call `record_audit`; manifest fields match `catalog/evidence-manifest-catalog.yaml`), sqlx integration tests, docs update describing the audit/evidence guarantees and their limits.

Steps 1–3 are independent of 4–6 and deliver immediate value (real attribution + transition history); 8 depends on 6–7.

### Risks & open questions

- **Hash-chain concurrency.** Chaining `audit_log` rows requires serializing inserts on the chain head (`pg_advisory_xact_lock` or a single-row head table). Under load this is a contention point; an alternative is per-request chains (chain key = `request_id`) which parallelize naturally but weaken global ordering claims. Decide before step 2.
- **Canonical JSON.** Digests are only as good as the serialization. `serde_json` map ordering must be pinned (sorted keys) and documented, or a future dependency bump silently breaks verification of historical packs.
- **Stages JSONB may carry sensitive values.** Engine stages hold raw `EvidenceItem.value`; persisting them pre-redaction puts sensitive strings in the `requests` table. Options: run `redact_evidence`-equivalent logic before persisting stages, or persist only redacted values. Needs a decision in step 4 — leaning to redact-before-persist for defense in depth.
- **Separation of duties.** Should `requests.created_by == approver` be rejected? The README's governance story implies yes, but the single-user demo flow breaks if enforced unconditionally. Proposal: enforce in live (Entra) mode, warn-only in static-dry-run.
- **Dry-run divergence.** The in-memory fallback cannot honor durability or append-only guarantees; endpoints must label responses (`"durable": false`) so demo output is never mistaken for evidence. Acceptable, but worth an explicit docs note.
- **Signing key management.** Phase 1 ships digest-only (HMAC optional). Real signatures need a key-distribution story (Vault reference per the secrets conventions); deferred, but the `signature` column reserves the slot.
- **Portal's first live API call.** Every portal server function today returns `static_dry_run()`; Feature 4 introduces the first genuine portal→API call and needs a base-URL/config decision for the same-origin boundary (likely portal server-side env var). This pattern will be reused by every other workspace, so it deserves review.
- **Migration numbering.** 044–046 assumed; parallel workstreams (other P0 sections) must coordinate sequence numbers since sqlx migrations are ordered.
- **`audit_log` growth.** No partitioning/retention initially; the catalog's `retentionClasses` suggest eventual retention policies. Revisit when volume warrants (partition by month, archive to evidence storage).

---

## Portal feature parity & functionality

The portal is a static brochure of the product, not a product surface. No code in `portal/portal-ui` performs a single HTTP request to `ryuki-api`: every `#[server]` read returns hardcoded `*_fallback()` snapshots, all seven request-lifecycle mutations route to `reject_static_preview_*` helpers that always `Err(...)`, login returns a literal `"mock-session-id"`, `shell.rs::is_authenticated()` returns `true`, admin saves are rejected, search is `disabled=true`, and there is no URL routing — one page of `#hash` anchors. Meanwhile the backend it ignores is real: `ryuki-api` registers ~616 routes — 609 in `contracts.rs` (383 GET, 220 POST, 4 DELETE, 2 PUT, all under `/api`), plus 6 in `main.rs` and 1 in `boundary.rs` — backed by 42 migrations and recently hardened lifecycle guards (commits `841e68f`, `90228ea`, `7172ea8`). The portal's `/api` allowlist does resolve — every path constant in `portal/portal-ui/src/api.rs` maps to a registered route — but that parity is maintained purely by hand: nothing in CI checks portal constants against the router, so a renamed route or typo'd constant becomes a silent latent 404. The core governance loop (Draft→Intake→Validated→Planned→Approved→Locked→Executing→Verifying→Completed) is fully implemented server-side and completely unreachable from the UI. This section makes the portal exercise the product.

### Current state

- **No transport.** `portal/portal-ui/Cargo.toml` depends only on axum/leptos/serde/ryuki-core — no reqwest/hyper-client/gloo. `portal/portal-ui/src/api_client.rs` defines typed `ApiResource<T>` wrappers whose only behavior is `decode_json()` over a body that is never fetched. `portal/portal-ui/src/main.rs` mounts no `/api` proxy; only `/healthz`, `/readyz`, and the Leptos routes exist.
- **All reads are fallbacks.** Every `#[server(prefix = "/portal/api")]` fn in `portal/portal-ui/src/server_boundary.rs:929-1151` (9 workspace snapshots, `get_request_list`, `get_request_detail`, `get_platform_health`, `get_auth_session`, `get_admin_rbac_roles`, `get_admin_platform_settings`, ...) constructs `PortalServerBoundary::static_dry_run()` and returns static data with `http_request_allowed: false`, `provider_calls_allowed: false`, `live_execution_allowed: false` hardcoded (e.g. `server_boundary.rs:251-271`, `393-397`, `455-457`).
- **All mutations are stubs.** `create_request`, `validate_request`, `plan_request`, `approve_request`, `lock_request`, `execute_request`, `verify_request` (`server_boundary.rs:1153-1247`) unconditionally call `reject_static_preview_request_create`/`reject_static_preview_request_action`. The UI is already fully wired to them — six `Action`s in `views/request_detail.rs:59-189` and the submit action in `views/request_create.rs` — so every button's only outcome is a red error badge. The matching live routes exist exactly: `/api/requests`, `/api/requests/{id}/validate|plan|approve|lock|execute|verify` (`sources/ryuki-api/src/contracts.rs:109-117`, table `migrations/003_requests.sql`).
- **Auth is theater.** `shell.rs:8-10` returns `true`; `app.rs:31-40` therefore never renders `LoginView` (dead code); `perform_login` (`server_boundary.rs:1097-1115`) fabricates `mock-session-id`. The real stack exists: `POST /api/auth/login` persists sessions (`contracts.rs:6100-6140`), `migrations/004_sessions.sql` (24h expiry), and `ryuki-api` already accepts `X-Session-Id` or `Authorization: Bearer <uuid>` (`sources/ryuki-api/src/main.rs:111-141`).
- **Allowlist parity holds, but nothing enforces it.** All 50 entries in `ALLOWED_PORTAL_API_PATHS` (`server_boundary.rs:77-128`) resolve to registered routes: the `/api/operations/*-contract` paths (`contracts.rs:591-630`), `/api/catalog/site-catalog-contract` (`contracts.rs:177`), `/api/catalog/secret-references` (`contracts.rs:195`), all 9 `/api/datacenter/*-contract` paths (`contracts.rs:1462-1494`), and `/api/boundary/status` (`boundary.rs:5`). The correspondence is hand-maintained, however — no test or validator parses the portal's path constants (`portal/portal-ui/src/api.rs`) against the router, so drift on either side would surface only as a runtime 404.
- **Zero portal surface for whole domains.** `/api/protect` (67 routes), `/api/identity` (47), `/api/maintain` (42), `/api/ops` (39), `/api/build` (35), `/api/network` (33), `/api/observe` (22), `/api/monitoring` (22), `/api/analytics` (18), `/api/audit` (12), `/api/retire` (10), `/api/vm` (5) have no UI; `views/mod.rs` has 6 modules. Backing schema exists (`migrations/005-043`: `patch_waves`, `decommissions`, `legal_holds`, `oob_access`, `shift_queue`, `monitoring_queue`, ...).
- **No routing.** `leptos_router` is absent from `Cargo.toml`; nav hrefs are `#dashboard`-style fragments (`workspace_catalog.rs:55-110`); `Shell` renders `DashboardView` plus every workspace panel simultaneously (`shell.rs:250-251`); request list/detail/create switching is an in-memory `create_signal(RequestsView::List)` (`views/workspaces.rs:309-354`) — refresh loses state, and an approver cannot be linked to a pending request.
- **Disabled chrome.** Global search input `disabled=true` (`shell.rs:170-178`) with no backing endpoint (only `/api/admin/sites/search` exists, `contracts.rs:1101`); admin save/reset rejected (`server_boundary.rs:1037-1077`) despite live `PUT /api/admin/platform-settings` (`contracts.rs:1121-1128`); logo upload `disabled=true` "coming in next release" (`views/workspaces.rs:1525-1545`) while `docs/configuration.md:125` claims it works; scope pills hardcoded `"Site: Global"` / `"Env: Production"` / frozen freshness strings (`server_boundary.rs:441-454`); the intake form renders "Request submission available in next release" (`views/workspaces.rs:218-224`); `PortalDatacenterReadinessSnapshot` (`server_boundary.rs:621-698`) plus 9 `ApiResource` constructors (`api_client.rs:121-170`) are dead code — the `/api/datacenter/*-contract` routes they target are registered (`contracts.rs:1462-1494`) but never fetched.

### Design

#### F1. Live API transport with execution-mode switching

**Goal.** Portal server functions call `ryuki-api` over HTTP when configured live, and keep today's static snapshots as an explicit offline/demo mode — never as silent fallback for errors.

**Data model.** None.

**Engine changes.** None (uses `ryuki_core::types::ExecutionMode`, which already has the `LiveProvider` variant).

**API endpoints.** No new routes; consumes existing ones.

**Portal UI / server boundary.**
- `portal/portal-ui/Cargo.toml`: add `reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"], optional = true }` to the `ssr` feature. HTTP happens only inside `#[server]` fns (server-to-server), preserving `browserProviderCallsAllowed: false` and the CSP `connect-src 'self'` in `main.rs` untouched.
- New `portal/portal-ui/src/upstream.rs` (ssr-only): `UpstreamClient { base_url: Url, http: reqwest::Client }` built from env `RYUKI_API_URL` (e.g. `http://ryuki-api:8081`) and `RYUKI_PORTAL_EXECUTION_MODE` (`static-dry-run` default | `live-provider`), provided via Axum state in `main.rs` and recovered in server fns with `leptos_axum::extract`. Every call validates the path through the existing `PortalServerBoundary::validate_platform_api_path` / `validate_request_lifecycle_api_path` allowlist guard *before* dispatch — the allowlist remains the SSRF/raw-data boundary.
- Replace the unconditional `PortalServerBoundary::static_dry_run()` constructor calls in `server_boundary.rs:929-1151` with `PortalServerBoundary::from_runtime_mode(mode)`; in `LiveProvider` mode, `http_request_allowed: true` is reported truthfully in `PortalPlatformReadPlan`/`BoundaryStatus` snapshots, and reads deserialize the upstream JSON via the existing `ApiResource::decode_json` so the typed safe-summary contract in `api_client.rs` finally earns its keep. In `StaticDryRun` mode behavior is byte-identical to today.
- Upstream failures map to the existing `PortalSafeFailure` pattern (`server_boundary.rs:288-296`): safe summary message, no stack traces, no raw payloads — never degrade to fallback data, which would fake health.

**Validation & evidence.** Unit tests pin both modes: static mode returns fallbacks with all `*_allowed: false`; live mode against a mock Axum server asserts path-allowlist enforcement and that non-allowlisted paths are refused before any socket is opened. Boundary snapshot (`/portal/api/boundary-status`) becomes the runtime evidence of which mode is active.

**Safety/dry-run.** Default mode stays `static-dry-run`; the GitHub Pages / demo deployment keeps working with zero config. Live mode requires explicit env opt-in, matching the repo's "dry-run by default, approval-gated live execution" convention.

#### F2. Allowlist route parity: enforce it in CI

**Goal.** Every constant in `portal/portal-ui/src/api.rs` resolves to a real `ryuki-api` route, enforced by CI forever. Parity holds today (verified constant-by-constant against the router), but only by hand-maintained convention.

**Data model.** None.

**Engine changes.** None.

**API endpoints.** Publish the route manifest: extract the router construction in `sources/ryuki-api/src/contracts.rs` so a `pub fn route_manifest() -> &'static [(Method, &'static str)]` (or a `routes.json` emitted by a `#[test]`) lists every registered path.

**Portal UI.** No deletions or remaps are needed — every existing constant in `api.rs` already resolves to a registered route (e.g. `/api/operations/activity-queue-contract` at `contracts.rs:630`, `/api/operations/runbook-launch-contract` at `:591`, `/api/operations/emergency-change-contract` at `:599`, `/api/catalog/site-catalog-contract` at `:177`, `/api/catalog/secret-references` at `:195`, the 9 `/api/datacenter/*-contract` paths at `:1462-1494`). The work is wiring: feed the constants, `ALLOWED_PORTAL_API_PATHS` (`server_boundary.rs:77-128`), and the `workspace_catalog.rs` `primary_api_path`/`secondary_api_path` values into the parity check so future additions on either side cannot drift.

**Validation & evidence.** New validator in `scripts/validator-rs/src/` (`portal_route_parity.rs`): parses portal path constants and asserts membership in the `ryuki-api` route manifest; wired into the existing validator run so a phantom path is a CI failure, not a latent 404.

**Safety/dry-run.** Pure reconciliation; no behavior change in static mode.

#### F3. Real authentication and session forwarding

**Goal.** `LoginView` becomes live code; the session created by `/api/auth/login` (persisted in `migrations/004_sessions.sql`) gates the shell and rides on every upstream call.

**Data model.** None new (sessions table exists). Optional follow-up: index on `sessions(expires_at)` for cleanup.

**Engine changes.** None — `ryuki-api` already binds persisted sessions via `X-Session-Id`/`Bearer <uuid>` (`sources/ryuki-api/src/main.rs:111-141`, commit `6afe852`).

**API endpoints.** Existing `/api/auth/login`, `/api/auth/session`, `/api/auth/logout` (`contracts.rs:1115-1119`).

**Portal UI.**
- `perform_login` (`server_boundary.rs:1097-1115`): POST upstream `/api/auth/login`; on success set an `HttpOnly; Secure; SameSite=Strict` cookie `ryuki_portal_session=<uuid>` via `leptos_axum::ResponseOptions`. The session id never reaches WASM.
- `get_auth_session`: read the cookie, GET upstream `/api/auth/session` with `X-Session-Id`, return the real `AuthSession`; on missing/expired session return unauthenticated. Delete `auth_session_fallback()`'s always-PlatformAdmin behavior in live mode so `role_satisfies` gating in `workspace_catalog.rs:39-53` reflects reality.
- `shell.rs::is_authenticated()` becomes a server-derived signal (SSR reads the cookie); `app.rs:40` then actually renders `LoginView` for anonymous users. `perform_logout` forwards to `/api/auth/logout` with the session id in the body (its expected shape, `contracts.rs:6142-6178`) and clears the cookie.
- `upstream.rs` gains `with_session(&self, session_id)` so every server fn attaches `X-Session-Id`.

**Validation & evidence.** Integration test: login → cookie set → `get_auth_session` round-trips the persisted row → logout deletes it. Evidence: auth events already logged server-side via the safe `AuthLogFields` metadata (`main.rs:54-67`).

**Safety/dry-run.** In static mode the portal keeps a clearly-labeled synthetic session (current behavior) but `LoginView` still renders first so the flow is demonstrable. Cookie attributes prevent token leakage to the browser context; no secrets in localStorage.

#### F4. Request lifecycle mutations go live

**Goal.** The seven already-wired UI actions perform real state transitions — the single highest-leverage fix in the repo, since both sides exist and only the stubs separate them.

**Data model.** None (`migrations/003_requests.sql`).

**Engine changes.** None — lifecycle guards were just hardened (`841e68f`, `90228ea`).

**API endpoints.** Existing: `POST /api/requests`, `POST /api/requests/{id}/validate|plan|approve|lock|execute|verify`, `GET /api/requests`, `GET /api/requests/{id}` (`contracts.rs:109-117`).

**Portal UI.** In `server_boundary.rs:1153-1247`, replace `reject_static_preview_request_create`/`reject_static_preview_request_action` with mode-gated dispatch: `StaticDryRun` keeps today's preview rejection verbatim; `LiveProvider` POSTs upstream with the session header and maps responses (including 409 lifecycle-guard violations and 403 role failures) into `StageActionResponse { success, message, ... }` (`models.rs:1011`). `get_request_list`/`get_request_detail` (`server_boundary.rs:1133-1151`) fetch live rows. `views/request_detail.rs` and `views/request_create.rs` need no structural change — they already render success/failure badges.

**Validation & evidence.** End-to-end test driving a request Draft→Completed through the portal server fns against a test `ryuki-api` + Postgres; assert each transition is persisted and each guard violation surfaces as a safe message. Evidence trail is the API's existing request history.

**Safety/dry-run.** Execute/verify remain whatever the API enforces (approval-gated, drift-validated per `90228ea`); the portal adds no bypass. Static mode unchanged.

#### F5. URL routing and deep linking

**Goal.** Every workspace and every request is addressable; an approver can be sent `/requests/REQ-1234` and land on the approve button.

**Data model / engine / API.** None.

**Portal UI.**
- Add `leptos_router = "0.8"` to `Cargo.toml` (hydrate + ssr features). In `app.rs`, wrap `Shell` in `<Router>` and define routes: `/` (dashboard), `/catalog`, `/requests`, `/requests/new`, `/requests/:id`, `/activity`, `/inventory`, `/cmdb`, `/evidence`, `/operations` (+ nested per F7), `/admin` (+ nested), `/search`, `/login`.
- `shell.rs` becomes the layout (topbar/nav/context strip + `<Outlet/>`); the always-render-everything block at `shell.rs:250-251` and the `RequestsView` signal state machine (`views/workspaces.rs:305-360`) are deleted — `RequestList`/`RequestDetail`/`RequestCreate` take params from `use_params`, callbacks become `<A>` navigations.
- Replace `#fragment` hrefs in `workspace_catalog.rs:55-110` with the paths above; nav `active` becomes route-derived instead of a static bool. `main.rs` already calls `leptos_axum::generate_route_list(App)`, so SSR picks the routes up automatically.
- `PortalRouteStateSnapshot` (`server_boundary.rs:441-443`) reports the actual matched route instead of the literal `"#dashboard"`/`"static-shell-route"`.

**Validation & evidence.** SSR tests asserting direct GETs of `/requests/:id` render the detail (no client redirect), and that role-gated routes 403/redirect for insufficient roles — `stable-navigation-required` review evidence per `catalog/portal-information-architecture-contract.yaml:127-130`.

**Safety/dry-run.** Pure navigation; works identically in both modes.

#### F6. Domain coverage: Protect, Maintain, Retire, Ops, Analytics, Identity, Network, Observe, VM, Audit

**Goal.** The roadmap stages (Protect/Publish/Maintain/Retire) and the other ~350 route-strong domains get read-first portal surfaces, without violating the IA contract's frozen 9-item primary nav.

**Constraint.** `portal-information-architecture-contract.yaml:127-130` (`stable-navigation-required`, decision: block) freezes Dashboard/Catalog/Requests/Activity/Inventory/CMDB/Evidence/Operations/Admin. New domains therefore mount as **sub-routes of existing nav items**, not new top-level entries: `/operations/runbooks|shift|emergency|incidents` (`/api/ops/*`), `/operations/protect` (DR readiness, legal holds, rotation — `/api/protect/*`, tables `migrations/007`, `026`, `037`), `/operations/maintain` (patch waves, baselines, certificates — `/api/maintain/*`, `migrations/010`, `011`, `024`, `032`), `/operations/retire` (`/api/retire/*`, `migrations/012`), `/inventory/network` (`/api/network/*`, `migrations/019`), `/inventory/vm` (`/api/vm/*`, `migrations/005`, `006`), `/inventory/analytics` (`/api/analytics/*`, `migrations/021`), `/evidence/audit` (`/api/audit/compliance/*`), `/admin/identity` (`/api/identity/*` AD/gMSA/access reviews, `migrations/018`, `020`, `030`), `/dashboard` gains observe/monitoring tiles (`/api/observe/*`, `/api/monitoring/*`, `migrations/031`).

**Data model / engine.** None — read views over existing routes and tables.

**API endpoints.** Existing; portal adds the corresponding constants to `api.rs` and entries to `ALLOWED_PORTAL_API_PATHS`.

**Portal UI.** New modules `views/ops.rs`, `views/protect.rs`, `views/maintain.rs`, `views/retire.rs`, `views/network.rs`, `views/vm.rs`, `views/analytics.rs`, `views/identity.rs`, `views/audit.rs`, each following the established snapshot pattern (typed model in `models.rs`, `#[server]` loader in `server_boundary.rs`, `Suspense`-wrapped table/card view). Secondary-nav tabs within Operations/Inventory/Admin route to them. Mutating flows (patch approve/execute, decommission, emergency change) reuse the request-lifecycle action pattern from F4 and are explicitly phase-2 per domain — read views first.

**Validation & evidence.** The F2 parity validator covers all new constants; per-view SSR smoke tests; coverage metric in the validator report: count of `/api` route prefixes with at least one portal consumer (target: every top-level domain ≥1 read view).

**Safety/dry-run.** Each new snapshot carries the same `*_allowed` boundary flags; static mode ships representative fallbacks so demos still render.

#### F7. Functional workspaces: catalog browser, CMDB exchange, activity actions, admin

**Goal.** The 8 descriptive cards in `views/workspaces.rs:205-263` become working surfaces.

- **Catalog**: browse all 116 contracts in `catalog/` (vs the 3 hardcoded entries in `models.rs::catalog_contract_fallbacks`) via the real `GET /api/catalog/offerings-contract` + `GET /api/catalog/categories`; "Request this" deep-links to `/requests/new?offering=...`. Remove the "Request submission available in next release" blocker (`views/workspaces.rs:218-224`) once F4 lands.
- **CMDB**: wire import preview / export / reconcile buttons to `POST /api/cmdb/import`, `GET /api/cmdb/export`, `POST /api/cmdb/reconcile` (`contracts.rs:1029-1031`, `migrations/014_cmdb_impact.sql`), surfacing accepted/rejected counts.
- **Activity**: live queue from `/api/ops/shift/summary`, `/api/ops/shift/handover`, `/api/ops/runbook/executions`; acknowledge/assign/escalate/resolve actions to `/api/ops/shift/*` (`contracts.rs:606-614`, `migrations/029_shift_queue.sql`).
- **Admin — settings**: replace `reject_static_preview_platform_settings_save/reset` (`server_boundary.rs:1037-1077`) with upstream `PUT /api/admin/platform-settings` and `POST .../reset` (verified-admin enforcement already server-side per `7172ea8`, table `migrations/001_platform_config.sql`).
- **Admin — sites**: new panel listing/searching/activating sites via `/api/admin/sites`, `/api/admin/sites/{unlocode}`, `.../activate|deactivate`, `/api/admin/sites/search` (`contracts.rs:1086-1101`, engine `sources/ryuki-engine/src/site_registry.rs`) — currently zero portal counterpart.
- **Admin — branding**: new backend `POST /api/admin/branding/logo` (multipart, size/type-validated PNG/JPEG/SVG with SVG sanitization) + `GET /api/branding/logo` in `contracts.rs`; **migration `migrations/044_branding_assets.sql`** (`branding_assets(id, content_type, bytes BYTEA, updated_by, updated_at)` — single-row table; DB storage keeps the no-shared-filesystem deployment simple). Enable the input at `views/workspaces.rs:1535-1539`; until then `docs/configuration.md:125` is false advertising and must be corrected in the same PR that ships this.

**Validation & evidence.** CMDB import/reconcile results render the API's accepted/rejected evidence counts; admin saves echo the persisted config; branding endpoint gets content-type/size negative tests.

**Safety/dry-run.** All mutations mode-gated as in F4; admin writes additionally require the verified-admin session the API enforces.

#### F8. Global search / command palette

**Goal.** The disabled topbar input (`shell.rs:170-178`) becomes the IA contract's required `global-search-command-palette` surface (`portal-information-architecture-contract.yaml:35,66`).

**Data model.** **Migration `migrations/045_search_indexes.sql`**: generated `tsvector` column + GIN index on `requests` (title/summary/stage), and `pg_trgm` indexes on site registry name fields and CMDB CI names as they land; extendable enum of searchable entity kinds.

**Engine changes.** New `sources/ryuki-engine/src/search.rs`: fan-out query over requests, sites (reusing `site_registry.rs` search), CIs, and evidence manifests; returns `SearchHit { entity_kind, entity_id, title, status, route_hint, safe_summary }` — summaries only, honoring `rawSearchRowsAllowed: false`.

**API endpoints.** `GET /api/search?q=&kinds=&limit=` in `contracts.rs`, session-gated, results filtered by the caller's roles.

**Portal UI.** Enable the input; add `search_portal(q)` server fn + allowlist entry; results dropdown/page at `/search` whose hits deep-link via F5 routes (`/requests/:id`, `/admin/sites/:unlocode`). Keyboard palette (Cmd-K) is a follow-up layered on the same endpoint.

**Validation & evidence.** Endpoint tests assert no raw rows/identifiers beyond the safe-summary shape; `searchPaletteSummary` review evidence per the IA contract.

**Safety/dry-run.** Static mode: input enabled but returns a labeled synthetic result set, so the surface is demonstrable offline.

#### F9. Scope, identity, and freshness context

**Goal.** The hardcoded pills (`server_boundary.rs:441-454`) become real: site/env scope pickers, the true session identity, and live freshness.

**Data model.** **Migration `migrations/046_user_preferences.sql`**: `user_preferences(user_id TEXT PRIMARY KEY, default_site TEXT, default_environment TEXT, theme TEXT, updated_at TIMESTAMPTZ)`.

**Engine changes.** Minor: preference read/write helpers; freshness sourced from existing inventory/monitoring/backup status routes.

**API endpoints.** `GET/PUT /api/auth/preferences` (session-bound); scope options from existing `/api/admin/sites`.

**Portal UI.** Site/env `<select>` pickers in `shell.rs` topbar backed by a `load_scope_options` server fn; selected scope stored in preferences and threaded through snapshot loaders as a query param so domain views filter by site (most `/api/analytics/*` handlers already accept `?site=`). Role pill and `role_satisfies` gating driven by the real session (F3) instead of `auth_session_fallback()`'s permanent PlatformAdmin (`models.rs:758-764`). Freshness labels computed from live endpoints, replacing the frozen "Inventory 6m ago"/"Monitoring stale" strings. Profile menu: display name, roles, theme (migrating the localStorage-only toggle), logout.

**Validation & evidence.** Satisfies the IA contract's `selector-scope-readiness` surface and `scope-selector-reviewed` guard (`portal-information-architecture-contract.yaml:36,75,131-134` — scope must be visible before risky workflows render ready).

**Safety/dry-run.** Static mode keeps labeled synthetic scope; preferences writes are mode-gated.

#### F10. Datacenter readiness: finish it or delete it

**Goal.** Resolve the dead `PortalDatacenterReadinessSnapshot` (`server_boundary.rs:621-698`) and its 9 unused `ApiResource`s (`api_client.rs:121-170`) over 9 registered-but-never-fetched `-contract` routes.

**Decision: finish it** — site readiness is core to a multi-site platform and the data exists (`migrations/040_datacenter_readiness.sql`, `019_network_readiness.sql`, `027_oob_access.sql`; engine datacenter/oob modules; real `/api/datacenter/firmware|hardware|network|oob|storage` routes).

**API endpoints.** New aggregation routes in `contracts.rs`: `GET /api/datacenter/readiness` (score + per-check summary per site) and `GET /api/datacenter/readiness/{unlocode}` (failing checks: power, cooling, rack space, switchports), composed in a new `sources/ryuki-engine` readiness aggregator over the existing per-domain data. Optionally collapse the portal's 9 per-check `-contract` constants in `api.rs` (all registered at `contracts.rs:1462-1494`, but never fetched) onto these 2 aggregate paths.

**Portal UI.** `views/datacenter.rs` mounted at `/inventory/datacenter` (stable-nav compliant), nav tab in the Inventory workspace, `#[server] load_portal_datacenter_readiness` finally exposing the snapshot; deep-links from the dashboard's existing "Datacenter" table cell (`views/dashboard.rs:1384`).

**Validation & evidence.** Covered by the F2 parity validator; readiness scores cite check-level evidence rows.

**Safety/dry-run.** Read-only; static fallbacks retained.

### Implementation plan

1. **(S)** F2: publish the `ryuki-api` route manifest and add the `scripts/validator-rs` route-parity check covering `portal/portal-ui/src/api.rs` + `ALLOWED_PORTAL_API_PATHS` (parity currently holds; the check locks it in). Unblocks everything; no behavior change.
2. **(M)** F1: `reqwest` behind `ssr`, `upstream.rs` client, `RYUKI_API_URL`/`RYUKI_PORTAL_EXECUTION_MODE` plumbing in `main.rs`, mode-aware `PortalServerBoundary`, truthful boundary flags, safe-failure mapping.
3. **(M)** F3: live login/session/logout, `ryuki_portal_session` cookie, real `get_auth_session`, kill `is_authenticated() == true`, resurrect `LoginView`.
4. **(S)** F4: swap the seven `reject_static_preview_*` stubs for mode-gated upstream calls; live `get_request_list`/`get_request_detail`. The core product loop is now operable end-to-end — ship a milestone here.
5. **(M)** F5: `leptos_router`, route table, shell-as-layout, delete the `RequestsView` signal machine, deep-linkable `/requests/:id`.
6. **(S)** F7-admin-settings: wire save/reset to `PUT /api/admin/platform-settings`; correct or implement the `docs/configuration.md:125` logo claim (decide in step 9).
7. **(M)** F7-catalog + F7-CMDB + F7-activity: live offerings browser, import/export/reconcile actions, shift-queue actions; remove the intake "next release" blocker.
8. **(M)** F9: scope pickers, real role gating, live freshness, `046_user_preferences.sql`, profile menu.
9. **(M)** F7-admin-sites + F7-branding: sites panel over `/api/admin/sites*`; branding endpoint + `044_branding_assets.sql` + enable upload input.
10. **(M)** F8: `045_search_indexes.sql`, engine `search.rs`, `GET /api/search`, enabled topbar search + `/search` results view.
11. **(L)** F6: domain read views (ops, protect, maintain, retire, network, vm, analytics, identity, audit, observe/monitoring tiles), one domain per PR, secondary nav under the stable 9 items.
12. **(M)** F10: datacenter readiness aggregation endpoints + `/inventory/datacenter` view; delete whatever the snapshot kept that the view doesn't use.
13. **(S)** Sweep: update IA-contract review evidence (`requiredGuards` in `catalog/portal-information-architecture-contract.yaml`), refresh `docs/`, confirm static-mode demo parity.

### Risks & open questions

- **Deployment topology.** Is the portal expected to reach `ryuki-api` server-side only (this design), or should `main.rs` also reverse-proxy `/api/*` for future client-side fetches? Server-side-only is safer (keeps `browserProviderCallsAllowed: false` and CSP `connect-src 'self'` intact) and is what the `#[server]` architecture implies — but it makes the portal a hard runtime dependency of the API; health endpoints (`/readyz`) should reflect upstream reachability in live mode.
- **Static demo regression.** ryuki.io is served from GitHub Pages off `main`; every feature must keep `static-dry-run` mode rendering credibly. Mitigation: mode-gated dispatch everywhere plus a CI job that builds and snapshot-tests the static mode.
- **Session strength.** Sessions are bare UUIDs with 24h expiry and no rotation/CSRF story beyond `SameSite=Strict`; fine for `MockDryRun`/`Local`, but the EntraId path (`auth_session_for_request`, `main.rs:70-79`) needs review before live mutations are exposed to real tenants. Open question: should portal server fns require `AuthMode::EntraId` for `LiveProvider` mode?
- **IA contract vs growth.** The blocking `stable-navigation-required` rule constrains F6 to sub-navigation. If Protect/Maintain/Retire deserve top-level presence as the roadmap matures, the contract itself must be versioned (it is `status: draft`) — who owns that decision?
- **Fallback divergence.** Keeping fallbacks for static mode means two render paths per view; without the parity validator and shared model types they will drift. The typed `ApiResource<T>` decode path mitigates this only if live responses actually deserialize into the same `models.rs` structs — the API's ad-hoc `json!` handlers (e.g. `analytics_cost_capacity`) may need response-shape tightening per domain.
- **Scope of F6.** ~616 routes cannot all get UI in one phase; the proposed read-first, one-domain-per-PR slicing needs explicit prioritization — suggested order: ops/shift (daily operator value), maintain/patch, protect/DR, retire, then analytics/identity/network.
- **Branding storage.** BYTEA-in-Postgres is proposed for simplicity; if logos must serve at high volume or the DB is shared, object storage may be preferable — but that introduces the platform's first blob-store dependency. Decision needed before step 9.

---

## Deployability, CI/CD & release engineering

Ryuki cannot currently be built as a container, shipped as a release, or operated in the Kubernetes topology it ships manifests for. Both application Dockerfiles fail at `cargo metadata` because they copy only a subset of the workspace (verified empirically: `sources/ryuki-api/Dockerfile` omits `portal/`, `scripts/`, and `tests/`; `portal/portal-ui/Dockerfile` omits `scripts/` and `tests/`), which transitively kills `make compose-up`, the Azure `BuildImages` stage, and the K8s deployments that reference never-built images. The only GitHub Actions workflow is the docs Pages deploy (`.github/workflows/static.yml`), so nothing gates `main` — broken code, failing tests, or committed secrets land directly on the live site, while the real pipeline definition sits unregistered in Azure DevOps syntax at `deploy/ci/azure-pipelines.yml`. The K8s `platform-api` Deployment has zero env/Secret wiring and the namespace-wide default-deny NetworkPolicies have no rule allowing the API to reach its own CNPG database, so the two halves of the committed deployment are mutually unusable. There are no tags, no changelog, no semver discipline, no API version prefix; the control-plane DB backup points at `s3://placeholder-bucket/` with no restore procedure; and the app tier is single-replica with no PDB. For a platform whose entire pitch is governed, evidence-backed infrastructure change — and which ships its own draft release-promotion contract (`catalog/platform-release-promotion-contract.yaml`) — the absence of any executable release machinery for itself is the most credibility-damaging gap in the repo. This theme is P0 because every other design theme depends on being able to build, gate, version, deploy, and restore the platform.

### Current state

- **CI**: `.github/workflows/static.yml` is the sole workflow (deploys `./docs` to Pages on push to `main`). All build/test/lint/secret-scan/image stages live in `deploy/ci/azure-pipelines.yml` — Azure DevOps syntax (`stages`/`pool`/`vmImage`), three stages (`BuildTest` with Rust/Security/Lint jobs, `BuildImages`, `PushImages`), no registration evidence. `deploy/ci/README.md:3` mislabels it a "GitHub Actions pipeline" and `:43` says to configure "GitHub Actions secrets". `tests/ci_integration_test.rs` asserts the pipeline YAML's structure but only runs when someone runs `cargo test` locally.
- **Container images**: `sources/ryuki-api/Dockerfile:6-9` copies `Cargo.toml Cargo.lock sources/` only; `portal/portal-ui/Dockerfile:9-13` adds `portal/` but not `scripts/`. Root `Cargo.toml:3-9` declares five workspace members including `portal/portal-ui` and `scripts/validator-rs`, plus five `[[test]]` targets under `tests/` (`Cargo.toml:18-36`), so both builds fail with "failed to load manifest for workspace member". `deploy/ci/Dockerfile.validator` copies a bare `Cargo.toml` + `src/` that cannot resolve its `workspace = true` deps or the `ryuki-core` path dep, and nothing references it.
- **K8s config**: `deploy/kubernetes/base/deployments.yaml:60-100` — the `platform-api` container has no `env`, `envFrom`, or volume mounts; `deploy/kubernetes/base/` contains no ConfigMap/Secret manifests. `sources/ryuki-core/src/config.rs:1002` defaults `database_url` to `postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform`; on connect failure `sources/ryuki-api/src/database.rs:94-96` falls back to in-memory stores and `/ready` (`main.rs:811-824`) returns `DatabaseUnavailable` — the pod runs forever NotReady, silently stateless.
- **NetworkPolicies**: `deploy/kubernetes/base/networkpolicies.yaml` ships `default-deny-ingress` and `default-deny-egress` for all pods; the only egress allows are portal-ui→platform-api:8080 and all-pods→kube-dns:53. No path to the CNPG cluster (`deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml`, same `ryuki-platform` namespace) on 5432 in either direction.
- **Releases**: all five crates are `0.1.0`; zero git tags local or remote; no CHANGELOG. The Kubernetes base now uses non-resolving `registry.example.invalid/...@sha256:<placeholder>` references and rejects mutable/unqualified final renders, but no adopted registry, release digest, signature, or running-image evidence exists. `x-api-version: 0.1.0` is hardcoded at `sources/ryuki-api/src/main.rs:546-548`; all 616 API routes are unversioned (no `/v1`). `catalog/platform-release-promotion-contract.yaml` defines the full promotion process on paper (`dev-render` → `rollback-readiness`, validation signals `helm-lint`/`kustomize-build-render`) but is `status: draft` with `registryPushAllowed`/`helmUpgradeAllowed`/`kubectlApplyAllowed` all `false` and nothing to lint or render.
- **Backup/DR**: CNPG Barman config points at `s3://placeholder-bucket/` / `https://placeholder-s3-endpoint.invalid` (`cnpg-cluster.yaml:57-68`); no `ScheduledBackup`/`Backup` resource anywhere; no restore/PITR/DR document anywhere in `deploy/`, `docs/`, or `catalog/`; compose persists to a bare `pgdata` volume. `RYUKI_RETENTION__*` parses into `AppConfig` and is echoed in the config snapshot (`sources/ryuki-api/src/config.rs:132-137`) but drives nothing. `catalog/platform-database-readiness-contract.yaml` self-acknowledges: `backupExecutionAllowed: false`, `restoreExecutionAllowed: false`.
- **HA & upgrades**: both Deployments `replicas: 1`, no PDB/HPA/anti-affinity/topology spread (the only PDB in the repo is Vault's, `deploy/kubernetes/vault/values-ha-raft.yaml:41`); the data tier is deliberately HA (CNPG `instances: 3`, required anti-affinity). 42 migration files (001–043, 002 absent), zero `.down.sql`; migrations run only at API boot via `sqlx::migrate!("../../migrations")` (`database.rs:69-71`), failure sets `MigrationStatus::Failed` and the process keeps running NotReady. No migrate CLI, no pre-upgrade Job, no Makefile `migrate` target.
- **Packaging & supply chain**: no `kustomization.yaml` or `Chart.yaml` anywhere; READMEs defer registry/host/TLS/S3 values to a "deployment-time overlay" that has no mechanism; `BuildProvider::ArgoCD` exists in `ryuki-core/src/config.rs` with no Application manifest. No dependabot/renovate, no `deny.toml`/cargo-audit, no trivy/syft/cosign. Ingress references `secretName: platform-tls-placeholder` for `platform.example.invalid` with no cert-manager resources. The Makefile exposes nine targets (stale `.PHONY` line declares a nonexistent `run`), none for docker builds, migrations, backup, release, or k8s apply.

### Design

#### F1. Buildable container images (P0, prerequisite for everything else)

- **Goal**: `docker build -f sources/ryuki-api/Dockerfile .` and `docker build -f portal/portal-ui/Dockerfile .` succeed from the repo root; `make compose-up` works end-to-end; the validator image either builds or is deleted.
- **Changes**: extend the COPY sets so the full workspace manifest graph resolves. For `sources/ryuki-api/Dockerfile`: `COPY Cargo.toml Cargo.lock ./`, then `COPY sources/ sources/`, `COPY portal/ portal/`, `COPY scripts/validator-rs/ scripts/validator-rs/`, `COPY tests/ tests/` (the root `[[test]]` package makes `tests/` load-bearing for `cargo metadata`). Same for `portal/portal-ui/Dockerfile`. Adopt **cargo-chef** in both Dockerfiles (`chef prepare` → `chef cook --release` → `COPY . .` → build) so dependency layers cache and full-workspace COPY does not blow up rebuild times. Longer-term option (tracked, not blocking): move the root `[[test]]` targets into a dedicated `tests/ryuki-integration-tests` member crate so partial-context builds become possible again. Rewrite `deploy/ci/Dockerfile.validator` to build from the repo root with the full workspace (`cargo build --release -p ryuki-validator`) and reference it from the CI image job, or delete it.
- **Data model / engine / API / portal UI**: none.
- **Validation & evidence**: add `docker_image.rs` to `scripts/validator-rs/src/` (registered in the `run-all` dispatcher at `main.rs:2243`) asserting each Dockerfile's COPY set covers every `[workspace] members` path plus `tests/`; extend `tests/compose_integration_test.rs` to assert build contexts/dockerfile paths still match. CI (F2) builds both images on every PR — the real regression gate.
- **Safety/dry-run**: build-only; images keep `RYUKI_API_EXECUTION_MODE=static-dry-run` / `RYUKI_PORTAL_EXECUTION_MODE=static-dry-run` as their baked default so a freshly built image can never execute live changes.

#### F2. GitHub Actions CI gating main (P0)

- **Goal**: nothing reaches `main` (and therefore the live ryuki.io Pages site) without build, test, lint, secret-scan, validator, and image-build all passing.
- **Changes**: new `.github/workflows/ci.yml` on `push`/`pull_request` to `main`, porting the Azure stages 1:1:
  - `build-test`: `cargo build --workspace` + `cargo test --workspace` (rust-toolchain pinned to 1.88 to match the Dockerfiles; `Swatinem/rust-cache`).
  - `lint`: `cargo fmt --check --all` + `cargo clippy --workspace -- -D warnings`.
  - `security`: `./scripts/no-secret-scan.sh`.
  - `validate`: `cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all`.
  - `images`: `docker build` both Dockerfiles (depends on F1), no push.
  - Gate `static.yml` on CI: convert the Pages deploy to `workflow_run` on "CI" success for `main` (or merge it as a final `needs:`-gated job in `ci.yml`), and enable branch protection on `main` requiring the CI check. Note the user's push-after-every-commit workflow continues to work — pushes still land, but Pages only redeploys on green.
  - Resolve the Azure duplication: delete `deploy/ci/azure-pipelines.yml` (it has no registration evidence) and fix `deploy/ci/README.md:3,43`; rewrite `tests/ci_integration_test.rs` to assert the structure of `.github/workflows/ci.yml` instead (same pattern, different YAML shape), so the existing "tests assert the pipeline" convention is preserved against the pipeline that actually runs.
- **Data model / engine / API / portal UI**: none.
- **Validation & evidence**: `tests/ci_integration_test.rs` rewrite as above; CI run URLs become citable evidence for the `platform-release-promotion` contract's `approval-evidence-ready` signal (F5).
- **Safety/dry-run**: CI never deploys; only the Pages job publishes, and only docs.

#### F3. Kubernetes runtime configuration wiring + Vault Secrets Operator artifacts

- **Goal**: a `kubectl apply` of `deploy/kubernetes/` produces a platform-api pod that can actually find its database and a portal-ui pod that knows its API base URL — using the Vault delivery path the manifests already promise.
- **Changes**:
  - New `deploy/kubernetes/base/configmap.yaml`: `platform-api-config` ConfigMap carrying non-secret `RYUKI_*` settings (`RYUKI_SERVER__BIND_ADDRESS=0.0.0.0:8080`, `RYUKI_PLATFORM_URL`, retention knobs); a portal-ui entry for its API base URL.
  - New `deploy/kubernetes/vault/vso-secrets.yaml`: the trio `catalog/vault-secret-delivery-contract.yaml:109-112` already specifies — `VaultConnection`, `VaultAuth` (Kubernetes auth role bound to the existing `platform-api` ServiceAccount), and `VaultStaticSecret` resources materializing the three Secrets the CNPG manifest references (`ryuki-platform-db-superuser`, `ryuki-platform-db-app-user`, `ryuki-platform-db-backup-s3`) plus a `ryuki-platform-api-db` Secret containing `RYUKI_DATABASE_URL` pointing at `ryuki-platform-db-rw.ryuki-platform.svc:5432` (the CNPG `-rw` service). For clusters without VSO, document a plain-Secret fallback in `deploy/kubernetes/base/README.md` — never a committed credential (repo rule: never commit secrets).
  - Wire `envFrom: [configMapRef: platform-api-config, secretRef: ryuki-platform-api-db]` into the `platform-api` container in `deployments.yaml`; add the API base URL env to portal-ui.
  - Harden the failure mode: add `RYUKI_DATABASE__REQUIRED=true` (new field in `sources/ryuki-core/src/config.rs` `DatabaseConfig`) — when set, `try_connect_with_url` failure in `sources/ryuki-api/src/database.rs` exits non-zero instead of falling back to in-memory stores. Default `false` to preserve local dev; set `true` in the K8s ConfigMap and compose. This converts "runs forever NotReady, silently stateless" into a crash-loop that operators and probes actually see, and is a hard prerequisite for multi-replica (F6).
- **Data model**: none (config only). **Engine**: none. **API**: config-snapshot route already echoes config; no new endpoints. **Portal UI**: none.
- **Validation & evidence**: extend `tests/kubernetes_integration_test.rs` (existing `parse_multi_doc` helpers) with assertions that the platform-api container has `envFrom` and that referenced ConfigMap/Secret names exist in the manifest set; extend the vault-secret-delivery validator surface to check the VSO trio files exist and reference only the approved secret names.
- **Safety/dry-run**: manifests remain static artifacts; nothing in the repo applies them (consistent with `kubectlApplyAllowed: false` in the readiness contracts until F9's promotion path matures).

#### F4. NetworkPolicy database path

- **Goal**: the committed NetworkPolicy set and the committed CNPG cluster are usable together.
- **Changes** in `deploy/kubernetes/base/networkpolicies.yaml`, following the file's existing allow-pair style:
  - `allow-platform-api-egress-to-db`: egress from `app.kubernetes.io/name: platform-api` pods to pods labeled `cnpg.io/cluster: ryuki-platform-db` on TCP 5432.
  - `allow-ingress-to-db-from-platform-api`: the matching ingress allow on the CNPG pod selector (default-deny-ingress otherwise blocks the other side).
  - CNPG also needs operator/replication traffic: an intra-cluster allow between `cnpg.io/cluster: ryuki-platform-db` pods (5432 + 8000 status port) and ingress from the operator namespace — without it the 3-instance cluster itself cannot form under default-deny.
  - Stub (commented or annotated `# enabled with VSO`) egress to Vault:8200 from platform-api, activated alongside F3's VSO trio.
- **Validation & evidence**: extend `tests/kubernetes_integration_test.rs` to assert a TCP-5432 egress path exists for the platform-api pod selector and a matching ingress allow exists for the `cnpg.io/cluster` selector. Update `deploy/kubernetes/base/README.md:14`, which currently defers "database services, provider egress" to "later implementation slices".
- **Data model / engine / API / portal**: none. **Safety**: default-deny posture is preserved; every new rule is a narrow pod-selector pair.

#### F5. Release engineering: versioning, tags, changelog, release workflow, API version

- **Goal**: immutable, traceable releases — a `vX.Y.Z` tag deterministically produces signed, digest-pinned images and a changelog, and the running API reports its real version.
- **Changes**:
  - Adopt conventional commits + **git-cliff**; add `CHANGELOG.md` at root and `cliff.toml`.
  - New `.github/workflows/release.yml` triggered on `v*` tags: full CI gate → build both images → tag `ghcr.io/<owner>/ryuki-platform-api:{X.Y.Z, sha-<short>}` (GHCR until the Harbor registry of `catalog/registry-readiness-contract.yaml` is approved; the deploy README already flags the registry as unapproved) → generate SBOM + sign (F10) → `gh release create` with the git-cliff changelog section.
  - `x-api-version`: replace the literal at `sources/ryuki-api/src/main.rs:546-548` with `env!("CARGO_PKG_VERSION")`; additionally embed git SHA + build timestamp at build time (`option_env!("RYUKI_BUILD_SHA")`, set via Docker `ARG` in the release workflow).
  - **New API endpoint** `GET /api/platform/release` (registered alongside the existing `/api/platform/health` family in `contracts.rs:1158-1175`): returns `{version, gitSha, buildTimestamp, apiVersionHeader, migrationStatus}` — the platform's own observability surface for "what is running".
  - **API versioning decision**: do not mass-rewrite the 609 `contracts.rs` routes now. Commit to header-based versioning (`x-api-version` request/response) as the v0 contract, and add a router-level `nest("/api/v1", ...)` alias in `main.rs` that serves the same router so external consumers can adopt the stable prefix today; document that unprefixed `/api/*` paths are deprecated for external use. This is one `nest` call instead of 609 route edits and keeps the Leptos same-origin server functions untouched.
  - Replace the base's non-resolving digest placeholders through the F9 overlay with the exact release registry/repository/digest, and run the immutable-image validator against the final render. Tag-based overlays remain local Compose-only and are not admitted to Kubernetes.
  - Wire the `platform-release-promotion` contract: the release workflow uploads its run metadata (lint/test/image-digest results) as the contract's `manifestRenderSummary`/`approval-evidence-ready` inputs, moving the contract from `status: draft` toward an evidence-backed process without flipping any of its execution-allowed flags.
- **Data model**: optional `044_platform_releases.sql` — table `platform_releases (id, version, git_sha, image_digest_api, image_digest_portal, changelog_excerpt, released_at, evidence_ref)` so release history is queryable next to the rest of the governance data; populated manually/via API until promotion automation matures. **Engine**: none initially. **Portal UI**: surface version + git SHA in the portal footer/admin page (reads `/api/platform/release`).
- **Validation & evidence**: new `release_engineering.rs` validator checking crate versions are consistent across the workspace and `CHANGELOG.md` has an entry for the current version; `tests/ci_integration_test.rs` extended to cover `release.yml` structure.
- **Safety/dry-run**: releases publish artifacts only; deployment remains a separate, approval-gated act per the promotion contract.

#### F6. Control-plane database backup, restore, and DR

- **Goal**: the platform that governs other systems' backup coverage (`backup-coverage-gap`, `controlled-restore` contracts) has a real, tested backup of itself and a written restore path.
- **Changes**:
  - New `deploy/kubernetes/cloudnativepg/scheduled-backup.yaml`: CNPG `ScheduledBackup` (e.g. `0 0 2 * * *`) targeting cluster `ryuki-platform-db`, plus `retentionPolicy` on the cluster spec mapped from the `RYUKI_RETENTION__*` values so that config finally becomes load-bearing; real Barman `destinationPath`/`endpointURL` supplied by the F9 overlay (placeholder stays in base, matching the existing convention).
  - New `deploy/kubernetes/object-storage/README.md` + bucket-requirements skeleton matching `catalog/object-storage-readiness-contract.yaml` required inputs (backup target, immutability/retention posture) — this is the missing artifact that keeps the Barman target a placeholder.
  - New runbook `deploy/kubernetes/cloudnativepg/restore-runbook.md` (same style as `deploy/kubernetes/vault/bootstrap-runbook.md`): CNPG recovery bootstrap from object store, PITR via `recoveryTarget`, full-cluster-loss DR sequence, and a quarterly restore-test procedure that feeds the platform's own `restore-testing` evidence pattern.
  - Compose/dev: `make db-backup` target running `docker compose -f deploy/compose/compose.yaml exec platform-db pg_dump -U ryuki ryuki_platform > output/backup-$(date).sql` and a matching `db-restore`.
  - **API/observability**: extend the `/api/platform/health/components` payload with a `controlPlaneBackup` component (last ScheduledBackup status is deploy-time information, so v1 reports static "configured/unconfigured" from config; live CNPG status polling is deferred until the platform is allowed to read its own cluster).
- **Data model**: none required (retention config already parses). **Engine**: none. **Portal UI**: backup status chip on the existing platform health dashboard surface. 
- **Validation & evidence**: new `platform_backup_readiness.rs` validator asserting `scheduled-backup.yaml` exists, references the right cluster/secret names, and that the restore runbook file exists — directly implementing the `backup-archive-readiness`/`restore-test-readiness` surfaces already enumerated in `catalog/platform-database-readiness-contract.yaml`.
- **Safety/dry-run**: backups are read-only with respect to the DB; restore procedures are runbook-only (manual, approval-gated), consistent with `restoreExecutionAllowed: false` until a tested cadence exists.

#### F7. Application-tier HA

- **Goal**: the control plane survives a node drain, matching the deliberately-HA data tier (CNPG `instances: 3`, Vault HA Raft).
- **Changes**: in `deploy/kubernetes/base/deployments.yaml`: `replicas: 2` for both apps; `topologySpreadConstraints` on `kubernetes.io/hostname` (preferred, `maxSkew: 1`) — lighter than the CNPG-style required anti-affinity for small clusters. New `deploy/kubernetes/base/pdb.yaml`: `PodDisruptionBudget` with `minAvailable: 1` for `portal-ui` and `platform-api`. Multi-replica correctness prerequisites: F3's `RYUKI_DATABASE__REQUIRED=true` (two replicas on in-memory fallback would silently hold divergent state — this must fail hard in K8s); migrations move out of boot path per F8; document that sqlx's migrator advisory lock already serializes concurrent boot migrations as the interim story.
- **Data model / engine / API / portal**: none beyond F3's flag.
- **Validation & evidence**: extend `tests/kubernetes_integration_test.rs`: `replicas >= 2`, PDB present for both apps, spread constraints present.
- **Safety**: PDB protects voluntary disruptions only; rollout `maxUnavailable: 0` keeps one replica serving during upgrades.

#### F8. Migration & upgrade tooling

- **Goal**: schema changes are an explicit deploy step with a defined failure mode and a documented rollback story, not a side effect of API boot.
- **Changes**:
  - Add a `migrate` mode to `sources/ryuki-api/src/main.rs`: the binary currently parses no args; add a minimal `std::env::args` check (matching the validator's argument style at `scripts/validator-rs/src/main.rs:406`) — `ryuki-api migrate` connects, runs `run_migrations` (`database.rs:69`), prints applied versions, exits 0/1. No clap dependency needed.
  - New `deploy/kubernetes/base/migrate-job.yaml`: pre-upgrade `Job` running the same image with `args: ["migrate"]`, applied before the Deployment rollout in the upgrade runbook; NetworkPolicy from F4 covers it via a shared pod label.
  - Makefile: `migrate:` target (`cargo run --manifest-path sources/ryuki-api/Cargo.toml -- migrate`).
  - **Rollback policy decision**: adopt forward-only migrations as explicit policy (`migrations/README.md`), documented to depend on F6's restore path for true rollback; require every destructive migration to ship in two releases (expand/contract). This matches reality better than retrofitting 42 `.down.sql` files of uncertain correctness.
  - New `deploy/kubernetes/base/upgrade-runbook.md`: image bump → migrate Job → rollout → verify `/ready` → rollback sequence (previous image digest + restore pointer).
- **Data model**: no new tables; `sqlx::migrate!` metadata table is the source of truth. **API**: `/api/platform/release` (F5) already exposes `migrationStatus`. **Portal**: none.
- **Validation & evidence**: validator check that migration filenames stay monotonically numbered and that no migration file is ever edited after commit (checksum drift is sqlx-fatal); `tests/kubernetes_integration_test.rs` asserts the Job manifest exists.
- **Safety/dry-run**: the migrate Job is the only component allowed to mutate schema; boot-time `migrate_if_connected` becomes verify-only (checks applied-version parity, refuses readiness on mismatch) once the Job path is in place — preserving the current behavior of never serving traffic on a bad schema.

#### F9. Deployment packaging: kustomize base + overlays (and optional ArgoCD)

- **Goal**: eliminate every "edit the committed YAML by hand" deferral; give the READMEs' promised "deployment-time overlay" a mechanism.
- **Changes**: add `deploy/kubernetes/base/kustomization.yaml` listing the six (plus new) base files; new `deploy/kubernetes/overlays/dev/` and `overlays/prod/` patching: image refs/digests (F5), ingress host + TLS secret (replacing `platform.example.invalid`/`platform-tls-placeholder`), CNPG Barman `destinationPath`/`endpointURL` (F6), replica counts. Makefile `k8s-render: kustomize build deploy/kubernetes/overlays/dev` and `k8s-apply` (explicitly marked operator-initiated). Optional follow-up: `deploy/kubernetes/argocd/application.yaml` to make `BuildProvider::ArgoCD` (`sources/ryuki-core/src/config.rs:457-486`) real. This also makes the promotion contract's `kustomize-build-render` validation signal executable — CI runs `kustomize build` on both overlays as a check.
- **Data model / engine / API / portal**: none.
- **Validation & evidence**: CI job `kustomize build` both overlays (render must succeed); `tests/kubernetes_integration_test.rs` switches from reading raw files to parsing rendered output where assertions concern the final shape.
- **Safety**: rendering is pure; `kubectl apply` remains manual/approval-gated per the readiness contracts.

#### F10. Supply-chain security

- **Goal**: CVE, SBOM, and provenance coverage for a platform whose pitch is governed, evidence-backed change.
- **Changes**: `.github/dependabot.yml` (ecosystems: `cargo`, `github-actions`, `docker` for both Dockerfiles); root `deny.toml` + `cargo deny check` job in `ci.yml` (advisories, licenses, bans); release workflow (F5) gains `syft` SBOM generation (SPDX, attached to the GitHub release), `trivy image` scan (fail on HIGH/CRITICAL), and `cosign sign` (keyless, GitHub OIDC). Pin base images by digest in both Dockerfiles (`rust:1.88-bookworm@sha256:…`, `debian:bookworm-slim@sha256:…`) and `postgres:18-alpine` in `deploy/compose/compose.yaml` — dependabot's docker ecosystem then keeps the digests fresh.
- **Validation & evidence**: SBOM + signature become release evidence artifacts referenced from the `platform_releases` row (F5); `tests/ci_integration_test.rs` asserts the deny/scan jobs exist.
- **Safety**: scan jobs are read-only; signing uses ephemeral OIDC identity, no long-lived keys in the repo (never commit secrets).

#### F11. TLS certificate automation (small)

- **Goal**: the ingress cert stops being unprovisionable while the platform ships a whole certificate-lifecycle engine (`migrations/011_certificates.sql`) for everyone else's certs.
- **Changes**: `deploy/kubernetes/base/cert-issuer.yaml` with a commented `ClusterIssuer` pair (ACME and enterprise-CA variants, documented in the vault-runbook style); annotate `ingress.yaml` with `cert-manager.io/cluster-issuer`; host + secret name parameterized by the F9 overlay. If direct API TLS (`RYUKI_SERVER__TLS_CERT_PATH`/`TLS_KEY_PATH`, `.env.example:19-20`) is kept, add a cert volume + mount in `deployments.yaml` fed by a `VaultStaticSecret`; otherwise document ingress-terminated TLS as the supported posture.
- **Validation & evidence**: `tests/kubernetes_integration_test.rs` asserts the ingress annotation exists. **Safety**: cert-manager is opt-in per overlay.

#### F12. Makefile operational targets (small, compounding)

- **Goal**: one entry point that would have exposed the broken Dockerfiles and missing migrate path on day one.
- **Changes** to `/Users/mvandenbulcke/Repos/ryuki.io/Makefile`: fix the stale `.PHONY` line (declares `run`, omits `run-api`/`run-portal`/`compose-*`); add `docker-build` (both images from repo root), `migrate` (F8), `db-backup`/`db-restore` (F6), `k8s-render`/`k8s-apply` (F9), `audit` (`cargo deny check`), `sbom` (syft local), `release-check` (fmt+clippy+test+validate+docker-build — the local mirror of CI). Update `deploy/README.md`, `deploy/ci/README.md`, and both kubernetes READMEs to reference targets instead of raw commands.

### Implementation plan

1. **F1 — fix both app Dockerfiles (COPY full workspace, cargo-chef), fix or delete `Dockerfile.validator`, add the docker-image validator check** — S/M. Unblocks compose, CI image jobs, and all deploy work.
2. **F2 — `.github/workflows/ci.yml` (build/test/lint/secret-scan/validator/image jobs), gate `static.yml` on CI, branch protection, delete Azure pipeline, rewrite `tests/ci_integration_test.rs`, fix `deploy/ci/README.md`** — M.
3. **F12 (first pass) — Makefile `docker-build` + `.PHONY` fix + `release-check`** — S. Do early so the local loop matches CI.
4. **F3 — ConfigMap + VSO trio + `envFrom` wiring + `RYUKI_DATABASE__REQUIRED` flag + k8s test assertions** — M.
5. **F4 — NetworkPolicy DB egress/ingress pairs + CNPG intra-cluster allows + tests** — S.
6. **F8 — `migrate` subcommand, migrate Job manifest, forward-only policy doc, upgrade runbook, boot-time verify-only switch** — M.
7. **F7 — replicas: 2, spread constraints, `pdb.yaml`, test assertions** — S (depends on 4 and 6).
8. **F9 — kustomization + dev/prod overlays, CI render check, Makefile k8s targets, optional ArgoCD app** — M.
9. **F5 — git-cliff + CHANGELOG, `release.yml`, GHCR digest tags, `x-api-version` from `CARGO_PKG_VERSION`, `/api/platform/release`, `/api/v1` nest alias, `044_platform_releases.sql`, portal version footer** — L.
10. **F6 — ScheduledBackup + retention mapping, object-storage skeleton, restore/DR runbook, compose backup targets, backup-readiness validator, health-component surface** — M/L.
11. **F10 — dependabot, deny.toml + CI job, trivy/syft/cosign in release.yml, digest-pinned base images** — M.
12. **F11 — cert-manager issuer + ingress annotation via overlay** — S.

Steps 1–5 are the P0 core ("it builds, it's gated, it can reach its database"); 6–9 make it operable; 10–12 make it shippable with a straight face.

### Risks & open questions

- **Registry choice**: `deploy/README.md` admits the `ryuki/*` names are unapproved placeholders and `catalog/registry-readiness-contract.yaml` envisions Harbor. The design defaults to GHCR (zero-setup, OIDC-signable) — does that conflict with the intended self-hosted Harbor posture, and who owns that decision?
- **CI cost/time**: `cargo leptos build --release` plus two full-workspace docker builds per PR is heavy. cargo-chef + `Swatinem/rust-cache` mitigates, but the image job may need to be main/release-only if PR latency becomes prohibitive.
- **Push-after-every-commit vs branch protection**: the user's workflow pushes directly to `main`; strict branch protection with required checks would block that. Proposed compromise — protection allows direct pushes but the Pages deploy gates on CI success — means broken code can still land on `main` (just not on the live site). Is that acceptable, or should the workflow move to PRs?
- **In-memory fallback removal**: `RYUKI_DATABASE__REQUIRED=true` changes failure semantics in K8s from "NotReady forever" to crash-loop. Some existing tests and the dev experience may rely on the fallback — audit which `sources/ryuki-api` stores actually use it before flipping the default anywhere.
- **`/api/v1` alias**: serving the same router under two prefixes is cheap, but the portal's Leptos same-origin server functions and any hardcoded client paths must be checked for path-relative assumptions before advertising the prefix.
- **Forward-only migrations**: acceptable only once F6's restore path is real and tested; until then, schema rollback is genuinely impossible — this dependency must be called out in the upgrade runbook.
- **CNPG operator traffic under default-deny**: the exact operator-namespace selectors for F4's intra-cluster allows depend on how/where the CNPG operator is installed; needs verification on a real cluster before the policies can be called complete.
- **Promotion contract flags**: when (if ever) do `registryPushAllowed`/`kubectlApplyAllowed` flip from `false`? The design keeps all execution flags off and treats CI/release runs purely as evidence sources, but a credible roadmap eventually needs a governed path to live deployment — likely a later phase gated on the platform's own approval-engine maturity.

---

## Lifecycle extension: Protect/Publish/Maintain/Retire & offering availability

Ryuki advertises an 11-stage governed lifecycle (intake → … → verify → protect → publish → maintain → retire) in its catalog contract, API metadata, and docs site, but the implemented state machine ends at `Completed`: `plan_request()` creates `protect` and `publish` stage records that nothing ever starts, no code links a completed request to the standalone protect/maintain/retire engines that *do* exist, and stage records are never persisted (the `requests` table has only scalar `status`/`stage` columns). Compounding this, all 12 catalog offerings are `status: planned`, the portal's New Request form and every lifecycle action button are hard-rejected as "preview-only", and the flagship P0 offering (Windows server deployment) has no engine at all. Until the request lifecycle actually reaches its advertised post-completion stages and at least one offering can be requested end-to-end through the shipped UI, the platform is a demo of a lifecycle rather than an automation platform.

### Current state

- **State machine ends at Completed.** `RequestStatus` (`sources/ryuki-engine/src/models.rs:101-112`) has variants `Draft..Completed,Failed`; the transition table in `transition_status()` (`sources/ryuki-engine/src/request_lifecycle.rs:482-492`) terminates at `Verifying → Completed`. `plan_request()` pushes `protect` (step 7) and `publish` (step 8) stages as `Pending` (`request_lifecycle.rs:280-296`) and no function anywhere completes them. There are no `maintain`/`retire` stage records at all.
- **Contract metadata advertises 11 stages.** `lifecycle_stages()`/`rql_stages()` (`sources/ryuki-api/src/contracts.rs:2428-2432, 2478-2483`) and `catalog/request-lifecycle-contract.yaml:23-34` (plus `protectionPlan`/`publishPlan`/`maintainPlan`/`retirePlan` plan sections at lines 66-69) declare protect/publish/maintain/retire. `docs/index.html:1363` even claims "CMDB reconciled, request closed" at stage 09 Complete while stage 11 is "Roadmap — CMDB publication".
- **Stage records are in-memory only.** `migrations/003_requests.sql` has single `status TEXT`/`stage TEXT` columns; `db_row_to_request` synthesizes a `Request` from 13 scalar columns, so the DB-backed path loses all stage/evidence history that the in-memory `REQUEST_STORE` (`contracts.rs:2418`) keeps.
- **The post-completion engines exist but are orphaned from the lifecycle.** `/api/protect/*` (backup coverage, secrets rotation, repository capacity, immutability, legal hold — `contracts.rs:840-949`), `/api/maintain/*` (patch, software, baseline — `contracts.rs:783-838`), and `/api/retire/decommission/*` (`server_decommission.rs`: `plan/validate/quarantine/execute/verify/rollback_decommission`) all work standalone. `cmdb_engine.rs` has `import_cmdb_records`/`reconcile_cmdb`/`export_cmdb` wired to `/api/cmdb/*` (`contracts.rs:1029-1031`). `request_lifecycle.rs` references none of them.
- **All offerings planned; portal rejects everything.** `catalog/offering-catalog.yaml` carries 12× `status: planned` (zero active); `catalog_request_form()` hardcodes `formSubmissionAllowed: false, liveRequestCreationAllowed: false` (`contracts.rs:3421-3424`) even though `requests_create` (`contracts.rs:7034-7071`) performs real Postgres INSERTs. The portal renders a full New Request form (`portal/portal-ui/src/views/request_create.rs`) but `reject_static_preview_request_create/_action` (`portal/portal-ui/src/server_boundary.rs:1154-1172`) returns errors for create/validate/plan/approve/lock/execute. The stage rail in `portal/portal-ui/src/views/request_detail.rs:238-250` hardcodes 7 stages ending at "verified".
- **Windows deployment is absent.** First offering in the catalog (`offering-catalog.yaml:11-63`, P0) — but the engine has only `linux_deployment.rs`, the API only `/api/build/linux/*` (`contracts.rs:1356-1366`), and only `migrations/009_linux_deployments.sql` exists. Windows appears only in static-seed JSON and, ironically, in the lifecycle engine's own unit tests (`request_lifecycle.rs:561`).
- **~25 contracts are descriptor-only** (static `"source":"static-seed"` GETs with no engine): zabbix-onboarding (`contracts.rs:976` — drift remediation IS implemented via `zabbix_drift.rs` + `migrations/013_zabbix_drift.sql`, onboarding is not), cluster-capacity-admission, worker-capability, approval-groups, feature-flag-governance, azure-landing-zone-validation, vsan-esxi-lifecycle, release-promotion, dependency-replay, etc. `scripts/validator-rs` lint modules for these reference paths from a removed repo layout (`api/Ryuki.Platform.Api/Program.cs`, `docs/workflows/*.md` — see `scripts/validator-rs/src/azure_landing_zone.rs:7-14`).
- **~~`orchestrate_reboot()` is unreachable~~ — DONE**: wired as `POST /api/maintain/patch/reboot` (`patch_reboot` handler in `contracts.rs`), with `patch-reboot` in `patch_contract`'s `supportedWorkflows`; the engine now also rejects `NoReboot`/`ScheduleOnly` waves (no auto-reboot stages) and the route is covered by the `MUTATING_ROUTES` auth tests.
- **`policy-guardrails.yaml` has no evaluation engine**: `validate_request()` hand-transcribes rule IDs (`p0-preflight-required-fields`, `p0-site-ou-catalog-match`) with hardcoded `VALID_SITES`/`VALID_ENVIRONMENTS`; only the validator schema-checks the YAML (`scripts/validator-rs/src/catalog.rs:339`).
- **No roadmap artifact**: `README.md:48` is one sentence; `docs/index.html:902,1364-1367` is a graphic; no `docs/roadmap.md`, no status taxonomy semantics (validator allows `planned|active|draft|deprecated` at `catalog.rs:9` but the catalog never uses anything but `planned`).

### Design

#### 1. Post-completion lifecycle stages (Protect → Publish → Operational, Retire)

**Goal.** Make protect/publish first-class, gated, evidence-producing transitions out of `Completed`, model "maintain" as enrollment evidence on an operational request, and model "retire" as a governed handoff to the existing decommission engine. Additive only — `Completed` keeps its meaning ("change delivered and verified") so existing consumers don't break.

**Data model.** New migration `migrations/044_request_stages.sql` (next free number after 043):

```sql
CREATE TABLE request_stages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    evidence JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    UNIQUE (request_id, name)
);
```

Plus `ALTER TABLE requests ADD COLUMN retire_request_id UUID REFERENCES requests(id)` to link a build request to the decommission request that retires it. All lifecycle handlers (`requests_validate/plan/approve/lock/execute/verify` at `contracts.rs:7160-7477`) upsert their stage row here instead of only flipping the scalar `stage` column; `db_row_to_request` reconstructs `Request.stages` from this table, closing the DB-vs-in-memory fidelity gap.

**Engine changes** (`sources/ryuki-engine/src/`):
- `models.rs`: extend `RequestStatus` with `Protecting`, `Publishing`, `Operational`, `Retiring`, `Retired`; extend `as_str()`/parsing accordingly.
- `request_lifecycle.rs`: extend `valid_transitions` with `Completed→Protecting`, `Protecting→Publishing`, `Publishing→Operational`, `Operational→Retiring`, `Retiring→Retired`, guarded by `require_completed_stage_for_transition` on `protect`/`publish`/`retire` (same pattern as :511-529). Add `protect_request()`, `publish_request()`, `retire_request()` mirroring `execute_request()`'s dry-run evidence style. `plan_request()` additionally pushes `maintain` (step 9) and `retire` (step 10) `Pending` stages so the persisted stage set matches the contract's plan sections.
- Stage semantics: **Protect** = backup coverage check via `backup_engine::generate_backup_coverage_report` scoped to the delivered asset + monitoring enrollment plan (zabbix-onboarding engine, see feature 4); evidence items `backup-coverage-summary`, `monitoring-enrollment-plan`. **Publish** = `cmdb_engine::reconcile_cmdb` against the request's CI context + `export_cmdb(records, "summary")`; evidence `cmdb-reconciliation-summary`. **Maintain** = not a transition: completing publish lands the request in `Operational`, and enrollment records (patch cycle from `patch_engine`, baseline from `os_baseline`, calendar window from `maintenance_calendar`) are appended as evidence on the `maintain` stage over time. **Retire** = `retire_request()` creates a linked `vm-decommission-quarantine` request driven by `server_decommission::plan/validate/quarantine/execute/verify_decommission`; the parent moves `Operational→Retiring` on quarantine and `Retiring→Retired` when `verify_decommission` evidence lands.

**API endpoints** (`sources/ryuki-api/src/contracts.rs`, registered next to `:112-117`):
- `POST /api/requests/{id}/protect` — `check_permission(&session, "execute")`; guards `status == Completed`; runs protect, completes the `protect` stage row, transitions to `Protecting`.
- `POST /api/requests/{id}/publish` — requires completed `protect` stage; runs reconcile/export, transitions `Publishing → Operational`.
- `POST /api/requests/{id}/retire` — requires `Operational`; creates the linked decommission request, sets `retire_request_id`.
- `GET /api/requests/{id}/stages` — list persisted stage rows with redacted evidence.
- Update the verify handler (`:7413-7477`) so the API response surfaces "next actions: protect" once `Completed`.

**Portal UI.** Extend the hardcoded rail in `views/request_detail.rs:238-250` to `["intake","validated","planned","approved","locked","executed","verified","protected","published","operational"]` with per-status match arms; add `request_protect_path`/`request_publish_path`/`request_retire_path` helpers to the lifecycle-path allowlist (`server_boundary.rs:138`, `is_allowed_request_lifecycle_path`) and matching `#[server]` fns. Render `Retiring/Retired` as a badge linking to the decommission request.

**Validation & evidence.** Every stage completion writes `EvidenceItem`s into `request_stages.evidence` (JSONB), keeping the redaction discipline from `execute_request` (redacted `ExecutionLog` values). Add an engine test asserting `RequestStatus::as_str()` values cover every stage in `request-lifecycle-contract.yaml`'s `lifecycleStages`, and a `scripts/validator-rs` check that the contract YAML and the API's `lifecycle_stages()` list stay identical.

**Safety/dry-run.** Protect and publish are read-only-or-simulated by default (coverage report and CMDB reconcile are computations over inventory; monitoring enrollment stays a plan). Live enrollment/CMDB push is gated behind approval plus a `platform_config` flag, matching the repo's dry-run-by-default convention. Retire inherits the decommission engine's quarantine-first, rollback-capable flow.

#### 2. Offering availability and live portal request actions

**Goal.** Give `status:` real semantics, ship at least the offerings whose engines exist, and let the portal actually drive the API it fronts.

- **Catalog.** Adopt the validator's existing taxonomy (`planned|draft|active|deprecated`, `scripts/validator-rs/src/catalog.rs:9`) plus a new `preview` value. Flip to `active`: linux-server-deployment, request-preflight, patch-wave-planning, controlled-restore-request, cmdb-import, cmdb-update-export, vm-decommission-quarantine, application-environment-retirement (all have engines + routes + migrations). Keep windows-server-deployment `planned` until feature 3. Add new offerings for the orphaned working engines: certificate-lifecycle, legal-hold, gmsa-lifecycle, access-recertification, emergency-change (each needs a `RequestType` variant in `models.rs` and a `parse_request_type` arm).
- **API.** Parse `catalog/offering-catalog.yaml` at startup (`include_str!` + `serde_yaml`, cached in a `OnceLock<CatalogIndex>` consistent with existing statics) and derive `formSubmissionAllowed`/`liveRequestCreationAllowed` in `catalog_request_form()` (`contracts.rs:3421-3424`, plus the duplicate flags at :2907-2908, :3376, :3401, :11517) from "≥1 active offering AND `platform_config.live_request_creation = true`" instead of hardcoding `false`. Per-offering forms gain `"status"` so the portal can grey out planned ones.
- **Portal.** Replace `reject_static_preview_request_create/_action` (`server_boundary.rs:1154-1172`) with real same-origin HTTP calls from the SSR server fns to the platform API (base URL from config, e.g. `RYUKI_API_BASE`); the path helpers (`request_create_path`, `request_validate_path`, …) and same-origin guards already exist — they currently validate paths and then throw the result away. Keep `PortalServerBoundary::static_dry_run()` as the fallback mode when no API base is configured, so the GitHub Pages static preview keeps working.
- **Validation.** `scripts/validator-rs/src/catalog.rs` gains: `active` offerings must name an existing workflow/engine (cross-check against a route manifest), and the count of `active` offerings must be consistent with the request-form flags.

#### 3. Windows server deployment engine

**Goal.** Implement the #1 P0 offering end to end, at dry-run parity with Linux.

- **Engine**: new `sources/ryuki-engine/src/windows_deployment.rs` modeled on `linux_deployment.rs` (`plan_/validate_/execute_/verify_linux_deployment` at :167-437): `supported_image_catalog()`, `plan_windows_deployment()` (inputs per the offering's `requiredInputs`: imageVersion, vmSizing, network, backupPolicy, monitoringProfile, cmdbContext, plus Windows-specific OU placement, customization-spec reference, gMSA worker identity reusing `gmsa_lifecycle` types), `validate_`, `execute_` (dry-run, redacted evidence), `verify_`. Promote the customization-spec governance facts currently frozen in the static descriptor (`contracts.rs:4405`) into validation rules.
- **Data model**: `migrations/045_windows_deployments.sql` mirroring `009_linux_deployments.sql`, adding `ou_path`, `customization_spec`, `gmsa_account` columns.
- **API**: `/api/build/windows/{plan,validate,execute,verify}` + `/api/build/windows/supported-images` + `/api/build/windows-deploy-contract`, registered beside the Linux block at `contracts.rs:1356-1366`; register the module in `ryuki-engine/src/lib.rs`.
- **Catalog/portal**: flip the offering to `preview`; the request form section already exists in `catalog_request_form()`'s `offeringForms`.

#### 4. Descriptor-only contract burn-down (first tranche) and reboot orchestration wiring

Prioritize the four that unblock other features or are pure CRUD:
- **zabbix-onboarding** (needed by the Protect stage): `sources/ryuki-engine/src/zabbix_onboarding.rs` next to `zabbix_drift.rs` — plan/validate/execute/verify host enrollment with host-group/template/proxy inputs; routes under `/api/monitoring/zabbix/onboarding/*` beside the drift routes (`contracts.rs:1194-1208`); migration `046_zabbix_onboarding.sql`.
- **cluster-capacity-admission**: thin engine wrapping existing `cost_capacity` data behind admit/review/block decisions; routes beside `/api/analytics/capacity/*`. No new table needed initially.
- **approval-groups** and **worker-capability**: CRUD + matching engines with migrations `047_approval_groups.sql`, `048_worker_registry.sql`; these back real RBAC routing for the approve stage.
- **Reboot orchestration** — DONE: shipped as `POST /api/maintain/patch/reboot` (`patch_reboot`), loading the wave from `patch_waves` and returning `patch_engine::orchestrate_reboot(&wave)` stages; `patch-reboot` is in `patch_contract`'s `supportedWorkflows`. Evidence-only (no wave transition); 503/404/409 contract; engine rejects `NoReboot`/`ScheduleOnly`.
- **Validator hygiene**: fix `scripts/validator-rs` path constants that point at the removed `api/Ryuki.Platform.Api/Program.cs` and nonexistent `docs/workflows/` (e.g. `azure_landing_zone.rs:7-14`) so lints check this repo's actual layout.

#### 5. Catalog-driven policy evaluation

New `sources/ryuki-engine/src/policy_engine.rs`: parse `catalog/policy-guardrails.yaml` (add `serde_yaml` to ryuki-engine's Cargo.toml; embed via `include_str!` or read from a configured catalog dir in containers), expose `evaluate(&Request, workflow_id) -> Vec<RuleDecision>` honoring each rule's `appliesTo/requiredInputs/decision/remediation`. Refactor `request_lifecycle::validate_request()` to delegate the required-fields and site/OU rules it currently hand-transcribes (`p0-preflight-required-fields`, `p0-site-ou-catalog-match`). API: `GET /api/catalog/policy-guardrails` returns parsed rules (replacing the static descriptor's `no-live-policy-execution` self-disclaimer at `contracts.rs:3487`); `POST /api/requests/{id}/policy-eval` runs evaluation and records evidence. A unit test asserting every rule ID referenced in code exists in the YAML (and vice versa for P0 rules) locks out drift.

#### 6. Roadmap document and truthful docs

- `docs/roadmap.md` + `docs/roadmap.html` (added to the docs-site nav, `sitemap.xml`, `search-index.json`): offering status taxonomy semantics (`planned/preview/active/deprecated`), per-offering targets for the 12 offerings, shipping criteria for the Protect/Publish/Maintain/Retire stages, and the descriptor-only backlog. Link from `README.md:48` and the docs lifecycle graphic.
- Fix `docs/index.html:1363` now: stage 09 copy becomes "Evidence pack sealed, request closed." (drop "CMDB reconciled") until feature 1's publish stage actually reconciles. GitHub Pages serves from `main`, so this ships immediately on push.

### Implementation plan

1. **S** — Docs truth fix: `docs/index.html:1363` copy; commit+push (Pages serves from main).
2. **M** — `migrations/044_request_stages.sql` + persist/load stages in all six existing lifecycle handlers (`contracts.rs:7160-7477`) and `db_row_to_request`; `retire_request_id` column.
3. **M** — Engine lifecycle extension: `RequestStatus` variants, transition table + guards, `protect_request/publish_request/retire_request`, `maintain`/`retire` pending stages in `plan_request`, unit tests including the contract-stage-parity test.
4. **M** — API routes `/api/requests/{id}/protect|publish|retire|stages` wiring `backup_engine`, `cmdb_engine`, `server_decommission`; update lifecycle contract handler metadata.
5. **S** — ~~Wire `orchestrate_reboot`~~ DONE: `POST /api/maintain/patch/reboot` + `patch-reboot` in the contract workflow list.
6. **M** — Catalog availability: parse `offering-catalog.yaml` in the API, derive form flags from status + `platform_config`, flip vetted offerings to `active`, add `preview` to `CATALOG_STATUSES`, add offerings + `RequestType` variants for the five orphaned engines.
7. **L** — Portal live mode: real HTTP calls in `server_boundary.rs` server fns (create + six actions + new protect/publish/retire), static-preview fallback, extended stage rail in `request_detail.rs`.
8. **L** — `windows_deployment.rs` engine + `045_windows_deployments.sql` + `/api/build/windows/*` routes + offering flip to `preview`.
9. **M** — `policy_engine.rs` + `validate_request` delegation + policy endpoints + rule-ID drift tests.
10. **L** — Descriptor-only tranche 1: `zabbix_onboarding.rs` (feeds Protect), `cluster_capacity_admission.rs`, `approval_groups.rs`, `worker_capability.rs` + migrations 046-048 + validator path-constant fixes.
11. **S** — `docs/roadmap.md`/`roadmap.html` + README link + validator status/roadmap consistency checks.

Steps 2-4 are the critical path; 5, 6, and 11 are independent quick wins; 7 depends on 6; 8 and 10 are parallelizable.

### Risks & open questions

- **Terminal-status compatibility.** Adding `Operational/Retired` after `Completed` changes what "done" means for dashboards and the portal's status badges. Proposed design is additive (`Completed` remains a valid resting state; protect/publish are operator-initiated), but should protect/publish be *required* (request not closable until published) or *advisory*? The catalog contract's `canonical-lifecycle-required` rule implies required; recommend required-for-`active`-offerings, advisory during `preview`.
- **Dual request stores.** Every lifecycle handler is duplicated for Postgres and the in-memory `REQUEST_STORE` fallback (`contracts.rs:2418`). Adding three more handlers doubles the drift surface — consider extracting a `RequestRepo` trait before step 4, at the cost of one extra refactor (M).
- **Contract YAML vs live behavior.** `request-lifecycle-contract.yaml` declares `liveExecutionAllowed: false` and the request-form contract declares `no-live-policy-execution`; enabling live portal actions (step 7) requires versioning these contracts up together or the validator and the marketing surface will contradict the running system — the exact gap this theme is fixing. Define who owns flipping contract `status: draft` → `active`.
- **Maintain modeling.** Treating Maintain as enrollment evidence on an `Operational` request (rather than a status) matches reality (maintenance is continuous) but deviates from the 13-stage graphic. Needs a docs decision so the roadmap, contract, and engine say the same thing.
- **Retire linkage semantics.** One request spawning another (`retire_request_id`) is new; decide whether decommission failure rolls the parent back to `Operational` (proposed: yes, via `rollback_decommission`).
- **Windows execute path is still simulated.** The engine work (step 8) gives dry-run parity only; live execution depends on the adapter layer, which is out of scope here — the offering should ship as `preview`, not `active`, and the roadmap must say so.
- **Catalog embedding.** `include_str!` of YAML means a rebuild on every catalog edit; reading from a mounted catalog dir is more operable but adds a runtime failure mode. Recommend `include_str!` default with an env-var override path.
- **Permissions.** Protect/publish/retire currently piggyback on the `execute` permission; should `publish` (CMDB write) and `retire` (destructive) get distinct permissions in `check_permission`'s model before approval-groups (step 10) lands?

---

## Notifications, webhooks & eventing

Ryuki is an approval-gated platform that cannot tell anyone anything. Every lifecycle transition (Draft→Intake→Validated→Planned→Approved→Locked→Executing→Verifying→Completed) ends in a SQL `UPDATE` and a JSON response — no email, no webhook, no in-portal signal. The `smtp` config group is parsed and validated at startup but never consumed; no mail crate and no outbound HTTP client (`reqwest`/`hyper` client) exists in any of the six `Cargo.lock` files, so even a Slack incoming-webhook is currently impossible to send. The request-lifecycle contract *requires* a `statusCallback` input, yet no column stores it and no handler ever invokes one. The result: approvers don't know work awaits them, requesters don't know their request was approved or failed, and external systems (ServiceNow, CI pipelines) cannot subscribe to anything. For a governed control plane whose entire value proposition is "humans approve, the platform executes," this is the single biggest credibility gap after live execution itself.

### Current state

- **SMTP config is dead code.** `SmtpConfig` (`sources/ryuki-core/src/config.rs:722-760`: `enabled`, `host`, `port`, `username`, `credential`, `from_address`, `use_tls`) is validated at startup (`config.rs:1271-1280`) and re-serialized read-only by the admin settings endpoint (`sources/ryuki-api/src/config.rs:115-120`). Nothing opens an SMTP connection; `docs/configuration.md:84` documents it as "Email notification transport" anyway.
- **No outbound delivery dependency at all.** No `lettre`, no `reqwest` in any `Cargo.lock` (root, `sources/ryuki-{api,core,engine}`, `portal/portal-ui`, `scripts/validator-rs`).
- **`statusCallback` is pure prose.** Declared a required input in `catalog/request-lifecycle-contract.yaml:47` and its JSON mirror at `sources/ryuki-api/src/contracts.rs:2803`, but `migrations/003_requests.sql` has no callback column, `requests_create` never accepts one, and the lifecycle handlers (`requests_approve` at `contracts.rs:7270`, `requests_lock` at `:7319`, `requests_execute` at `:7366`, `requests_verify`) do `UPDATE` + return JSON with no event emission, outbox write, or dispatch of any kind.
- **The contracts codify the absence.** `"request-notification-dispatch-disabled"` (`contracts.rs:2605`) plus dozens of `"notificationDispatchAllowed": false` guards (`contracts.rs:2705,2748,2830,3594,4027,...`).
- **Outage comms is mock-send by design.** `send_notice()` (`sources/ryuki-engine/src/outage_comms.rs:266-292`) flips status to `Sent` and appends metadata `sent_to: support-groups (mock)`; its contract declares `"liveNotificationAllowed": false` (`outage_comms.rs:444`) and "creates drafts and mock-sends only" (`:501`). `maintenance_calendar.rs:415` carries the same flag. `alert_routing_engine.rs` records routing decisions to support-group *name strings* (`migrations/008_alert_routing.sql`) with no transport.
- **No delivery schema.** Across migrations 001–043 there is no table matching webhook/notification/event/delivery/outbox/subscription. The nearest tables are dead ends: `servicenow_queue` (034, queue with no consumer), `outage_notices`/`outage_notice_systems`/`outage_notice_acknowledgments` (042, draft/mock-send), `alert_routes`/`route_decisions` (008, routing only).
- **No portal notification UX.** The topbar (`portal/portal-ui/src/shell.rs:160-225`) has brand, a permanently disabled search input, scope/session pills, and a theme toggle — no bell, feed, or unread badge. No toast classes in `portal/portal-ui/styles.css`, no `EventSource`/`WebSocket`/polling anywhere in portal src, no SSE or `WebSocketUpgrade` endpoint in `ryuki-api` — even though the portal CSP already allows `connect-src 'self' ws: wss:` (`portal/portal-ui/src/main.rs:62`).

### Design

The unifying primitive is a **durable outbox**: lifecycle handlers write *platform events* in the same transaction as the state change; a background dispatcher fans each event out to channels (in-portal notification rows, email, webhooks, and later the `servicenow_queue` drain). This keeps handlers fast, makes delivery retryable and auditable (evidence-first), and gives every channel one integration point.

#### Feature 1 — Platform event outbox

- **Goal:** A single, transactional record of "something notification-worthy happened," decoupled from delivery.
- **Data model:** New `migrations/044_platform_events.sql`:
  - `platform_events(id UUID PK, event_type TEXT NOT NULL, subject_kind TEXT NOT NULL, subject_id UUID, site TEXT, environment TEXT, actor TEXT, payload JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(), dispatched_at TIMESTAMPTZ)` with index on `(dispatched_at) WHERE dispatched_at IS NULL`.
  - Initial `event_type` vocabulary mirrors the lifecycle stages: `request.created`, `request.validated`, `request.planned`, `request.approval_needed`, `request.approved`, `request.locked`, `request.executing`, `request.verified`, `request.completed`, `request.failed`, plus `outage_notice.sent`.
- **Engine/API changes:** Add `sources/ryuki-api/src/events.rs` with `emit_event(pool, &PlatformEvent)` invoked from each lifecycle handler in `contracts.rs` (`requests_create` ~`:109` route block, `requests_validate`, `requests_plan`, `requests_approve:7270`, `requests_lock:7319`, `requests_execute:7366`, `requests_verify`). In DB mode the insert joins the same handler flow as the existing `UPDATE`; in the in-memory fallback (`request_store()`) events are skipped (the fallback is demo-only).
- **API endpoints:** `GET /api/events` (admin, filterable by type/subject) for audit and debugging, registered in `contracts::routes()` alongside the existing `/api/requests/*` routes.
- **Validation & evidence:** New validator `scripts/validator-rs/src/platform_events.rs` (following the `alert_routing.rs` pattern) asserting every lifecycle route has a matching emit and that the event vocabulary matches the contract enum. Each event row *is* evidence; `GET /api/events` becomes part of the evidence manifest.
- **Safety/dry-run:** Event emission is always on — recording that something happened is read-side-effect-free. Delivery (below) is what's gated.

#### Feature 2 — Email notifications (make SmtpConfig real)

- **Goal:** Approvers get "approval needed" mail; requesters get approved/failed/completed mail.
- **Data model:** Part of `migrations/045_notification_delivery.sql`: `notification_deliveries(id UUID PK, event_id UUID REFERENCES platform_events, channel TEXT CHECK (channel IN ('email','webhook','portal')), recipient TEXT, status TEXT CHECK (status IN ('pending','sent','failed','skipped_dry_run')), attempts INT DEFAULT 0, last_error TEXT, next_retry_at TIMESTAMPTZ, created_at, updated_at)` with index on `(status, next_retry_at)`.
- **Engine/API changes:** Add `lettre` (tokio + rustls) to `sources/ryuki-api/Cargo.toml`. New `sources/ryuki-api/src/notify.rs`: a tokio background task (spawned from `main.rs` startup, holding the pool and `SmtpConfig` via cloned state — no global mutable state, per repo convention) that polls undelivered `platform_events`, resolves recipients, renders a plain-text template per event type, and records the outcome in `notification_deliveries`. Recipient resolution: requester from `requests.created_by` (`migrations/003_requests.sql`); approvers from the role/permission model behind `check_permission(&session, "approve")` — initially a configured approver alias (new `notifications.approver_address` config key) until per-user email addresses exist (cross-reference: RBAC administration theme).
- **API endpoints:** `POST /api/admin/notifications/test` (admin-only) sends a test mail and returns the delivery row — mirrors how admins verify settings today via `sources/ryuki-api/src/config.rs`.
- **Portal UI:** Admin settings surface gains an SMTP "send test" action plus a read-only delivery-status table.
- **Validation & evidence:** `notification_deliveries` rows are the evidence trail (who was told what, when, success/failure). Validator check: `smtp.enabled=true` requires `notifications.approver_address` or equivalent recipient source.
- **Safety/dry-run:** Honor the existing dry-run convention: when `smtp.enabled=false` (the default, `config.rs:746`) the dispatcher writes `status='skipped_dry_run'` rows with the fully rendered message — observable, auditable, zero egress. Live send requires `smtp.enabled=true` *and* a new `notifications.live_dispatch=true` flag, matching the platform's approval-gated-live pattern. Never log `smtp.credential` (it already deserializes from `password`; keep it out of `Debug`/admin re-serialization redaction as `config.rs:115-120` does for secrets).

#### Feature 3 — Webhooks and `statusCallback` honoring

- **Goal:** External systems subscribe to lifecycle events; the contract-required per-request `statusCallback` URL actually gets called.
- **Data model:** New `migrations/046_webhooks.sql`:
  - `webhook_subscriptions(id UUID PK, name TEXT, url TEXT NOT NULL, secret TEXT NOT NULL, event_types TEXT[] NOT NULL, site_filter TEXT, enabled BOOLEAN DEFAULT FALSE, created_by TEXT, created_at, updated_at)`.
  - `webhook_deliveries(id UUID PK, subscription_id UUID REFERENCES webhook_subscriptions, event_id UUID REFERENCES platform_events, attempt INT, status TEXT CHECK (status IN ('pending','delivered','failed','dead','skipped_dry_run')), response_code INT, response_excerpt TEXT, next_retry_at TIMESTAMPTZ, created_at)` with index on `(status, next_retry_at)`.
  - `ALTER TABLE requests ADD COLUMN status_callback_url TEXT;` — finally backing `statusCallback` from `catalog/request-lifecycle-contract.yaml:47`. Treated as an implicit single-request subscription by the dispatcher.
- **Engine/API changes:** Add `reqwest` (rustls, no default features) to `sources/ryuki-api/Cargo.toml` — this is the first outbound HTTP capability in the codebase and should live *only* in the dispatcher module. Extend the `notify.rs` dispatcher with a webhook lane: HMAC-SHA256 signature header (`X-Ryuki-Signature: sha256=<hex>` over the raw body using the subscription secret), `X-Ryuki-Event` type header, JSON body = the `platform_events.payload` envelope, exponential backoff (e.g. 1m/5m/30m/2h/6h then `dead`), 10s timeout, response body truncated to an excerpt (never store full responses — consistent with the contracts' raw-payload prohibitions).
- **API endpoints:** New `sources/ryuki-api/src/webhooks.rs` router merged in `main.rs` (~line 658, next to `contracts::routes()` / `boundary::routes()`): `GET/POST /api/webhooks`, `GET/PUT/DELETE /api/webhooks/{id}`, `POST /api/webhooks/{id}/test` (signed ping delivery), `GET /api/webhooks/{id}/deliveries`. All admin-gated via the existing `AuthExtractor` + `check_permission` pattern. `requests_create` accepts and persists `statusCallback`.
- **Portal UI:** New admin view `portal/portal-ui/src/views/webhooks.rs` (list, create, enable/disable, recent deliveries with response codes), wired through `portal/portal-ui/src/api_client.rs` resource functions like the existing `*_resource()` helpers.
- **Validation & evidence:** `webhook_deliveries` is the evidence trail. New validator `scripts/validator-rs/src/webhook_subscription.rs`: URL must be https (or explicitly allowlisted http for lab), secret length ≥ 32, event types ⊆ vocabulary, SSRF guard (reject RFC1918/link-local/metadata targets unless an admin allowlist permits — this platform manages private datacenters, so the allowlist will be exercised; make the check explicit, not absent).
- **Safety/dry-run:** Subscriptions are created `enabled=false`. With the global `notifications.live_dispatch=false` default, deliveries are recorded as `skipped_dry_run` with the signed payload they *would* have sent — reviewable before any egress. Flipping a subscription to enabled is an admin action that should itself emit a `platform_event` (and eventually ride the approval lifecycle). Update the lifecycle contract JSON (`contracts.rs:2605` area) to replace `request-notification-dispatch-disabled` with the gated-live description, and flip `notificationDispatchAllowed` only on the request-lifecycle contract — the other engines' `false` flags stay until each is deliberately enabled.

#### Feature 4 — In-portal notifications (bell, feed, toasts)

- **Goal:** An approver sees "3 requests awaiting approval" without being told out-of-band; a requester sees "approved" without re-navigating to `/requests/{id}`.
- **Data model:** In `migrations/045_notification_delivery.sql`: `portal_notifications(id UUID PK, recipient TEXT NOT NULL, event_id UUID REFERENCES platform_events, title TEXT, body TEXT, link_path TEXT, read_at TIMESTAMPTZ, created_at)` with index on `(recipient, read_at)`. `recipient` matches the session identity used by `AuthExtractor` / `requests.created_by`.
- **Engine/API changes:** The dispatcher's portal lane inserts rows fanned out per recipient (requester always; all approval-capable users for `request.approval_needed`).
- **API endpoints:** In `contracts.rs` or the new `webhooks.rs` sibling `notifications.rs`: `GET /api/notifications` (current session's, newest first, unread count), `POST /api/notifications/{id}/read`, `POST /api/notifications/read-all`. Phase 2: `GET /api/notifications/stream` as `axum::response::Sse` — the portal CSP already permits it (`main.rs:62`).
- **Portal UI:** Bell button + unread badge in the topbar toolbar (`portal/portal-ui/src/shell.rs` ~line 179, beside the theme toggle), dropdown feed of the latest 20 with mark-read, and a full `portal/portal-ui/src/views/notifications.rs` page. Toast styles in `portal/portal-ui/styles.css` (`.toast`, `.toast-stack`, status variants reusing the existing badge palette). Start with polling (30s timer in the shell, same-origin fetch via `api_client.rs`); upgrade to SSE later without UI changes.
- **Validation & evidence:** Read receipts (`read_at`) close the loop for "approver was informed" evidence. Pruning per the existing retention config group in `sources/ryuki-core/src/config.rs`.
- **Safety/dry-run:** In-portal rows are not egress, so they are *always* live — this is deliberately the one channel exempt from the live-dispatch gate, giving the platform a useful notification UX even in fully dry-run deployments.

#### Feature 5 — Real outage-comms send behind the existing gate

- **Goal:** `POST /api/operations/outage-comms/notices/{id}/send` (`contracts.rs:700`) performs real delivery when explicitly enabled, instead of unconditionally writing `sent_to: support-groups (mock)`.
- **Engine changes:** `send_notice()` (`sources/ryuki-engine/src/outage_comms.rs:266`) returns the rendered notice + resolved recipient groups; the API layer (which owns the pool and dispatcher) emits an `outage_notice.sent` platform event whose delivery routes through the email/webhook lanes. Engine stays transport-free, preserving the engine/adapter boundary. `alert_routes` (008) finally gets a consumer: route decisions map support-group names to subscription/recipient entries.
- **Safety/dry-run:** Gate on `liveNotificationAllowed` flipping to `true` in the contract (`outage_comms.rs:444`) *and* the global `notifications.live_dispatch` flag; mock-send remains the default and the dry-run path keeps writing the mock metadata marker so existing evidence expectations hold. `maintenance_calendar.rs:415` follows the same pattern later.

### Implementation plan

1. **(S)** Add `lettre` + `reqwest` to `sources/ryuki-api/Cargo.toml`; redaction audit of `SmtpConfig.credential` in admin re-serialization (`sources/ryuki-api/src/config.rs:115-120`).
2. **(M)** `migrations/044_platform_events.sql` + `sources/ryuki-api/src/events.rs` + `emit_event` calls in all seven lifecycle handlers in `contracts.rs`; `GET /api/events`.
3. **(M)** `migrations/045_notification_delivery.sql` (`notification_deliveries`, `portal_notifications`) + dispatcher skeleton in `sources/ryuki-api/src/notify.rs` running in dry-run (`skipped_dry_run`) mode end-to-end.
4. **(M)** Email lane: templates per event type, recipient resolution from `requests.created_by` + approver config, `POST /api/admin/notifications/test`, `notifications.live_dispatch` config flag.
5. **(L)** Webhooks: `migrations/046_webhooks.sql` (incl. `requests.status_callback_url`), `sources/ryuki-api/src/webhooks.rs` CRUD + test endpoint, HMAC signing + retry/backoff lane in the dispatcher, `statusCallback` accepted in `requests_create`, contract JSON updates at `contracts.rs:2605/2803`.
6. **(L)** Portal: notifications API routes, bell + dropdown in `shell.rs`, `views/notifications.rs`, toast styles, polling in `api_client.rs`.
7. **(M)** Validators: `scripts/validator-rs/src/platform_events.rs` + `webhook_subscription.rs` (SSRF/secret/event-type checks); wire into the validation run.
8. **(M)** Outage-comms live lane behind `liveNotificationAllowed`; connect `alert_routes` to recipients.
9. **(S)** Phase 2: SSE stream endpoint + portal upgrade from polling.

### Risks & open questions

- **Recipient identity is the weakest link.** `requests.created_by` and sessions (004) carry usernames, not email addresses; there is no user-profile table. Email delivery beyond a static approver alias depends on the RBAC/user-administration theme landing first. Decision needed: per-user email column vs. directory lookup vs. config-mapped role aliases.
- **SSRF and egress policy.** This is the first outbound HTTP in the codebase, in a product that manages private datacenter networks. The webhook target allowlist/denylist semantics (RFC1918 allowed when explicitly listed?) need a deliberate policy decision, not a default.
- **Dispatcher single-instance assumption.** A `FOR UPDATE SKIP LOCKED` poll keeps the design correct under multiple API replicas, but the current deployment story is single-process; decide whether to build for N replicas now (cheap with SKIP LOCKED) or document the constraint.
- **Contract blast radius.** Dozens of engines assert `notificationDispatchAllowed: false`. Flipping only the request-lifecycle contract is intentional, but the validator suite and any contract-parity checks must tolerate mixed values — verify `scripts/validator-rs` doesn't hard-code the `false` expectation.
- **Mock-send semantics in evidence.** Existing demo evidence expects `sent_to: support-groups (mock)`. Keep the marker for dry-run sends or migrate the expectation — pick one and update `outage_comms` tests accordingly.
- **statusCallback authentication.** Per-request callback URLs have no subscription secret. Options: sign with a platform-wide key, mint a per-request secret returned at intake, or require callbacks to be pre-registered subscriptions. Pre-registration is safest but weakens the "contract-required input" story.
- **Open question:** should the `servicenow_queue` (034) drain become a dispatcher lane in this workstream, or stay in the CMDB/Publish theme? The outbox design supports it either way; recommend deferring the drain but reserving the `channel` enum value now.

---

## Scheduling & background automation

Ryuki models time-driven work everywhere — patch waves, maintenance windows, monthly golden-image builds, secret-rotation due dates, DR test cadences, recertification campaigns — but nothing in the platform can fire on its own. There is no job queue, no timer, no cron facility, no worker process, and no jobs schema: every computation happens synchronously inside an Axum handler at the instant a client calls it. A "scheduled" monthly image build is a row pushed into an in-process `Mutex<Vec>` that never re-fires; "due" rotations are recomputed on every GET and forgotten. For a credible automation platform this is the single largest structural gap: the catalog contracts already describe a worker-dispatch and operation-queue model (`catalog/worker-capability-contract.yaml`, `catalog/activity-operation-queue-contract.yaml`), but both explicitly disable it (`liveDispatchAllowed: false`, `workerDispatchAllowed: false`) and no implementation exists behind them.

### Current state

- **No background execution machinery.** `sources/ryuki-api/src/main.rs` (the `main` at lines 584–723) only configures middleware and serves Axum; it spawns no tasks. No `Cargo.toml` in the workspace depends on any scheduler or job-queue crate (no `tokio-cron-scheduler`, `apalis`, `sqlxmq`). A grep for `tokio::spawn`/`interval`/`cron` across `sources/`, `portal/`, and `scripts/validator-rs` finds only false positives ("acronis" in `sources/ryuki-core/src/types.rs:745`, a `upper_case_acronyms` clippy allow in `sources/ryuki-engine/src/sql_deployment.rs:59`).
- **"Schedule" endpoints don't schedule.** `image_factory::schedule_monthly_build` (`sources/ryuki-engine/src/image_factory.rs:314-351`) pushes a `GoldenImage` with status `Building` into the in-process `image_store()` mutex and returns `{"source":"dry-run","scheduled":true,"cadence":"monthly"}` — no timer, no persistence, no re-fire. Notably, migration `migrations/041_image_factory.sql` already creates `golden_images` and `build_test_results` tables, but the engine never reads or writes them. The maintenance calendar contract hard-codes rule `no-live-calendar-action`: it "produces aggregate plans only and never schedules changes or sends notifications" (`sources/ryuki-engine/src/maintenance_calendar.rs:490-496`).
- **All due-date surfaces are pull-only.** `sources/ryuki-api/src/contracts.rs` registers request-time computations at `/api/protect/secrets/due` and `/api/protect/secrets/expiring` (lines 885–886), `/api/observe/synthetic/run-all` (line 999; handler `synthetic_run_all` at line 5738 calls `synthetic_health::run_all_checks` synchronously over in-memory `CHECK_STORE`/`RESULT_STORE`), `/api/protect/dr/due-tests` (1289), `/api/maintain/certificates/expiring` (1260–1261), `/api/identity/gmsa/expiring` (291), `/api/identity/access-review/due` (219), `/api/protect/legal-hold/expiring` (961), `/api/datacenter/oob/cert-expiring` (1608), and `/api/datacenter/hardware/warranty-expiring` (1661–1662).
- **No durable substrate.** Migrations `001`–`043` contain no `jobs`, `schedules`, `job_executions`, or `workers` table. The three `*_queue` tables (`029_shift_queue.sql`, `031_monitoring_queue.sql`, `034_servicenow_queue.sql`) are human review queues with no lease, worker-assignment, or `next_run_at` columns. `migrations/017_maintenance_windows.sql` and `migrations/010_patch_waves.sql` store windows/waves with status fields, but nothing consumes them at `start_time`.
- **Workers are contract fiction.** `catalog/worker-capability-contract.yaml` is `status: draft`, `source: static-seed`, with `liveDispatchAllowed: false` and rule `no-live-worker-dispatch`; `catalog/activity-operation-queue-contract.yaml` declares `workerDispatchAllowed: false` and `queueSummaryReadOnly: true` (though it usefully enumerates queue states: `queued/running/blocked/retrying/waiting-approval/completed/failed/canceled/stale`). `contracts.rs` contains 12 occurrences of `workerExecutionEnabled: false` / `worker-execution-disabled`, and no worker process exists in any crate.
- **Window/retention config is display-only.** `RYUKI_RETENTION__*` and `RYUKI_MAINTENANCE_WINDOW__*` are validated at startup (`sources/ryuki-core/src/types.rs:481-517`, `sources/ryuki-core/src/config.rs`) but their only runtime consumer is the admin JSON serializer (`sources/ryuki-api/src/config.rs:132-143`). No lifecycle guard reads `config.maintenance_window.*` when a request enters `Executing` (`request_lifecycle::transition_status`, `sources/ryuki-engine/src/request_lifecycle.rs:482-524`), and `backup_engine.rs:123`'s only "retention" mention is a hardcoded string.

### Design

#### Feature 1 — Durable scheduler schema (`migrations/044_scheduler.sql`)

**Goal.** Give recurring and background work a persistent home so fired jobs survive restarts and produce auditable history.

**Data model.** One new migration, `migrations/044_scheduler.sql`, following the house style of `034_servicenow_queue.sql` (UUID PKs, TIMESTAMPTZ, CHECK-constrained status, JSONB metadata, seed rows):

- `schedules` — `id UUID PK`, `name TEXT UNIQUE`, `job_kind TEXT` (e.g. `synthetic-run-all`, `image-factory-monthly-build`, `secrets-due-scan`, `certificates-expiring-scan`, `dr-tests-due-scan`, `access-review-due-scan`), `cadence TEXT CHECK (cadence IN ('hourly','daily','weekly','monthly','cron'))`, `cron_expr TEXT`, `site TEXT`, `payload JSONB DEFAULT '{}'`, `enabled BOOLEAN DEFAULT false`, `live_execution_allowed BOOLEAN DEFAULT false`, `next_run_at TIMESTAMPTZ`, `last_run_at TIMESTAMPTZ`, `created_by TEXT`, timestamps.
- `job_executions` — `id UUID PK`, `schedule_id UUID NULL REFERENCES schedules(id)` (NULL = ad-hoc "run now"), `job_kind TEXT`, `status TEXT` CHECK-constrained to exactly the queue states already published in `catalog/activity-operation-queue-contract.yaml` (`queued`, `running`, `blocked`, `retrying`, `waiting-approval`, `completed`, `failed`, `canceled`, `stale`), `attempt INT`, `max_attempts INT DEFAULT 3`, `leased_by TEXT`, `lease_expires_at TIMESTAMPTZ`, `scheduled_for TIMESTAMPTZ`, `started_at`/`finished_at TIMESTAMPTZ`, `result JSONB` (redacted summary only), `evidence_refs JSONB DEFAULT '[]'`, `blocked_reason TEXT`, `error TEXT`. Index on `(status, scheduled_for)` for claim queries.
- `workers` — `id UUID PK`, `worker_name TEXT UNIQUE`, `capability_tags TEXT[]` drawn from the contract's `capabilityTypes` (`generic-worker`, `windows-gmsa`, `powercli`, `linux-ansible`, `protected-network`), routing columns mirroring the contract's `routingDimensions` (`site TEXT`, `network_zone TEXT`, `os_families TEXT[]`, `risk_levels TEXT[]`), `status TEXT CHECK (status IN ('registered','healthy','degraded','offline'))`, `last_heartbeat_at TIMESTAMPTZ`. Seed exactly one row: `platform-internal` with `capability_tags = ARRAY['generic-worker']` — the in-process executor.

Seed `schedules` with disabled examples (`synthetic-run-all` daily per site, `image-factory-monthly-build` monthly for DEFRA) so the portal has something to render in dry-run installs.

**Validation & evidence.** Extend the `db_tests::test_migrations_run_against_pg18` assertion list in `sources/ryuki-api/src/main.rs` to include the three new tables. `result` and `evidence_refs` carry summaries only — never raw provider payloads, per `catalog/activity-operation-queue-contract.yaml` rule `raw-activity-queue-data-not-exposed`.

**Safety.** Seeds are `enabled = false` and `live_execution_allowed = false`; the migration alone changes no runtime behavior.

#### Feature 2 — In-process scheduler runtime (`sources/ryuki-api/src/scheduler.rs`)

**Goal.** A tick loop that fires due schedules, claims executions safely, runs job kinds against existing pure engine functions, and records results — without adding a third service (the existing `two-service-local-topology-required` governance rule in `contracts.rs:3361` requires the portal and API to remain the only active services until a worker slice is separately approved, so in-process is the *governance-compliant* first step).

**Engine/API changes.**
- New module `sources/ryuki-api/src/scheduler.rs`, spawned with `tokio::spawn(scheduler::run(...))` from `main()` immediately after `database::migrate_if_connected()` (main.rs:622). It does nothing unless `config.scheduler.enabled` is true *and* `database::get_db()` returns a pool.
- Config: add a `SchedulerConfig` section to `sources/ryuki-core/src/config.rs` (`RYUKI_SCHEDULER__ENABLED` default `false`, `RYUKI_SCHEDULER__TICK_SECONDS` default `30`, `RYUKI_SCHEDULER__LEASE_SECONDS` default `300`), validated alongside the existing sections in `types.rs`, surfaced in the admin serializer in `sources/ryuki-api/src/config.rs`, documented in `docs/configuration.md` and `.env.example`.
- Tick loop: take a Postgres advisory lock (`pg_try_advisory_lock`) so multiple API replicas never double-fire; then `UPDATE schedules ... WHERE enabled AND next_run_at <= NOW()` to enqueue `job_executions` rows (`status = 'queued'`) and advance `next_run_at`; then claim work with `SELECT ... FROM job_executions WHERE status IN ('queued','retrying') ... FOR UPDATE SKIP LOCKED`, setting `leased_by = 'platform-internal'` and `lease_expires_at`. Use plain `tokio::time::interval` — no new crate needed for v1; cron-expression parsing can use the small `cron` crate if `cadence = 'cron'` is kept in scope.
- Job dispatch: a `match job_kind` that calls existing engine functions — `synthetic_health::run_all_checks(site)`, the due/expiring computations behind `secrets_due_rotations`, `certificates_expiring`, `dr_tests_due`, `access_reviews_due`, `gmsa_expiring`, `hardware_warranty_expiring`, and `image_factory::schedule_monthly_build`. Findings are written into `job_executions.result` as a redacted summary (counts, IDs, statuses) and, where a human should act, inserted into the existing review queues (`shift_queue` from `migrations/029_shift_queue.sql` is the natural sink for "12 secrets due for rotation" findings).
- Actor identity: scheduler-originated rows record `created_by = 'system-scheduler'`. The HTTP auth middleware (`auth_middleware`, main.rs:169) is not in this path, so the system principal must be stamped explicitly in every insert for the audit trail.
- Shutdown: the loop watches the existing `DRAINING` flag (main.rs:259, `set_draining`) and stops claiming new work when draining, letting in-flight jobs finish within the shutdown timeout.

**Validation & evidence.** Each execution appends an evidence reference (summary JSON, started/finished timestamps, outcome) to `evidence_refs`, consistent with the platform's evidence-first posture. Unit tests cover `next_run_at` advancement, lease expiry reclamation (`stale` status), and retry/backoff transitions.

**Safety/dry-run.** Scheduler disabled by default; every job kind runs in dry-run mode (results carry `"source":"dry-run"` exactly like the handlers they reuse). A job may only trigger a state-changing action if its schedule has `live_execution_allowed = true`, and even then it must not bypass governance: jobs that want changes **create Draft requests in the existing request lifecycle** (e.g. "monthly image build" creates a request that still passes Validated→Planned→Approved→Locked), they never execute directly. This keeps the scheduler aligned with the lifecycle hardening in recent commits (`90228ea`, `841e68f`).

#### Feature 3 — Schedule management API + portal surface

**Goal.** Operators can see, enable, pause, and manually fire schedules, and audit execution history.

**API endpoints** (in `sources/ryuki-api/src/contracts.rs`, following the `/api/ops/...` convention used by runbooks and shift queue at lines 573–614):
- `GET /api/ops/scheduler/schedules` — list with `next_run_at`/`last_run_at`.
- `POST /api/ops/scheduler/schedules` — create (PlatformAdmin only, mirroring the verified-admin guard from commit `7172ea8`).
- `PATCH /api/ops/scheduler/schedules/{id}` — enable/disable, cadence change.
- `POST /api/ops/scheduler/schedules/{id}/run-now` — enqueue an ad-hoc `job_executions` row (still executed by the loop, so manual runs share the same evidence path).
- `GET /api/ops/scheduler/executions?schedule_id=&status=` and `GET /api/ops/scheduler/executions/{id}` — history.
- `GET /api/ops/scheduler/workers` — worker registry + heartbeat freshness.
- `GET /api/ops/scheduler-contract` — static contract describing job kinds, queue states, and guards, replacing the fiction in `admin_worker_capability` (contracts.rs:1074–1075, handler at 5994) with one backed by real tables.
- Rewire `POST /api/datacenter/image-factory/schedule-monthly` (contracts.rs:1758–1759, handler at 9287) to insert a `schedules` row (and persist images to the already-existing `golden_images` table from migration 041) instead of mutating the in-memory store.

**Portal UI.** `portal/portal-ui/src/views/dashboard.rs` gains an "Automation" card (enabled schedules, next fire, last 24h success/failure counts); `portal/portal-ui/src/views/workspaces.rs` gains a scheduler workspace listing schedules with toggle/run-now actions and an execution-history drawer — all via same-origin server functions per the Leptos SSR convention.

**Validation & evidence.** New catalog contract `catalog/job-scheduler-contract.yaml` (rules: `dry-run-by-default`, `jobs-create-requests-not-changes`, `no-secret-values-in-results`, `evidence-required-per-execution`) with a matching self-contained validator `scripts/validator-rs/src/job_scheduler.rs`, alongside updates to `scripts/validator-rs/src/worker_capability.rs` and `activity_operation_queue.rs` for the newly-real fields.

**Safety.** Mutating routes are already behind the unsafe-method auth middleware; schedule creation/enable additionally requires the PlatformAdmin role. `run-now` on a `live_execution_allowed = false` schedule always produces a dry-run execution.

#### Feature 4 — Worker dispatch model (`sources/ryuki-worker`, phase 2)

**Goal.** Make `catalog/worker-capability-contract.yaml` real: out-of-process workers (e.g. a gMSA Windows worker, a PowerCLI worker in a protected network zone) claim jobs by capability instead of the API executing everything in-process.

**Design.** New crate `sources/ryuki-worker` that registers itself in `workers`, heartbeats, and claims `job_executions` whose routing dimensions (`workflowType`, `osFamily`, `site`, `networkZone`, `riskLevel` — the contract's `routingDimensions`) match its `capability_tags`, using the same `FOR UPDATE SKIP LOCKED` lease. Routing-ambiguity blocks dispatch (`route-ambiguous` → `status = 'blocked'`), matching contract rule `ambiguous-route-blocks-dispatch`. Worker credentials are secret *references* only (`secretValuesAllowed: false`). This phase requires explicitly revising the contract (`liveDispatchAllowed`), the `two-service-local-topology-required` rule, and the compose topology — it is deliberately sequenced last and gated on its own approval.

#### Feature 5 — Enforce maintenance-window and retention config

**Goal.** The configuration the platform already validates should change behavior: requests should not enter `Executing` outside a window, and backup grading should use configured retention.

**Engine changes.**
- `sources/ryuki-engine/src/request_lifecycle.rs`: extend the `(Locked, Executing)` transition arm (lines 489/521) with a window check. Engines are config-free pure functions today, so pass a small snapshot struct (`MaintenanceWindowPolicy { enabled, day_of_week, start_hour_utc, duration_hours }` plus any matching per-site rows from `maintenance_windows`) as a parameter from the API handler — preserving the "no global mutable state" convention. Outside the window the transition returns a blocked result with reason `outside-maintenance-window` (warn-only mode configurable; emergency changes via the existing emergency-change path bypass with evidence).
- Precedence: a site-scoped active row in `maintenance_windows` (migration 017) overrides the global `config.maintenance_window` default; the same handler change finally makes migration 017 consumed data.
- `sources/ryuki-engine/src/backup_engine.rs` and `immutability_compliance.rs`: grade coverage against `config.retention.daily/weekly/monthly/yearly` (passed in the same snapshot style) instead of the hardcoded string at `backup_engine.rs:123`.

**API/portal.** A `GET /api/ops/scheduler/window-status` route reporting "in window / next window opens at"; the portal admin settings view shows *enforcement status* ("enforced, warn-only, disabled") rather than bare values; request detail (`portal/portal-ui/src/views/request_detail.rs`) surfaces the blocked reason when a transition is held for the window.

**Safety.** Ship warn-only by default (`RYUKI_MAINTENANCE_WINDOW__ENFORCEMENT=warn|block|off`), so existing flows do not break on upgrade; blocking mode is an explicit opt-in.

### Implementation plan

1. **S** — Add `SchedulerConfig` (`RYUKI_SCHEDULER__*`) and `RYUKI_MAINTENANCE_WINDOW__ENFORCEMENT` to `sources/ryuki-core/src/config.rs` + `types.rs` validation, admin serializer, `docs/configuration.md`, `.env.example`.
2. **M** — `migrations/044_scheduler.sql` (`schedules`, `job_executions`, `workers`) with seeds; extend the PG18 migration test in `sources/ryuki-api/src/main.rs`.
3. **M** — `sources/ryuki-api/src/scheduler.rs`: tick loop, advisory lock, enqueue + `SKIP LOCKED` claim, lease expiry → `stale`, retry/backoff, `DRAINING`-aware shutdown; spawn from `main()`.
4. **M** — First job kinds wired to existing engine functions (`synthetic-run-all`, secrets/certificates/DR/access-review/gmsa/warranty due-scans) writing `job_executions.result` + `shift_queue` findings.
5. **M** — Persist image factory to `golden_images`/`build_test_results` (migration 041) and rewire `/api/datacenter/image-factory/schedule-monthly` to create a `schedules` row.
6. **M** — Schedule management routes under `/api/ops/scheduler/...` + `scheduler-contract`; PlatformAdmin guard on mutations.
7. **M** — Portal: dashboard "Automation" card + scheduler workspace with execution history.
8. **M** — Maintenance-window guard on `Locked→Executing` (warn-only default) + retention-aware grading in `backup_engine`/`immutability_compliance`.
9. **S** — `catalog/job-scheduler-contract.yaml` + `scripts/validator-rs/src/job_scheduler.rs`; update `worker_capability.rs`/`activity_operation_queue.rs` validators.
10. **L** — Phase 2: `sources/ryuki-worker` crate, capability routing, contract/topology revisions for out-of-process dispatch.

### Risks & open questions

- **Governed execution boundary.** The strongest open question: when a fired job needs to *change* something, does it always create a Draft request (recommended; preserves the Draft→…→Executing lifecycle and approval gates) or may whitelisted low-risk kinds (synthetic checks, due-scans) act directly? Proposed rule: read/compute jobs act directly; anything mutating infrastructure creates a request.
- **In-memory engine state.** `synthetic_health`'s `CHECK_STORE`/`RESULT_STORE` and `image_factory`'s `image_store()` are process-local; scheduled runs against them produce history that vanishes on restart. Persisting these stores (041 already exists for images; synthetic checks have `016_synthetic_checks.sql`) is a prerequisite for meaningful job history and may grow steps 4–5.
- **HA semantics.** Advisory lock gives single-firer behavior, but lease takeover, clock skew between replicas, and misfire/catch-up policy after downtime (fire-once vs skip) need explicit decisions; recommend "skip missed, log a `stale` execution" for v1.
- **Window timezone semantics.** `config.maintenance_window` is defined in UTC hours; per-site windows in `maintenance_windows` are TIMESTAMPTZ ranges. Sites span timezones with DST — confirm UTC-only is acceptable for v1 or add per-site timezone columns.
- **Topology governance.** The `two-service-local-topology-required` rule (contracts.rs:3361) and `worker-capability-contract.yaml`'s `no-live-worker-dispatch` rule must be formally revised before phase 2; the in-process scheduler intentionally avoids tripping either, but reviewers should confirm a background task inside ryuki-api does not itself count as "runtime expansion".
- **Cron scope.** Full cron expressions add a dependency and validation surface; v1 could ship `hourly/daily/weekly/monthly` cadences only and defer `cron_expr`.

---

## Platform observability & self-monitoring

The control plane cannot see itself. All seven component self-health checks in `sources/ryuki-engine/src/health_monitor.rs` unconditionally return `Healthy`/`Simulated`, including the database check — even though `ryuki-api` holds a live sqlx pool it already pings in `/ready`. These fake checks feed six JSON routes and the `ryuki_platform_health` Prometheus gauge, so vault, Kubernetes, validator, adapter, portal, and DB failures are invisible at the component level. `/metrics` is hand-assembled, process-local, unauthenticated, and fabricates quantiles from min/avg/max; tracing parses `traceparent` but exports nowhere. The deploy artifacts ship no scrape wiring, alert rules, dashboards, or log shipping, and the NetworkPolicies actively block a monitoring namespace from scraping. Finally, the operator-facing `platform-health-dashboard` is a `status: planned` catalog offering whose portal surface renders a hardcoded fallback frozen at `2025-01-01T00:00:00Z`. For a governed automation platform whose pitch is "Zero blind spots" (`docs/index.html:887`), the platform itself is the biggest blind spot — an outage of vault or an adapter would execute-gate nothing and alert no one.

### Current state

**Self-health checks are stubs.**
- `sources/ryuki-engine/src/health_monitor.rs:102-181` — `check_api_health`, `check_portal_health`, `check_validator_health`, `check_kubernetes_health`, `check_vault_health`, `check_database_health`, `check_adapter_health` all hardcode `HealthStatus::Healthy` + `HealthSource::Simulated` with a `"DRY-RUN: ... simulated"` message. The `HealthSource` enum already defines `DependencyBacked` and `Unavailable` variants (lines 23-29) but nothing ever produces them.
- Unit tests at `health_monitor.rs:270-283` (`test_all_checks_healthy_in_dry_run`) and `:286-296` assert every check is always `Healthy`/`Simulated`, cementing the stub.
- Consumers: routes registered in `sources/ryuki-api/src/contracts.rs:1158-1175` (`/api/platform/health`, `/api/platform/health/all`, `/api/platform/health/components`, `/api/platform/health/adapters`, `/api/platform/health/check/{adapter}`, `/api/platform/health/metrics`), handlers at `contracts.rs:6466-6530` and `:9525-9540`, plus the `/metrics` handler at `sources/ryuki-api/src/main.rs:919-986` emitting `ryuki_platform_health{component=...}` permanently `1`.
- Real probes that DO exist: `/health` (pool presence + config validation, `main.rs:725-776`), `/ready` (real `SELECT 1` + migration state, `main.rs:778-842`), pool gauges from `sources/ryuki-api/src/database.rs:47-67` (`ryuki_db_pool_connected`). A DB outage is detectable via readiness; nothing else is.

**Metrics and tracing are hand-rolled with no export backend.**
- Per-endpoint counters: `Mutex<HashMap<String, u64>>` keyed `"METHOD /path"` with no cardinality cap (`main.rs:271-284`, `:307-342`); `normalize_metrics_path` only collapses UUID/numeric segments, so 404-probed paths create permanent label entries.
- Durations: `Mutex<Vec<u64>>` with O(n) `Vec::remove(0)` eviction at 10k entries (`main.rs:344-388`); quantiles fabricated from min/avg/max in `health_monitor.rs:225-263` ("Estimate quantiles using min, avg, and max"). No per-status-code or error-rate metrics; everything resets on restart.
- `/metrics` is unauthenticated: `auth_middleware` only gates unsafe methods (`main.rs:154-208`), so every GET passes.
- A duplicate static route `/api/platform/health/metrics` (`contracts.rs:9535-9540`) serves `metrics_text()` with the request counter hardwired to 0.
- `traceparent` is parsed in `request_id_middleware` and a `traceresponse` is fabricated from a fresh UUID (`main.rs:210-252`); spans go only to the stdout `tracing_subscriber` (`main.rs:590-611`). No `opentelemetry`, `tracing-opentelemetry`, `prometheus`, or `metrics` crate exists in any `Cargo.toml`/`Cargo.lock` in the workspace.
- `/api/boundary/status` returns `Json(BoundaryStatus::default())` with no computed state (`sources/ryuki-api/src/boundary.rs:8-10`).

**Deploy artifacts have zero observability wiring.**
- The only monitor in the repo is CNPG's `enablePodMonitor: true` (`deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml:72`). No ServiceMonitor/PodMonitor for `platform-api`/`portal-ui`, no `prometheus.io/scrape` annotations, no PrometheusRule, no Grafana dashboards, no loki/fluent-bit/vector/promtail anywhere; `deploy/compose/compose.yaml` ships only postgres + platform-api + portal-ui.
- `deploy/kubernetes/base/networkpolicies.yaml` is default-deny both directions; ingress to `platform-api:8080` is allowed only from ingress-nginx and portal-ui pods, so a Prometheus in a `monitoring` namespace cannot scrape. `default-deny-egress` plus DNS-only egress also blocks any future OTLP export.
- `RYUKI_LOG_EXTENDED__FILE_PATH` (`.env.example:81-82`) is parsed and validated in `sources/ryuki-core/src/config.rs` (`log_extended` field; `retention_days > 0` rule) and echoed in `/api/platform/status` (`sources/ryuki-api/src/config.rs:122-124`) — but no code ever opens the file; `tracing_appender` is absent from the workspace, and `deployments.yaml:44,95` set `readOnlyRootFilesystem: true` with no volumes, so a file write would fail anyway. Dead config.

**Operator surface is a frozen mock.**
- `platform-health-dashboard` is `status: planned` in `catalog/offering-catalog.yaml:398-399` and duplicated as a static seed in `contracts.rs:3390`.
- The portal server fn `get_platform_health` (`portal/portal-ui/src/server_boundary.rs:990-997`) validates the path against the same-origin guard, then returns `platform_health_fallback()` — all-healthy, timestamp `"2025-01-01T00:00:00Z"` (`portal/portal-ui/src/models.rs:674-689`). The portal `PlatformHealth`/`HealthCheck` models (`models.rs:611-626`) drop the `source` field, so operators cannot see the data is simulated.
- `portal/portal-ui/src/api_client.rs` is path-validation + JSON-decoding only — **there is no HTTP transport in portal-ui at all** (no reqwest/hyper client dependency). `OperationsWorkspaceDetail` (`portal/portal-ui/src/views/workspaces.rs:1041-1130`) renders `operation_run_fallbacks()` with "Runbook launch and platform health stay static"; `PortalActivityRunStateSnapshot::static_dry_run` hardcodes `queue_state: "blocked"`, `run_state: "dry-run-only"` (`server_boundary.rs:586-619`). `ALLOWED_PORTAL_API_PATHS` (`server_boundary.rs:77-128`) contains neither `/metrics` nor `/api/platform/uptime`.
- The acceptance bar already exists: `scripts/validator-rs/src/platform_health.rs` requires components (`portal-ui`, `platform-api`, `platform-db`, `platform-vault`, `adapters`, `queue`, ...), signals (`readiness`, `stale-data`, `dependency-health`, ...), and block rules (`stale-data-must-be-marked`, `owner-and-remediation-required`, `raw-logs-not-exposed`, `no-live-health-remediation`). Caveat: that validator pins `status: draft` / `source: static-seed` / `healthMode: degraded-read-only` / `providerCallsEnabled: false` and parses legacy C# paths (`api/Ryuki.Platform.Api/Program.cs`, `docs/workflows/platform-health.md`) that no longer exist in the tree.

### Design

#### Feature 1 — Dependency-backed component health checks

**Goal.** Every check in `ryuki_platform_health{component=...}` and the `/api/platform/health*` routes reflects a real probe or honestly reports `Unknown`/`Unavailable`; the DB check is always live (in-process, safe in dry-run); the `source` field is never silently `simulated` while claiming `healthy`.

**Data model.** New migration `migrations/044_platform_health_snapshots.sql`:

```sql
CREATE TABLE platform_health_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    component       TEXT NOT NULL,
    check_name      TEXT NOT NULL,
    status          TEXT NOT NULL,      -- healthy|degraded|unhealthy|unknown
    source          TEXT NOT NULL,      -- simulated|dependency-backed|unavailable
    latency_ms      INTEGER,
    message         TEXT NOT NULL,      -- component-safe summary, no URLs/hosts
    owner           TEXT NOT NULL,
    safe_remediation TEXT NOT NULL
);
CREATE INDEX idx_health_snapshots_component_time
    ON platform_health_snapshots (component, captured_at DESC);
```

Snapshots are the evidence trail (the offering's required evidence includes "Health snapshot" and "Dashboard timestamp"); Prometheus remains the time-series source of truth. A retention sweep deletes rows older than `retention.health_snapshot_days` (new field in `RetentionConfig`, `sources/ryuki-core/src/config.rs`).

**Engine changes.** Refactor `sources/ryuki-engine/src/health_monitor.rs` so the engine stays pure (no I/O, matching the repo's engine/adapter split):
- New `pub struct ProbeOutcome { pub reachable: Option<bool>, pub latency_ms: Option<u64>, pub detail: ProbeDetail }` and `pub fn evaluate_check(name, component, owner, safe_remediation, outcome: Option<ProbeOutcome>) -> HealthCheck`. `None` outcome ⇒ `HealthStatus::Unknown` + `HealthSource::Simulated` with a message like `"not probed: probe mode is simulated"` — no more fake `Healthy`.
- Extend `HealthCheck` with `owner: String` and `safe_remediation: String` (required by the validator's `owner-and-remediation-required` rule and the contract's `requiredInputs`). Ownership comes from a static `COMPONENT_OWNERS` map in the engine (e.g. `platform-db` → "Platform Admin").
- Delete `metrics_text`, `metrics_text_with_api_requests`, and `append_duration_metrics` (`health_monitor.rs:183-263`) — metrics assembly moves to the API recorder (Feature 2).
- Rewrite the test module: replace `test_all_checks_healthy_in_dry_run` with table-driven tests asserting Unknown-when-unprobed, Unhealthy-on-failed-probe, Degraded-on-slow-probe, and that messages never contain `://`, IPs, or hostnames (the validator's `scan_prohibited_value` rejects them).

**API changes.** New module `sources/ryuki-api/src/health_probes.rs` (the API owns the pool and HTTP clients):
- `probe_database()` — `crate::database::get_db()` + `SELECT 1` with measured latency, exactly like `readiness_check()` (`main.rs:831-841`); always live, even in dry-run (in-process resource, not a provider call).
- `probe_api()` — in-process: uptime, `migration_status()`, draining flag; always dependency-backed.
- `probe_portal()`, `probe_validator()`, `probe_vault()`, `probe_kubernetes()` — `reqwest` (new dependency in `sources/ryuki-api/Cargo.toml`, rustls feature) GETs against configurable endpoints: portal `/readyz`, vault `/v1/sys/health` (unauthenticated by design), Kubernetes `/readyz` via the in-cluster service account. New `HealthProbeConfig` in `sources/ryuki-core/src/config.rs` (`AppConfig.health`): `probe_mode: simulated|live` (default `simulated`), `interval_secs` (default 60), `timeout_ms` (default 2000), `portal_base_url`, `vault_base_url`, `kubernetes_base_url`, all optional — unset endpoint ⇒ `Unavailable`. Env: `RYUKI_HEALTH__PROBE_MODE`, `RYUKI_HEALTH__PORTAL_BASE_URL`, etc. in `.env.example`.
- `probe_adapter(adapter)` — only adapters configured for live execution get probed; in dry-run they report `Unknown`/`Simulated` ("adapter not enrolled for live probing").
- A background `tokio::spawn` sampler started in `main()` after `migrate_if_connected()` runs all probes every `interval_secs`, stores the result in a `tokio::sync::watch` channel (no global mutable state beyond the existing `OnceLock` pattern), sets the `ryuki_platform_health` gauge, and inserts a `platform_health_snapshots` row when the pool is up.
- Handlers `platform_health`, `platform_health_components`, `platform_health_adapters`, `platform_health_all_checks`, `platform_health_check_adapter` (`contracts.rs:6466-6530`, `:9525-9533`) read the latest sampled `PlatformHealth` from the watch channel and add `"stale": true` + `stale-data` marker when the snapshot is older than `2 × interval_secs` (satisfies `stale-data-must-be-marked`). New route `GET /api/platform/health/history?component=&limit=` backed by the snapshot table.

**Validation & evidence.** Snapshots are the evidence record; the `/api/operations/platform-health-contract` payload gains `healthMode: "live-read-only"` when `probe_mode=live`. Update `scripts/validator-rs/src/platform_health.rs` to accept `healthMode ∈ {degraded-read-only, live-read-only}` and `source ∈ {static-seed, dependency-backed}` while keeping `providerCallsEnabled=false`, `liveExecutionAllowed=false`, `rawLogsAllowed=false` immutable (health stays read-only forever — `no-live-health-remediation`).

**Safety/dry-run.** Probes are read-only GETs with hard timeouts and no retry storms; they are infrastructure self-checks, not provider calls, but adapter probes still respect the execution boundary (simulated unless the adapter is live-enabled). Check messages carry component-safe text only — never endpoint URLs, credentials, or raw payloads (enforced by the rewritten engine tests and the existing validator prohibited-value scan).

#### Feature 2 — Real metrics pipeline and tracing export

**Goal.** Histogram-based, status-labeled, bounded-cardinality metrics from a standard recorder; OTLP trace export with real context propagation; `/metrics` no longer anonymous.

**Engine changes.** None beyond the deletions in Feature 1.

**API changes** (`sources/ryuki-api/src/main.rs`, `Cargo.toml`):
- Add `metrics` + `metrics-exporter-prometheus`. Replace `request_counter_middleware` + `timing_middleware` (`main.rs:307-388`) and the `PerEndpointCounter`/`DurationTracker` statics (`main.rs:271-284`, `:344-355`) with one `track_http_metrics` middleware that uses axum's `MatchedPath` for the route label (registered routes only; unmatched requests get `route="unmatched"` — kills the 404-cardinality leak) and records:
  - `ryuki_http_requests_total{method, route, status}` (counter)
  - `ryuki_http_request_duration_seconds{method, route}` (true histogram, default buckets)
  - `ryuki_db_pool_connections{state}` / `ryuki_db_pool_connected` re-registered as gauges from `database::pool_metrics()`
  - `ryuki_platform_health{component, source}` set by the Feature 1 sampler
  - keep `ryuki_platform_info{version}`.
- The `/metrics` handler becomes `PrometheusHandle::render()`. Delete the duplicate `/api/platform/health/metrics` route (`contracts.rs:1163-1166`, `:9535-9540`) — one scrape endpoint.
- Gate `/metrics`: new `ObservabilityConfig` in `ryuki-core/src/config.rs` with `metrics_bind_addr: Option<String>` (preferred: a second listener on `:9090`, which composes cleanly with NetworkPolicies and keeps the main listener auth story unchanged) and `metrics_bearer_token: Option<String>` for single-listener deployments; when a token is set, the handler requires `Authorization: Bearer`. Never log the token; `.env.example` documents `RYUKI_OBSERVABILITY__METRICS_BIND_ADDR` / `__METRICS_BEARER_TOKEN` as commented placeholders (no real secrets committed).
- Tracing: add `tracing-opentelemetry`, `opentelemetry`, `opentelemetry-otlp`, `opentelemetry_sdk`. In the subscriber init (`main.rs:590-611`), layer an OTLP exporter when `RYUKI_OBSERVABILITY__OTLP_ENDPOINT` is set (service name `ryuki-platform-api`); otherwise behavior is unchanged. In `request_id_middleware` (`main.rs:210-252`), extract the W3C context from the incoming `traceparent` and set it as the span parent instead of fabricating `traceresponse` from a random UUID; keep `x-request-id` for log correlation.
- Implement `BoundaryStatus` computation in `sources/ryuki-api/src/boundary.rs` from `config_store::get_app_config()` (execution mode, provider-call/live-execution flags) so the boundary endpoint and the portal's boundary banner reflect actual configuration rather than `Default::default()`.
- Portal parity (optional, same pattern): add the recorder to the portal Axum server so `portal-ui:9090/metrics` exists for the ServiceMonitor in Feature 3.

**Validation & evidence.** Keep `test_metrics_text_no_secrets`-equivalent assertions against rendered exporter output; add a contract test asserting `route` label cardinality equals the registered route count + 1.

**Safety/dry-run.** Metrics and traces carry route templates and status codes only — no request bodies, no identifiers; the OTLP exporter is off unless explicitly configured.

#### Feature 3 — Scrape wiring, alerts, dashboards, and log shipping in deploy artifacts

**Goal.** A cluster operator who applies `deploy/kubernetes/` gets scraped metrics, alert rules, a dashboard, and a documented log path with zero bespoke glue.

**Deploy changes** (no code):
- `deploy/kubernetes/monitoring/` (new directory, applied optionally like `cloudnativepg/`):
  - `servicemonitors.yaml` — ServiceMonitors for `platform-api` and `portal-ui` targeting the metrics port (matches the `app.kubernetes.io/name` labels already in `deployments.yaml`/`services.yaml`).
  - `prometheusrules.yaml` — `RyukiApiDown` (`up == 0` for 5m), `RyukiApiNotReady` (readiness probe failures), `RyukiDbPoolDisconnected` (`ryuki_db_pool_connected == 0` for 5m), `RyukiComponentUnhealthy` (`ryuki_platform_health == 0` for 10m, severity by component), `RyukiHighErrorRate` (5xx ratio from `ryuki_http_requests_total` > 5% over 10m), `RyukiHealthDataStale` (sampler timestamp age).
  - `grafana-dashboard-platform.json` — request rate/latency/error panels, pool gauges, component-health heatmap, uptime.
  - `fluent-bit.yaml` — example DaemonSet shipping stdout JSON logs (the supported log path) to a configurable sink.
- `deploy/kubernetes/base/networkpolicies.yaml` — add `allow-monitoring-ingress` (namespaceSelector `kubernetes.io/metadata.name: monitoring` → tcp/9090 on both apps) and `allow-platform-api-egress-otlp` (egress to the collector service, tcp/4317) since `default-deny-egress` currently blocks both scraping and exporting.
- `deployments.yaml` — add the `metrics` containerPort 9090 to both pods.
- `deploy/compose/compose.yaml` — add `prometheus` + `grafana` services under a `profiles: ["observability"]` block with a checked-in scrape config, so local dev sees the same dashboards.
- **Kill the dead log-file config** rather than implement it: remove `log_extended` from `ryuki-core/src/config.rs` (struct field, validation rule), `sources/ryuki-api/src/config.rs:122-124`, `.env.example:81-82`, and `docs/configuration.md`; document "stdout JSON + cluster-level shipping" in `deploy/kubernetes/README.md`. (Alternative — `tracing_appender` + an `emptyDir` volumeMount — adds rotation, retention, and `readOnlyRootFilesystem` exceptions for no benefit in Kubernetes; rejected.)

**Validation & evidence.** Extend `scripts/validator-rs` (new `deploy_observability.rs` check module, wired like `check_config.rs`) to assert: every Deployment exposing `/metrics` has a matching ServiceMonitor, every alert rule references an existing metric family name, and no manifest contains `prometheus.io/scrape` annotations pointing at unauthenticated paths that NetworkPolicies don't permit.

**Safety/dry-run.** Manifests are inert until applied; the monitoring directory is opt-in and documented as such; no secrets in any YAML (Grafana admin creds referenced as a Secret name only).

#### Feature 4 — Live portal platform-health dashboard

**Goal.** Ship the `platform-health-dashboard` offering: the portal shows real component health with explicit source/staleness labeling, uptime, and DB-backed run history — meeting the validator's four block rules.

**Portal transport (prerequisite).** `portal/portal-ui/src/api_client.rs` has no HTTP layer. Add an ssr-feature-gated `reqwest` dependency to `portal/portal-ui/Cargo.toml` and a `fetch_resource<T>(resource: &ApiResource<T>) -> Result<T, ApiClientError>` that resolves `same_origin_path()` against a `RYUKI_PORTAL__PLATFORM_API_BASE_URL` env (the `allow-portal-ui-egress-to-platform-api` NetworkPolicy already permits this hop). The existing path-allowlist guard stays the single choke point: only paths in `ALLOWED_PORTAL_API_PATHS` (`server_boundary.rs:77-128`) can ever be fetched.

**Models** (`portal/portal-ui/src/models.rs:611-626`): add `source: String` to both `PlatformHealth` and `HealthCheck`, plus `owner`, `safe_remediation`, and `stale: bool`; keep `platform_health_fallback()` but stamp it `source: "fallback"`, `stale: true` so the frozen timestamp can never masquerade as live data.

**Server functions** (`portal/portal-ui/src/server_boundary.rs`):
- `get_platform_health` (`:990-997`): after the same-origin guard, fetch `/api/platform/health` via the new transport; on error return the fallback with the explicit stale/fallback markers. Same pattern for new `get_platform_uptime` (`/api/platform/uptime`) and `get_platform_health_history` (`/api/platform/health/history`).
- Add `platform_uptime_path()` / `platform_health_history_path()` to `portal/portal-ui/src/api.rs` (following the existing `platform_health_path()` const-fn convention at `api.rs:282`) and register them in `ALLOWED_PORTAL_API_PATHS`. Raw `/metrics` is deliberately **not** allowlisted — the portal shows summaries, never scrape output (`raw-logs-not-exposed`).

**View.** New `portal/portal-ui/src/views/platform_health.rs` registered in `views/mod.rs` and routed from the operations workspace (replacing the static health column in `OperationsWorkspaceDetail`, `views/workspaces.rs:1090-1133`):
- Component grid: status badge (`badge good|warn|bad` per existing classes), **source chip** (`simulated` / `dependency-backed` / `fallback`), owner, safe next action, last-check age with a visible "STALE" banner past the freshness window (offering input `freshnessWindow`).
- Uptime + DB pool summary panel from `get_platform_uptime` and the health payload.
- Run history table fed by `operation_runs_resource()` through the new transport instead of `operation_run_fallbacks()` (`models.rs` fallbacks remain for transport failure, marked as such).

**Catalog & contract flips (last step).** Set `status: available` for `platform-health-dashboard` in `catalog/offering-catalog.yaml` and the duplicated seed JSON at `contracts.rs:3390`; update `catalog/platform-health-contract.yaml` (`healthMode: live-read-only`, `source: dependency-backed`) together with the validator constants; create the missing `docs/workflows/platform-health.md` the validator requires (endpoint, "No live provider calls.", "No raw logs", "component-safe status").

**Safety/dry-run.** The dashboard is read-only (`dryRunRequired: false` in the offering because there is nothing to execute); remediation is advisory text only; all fetches stay same-origin-guarded and allowlisted; simulated/fallback data is always labeled — never rendered as live.

### Implementation plan

1. **S** — Compute real `BoundaryStatus` in `sources/ryuki-api/src/boundary.rs` from `config_store` (independent, unblocks honest portal banners).
2. **M** — Refactor `sources/ryuki-engine/src/health_monitor.rs`: `ProbeOutcome`/`evaluate_check`, `owner`/`safe_remediation` fields, delete `metrics_text*`/`append_duration_metrics`, rewrite the always-healthy tests.
3. **M** — `sources/ryuki-api/src/health_probes.rs` + `HealthProbeConfig` in `ryuki-core/src/config.rs` + background sampler + rewire handlers in `contracts.rs:6466-6530`/`:9525-9533`; live DB probe lands here.
4. **S** — `migrations/044_platform_health_snapshots.sql` + snapshot insert/retention sweep + `GET /api/platform/health/history`.
5. **M** — Swap to `metrics`/`metrics-exporter-prometheus`: unified middleware with `MatchedPath` labels, real histograms, second metrics listener/bearer gating, delete duplicate `contracts.rs` metrics route and the `Mutex` statics in `main.rs`.
6. **M** — OTLP layer in the subscriber init (`main.rs:590-611`) + real `traceparent` propagation in `request_id_middleware`.
7. **S** — Delete dead `log_extended` config (`ryuki-core/src/config.rs`, `sources/ryuki-api/src/config.rs:122-124`, `.env.example:81-82`, `docs/configuration.md`).
8. **M** — `deploy/kubernetes/monitoring/` (ServiceMonitors, PrometheusRules, Grafana JSON, fluent-bit example), NetworkPolicy additions, metrics ports in `deployments.yaml`, compose `observability` profile, README docs.
9. **M** — Portal transport: ssr-gated reqwest in `portal/portal-ui/Cargo.toml`, `fetch_resource` in `api_client.rs`, extended `PlatformHealth` models, live `get_platform_health`/`get_platform_uptime`/history server fns, allowlist additions.
10. **M** — `portal/portal-ui/src/views/platform_health.rs` + rewire `OperationsWorkspaceDetail`; stale/source/owner rendering.
11. **M** — Port `scripts/validator-rs/src/platform_health.rs` off the legacy C# paths (`api/Ryuki.Platform.Api/Program.cs`) to validate the Rust contract endpoint output; relax pinned `draft`/`static-seed`/`degraded-read-only` constants to the live-mode equivalents; add the deploy-observability validator module.
12. **S** — Flip `platform-health-dashboard` to `available` in `catalog/offering-catalog.yaml` + `contracts.rs:3390` seed, update `catalog/platform-health-contract.yaml`, create `docs/workflows/platform-health.md`.

Dependency order: 2→3→4 (health), 2→5→6 (metrics/tracing), 5→8 (deploy needs real metric names), 3+9→10→12, 11 before any flip in 12.

### Risks & open questions

- **Validator lock-in.** `scripts/validator-rs/src/platform_health.rs` hard-pins `status: draft`, `source: static-seed`, `healthMode: degraded-read-only` and parses C# files that no longer exist in the tree — meaning the current acceptance gate validates a ghost. Step 11 must land before any live flip or CI will contradict shipped behavior. Open question: should the validator validate the *running* contract endpoint JSON (golden-file) instead of source-text parsing, which is brittle across the C#→Rust port?
- **Metric renames.** Moving to `ryuki_http_request_duration_seconds` histograms changes families (`ryuki_api_request_duration_milliseconds` summary disappears). Today there are zero scrapers in-repo, so this is the cheapest moment to adopt conventional names — but any out-of-tree dashboards break. Decide and document once.
- **NetworkPolicy/egress blast radius.** `default-deny-egress` means every new dependency (OTLP collector, vault probe, portal probe, Kubernetes API) needs an explicit egress rule; the Kubernetes probe also needs RBAC on the `platform-api` service account (`deploy/kubernetes/base/serviceaccounts.yaml`). Missing rules will read as `Unhealthy` and page someone — probe failures must distinguish "blocked by policy" (`Unavailable`) from "dependency down" (`Unhealthy`) where possible (timeout vs refused).
- **Sampler per replica.** Each API replica probes independently and writes snapshots; fine at `replicas: 1` (current manifests), duplicated rows and probe fan-out at scale. Defer leader election; note `instance` label on the gauge.
- **`/metrics` exposure choice.** Separate listener (`:9090`) vs bearer token on the main listener: the separate listener composes best with NetworkPolicies but adds a port to manifests and compose; recommendation is separate-listener default with token as the fallback — confirm with deploy owners.
- **Snapshot table vs Prometheus history.** Both store health over time. Position the table strictly as governance evidence (joins into evidence packs, survives Prometheus retention) and Prometheus as the operational source; revisit if the table growth needs partitioning beyond the retention sweep.
- **Owner registry.** `owner`/`safe_remediation` start as a static engine map; longer term they likely belong in the catalog (per-component ownership is also a Maintain-stage roadmap concern). Acceptable now, flagged for the Maintain design.
- **Vault probe semantics.** `/v1/sys/health` returns non-200 for sealed/standby states by design; the probe must map status codes (200/429/472/473/501/503) to `Healthy`/`Degraded`/`Unhealthy` explicitly rather than treating any non-200 as down.

---

## Catalog, contract & documentation integrity

Ryuki's credibility rests on the claim that 116 catalog contracts, 230 static validation checks, and an evidence-first API stay in lockstep — but the toolchain that should enforce this is itself broken. The validator fails 116 of 121 slices (`run-all --root .` → `{"total":121,"passed":5,"failed":116}`) because it still hard-requires a deleted C# API and a `docs/workflows/` tree that has never existed; `make validate` cannot even start (`missing --root`); the catalog YAML is never loaded at runtime, so the API serves an independently hand-maintained JSON copy with no drift detection; the only 8 contracts marked `status: active` are 3-line stubs; the site catalog has four contradictory sources of truth; and there is no OpenAPI spec for the ~616 routes. Until the governance loop closes — catalog → API → validator → docs — every "governed" claim is unverifiable, and that is disqualifying for a platform whose whole pitch is auditable automation.

### Current state

- **Validator**: `scripts/validator-rs/src/main.rs:143-149` hard-codes `API_README_PATH`/`PROGRAM_PATH` under the deleted `api/Ryuki.Platform.Api/`, plus missing `docs/platform-build-sheet.md` and `docs/workflows/README.md`. `parse_root_args` (`main.rs:2409-2431`) errors with `missing --root` when the flag is absent; the `Makefile:13-14` `validate` target, `catalog/README.md` ("Validate catalog changes with `… -- validate catalog`"), and `docs/getting-started.md:47-50` (step 6) all document invocations that fail. `app_skeleton.rs:6-13` lists the C# files in `REQUIRED_FILES`, and `validate_api()` (`app_skeleton.rs:765-838`) asserts .NET 10 project content. `COVERAGE_TSV` (`main.rs:151+`, 151 rows) references 6 nonexistent catalog YAMLs, 121 nonexistent workflow docs, and 17 endpoints that appear nowhere in `sources/` (15 `/api/status/*`, `/api/catalog/governance-catalog-api`, `/api/operations/endpoint-inventory`).
- **Runtime catalog**: zero `include_str!`/fs reads of `catalog/` in `sources/` or `portal/`. Every contract endpoint is a hardcoded `json!()` blob in the 11,885-line `sources/ryuki-api/src/contracts.rs` (e.g. `catalog_offerings()` at `:3373` inlines 12 offerings with `"source":"static-seed"`). `sources/ryuki-core/src/yaml.rs` is only a duplicate-key linter.
- **Validation depth**: `scripts/validator-rs/src/ryuki_api.rs` does source-text scanning (`contracts_rs.contains("\"{endpoint}\"")` at `:285`) and explicitly forbids HTTP clients (`:231`); no behavioral check anywhere can call a route and diff it against catalog YAML.
- **Workflow docs**: `docs/workflows/` does not exist; `docs/` has exactly 5 content pages. 58+ run-all errors are directly "workflow README missing/must include"; per-slice modules like `scripts/validator-rs/src/access_review_recertification.rs` grep docs for exact phrases ("No live provider calls.", endpoint paths).
- **Stub contracts**: exactly 8 files match `^status: active` in `catalog/` (app-skeleton, catalog, compose, kubernetes-manifest, local-auth, release-image-builds, sensitive-output-guardrails, vault-foundation) — each a verbatim 3-line "static stub for COVERAGE_TSV registration". 106 substantive contracts sit at `draft`; `site-catalog.yaml` is `stub`.
- **Site catalog**: four sources of truth — `catalog/site-catalog.yaml` (stub, claims "database-driven"), `catalog_site_catalog()` (`contracts.rs:3454`, legacy `CORP.local`/`Ryuki EU`/5 sites), the real in-memory `SITE_STORE: LazyLock<Mutex<Vec<SiteEntry>>>` (`sources/ryuki-engine/src/site_registry.rs:787-788`, 88 sites/49 countries, lost on restart — `migrations/` has no `sites` table), and `scripts/validator-rs/src/site_catalog_contract.rs:14` still demanding `CORP.local` (13 failures).
- **API contract**: no utoipa/aide/schemars anywhere; 616 `.route()` registrations (609 `contracts.rs` + 6 `main.rs` + 1 `boundary.rs`); the portal client (`portal/portal-ui/src/api_client.rs`) is hand-written.
- **Docs drift**: `docs/architecture.md:7,18,22` says Leptos SPA/WASM with 3 adapters vs README's SSR/17 adapters (code confirms SSR via `portal/portal-ui/Cargo.toml` ssr feature); site counts disagree three ways (README 89/49, `docs/site-management.md` 89/33, code 88/49). CI (`.github/workflows/static.yml`) only deploys Pages — nothing runs `make validate`.

### Design

#### 1. Repair the conformance validator and its registry

- **Goal**: `make validate` runs green from a clean checkout and every registry row points at a file/endpoint that exists.
- **Engine/validator changes**: in `scripts/validator-rs/src/main.rs`, default `root` to `std::env::current_dir()` in `parse_root_args` (keep `--root` as an override); delete `API_README_PATH`/`PROGRAM_PATH` C# constants and repoint `SharedContext.program` (`main.rs:3464-3479`) at `sources/ryuki-api/src/contracts.rs` and `SharedContext.api_readme` at a new generated `docs/api/endpoints.md` (see feature 6), so the ~120 per-slice modules that assert `readme.contains(ENDPOINT)`/`program.contains(...)` are fixed via the shared context rather than per-file edits (a handful of slices with C#-specific assertions get individual fixes). In `app_skeleton.rs`, drop `api/Ryuki.Platform.Api/*` from `REQUIRED_FILES` and delete `validate_api()`'s .NET assertions. Rewrite `COVERAGE_TSV`: remove the 6 rows pointing at nonexistent YAMLs (or create the YAMLs where a slice module exists, e.g. `governance_catalog_api.rs`, `operations_endpoint_inventory.rs`), and replace the 17 dead endpoint refs with the real mounted routes or delete the rows.
- **API endpoints / portal UI**: none.
- **Validation & evidence**: add a `validator self-check` unit test asserting every `COVERAGE_TSV` row's catalog file exists under `catalog/`, doc file under `docs/workflows/`, and endpoint string appears in `contracts.rs`/`main.rs`. Add a `ci.yml` GitHub Actions workflow running `make validate` + `cargo test --workspace` so drift fails PRs.
- **Safety/dry-run**: validator stays read-only; document the working invocations in `Makefile`, `catalog/README.md` (Catalog Rules), and `docs/getting-started.md` step 6.

#### 2. Load catalog YAML at runtime (one source of truth)

- **Goal**: `catalog/*.yaml` is the data the API serves, ending the dual-maintenance of YAML + `json!()` blobs.
- **Data model**: none (filesystem-sourced). Add `catalog_dir: PathBuf` (default `./catalog`, env `RYUKI_CATALOG_DIR`) to `RyukiConfig` in `sources/ryuki-core/src/config.rs`.
- **Engine changes**: new `sources/ryuki-core/src/catalog.rs` with a typed envelope `ContractDocument { slice: String, version: u32, status: ContractStatus, body: serde_json::Value }` parsed via `serde_yaml` (move the dep from ryuki-engine to workspace level). A `CatalogStore::load(dir)` reads all 116 files at startup, runs the existing duplicate-key lint (`ryuki-core/src/yaml.rs`), and fails fast on parse errors.
- **API endpoints**: hold `Arc<CatalogStore>` in Axum state (per AGENTS.md: state + extractors, no global mutable state). Phase 1: new routes `GET /api/catalog/contracts` (index: slice, status, version) and `GET /api/catalog/contracts/{slice}` served from the store. Phase 2: migrate the pure-mirror handlers in `contracts.rs` (starting with `catalog_offerings()` `:3373`, `catalog_request_form()`, `catalog_recommendations()`) to render from `CatalogStore`, preserving response shapes so `portal/portal-ui/src/api_client.rs` and `workspace_catalog.rs` are unaffected.
- **Validation & evidence**: validator gains a `check-contract-load` mode that loads the store exactly as the API does, so a YAML that won't parse blocks `make validate` before it blocks startup.
- **Safety/dry-run**: read-only loading; no write path to `catalog/` from the API. Startup failure on bad YAML is intentional (fail-closed).

#### 3. Behavioral contract conformance tests

- **Goal**: replace "the route string appears somewhere in the source" with "the mounted route returns the contracted JSON".
- **Engine/API changes**: new `sources/ryuki-api/tests/contract_conformance.rs` using `tower::ServiceExt::oneshot` against `contracts::routes()` (axum + tower are already dependencies — no new crates, and the validator's no-HTTP-client rule at `ryuki_api.rs:231` stays intact). Tests: (a) every endpoint in the repaired `COVERAGE_TSV` returns 200 with a JSON body; (b) safety invariants — every `*Allowed` boolean in contract responses is `false` unless on an explicit allowlist, `"source"` is `"static-seed"` or `"catalog"`; (c) for migrated handlers, the response equals the `CatalogStore` rendering of the YAML.
- **Validation & evidence**: export the `COVERAGE_TSV` endpoint list from the validator crate (or a shared include) so the test and validator can't drift from each other. Wire into `make test` and `ci.yml`.
- **Safety/dry-run**: in-process only; no network, no database requirement (contract handlers are stateless today — `contracts.rs` has zero `State<` extractors).

#### 4. Per-contract workflow documentation (`docs/workflows/`)

- **Goal**: an operator runbook page exists for each of the 121 registry entries, satisfying the per-slice doc checks.
- **Changes**: create `docs/workflows/README.md` (index table: workflow, contract YAML, endpoint, doc link) plus one doc per `COVERAGE_TSV` doc-column filename. Template sections: purpose, lifecycle mapping (Draft→…→Completed), endpoint path (the validators assert `doc.contains(ENDPOINT)`), required inputs/approvals (from the catalog YAML), prohibitions using the exact phrases slice modules grep for (e.g. "No live provider calls.", "No live directory changes.", "safe access review summaries only" in `access_review_recertification.rs:800-840`), and evidence artifacts. Add a `scaffold-docs` subcommand to `scripts/validator-rs` that emits missing docs from `COVERAGE_TSV` + catalog YAML (write-if-absent only), then hand-finish; iterate `run-all` until the 58 direct "workflow README" errors and downstream "doc missing/must prohibit" errors clear.
- **Portal UI**: link runbook docs from workspace detail panels later (out of scope here).
- **Validation & evidence**: the existing per-slice checks become the gate; regenerate the Pages site (`scripts/md2docs.py` → `docs/*.html`, `search-index.json`, `sitemap.xml`).
- **Safety/dry-run**: docs only.

#### 5. Real content for the 8 "active" stubs + a status-promotion policy

- **Goal**: `status: active` means something.
- **Changes**: author substantive contracts for the 8 stub YAMLs in `catalog/`, prioritizing the three with live code behind them: `local-auth-contract.yaml` (mirror the `/api/auth/local/*` surface and `ryuki-engine` auth), `sensitive-output-guardrails-contract.yaml` (codify `sources/ryuki-core/src/secret_scan.rs` rules), `vault-foundation-contract.yaml` (deploy/ Vault wiring); then app-skeleton, catalog, compose, kubernetes-manifest, release-image-builds aligned with their existing slice modules (`scripts/validator-rs/src/local_auth.rs`, `sensitive_output_guardrails.rs`, `vault_foundation.rs`, etc.).
- **Validation & evidence**: define the lifecycle in `catalog/README.md`: `stub → draft → active`, where `active` requires (1) slice validator green, (2) conformance test covering its endpoint, (3) workflow doc present. Add a validator check that any `status: active` YAML contains non-trivial content (e.g. `rules`/guard sections), so 3-line stubs can never be "active" again. Decide and document promotion criteria for the 106 drafts.
- **Safety/dry-run**: contract content only; all `*Allowed` flags remain `false` until live execution is separately approved.

#### 6. One source of truth for the site catalog

- **Goal**: collapse four contradictory site sources into one persistent registry.
- **Data model**: new `migrations/044_sites.sql`: `CREATE TABLE sites (unlocode TEXT PRIMARY KEY, city TEXT NOT NULL, country_code TEXT NOT NULL, country TEXT NOT NULL, region TEXT, active BOOLEAN NOT NULL DEFAULT FALSE, activated_by TEXT, activated_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())` plus an index on `(country_code, active)`. Runs via sqlx on startup like the existing 42 migrations.
- **Engine changes**: keep `reference_sites()` in `sources/ryuki-engine/src/site_registry.rs` as the canonical seed (fix the count question: 88 today vs README's 89); delete the `SITE_STORE` `LazyLock` (`:787-788`). Persistence lives in `sources/ryuki-api/src/database.rs` (sqlx is already a dependency): a `SiteStore` that upserts seed rows on startup and owns activate/deactivate.
- **API endpoints**: `/api/admin/sites*` (`contracts.rs:1086-1101`) keep their shapes but read/write through `SiteStore`, so activations survive restarts. Rewrite `catalog_site_catalog()` (`contracts.rs:3454`) to derive from the registry (site/country counts, active sites) and drop the legacy `CORP.local`/`Ryuki EU`/5-site facts — or return 410 with a pointer to `/api/admin/site-registry-contract` if consumers agree.
- **Portal UI**: admin sites and catalog views (`portal/portal-ui/src/api_client.rs` consumers) re-verified against the unchanged list/activate shapes; surface "persisted" provenance in the admin sites view.
- **Validation & evidence**: rewrite `scripts/validator-rs/src/site_catalog_contract.rs` (drop `REQUIRED_DOMAIN = "CORP.local"` at `:14`) to validate the new derived shape; update `catalog/site-catalog.yaml`'s note to "database-backed, seeded from the UN/LOCODE reference set"; activation/deactivation writes an evidence record (who/when) consistent with the existing lifecycle pattern.
- **Safety/dry-run**: site activation is metadata-only (no provider calls); keep it admin-gated as today.

#### 7. OpenAPI specification and generated API docs

- **Goal**: a machine-readable contract for the API so clients, workers, and the validator stop reverse-engineering 616 routes.
- **Changes**: add `utoipa` + `utoipa-swagger-ui` to `sources/ryuki-api/Cargo.toml`. Phase 1: annotate the ~40 operational routes (auth `/api/auth/*`, `/api/admin/sites/*`, requests lifecycle, `/health`, `/ready`, platform status). Phase 2: the ~580 static contract GETs share one `ContractDocument` response schema and are added to the spec programmatically from the same endpoint table the conformance tests use — no per-handler annotation needed. Mount `GET /openapi.json` and `/docs` (Swagger UI) in `sources/ryuki-api/src/main.rs`.
- **Portal UI**: optionally generate `portal/portal-ui/src/models.rs` types from the spec later (open question).
- **Validation & evidence**: validator check that `/openapi.json` is mounted and the spec text covers every `REQUIRED_ENDPOINTS` entry in `ryuki_api.rs`; generate `docs/api/endpoints.md` from the spec at build time — this becomes the `api_readme` shared-context input from feature 1, closing the loop.
- **Safety/dry-run**: `/docs` gated behind the same auth as admin routes or disabled when `configuredForProduction` is true; spec contains no secrets (paths and schemas only).

#### 8. Documentation truth pass + drift guards

- **Goal**: no two documents disagree with each other or the code.
- **Changes**: `docs/architecture.md` — SSR (not SPA/WASM) per `portal/portal-ui/Cargo.toml`, adapter box lists all 17 adapters; `docs/getting-started.md` — add a `make run-portal` step (the Quick Start currently never starts the portal), fix "Leptos SPA frontend" (line 73), fix step 6's validator command; `docs/site-management.md` and `README.md:33` — one canonical site/country number matching `reference_sites()` (88/49, or adjust the seed to 89); regenerate HTML/search-index/sitemap via `scripts/md2docs.py`.
- **Validation & evidence**: small `docs_consistency` slice in `scripts/validator-rs/src/` asserting the canonical numbers (site count, country count, adapter count) appear consistently in README and docs, derived from the code at validator build time — so the next renumbering can't silently drift.
- **Safety/dry-run**: docs only.

### Implementation plan

1. **(S)** Validator CLI fix: default `--root` to cwd; fix `Makefile`, `catalog/README.md`, `docs/getting-started.md` step 6. `make validate` now *runs* (still red).
2. **(M)** Purge C# from the validator: `app_skeleton.rs` `REQUIRED_FILES`/`validate_api()`, repoint `SharedContext` `program`/`api_readme` sources, fix slices with C#-specific assertions.
3. **(M)** `COVERAGE_TSV` registry cleanup (6 YAML refs, 17 endpoint refs, dead rows) + registry self-check test.
4. **(L)** `docs/workflows/`: scaffold-docs subcommand, author/finish 121 docs + index, regenerate Pages site; iterate `run-all` to green or to a short list of acknowledged-real failures.
5. **(M)** CI workflow (`.github/workflows/ci.yml`) running `make validate`, `cargo test --workspace`, fmt/clippy.
6. **(M)** `CatalogStore` in `ryuki-core` + Axum state wiring + `GET /api/catalog/contracts{,/ {slice}}`.
7. **(M)** Migrate `catalog_offerings`/`catalog_request_form`/`catalog_recommendations` to `CatalogStore`; conformance test asserts YAML↔response equality.
8. **(M)** Conformance test suite (`sources/ryuki-api/tests/contract_conformance.rs`) over all registry endpoints + safety-flag invariants.
9. **(M)** Site registry: `migrations/044_sites.sql`, `SiteStore` in ryuki-api, rewrite `catalog_site_catalog()` + `site_catalog_contract.rs`, update `site-catalog.yaml` note and portal admin views.
10. **(L)** Author the 8 stub contracts; add status-promotion policy + active-means-content validator check.
11. **(L)** OpenAPI: utoipa on operational routes, programmatic contract entries, `/openapi.json` + `/docs`, generated `docs/api/endpoints.md`, validator coverage check.
12. **(S)** Docs truth pass (architecture/getting-started/site-management/README) + `docs_consistency` slice; regenerate HTML site.

### Risks & open questions

- **Validator green vs honest**: some of the 116 failures may encode aspirational requirements rather than bugs; each slice fix needs a judgment call — relax the check (and record why) or build the missing artifact. Avoid weakening checks just to get green; track exceptions in the run-all output.
- **Doc-phrase coupling**: per-slice validators grep for exact English sentences in workflow docs. Scaffolding will satisfy them, but this is brittle; consider migrating to structured front-matter checks after the tree exists (out of scope here, worth a follow-up).
- **Response-shape freeze**: migrating `json!()` blobs to `CatalogStore` must be byte-shape-compatible for `portal/portal-ui/src/api_client.rs`; the conformance tests in step 8 must land *before* step 7's migration to act as the safety net.
- **Canonical site count**: pick 88 (current code) or 89 (README) before step 9; the seeded `sites` table makes whichever number we choose durable.
- **OpenAPI scope creep**: 616 routes invite a months-long annotation slog; the design deliberately splits ~40 hand-annotated operational routes from programmatically-registered contract GETs. Decide whether portal type generation from the spec is worth replacing the hand-written `models.rs` (risk: churn in Leptos views).
- **`status: active` semantics**: does "active" imply live execution readiness or merely "contract content complete"? The promotion policy in step 10 must define this before any of the 106 drafts are promoted, or the status field loses meaning again.
- **Startup fail-closed on bad YAML**: loading `catalog/` at API startup means a malformed contract can take the API down; mitigated by `check-contract-load` in `make validate` and CI, but confirm operators accept fail-closed over serve-stale.

---

## Test & verification depth

Ryuki advertises "1,380+ tests" (README.md:9) but almost none of them verify behavior at the boundaries where the platform actually runs: no test ever constructs the Axum router, opens a database connection in CI, renders a portal view, or talks to a mock provider. The sole real-PostgreSQL test silently self-skips because CI provisions no database; adapter "contract tests" assert the literal `DRY-RUN` string produced two functions above them; the root "integration tests" are serde_yaml lint passes over deploy manifests; and there is no lifecycle scenario test, e2e tooling, load test, fuzzing, or coverage measurement anywhere. This matters acutely right now: the five most recent commits (7172ea8 verified-admin settings writes, 6afe852 bound persisted sessions, 841e68f/0df9ce1/90228ea lifecycle guards) all hardened exactly the DB- and HTTP-layer paths that sit at 0% executed coverage, so regressions in the platform's security and governance core would pass the entire suite.

### Current state

- **DB integration test self-skips.** `db_tests::test_migrations_run_against_pg18` (sources/ryuki-api/src/main.rs:1367-1398) returns early with a pass when `RYUKI_DATABASE_URL` is unset. The only test-running CI, deploy/ci/azure-pipelines.yml (BuildTest stage: `cargo test --workspace` on bare ubuntu-latest), provisions no postgres service and never sets the variable — so the test has never executed in CI. Even run manually it asserts only that `platform_config` has 9 rows and that 3 table names exist, against a migrations/ directory of **42** files (001, 003-043). The 23 live `sqlx::query` call sites (19 in sources/ryuki-api/src/contracts.rs, 4 in main.rs) have zero exercised integration coverage.
- **Router never constructed in tests.** The `Router` with its 12-layer middleware stack (ConcurrencyLimit, security headers, request counter, request id, rate limit, `auth_middleware`, timeout, body limit, CORS, compression, cache-control, timing) is built inline inside `main()` (sources/ryuki-api/src/main.rs:652-702). sources/ryuki-api/Cargo.toml has **no `[dev-dependencies]` section at all**; grep for `oneshot|tower::ServiceExt|TestServer|axum_test` across the repo is empty. Auth, rate limiting, and error mapping are tested only as extracted pure helpers (main.rs:1040-1240).
- **Portal untested.** All 38 portal `#[test]`s live in portal/portal-ui/src/{api_client.rs, server_boundary.rs, api.rs}. The six views (views/{dashboard,login,request_create,request_detail,requests,workspaces}.rs) plus app.rs, shell.rs, models.rs, and workspace_catalog.rs have zero `#[cfg(test)]` blocks. No Playwright/Cypress/wasm-bindgen-test exists anywhere; shell.rs and login.rs are currently modified in the working tree with no safety net.
- **Root "integration tests" are YAML linting.** tests/{compose,kubernetes,ci}_integration_test.rs parse deploy YAML with serde_yaml and assert field strings; tests/integration_test.rs makes 4 shallow in-process engine calls; tests/workspace_integration_test.rs is 5 lines. The root crate (Cargo.toml `[dependencies]`) has no HTTP client. CI builds Docker images (BuildImages stage) but never runs them — no smoke stage exists between BuildImages and PushImages.
- **Adapter tests are self-referential.** `sanitized_dry_run_result` (sources/ryuki-engine/src/adapter_framework.rs:8) produces the `DRY-RUN:` string that the mod-tests then `assert!(result.contains("DRY-RUN"))` (lines 1297, 1309, 1363, 1445, 1498, 1531). All 17 adapters return canned `...example.invalid (DRY-RUN)` endpoints. catalog/adapter-contract-test-contract.yaml (status: draft) prescribes five fixtureTypes, but fixtures/ contains exactly one file (inventory/coverage-sample.yaml), and scripts/validator-rs/src/adapter_contract_test.rs validates only the contract YAML's field lists, never fixture existence.
- **Production auth path least tested — and a stub.** `validate_token` in sources/ryuki-engine/src/auth.rs unconditionally returns `AuthSession::unverified_entra()` (no jsonwebtoken/JWKS anywhere in the workspace). The real verified path — `auth_session_from_persisted_session` (main.rs:129), a live `SELECT ... FROM sessions WHERE id = $1 AND expires_at > NOW()` — is never executed by any test, nor are the `auth_login`/`auth_logout` handlers (contracts.rs:6100, 6142) that INSERT/DELETE `sessions` rows.
- **No load tests, no fuzzing, no coverage.** No criterion/`[[bench]]`/k6/vegeta artifacts; the governor rate limiter is verified only by single-threaded quota-config tests (main.rs:1171-1226). No proptest/quickcheck/cargo-fuzz for secret_scan, yaml.rs, or header parsing. No tarpaulin/cargo-llvm-cov/grcov in Makefile or CI; raw test count is the only quality metric.
- **`/api/validation/run` is a stub.** `validation_run` (main.rs:901-917) validates the `slice` param is non-empty, ignores it, and returns `warnings: ["static dry-run: no live validation performed"]` for any slice name, real or fictional. scripts/validator-rs (230 checks) is invoked only via Makefile/CI shell.

### Design

#### 1. Real PostgreSQL integration tests that fail loud in CI

- **Goal:** every `sqlx::query` site and all 42 migrations exercised against a real postgres on every PR; silent skips impossible in CI.
- **Data model:** none (tests target existing tables: `platform_config`, `requests` (migrations/003_requests.sql), `sessions` (migrations/004_sessions.sql), and the 38 domain tables in migrations/005-043).
- **Engine/API changes:** in sources/ryuki-api/src/main.rs `db_tests`, add a fail-loud guard — if `RYUKI_REQUIRE_DB=1` and `RYUKI_DATABASE_URL` is unset, `panic!` instead of `return`. Expand the test module: assert the full 42-migration table set from `information_schema.tables`, seed rows, and add tests for `database::try_connect_with_url` / `database::run_migrations` failure modes (sources/ryuki-api/src/database.rs). Add a `contracts_db_tests` module covering the 19 query sites in contracts.rs (request CRUD against `requests`, session create/delete against `sessions`, the verified-admin `platform_config` write guard from 7172ea8).
- **CI:** in deploy/ci/azure-pipelines.yml BuildTest/Rust job, start postgres before tests (`docker run -d -p 5432:5432 -e POSTGRES_... postgres:18-alpine` — same image deploy/compose/compose.yaml uses) and export `RYUKI_DATABASE_URL=postgres://...localhost:5432/ryuki_platform` plus `RYUKI_REQUIRE_DB=1`.
- **Validation & evidence:** add a validator slice in scripts/validator-rs (e.g. `ci_db_coverage.rs`) asserting the pipeline YAML contains the postgres step and both env vars — turning today's YAML-linting habit to advantage so the skip can never silently return.
- **Safety/dry-run:** tests run against a throwaway container; no provider calls. Local `make test` keeps the soft-skip (no `RYUKI_REQUIRE_DB`), preserving contributor ergonomics.

#### 2. Router-level HTTP test harness

- **Goal:** route wiring, middleware ordering, and error mapping verified via in-process `oneshot` requests, no network.
- **Engine/API changes:** factor router construction out of `main()` into `pub(crate) fn build_router(app_config: &AppConfig, rate_limiter: ...) -> Router` in a new sources/ryuki-api/src/router.rs (it already only composes `Router::new()` + `contracts::routes()` + `boundary::routes()` + layers; `main()` keeps only config load, DB connect, bind, serve). Add `[dev-dependencies]` to sources/ryuki-api/Cargo.toml: `tower = { features = ["util"] }`, `http-body-util`, `axum-test` (or plain `tower::ServiceExt::oneshot`).
- **API endpoints:** none new; tests cover existing ones — `/health`, `/ready`, `/metrics`, `/api/platform/status`, the 35+ contracts.rs routes (including `/api/requests/{id}/{validate,plan,approve,lock,execute,verify}`), and boundary.rs.
- **Test matrix:** unsafe method without session → 401 `AUTH_REQUIRED` (auth_middleware, main.rs:169-208); `/api/auth/login` and `/api/auth/logout` exempt (`is_auth_exempt_path`, main.rs:161); burst → 429 from rate_limit_middleware; oversized body → 413 from `RequestBodyLimitLayer`; security headers present on every response; unknown path → `not_found` fallback; slow handler → 504 `REQUEST_TIMEOUT` envelope.
- **Portal UI:** none.
- **Safety/dry-run:** harness uses `auth_mode = mock-dry-run` config; no DB needed for routing tests (DB-backed assertions live in feature 1's module).

#### 3. Lifecycle scenario test + CI smoke stage

- **Goal:** one test that proves the headline product claim — a request driven Draft→Intake→Validated→Planned→Approved→Locked→Executing→Verifying→Completed through the real API with DB persistence.
- **Data model:** none; asserts rows/status columns in `requests` (migrations/003_requests.sql) after each transition.
- **Changes:** add `reqwest`, `tokio` to root Cargo.toml `[dependencies]` (the test-only crate) and a new `[[test]] tests/lifecycle_e2e.rs`, gated on `RYUKI_E2E_BASE_URL`. Flow: `POST /api/auth/login` → capture `session_id` → `Bearer <session_id>` on `POST /api/requests` → walk `/api/requests/{id}/validate|plan|approve|lock|execute|verify` (contracts.rs:112-117) → `GET /api/requests/{id}` asserting status, stage `StageStatus::Completed` entries, and the evidence/plan fields the engine writes (request_lifecycle.rs). Include negative transitions (lock before approve → error), pinning the guards from commits 841e68f/0df9ce1.
- **CI:** new `Smoke` stage in deploy/ci/azure-pipelines.yml between BuildTest and BuildImages (or after BuildImages, reusing the `:ci` images): `docker compose -f deploy/compose/compose.yaml up -d`, wait for `/health`, run `cargo test --test lifecycle_e2e`, curl portal `/healthz`, `compose down`.
- **Validation & evidence:** the scenario test doubles as executable documentation of the lifecycle contract `/api/requests/lifecycle-contract` (contracts.rs:97).
- **Safety/dry-run:** the stack already defaults to static-dry-run execution, so "execute" performs no provider calls — the scenario is inherently safe.

#### 4. Portal component tests + browser e2e

- **Goal:** the six views and shell signal logic stop being a zero-coverage zone; one real browser path guards login → dashboard → request creation.
- **Changes (component):** add `wasm-bindgen-test` dev-dependency to portal/portal-ui/Cargo.toml (hydrate-feature gated); per-view `#[cfg(test)]` modules for views/{login,dashboard,requests,request_create,request_detail,workspaces}.rs and shell.rs covering signal/derived-state logic (form validation in request_create, filter logic in requests, theme/nav state in shell). Where logic is too embedded in the `view!` macro to test, extract pure functions first — same pattern the API crate already uses.
- **Changes (e2e):** new portal/e2e/ directory with a Playwright project (package.json, playwright.config.ts) that runs against `make run-portal` (`cargo leptos serve`) + ryuki-api from compose. Specs: login posts to `/api/auth/login` and lands on dashboard; create-request wizard submits and the new request appears in requests view; logout clears session.
- **CI:** add a `PortalE2E` job to the Smoke stage (browsers preinstalled on ubuntu-latest via `npx playwright install --with-deps chromium`).
- **Validation & evidence:** extend scripts/validator-rs `app_skeleton.rs`/`design_system.rs` family with a check that every file in portal/portal-ui/src/views/ has a `#[cfg(test)]` block or is listed in an explicit allowlist, so new views can't ship untested by default.
- **Safety/dry-run:** e2e runs against the static-dry-run auth mode (`auth_login`'s `MockDryRun` branch, contracts.rs:6100); no Entra tenant required.

#### 5. Adapter contract fixtures + mock-provider tests

- **Goal:** adapter tests verify request shaping and response parsing against realistic provider payloads instead of echoing `dry_run_message()` back at itself; the draft catalog contract becomes enforced reality.
- **Data model:** filesystem corpus, not DB: fixtures/adapters/<provider>/ (vmware, hyperv, proxmox, nutanix, xen, kvm, veeam, commvault, rubrik, cohesity, netbackup, zabbix, prometheus, datadog, grafana, solarwinds, servicenow) with the five fixtureTypes from catalog/adapter-contract-test-contract.yaml: `static-json-fixture`, `static-yaml-fixture`, `mock-provider-result`, `negative-case-fixture`, `redacted-evidence-fixture` — all redacted per the contract's header rule (no real endpoints, tenant IDs, hostnames).
- **Engine changes:** add `wiremock` dev-dependency to sources/ryuki-engine/Cargo.toml. Rewrite the adapter_framework.rs test module: load fixtures, drive `sync_inventory()`/`execute()`, assert parsed `InventoryItem` fields and structured operation results including negative cases (provider 500, malformed payload, pagination truncation). Where adapters are pure canned structs today, this also forces the seam (a fixture-backed transport trait) that live execution will eventually need — without enabling any live calls (`providerCallsEnabled: false` stays true).
- **Validation & evidence:** extend scripts/validator-rs/src/adapter_contract_test.rs to resolve each declared `fixtureSet` to files on disk under fixtures/adapters/, fail on missing files, and run the existing redaction/no-secret patterns over fixture contents (reuse secret_scan from ryuki-core). Promote the contract from `status: draft` once enforced.
- **Safety/dry-run:** wiremock binds localhost only; `networkEgressAllowed: false` is preserved; the validator guard `fixture-set-redacted` is now mechanically checked.

#### 6. Verifying the production auth path

- **Goal:** the path hardened by 6afe852/7172ea8 — persisted session → verified write — has end-to-end tests, and Entra validation stops being a stub.
- **Data model:** none new; uses `sessions` (migrations/004_sessions.sql) including `expires_at` expiry semantics.
- **Engine changes:** implement real token validation in sources/ryuki-engine/src/auth.rs behind an `EntraConfig` (tenant, audience, JWKS URL): add `jsonwebtoken`, validate signature/exp/aud/iss, map roles claim; keep `AuthSession::unverified_entra()` as the explicit fallback when config is absent. Test with locally-generated RSA keypairs and signed fixtures (expired, wrong audience, tampered roles, alg=none) — replacing the codified "never validate" test at auth.rs:456 with "never validate *without keys*".
- **API tests (needs features 1+2):** `POST /api/auth/login` → row in `sessions` → `Bearer <session_id>` on an unsafe method passes `auth_middleware` → verified-admin `platform_config` write succeeds; expired `expires_at` → 401; `auth_logout` deletes the row; `X-Ryuki-Session-Id` header path (`session_id_from_headers`, main.rs:111) and malformed-UUID → `unverified_session("invalid-session-id")`.
- **Portal UI:** none required; portal/e2e login spec (feature 4) covers the browser side.
- **Safety/dry-run:** JWKS fetch only when `EntraConfig` is fully set; default remains static-dry-run; fixture keys are test-generated, never committed secrets (scripts/no-secret-scan.sh continues to gate).

#### 7. Wire `/api/validation/run` to the real validator

- **Goal:** the platform can self-validate through its own API instead of returning canned success for fictional slice names.
- **Engine changes:** restructure scripts/validator-rs as lib+bin — extract the per-slice dispatch from the giant `match` in scripts/validator-rs/src/main.rs into `lib.rs` exposing `pub fn run_slice(name: &str) -> Result<SliceReport, UnknownSlice>` and `pub fn list_slices()`; the CLI keeps `run-all`. Add `ryuki-validator = { path = "../../scripts/validator-rs" }` to sources/ryuki-api/Cargo.toml.
- **API endpoints:** rewrite `validation_run` (main.rs:901-917) to dispatch to `run_slice`; unknown slice → 404 problem-details; real errors/warnings populate `ValidationResult`. Add `GET /api/validation/slices`. Long-running `run-all` stays CLI/CI-only (or becomes async later — out of scope here).
- **Portal UI:** optional follow-on — surface slice results in a portal view; not required for this theme.
- **Validation & evidence:** router tests (feature 2) assert the 404-on-unknown-slice and a real slice's report shape; optionally record runs in a small `validation_runs` table (new migration `044_validation_runs.sql`: id, slice, errors_count, warnings_count, ran_at) to fit the platform's evidence-first pattern.
- **Safety/dry-run:** validator slices are read-only static analysis; no behavior change to dry-run posture.

#### 8. Load/benchmark, property-based/fuzz, and coverage baselines

- **Goal:** quantitative floors under the concurrency-sensitive and parser-heavy code, and an honest replacement for "1,380+ tests" as the quality metric.
- **Benchmarks/load (M):** criterion benches in sources/ryuki-engine/benches/ (lifecycle transition throughput, secret_scan throughput) and sources/ryuki-api/benches/; a k6 (or vegeta) script under scripts/load/ targeting `/health`, `/api/platform/status`, and a rate-limited path against the compose stack, asserting governor behavior under real concurrency (429 rate, no panics under `ConcurrencyLimitLayer` saturation). Optional CI perf stage gating p99.
- **Property/fuzz (S-M):** proptest dev-deps in sources/ryuki-core (secret_scan line scanner, yaml.rs loader — pathological nesting/anchors) and sources/ryuki-api (`session_id_from_headers`, `bearer_value`, `resolve_auth_metadata`, `rate_limit_path_group` — arbitrary bytes/invalid UTF-8, building on the single hand-written case at main.rs:1040); cargo-fuzz targets under fuzz/ for the serde_yaml catalog ingestion used by scripts/validator-rs/src/catalog.rs (run scheduled, not per-PR).
- **Coverage (S):** `make coverage` target using cargo-llvm-cov; a CI step in the Rust job publishing lcov per-crate with a modest initial threshold (e.g. fail < 50% lines workspace-wide, ratchet upward), so the 0% files — contracts.rs DB paths, portal/portal-ui/src/views/* — become visible in every PR.
- **Safety/dry-run:** all targets run against local/in-process services only.

### Implementation plan

1. **(S)** Fail-loud DB skip (`RYUKI_REQUIRE_DB`) + postgres service + env vars in deploy/ci/azure-pipelines.yml — makes every later DB test real. *Feature 1.*
2. **(M)** Expand db_tests to all 42 migrations; add contracts_db_tests for the 19 contracts.rs query sites. *Feature 1.*
3. **(M)** Extract `build_router()` into sources/ryuki-api/src/router.rs; add dev-dependencies; write the middleware/route oneshot test matrix. *Feature 2.*
4. **(M)** DB-backed auth session tests: login → sessions row → verified unsafe write → expiry/logout (pins 6afe852 and 7172ea8). *Feature 6, part 2.*
5. **(M)** tests/lifecycle_e2e.rs + compose Smoke stage in CI. *Feature 3.*
6. **(S)** Coverage: `make coverage` (cargo-llvm-cov) + CI lcov publish with starter threshold. *Feature 8.*
7. **(L)** Fixture corpus under fixtures/adapters/ for all 17 providers + wiremock adapter tests + adapter_contract_test.rs fixture-existence/redaction enforcement. *Feature 5.*
8. **(M)** validator-rs lib extraction + real `/api/validation/run` (+ `/api/validation/slices`, optional migrations/044_validation_runs.sql). *Feature 7.*
9. **(M)** Portal component tests (wasm-bindgen-test) for views/ and shell.rs; extract testable pure functions where needed. *Feature 4.*
10. **(M)** portal/e2e/ Playwright harness + PortalE2E CI job. *Feature 4.*
11. **(L)** Real Entra JWT validation (jsonwebtoken + JWKS) with signed-fixture tests. *Feature 6, part 1.*
12. **(S-M)** proptest modules; criterion benches; scripts/load/ k6 script; scheduled cargo-fuzz. *Feature 8.*

Steps 1-3 unblock everything else and should land first; 4-6 close the gap on the recent security commits; 7-12 can proceed in parallel.

### Risks & open questions

- **CI runtime growth.** Postgres + smoke + Playwright + coverage could double BuildTest wall time on the single ubuntu-latest pool. Mitigation: keep Smoke/PortalE2E as parallel jobs; cache cargo; consider `cargo nextest`. Open question: is the Azure pipeline the long-term CI (the only other workflow is GitHub Pages), or should this investment target GitHub Actions where `services: postgres` is one stanza?
- **Router extraction touches `main()` with zero existing harness** — the exact chicken-and-egg this theme fixes. Do the move as a pure cut-and-paste commit verified by `cargo build` + manual `make run-api` smoke before adding behavior tests on top.
- **DB test isolation.** Parallel `cargo test` against one database risks cross-test interference on `sessions`/`requests`. Options: per-test schemas, `sqlx::test`-style per-test databases, or serializing the DB modules (`--test-threads=1` for those modules). Needs a decision before step 2 scales.
- **Edition/toolchain friction.** Workspace mixes edition 2024 (root) and 2021 (crates) on pinned Rust 1.88; wasm-bindgen-test and cargo-llvm-cov must be validated against that pin before CI adoption.
- **Adapter fixture realism vs. redaction.** The contract forbids raw provider payloads; fixtures must be hand-synthesized to provider API *shapes* without copying real responses. Who owns shape-accuracy review per provider, and does `mock-provider-result` fidelity matter before live adapter execution exists at all? (If live execution ships in a later phase, the wiremock seam from feature 5 is the prerequisite either way.)
- **Entra scope.** Real JWKS validation (step 11) is arguably a production-auth feature, not a test feature — it appears here because the *test* for it currently codifies never validating tokens. If another design section owns Entra SSO, this section's scope shrinks to the signed-fixture test harness.
- **Coverage threshold politics.** A hard gate set too high will be ratcheted off; recommend starting informational-only for 2-3 weeks, then enforcing at observed-baseline-minus-2%.
- **`/api/validation/run` blast radius.** Compiling validator-rs into ryuki-api couples API build time to 230 checks and rayon; the shell-out alternative keeps crates decoupled but needs an allowlist to avoid argument-injection. Lean library-crate for type-safety, but confirm binary-size/build-time budget.

---

## Adapter & vendor expansion

Ryuki advertises 17 provider adapters, but its vendor surface is both narrower and more brittle than the configuration suggests. Ten of fourteen provider categories accept a `RYUKI_*_PROVIDER` value for which **no adapter exists at all** — storage, DNS, IPAM, load-balancer, firewall, build/CI-CD, network/SDN, Kubernetes, database, and secrets are config-only enums whose values are echoed in a settings summary and never construct anything. There is no adapter registry or factory: "an adapter" is a set of hand-coordinated static declarations spread across the engine, core config, API seed JSON, catalog YAML, and three validator constants, and that set has already drifted (the readiness catalog covers 6 of 17 adapters; a `veeam-one` ghost has a type variant and validator pin but no struct; seven adapters return a different readiness shape than the other ten). Growing vendor coverage — the owner's stated goal — therefore has two halves: harden the extension mechanism so each new adapter lands in one canonical, validator-pinned shape, then add vendors in priority order, starting with the empty categories where vendor-neutral engine mocks already exist. This theme deliberately stays inside the platform's dry-run governance: every new adapter ships blocked-by-default and mock-only; making any of them live is the "Live adapter execution & provider integration" theme (P0, above), not this one.

### Current state

- **The extension mechanism is a hand-edit checklist, not a registry.** `sources/ryuki-engine/src/adapter_framework.rs` defines the synchronous `ProviderAdapter` trait (`connect/health_check/sync_inventory/execute/disconnect`, lines 11-17) and all 17 `<X>Adapter` structs with `static_dry_run()` constructors in one ~1,500-line file. The type enum `AdapterType` lives in `sources/ryuki-engine/src/models.rs:373-392` (18 variants — including `VeeamOne`, which has **no struct**) with kebab-case `Display` arms at lines 394-417. Nothing constructs an adapter outside its own unit tests.
- **Provider env vars are pure configuration.** `sources/ryuki-core/src/config.rs` declares one kebab-case serde enum per category (`HypervisorProvider`, `MonitoringProvider`, `BackupProvider`, `StorageProvider`, `DnsProvider`, `IpamProvider`, `LoadBalancerProvider`, `FirewallProvider`, `BuildProvider`, `NetworkProvider`, `SecretProvider`, `DatabaseProvider`, `KubernetesRuntime`), loaded via Figment `Env::prefixed("RYUKI_").split("__")` (`config.rs:1079`). The selected value is only echoed in the config summary (`sources/ryuki-api/src/config.rs:62-64`) and exposed as editable admin settings keys (`sources/ryuki-api/src/contracts.rs:6575-6643`); no factory maps e.g. `HypervisorProvider::Vmware` to `VMwareAdapter`.
- **The API surface is duplicated static seed JSON.** The 17-adapter list is hardcoded twice in `sources/ryuki-api/src/contracts.rs` — `integrations_readiness()` (line 4040) and `adapter_json()` (line 4065) — with per-adapter Axum routes registered around lines 387-460, plus separate id lists in `integrations_adapter_matrix()` (line 4216), `integrations_adapter_contract_test()` (line 4229), and the inventory-coverage domains (lines 4268, 4274). The readiness handlers for nutanix/xen/kvm/commvault/rubrik/cohesity/netbackup (lines 4132-4214) return a divergent `status:"available", mode:"static-dry-run"` shape instead of the blocked-by-default `adapter_json()` shape the original ten use.
- **Catalog and validators pin the surface — and have drifted.** `catalog/adapter-readiness-catalog.yaml` (every entry must be `status: blocked`, `readinessState: missing-secret-reference`, `providerCallsEnabled: false`, `dryRunOnly: true`) lists only 6 of 17 adapters (vmware, hyperv, proxmox, veeam, zabbix, servicenow). `scripts/validator-rs/src/adapter_contract.rs` (`REQUIRED_ADAPTERS`, line 12) still validates a legacy C# path `api/Ryuki.Platform.Api/Program.cs` that no longer exists; `adapter_readiness_matrix.rs` (`REQUIRED_ADAPTERS`, line 9) includes the structless `veeam-one`; `ryuki_engine.rs` pins `REQUIRED_ADAPTER_TYPES`/`REQUIRED_TRAIT_METHODS` and bans `reqwest`/`sqlx`/`hyper` in the engine (`PROHIBITED_IMPORTS`), so the engine is offline by construction.
- **Six empty categories already have vendor-neutral engine mocks** — `storage_provisioning.rs` (which even carries its own seeded `StorageVendor` enum: PureStorage, NetApp, … disconnected from the env var), `dns_ipam.rs` (DNS + IPAM), `load_balancer.rs`, `firewall_rules.rs`, `network_readiness.rs` — making them the cheapest adapter targets. Build/CI-CD has **no engine module at all**. Database is advisory-only (real connectivity is sqlx via `RYUKI_DATABASE_URL` regardless of provider value); Kubernetes readiness is contract YAML only (`catalog/kubernetes-runtime-readiness-contract.yaml`); secrets selection emits only a validation warning, with `catalog/secret-reference-catalog.yaml` declaring vaultwarden the sole `primaryProvider` and `futureProviders: []`.
- **ITSM has an adapter but no provider variable.** `ServiceNowAdapter` is file-exchange-only (mock engine `sources/ryuki-engine/src/servicenow_api.rs`, gated by `catalog/servicenow-future-api-contract.yaml`), yet no `RYUKI_ITSM_PROVIDER` exists in `.env.example` (provider block: lines 35-61) or the `docs/configuration.md` provider table (lines 58-70) — the one category where an adapter exists without a config enum.

### Design

The governing principle: **expand inside the existing dry-run governance, and fix the mechanism before scaling it.** Every new adapter lands exactly as the current 17 do — blocked, secretless, `dryRunOnly: true`, validator-pinned — so vendor breadth grows without widening the live-execution gap (that gap is owned by the live-adapter theme). Before adding adapter #18, the drift above must be repaired, or every new vendor inherits three inconsistent registration patterns.

#### 1 — Harden the extension mechanism (the de facto registration checklist)

- **Goal:** one canonical, documented, low-drift path for adding an adapter, instead of today's implicit 11-surface hand edit.
- **Codify the checklist** as `docs/contributing/adding-an-adapter.md`. The verified steps are: (1) `AdapterType` variant + `Display` arm (`models.rs:373-417`); (2) struct + `static_dry_run()` + `impl ProviderAdapter` in `adapter_framework.rs`, added to the three all-adapter test vectors (`test_all_adapter_configs_are_safe`, `test_all_adapter_readiness_defaults_to_configured`, `test_all_adapters_execute_excludes_params`); (3) provider-enum variant (or new category enum + `RyukiConfig` field ~`config.rs:956` and `Default` ~`:1028`); (4) `.env.example` + `docs/configuration.md` rows; (5) seed object in **both** `integrations_readiness()` and `adapter_json()`, route + handler, matrix/contract-test/inventory-coverage id lists in `contracts.rs`; (6) `inventory_sync.rs` source + `mock_inventory_for_source()` arm; (7) `catalog/adapter-readiness-catalog.yaml` entry in the validator-enforced shape; (8) `secret-reference-catalog.yaml` `allowedConsumers` (`<id>-adapter`) + matrix-contract `supportedAdapters`; (9) validator pins in `adapter_contract.rs:12`, `adapter_readiness_matrix.rs:9`, `ryuki_engine.rs` `REQUIRED_ADAPTER_TYPES`; (10) README/architecture doc bumps (README.md lines 9, 34); (11) verify via `cargo test -p ryuki-engine -p ryuki-api` + `cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all`.
- **De-duplicate before scaling:** collapse the two seed lists in `contracts.rs` into one `const`/builder consumed by `integrations_readiness()`, `adapter_json()`, the matrix, the contract-test targets, and inventory coverage; standardize the seven divergent readiness handlers (`contracts.rs:4132-4214`) on `adapter_json()`; backfill `adapter-readiness-catalog.yaml` from 6 to all 17 entries; resolve `veeam-one` (recommended: add the missing `VeeamOneAdapter` struct, since the id is already validator-pinned and catalog-listed); delete the dead C# path check from `adapter_contract.rs`. A `declare_dry_run_adapter!` macro in `adapter_framework.rs` can collapse step 2's boilerplate while keeping the validator's `static_dry_run`/`DRY-RUN` requirements satisfied.

#### 2 — Vendor candidates per category and what each must implement

Every new adapter implements the same contract: the 5 trait methods (with `execute()` returning `sanitized_dry_run_result(...)` and never echoing params — test-enforced), a `static_dry_run()` constructor (endpoint `*.example.invalid (DRY-RUN)`, metadata `dry_run=true`), a mock inventory arm, the blocked-by-default seed/catalog entries, and the validator pins. Selection criteria: fill empty categories first; prefer vendors with mature REST APIs; exploit API-compatible bundles and existing auth synergy (Ryuki already implements Entra via `RYUKI_ENTRA_*`).

**Wave 1 — first adapters in empty categories** (each fills a category with zero adapters today):

| Category | First adapters ("next" tier) | Rationale |
|---|---|---|
| IPAM/DCIM | **NetBox**; Infoblox | NetBox is the highest-leverage single adapter in the program: de facto network source of truth, doubles as lightweight CMDB/DCIM, excellent REST+GraphQL API. Nautobot later (large code overlap). |
| DNS | **Infoblox NIOS**; Windows DNS (later: PowerDNS, BlueCat) | One Infoblox WAPI adapter serves both the DNS and IPAM enums. Windows DNS is in every AD shop but has no REST (WinRM/RFC2136) — high value, higher cost. |
| Storage | **NetApp ONTAP**, **Pure FlashArray**; Dell PowerStore (later: Ceph, HPE Alletra) | All enum values already exist; ONTAP/Purity REST APIs are excellent; `storage_provisioning.rs` already seeds these vendor names. |
| Load balancer | **F5 BIG-IP**, **HAProxy** (Data Plane API) (later: NetScaler NITRO, VMware Avi, NGINX Plus-only) | Enum values exist; iControl/AS3 and DPA are well-documented. |
| Firewall | **Palo Alto PAN-OS/Panorama**, **FortiGate/FortiManager** (later: Check Point R80+, Cisco FMC) | Enum values exist; Panorama/FortiManager give multi-site fan-out. The `cisco-asa` enum value targets an effectively unautomatable product — retarget to FMC. |
| Network/SDN | **Cisco ACI**, **VMware NSX** (later: Arista CloudVision, Juniper Apstra) | Both enum values exist; NSX has direct synergy with the VMware adapter. |
| Secrets | **HashiCorp Vault** (serving OpenBao via API compatibility); Azure Key Vault (Entra synergy) | Secret references are the gate every adapter's readiness depends on, so this category unblocks readiness progression platform-wide. |
| Build/CI-CD | **GitHub Actions**, **Azure DevOps**, **Jenkins** (later: GitLab CI, Argo CD) | All three enum values exist; requires a new engine mock module first (see §3). |

**Wave 2 — depth in covered categories:** hypervisor: **OpenStack** (the major VMware-exodus destination), **XCP-ng/Xen Orchestra** (may extend the existing Xen XAPI layer), **Azure Local** (Entra synergy); backup: **HYCU** (Nutanix-shop synergy with the AHV adapter), **Dell PowerProtect DM**; monitoring: **checkmk**, **Icinga 2** (VictoriaMetrics likely needs only Prometheus-adapter extensions, not a new adapter); ITSM: **Jira Service Management**, **TOPdesk** — gated on the missing ITSM provider enum (§3). Later/niche tiers (CloudStack, oVirt/OLVM, IBM Storage Protect, Acronis, PRTG, LibreNMS, GLPI, BMC Helix, CyberArk, Delinea, phpIPAM, Device42, OPNsense, MongoDB Ops Manager, etc.) are recorded as candidates but not scheduled.

#### 3 — First implementations for config-only categories

- **Reuse the vendor-neutral engine mocks as the domain layer.** For storage, DNS, IPAM, load-balancer, firewall, and network/SDN, the new adapters' `sync_inventory()`/`execute()` mock outputs should be expressed in the domain vocabulary already modeled by `storage_provisioning.rs`, `dns_ipam.rs`, `load_balancer.rs`, `firewall_rules.rs`, and `network_readiness.rs` — and `storage_provisioning.rs`'s private `StorageVendor` enum should be replaced by (or mapped to) the shared `AdapterType`/`StorageProvider` values so the engine and config stop disagreeing about vendor identity.
- **Build/CI-CD gets an engine module first.** There is no `sources/ryuki-engine/src/build_pipeline.rs` equivalent today; create the vendor-neutral mock (pipelines, runs, artifacts, gates) following the `load_balancer.rs`/`firewall_rules.rs` pattern before adding the GitHub Actions/Azure DevOps/Jenkins adapters on top.
- **Close the ITSM enum gap.** Add `RYUKI_ITSM_PROVIDER` (`ItsmProvider` enum, default `servicenow`) to `sources/ryuki-core/src/config.rs`, `.env.example`, and `docs/configuration.md` before a second ITSM adapter lands; the ServiceNow live-API gate (`catalog/servicenow-future-api-contract.yaml`) is the template for how Jira SM/TOPdesk live access would eventually be contracted.
- **Decide which categories are adapter-shaped at all.** Database (real connectivity is already sqlx via `RYUKI_DATABASE_URL`; the enum is advisory) and Kubernetes (readiness is contract YAML, no runtime client) do not obviously fit the `ProviderAdapter` mock model — recommend keeping them config-advisory and deferring real clients to the live-execution theme. Secrets is the exception: a Vault/OpenBao dry-run adapter is justified now because the entire readiness model (`missing-secret-reference`) hinges on this category, and `secret-reference-catalog.yaml` (`futureProviders: []`) must be updated to name the planned providers in the same change.

#### 4 — Readiness, validation & evidence requirements for every new adapter

- **Dry-run-first, blocked-by-default, no exceptions.** Catalog entry and seed JSON ship with `status: blocked`, `readinessState: missing-secret-reference`, `providerCallsEnabled: false`, `dryRunOnly: true`, `requiresSecretReference: true`, `requiresApproval: true`, `safeCapabilities` including `readiness`, and `blockedReasons` including `secret-reference-missing` and `approval-route-required`. `execute()` must route through `sanitized_dry_run_result()`; `test_all_adapters_execute_excludes_params` enforces that params are never echoed.
- **Contract tests and validator pins are part of the definition of done.** The adapter id is appended to the three all-adapter engine test vectors, the contract-test targets (`contracts.rs:4229`), the matrix adapters array (`:4216`), `supportedAdapters` in `catalog/adapter-readiness-matrix-contract.yaml`, and the three validator constants (`adapter_contract.rs:12`, `adapter_readiness_matrix.rs:9`, `ryuki_engine.rs` `REQUIRED_ADAPTER_TYPES`). An adapter that exists in code but not in the pins is a validation failure by design.
- **Catalog hygiene is validator-enforced.** `adapter_contract.rs` scans catalog entries for URLs/IPs/UUIDs/secret-like keys — entries carry only kebab-case ids, `<id>-adapter` components, and `/api/integrations/<id>` apiGroups. `secret-reference-catalog.yaml` `allowedConsumers` gains `<id>-adapter` so the future secrets layer knows who may resolve what.
- **The engine stays offline.** No new adapter may introduce `reqwest`/`sqlx`/`hyper` into `ryuki-engine` (`PROHIBITED_IMPORTS` fails the contract checks); live clients belong in the `ryuki-adapters` crate designed in the live-execution theme. The acceptance gate for every adapter PR is `cargo test -p ryuki-engine -p ryuki-api` plus the full validator run (Makefile default target).

### Implementation plan

1. **(S)** Repair API drift: standardize the seven nonconforming readiness handlers (`contracts.rs:4132-4214`) on `adapter_json()`; collapse the duplicated seed lists in `integrations_readiness()`/`adapter_json()` and the matrix/contract-test/inventory-coverage id lists onto one shared constant.
2. **(M)** Backfill `catalog/adapter-readiness-catalog.yaml` from 6 to all 17 adapters in the validator-enforced shape; extend `adapter-readiness-matrix-contract.yaml`; resolve `veeam-one` by adding the missing `VeeamOneAdapter` struct and test-vector entries.
3. **(S)** Delete the legacy C# path check (`api/Ryuki.Platform.Api/Program.cs`) from `scripts/validator-rs/src/adapter_contract.rs` and re-point validation at the Rust surfaces.
4. **(S)** Add the `ItsmProvider` enum + `RYUKI_ITSM_PROVIDER` to `sources/ryuki-core/src/config.rs`, `.env.example` (lines 35-61 block), and `docs/configuration.md` (provider table).
5. **(S)** Write `docs/contributing/adding-an-adapter.md` from the verified checklist; add the `declare_dry_run_adapter!` boilerplate macro.
6. **(L)** Wave 1a — first adapters for empty categories with existing engine mocks: NetBox (IPAM), Infoblox (shared DNS+IPAM), NetApp ONTAP + Pure FlashArray (storage), F5 BIG-IP + HAProxy (load balancer), Palo Alto + FortiGate (firewall), Cisco ACI + VMware NSX (network/SDN) — each via the full checklist, reusing the matching engine module's domain vocabulary.
7. **(M)** Wave 1b — secrets: HashiCorp Vault dry-run adapter with an `openbao` API-compatible alias; update `secret-reference-catalog.yaml` `futureProviders` and `allowedConsumers` in the same change.
8. **(M)** Wave 1c — build/CI-CD: new vendor-neutral engine mock `sources/ryuki-engine/src/build_pipeline.rs`, then GitHub Actions, Azure DevOps, and Jenkins adapters.
9. **(L)** Wave 2 — depth in covered categories: OpenStack, XCP-ng (extending the Xen XAPI layer), Azure Local (hypervisor); HYCU, Dell PowerProtect DM (backup); checkmk, Icinga 2 (monitoring); Jira Service Management, TOPdesk (ITSM, after step 4).
10. **(S)** Per wave: bump README.md adapter count/vendor list (lines 9, 34), touch `docs/architecture.md` if the adapter diagram text changes, and gate merge on `cargo test -p ryuki-engine -p ryuki-api` + validator `run-all`.

### Risks & open questions

- **Static-list scaling.** Each adapter touches ~11 surfaces and three validator constants; at 30+ adapters, hand-maintained drift is guaranteed (it already happened at 17 — the catalog covers 6, and seven handlers diverged). Decision needed before Wave 2: keep hand-pinned lists with the consolidated constant from step 1, or move to a build-time generation step that emits seed JSON, catalog entries, and validator pins from one declaration.
- **Mock inflation vs. credibility.** Shipping ~15 more dry-run adapters before the live-execution theme lands widens the gap between advertised vendor support and executable behavior — the exact overclaim the P0 theme documents in README/docs. Mitigation: readiness stays honestly `blocked`/`dryRunOnly`, and each wave's announcement copy must say "governed dry-run support," not "integration."
- **Non-REST vendors strain the framework.** Windows DNS (WinRM/RFC2136), SQL Server (TDS/T-SQL), IBM Storage Protect (`dsmadmc` CLI), and classic Cisco ASA (CLI-only) have no REST surface; the future live substrate is HTTP-shaped. Either scope these out of adapter form, or the live-adapter theme must define a second transport class (command-channel adapters) before they are promised.
- **Enum values that name the wrong target.** `cisco-asa` should become (or alias to) Cisco Secure Firewall/FMC; `nginx` is only automatable as NGINX Plus; HAProxy requires the Data Plane API. Renaming published kebab-case enum values is a config-compat break — serde aliases can carry both, but a policy is needed.
- **API-compatible pairs: one struct or two ids?** Vault/OpenBao, NetBox/Nautobot, and Prometheus/VictoriaMetrics could share implementations, but the readiness catalog, routes, and validator pins assume a 1:1 id-to-component mapping. Recommend distinct ids sharing an implementation internally; confirm the catalog's unique-component rule tolerates that.
- **HPE Alletra's control plane is cloud-hosted** (Data Services Cloud Console, OAuth2) — a cloud dependency inside an on-prem governance product is a posture question, not just an adapter; defer until a policy exists.
- **The provider-env-to-adapter binding stays absent by design here.** Users may reasonably assume `RYUKI_DNS_PROVIDER=infoblox` activates the Infoblox adapter; it will not until the live-execution theme builds the factory/dispatch seam. The configuration docs added in step 4/10 must state this explicitly to avoid compounding the execution-mode-theater problem already documented in the P0 theme.
- **Open question:** should `veeam-one` be completed (step 2's recommendation) or retired? Retiring requires touching the same validator pins and matrix contract; completing it adds a monitoring-flavored adapter under a backup vendor's name. Recommend completing it as a monitoring-category adapter and noting the category in its catalog entry.

---

## Appendix: claims investigated and refuted

The following claims were raised during the survey, adversarially verified against the repository, and **refuted**. They are recorded here so future readers do not re-litigate them.

- **"Reference/seed data lives in engine code instead of the tables built for it"** — REFUTED: the claim's core evidence is false. 36 of 42 migrations contain INSERT seed rows, not just 001_platform_config.sql. The three named tables are all seeded: `linux_distro_catalog` at `/Users/mvandenbulcke/Repos/ryuki.io/migrations/009_linux_deployments.sql:30`, `approved_packages` at `/Users/mvandenbulcke/Repos/ryuki.io/migrations/032_software_packages.sql:37`, `baseline_checks` at `/Users/mvandenbulcke/Repos/ryuki.io/migrations/024_os_baseline.sql:21` (`failure_patterns` also seeded in 028, `site_capacity`/`vm_utilization` in 021, `site_status`/`component_status` in 025). The residual kernel — engines ALSO hardcode parallel Rust seed data (e.g. `aiops.rs:80 seed_suggestions()`) that can diverge from the SQL seeds because nothing reads the tables — is real, but it is a facet of the confirmed dead-schema claim, not a missing-seeds problem as stated.

## Appendix: method

This document was produced by an orchestrated multi-agent analysis run on 2026-06-12. Independent survey agents each took a slice of the platform — domain engines, API layer, portal, catalog contracts, migrations, deploy artifacts, docs, and test surfaces — and proposed candidate gaps with file/line evidence. A separate adversarial-verification pass re-checked every claim against the repository source; claims that failed verification were either dropped or recorded in the refuted-claims appendix above, and surviving claims were consolidated into 13 priority-ordered theme sections, each authored as a self-contained design (current state, design, implementation plan, risks). A fourteenth theme, "Adapter & vendor expansion," was researched and added in a follow-up pass on the same date at the owner's request. All file paths and line numbers reference the repository at `/Users/mvandenbulcke/Repos/ryuki.io` as of the time of writing (branch `main`, HEAD `7172ea8`); they are evidence pointers, not stable anchors, and may drift as the codebase evolves. Proposed migration numbers (044+) were assigned independently per theme and must be reconciled into a single sequence at implementation time.
