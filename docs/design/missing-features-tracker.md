# Missing-features execution tracker

A 9-area analysis swarm (2026-06-24) produced 66 ranked missing features
(deduped from 69 raw, every claim spot-checked against code). The owner approved
implementing **all 66**. This file tracks execution.

## Execution model

- **Serial, dependency-ordered.** Each feature lands as one slice: design →
  migration (sequential number) → engine/API/portal → tests → gate → Codex
  review → commit + push. Features are NOT built in parallel — they collide on
  migration numbers and on the hot shared files (`contracts.rs`, `main.rs`).
- **Gate per slice:** `cargo fmt --all`; `cargo clippy --workspace --all-targets
  -- -D warnings`; `cargo test -p ryuki-api --bins`; the relevant `*_db_tests`
  with `RYUKI_DATABASE_URL`; `bash scripts/no-secret-scan.sh`. Then a GPT-5 Codex
  review before commit.
- **Engines stay pure** (validator-enforced no-IO); credit Codex as co-author.

## Key dependencies (drive ordering)

- **#1 scheduler** unblocks #31, #39, #40, #45, #52 (and feeds #19, #22).
- **#2 administrable/scoped RBAC** precedes #48 (recert revocation).
- **Analytics chain (strict):** #34 metric history → #35 detection → #36
  generation → #37 what-if → #53/#54 budgets/commitment.
- **#14 API list/pagination** precedes #15 / #59 (portal faceting/scope).
- **require-key rollout (idempotency 2b+)** precedes requiring keys on
  portal-called routes — needs `UpstreamClient` to send keys first.

## Backlog (rank order; `[x]` = shipped)

| # | ✓ | Feature | Area | E | V | 📋 |
|---|---|---|---|---|---|---|
| 1 | [ ] | Durable scheduler / background job engine | Roadmap | L | H | ✓ |
| 2 | [ ] | Administrable, site/env-scoped RBAC | Security | L | H | ✓ |
| 3 | [x] | Separation-of-duties on approval (no self-approve) | Security | S | H | ✓ |
| 4 | [ ] | Multi-role approval quorum | Security | M | H | ✓ |
| 5 | [x] | Tamper-evident audit hash chain + verify | Security | M | H | ✓ |
| 6 | [ ] | Dependency-backed platform self-health probes | Roadmap | L | H | ✓ |
| 7 | [ ] | Protect/Publish/Retire actions in portal | Portal | M | H | ✓ |
| 8 | [~] | Agent enrollment approve/revoke from portal | Portal | M | H | — |
| 9 | [ ] | Outbound notifications (email/webhook/callback/chat) | Roadmap | L | H | ✓ |
| 10 | [ ] | Destroy/teardown execution mode (live decommission) | Exec | L | H | — |
| 11 | [ ] | Pre-dispatch policy gate for unsafe IaC | Exec | M | H | — |
| 12 | [ ] | Agent-side vault-backed secret resolution | Exec | L | H | ✓ |
| 13 | [ ] | Request rework/fail/soft-delete transitions | API | M | H | ✓ |
| 14 | [ ] | List filtering/search + pagination envelope (API) | API | M | H | ✓ |
| 15 | [ ] | Faceted request filtering/sort/pagination (portal) | Portal | M | H | — |
| 16 | [ ] | Enforced site degradation mode (write gating) | Resil | L | H | — |
| 17 | [ ] | Bulk / batch operations | API | M | H | — |
| 18 | [ ] | Inbound integration webhook receivers | Integ | L | H | — |
| 19 | [ ] | Connection health monitoring (scheduled + history) | Integ | M | H | — |
| 20 | [ ] | Step-up / MFA re-auth for high-risk actions | Security | M | H | — |
| 21 | [ ] | Live secret rotation (Vault) + break-glass | Security | L | H | ✓ |
| 22 | [ ] | Domain-event alert generation | Observ | M | H | — |
| 23 | [ ] | CP-side poison-job cap / dead-letter | Resil | M | H | — |
| 24 | [ ] | Audit-trail export / streaming to SIEM | Observ | M | H | — |
| 25 | [ ] | SLO / error-budget tracking | Observ | M | H | — |
| 26 | [ ] | CP database backup/restore + DR runbook | Roadmap | M | H | ✓ |
| 27 | [ ] | Bidirectional CMDB reconciliation + drift | Integ | L | H | ✓ |
| 28 | [ ] | Active Directory / Entra integration adapter | Integ | L | H | — |
| 29 | [ ] | DR failover orchestration (runbook-driven) | Resil | L | H | — |
| 30 | [ ] | Circuit breaker for provider/adapter calls | Resil | M | H | — |
| 31 | [ ] | Scheduled/recurring agent jobs (drift-scan) | Exec | L | H | ✓ |
| 32 | [ ] | Per-notification mark-read + deep-link | Portal | S | M | — |
| 33 | [ ] | CMDB import/export/reconcile actions in portal | Portal | M | M | ✓ |
| 34 | [ ] | Time-series metric history + forecasting | AIOps | L | H | ✓ |
| 35 | [ ] | Anomaly / waste detection engine | AIOps | M | H | — |
| 36 | [ ] | AIOps suggestion-generation engine | AIOps | M | H | — |
| 37 | [ ] | What-if capacity & cost planning | AIOps | M | H | — |
| 38 | [ ] | Storage array registration / lifecycle | API | M | M | — |
| 39 | [ ] | Maintain lifecycle stage (recurring review) | Roadmap | M | M | ✓ |
| 40 | [ ] | Scheduled/recurring synthetic health checks | Observ | S | M | ✓ |
| 41 | [ ] | Integration credential rotation / expiry | Integ | M | M | — |
| 42 | [ ] | Multi-step orchestration / job dependencies | Exec | L | M | ✓ |
| 43 | [ ] | Post-apply verification (re-plan → Verified) | Exec | M | M | — |
| 44 | [ ] | Agent liveness sweep + offline detection | Exec | M | M | — |
| 45 | [ ] | Per-site / per-tenant usage metering | Observ | M | M | — |
| 46 | [ ] | Chargeback / showback cost allocation | AIOps | M | M | — |
| 47 | [ ] | Backup verification + restore-test recency | Resil | M | M | — |
| 48 | [ ] | Enforced access recertification w/ revocation | Security | L | M | — |
| 49 | [ ] | Secret update & deregistration | API | S | M | — |
| 50 | [ ] | Evidence pack file download / export | Portal | S | M | — |
| 51 | [ ] | Per-vendor connection capability catalog | Integ | M | M | — |
| 52 | [ ] | Route DR-overdue/failed tests into work queue | Resil | S | M | — |
| 53 | [ ] | Cost/capacity budget thresholds + alerts | AIOps | M | M | — |
| 54 | [ ] | Reserved-capacity / commitment cost modeling | AIOps | M | M | — |
| 55 | [ ] | DNS record update endpoint | API | S | M | — |
| 56 | [ ] | IPAM subnet CRUD | API | M | M | — |
| 57 | [ ] | Load-balancer virtual-server delete/update | API | M | M | — |
| 58 | [ ] | Connection usage audit trail | Integ | M | M | — |
| 59 | [ ] | Scope (site/env) selector + user preferences | Portal | M | M | ✓ |
| 60 | [ ] | Evidence blob store for large artifacts | Exec | M | M | — |
| 61 | [ ] | On-call / escalation contact registry | Observ | M | M | — |
| 62 | [ ] | audit_log retention / partitioning / archival | Resil | M | M | ✓ |
| 63 | [x] | Observability deploy wiring | Roadmap | M | M | ✓ |
| 64 | [ ] | OpenAPI / machine-readable API spec | Roadmap | M | M | ✓ |
| 65 | [ ] | Optional gated AI narrative adapter | AIOps | M | M | — |
| 66 | [ ] | Release engineering (versioning/tags/changelog) | Roadmap | M | M | ✓ |

_Legend: E = effort (S/M/L), V = value (H/M), 📋 = in `missing-features.md`.
`[x]` shipped · `[~]` partial (core shipped; follow-up tracked) · `[ ]` not started._

**Shipped:** #3 SoD (`aa0e188`), #5 audit hash chain (`6bcb231`), #8 agent
approve — revoke deferred (`6d6fb5b`), #63 observability deploy (`0ce0ed3`).
