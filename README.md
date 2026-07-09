<p align="center">
  <img src="docs/assets/logo.svg" width="96" alt="Ryuki logo — the coiled ryū guarding its pearl">
</p>

<h1 align="center">Ryuki</h1>

<p align="center"><em>竜騎 &mdash; the Dragon Knight. A governed control plane that watches over your infrastructure.</em></p>

System-engineer platform for multi-site datacenter infrastructure management — **17 provider adapters, 110+ catalog contracts, 3,900+ tests, 100% Rust**.

**Website & documentation:** [ryuki.io](https://ryuki.io) · [Getting Started](https://ryuki.io/getting-started.html) · [Architecture](https://ryuki.io/architecture.html) · [Configuration](https://ryuki.io/configuration.html) · [RBAC & Scoping](https://ryuki.io/rbac-and-scoping.html) · [Agents & Live Execution](https://ryuki.io/agents-and-live-execution.html) · [API Reference](https://ryuki.io/api-reference.html) · [all docs](https://ryuki.io/documentation.html)

## What It Does

Ryuki is an operational control plane that gives system engineers, datacenter teams, backup administrators, monitoring teams, and service desk operators a governed way to request, operate, evidence, and retire infrastructure services across multiple sites.

### Capabilities

| Domain | What You Can Do |
|---|---|
| **VMware / Hyper-V / Proxmox** | VM lifecycle, placement, capacity governance, snapshot management, day-2 resize |
| **Windows & Linux** | Deployment, patching, OS baseline compliance, decommission |
| **SQL Server** | Deployment with disk layout, service accounts, SPNs, application-aware backup |
| **Veeam Backup & Replication** | Backup coverage reports, controlled restore, DR replication, repository health |
| **Zabbix** | Host onboarding, alert routing, maintenance windows, drift detection |
| **ServiceNow CMDB** | Excel import/export, CI reconciliation, relationship graph |
| **Datacenter** | Hardware lifecycle, firmware baselines, switchport/VLAN readiness, datacenter readiness checks |
| **Image Factory** | Monthly golden image build, test, promote, publish |
| **Runbook Execution** | Approved runbook catalog, step tracking, approval gates, rollback |
| **Firmware Lifecycle** | EOL tracking, compliance exceptions, vendor summaries, firmware governance |
| **Incident Context** | Context assembly, affected services, on-call escalation, dependency graph |
| **Access Recertification** | AD groups, service accounts, local admin, sudo — recertification campaigns |
| **Site Registry** | UN/LOCODE reference (89 locations, 49 countries), activate/deactivate via admin |
| **Adapter Framework** | 17 provider adapters: VMware, Hyper-V, Proxmox, Nutanix AHV, Xen, KVM, Veeam, Commvault, Rubrik, Cohesity, NetBackup, Zabbix, Prometheus, Datadog, Grafana, SolarWinds, ServiceNow |
| **Evidence & Audit** | Redacted evidence packs, approval chains, shift handover, compliance dashboards |
| **Break-Glass** | Emergency change with full audit trail, no bypass on evidence |

### Request Lifecycle

Every infrastructure request flows through governed statuses:

```
Draft → Intake → Validated → Planned → Approved → Locked → Executing → Verifying → Completed
```

A request that fails at any stage lands in a terminal `Failed` status and keeps its full evidence trail. Each stage produces redacted evidence suitable for audit, CAB, incident review, and handover.

On the roadmap, four stages extend the pipeline beyond completion: `Protect` (backup coverage and monitoring enrollment), `Publish` (CMDB and service-catalog visibility), `Maintain` (patching, compliance, and ownership through the service life), and `Retire` (governed decommission with final evidence).

## Architecture

```
Browser → Portal UI (Leptos/Axum SSR) → Platform API (Axum) → Engine + Database
                                              ↓
                                          Vault (secrets)
```

| Component | Stack | Role |
|---|---|---|
| `portal-ui` | Rust / Leptos / Axum | Full-stack SSR portal, same-origin API boundary, role-filtered navigation |
| `ryuki-api` | Rust / Axum / sqlx | Control plane API, Entra ID auth, request lifecycle, admin settings |
| `ryuki-engine` | Rust | Domain engines: models, evidence pipeline, health monitoring, adapters, workflows |
| `ryuki-core` | Rust | Shared types, secret scanning, YAML utilities |
| `ryuki-agent` | Rust | Operator-deployed execution agent — Terraform/Ansible with a signed live-apply trust gate |
| `ryuki-runner` | Rust | Process-spawning layer for Terraform and Ansible runs |
| `ryuki-protocol` | Rust | Control-plane↔agent wire contract — pure types plus Ed25519 signature primitives |
| `ryuki-validator` | Rust | Self-contained static validation engine — 129 validator modules, registry-enforced coverage |
| PostgreSQL | CloudNativePG / Docker | Control plane database, migrations via sqlx |
| Vault | HashiCorp Vault | Runtime secrets, adapter credentials, PKI |

### Network Policy

| Source | Allowed Destination |
|---|---|
| Browser | Ingress over TLS only |
| Ingress | `portal-ui` and `ryuki-api` |
| `portal-ui` | `ryuki-api` only (same-origin) |
| `ryuki-api` | PostgreSQL, Vault, approved adapters |
| Adapters | Only approved provider endpoints |

Default deny. Explicit egress and ingress allowances only.

## Quick Start

### Prerequisites

- Rust (stable, see `rust-toolchain.toml`)
- Docker (for PostgreSQL)
- PostgreSQL 18 client libraries (for sqlx)

### Setup

```bash
# Clone
git clone https://github.com/mvandenbulcke/ryuki.io.git
cd ryuki.io

# Start PostgreSQL
docker compose -f deploy/compose/compose.yaml up -d platform-db

# Configure environment
cp .env.example .env
# Edit .env — set RYUKI_DATABASE_URL; for live SSO set RYUKI_AUTH_MODE,
# RYUKI_ENTRA_TENANT_ID, and RYUKI_ENTRA_CLIENT_ID

# Build
cargo build --workspace

# Test
cargo test --workspace

# Run API
cargo run --manifest-path sources/ryuki-api/Cargo.toml

# Run portal (separate terminal)
cargo leptos serve --manifest-path portal/portal-ui/Cargo.toml
```

### Validation

```bash
# Full validator
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all --root .

# Format check
cargo fmt --check --all

# Clippy (matches the CI lint gate)
cargo clippy --workspace -- -D warnings

# Secret scan
./scripts/no-secret-scan.sh
```

## Authentication

### Entra ID App Roles

Ryuki uses Entra ID [app roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps), not group-based authorization. Roles are defined in the app registration manifest and assigned to users in the Enterprise Application.

| Role | Scope |
|---|---|
| `PlatformAdmin` | Configure platform, manage integrations, emergency controls |
| `DatacenterApprover` | Approve site, hardware, network, capacity changes |
| `VMwareOperator` | VMware, vCenter, ESXi, vSAN operations |
| `HyperVOperator` | Hyper-V host, cluster, VM operations |
| `ProxmoxOperator` | Proxmox node, cluster, VM operations |
| `WintelLinuxOperator` | Windows/Linux, AD, gMSA, patching, OS baselines |
| `BackupOperator` | Veeam backup, restore, replica, retention |
| `MonitoringOperator` | Zabbix onboarding, templates, alert routing |
| `ServiceDesk` | Approved low-risk runbooks, incident context |
| `Auditor` | Read-only: requests, approvals, evidence, policy state |
| `Requester` | Submit catalog requests, view own status |
| `BreakGlassAdmin` | Emergency operations with full audit trail |

See `docs/entra-app-registration.md` for the app manifest template.

## Configuration

All configuration via environment variables with the `RYUKI_` prefix (nested fields use `__`, e.g. `RYUKI_SERVER__BIND_ADDRESS`). See `.env.example` for the full reference.

| Variable | Purpose |
|---|---|
| `RYUKI_DATABASE_URL` | PostgreSQL connection string |
| `RYUKI_AUTH_MODE` | `mock-dry-run` (default), `static-dry-run`, `entra-id`, or `local` |
| `RYUKI_ENTRA_TENANT_ID` | Azure AD directory ID |
| `RYUKI_ENTRA_CLIENT_ID` | App registration client ID |
| `RYUKI_ENTRA_AUTHORITY` | OIDC authority URL |
| `RYUKI_PLATFORM_NAME` | Display name in portal |
| `RYUKI_PLATFORM_URL` | Platform URL for redirects |

Provider backends are selected per category — `RYUKI_HYPERVISOR_PROVIDER` (vmware / hyperv / proxmox / nutanix-ahv / xen / kvm), `RYUKI_BACKUP_PROVIDER`, `RYUKI_MONITORING_PROVIDER`, `RYUKI_SECRET_PROVIDER`, `RYUKI_DATABASE_PROVIDER`, `RYUKI_KUBERNETES_RUNTIME`, plus storage, DNS, IPAM, load-balancer, firewall, CI/CD, and SDN categories — all documented in `.env.example`.

### Site Management

Sites use UN/LOCODE identifiers (e.g. `DEFRA` for Frankfurt, `GBLON` for London). The admin API provides:

- `GET /api/admin/sites/countries` — List available countries
- `GET /api/admin/sites/countries/{DE}/cities` — List cities for a country
- `POST /api/admin/sites/{code}/activate` — Activate a site for operations

See `docs/site-management.md` for details.

## Safety

- **Dry-run by default**: Write-capable operations require explicit plan before execution
- **Approval gated**: Live execution requires validation, approval, locking
- **Evidence first**: Every operation emits redacted evidence for audit, CAB, incident review
- **Least privilege**: Per-adapter identities, separate read/write credentials
- **Idempotent by default**: Operations are retry-safe or explicitly marked non-idempotent
- **Never committed**: Secrets, tokens, credentials, tenant IDs, object IDs, private IPs, raw provider payloads
- **Same-origin browser isolation**: Portal never calls provider APIs or adapters directly

## License

[MIT](LICENSE)
