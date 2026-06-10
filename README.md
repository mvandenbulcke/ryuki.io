# Ryuki

System engineer platform engineering portal for multi-site datacenter infrastructure management.

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
| **Datacenter** | Hardware lifecycle, firmware baselines, switchport/VLAN readiness |
| **Image Factory** | Monthly golden image build, test, promote, publish |
| **Evidence & Audit** | Redacted evidence packs, approval chains, shift handover, compliance dashboards |
| **Break-Glass** | Emergency change with full audit trail, no bypass on evidence |

### Request Lifecycle

Every infrastructure request flows through governed stages:

```
Intake → Validate → Plan → Approve → Lock → Execute → Verify → Protect → Publish → Maintain → Retire
```

Each stage produces redacted evidence suitable for audit, CAB, incident review, and handover.

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
| `ryuki-engine` | Rust | Domain models, evidence pipeline, health monitoring, adapters, workflows |
| `ryuki-core` | Rust | Shared types, secret scanning, YAML utilities |
| `ryuki-validator` | Rust | Self-contained static validation engine (352 slices) |
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
# Edit .env with your Entra ID tenant/client IDs

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
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all

# Lint + format + secret scan
cargo fmt --check --all
cargo clippy --workspace -- -D warnings
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

All configuration via environment variables. See `.env.example` for the full reference.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `ENTRA_TENANT_ID` | Azure AD directory ID |
| `ENTRA_CLIENT_ID` | App registration client ID |
| `ENTRA_AUTHORITY` | OIDC authority URL |
| `PLATFORM_NAME` | Display name in portal |
| `PLATFORM_URL` | Platform URL for redirects |

### Database

PostgreSQL 18 with sqlx migrations:

| Migration | Tables |
|---|---|
| `001_platform_config.sql` | Key-value platform settings |
| `003_requests.sql` | Request lifecycle |
| `004_sessions.sql` | Auth sessions |
| `005_vm_day2_operations.sql` | VM day-2 change tracking |
| `006_snapshots.sql` | Snapshot governance |
| `007_backup_restore.sql` | Coverage reports + restore requests |

Gap at 002 is intentional — removed Entra groups table when migrating to app roles.

## Safety

- **Dry-run by default**: Write-capable operations require explicit plan before execution
- **Approval gated**: Live execution requires validation, approval, locking
- **Evidence first**: Every operation emits redacted evidence for audit, CAB, incident review
- **Least privilege**: Per-adapter identities, separate read/write credentials
- **Idempotent by default**: Operations are retry-safe or explicitly marked non-idempotent
- **Never committed**: Secrets, tokens, credentials, tenant IDs, object IDs, private IPs, raw provider payloads
- **Same-origin browser isolation**: Portal never calls provider APIs or adapters directly

## License

MIT
