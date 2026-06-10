# Ryuki

System engineer platform engineering portal for multi-site datacenter infrastructure management.

**ryuki.io** — tames your infrastructure.

## What it does

Ryuki is an operational control plane for datacenter and system engineering teams. It provides governed, auditable workflows for:

- **VMware / Hyper-V / Proxmox** — VM lifecycle, placement, capacity governance
- **Windows & Linux** — deployment, patching, OS baseline compliance
- **SQL Server** — deployment, application-aware backup
- **Veeam Backup & Replication** — backup coverage, restore, DR, repository health
- **Zabbix** — host onboarding, alert routing, maintenance windows, drift detection
- **ServiceNow CMDB** — Excel import/export, CI reconciliation, relationship graph
- **Datacenter** — hardware lifecycle, firmware baselines, switchport/VLAN readiness
- **Image Factory** — monthly golden image build, test, promote, publish
- **Evidence & Audit** — redacted evidence packs, approval chains, shift handover

## Architecture

| Component | Stack | Description |
|---|---|---|
| `ryuki-portal-ui` | Rust / Leptos / Axum | Full-stack SSR portal with Sigma design system |
| `ryuki-api` | Rust / Axum / sqlx | Control plane API, auth, request lifecycle |
| `ryuki-engine` | Rust | Domain models, evidence, health, adapters |
| `ryuki-core` | Rust | Shared types, utilities, secret scanning |
| `ryuki-validator` | Rust | 98-slice static validation engine |
| PostgreSQL | CloudNativePG / Docker | Control plane database |
| Vault | HashiCorp Vault | Secrets management |

## Quick Start

```bash
# Start PostgreSQL
docker compose -f deploy/compose/compose.yaml up -d platform-db

# Copy and configure environment
cp .env.example .env

# Build and test
cargo build --workspace
cargo test --workspace

# Run validators
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```

## Configure Entra ID SSO

1. In Entra admin center, create an App Registration named "Ryuki Infrastructure Platform"
2. Set redirect URI: `http://localhost:18080/auth/callback` (Web platform)
3. Define app roles in the manifest (PlatformAdmin, VMwareOperator, etc.)
4. Set `ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` in `.env` or the admin portal
5. See `docs/entra-app-registration.md` for the full app roles manifest

## Safety

- Static/dry-run by default — no live provider execution without explicit approval
- Secrets via Vault-managed references — never committed
- Redacted evidence — audit-ready without exposing credentials
- Same-origin browser isolation — portal never calls provider APIs directly

## License

MIT
