# Architecture

## Stack

| Layer      | Technology               |
|------------|--------------------------|
| Portal     | Rust / Leptos (WASM)     |
| API        | Rust / Axum              |
| Engine     | Rust                     |
| Core       | Rust                     |
| Database   | PostgreSQL / sqlx        |
| Secrets    | HashiCorp Vault          |
| Auth       | Entra ID (OIDC / OAuth2) |

## Component Diagram

```
 Browser (WASM)
      │
      ▼
┌──────────┐
│  Portal  │  Leptos SPA, same-origin
│ portal-ui│
└────┬─────┘
     │ HTTP (JSON)
     ▼
┌──────────┐
│   API    │  Axum server, CORS (same-origin only)
│ ryuki-api│
└────┬─────┘
     │
     ▼
┌──────────┐
│  Engine  │  Business logic, auth, request lifecycle
│ryuki-eng │
└────┬─────┘
     │
     ▼
┌──────────┐     ┌──────────┐     ┌──────────┐
│   Core   │     │ PostgreSQL│     │  Vault   │
│ryuki-core│     │  (sqlx)  │     │ (secrets)│
└──────────┘     └──────────┘     └──────────┘
     │
     ▼
┌──────────────┐
│   Adapters   │  Pluggable provider implementations
│  (vsphere,   │
│  hyperv,     │
│  proxmox)    │
└──────────────┘
```

## Key Decisions

- **Same-origin**: Portal and API served from the same origin. CORS allows the Portal origin only.
- **Dry-run default**: Provider operations default to mock/dry-run (`provider_calls_enabled = false`). Live infrastructure execution is a separate, operator-gated path — see [Execution Model](#execution-model). `RYUKI_AUTH_MODE` selects authentication (`entra-id` for real SSO, otherwise a static dev session); it does **not** enable live provider calls.
- **Vault secrets**: Platform secrets (DB credentials, provider tokens) stored in HashiCorp Vault, never in environment or config files.
- **Entra app roles**: RBAC via Entra ID app roles with `roles` claim in the access token. No group-name-to-role mapping.

## Network Policy

```
Browser ──► Portal (same-origin) ──► API ──► Database
                                        ├───► Vault
                                        └───► Adapters
```

Only the API server has access to the database, Vault, and provider adapters. The Portal communicates exclusively with the API.

## Execution Model

Ryuki is **dry-run-first**. Almost every operation plans, validates, and records
evidence without touching live infrastructure: the provider catalogue entries are
credential/endpoint registries whose connection test is a shape-check stub (no
live vendor call), and most domains report `provider_calls_enabled = false`.

There is exactly **one** live execution path, and it is operator-gated end to end:
an operator-deployed agent runs Terraform/Ansible against real infrastructure
under a control-plane-signed grant.

### Modes

| Mode | Who can dispatch | What runs |
| --- | --- | --- |
| `OfflineDryRun` (default) | `execute` tier | `terraform validate` / `ansible-playbook --check` in an isolated workspace, embedded IaC only, no credentials. |
| `LivePlan` | `admin` tier | Real `terraform init` → `plan` → `show -json` against the backend. Produces a plan + a `plan_digest`; **no mutation**. |
| `LiveApply` | minted by an `admin` via `approve-live-apply`, never dispatched directly | `terraform apply` of the **exact** approved plan, on an agent that accepts the signed grant. |

### Live-apply trust chain

1. An operator dispatches a `LivePlan` (admin-only). The agent runs the plan and
   returns scrubbed evidence plus the plan digest.
2. An `admin` approves via `POST /api/requests/{id}/approve-live-apply`. The
   control plane mints a `LiveApply` grant **signed with its Ed25519 key**,
   binding the request id, the approved plan digest, the approver, and a
   short expiry (≤ 24 h). A unique constraint prevents a second request-level
   live apply; in orchestrated multi-step runs each step gets exactly one
   step-scoped `LiveApply`, gated by the step's `FOR UPDATE` approval lock
   (migration 153).
3. The agent only acts if `RYUKI_AGENT_ALLOW_LIVE=true` and it has pinned the
   control-plane public key. It re-plans, then refuses unless **all** hold:
   the grant signature verifies against the pinned CP key; the grant is for this
   request; it has not expired; and the freshly computed plan digest **matches**
   the approved one. Any mismatch → a signed refusal is reported and `apply` is
   never called.
4. On success the agent applies the saved plan bytes (not a re-plan), so the
   applied change is exactly what was approved (closes the plan-then-apply TOCTOU
   gap). Terraform errors if live state has since drifted.

Credentials never reach the control plane; the agent resolves them locally and
all command output is scrubbed before it becomes signed evidence.

### Operator flags

| Flag | Side | Effect |
| --- | --- | --- |
| `RYUKI_AGENT_ALLOW_LIVE` | Agent | `true`/`1` unlocks `LivePlan`/`LiveApply`; anything else = dry-run only. Cleartext non-loopback URLs are rejected at startup. |
| `RYUKI_AGENT_CP_URL` / `RYUKI_AGENT_TOKEN` / `RYUKI_AGENT_KEY_PATH` | Agent | CP endpoint (HTTPS for live), enrolment token, and the agent signing key. |
| `RYUKI_AGENT_BACKEND_HCL` | Agent | Durable Terraform state backend for production applies. |
| `RYUKI_CP_SIGNING_KEY_PATH` | Control plane | CP Ed25519 grant-signing key (created at `0600` on first boot). |

### Maturity

The dry-run pipeline, the full live trust gate (grant signing/verification,
plan-digest integrity, refusal reporting, no-double-apply), agent-side
`LiveApply` and `LiveDestroy` execution, the end-to-end credential seam, and a
Vault KV v2 resolver are all implemented and tested. Running a real apply
against live infrastructure is operator-owned: it requires a deployed agent
with `RYUKI_AGENT_ALLOW_LIVE=true`, real provider credentials via
`RYUKI_LIVE_CRED_<NAME>`, and a durable state backend. The vendor-API adapters
for a given provider are enabled per integration as you go live.
