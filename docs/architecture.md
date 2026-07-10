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
| `OfflineDryRun` (default) | `execute` tier | Terraform `init`, `validate`, and a best-effort credential-free plan, or `ansible-playbook --check`, in an isolated workspace. Registry downloads may occur; no provider credentials or mutation authority are supplied. |
| `LivePlan` | `admin` tier | Real `terraform init` → `plan` → `show -json` against the backend. Produces a plan + a `plan_digest` without applying provider resources; backend initialization, locking, and state metadata can still change. |
| `LiveApply` | minted by an `admin` via `approve-live-apply`, never dispatched directly | Creates a fresh plan, requires its canonical digest to match the reviewed plan, then applies that matching binary plan. |
| `LiveDestroy` | system compensation after a failed multi-step live run | `terraform destroy` against the exact step state, authorized by a step-scoped signed grant. |

The vSphere bundles pin `vmware/vsphere` at `2.16.1` and carry generated
multi-platform checksum locks. Every Terraform execution mode initializes with
`-lockfile=readonly`, so dependency selection is part of the digest-bound IaC
rather than mutable job-local state.

### Live-apply trust chain

1. An operator dispatches a `LivePlan` (admin-only). The agent runs the plan and
   returns scrubbed evidence plus the plan digest.
2. The control plane derives a digest-verified, allowlisted Plan Review from the
   stored plan bytes. It exposes managed actions and request placement, never
   raw Terraform JSON or provider object identifiers. Server apply approval is
   refused if this projection cannot be derived.
3. An `admin` approves via `POST /api/requests/{id}/approve-live-apply`. The
   control plane mints a `LiveApply` grant **signed with its Ed25519 key**,
   binding the request id, approved plan digest, full JobSpec digest (including
   mode and state key), approver, and a short expiry (<= 24 h). A unique constraint prevents a second request-level
   live apply; in orchestrated multi-step runs each step gets exactly one
   step-scoped `LiveApply`, gated by the step's `FOR UPDATE` approval lock
   (migration 153).
4. The protocol-v2 agent only acts if `RYUKI_AGENT_ALLOW_LIVE=true` and it has
   pinned the control-plane public key. It verifies the embedded IaC digest and
   refuses unless **all** hold: the grant signature verifies; its full JobSpec
   digest matches this exact job; request, step, mode, and state ownership match;
   it has not expired; and the freshly computed plan digest **matches** the
   approved one. Any mismatch produces a signed refusal and mutation is never
   called. Plan, apply, and destroy for a state key are pinned to the same agent.
5. On success the LiveApply job applies the fresh binary plan whose canonical
   JSON digest matched the reviewed plan. Binary `tfplan` bytes are not carried
   between jobs; digest equality is the approval invariant that closes the
   plan-then-apply TOCTOU gap. A post-apply plan must confirm convergence before
   the vSphere request can be verified as completed.

Credentials never reach the control plane; the agent resolves them locally and
all command output is scrubbed before it becomes signed evidence.

### Operator flags

| Flag | Side | Effect |
| --- | --- | --- |
| `RYUKI_AGENT_ALLOW_LIVE` | Agent | `true`/`1` unlocks `LivePlan`/`LiveApply`/`LiveDestroy`; anything else = dry-run only. Cleartext non-loopback URLs are rejected at startup. |
| `RYUKI_AGENT_CP_URL` / `RYUKI_AGENT_TOKEN` / `RYUKI_AGENT_KEY_PATH` | Agent | CP endpoint (HTTPS for live), enrolment token, and the agent signing key. |
| `RYUKI_AGENT_BACKEND_HCL` | Agent | Durable Terraform backend template. The active path/key attribute must contain `{STATE_KEY}` for per-request/per-step isolation; comments and unrelated attributes do not satisfy the gate. Remote authentication must work within the agent's minimal environment because arbitrary backend credential variables are not passed through. |
| `RYUKI_CP_SIGNING_KEY_PATH` | Control plane | CP Ed25519 grant-signing key (created at `0600` on first boot). |

### Maturity

The dry-run pipeline, the full live trust gate (grant signing/verification,
plan-digest integrity, refusal reporting, no-double-apply), agent-side
`LiveApply` and `LiveDestroy` execution, the provider credential-injection path,
and a Vault KV v2 resolver are covered by repository and CI tests. A
provider-connected vSphere run is not accepted until the operator-owned gates
in [First Test Acceptance](first-test.md) pass against an approved disposable
target. It requires a deployed agent with `RYUKI_AGENT_ALLOW_LIVE=true`, real
provider credentials via `RYUKI_LIVE_CRED_<NAME>`, and a durable isolated state
backend. The vendor-API adapters for a given provider are enabled per
integration as you go live.

Automatic `LiveDestroy` is compensation for a failed multi-step run. There is
not yet an operator-triggered destroy endpoint for a successful single-job
request, so the first live test must approve and rehearse a state-keyed cleanup
procedure before apply. See [First Test Acceptance](first-test.md).
