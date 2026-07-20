# Architecture

## Stack

| Layer      | Technology               |
|------------|--------------------------|
| Portal     | Rust / Leptos (WASM)     |
| API        | Rust / Axum              |
| Engine     | Rust                     |
| Core       | Rust                     |
| Database   | PostgreSQL / sqlx        |
| Secrets    | Provider-neutral resolver capability with current Vault adapter; target versioned provider registry |
| Auth       | Current Entra implementation; target versioned multi-provider registry |

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

- **Same-origin**: Portal and API are normally served from one validated origin. CORS is not a CSRF control: every unsafe browser operation also requires exact origin validation and a session-bound CSRF proof at the shared portal/API admission boundary.
- **Dry-run default**: Provider operations default to mock/dry-run (`provider_calls_enabled = false`). Live infrastructure execution is a separate, operator-gated path — see [Execution Model](#execution-model). `RYUKI_AUTH_MODE` is a transitional switch; static identity is accepted only by an explicit loopback/isolated development profile and never as a production fallback.
- **Pluggable secret managers**: Domain code stores typed secret references, not provider-specific credentials. The current live-shaped resolver is HashiCorp Vault and is not the final production contract. The target registry admits Vault, OpenBao, cloud-native managers, and enterprise adapters by narrow, independently tested resolution, issuance, lease, key, certificate, publication, and materialization capabilities. CSI/ESO/VSO delivery is a custody boundary, not a generic `SecretStore` equivalent.
- **Provider-neutral identity and authority**: Authentication carriers are namespaced by `(provider, issuer, subject)` and cannot grant platform authority directly. Interactive local, OIDC, and Entra identities are intersected with a versioned server-owned role/site/environment assignment; Unknown and Revoked fail closed, and Global is explicit rather than inferred from an empty list. The same contract is ready for brokered SAML/LDAP and passkeys, while production acceptance remains blocked on the shared registry, lifecycle, and live-provider evidence gates.

## Platform security boundary

Authentication protocols remain pluggable, but they feed one platform-wide
principal, policy, transition, and audit boundary. The production target covers
browser sessions, OIDC, local emergency access, API tokens, agents, webhooks,
system workers, approvals, provider credentials, and evidence. See the
[Platform Security Boundary Specification](architecture/platform-security-boundary.md)
for its normative invariants, migration work packages, acceptance tests, and
the split between repository work and operator-owned Entra/Vault/PKI changes.

The boundary specification is the required target state. Development modes and
the current implementation may not yet conform, and must not be presented as
production-ready merely because their individual authentication or signature
checks pass.

## Network Policy

```
Browser ──► Portal (same-origin) ──► API ──► Database
                                        └───► control-plane secret/key services

API ──► Agent control channel ──► Agent ──► workload secret/key service
                                      └───► infrastructure provider endpoint
```

The Portal communicates exclusively with the API, and only the API accesses the
control-plane database. The intended live execution plane is agent-local: once
sealed per-command descendant containment exists, the agent will resolve
workload credentials and call provider endpoints under a signed, scoped grant.
The current production runner refuses every external Terraform and Ansible
spawn before that point. Network policy must still isolate control-plane egress
from future agent workload egress; neither plane receives ambient access to the
other's secret services or provider destinations.

## Execution Model

Ryuki is **dry-run-first**. Almost every operation plans, validates, and records
evidence without touching live infrastructure: the provider catalogue entries are
credential/endpoint registries whose connection test is a shape-check stub (no
live vendor call), and most domains report `provider_calls_enabled = false`.

There is exactly **one** governed live-execution protocol path, and it is
operator-gated end to end. Production external execution is not enabled in this
snapshot: no mode may spawn Terraform or Ansible until the runner can attach
every descendant before execution, terminate the whole set, and wait until the
set is empty.

### Modes

| Mode | Who can dispatch | Protocol / acceptance behavior (external spawn currently unavailable) |
| --- | --- | --- |
| `OfflineDryRun` (default) | `execute` tier | Models Terraform `init`, `validate`, and a best-effort credential-free plan, or `ansible-playbook --check`, without provider authority. Pure/stub tests exercise it; production refuses before either CLI starts. |
| `LivePlan` | `admin` tier | Real `terraform init` → `plan` → `show -json` against the backend. Produces a plan + a `plan_digest` without applying provider resources; backend initialization, locking, and state metadata can still change. |
| `LiveApply` | minted by an `admin` via `approve-live-apply`, never dispatched directly | Creates a fresh plan, requires its canonical digest to match the reviewed plan, then applies that matching binary plan. |
| `LiveDestroy` | system compensation after a failed multi-step live run | `terraform destroy` against the exact step state, authorized by a step-scoped signed grant. |

The vSphere bundles pin `vmware/vsphere` at `2.16.1` and carry generated
multi-platform checksum locks. The runner is designed to initialize every
Terraform mode with `-lockfile=readonly`, so dependency selection remains part
of the digest-bound IaC once external execution is admitted.

### Live-apply trust chain

1. An operator dispatches a `LivePlan` (admin-only). In protocol and pure/stub
   acceptance tests, the agent returns scrubbed evidence with its own
   `evidence_digest` plus a distinct, signed `raw_plan_digest` computed from
   the complete canonical Terraform plan before redaction; production
   currently refuses before Terraform starts.
2. The control plane derives a digest-verified, allowlisted Plan Review from the
   stored plan bytes. It exposes managed actions and request placement, never
   raw Terraform JSON or provider object identifiers. Server apply approval is
   refused if this projection cannot be derived.
3. An `admin` approves via `POST /api/requests/{id}/approve-live-apply`, sending
   the exact reviewed plan job UUID, attempt UUID, and lowercase raw-plan
   digest. The
   control plane locks and re-verifies that exact signed result before minting
   a `LiveApply` grant **signed with its Ed25519 key**. The grant binds the
   request and platform, exact plan row/attempt, approved plan and complete
   JobSpec digests, planning-agent enrollment/key/profile authority, approver,
   and a short expiry (<= 24 h). A later same-digest row cannot replace the
   reviewed row, and a unique constraint prevents a second request-level apply.
   Human per-step approval is disabled: its portal control is absent and the
   route returns `409 Conflict` without minting.
4. The protocol-v7 agent only acts if `RYUKI_AGENT_ALLOW_LIVE=true`, it has
   pinned the control-plane public key, and external containment is available.
   It verifies the embedded IaC digest and refuses unless **all** hold: the
   grant signature verifies; its full JobSpec digest and exact plan row/attempt
   match; request, exact request resource version, platform, step, mode, state
   owner, planning-agent enrollment/key/profile, and expiry match; and the
   freshly computed raw-plan digest matches the approved one. Protocol v1
   through v6 is rejected. Plan, apply, and
   destroy for a state key remain pinned to the same agent.
5. Once containment is implemented, the LiveApply path will apply only the
   fresh binary plan whose canonical raw JSON digest matched the reviewed plan.
   Binary `tfplan` bytes are not carried between jobs; digest equality is the
   approval invariant that closes the plan-then-apply TOCTOU gap. A post-apply
   plan must confirm convergence before the vSphere request can be verified as
   completed.

Credentials never reach the control plane; the current agent environment seam
resolves them locally and scrubs output before signing. Its free-form credential
values and provider authority id/version are separate, non-atomic environment
reads, however. A typed secret-manager connector and deployment readback must
prove their exact version binding before provider-connected activation.

### Operator flags

| Flag | Side | Effect |
| --- | --- | --- |
| `RYUKI_AGENT_ALLOW_LIVE` | Agent | `true`/`1` passes the live-mode configuration gate; it does not bypass the missing descendant-containment capability, so external spawn still fails closed. Anything else is dry-run-only. Cleartext non-loopback URLs are rejected at startup. |
| `RYUKI_AGENT_CP_URL` / `RYUKI_AGENT_TOKEN` / `RYUKI_AGENT_KEY_PATH` | Agent | CP endpoint (HTTPS for live), enrolment token, and the agent signing key. |
| `RYUKI_AGENT_BACKEND_HCL` | Agent | Terraform backend template. The active path/key attribute must contain `{STATE_KEY}` for per-request/per-step isolation; comments and unrelated attributes do not satisfy the gate. Remote-execution backend type `remote` is rejected. A privacy-safe semantic authority digest is bound from plan through mutation. |
| `RYUKI_LIVE_PROVIDER_AUTHORITY_ID` / `RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION` | Agent | Non-secret opaque provisioning-record reference and immutable version for the exact vSphere destination/account credential set. Missing/malformed metadata fails live profile minting; changing the set requires version rotation and reapproval. |
| `RYUKI_CP_SIGNING_KEY_PATH` | Control plane | CP Ed25519 grant-signing key path. First-boot local creation is disposable development behavior only; production requires externally governed key custody, rotation, and recovery evidence. |

### Maturity

The no-provider-authority/no-spawn dry-run protocol path, the live trust gate
(exact plan-row/spec/authority grant signing and verification, digest integrity,
refusal reporting, and no-double-apply), credential-resolution comparisons, and
a Vault KV v2 control-plane resolver are covered by repository tests. These are
protocol and pure/stub acceptance paths, not production external execution.
Terraform and Ansible `OfflineDryRun`, `LivePlan`, `LiveApply`, and
`LiveDestroy` all remain unavailable until a sealed per-command descendant-
containment adapter exists. Provider-connected activation additionally requires
the operator-owned gates in [First Test Acceptance](first-test.md), a typed
versioned credential/authority connector with deployment readback, a durable
isolated state backend, and an approved disposable target.

Automatic `LiveDestroy` is compensation for a failed multi-step run. There is
not yet an operator-triggered destroy endpoint for a successful single-job
request, so the first live test must approve and rehearse a state-keyed cleanup
procedure before apply. See [First Test Acceptance](first-test.md).
