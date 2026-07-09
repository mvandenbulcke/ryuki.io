# Agents & Live Execution

Ryuki is dry-run-first: every domain plans, validates, and records evidence without touching live systems. The single path to real infrastructure runs Terraform and Ansible through a `ryuki-agent` you deploy next to the infrastructure it manages. This guide covers enrolling an agent, dispatching work, and the signed approval chain that gates a live apply.

## How an agent joins the platform

1. Register the agent with the control plane: `POST /api/agents/register` with `agent_id`, `platform`, `capabilities`, and the agent's Ed25519 `public_key`. The response contains the agent bearer token (prefix `rya_`) exactly once; store it securely. New agents start as `pending`.
2. An admin approves the agent: `POST /api/admin/agents/{agent_id}/approve`, assigning the platform and optionally narrowing capabilities. Revocation is terminal; a revoked agent cannot be re-approved.
3. Run the binary with the enrolment settings below. On first boot the agent generates an Ed25519 keypair and writes the seed to `RYUKI_AGENT_KEY_PATH` with mode `0600`; it refuses to overwrite an existing key file.

The agent binary does not self-register yet: registration is an API call you make during provisioning, then the token is supplied to the process.

| Variable | Required | Meaning |
| --- | --- | --- |
| `RYUKI_AGENT_CP_URL` | yes | Control-plane base URL. HTTPS is mandatory for live mode; cleartext is only accepted for loopback development. |
| `RYUKI_AGENT_PLATFORM` | yes | The platform this agent executes for. |
| `RYUKI_AGENT_TOKEN` | yes | Agent bearer token from registration (`rya_...`). |
| `RYUKI_AGENT_KEY_PATH` | no | Ed25519 seed path (default `agent.key`). |
| `RYUKI_AGENT_ALLOW_LIVE` | no | Only the literal `true` or `1` unlocks live modes. Anything else, including typos, fails safe to dry-run-only. |
| `RYUKI_AGENT_BACKEND_HCL` | no | Operator-supplied Terraform state backend HCL, written into the workspace before `init`. Optional, but production operators should supply a durable backend; otherwise Terraform uses the bundle's default. |
| `RYUKI_AGENT_POLL_INTERVAL_SECS` / `RYUKI_AGENT_LEASE_SECS` | no | Job polling (10s) and lease (300s) tuning. |

When live mode is enabled, the agent fetches the control plane's public key once (`GET /api/agents/cp-public-key`) and pins it for the process lifetime. If the pin fails, live plans still run; live applies are refused.

## Execution modes

| Mode | Dispatched by | What runs |
| --- | --- | --- |
| `OfflineDryRun` (default) | `execute` tier | `terraform validate` / `ansible-playbook --check` in an isolated workspace. No credentials, no network mutation. |
| `LivePlan` | admin | Real `terraform init` → `plan` → `show -json` against the backend. Produces evidence and a plan digest. Nothing mutates. |
| `LiveApply` | never dispatched directly; minted by approval | `terraform apply` of the exact approved plan bytes. |
| `LiveDestroy` | system, during auto-teardown | Reverse-order teardown of applied steps. The trust gate is live; agent-side destroy execution is a pending slice and currently reports a clean refusal. |

## The live-apply trust chain

1. **Plan.** An admin dispatches `POST /api/requests/{id}/execute?mode=live-plan`. The agent plans against the real backend and posts scrubbed evidence plus a SHA-256 plan digest.
2. **Approve.** An admin calls `POST /api/requests/{id}/approve-live-apply`. The control plane mints a grant signed with its Ed25519 key, binding the request id, the approved plan digest, the approver, and an expiry (whole-request approvals use a 1-hour TTL; grants are capped at 24 hours). The database allows one request-level live apply; step-scoped applies in orchestrated runs are bounded one per step.
3. **Verify.** The agent re-checks everything before acting, in order: live mode enabled, grant present, signature valid against the pinned key, request id match, step binding, expiry, and a fresh re-plan whose digest must equal the approved one. Any failure produces a signed `LiveRefused` result and `apply` is never called. When the result comes back, the control plane independently verifies the grant signature, the request and step binding, expiry, and that the reported digest equals the approved one.
4. **Apply.** On success, Terraform applies the saved plan bytes from the approved plan, never a re-plan, so what changes is exactly what was approved, and Terraform itself errors if live state drifted. Ansible live applies re-run the approved playbook and variables after the check-mode digest gate.

Refusals and results are durable: the agent enqueues every result to a local outbox before posting, so a network failure cannot lose a refusal.

## Where to see results

| What | Where |
| --- | --- |
| Job state, including `live_refused` | `GET /api/admin/agents/jobs/{job_id}/state` (admin) |
| Full job result | `GET /api/admin/agents/jobs/{job_id}/result` (admin) |
| Request audit trail / evidence | `GET /api/requests/{id}/audit` and `/evidence` (audit tier) |

## Credentials never reach the control plane

Provider credentials live on the agent host, never on the control plane. Each offering declares the secret variables it needs; the vSphere server-deployment offerings declare `VSPHERE_USER`, `VSPHERE_PASSWORD`, and `VSPHERE_SERVER`. For each declared name `<NAME>`, set `RYUKI_LIVE_CRED_<NAME>` on the agent. Before any Terraform runs, the agent resolves the declared set and refuses fail-closed if one is missing or empty, reporting a signed refusal that names the variable but never its value.

For a live run, the agent injects only the declared names — plus their `TF_VAR_<lowercase>` aliases, since the bundles route credentials through `var.vsphere_*` — into the Terraform subprocess, on top of a minimal allowlist (`PATH`, `HOME`, `TMPDIR`, locale). Dry-runs receive no credentials at all, enforced at both the agent and the runner API boundary. All command output is scrubbed before it becomes signed evidence.

Control-plane side, integration connections can resolve credential handles through Vault (`VAULT_ADDR` / `VAULT_TOKEN`; handles are `<mount>/<path>[#<field>]`) or a mock resolver by default — see [Configuration](configuration.md). The grant-signing key lives at `RYUKI_CP_SIGNING_KEY_PATH` (default `cp-signing.key`), created `0600` on first boot.

## Auto-teardown on failed multi-step runs

If a step fails mid-way through a multi-step live request, the control plane force-fails any steps still awaiting approval, then tears down applied steps in reverse dependency order. Each teardown is its own step-scoped `LiveDestroy` grant (approver `system:auto-teardown`); a grant minted for a whole-request apply can never authorize a destroy. If a destroy itself fails, the cascade halts rather than thrashing, and the surviving steps are left for operator reconciliation.

## Running a live apply against real infrastructure

The full path is implemented and tested; the remaining work is operator configuration and the decision to point it at production. To take one offering live against a real vSphere backend:

1. **Enrol an agent** where it can reach vCenter (see the enrolment steps above), and give it a durable Terraform state backend HCL via `RYUKI_AGENT_BACKEND_HCL` — without one, an apply's state does not persist and a later teardown finds nothing to destroy.
2. **Provide credentials** on the agent host: `RYUKI_LIVE_CRED_VSPHERE_USER`, `RYUKI_LIVE_CRED_VSPHERE_PASSWORD`, `RYUKI_LIVE_CRED_VSPHERE_SERVER`. A missing one produces a signed refusal before Terraform runs.
3. **Unlock live mode** with `RYUKI_AGENT_ALLOW_LIVE=true` and confirm the agent pinned the control-plane public key at startup.
4. **Drive the governed flow**: dispatch a `LivePlan`, review the plan evidence, approve it, and let the agent apply the saved plan bytes. The trust gate verifies the signed grant and the re-planned digest before it touches anything.

Start with one low-stakes offering and one cluster; the dry-run pipeline lets you rehearse the whole lifecycle first with zero infrastructure risk.

## What is implemented, and what stays yours

Implemented and tested: the dry-run pipeline; the full live trust gate (grant signing and verification, plan-digest integrity, refusal reporting, no-double-apply); agent-side `LiveApply` and `LiveDestroy` execution; the credential seam end to end; and a real Vault KV v2 resolver on the control plane.

Operator-owned: real provider credentials, a durable state backend, pointing an agent at production, and the vendor-API adapters for providers whose live integration you enable. The trust machinery does not change when you go live — only the target does.
