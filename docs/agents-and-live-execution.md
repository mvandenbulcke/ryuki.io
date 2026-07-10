# Agents & Live Execution

Ryuki is dry-run-first: every domain plans, validates, and records evidence without touching live systems. The execution agent can run Terraform and Ansible previews, but the current mutation approval surface is deliberately limited to the reviewed Linux and Windows vSphere single-VM Terraform bundles. This guide covers enrolling an agent, dispatching work, and the signed approval chain that gates that live apply.

## How an agent joins the platform

1. Register the agent with the control plane. Either call `POST /api/agents/register` during provisioning, or opt into first-boot self-registration with `RYUKI_AGENT_SELF_REGISTER=true`. The response token has prefix `rya_`, is shown once, and must be stored securely. New agents start as `pending`.
2. An admin approves the agent: `POST /api/admin/agents/{agent_id}/approve`, assigning the platform and optionally narrowing capabilities. Revocation is terminal; a revoked agent cannot be re-approved.
3. Run the binary with the enrolment settings below. On first boot the agent generates an Ed25519 keypair and writes the seed to `RYUKI_AGENT_KEY_PATH` with mode `0600`; it refuses to overwrite an existing key file.

With self-registration enabled and no token in the environment or token file,
the binary registers its platform and public key, writes the returned token to
`RYUKI_AGENT_TOKEN_PATH` with mode `0600`, and exits successfully for the admin
approval handoff. Start it again after approval. A malformed existing token file
never triggers automatic re-registration.

| Variable | Required | Meaning |
| --- | --- | --- |
| `RYUKI_AGENT_CP_URL` | yes | Control-plane base URL. HTTPS is mandatory for live mode; cleartext is only accepted for loopback development. |
| `RYUKI_AGENT_PLATFORM` | yes | The canonical site/platform code this agent executes for. Non-empty ASCII letters, digits, dots, hyphens, and underscores are accepted, so registered custom codes such as `DC.EU-01` are valid. |
| `RYUKI_AGENT_TOKEN` | conditional | Agent bearer token from registration (`rya_...`). It takes precedence over the token file. |
| `RYUKI_AGENT_TOKEN_PATH` | no | Persisted token path. Defaults next to the agent key. |
| `RYUKI_AGENT_SELF_REGISTER` | no | `true`/`1` permits one first-boot registration only when neither token source exists. |
| `RYUKI_AGENT_KEY_PATH` | no | Ed25519 seed path (default `agent.key`). |
| `RYUKI_AGENT_ALLOW_LIVE` | no | Only the literal `true` or `1` unlocks live modes. Anything else, including typos, fails safe to dry-run-only. |
| `RYUKI_AGENT_BACKEND_HCL` | conditional | Operator-supplied Terraform backend template. Its active backend state-location attribute must contain `{STATE_KEY}` so each request or step uses isolated durable state; a placeholder in a comment or unrelated attribute is rejected. |
| `RYUKI_AGENT_POLL_INTERVAL_SECS` | no | Idle job-polling interval (default 10s). It does not control a running job's lease. |

The recognized state-location attributes are `path` (`local`, `consul`), `key`
(`s3`, `azurerm`, `oss`, `cos`), `prefix` (`gcs`, `etcdv3`), `schema_name`
(`pg`), `secret_suffix` (`kubernetes`), `address` (`http`), and `name` or
`prefix` inside a `remote` backend's `workspaces` block. Unknown backend types
fail closed because isolation cannot be proven.

A `local` backend must use an absolute `path`. Relative paths resolve inside
the fresh temporary workspace created for each plan, apply, and destroy phase,
so they are rejected before Terraform starts.

Lease deadlines are control-plane owned: the initial and non-live deadline is
300 seconds, while a successfully fenced running live job is renewed to 2,400
seconds. The agent renews its exact attempt fence every 60 seconds and before
mutation-sensitive boundaries. `RYUKI_AGENT_LEASE_SECS` remains accepted by the
current agent configuration for compatibility, but it does not change these
control-plane deadlines and must not be treated as a safety control.

Every successful renewal emits `fenced lease renewal succeeded` with the job
ID, attempt ID, lease generation, renewed deadline, and renewal phase. The
fencing token is deliberately omitted. Retain this structured, value-free log
as acceptance evidence that the exact running attempt renewed its lease.

A renewal failure fences the next agent boundary, but it cannot preempt a
Terraform subprocess that is already inside a provider call. Each Terraform
subprocess has a 600-second timeout, and the 2,400-second live lease prevents a
second agent attempt during that bounded uncertainty window. Treat any such
attempt as disposition-unknown and reconcile state plus provider inventory;
never approve a replacement apply on the same request.

The Terraform subprocess starts from a minimal environment: `PATH`, `HOME`,
`TMPDIR`, locale, and only the offering-declared provider variables. There is no
declared pass-through for AWS, Azure, GCP, or other backend credential
environment variables. A remote backend is therefore usable only when its
authentication works without additional process environment values, such as an
approved ambient workload/instance identity. Do not embed credentials in the
backend template. The normative first test uses the bundled local backend.

The Linux and Windows vSphere bundles pin `vmware/vsphere` exactly at `2.16.1`
and embed Terraform's generated dependency lock with checksums for Linux and
macOS on amd64 and arm64. Terraform offline dry-run, live plan/apply/destroy,
and proving-ground cleanup all initialize with `-lockfile=readonly`; changing
the provider requires an explicit source-and-lock update that changes the
approved IaC digest.

When live mode is enabled, the agent fetches the control plane's public key once (`GET /api/agents/cp-public-key`) and pins it for the process lifetime. If the pin fails, live plans still run; live applies are refused.

## Execution modes

| Mode | Dispatched by | What runs |
| --- | --- | --- |
| `OfflineDryRun` (default) | `execute` tier | Terraform `init`, `validate`, and a best-effort credential-free plan, or `ansible-playbook --check`, in an isolated workspace. Registry downloads may occur, but no provider credentials or mutation authority are supplied. |
| `LivePlan` | admin | Real `terraform init` → `plan` → `show -json` against the backend. Produces evidence and a plan digest. It does not apply provider resources; backend initialization, locking, and state metadata can still change. |
| `LiveApply` | never dispatched directly; minted by approval | Re-plans, requires the canonical plan digest to equal the approved digest, then applies that fresh matching binary plan. |
| `LiveDestroy` | system, during auto-teardown | Reverse-order Terraform teardown of applied steps, authorized by a step-scoped control-plane grant. Ansible destroy refuses because it has no Terraform state. |

## The live-apply trust chain

1. **Plan.** An admin dispatches `POST /api/requests/{id}/execute?mode=live-plan`. The agent plans against the real backend and posts scrubbed evidence plus a SHA-256 plan digest.
2. **Review.** The control plane stores the digest-covered plan bytes privately and derives an admin-only projection from the actual planned VM shape and the five planned vSphere placement lookups. Those values must exactly match the JobSpec; missing or mismatched `change.after` data fails closed. Raw Terraform JSON and provider object identifiers are not exposed.
3. **Approve.** An admin calls `POST /api/requests/{id}/approve-live-apply`. The control plane mints a grant signed with its Ed25519 key, binding the request id, the approved plan digest, the complete JobSpec digest (including mode, IaC digest, variables, and state key), the approver, and an expiry (whole-request approvals use a 1-hour TTL; grants are capped at 24 hours). The database allows one request-level live apply; step-scoped applies in orchestrated runs are bounded one per step.
4. **Verify authority.** Before provider execution, the agent requires protocol v2, re-computes the embedded IaC digest, verifies the grant and its exact JobSpec binding, checks request/step ownership and expiry, and runs a fresh plan whose digest must equal the approved one. Any failure produces a signed `LiveRefused` result and mutation is never called. The control plane independently repeats the signed grant, spec, state-owner, and approved-digest checks on result ingest.
5. **Apply and converge.** The LiveApply job creates a fresh binary plan, proves its canonical `terraform show -json` digest equals the reviewed digest, and applies that matching binary plan. It does not reuse a binary `tfplan` file from the earlier job. The runner then re-plans; a vSphere request cannot complete verification unless that post-apply plan is clean. Other Terraform offerings and Ansible check-mode runs remain preview-only until they have their own typed, server-derived review projection; neither approval endpoint will mint a grant for them.

Plan, apply, and destroy jobs for one state key are pinned to the same approved
agent. This is mandatory for an agent-local backend and remains enforced for a
remote backend so an operator cannot accidentally resolve the same logical key
through different backend templates. The binding survives plan lease expiry,
retry, and administrative requeue. If the owning agent is offline or revoked,
the job stays pending for operator recovery; it does not fail over to another
agent with a potentially different backend template.

Refusals and results are durable: the agent enqueues every result to a local outbox before posting, so a network failure cannot lose a refusal.

## Where to see results

| What | Where |
| --- | --- |
| Job state, including `live_refused` | `GET /api/admin/agents/jobs/{job_id}/state` (admin) |
| Signed result metadata and safe LivePlan review | `GET /api/admin/agents/jobs/{job_id}/result` (admin) |
| Request audit trail / evidence | `GET /api/requests/{id}/audit` and `/evidence` (audit tier) |

## Credentials never reach the control plane

Provider credentials live on the agent host, never on the control plane. Each offering declares the secret variables it needs; the vSphere server-deployment offerings declare `VSPHERE_USER`, `VSPHERE_PASSWORD`, and `VSPHERE_SERVER`. For each declared name `<NAME>`, set `RYUKI_LIVE_CRED_<NAME>` on the agent. Before any live Terraform run, the agent resolves the declared set and refuses fail-closed if one is missing or empty, reporting a signed refusal that names the variable but never its value.

For a live run, the agent injects only the declared names — plus their `TF_VAR_<lowercase>` aliases, since the bundles route credentials through `var.vsphere_*` — into the Terraform subprocess, on top of a minimal allowlist (`PATH`, `HOME`, `TMPDIR`, locale). Dry-runs receive no credentials at all, enforced at both the agent and the runner API boundary. All command output is scrubbed before it becomes signed evidence.

Control-plane side, integration connections can resolve credential handles through Vault (`VAULT_ADDR` / `VAULT_TOKEN`; handles are `<mount>/<path>[#<field>]`) or a mock resolver by default — see [Configuration](configuration.md). The grant-signing key lives at `RYUKI_CP_SIGNING_KEY_PATH` (default `cp-signing.key`), created `0600` on first boot.

## Auto-teardown on failed multi-step runs

If a step fails mid-way through a multi-step live request, the control plane force-fails any steps still awaiting approval, then tears down applied steps in reverse dependency order. Each teardown is its own step-scoped `LiveDestroy` grant (approver `system:auto-teardown`); a grant minted for a whole-request apply can never authorize a destroy. If a destroy itself fails, the cascade halts rather than thrashing, and the surviving steps are left for operator reconciliation.

## Running a live apply against real infrastructure

The execution core is covered by repository and CI tests. Provider-connected
vSphere acceptance is still pending the gates in
[First Test Acceptance](first-test.md), including cleanup against an approved
disposable target. To take one offering live against a real vSphere backend:

1. **Enrol an agent** where it can reach vCenter (see the enrolment steps above), and give it a durable Terraform backend template via `RYUKI_AGENT_BACKEND_HCL`. Its active state-location attribute must contain `{STATE_KEY}`; the control plane supplies a stable `request-<id>` or `step-<id>` key shared by plan, apply, and destroy for that one unit of work.
2. **Provide credentials** on the agent host: `RYUKI_LIVE_CRED_VSPHERE_USER`, `RYUKI_LIVE_CRED_VSPHERE_PASSWORD`, `RYUKI_LIVE_CRED_VSPHERE_SERVER`. A missing one produces a signed refusal before Terraform runs.
3. **Unlock live mode** with `RYUKI_AGENT_ALLOW_LIVE=true` and confirm the agent pinned the control-plane public key at startup.
4. **Supply placement**: the request must carry the real vSphere datacenter, cluster, datastore, network, template, and disk size. Missing live-placement inputs are rejected before dispatch; sample defaults are not substituted.
5. **Drive the governed flow**: dispatch a `LivePlan`, wait while the request remains `executing`, review the digest-verified projection, approve it, and let the same backend-owning agent build and apply a fresh digest-matching plan. Only a converged apply satisfies the request-verification prerequisite.
6. **Clean up**: successful single-job requests do not currently expose an operator-triggered `LiveDestroy`. Rehearse and approve the state-keyed cleanup procedure before live apply, then verify both the provider and Terraform state are empty.

Start with one low-stakes offering and one cluster; the dry-run pipeline lets you rehearse the whole lifecycle first with zero infrastructure risk.
The normative checklist is [First Test Acceptance](first-test.md); the runnable
local stack is in `deploy/proving-ground`.

## What is implemented, and what stays yours

Implemented and tested: the dry-run pipeline; protocol-v2-only negotiation; the
live trust gate (exact-spec grant binding, IaC and plan digest integrity,
state-owner validation, agent affinity, refusal reporting, no-double-apply);
the safe plan-review projection; agent-side `LiveApply` and `LiveDestroy`
execution; the credential seam end to end; and a real Vault KV v2 resolver on
the control plane.

Operator-owned: real provider credentials, a durable state backend, placement
identifiers, approval of the first target, and cleanup of a successful
single-job apply. Automatic `LiveDestroy` exists only as compensation for a
failed multi-step run; it is not a general operator destroy endpoint.
