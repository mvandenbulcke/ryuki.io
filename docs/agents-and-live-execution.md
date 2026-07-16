# Agents & Live Execution

Ryuki is dry-run-first: every domain plans, validates, and records evidence without touching live systems. The agent protocol defines Terraform and Ansible preview behavior, but the production runner currently refuses every external CLI spawn until sealed per-command descendant containment exists. The mutation approval surface is deliberately limited to the reviewed Linux and Windows vSphere single-VM Terraform bundles as protocol and acceptance-test groundwork. This guide covers enrolling an agent, dispatching work, and the signed approval chain that gates a future live apply.

This page describes the current agent protocol. Its production migration target
is the shared
[Platform Security Boundary Specification](architecture/platform-security-boundary.md):
rotatable workload identity, versioned signing trust, replay resistance, and
capability-based secret-manager adapters. The current enrollment boundary now
implements invite/key binding and proof of possession; the returned bearer is
still a transitional runtime credential rather than the final workload-
identity boundary.

## How an agent joins the platform

1. Generate or preprovision the agent's Ed25519 identity on the intended host. The seed at `RYUKI_AGENT_KEY_PATH` is the durable workload identity, must be mode `0600`, and is never delivered to the control plane. `ryuki-agent --enrollment-public-key` loads or creates that same key and prints only its canonical public half for the trusted provisioning workflow; this narrow mode reads no token, challenge, control-plane URL, or provider credential.
2. An unrestricted admin calls `POST /api/admin/agents/enrollment-challenges` with the intended `agent_id`, `platform`, canonical public key, and optional lifetime (60 seconds to 24 hours; default 15 minutes). The response contains a challenge UUID and `ryc_...` one-time secret. Only its SHA-256 hash is stored. Deliver both values to the intended host through the deployment's existing secret manager or equivalent trusted bootstrap channel; never put them in source control, tickets, logs, or screenshots.
3. Start the agent with `RYUKI_AGENT_SELF_REGISTER=true` and the two challenge variables below. It signs a domain-separated claim binding the challenge, agent id, platform, and exact public key with the existing Ed25519 private key. `POST /api/agents/register` locks and atomically consumes the matching grant before inserting the `pending` identity and returning the one-time `rya_...` bearer. A replay, concurrent second claimant, expired grant, or different id/platform/key/proof is rejected without allocating an identity.
4. An admin reads the current roster from `GET /api/admin/agents`, verifies `cryptographically_admitted: true` and the non-secret `public_key_fingerprint`, then approves that exact snapshot with `POST /api/admin/agents/{agent_id}/approve`. The request must include the immutable `enrollment_id`, fingerprint, and the same preprovisioned `platform`. A stale or unlinked Pending row cannot be approved. Capabilities may be narrowed explicitly. Revocation through `POST /api/admin/agents/{agent_id}/revoke` carries the same enrollment id and fingerprint.

With self-registration enabled and no token in the environment or token file,
the binary requires a complete canonical challenge pair, signs it with the
existing key, writes the returned token to `RYUKI_AGENT_TOKEN_PATH` with mode
`0600`, and exits successfully for the admin approval handoff. Start it again
after approval. A malformed existing token file never triggers automatic
re-registration. The challenge is already consumed and may be removed from the
runtime secret injection after the first successful boot.

### Enrollment-contract upgrade

The enrollment-binding release is an explicit non-overlap API cutover, not an
ordinary rolling update. Drain old API replicas (or remove registration and
agent-admin routes from them) before applying migration 158, then start only
replicas that set enrollment contract v3 before restoring traffic. The migration
installs a fail-closed database bridge that rejects old Pending inserts and
all other non-challenge-bound agent inserts, plus agent-id-only
approval/revocation updates, including after a rollback. That
bridge protects durable state, but an old public registration handler still
parses and decodes the request before PostgreSQL rejects it; draining old
replicas is therefore required to close the resource-admission path as well as
the state-mutation path. Migration 158 removes pre-cutover Pending allocations
because their provenance cannot be established and retaining their unique ids
would preserve the squatting denial. The database marker remains enrollment
contract v3, while the release-wide wire protocol is v6 because signed live
grants also bind destination platform, the exact successful plan job and
attempt, the exact planning-agent enrollment and key, and the reviewed
execution trust profile; signed results bind the immutable enrollment UUID.
Deploy only matching protocol-v6
API, agent, and portal components after the v3 enrollment migration is ready.

Pre-cutover Approved and Revoked rows remain operable so the cutover does not
silently revoke running workloads, but the migration cannot establish who
controlled their keys at original enrollment. The admin roster marks those rows
`cryptographically_admitted: false`. Inventory them during the cutover and
revoke and re-enroll every Approved legacy row through a fresh challenge before
treating the enrollment finding as closed. This is an explicit migration
ceremony, not proof that a legacy identity was benign. Revocation is terminal
and the current API does not delete or reuse that human-readable id, so a
same-id replacement requires a separately reviewed retirement/data-migration
procedure; never assume that revocation alone frees the id for registration.

The portal refuses to render a roster that the API reports as capped. As a
separate cutover gate, run the following non-secret inventory directly against
the migrated database and require zero rows before closure; it checks the same
complete linkage as `cryptographically_admitted` rather than trusting a
nullable challenge id alone:

```sql
SELECT
    agent.id AS enrollment_id,
    agent.agent_id,
    agent.platform,
    agent.created_at
FROM agents AS agent
WHERE agent.status = 'approved'
  AND NOT EXISTS (
      SELECT 1
      FROM agent_enrollment_challenges AS challenge
      WHERE challenge.id = agent.enrollment_challenge_id
        AND challenge.status = 'consumed'
        AND challenge.consumed_enrollment_id = agent.id
        AND challenge.agent_id = agent.agent_id
        AND challenge.platform = agent.platform
        AND challenge.public_key = agent.public_key
  )
ORDER BY agent.created_at, agent.id;
```

| Variable | Required | Meaning |
| --- | --- | --- |
| `RYUKI_AGENT_CP_URL` | yes | Control-plane base URL. HTTPS is mandatory in every mode; cleartext is accepted only for the explicit loopback development exception. |
| `RYUKI_AGENT_PLATFORM` | yes | The canonical site/platform code this agent executes for. Non-empty ASCII letters, digits, dots, hyphens, and underscores are accepted, so registered custom codes such as `DC.EU-01` are valid. |
| `RYUKI_AGENT_TOKEN` | conditional | Agent bearer token from registration (`rya_...`). It takes precedence over the token file. |
| `RYUKI_AGENT_TOKEN_PATH` | no | Persisted token path. Defaults next to the agent key. |
| `RYUKI_AGENT_SELF_REGISTER` | no | `true`/`1` permits one first-boot registration only when neither token source exists and a complete trusted challenge pair is configured. |
| `RYUKI_AGENT_ENROLLMENT_CHALLENGE_ID` | with self-registration | UUID returned once by the trusted admin provisioning endpoint. |
| `RYUKI_AGENT_ENROLLMENT_CHALLENGE` | with self-registration | One-time `ryc_` bootstrap secret delivered through an existing provider-neutral secret channel. Debug output redacts it; remove it after successful consumption. |
| `RYUKI_AGENT_KEY_PATH` | no | Ed25519 seed path (default `agent.key`). |
| `RYUKI_AGENT_ALLOW_LIVE` | no | Only the literal `true` or `1` unlocks live modes. Anything else, including typos, fails safe to dry-run-only. |
| `RYUKI_AGENT_BACKEND_HCL` | conditional | Operator-supplied Terraform backend template. Its active backend state-location attribute must contain `{STATE_KEY}` so each request or step uses isolated durable state; a placeholder in a comment or unrelated attribute is rejected. |
| `RYUKI_LIVE_PROVIDER_AUTHORITY_ID` | live vSphere jobs | Stable non-secret opaque provisioning reference in canonical `provider-authority/vsphere/...` form. It must not contain a hostname, account name, tenant id, credential, or provider-returned value. |
| `RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION` | live vSphere jobs | Canonical `v...` immutable version of the referenced destination/account credential set. Rotate it whenever `VSPHERE_SERVER`, `VSPHERE_USER`, or any credential member changes. |
| `RYUKI_TERRAFORM_EXECUTABLE` | runner jobs | Absolute, already-canonical Terraform regular-file path. Bare names, relative paths, symlinks, unsafe ownership/modes, and writable parent chains are rejected. |
| `RYUKI_TERRAFORM_EXPECTED_VERSION` | Terraform jobs | Exact version token from the first line of `terraform version` (without the leading `v`). |
| `RYUKI_TERRAFORM_EXECUTABLE_SHA256` | no | Optional reviewed SHA-256 for the Terraform executable; when set, a mismatch fails closed. |
| `RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE` | runner jobs | Absolute, already-canonical `ansible-playbook` regular-file path under the same provenance rules. |
| `RYUKI_ANSIBLE_PLAYBOOK_EXPECTED_VERSION` | Ansible jobs | Exact Ansible core version token from the first line of `ansible-playbook --version`. |
| `RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256` | no | Optional reviewed SHA-256 for the Ansible executable; when set, a mismatch fails closed. |
| `RYUKI_AGENT_POLL_INTERVAL_SECS` | no | Idle job-polling interval (default 10s). It does not control a running job's lease. |

Version identity is a local fail-closed admission check, not a publisher
attestation. Deployed service/image definitions should also pin reviewed
package or image provenance and set the executable SHA-256 values. The
repository cannot prove a rendered service manager's package source or PATH;
retain those facts as deployment conformance evidence.

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

A renewal failure propagates cancellation into the active supervised runner
phase. The runner requests termination of the contained descendant set and
does not recycle its execution slot until the child is reaped. Each Terraform
subprocess also has a 600-second ceiling, while the 2,400-second live lease
prevents a second agent attempt during bounded cleanup. Only when termination
and an empty descendant set cannot be confirmed must the attempt be treated as
disposition-unknown: reconcile state plus provider inventory and never approve
a replacement apply on the same request.

Control-plane request planning uses a separate four-slot, process-local
Terraform-enrichment admission bound. The blocking worker owns its permit and
one drop-triggered cancellation signal shared by the executable probe and all
Terraform phases. When the HTTP deadline drops the handler (or another owner
drops it), the runner terminates its active process group and the permit is not
recycled until its direct child is reaped, including the bounded deferred
reaper used for an exceptional slow kernel cleanup. Deployment replica count
still determines the fleet-wide aggregate, so retain that value as deployment
capacity evidence.

The top-level Terraform executable is selected only through the approved
absolute-path configuration above and is validated before provider credentials
are processed or attached. Its subprocess still receives a minimal environment:
`PATH`, `HOME`, `TMPDIR`, locale, and only the offering-declared provider
variables. That inherited `PATH` may be used by Terraform providers or Ansible
forks/interpreters, but never to select the top-level CLI. There is no declared
pass-through for AWS, Azure, GCP, or other backend credential environment
variables. Backend authentication follows a closed schema: supported
non-local backends would have to carry their exact inline scalar authentication
configuration in the isolation-validated operator template. File discovery,
ambient CLI state, instance metadata, in-cluster or workload identity, and
default credential chains are forbidden. The current reviewed policy rejects
both `remote` and `pg` backends; the bundled absolute `local` backend is the
normative path. Never commit an operator backend template that contains secret
material.

The Linux and Windows vSphere bundles pin `vmware/vsphere` exactly at `2.16.1`
and embed Terraform's generated dependency lock with checksums for Linux and
macOS on amd64 and arm64. Terraform offline dry-run, live plan/apply/destroy,
and proving-ground cleanup all initialize with `-lockfile=readonly`; changing
the provider requires an explicit source-and-lock update that changes the
approved IaC digest.

When live mode is enabled, the agent fetches the control plane's public key once (`GET /api/agents/cp-public-key`) and pins it for the process lifetime. If the pin fails, live plans still run; live applies are refused.

Production external Terraform and Ansible execution in every mode is
intentionally unavailable in this release. The runner has no production adapter that can
attach every descendant before execution, terminate the complete descendant
set, and wait until that set is empty. Consequently production live paths fail
closed before a provider process is spawned, and `OfflineDryRun` fails before
spawning Terraform or Ansible too. The modes below describe protocol and
pure/stub acceptance behavior, not a currently enabled external execution
path. `OfflineDryRun` remains useful only as a no-provider-authority, no-spawn
control-plane rehearsal until containment is implemented.

## Execution modes

| Mode | Dispatched by | Protocol / acceptance behavior (external spawn currently unavailable) |
| --- | --- | --- |
| `OfflineDryRun` (default) | `execute` tier | Models Terraform `init`, `validate`, and a best-effort credential-free plan, or `ansible-playbook --check`, in an isolated workspace. Pure/stub tests exercise the flow; production refuses before either CLI starts. No provider credentials or mutation authority are supplied. |
| `LivePlan` | admin | Real `terraform init` → `plan` → `show -json` against the backend. Produces evidence and a plan digest. It does not apply provider resources; backend initialization, locking, and state metadata can still change. |
| `LiveApply` | never dispatched directly; whole-request jobs are minted by approval | Re-plans, requires the canonical plan digest to equal the approved digest, then applies that fresh matching binary plan. Human per-step approval is disabled in this release. |
| `LiveDestroy` | system, during auto-teardown | Reverse-order Terraform teardown of applied steps, authorized by a step-scoped control-plane grant. Ansible destroy refuses because it has no Terraform state. |

## The live-apply trust chain

1. **Plan.** An admin dispatches `POST /api/requests/{id}/execute?mode=live-plan`. The agent plans against the real backend and posts scrubbed evidence plus a SHA-256 plan digest.
2. **Review.** The control plane stores the digest-covered plan bytes privately and derives an admin-only projection from the actual planned VM shape and the five planned vSphere placement lookups. Those values must exactly match the JobSpec; missing or mismatched `change.after` data fails closed. Raw Terraform JSON and provider object identifiers are not exposed.
3. **Approve.** An admin calls `POST /api/requests/{id}/approve-live-apply` with the exact reviewed plan job UUID, attempt UUID, and digest. The control plane locks and re-verifies that selected row, including its attempt, lease generation, result UUID, signed-envelope identity, immutable enrollment, key, profile, spec, and digest. It then mints an Ed25519 grant binding the request id, destination platform, exact plan job and attempt, approved plan digest, complete JobSpec digest (including mode, IaC digest, variables, and state key), exact successful-planning agent id/enrollment/key, canonical execution-trust-profile digest, approver, and expiry (whole-request approvals use a 1-hour TTL; grants are capped at 24 hours). A later same-digest plan row cannot replace the row the administrator reviewed. The database allows one request-level live apply. Human per-step approval is deliberately disabled: the step route completes its admin, scope, and separation-of-duties checks, then returns `409 Conflict` without minting a job. Exact-plan step-grant support remains internal protocol groundwork rather than an enabled operator workflow.
4. **Verify authority.** Before provider execution, the agent requires protocol v6, re-computes the embedded IaC digest, verifies the grant and its exact JobSpec, destination, plan job/attempt, planning-agent enrollment/key, execution-profile digest, request/step ownership, and expiry, then runs a fresh plan whose digest must equal the approved one. Any failure produces a signed `LiveRefused` result and mutation is never called. The control plane independently repeats the signed grant, platform, spec, state-owner, assigned-agent, profile, plan-row, and approved-digest checks on result ingest. Protocol v1 through v5 peers, including digest-only v5 grants, are rejected rather than interpreted without those bindings.
5. **Apply and converge.** The LiveApply job creates a fresh binary plan, proves its canonical `terraform show -json` digest equals the reviewed digest, and applies that matching binary plan. It does not reuse a binary `tfplan` file from the earlier job. The runner then re-plans; a vSphere request cannot complete verification unless that post-apply plan is clean. Other Terraform offerings and Ansible check-mode runs remain preview-only until they have their own typed, server-derived review projection; neither approval endpoint will mint a grant for them.

Plan, apply, and destroy jobs for one state key are pinned to the same approved
agent. This is mandatory for the currently reviewed agent-local backend and
would remain enforced if a non-local backend were admitted later, so an
operator cannot resolve the same logical key through different backend
templates. The binding survives plan lease expiry, retry, and administrative
requeue. If the owning agent is offline or revoked, the job stays pending for
operator recovery; it does not fail over to another agent with a potentially
different backend template.

Refusals and results are durable: the agent enqueues every result to a local outbox before posting, so a network failure cannot lose a refusal.

## Where to see results

| What | Where |
| --- | --- |
| Job state, including `live_refused` | `GET /api/admin/agents/jobs/{job_id}/state` (admin) |
| Signed result metadata and safe LivePlan review | `GET /api/admin/agents/jobs/{job_id}/result` (admin) |
| Request audit trail / evidence | `GET /api/requests/{id}/audit` and `/evidence` (audit tier) |

## Credentials never reach the control plane

Provider credentials live on the agent host, never on the control plane. Each offering declares the secret variables it needs; the vSphere server-deployment offerings declare `VSPHERE_USER`, `VSPHERE_PASSWORD`, and `VSPHERE_SERVER`. For each declared name `<NAME>`, set `RYUKI_LIVE_CRED_<NAME>` on the agent. Trusted provisioning must also set `RYUKI_LIVE_PROVIDER_AUTHORITY_ID` and `RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION` for that exact destination/account set and rotate the version whenever any member changes. Before any live Terraform run, the agent resolves the declared set and refuses fail-closed if a value or the authority metadata is missing or malformed, reporting a signed refusal that names only the configuration field, never its value.

This environment seam does not yet prove exact credential consistency. Profile
derivation packages credentials and authority metadata into one in-memory
resolution result, but they are separate process-environment reads, and the
runner invocation resolves credential values again. They are neither
cryptographically linked nor atomically resolved from one versioned secret-
manager record. Trusted operators must maintain that correspondence today.
Provider-connected activation requires a typed secret-manager connector that
returns the credential bundle and its immutable authority metadata together,
plus deployment readback proving that binding; the current validated strings
are not a substitute for that control.

For a live run, the agent first approves the configured absolute CLI identity,
then injects only the declared names — plus their `TF_VAR_<lowercase>` aliases,
since the bundles route credentials through `var.vsphere_*` — into the
Terraform subprocess, on top of a minimal allowlist (`PATH`, `HOME`, `TMPDIR`,
locale). Dry-runs receive no credentials at all, enforced at both the agent and
the runner API boundary. All command output is scrubbed before it becomes
signed evidence.

Control-plane side, integration connections resolve external credential handles
through the provider-neutral secret resolver capability. The current Vault
adapter uses the all-or-none `VAULT_ADDR` / `VAULT_TOKEN` compatibility settings
and `<mount>/<path>[#<field>]` handles. Partial or transport-unsafe configuration
stops startup; missing configuration fails the dependent production/live
operation. The development resolver is admitted only when both the platform and
connection explicitly select static/mock dry-run — see
[Configuration](configuration.md). The grant-signing key lives at
`RYUKI_CP_SIGNING_KEY_PATH` (default `cp-signing.key`), created `0600` on first
boot.

## Auto-teardown on failed multi-step runs

If a step fails mid-way through a multi-step live request, the control plane force-fails any steps still awaiting approval, then tears down applied steps in reverse dependency order. Each teardown is its own step-scoped `LiveDestroy` grant (approver `system:auto-teardown`); a grant minted for a whole-request apply can never authorize a destroy. If a destroy itself fails, the cascade halts rather than thrashing, and the surviving steps are left for operator reconciliation.

The portal exposes no human per-step approve control in this release, and the
corresponding API route fails closed without minting. The exact-plan machinery
for step grants is retained for protocol validation and for system-owned
compensation authority; it is not evidence that per-step live apply is enabled.

## Preparing for future provider-connected live execution

This release cannot run a production external provider process because the
required descendant-containment adapter does not yet exist. Do not use the
protocol implementation as authority to attempt a real live apply. After a
future release supplies that adapter and passes the gates in
[First Test Acceptance](first-test.md), including cleanup against an approved
disposable target, the remaining deployment prerequisites are:

1. **Enrol an agent** where it can reach vCenter (see the enrolment steps above), and give it a durable Terraform backend template via `RYUKI_AGENT_BACKEND_HCL`. Its active state-location attribute must contain `{STATE_KEY}`; the control plane supplies a stable `request-<id>` or `step-<id>` key shared by plan, apply, and destroy for that one unit of work.
2. **Provide credentials and their non-secret authority reference** on the agent host: `RYUKI_LIVE_CRED_VSPHERE_USER`, `RYUKI_LIVE_CRED_VSPHERE_PASSWORD`, `RYUKI_LIVE_CRED_VSPHERE_SERVER`, `RYUKI_LIVE_PROVIDER_AUTHORITY_ID`, and `RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION`. A missing or malformed value produces a signed refusal before Terraform runs; changing the destination/account set requires a new authority version, plan, and approval.
3. **Unlock live mode** with `RYUKI_AGENT_ALLOW_LIVE=true` and confirm the agent pinned the control-plane public key at startup.
4. **Supply placement**: the request must carry the real vSphere datacenter, cluster, datastore, network, template, and disk size. Missing live-placement inputs are rejected before dispatch; sample defaults are not substituted.
5. **Drive the governed flow only after containment is enabled**: dispatch a `LivePlan`, wait while the request remains `executing`, review the digest-verified projection for its exact plan job and attempt, approve that same reference, and let the same backend-owning agent build and apply a fresh digest-matching plan. Only a converged apply satisfies the request-verification prerequisite.
6. **Clean up**: successful single-job requests do not currently expose an operator-triggered `LiveDestroy`. Rehearse and approve the state-keyed cleanup procedure before live apply, then verify both the provider and Terraform state are empty.

Until that adapter exists, use the `OfflineDryRun` protocol path only to
rehearse the control-plane lifecycle with no external spawn and no provider
mutation authority; pure/stub evidence is not real Terraform or Ansible
execution. The normative future-live checklist is
[First Test Acceptance](first-test.md); the local protocol stack is in
`deploy/proving-ground`.

## What is implemented, and what stays yours

Implemented and tested: the no-provider-authority/no-spawn dry-run protocol
path; protocol-v6-only negotiation; the
fail-closed live protocol and acceptance paths (exact-spec and exact-plan-row
grant binding, IaC and plan digest integrity, state-owner validation, exact
planning-agent enrollment/key and execution-profile affinity, refusal
reporting, no-double-apply); the safe plan-review projection; credential
resolution and provider-authority comparison seams; and a real Vault KV v2
resolver on the control plane. Production external `OfflineDryRun`, `LivePlan`,
`LiveApply`, and `LiveDestroy` execution remains unavailable until the required
descendant-containment adapter is implemented.

Operator-owned: real provider credentials, a durable state backend, placement
identifiers, approval of the first target, and cleanup of a successful
single-job apply. Automatic `LiveDestroy` exists only as compensation for a
failed multi-step run; it is not a general operator destroy endpoint.
