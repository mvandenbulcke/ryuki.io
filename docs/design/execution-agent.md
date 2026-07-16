# Per-platform execution agent — design

Status: **design, hardened** (unparked 2026-06-15; revised after a GPT-5 Codex
adversarial design review). This is the live-execution architecture that closes
the largest AWX-parity gap — running approved Terraform/Ansible against real
platforms — while keeping Ryuki's approval gates, dry-run-by-default posture, and
tamper-evident evidence, which AWX lacks.

It is **docs-driven** (Terraform/Ansible/provider APIs are publicly documented),
so the agent, protocol, and dry-run paths are built and tested **without any live
platform**. Live change is gated behind operator-controlled deployment + creds +
explicit intent (§2), so the **repository and CI touch zero real infrastructure**.

> **Design-review note.** A first draft assumed at-least-once job redelivery with
> agent-side idempotency was safe for live `terraform apply`. It is **not** — that
> was the single most dangerous flaw. Live apply now uses **fencing + explicit
> reconciliation**, never automatic redispatch. State, identity, and the signed
> result envelope were hardened accordingly.

## 1. Goal & non-goals

**Goal.** A lightweight agent deployed once per platform/site (vCenter agent in
DEFRA, Proxmox agent in GBLON, …) that registers with the Ryuki control plane,
pulls **approved** jobs, runs Terraform/Ansible **locally** with **local
credentials** and a **durable platform-local state backend**, and returns
**signed** evidence. The control plane never holds a platform's credentials and
never needs egress to a platform's API (AWX execution-node model — chosen for
egress, credential locality, and segmentation).

**Non-goals (now):** control-plane HA, agent auto-update, a full secrets vault.

## 2. Safety model & execution modes (non-negotiable)

There is no single "dry-run". Three explicit modes, because a plan still reads
live systems:

| Mode | Touches the platform? | Mutates? | Where it runs in CI |
|---|---|---|---|
| `OfflineDryRun` | No (no providers configured / `validate` only) | No | ✅ fully exercised |
| `LivePlan` | **Yes** — `terraform plan` / `ansible --check` read live state | No (best-effort; see caveat) | ❌ needs a deployed agent |
| `LiveApply` | Yes | **Yes** | ❌ operator-gated |

**LiveApply requires ALL of:**
1. The job carries `LiveApply` **and a control-plane-signed approval grant**
   (`VerifiedLiveContext`: request id, approved-plan digest, approver, expiry).
   The agent **verifies the grant's signature against the control plane's public
   key independently** — it does not trust a bare `mode` field.
2. The agent was started `--allow-live` with real credentials in its environment.
3. The grant's approved-plan digest **matches the raw canonical plan the agent
   just produced**
   (plan-then-apply: the agent re-plans and refuses if the plan diverges from the
   approved one — no applying an unreviewed plan).

Absent any one → the agent reports `LiveRefused` and mutates nothing.

**Caveat:** `--check`/`plan` are not universally side-effect-free (custom
modules, provisioners, data sources). A **policy gate** forbids unsafe
constructs (local-exec/remote-exec provisioners, non-check-safe Ansible tasks)
before a LivePlan/LiveApply is dispatched.

Credentials are resolved by the agent from its own environment/host secret store
and **never enter the control plane** — Ryuki stores references only.

## 3. Topology

```
   approve + sign grant            pull (long-poll, SKIP LOCKED)        run locally
operator ──────────────►  Ryuki control plane  ◄──────────────────  execution agent ──► terraform/ansible
 (portal)                  (ryuki-api)            post SIGNED result    (per platform)     local creds +
                            │ agent_jobs queue (fencing, leases)                            durable locked
                            │ agents registry (approved pubkeys, caps)                      state backend
                            ▼ verifies signature + grant
                        evidence store
```

The agent **initiates** every connection (outbound HTTPS only); no inbound path
into the platform zone.

## 4. Components & crates

| Crate | Role |
|---|---|
| `ryuki-runner` (new — extracted) | The Terraform/Ansible execution core (`exec` timeout + process-group kill, 0700 `workspace`, `TerraformRunner`/`AnsibleRunner` `init→validate→plan`, `iac` resolver, `TF_VAR_*`/env secret injection). Today in `ryuki-api/src/runner`; extracted unchanged so API and agent run identical logic. |
| `ryuki-protocol` (new) | Wire contract: `AgentRegistration`, `Job`/`JobSpec`/`JobMode`, `JobLease` (with `attempt_id`, `lease_generation`, `fencing_token`), `JobResult` (idempotency key), `SignedEnvelope`, `VerifiedLiveContext`. Pure serde, no IO. |
| `ryuki-agent` (new binary) | Per-platform executor: config, key, register, pull-loop, run via `ryuki-runner`, **durable outbox**, sign + post result, heartbeat. |
| `ryuki-api` (existing) | Dispatch surface: `agents`/`agent_jobs` migrations, register/poll/ack/result/heartbeat with per-request agent auth + lease/fencing, approved-request→job + signed grant, signature & grant verification. |
| `ryuki-engine` (existing) | Evidence redaction (scrub-before-sign), reused by the agent. |

## 5. Dispatch protocol (agent-initiated REST, `/api/agents`)

Every request is **bound to the agent's key** (request signing, or mandatory
mTLS for live-capable agents) — a stolen bearer token alone cannot poll, lease,
or post. Tokens are stored hashed, are revocable/rotatable, and carry claims
(`agent_id`, platform, capabilities, key fingerprint).

| Endpoint | Purpose |
|---|---|
| `POST /register` | Enroll: id, platform/site, capabilities (tool + provider versions), **public key**. **Pending until an admin approves it AND assigns platform/capabilities from trusted inventory** (not self-declared). |
| `GET /{id}/jobs` | Long-poll next dispatchable job for this platform via `SELECT … FOR UPDATE SKIP LOCKED`; issues a lease with `attempt_id` + `lease_generation` + `fencing_token`. One outstanding poll per agent; jittered backoff. |
| `POST /{id}/jobs/{job}/ack` | `Leased → Running` (carries the fencing token). |
| `POST /{id}/jobs/{job}/result` | Final `JobResult` + **signed envelope** (§6). **Idempotent** by `(job_id, attempt_id, result_id)`. CP verifies signature + fencing (only the current attempt is accepted) before storing evidence + transitioning the request. |
| `POST /{id}/heartbeat` | Liveness + running job + fencing token. |

**Lease & fencing.** Expiry is decided by **control-plane DB time only** (no
client clock). On expiry:
- `OfflineDryRun` / `LivePlan` (no mutation) → return to `Pending`, redispatch
  with a **new** `attempt_id`/`lease_generation`; the stale attempt's result is
  rejected by fencing.
- `LiveApply` (mutating) → **never auto-redispatch.** Transition to
  `ReconcileRequired`; an operator reconciles against Terraform state and
  explicitly re-dispatches or closes. This prevents a partial-apply-then-retry
  duplicate mutation.
  - **Status: only the "closes" half is built.** A terminal non-Succeeded
    LiveApply permanently consumes the request's single live-apply slot
    (`idx_agent_jobs_unique_live_apply` spans ALL statuses; migration 057), so the
    operator's in-place action is to **close** the request via `POST
    /api/requests/{id}/fail`. There is **no in-place re-dispatch yet** — the
    "explicitly re-dispatches" path is a **DEFERRED owner decision** (it overlaps
    LiveRefused-recoverability / operator-re-approve and needs operator attestation
    of post-apply state + a new signed grant + a fresh plan-vs-current check). Until
    then, re-attempting a live-apply means starting a **fresh request** (a new
    lifecycle re-planned/re-approved against the current state). The fail-closed
    default is intentional; see `create_live_apply_job` and migration 057.

**Lost results.** The agent writes a local run journal + the signed result to a
**durable outbox before** posting, then retries the idempotent POST until the CP
acknowledges — so a result is never lost to a timed-out POST.

## 6. Identity, trust & the signed result envelope

- **Agent keypair (Ed25519)** generated at first start; public key enrolled and
  **admin-approved**; private key never leaves the host (non-exportable where the
  host supports it).
- **Every request** is signed by / mTLS-bound to that key — dispatch authority,
  not just evidence.
- **Signed result envelope** binds the full context, not a bare digest:
  `agent_id, agent_enrollment_id, platform, job_id, attempt_id, lease_generation, request_id, mode,
  status, job_spec_digest, approved_plan_digest, raw_plan_digest, evidence_digest,
  redaction_policy_version, timestamp, key_id, cp_nonce`. The CP verifies the
  signature against the enrolled key, checks the nonce/attempt to **reject
  replays and stale attempts**, and recomputes `evidence_digest` over the exact
  canonical bytes it stores (extending the existing digest-seal model to a remote
  origin). For a successful `LivePlan`, `raw_plan_digest` is separately required
  and signature-bound; it is never inferred from `evidence_digest`.
- **Scrub before sign.** The agent runs the engine's `redact_evidence` so no raw
  secret is in the signed/sent pack; the envelope records the redaction-policy
  version and the CP re-runs compliance checks (pattern redaction is not a
  complete DLP guarantee).

## 7. Terraform state (durable, locked, per-platform)

The existing runner workspace is **ephemeral with no cross-run state** — correct
for `OfflineDryRun`, unsafe for `LiveApply`. Live runs use a **durable
platform-local backend with native locking** (e.g. a Postgres/S3/Consul backend
inside the platform zone), with: state-key naming per request/resource, locking
to enforce **single-writer**, encryption at rest, backups, and a documented DR /
state-recovery procedure. No live apply runs without a healthy locked backend.

## 8. Build slices (each: delegate → Opus review → GPT-5 Codex adversarial → gate → commit)

- **S1 — Runner extraction (safe refactor, no behavior change).** Move
  `runner/*` from `ryuki-api` into `ryuki-runner`; fix imports; all tests stay
  green. Isolated and low-risk — done first.
- **S2 — Protocol types.** `ryuki-protocol` with the FULL safe contract from day
  one: attempts, `lease_generation`, fencing token, idempotent result key, the
  signed envelope, `VerifiedLiveContext`, explicit `JobMode`. Serde round-trip +
  signature/verify unit tests. **Signature verification is built here, not
  stubbed** — no result-accepting endpoint ships before verification exists.
- **S3 — Control-plane dispatch (dry-run scope).** `agents` + `agent_jobs`
  migrations; register (admin-approval) / poll (`SKIP LOCKED`) / ack / result
  (verified, idempotent, fenced) / heartbeat; approved-request → `OfflineDryRun`
  job. Per-request agent auth.
- **S4 — Agent binary (dry-run).** `ryuki-agent`: config, keygen, register,
  pull-loop, run via `ryuki-runner` in `OfflineDryRun`, durable outbox, sign +
  post. End-to-end **dry-run** test: agent ↔ test control plane, locally, no
  infra.
- **S5 — Live path.** `LivePlan`/`LiveApply` modes; CP-signed approval grant +
  agent-side grant verification + plan-digest match; durable locked state
  backend; `ReconcileRequired` on live-lease expiry; policy gate for unsafe
  constructs. Still no infra in CI (live needs a deployed agent + creds);
  operator runbook for real-platform deployment.
- **S6 — Portal.** Agents view: enrolled/approved agents + capabilities, job
  queue + lease/attempt/fencing status, per-job signed-evidence + grant
  indicator, heartbeat health, `ReconcileRequired` alerts.

S1–S4 deliver a working **dry-run** distributed executor with verified signed
evidence — provable end-to-end locally. S5 is the operator-controlled live
unlock with the fencing/state/grant invariants. S6 makes it visible.

## 9. Why this beats AWX

AWX is execution-first with bolt-on RBAC and no equivalent to approval gates or
signed, reproducible evidence. This keeps Ryuki's approval-gated,
dry-run-by-default, signed-evidence governance and pushes credentials + execution
into each platform's own security zone — solving the egress, credential-locality,
and segmentation problems a central AWX struggles with — while making live apply
**fenced, reconcilable, and tamper-evident** rather than fire-and-forget.
