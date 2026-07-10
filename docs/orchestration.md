# Multi-Step Orchestration

Some offerings are not one job but a sequence: preflight, deploy, enroll monitoring. Ryuki can materialize a dependency-ordered step plan inside a single governed request, execute steps as their dependencies succeed, gate each live apply on its own approval, and roll back applied steps in reverse order when a later step fails.

## What exists today

One composite offering is wired: **managed server onboarding**, three steps (`preflight` → `deploy` → `monitor`), each depending on the previous. It is selected by creating a `server-deployment` request whose `fields.deployment_profile` is `managed-onboarding` (the server mirrors that allowlisted field into request metadata); it is not a separate catalog entry. Each step references a real single-offering IaC bundle.

Step plans are defined in code (a step template in `ryuki-runner`), not in YAML: adding a new composite offering is a code change. The plan is validated at request creation (duplicate keys, unknown dependencies, and cycles are rejected), materialized in the same transaction as the request, and immutable afterwards.

## How a stepped request runs

1. `POST /api/requests` creates the request and materializes the step plan.
2. `POST /api/requests/{id}/execute` dispatches the initially ready steps (dependencies satisfied). The default mode is `OfflineDryRun`; `?mode=live-plan` requires admin.
3. When an agent posts a step's job result, the control plane locks the whole plan, records the outcome, and dispatches any steps that just became ready. There is no polling scheduler; progress rides on job completion.
4. `GET /api/requests/{id}` includes a `steps` array with each step's key, dependencies, IaC reference, and status.

If a step fails, in-flight siblings are swept to failed and their pending agent jobs cancelled. A failed dependency blocks its dependents permanently, by design; there is no automatic retry or skip.

## Per-step live apply

A stepped request can never be live-applied as a whole; `?mode=live-apply` and the request-level approval endpoint both refuse. Instead each step earns its own apply:

1. The step's live plan completes and the step parks in `AwaitingApproval`, carrying its plan digest.
2. An admin (not the requester; separation of duties is enforced) calls `POST /api/requests/{id}/steps/{step_key}/approve-live-apply`.
3. The approval flips the step to `Applying` under a row lock, so a double approval loses cleanly, and mints a step-scoped grant bound to that one job: signed by the control plane, digest-checked by the agent, one live apply per step.
4. Approval is refused if the request has begun rolling back.

## Automatic teardown

If a live step fails after earlier steps have applied, the control plane rolls back:

- Steps still awaiting approval are failed first, so nothing new can be approved into a collapsing run.
- Applied steps are torn down in reverse dependency order, each with its own step-scoped `LiveDestroy` grant minted by the system. The authority to destroy derives from the step's own apply approval; a whole-request grant can never authorize a destroy.
- If a destroy itself fails, the cascade halts rather than thrashing. The request ends `failed`, and any steps still marked applied or tearing down are the operator's reconciliation list.

The request remains `executing` while teardown runs, so destroy results flow through the same result path, and settles at `failed` once nothing is left applied.

## Honest limits

- **Portal support exists.** Request detail renders the step plan and status of every step. An admin sees a two-click live-apply approval on a step only while it is `AwaitingApproval`; the API remains available for automation.
- **Destroy is compensating, not operator-triggered.** Terraform `LiveDestroy` runs on the agent during automatic rollback of a failed multi-step run. A successful request has no general operator destroy endpoint, so its cleanup must use a separately approved state-keyed procedure.
- **Live steps need a real agent.** Per-step live applies require a deployed agent with `RYUKI_AGENT_ALLOW_LIVE=true` and real provider credentials; CI validates the control-plane side with simulated agent results.
- **Provider egress.** Server-deployment bundles use the real `vmware/vsphere` Terraform provider: `init` needs one-time registry egress, and `plan` needs a reachable vCenter, degrading gracefully otherwise.
- **No in-place retry.** A non-stepped request's single live-apply slot is consumed permanently, even by a failure; recovery is a new request.
