# Multi-Step Orchestration

Some offerings are not one job but a sequence: preflight, deploy, enroll monitoring. Ryuki can materialize a dependency-ordered step plan inside a single governed request and track steps as their dependencies succeed. Human per-step live apply is deliberately disabled in this release; the signed step-grant and reverse-order compensation machinery remains internal protocol groundwork, not an enabled operator workflow.

## What exists today

One composite offering is wired: **managed server onboarding**, three steps (`preflight` → `deploy` → `monitor`), each depending on the previous. It is selected by creating a `server-deployment` request whose `fields.deployment_profile` is `managed-onboarding` (the server mirrors that allowlisted field into request metadata); it is not a separate catalog entry. Each step references a real single-offering IaC bundle.

Step plans are defined in code (a step template in `ryuki-runner`), not in YAML: adding a new composite offering is a code change. The plan is validated at request creation (duplicate keys, unknown dependencies, and cycles are rejected), materialized in the same transaction as the request, and immutable afterwards.

## How a stepped request runs

1. `POST /api/requests` creates the request and materializes the step plan.
2. `POST /api/requests/{id}/execute` dispatches the initially ready steps (dependencies satisfied). The default mode is `OfflineDryRun`; `?mode=live-plan` requires admin.
3. When an agent posts a step's job result, the control plane locks the whole plan, records the outcome, and dispatches any steps that just became ready. There is no polling scheduler; progress rides on job completion.
4. `GET /api/requests/{id}` includes a `steps` array with each step's key, dependencies, IaC reference, and status.

If a step fails, in-flight siblings are swept to failed and their pending agent jobs cancelled. A failed dependency blocks its dependents permanently, by design; there is no automatic retry or skip.

## Per-step live apply is disabled

A stepped request cannot be live-applied as a whole; `?mode=live-apply` and the request-level approval endpoint both refuse. Human approval of an individual step is also disabled in this release:

1. The portal renders the step plan and statuses but exposes no per-step live-apply control.
2. `POST /api/requests/{id}/steps/{step_key}/approve-live-apply` retains verified-human admin, request-scope, separation-of-duties, and closed exact-plan-body checks, then returns `409 Conflict` without changing the step or minting a job.
3. The internal exact-plan and step-scoped grant types are retained for protocol validation and system-owned compensation. They are not authority for an operator to apply a step.
4. Enabling human per-step apply requires a dedicated safe review projection for each exact step plan job, attempt, and digest, plus a separately reviewed release.

## Automatic teardown

The protocol retains a system-owned reverse-order compensation path for a future release in which live steps are admitted. If such a live step fails after earlier steps have applied, the control plane is designed to roll back:

- Steps still awaiting approval are failed first, so nothing new can enter a collapsing run.
- Applied steps are torn down in reverse dependency order, each with its own step-scoped `LiveDestroy` grant minted by the system. The authority to destroy derives from the step's own apply approval; a whole-request grant can never authorize a destroy.
- If a destroy itself fails, the cascade halts rather than thrashing. The request ends `failed`, and any steps still marked applied or tearing down are the operator's reconciliation list.

The request remains `executing` while teardown runs, so destroy results flow through the same result path, and settles at `failed` once nothing is left applied.

## Honest limits

- **Portal status support exists; approval does not.** Request detail renders the step plan and status of every step, but no per-step live-apply button or action is present. The API route is a fail-closed `409`, not an automation path.
- **Destroy is compensating, not operator-triggered.** Terraform `LiveDestroy` runs on the agent during automatic rollback of a failed multi-step run. A successful request has no general operator destroy endpoint, so its cleanup must use a separately approved state-keyed procedure.
- **External execution is unavailable.** Production refuses every Terraform/Ansible mode before spawn until the reviewed per-command containment adapter exists; no live or offline step execution is claimed here.
- **Future provider egress.** If external execution is admitted later, server-deployment bundles use the checksum-locked `vmware/vsphere` provider: `init` needs registry egress and `plan` needs a reachable vCenter.
- **No in-place retry.** A non-stepped request's single live-apply slot is consumed permanently, even by a failure; recovery is a new request.
