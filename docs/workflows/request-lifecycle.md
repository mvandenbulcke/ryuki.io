# Requests

## Purpose

Operator runbook for the **Requests** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `request-lifecycle-contract.yaml`
- Serves contract route `/api/requests/lifecycle-contract`.
- Validator slice `request-lifecycle`
- Contract `request-lifecycle-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

The catalog `lifecycleStages` map to the request lifecycle as follows. Stages before `execute` are provider-safe review steps gated on an approved dry-run plan and a redacted evidence path.

| Stage | Phase | Provider action |
| --- | --- | --- |
| intake | Capture request context and offering | none |
| validate | Validate required inputs and policy guardrails | none |
| plan | Build the provider-safe dry-run plan | none |
| approve | Apply the approval route decisions | none |
| lock | Reserve the lock scope before dispatch | none |
| execute | Dispatch the approved dry-run plan | gated, blocked until live runs are approved |
| verify | Verify post-execution state from evidence | none |
| protect | Confirm backup and DR posture | none |
| publish | Publish evidence and CMDB updates | none |
| maintain | Track day-2 maintenance obligations | none |
| retire | Drive decommission and retirement governance | none |

## Required inputs and approvals

Required inputs (from the contract YAML).

    requestContext
    requesterRole
    offering
    site
    environment
    owner
    criticality
    dryRunPlan
    approvalRoute
    lockScope
    evidenceManifest
    statusCallback

Required guards and approvals (from the contract YAML).

    intake-complete
    validation-passed
    dry-run-reviewed
    approval-route-assigned
    lock-scope-ready
    evidence-redacted
    provider-safe-plan-ready
    status-callback-ready
    fail-safe-state-reviewed

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live execution.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- approved dry-run plan.
- redacted evidence path.

## Evidence

Required evidence (from the contract YAML).

    Request payload summary
    Validation result
    Provider-safe dry-run plan
    Approval decisions
    Lock record
    Execution plan summary
    Verification plan
    Protection policy summary
    Publish plan
    Lifecycle handover notes
    Evidence references
