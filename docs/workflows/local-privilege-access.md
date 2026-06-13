# Local admin and sudo access request

## Purpose

Operator runbook for the **Local admin and sudo access request** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `local-privilege-access-contract.yaml`
- Serves contract route `/api/identity/local-privilege-access-contract`.
- Validator slice `local-privilege-access`
- Contract `local-privilege-access-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    ticketContext
    requesterSummary
    accessAction
    targetScopeSummary
    privilegeProfile
    operatingSystemFamily
    expiryWindow
    owner
    supportGroup
    approvalRoute
    rollbackPlan
    evidenceManifest

Required guards and approvals (from the contract YAML).

    ticket-context-known
    requester-authorized
    target-scope-summarized
    privilege-profile-reviewed
    os-family-supported
    expiry-window-reviewed
    approval-route-assigned
    worker-capability-reviewed
    rollback-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live directory changes.
- No live local administrator changes.
- No live sudoers changes.
- No privilege grant or removal.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static local privilege access summaries only.

## Evidence

Required evidence (from the contract YAML).

    Privilege request summary
    Target scope summary
    Privilege profile review
    Directory group review
    Sudoers review
    Expiry and review window
    Worker capability decision
    Approval route
    Rollback plan
    Evidence references
