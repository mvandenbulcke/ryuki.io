# Operator runbook launcher

## Purpose

Operator runbook for the **Operator runbook launcher** / **Operations** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `operator-runbook-contract.yaml`
- Serves contract route `/api/operations/runbook-launch-contract`.
- Validator slice `operator-runbook`
- Contract `operator-runbook-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    ticketContext
    requester
    targetResource
    runbookType
    owner
    site
    environment
    riskJustification
    evidenceManifest

Required guards and approvals (from the contract YAML).

    role-authorized
    approval-route-assigned
    worker-capability-known
    dry-run-ready
    dependency-health-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- provider-safe runbook plans.

## Evidence

Required evidence (from the contract YAML).

    Request payload summary
    Validation result
    Runbook plan summary
    Approval decisions
    Worker capability decision
    Handover notes
    Evidence references
