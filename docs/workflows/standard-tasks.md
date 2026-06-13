# Standard L1/L2 tasks

## Purpose

Operator runbook for the **Standard L1/L2 tasks** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `standard-task-contract.yaml`
- Serves contract route `/api/operations/standard-task-contract`.
- Validator slice `standard-task`
- Contract `standard-task-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    ticketContext
    requester
    taskType
    targetResourceSummary
    operatingSystemFamily
    site
    environment
    owner
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    ticket-context-known
    requester-authorized
    task-type-supported
    target-scope-summarized
    worker-capability-known
    dry-run-plan-reviewed
    approval-route-assigned
    maintenance-window-reviewed
    rollback-or-handover-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live service changes.
- No live disk changes.
- No live backup actions.
- No live alert suppression.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static standard task summaries only.

## Evidence

Required evidence (from the contract YAML).

    Request summary
    Task plan summary
    Target scope summary
    Worker capability decision
    Approval route
    Risk and rollback notes
    Evidence references
