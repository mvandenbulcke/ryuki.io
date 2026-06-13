# Requests

## Purpose

Operator runbook for the **Requests** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `request-execution-timeline-contract.yaml`
- Serves contract route `/api/requests/execution-timeline-contract`.
- Validator slice `request-execution-timeline`
- Contract `request-execution-timeline-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    request-scope-known
    timeline-source-reviewed
    evidence-redacted
    approval-state-known
    lock-state-known
    operation-link-safe
    status-callback-safe
    raw-detail-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live request queries.
- No provider calls.
- No request, workflow, operation, provider, or notification mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw request payloads.
- raw timeline rows.
- raw approval data.
- raw evidence payloads.
- raw logs.
- raw recipient data.
- static request execution timeline summaries only.

## Evidence

Required evidence (from the contract YAML).

    Request timeline summary
    Approval state summary
    Operation link summary
    Evidence reference summary
    Blocked reason summary
