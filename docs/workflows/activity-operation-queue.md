# Activity

## Purpose

Operator runbook for the **Activity** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `activity-operation-queue-contract.yaml`
- Serves contract route `/api/operations/activity-queue-contract`.
- Validator slice `activity-operation-queue`
- Contract `activity-operation-queue-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    operation-scope-known
    queue-state-known
    lock-state-known
    retry-policy-known
    blocked-reason-present
    stale-data-marked
    evidence-redacted
    live-query-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live queue queries.
- No operation, workflow, lock, retry, worker, provider, or notification mutation.
- No provider calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw operation rows.
- raw child operation rows.
- raw execution logs.
- raw provider payloads.
- raw user data.
- tenant identifiers.
- static Activity operation queue summaries only.

## Evidence

Required evidence (from the contract YAML).

    Activity queue summary
    Parent operation summary
    Child operation summary
    Lock state summary
    Retry state summary
    Blocked reason summary
    Handover notes
    Evidence references
