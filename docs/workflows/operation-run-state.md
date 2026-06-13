# Activity

## Purpose

Operator runbook for the **Activity** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `operation-run-state-contract.yaml`
- Serves contract route `/api/operations/run-state-contract`.
- Validator slice `operation-run-state`
- Contract `operation-run-state-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    operation-scope-known
    child-operations-summarized
    lock-scope-reviewed
    retry-policy-reviewed
    redacted-log-summary-ready
    evidence-redacted
    live-execution-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live execution.
- No worker dispatch.
- No provider calls.
- No operation, child operation, lock, retry, or workflow mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw operation rows.
- raw execution logs.
- raw recipient data.
- token values.
- serial numbers.
- static operation run-state summaries only.

## Evidence

Required evidence (from the contract YAML).

    Operation run summary
    Child operation summary
    Lock state summary
    Retry state summary
    Redacted log summary
    Evidence references
