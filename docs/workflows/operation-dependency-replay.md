# Activity

## Purpose

Operator runbook for the **Activity** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `operation-dependency-replay-contract.yaml`
- Serves contract route `/api/operations/dependency-replay-contract`.
- Validator slice `operation-dependency-replay`
- Contract `operation-dependency-replay-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    graph-source-reviewed
    dependency-order-reviewed
    lock-scope-reviewed
    blocker-state-reviewed
    retry-policy-reviewed
    replay-dry-run-only
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live replay.
- No operation, child operation, lock, retry, or workflow mutation.
- No provider calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw operation rows.
- raw recipient data.
- serial numbers.
- static operation dependency replay summaries only.

## Evidence

Required evidence (from the contract YAML).

    Dependency graph summary
    Replay phase summary
    Lock evaluation summary
    Blocked reason summary
    Retry policy summary
    Evidence references
