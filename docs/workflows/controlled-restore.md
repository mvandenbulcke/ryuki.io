# Controlled restore request

## Purpose

Operator runbook for the **Controlled restore request** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `controlled-restore-contract.yaml`
- Serves contract route `/api/protect/controlled-restore-contract`.
- Validator slice `controlled-restore`
- Contract `controlled-restore-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    businessPurpose
    requester
    restoreType
    sourceResource
    restorePoint
    targetSelection
    owner
    site
    environment
    verificationPlan
    retentionNeed

Required guards and approvals (from the contract YAML).

    restore-point-known
    target-isolation-reviewed
    owner-approval-assigned
    backup-operator-approval-assigned
    verification-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- never enables live restore execution.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- provider-safe restore plans.

## Evidence

Required evidence (from the contract YAML).

    Request payload summary
    Validation result
    Restore plan summary
    Approval decisions
    Lock record
    Verification result
    Evidence references
