# Restore testing

## Purpose

Operator runbook for the **Restore testing** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `restore-testing-contract.yaml`
- Serves contract route `/api/protect/restore-testing-contract`.
- Validator slice `restore-testing`
- Contract `restore-testing-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    application
    criticality
    backupPolicy
    restoreType
    restorePointSelection
    verificationPlan
    owner
    supportGroup
    testWindow
    evidenceManifest

Required guards and approvals (from the contract YAML).

    restore-point-known
    target-isolation-reviewed
    verification-plan-ready
    owner-approval-assigned
    backup-operator-approval-assigned
    schedule-window-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live restore execution.
- No test execution.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- restore test plans and evidence summaries.

## Evidence

Required evidence (from the contract YAML).

    Restore test scope
    Restore point summary
    Isolation plan
    Verification plan
    Schedule cadence
    Approval decisions
    Evidence pack
    Evidence references
