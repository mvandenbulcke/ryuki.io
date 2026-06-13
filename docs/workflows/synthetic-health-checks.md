# Synthetic service health checks

## Purpose

Operator runbook for the **Synthetic service health checks** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `synthetic-health-check-contract.yaml`
- Serves contract route `/api/observe/synthetic-health-check-contract`.
- Validator slice `synthetic-health-check`
- Contract `synthetic-health-check-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    serviceName
    application
    site
    environment
    checkType
    targetSummary
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    check-target-reviewed
    check-type-supported
    owner-known
    maintenance-window-known
    synthetic-definition-dry-run
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Synthetic check summary
    Target scope summary
    Synthetic definition draft
    Expected result
    Alert impact
    Maintenance impact
    Approval route
    Evidence references
