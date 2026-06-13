# Alert routing and escalation

## Purpose

Operator runbook for the **Alert routing and escalation** / **Alert routing model** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `alert-routing-contract.yaml`
- Serves contract route `/api/observe/alert-routing-contract`.
- Validator slice `alert-routing`
- Contract `alert-routing-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    alertSource
    site
    environment
    application
    criticality
    supportGroup
    maintenanceWindow
    escalationPolicy

Required guards and approvals (from the contract YAML).

    owner-known
    support-group-known
    maintenance-window-known
    alert-template-mapped
    escalation-policy-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- never enables live alert routing changes.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- provider-safe routing plans.

## Evidence

Required evidence (from the contract YAML).

    Alert routing summary
    Validation result
    Support group mapping
    Maintenance window reference
    Escalation decision
    Handover notes
    Evidence references
