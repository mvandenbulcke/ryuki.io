# Inventory

## Purpose

Operator runbook for the **Inventory** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `inventory-resource-overview-contract.yaml`
- Serves contract route `/api/inventory/resource-overview-contract`.
- Validator slice `inventory-resource-overview`
- Contract `inventory-resource-overview-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    inventory-snapshot-reviewed
    site-scope-reviewed
    resource-type-summary-reviewed
    freshness-state-reviewed
    backup-status-reviewed
    monitoring-status-reviewed
    cmdb-status-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider sync.
- No live inventory queries.
- No provider calls.
- No inventory, remediation, or workflow mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw inventory rows.
- raw owner data.
- raw logs.
- raw recipient data.
- serial numbers.
- static inventory resource overview summaries only.

## Evidence

Required evidence (from the contract YAML).

    Resource overview summary
    Site readiness summary
    Protection and observability summary
    CMDB status summary
    Evidence references
