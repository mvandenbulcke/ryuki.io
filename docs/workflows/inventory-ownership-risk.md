# Inventory

## Purpose

Operator runbook for the **Inventory** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `inventory-ownership-risk-contract.yaml`
- Serves contract route `/api/inventory/ownership-risk-contract`.
- Validator slice `inventory-ownership-risk`
- Contract `inventory-ownership-risk-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    inventory-snapshot-reviewed
    ownership-summary-reviewed
    support-group-reviewed
    drift-timeline-reviewed
    stale-marker-reviewed
    risk-band-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider sync.
- No live owner lookup.
- No CMDB mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- remediation mutation.
- workflow mutation.
- provider calls.
- raw inventory rows.
- raw owner data.
- raw logs.
- raw recipient data.
- serial numbers.
- static inventory ownership risk summaries only.

## Evidence

Required evidence (from the contract YAML).

    Ownership score summary
    Stale asset risk summary
    Drift timeline summary
    Inventory freshness summary
    Evidence references
