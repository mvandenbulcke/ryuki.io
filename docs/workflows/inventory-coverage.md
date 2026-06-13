# Inventory

## Purpose

Operator runbook for the **Inventory** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `inventory-coverage-contract.yaml`
- Serves contract route `/api/inventory/coverage-contract`.
- Validator slice `inventory-coverage`
- Contract `inventory-coverage-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

The contract YAML does not declare structured inputs yet. Capture the requesting role, target site, environment, and the approval decision in the request record before the approve stage completes.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- not raw provider payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Also serves `/api/inventory/coverage/local/summary`.
- Stale data blocks execution.
- VMware, Hyper-V, Proxmox.
- fixtures/inventory/coverage-sample.yaml.

## Evidence

Required evidence (from the contract YAML).

    Inventory snapshot
    Coverage gap list
    Stale-data markers
    CMDB reconciliation summary
    Evidence references
