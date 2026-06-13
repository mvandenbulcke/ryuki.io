# Hardware warranty and support lifecycle

## Purpose

Operator runbook for the **Hardware warranty and support lifecycle** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `hardware-lifecycle-contract.yaml`
- Serves contract route `/api/operations/hardware-lifecycle-contract`.
- Validator slice `hardware-lifecycle`
- Contract `hardware-lifecycle-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    hardwareProfile
    lifecycleState
    site
    owner
    capacityRole
    supportStatus
    firmwareBaseline
    refreshWindow
    evidenceManifest

Required guards and approvals (from the contract YAML).

    model-known
    site-known
    support-status-known
    firmware-baseline-known
    capacity-role-known
    cmdb-owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live execution.
- No serial numbers.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- metadata-only hardware lifecycle contract.
- prior vendor recommended release train (N-1)
- HPE profiles use prior applicable SPP, MSA, and SimpliVity recommendation sets.
- Lenovo SR, VX, and MX profiles use prior recommended recipes.
- Evidence stays summary-only.

## Evidence

Required evidence (from the contract YAML).

    Hardware lifecycle summary
    Site placement
    Support status
    Firmware baseline
    Capacity role
    Refresh decision
    Risk notes
    Evidence references
