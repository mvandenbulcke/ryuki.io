# Datacenter readiness

## Purpose

Operator runbook for the **Datacenter readiness** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `datacenter-readiness-contract.yaml`
- Serves contract route `/api/operations/datacenter-readiness-contract`.
- Validator slice `datacenter-readiness`
- Contract `datacenter-readiness-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    site
    requester
    owner
    hardwareProfile
    clusterProfile
    networkScope
    storageScope
    capacityNeed
    evidenceManifest

Required guards and approvals (from the contract YAML).

    site-known
    owner-known
    rack-capacity-known
    power-cooling-reviewed
    network-readiness-known
    storage-readiness-known
    firmware-baseline-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No raw inventory rows.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- site-safe readiness summaries.

## Evidence

Required evidence (from the contract YAML).

    Site readiness summary
    Rack and power review
    Cooling review
    Network readiness summary
    Storage readiness summary
    Firmware and support baseline
    Capacity decision
    Risk notes
    Evidence references
