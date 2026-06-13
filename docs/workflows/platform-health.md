# Platform health dashboard

## Purpose

Operator runbook for the **Platform health dashboard** / **Platform self-monitoring** / **Operations** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `platform-health-contract.yaml`
- Serves contract route `/api/operations/platform-health-contract`.
- Validator slice `platform-health`
- Contract `platform-health-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    component
    owner
    healthSignal
    healthState
    staleDataMarker
    safeRemediation
    evidenceManifest

Required guards and approvals (from the contract YAML).

    component-registered
    owner-known
    stale-data-marked
    dependency-status-known
    safe-remediation-set
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No raw logs.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- component-safe status.

## Evidence

Required evidence (from the contract YAML).

    Health summary
    Component owner
    Dependency state
    Stale-data marker
    Safe remediation
    Handover notes
    Evidence references
