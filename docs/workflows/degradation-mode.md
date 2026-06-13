# Multi-site degradation mode

## Purpose

Operator runbook for the **Multi-site degradation mode** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `degradation-mode-contract.yaml`
- Serves contract route `/api/operations/degradation-mode-contract`.
- Validator slice `degradation-mode`
- Contract `degradation-mode-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    affectedScope
    degradationState
    dependencyStatus
    staleDataMarker
    owner
    safeRemediation
    evidenceManifest

Required guards and approvals (from the contract YAML).

    affected-scope-known
    dependency-status-known
    stale-data-marked
    write-execution-blocked
    safe-remediation-set
    owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No automatic failover.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- stale-data markers.

## Evidence

Required evidence (from the contract YAML).

    Degradation summary
    Affected scope
    Dependency state
    Stale-data marker
    Blocked execution decision
    Safe remediation
    Handover notes
    Evidence references
