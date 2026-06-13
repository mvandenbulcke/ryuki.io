# Image factory

## Purpose

Operator runbook for the **Image factory** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `image-factory-contract.yaml`
- Serves contract route `/api/images/factory-contract`.
- Validator slice `image-factory`
- Contract `image-factory-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    imageFamily
    distribution
    patchCycle
    baselineProfile
    hardeningProfile
    requester
    owner
    evidenceManifest

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- live promotion disabled.
- provider-safe image plan.

## Evidence

Required evidence (from the contract YAML).

    Image build summary
    Patch manifest
    Vulnerability scan summary
    Test result
    Approval decisions
    Promotion decision
    Evidence references
