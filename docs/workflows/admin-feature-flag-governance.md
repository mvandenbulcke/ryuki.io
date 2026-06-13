# Admin

## Purpose

Operator runbook for the **Admin** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `admin-feature-flag-governance-contract.yaml`
- Serves contract route `/api/admin/feature-flag-governance-contract`.
- Validator slice `admin-feature-flag-governance`
- Contract `admin-feature-flag-governance-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    owner-assigned
    approval-route-assigned
    blast-radius-reviewed
    rollback-plan-ready
    evidence-redacted
    live-toggle-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live feature toggle.
- No rollout, targeting, policy, or workflow mutation.
- No provider calls.
- No notification dispatch.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw feature flag rows.
- raw targeting rows.
- raw user rows.
- raw group rows.
- token values.
- static admin feature-flag governance summaries only.

## Evidence

Required evidence (from the contract YAML).

    Feature flag summary
    Rollout plan summary
    Approval route summary
    Blast radius summary
    Rollback plan summary
    Evidence references
