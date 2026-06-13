# Brand and design token documentation

## Purpose

Operator runbook for the **Brand and design token documentation** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `design-system-contract.yaml`
- Serves contract route `/api/platform/design-system-contract`.
- Validator slice `design-system`
- Contract `design-system-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    themeSummary
    accessibilitySummary
    brandingSummary
    surfaceSummary
    statusBadgeSummary
    tableGuidanceSummary
    formGuidanceSummary
    errorEvidenceSummary
    evidenceManifest

Required guards and approvals (from the contract YAML).

    light-theme-reviewed
    dark-theme-reviewed
    contrast-reviewed
    focus-treatment-reviewed
    non-color-status-reviewed
    branding-reviewed
    table-density-reviewed
    form-safety-reviewed
    evidence-presentation-reviewed

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No external font fetch.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Light theme review
    Dark theme review
    Accessibility review
    Branding configuration review
    UI surface review
    Status badge review
    Table guidance review
    Form guidance review
    Error and evidence presentation review
