# Evidence

## Purpose

Operator runbook for the **Evidence** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `evidence-export-retention-contract.yaml`
- Serves contract route `/api/evidence/export-retention-contract`.
- Validator slice `evidence-export-retention`
- Contract `evidence-export-retention-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    redaction-state-redacted
    export-readiness-approved
    retention-class-assigned
    metadata-only-search
    no-raw-payloads
    recipient-data-redacted
    provider-payloads-blocked
    retention-review-recorded

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No raw evidence payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- metadata-only audit search.
- evidence-manifest-catalog.yaml.

## Evidence

Required evidence (from the contract YAML).

    Export package summary
    Redaction state review
    Retention class decision
    Audit search scope summary
    Prohibited content review
    Evidence references
