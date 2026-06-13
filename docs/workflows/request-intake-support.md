# Requests

## Purpose

Operator runbook for the **Requests** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `request-intake-support-contract.yaml`
- Serves contract route `/api/requests/intake-support-contract`.
- Validator slice `request-intake-support`
- Contract `request-intake-support-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    template-source-reviewed
    duplicate-signals-reviewed
    draft-state-read-only
    request-submission-blocked
    draft-persistence-blocked
    raw-payloads-blocked
    recipient-data-blocked
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live submission.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- draft persistence.
- raw duplicate rows.
- raw recipient data.
- static request intake support summaries only.

## Evidence

Required evidence (from the contract YAML).

    Template catalog review
    Duplicate signal review
    Draft state summary
    Intake precheck summary
    Evidence references
