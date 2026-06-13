# Evidence

## Purpose

Operator runbook for the **Evidence** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `evidence-compliance-dashboard-contract.yaml`
- Serves contract route `/api/evidence/compliance-dashboard-contract`.
- Validator slice `evidence-compliance-dashboard`
- Contract `evidence-compliance-dashboard-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    control-scope-known
    evidence-pack-referenced
    redaction-state-reviewed
    stale-data-marked
    owner-assigned
    live-evaluation-blocked
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live compliance evaluation.
- No evidence, export, retention, or workflow mutation.
- No provider calls.
- No notification dispatch.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw evidence payloads.
- raw control rows.
- raw audit logs.
- raw user data.
- tenant identifiers.
- static evidence compliance dashboard summaries only.

## Evidence

Required evidence (from the contract YAML).

    Compliance dashboard summary
    Control status summary
    Evidence pack references
    Redaction summary
    Stale data summary
    Owner review summary
    Evidence references
