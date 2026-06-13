# Legal hold and extended retention

## Purpose

Operator runbook for the **Legal hold and extended retention** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `legal-hold-retention-contract.yaml`
- Serves contract route `/api/protect/legal-hold-retention-contract`.
- Validator slice `legal-hold-retention`
- Contract `legal-hold-retention-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    holdScopeSummary
    businessReasonSummary
    retentionPolicy
    requestedRetentionClass
    startDate
    expiryDate
    reviewCadence
    owner
    supportGroup
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    hold-scope-summarized
    retention-policy-known
    approval-route-assigned
    backup-impact-reviewed
    expiry-date-set
    review-cadence-set
    release-process-defined
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live retention changes.
- No Veeam or ServiceNow mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- safe legal hold summaries only.

## Evidence

Required evidence (from the contract YAML).

    Legal hold summary
    Scope review
    Retention decision
    Backup impact review
    Approval route
    Expiry and review cadence
    Release readiness
    Evidence references
