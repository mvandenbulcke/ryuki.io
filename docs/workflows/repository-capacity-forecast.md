# Repository capacity forecasting

## Purpose

Operator runbook for the **Repository capacity forecasting** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `repository-capacity-forecast-contract.yaml`
- Serves contract route `/api/protect/repository-capacity-contract`.
- Validator slice `repository-capacity-forecast`
- Contract `repository-capacity-forecast-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    repositoryScope
    site
    backupPolicy
    retentionPolicy
    growthTrend
    owner
    supportGroup
    forecastWindow
    evidenceManifest

Required guards and approvals (from the contract YAML).

    repository-summary-known
    retention-policy-known
    growth-trend-known
    backup-policy-known
    site-pairing-known
    forecast-window-set
    owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live remediation.
- No repository or retention mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate forecast summaries.

## Evidence

Required evidence (from the contract YAML).

    Repository capacity summary
    Growth trend summary
    Retention risk
    Hub-spoke capacity impact
    Immutability headroom
    Remediation options
    Approval route
    Evidence references
