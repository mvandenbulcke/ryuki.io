# Dashboard

## Purpose

Operator runbook for the **Dashboard** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `dashboard-risk-heatmap-contract.yaml`
- Serves contract route `/api/dashboard/risk-heatmap-contract`.
- Validator slice `dashboard-risk-heatmap`
- Contract `dashboard-risk-heatmap-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    aggregate-only
    stale-data-marked
    risk-band-reviewed
    trend-window-reviewed
    evidence-redacted
    live-query-blocked
    raw-detail-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live metrics queries.
- No live dashboard reads.
- No dashboard, workflow, provider, or notification mutation.
- No provider calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Risk heatmap summary.

## Evidence

Required evidence (from the contract YAML).

    Risk heatmap summary
    Trend window summary
    Risk band summary
    Stale-data marker summary
    Evidence references
