# Dashboard

## Purpose

Operator runbook for the **Dashboard** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `dashboard-global-overview-contract.yaml`
- Serves contract route `/api/dashboard/global-overview-contract`.
- Validator slice `dashboard-global-overview`
- Contract `dashboard-global-overview-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    aggregate-only
    stale-data-marked
    evidence-redacted
    owner-domain-safe
    scope-known
    live-query-blocked
    raw-detail-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live dashboard queries.
- No dashboard, workflow, provider, or notification mutation.
- No provider calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw request rows.
- raw operation rows.
- raw inventory rows.
- raw CMDB rows.
- raw monitoring rows.
- tenant identifiers.
- static dashboard global overview summaries only.

## Evidence

Required evidence (from the contract YAML).

    Dashboard summary
    Site readiness summary
    Request backlog summary
    Failed operation summary
    Patch risk summary
    Backup risk summary
    Monitoring gap summary
    CMDB risk summary
    Evidence references
