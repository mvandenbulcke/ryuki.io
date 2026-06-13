# Cost and capacity analytics

## Purpose

Operator runbook for the **Cost and capacity analytics** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `cost-capacity-analytics-contract.yaml`
- Serves contract route `/api/analytics/cost-capacity-contract`.
- Validator slice `cost-capacity-analytics`
- Contract `cost-capacity-analytics-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    analyticsScope
    site
    serviceDomain
    capacitySummary
    costBand
    growthTrend
    forecastWindow
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    analytics-scope-summarized
    aggregate-usage-known
    cost-band-known
    growth-trend-known
    forecast-window-set
    owner-known
    remediation-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live remediation.
- No billing export ingestion.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate cost and capacity summaries only.
- without calling VMware, Hyper-V, Proxmox, Veeam, CMDB, billing, or provider APIs.
- VMware, Hyper-V, and Proxmox static platform scope.

## Evidence

Required evidence (from the contract YAML).

    Cost capacity summary
    Capacity forecast
    Storage forecast
    Backup forecast
    Cost trend
    Efficiency opportunities
    Remediation options
    Evidence references
