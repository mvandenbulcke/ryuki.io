# Noise and flapping remediation

## Purpose

Operator runbook for the **Noise and flapping remediation** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `noise-flapping-remediation-contract.yaml`
- Serves contract route `/api/observe/noise-flapping-remediation-contract`.
- Validator slice `noise-flapping-remediation`
- Contract `noise-flapping-remediation-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    alertPatternSummary
    site
    environment
    monitoringProfile
    owner
    supportGroup
    maintenanceWindow
    evidenceManifest

Required guards and approvals (from the contract YAML).

    alert-pattern-summary-known
    monitoring-profile-known
    owner-known
    maintenance-window-reviewed
    remediation-request-dry-run
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live remediation.
- No Zabbix mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- noise summaries only.

## Evidence

Required evidence (from the contract YAML).

    Noise summary
    Flapping pattern summary
    Threshold review
    Suppression window proposal
    Escalation review
    Remediation request draft
    Approval route
    Evidence references
