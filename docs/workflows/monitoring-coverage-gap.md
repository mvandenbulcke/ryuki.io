# Monitoring coverage gap report

## Purpose

Operator runbook for the **Monitoring coverage gap report** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `monitoring-coverage-gap-contract.yaml`
- Serves contract route `/api/observe/monitoring-coverage-gap-contract`.
- Validator slice `monitoring-coverage-gap`
- Contract `monitoring-coverage-gap-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    assetScope
    site
    environment
    monitoringProfile
    hostGroupProfile
    templateProfile
    proxyOrServerProfile
    maintenanceWindow
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    inventory-coverage-current
    monitoring-profile-known
    host-summary-known
    host-group-known
    template-known
    proxy-or-server-known
    maintenance-window-known
    owner-known
    support-group-known
    alert-routing-reviewed
    stale-data-marked
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live remediation.
- No Zabbix mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate coverage summaries only.
- default built-in templates.
- Lenovo XCC SNMP.

## Evidence

Required evidence (from the contract YAML).

    Monitoring coverage summary
    Host onboarding state
    Host group and template review
    Proxy or server review
    Maintenance window review
    Alert routing review
    Owner routing
    Remediation draft
    Evidence references
