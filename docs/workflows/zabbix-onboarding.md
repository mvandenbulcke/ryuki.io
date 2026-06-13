# Zabbix onboarding

## Purpose

Operator runbook for the **Zabbix onboarding** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `zabbix-onboarding-contract.yaml`
- Serves contract route `/api/observe/zabbix-onboarding-contract`.
- Validator slice `zabbix-onboarding`
- Contract `zabbix-onboarding-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    assetScope
    hostSummary
    site
    environment
    monitoringProfile
    hostGroupProfile
    templateProfile
    proxyOrServerProfile
    maintenanceWindow
    owner
    supportGroup
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    inventory-source-known
    monitoring-profile-known
    host-summary-known
    host-group-known
    template-known
    proxy-or-server-known
    maintenance-window-known
    owner-known
    support-group-known
    dry-run-plan-produced
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live onboarding.
- No Zabbix mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw host rows.
- provider payloads.
- default built-in templates.
- default-built-in-templates.
- Lenovo XCC SNMP.

## Evidence

Required evidence (from the contract YAML).

    Onboarding summary
    Host summary review
    Host group and template plan
    Proxy or server plan
    Maintenance window plan
    Owner routing
    Approval route
    Dry-run onboarding plan
    Evidence references
