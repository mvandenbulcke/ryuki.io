# Zabbix drift remediation

## Purpose

Operator runbook for the **Zabbix drift remediation** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `zabbix-drift-remediation-contract.yaml`
- Serves contract route `/api/observe/zabbix-drift-remediation-contract`.
- Validator slice `zabbix-drift-remediation`
- Contract `zabbix-drift-remediation-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    hostSummary
    site
    environment
    monitoringProfile
    owner
    supportGroup
    maintenanceWindow
    evidenceManifest

Required guards and approvals (from the contract YAML).

    monitoring-profile-known
    host-identity-known
    zabbix-mapping-reviewed
    owner-known
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

- drift summaries only.

## Evidence

Required evidence (from the contract YAML).

    Drift summary
    Expected mapping
    Observed mapping summary
    Remediation request draft
    Maintenance impact
    Owner review
    Approval route
    Evidence references
