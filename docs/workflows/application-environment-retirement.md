# Application environment retirement

## Purpose

Operator runbook for the **Application environment retirement** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `application-environment-retirement-contract.yaml`
- Serves contract route `/api/workflows/application-environment/retirement-contract`.
- Validator slice `application-environment-retirement`
- Contract `application-environment-retirement-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    requester
    application
    environment
    owner
    serviceCriticality
    dependencyGraph
    dataRetentionNeed
    backupRetentionNeed
    accessClosureScope
    cmdbContext
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    request-preflight-ready
    relationship-graph-reviewed
    dependency-impact-reviewed
    data-retention-reviewed
    backup-retention-reviewed
    access-closure-reviewed
    monitoring-disable-reviewed
    cmdb-retirement-reviewed
    rollback-window-reviewed
    final-closure-blocked
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live VMware, Hyper-V, Proxmox, monitoring, backup, CMDB, access, or data deletion changes.
- No raw dependency rows, raw relationship rows.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- VMware, Hyper-V, and Proxmox dry-run parity.
- static application environment retirement summaries only.

## Evidence

Required evidence (from the contract YAML).

    Retirement summary
    Relationship review
    Dependency impact
    Data retention plan
    Backup retention plan
    Access closure plan
    Monitoring disable plan
    CMDB retirement plan
    Rollback window
    Final closure hold
    Evidence references
