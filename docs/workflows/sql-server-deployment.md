# SQL Server deployment

## Purpose

Operator runbook for the **SQL Server deployment** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `sql-server-deployment-contract.yaml`
- Validator slice `sql-server-deployment`
- Contract `sql-server-deployment-contract.yaml` is marked draft (version 1)

Endpoint: `/api/workflows/sql-server/deployment-contract`

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    businessPurpose
    sqlWorkloadProfile
    deploymentTopology
    hypervisorPlatform
    site
    environment
    criticality
    owner
    supportGroup
    diskLayoutSummary
    runtimeIdentitySummary
    spnPolicySummary
    backupPolicy
    monitoringProfile
    cmdbContext
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    request-preflight-ready
    topology-reviewed
    capacity-admission-ready
    disk-layout-reviewed
    runtime-identity-reviewed
    spn-policy-reviewed
    backup-plan-reviewed
    monitoring-plan-reviewed
    cmdb-publication-reviewed
    approval-route-assigned
    rollback-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live VMware, Hyper-V, Proxmox, SQL, directory, DNS, backup, monitoring, or CMDB changes.
- No raw SQL instance data, database data, paths, backup rows, host identifiers, listener identifiers, port values, credentials, or provider payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static SQL Server deployment summaries only.
- VMware.
- Hyper-V.
- Proxmox.
- live hypervisor execution.

## Evidence

Required evidence (from the contract YAML).

    SQL deployment summary
    Topology review
    Placement plan
    Disk layout plan
    Runtime identity review
    SPN policy review
    Backup policy plan
    Monitoring plan
    CMDB publication plan
    Rollback plan
    Evidence references
