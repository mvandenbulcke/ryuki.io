# Platform Database Readiness

## Purpose

This slice adds a static readiness contract for the production control-plane database. It turns the CloudNativePG PostgreSQL decision into reviewable topology, storage, backup, restore, monitoring, secret-reference, network-policy, and evidence gates without applying Kubernetes resources or connecting to a database.

## Contract

- Contract definition `platform-database-readiness-contract.yaml`
- Validator slice `platform-database-readiness`
- Contract `platform-database-readiness-contract.yaml` is marked draft (version 1)

Endpoint: `/api/platform/database-readiness-contract`

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    runtimeProfile
    clusterTopologySummary
    storageProfile
    backupArchiveSummary
    restoreTestSummary
    monitoringProfile
    vaultReferenceSummary
    networkPolicySummary
    maintenanceWindow
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    operator-install-reviewed
    three-instance-topology-reviewed
    storage-class-reviewed
    wal-archive-reviewed
    object-backup-reviewed
    restore-test-reviewed
    monitoring-reviewed
    vault-reference-reviewed
    network-policy-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- Use static database readiness summaries only.
- No Kubernetes apply, CloudNativePG cluster creation, database mutation, schema migration, backup execution, restore execution, or object storage access.
- No database names, usernames, credential values, connection strings, endpoints, private IPs, raw database rows, raw Kubernetes payloads, raw backup payloads, object-storage payloads, tokens, or provider payloads.
- No live provider calls.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Database readiness summary
    Cluster topology review
    Storage readiness
    Backup archive review
    Restore test review
    Monitoring readiness
    Network policy review
    Evidence references
