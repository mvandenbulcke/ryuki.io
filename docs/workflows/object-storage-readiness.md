# Object Storage Readiness

## Purpose

This slice adds a static readiness contract for Azure Blob object storage used by evidence packs, exports, retained audit artifacts, and CloudNativePG backup targets. It turns the object storage decision into reviewable retention, immutability, lifecycle, private-network, secret-reference, monitoring, and evidence gates without calling Azure APIs or reading storage content.

## Contract

- Contract definition `object-storage-readiness-contract.yaml`
- Validator slice `object-storage-readiness`
- Contract `object-storage-readiness-contract.yaml` is marked draft (version 1)

Endpoint: `/api/platform/object-storage-readiness-contract`

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    storageUseCaseSummary
    containerRoleSummary
    retentionPolicySummary
    immutabilityPolicySummary
    lifecyclePolicySummary
    privateEndpointSummary
    vaultReferenceSummary
    monitoringProfile
    backupTargetSummary
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    azure-blob-provider-reviewed
    container-purpose-reviewed
    retention-policy-reviewed
    immutability-versioning-reviewed
    lifecycle-management-reviewed
    private-endpoint-reviewed
    shared-key-disabled-reviewed
    vault-reference-reviewed
    diagnostic-logging-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- Use static object storage readiness summaries only.
- No Azure API calls, storage account mutation, container mutation, blob reads or writes, lifecycle policy mutation, immutability policy mutation, public network enablement, or shared key usage.
- No storage account names, container names, blob names, URLs, endpoints, subscription identifiers, resource group names, tenant identifiers, object identifiers, private network details, access keys, shared keys, SAS tokens, connection strings, raw blob payloads, raw storage payloads, or provider payloads.
- No live provider calls.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Object storage readiness summary
    Account security review
    Container role review
    Retention policy review
    Immutability and versioning review
    Lifecycle management review
    Private network review
    Backup target review
    Monitoring diagnostics review
    Evidence references
