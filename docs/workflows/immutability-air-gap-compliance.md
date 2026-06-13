# Immutability and air-gap compliance

## Purpose

Operator runbook for the **Immutability and air-gap compliance** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `immutability-air-gap-compliance-contract.yaml`
- Serves contract route `/api/protect/immutability-air-gap-compliance-contract`.
- Validator slice `immutability-air-gap-compliance`
- Contract `immutability-air-gap-compliance-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    repositoryScope
    repositoryPostureProfile
    repositoryTransitionState
    site
    backupPolicy
    retentionPolicy
    immutabilityPolicy
    airGapStrategy
    backupCopyIsolation
    immutableRetention
    capacityRunway
    rollbackFallbackPlan
    cutoverReadiness
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    repository-summary-known
    immutability-policy-known
    retention-policy-known
    air-gap-strategy-known
    repository-transition-reviewed
    isolation-path-reviewed
    backup-copy-isolation-known
    immutable-retention-known
    capacity-runway-known
    rollback-fallback-known
    cutover-readiness-reviewed
    owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live remediation.
- No repository, appliance, object storage, or retention mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate posture summaries.
- current Veeam StoreOnce appliance class.
- future Veeam hardened Linux repository class.
- backup copy isolation.
- immutable retention.
- capacity runway.
- rollback or fallback.
- year class.

## Evidence

Required evidence (from the contract YAML).

    Repository posture summary
    Current StoreOnce posture
    Hardened Linux repository readiness
    Immutability policy
    Air-gap strategy
    Retention lock status
    Isolation review
    Repository transition readiness
    Cutover readiness
    Backup copy isolation
    Immutable retention
    Capacity runway
    Rollback or fallback plan
    Policy exceptions
    Remediation options
    Approval route
    Evidence references
