# Backup coverage gap report

## Purpose

Operator runbook for the **Backup coverage gap report** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `backup-coverage-gap-contract.yaml`
- Serves contract route `/api/protect/backup-coverage-gap-contract`.
- Validator slice `backup-coverage-gap`
- Contract `backup-coverage-gap-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    assetScope
    site
    environment
    criticality
    owner
    supportGroup
    backupPolicy
    retentionPolicy
    replicaRequirement
    evidenceManifest

Required guards and approvals (from the contract YAML).

    inventory-coverage-current
    backup-policy-known
    retention-policy-known
    replica-requirement-reviewed
    criticality-known
    owner-known
    support-group-known
    stale-data-marked
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live remediation.
- No backup job, policy, replica, repository, or provider mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate gap summaries only.

## Evidence

Required evidence (from the contract YAML).

    Backup coverage summary
    Gap classification
    Policy comparison
    Retention review
    Replica review
    Owner routing
    Remediation draft
    Evidence references
