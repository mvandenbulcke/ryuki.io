# Backup and DR assignment

## Purpose

Operator runbook for the **Backup and DR assignment** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `backup-dr-assignment-contract.yaml`
- Serves contract route `/api/protect/backup-dr-assignment-contract`.
- Validator slice `backup-dr-assignment`
- Contract `backup-dr-assignment-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    application
    site
    environment
    criticality
    backupPolicy
    drPolicy
    tagSummary
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    policy-catalog-known
    site-pairing-known
    tags-reviewed
    owner-known
    backup-operator-review-assigned
    dr-impact-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live backup or DR assignment.
- No replica creation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate assignment summaries.

## Evidence

Required evidence (from the contract YAML).

    Assignment summary
    Tag policy mapping
    Backup policy decision
    DR replica decision
    Site-pairing impact
    Policy exceptions
    Approval route
    Evidence references
