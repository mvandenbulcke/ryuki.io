# Application-aware backup validation

## Purpose

Operator runbook for the **Application-aware backup validation** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `application-aware-backup-validation-contract.yaml`
- Serves contract route `/api/protect/application-aware-backup-validation-contract`.
- Validator slice `application-aware-backup`
- Contract `application-aware-backup-validation-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    application
    workloadType
    site
    backupPolicy
    guestProcessingPolicy
    sqlMetadataSummary
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    backup-policy-known
    workload-supported
    guest-processing-policy-known
    sql-metadata-reviewed
    owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live backup execution.
- No guest processing execution.
- No credential access or secret value exposure.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- validation summaries only.

## Evidence

Required evidence (from the contract YAML).

    Application-aware validation summary
    Workload scope
    Guest processing policy
    SQL metadata summary
    Policy exceptions
    Remediation options
    Approval route
    Evidence references
