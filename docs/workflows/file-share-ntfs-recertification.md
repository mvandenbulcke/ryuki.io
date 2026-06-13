# File share and NTFS recertification

## Purpose

Operator runbook for the **File share and NTFS recertification** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `file-share-ntfs-recertification-contract.yaml`
- Serves contract route `/api/identity/file-share-ntfs-recertification-contract`.
- Validator slice `file-share-ntfs-recertification`
- Contract `file-share-ntfs-recertification-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    recertificationCycle
    shareScopeSummary
    permissionSummary
    ownershipSummary
    groupAccessSummary
    staleAccessSummary
    exceptionSummary
    owner
    supportGroup
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    recertification-scope-summarized
    owner-attestation-reviewed
    group-access-reviewed
    ntfs-acl-reviewed
    share-permission-reviewed
    stale-access-reviewed
    exception-route-assigned
    approval-route-assigned
    remediation-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live directory changes.
- No live share permission changes.
- No live NTFS ACL changes.
- No live ServiceNow changes.
- No AD group membership changes.
- No owner, inheritance, share permission, or NTFS ACL changes.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static file share NTFS recertification summaries only.

## Evidence

Required evidence (from the contract YAML).

    Recertification summary
    Share scope summary
    Ownership attestation
    Group access summary
    NTFS ACL review
    Share permission review
    Stale access review
    Exception decision
    Remediation plan
    Evidence references
