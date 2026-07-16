# Firmware compliance exceptions

## Purpose

Operator runbook for the **Firmware compliance exceptions** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `firmware-compliance-exception-contract.yaml`
- Serves contract route `/api/operations/firmware-compliance-exception-contract`.
- Validator slice `firmware-compliance-exception`
- Contract `firmware-compliance-exception-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    site
    hardwareProfile
    platformRole
    targetBaseline
    observedBaselineSummary
    exceptionReason
    clusterCriticality
    supportStatus
    remediationWindow
    expiryDate
    reviewCadence
    owner
    evidenceManifest

Required guards and approvals (from the contract YAML).

    site-known
    hardware-profile-known
    target-baseline-known
    observed-baseline-summarized
    compatibility-impact-reviewed
    support-risk-reviewed
    cluster-criticality-reviewed
    maintenance-window-known
    exception-owner-assigned
    expiry-date-set
    remediation-plan-ready
    evidence-redacted

Runtime risk acceptance uses a two-principal lifecycle:

1. An execute-capable maker submits `POST /api/datacenter/firmware/exception`.
   The API derives `requested_by` from the verified session and stores a
   `Pending` row; no exception authority or firmware action is granted.
   `expiryDays` must be between 1 and 365.
2. A different principal with the explicit `approve` permission submits
   `POST /api/datacenter/firmware/exception/{id}/approve` with the pending
   row's `expectedVersion`. The API derives `approved_by` from that checker,
   repeats maker/checker separation in the state CAS, and commits the approval
   with its audit entry in one transaction.
3. PostgreSQL `CURRENT_DATE` computes and evaluates the inclusive expiry date.
   Once that date has passed, the exception is ineffective immediately and the
   device's underlying EOL/version result is used by inventory and reports.
   A stale approval cannot extend or revive the expired request.
4. Rows created before this lifecycle are marked `Legacy` and grant no
   authority because their distinct maker identity cannot be proven. Submit a
   new request instead of editing or adopting legacy evidence.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No host identifiers, serial numbers, asset tags, endpoint names, usernames, credentials, tokens, tenant identifiers, object identifiers, private network details, exact observed firmware versions, raw logs, or vendor payloads in committed files.
- No live provider calls.
- No live firmware.
- No raw inventory rows.
- No client-supplied maker, checker, approval state, or expiry date.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- dry-run review artifact.
- firmware-safe exception summaries only.

## Evidence

Required evidence (from the contract YAML).

    Firmware exception summary
    Target baseline summary
    Observed baseline summary
    Compatibility impact review
    Support risk review
    Cluster criticality review
    Remediation plan
    Approval route
    Expiry and review date
    Evidence references
