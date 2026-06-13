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

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No host identifiers, serial numbers, asset tags, endpoint names, usernames, credentials, tokens, tenant identifiers, object identifiers, private network details, exact observed firmware versions, raw logs, or vendor payloads in committed files.
- No live provider calls.
- No live firmware.
- No raw inventory rows.

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
