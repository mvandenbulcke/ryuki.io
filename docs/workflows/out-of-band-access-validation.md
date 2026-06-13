# Out-of-band access validation

## Purpose

Operator runbook for the **Out-of-band access validation** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `out-of-band-access-validation-contract.yaml`
- Serves contract route `/api/operations/out-of-band-access-validation-contract`.
- Validator slice `out-of-band-access-validation`
- Contract `out-of-band-access-validation-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    site
    hardwareProfile
    platformRole
    owner
    supportGroup
    accessProfile
    certificateProfile
    breakGlassProfile
    cmdbContext
    evidenceManifest

Required guards and approvals (from the contract YAML).

    site-known
    hardware-profile-known
    support-owner-known
    access-profile-reviewed
    certificate-profile-reviewed
    role-model-reviewed
    break-glass-procedure-reviewed
    incident-runbook-linked
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No endpoint identifiers, serial numbers, asset tags, account identifiers, hostnames, usernames, credentials, tokens, tenant identifiers, object identifiers, private network details, raw logs, or provider payloads in committed files.
- No live provider calls.
- No live access checks.
- No live certificate checks.
- No raw inventory rows.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- OOB-safe readiness summaries only.

## Evidence

Required evidence (from the contract YAML).

    OOB readiness summary
    Access profile review
    Certificate readiness review
    Role model review
    Break-glass readiness review
    Incident readiness review
    Exception decision
    Evidence references
