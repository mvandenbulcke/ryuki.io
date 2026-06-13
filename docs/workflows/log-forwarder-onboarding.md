# Log forwarder onboarding

## Purpose

Operator runbook for the **Log forwarder onboarding** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `log-forwarder-onboarding-contract.yaml`
- Serves contract route `/api/observe/log-forwarder-onboarding-contract`.
- Validator slice `log-forwarder-onboarding`
- Contract `log-forwarder-onboarding-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    osFamily
    site
    environment
    logProfile
    forwardingPolicy
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    os-family-supported
    log-profile-known
    forwarding-policy-known
    owner-known
    support-group-known
    route-reviewed
    installation-plan-dry-run
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live agent installation.
- No live configuration changes.
- No log platform mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- log onboarding summaries only.

## Evidence

Required evidence (from the contract YAML).

    Onboarding summary
    Log source scope
    Forwarding policy
    Route review
    Agent readiness
    Remediation dry-run plan
    Approval route
    Evidence references
