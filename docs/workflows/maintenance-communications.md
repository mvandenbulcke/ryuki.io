# Maintenance and outage communications

## Purpose

Operator runbook for the **Maintenance and outage communications** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `maintenance-communications-contract.yaml`
- Serves contract route `/api/operations/maintenance-communications-contract`.
- Validator slice `maintenance-communications`
- Contract `maintenance-communications-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    maintenanceWindow
    affectedServices
    ciRelationshipSummary
    owner
    supportGroup
    audience
    messageType
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    maintenance-window-known
    affected-ci-known
    owner-known
    audience-approved
    message-template-approved
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No raw recipient data, hostnames, usernames, credentials, tokens, tenant identifiers, object identifiers, endpoint names, private network details, raw logs, or provider payloads in committed files.
- No live provider calls.
- No live notification send.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Communication draft
    Affected CI summary
    Audience decision
    Owner approval
    Maintenance window
    Channel plan
    Handover notes
    Evidence references
