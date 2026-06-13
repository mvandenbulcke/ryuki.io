# Monitoring review queue SLA

## Purpose

Operator runbook for the **Monitoring review queue SLA** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `monitoring-review-queue-contract.yaml`
- Serves contract route `/api/observe/monitoring-review-queue-contract`.
- Validator slice `monitoring-review-queue`
- Contract `monitoring-review-queue-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    queueItemSummary
    platformCiKey
    site
    environment
    monitoringProfile
    owner
    supportGroup
    slaPolicy
    evidenceManifest

Required guards and approvals (from the contract YAML).

    queue-item-summary-known
    mapping-ambiguity-marked
    owner-known
    support-group-known
    sla-policy-known
    escalation-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live ServiceNow task creation.
- No live escalation.
- No Zabbix mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate queue summaries only.

## Evidence

Required evidence (from the contract YAML).

    Queue summary
    Mapping ambiguity
    Ownership review
    SLA status
    Escalation draft
    Handover notes
    Approval route
    Evidence references
