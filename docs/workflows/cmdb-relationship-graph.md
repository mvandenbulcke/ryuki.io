# CMDB relationship graph

## Purpose

Operator runbook for the **CMDB relationship graph** / **CMDB** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `cmdb-relationship-graph-contract.yaml`
- Serves contract route `/api/cmdb/relationship-graph-contract`.
- Validator slice `cmdb-relationship-graph`
- Contract `cmdb-relationship-graph-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    ciClass
    relationshipSource
    relationshipTarget
    relationshipType
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    cmdb-file-contract-validated
    ci-identity-known
    relationship-source-known
    relationship-direction-known
    stale-data-marked
    reviewer-approval-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live ServiceNow API calls.
- No raw provider payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate-safe graph summaries.

## Evidence

Required evidence (from the contract YAML).

    Relationship graph summary
    CI identity summary
    Relationship source
    Relationship direction
    Accepted/rejected edges
    Reviewer approval
    Evidence references
