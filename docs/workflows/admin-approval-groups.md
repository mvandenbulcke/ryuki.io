# Admin

## Purpose

Operator runbook for the **Admin** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `admin-approval-groups-contract.yaml`
- Serves contract route `/api/admin/approval-groups-contract`.
- Validator slice `admin-approval-groups`
- Contract `admin-approval-groups-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    default-datacenter-approver-reviewed
    group-purpose-reviewed
    delegation-boundary-reviewed
    separation-of-duties-reviewed
    break-glass-reviewed
    expiry-review-set
    evidence-redacted
    live-identity-lookup-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live identity lookup.
- No Graph calls.
- No role assignment, group membership, approval, policy, or workflow mutation.
- No provider calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw user data.
- raw group data.
- raw membership rows.
- group identifiers.
- Datacenter final approval remains the default.
- static admin approval group summaries only.
- VMware operators.
- Hyper-V operators.
- Proxmox operators.
- backup operators.
- monitoring operators.
- CMDB import/export reviewers.
- security/auditors.
- break-glass approvers.
- service desk triage.
- Placeholder refs only.

## Evidence

Required evidence (from the contract YAML).

    Approval group mapping summary
    Datacenter fallback summary
    Delegation boundary summary
    Separation of duties summary
    Evidence references
