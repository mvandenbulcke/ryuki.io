# Azure VM and landing-zone validation

## Purpose

Operator runbook for the **Azure VM and landing-zone validation** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `azure-landing-zone-validation-contract.yaml`
- Serves contract route `/api/workflows/azure-landing-zone/validation-contract`.
- Validator slice `azure-landing-zone-validation`
- Contract `azure-landing-zone-validation-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    businessPurpose
    workloadProfile
    landingZoneScopeSummary
    managementGroupSummary
    subscriptionSummary
    policyBaselineSummary
    namingTaggingSummary
    connectivitySummary
    identitySummary
    securitySummary
    vmSizingSummary
    backupMonitoringSummary
    cmdbContext
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    source-inventory-acknowledged
    safe-facts-extraction-required
    raw-alz-sources-blocked
    tenant-identifiers-blocked
    subscription-identifiers-blocked
    policy-baseline-reviewed
    naming-tagging-reviewed
    connectivity-reviewed
    identity-reviewed
    security-reviewed
    azure-vm-readiness-reviewed
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No Terraform execution, tenant-backed plan, or apply.
- No Azure, management group, subscription, policy, role, network, VM, CMDB, or ServiceNow changes.
- No tenant IDs, subscription IDs, object IDs, principal IDs, resource IDs, management group IDs, policy assignment IDs, role assignment IDs, private IPs, address CIDRs, raw ALZ sources, Terraform state, Terraform plans, credential values, secret values, access tokens, or Azure payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static Azure landing-zone validation summaries only.

## Evidence

Required evidence (from the contract YAML).

    Azure validation summary
    ALZ source inventory
    Safe facts review
    Policy baseline review
    Naming and tagging review
    Connectivity guardrail review
    Identity guardrail review
    Security guardrail review
    Azure VM readiness
    CMDB publication plan
    Evidence references
