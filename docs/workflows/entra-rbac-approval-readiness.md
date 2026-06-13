# Entra ID SSO and RBAC

## Purpose

Operator runbook for the **Entra ID SSO and RBAC** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `entra-rbac-approval-readiness-contract.yaml`
- Serves contract route `/api/identity/entra-rbac-approval-readiness-contract`.
- Validator slice `entra-rbac-approval-readiness`
- Contract `entra-rbac-approval-readiness-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    identityProviderDecision
    runtimeConfigurationSummary
    protectedApiProfile
    appRoleMappingSummary
    groupClaimMappingSummary
    roleActionMatrix
    approvalRouteSummary
    localMockBoundary
    breakGlassSummary
    evidenceManifest

Required guards and approvals (from the contract YAML).

    identity-provider-confirmed
    runtime-config-externalized
    protected-api-profile-reviewed
    app-role-mapping-reviewed
    group-claim-mapping-reviewed
    role-action-matrix-reviewed
    approval-routes-reviewed
    local-mock-boundary-enforced
    break-glass-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live authentication or token validation.
- No Microsoft Graph calls or Entra group lookup.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Use static readiness summaries only.

## Evidence

Required evidence (from the contract YAML).

    Identity readiness summary
    Runtime configuration review
    Protected API readiness
    Role mapping review
    Approval route review
    Local mock boundary
    Break-glass review
    Evidence references
