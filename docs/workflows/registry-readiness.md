# Registry Readiness

## Purpose

This slice adds a static readiness contract for the on-prem Harbor registry used by Ryuki platform images. It turns the registry decision into reviewable project, RBAC, robot account, retention, vulnerability scanning, tag immutability, quota, audit, replication, webhook, and evidence gates without calling Harbor APIs or moving images.

## Contract

- Contract definition `registry-readiness-contract.yaml`
- Validator slice `registry-readiness`
- Contract `registry-readiness-contract.yaml` is marked draft (version 1)

Endpoint: `/api/platform/registry-readiness-contract`

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    registryUseCaseSummary
    projectTopologySummary
    rbacModelSummary
    robotAccountScopeSummary
    retentionPolicySummary
    immutabilityRuleSummary
    scannerProfile
    quotaSummary
    auditLogSummary
    replicationWebhookSummary
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    harbor-provider-reviewed
    project-creation-reviewed
    project-rbac-reviewed
    robot-account-scope-reviewed
    retention-policy-reviewed
    vulnerability-scanner-reviewed
    immutability-rule-reviewed
    quota-reviewed
    audit-log-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- Use static registry readiness summaries only.
- No Harbor API calls, registry push, registry pull, project mutation, robot account mutation, retention policy mutation, immutability rule mutation, scanner mutation, replication mutation, or webhook mutation.
- No registry URLs, project names, repository names, image tags, image digests, robot account names, robot secrets, user names, group names, OIDC identifiers, LDAP identifiers, CVE rows, webhook URLs, replication endpoints, tenant identifiers, object identifiers, private network details, credentials, tokens, raw registry payloads, raw scanner payloads, or provider payloads.
- No live provider calls.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Registry readiness summary
    System security review
    Project topology review
    RBAC and robot scope review
    Retention policy review
    Immutability rule review
    Scanner readiness review
    Quota review
    Audit log review
    Evidence references
