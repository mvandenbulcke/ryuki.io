# Application environment deployment

## Purpose

Operator runbook for the **Application environment deployment** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `application-environment-deployment-contract.yaml`
- Serves contract route `/api/workflows/application-environment/deployment-contract`.
- Validator slice `application-environment-deployment`
- Contract `application-environment-deployment-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    businessPurpose
    applicationProfile
    environmentProfile
    tierProfile
    site
    criticality
    owner
    supportGroup
    dnsIpamSummary
    certificateSummary
    networkFlowSummary
    monitoringProfile
    backupPolicy
    cmdbRelationshipSummary
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    request-preflight-ready
    tier-topology-reviewed
    placement-plan-reviewed
    dns-ipam-plan-reviewed
    certificate-plan-reviewed
    network-flow-reviewed
    monitoring-plan-reviewed
    backup-plan-reviewed
    cmdb-relationship-reviewed
    approval-route-assigned
    rollback-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live VMware, Hyper-V, Proxmox, DNS/IPAM, certificate, firewall, monitoring, backup, or CMDB changes.
- No raw DNS records, host identifiers, FQDNs, IP addresses, firewall rules, CMDB rows, recipient data, credentials, or provider payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- VMware, Hyper-V, and Proxmox parity is limited to static dry-run summaries.
- static application environment deployment summaries only.

## Evidence

Required evidence (from the contract YAML).

    Environment summary
    Tier topology
    Placement plan
    DNS and IPAM plan
    Certificate plan
    Network flow plan
    Monitoring plan
    Backup plan
    CMDB relationship plan
    Rollback plan
    Handover plan
    Evidence references
