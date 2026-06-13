# Customization spec governance

## Purpose

Operator runbook for the **Customization spec governance** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `customization-spec-governance-contract.yaml`
- Serves contract route `/api/integrations/vmware/customization-spec-governance-contract`.
- Validator slice `customization-spec-governance`
- Contract `customization-spec-governance-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    site
    country
    hypervisorPlatform
    customizationSpecReference
    domainReference
    ouPatternReference
    timezoneCode
    dhcpNetworkBehavior
    organizationLabel
    windowsBehavior
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    site-known
    safe-facts-from-catalog
    ou-pattern-derived
    free-form-ou-blocked
    encrypted-xml-excluded
    drift-check-reviewed
    stale-data-marked
    owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live guest customization execution.
- No raw XML or encrypted XML values.
- No free-form OU paths.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- calling VMware, Hyper-V, or Proxmox.
- safe fact summaries only.
- VMware.
- Hyper-V.
- Proxmox.
- Guest customization parity is limited to static safe-fact summaries.

## Evidence

Required evidence (from the contract YAML).

    Safe customization fact summary
    Site catalog version
    Site mapping decision
    OU placement decision
    Timezone and DHCP behavior
    Windows behavior review
    Drift review
    Blocked findings
    Evidence references
