# Platform Build Sheet

The build sheet records the decisions that shape the Ryuki platform. Source
material is referenced by stable reference code only; raw filenames, paths, and
provider detail are kept out of the committed sheet.

## Source Inputs Reviewed

The following source inputs were reviewed when assembling this build sheet. Each
row references the input by a stable reference code so the committed sheet never
exposes raw source filenames or storage paths.

| Source reference | Use In This Build Sheet |
| --- | --- |
| source-ref-product-brief | Scope, goals, and non-goals for the platform build. |
| source-ref-brand-purpose | Brand voice, naming, and presentation guidance. |
| source-ref-logo-asset | Logo and visual identity used by the portal shell. |
| source-ref-customization-spec-set | Customization specification set governing per-site deployment options. |

## P0 Foundation Backlog

Foundation items establish the cross-cutting capabilities every workflow depends
on. Each item maps to a catalog contract and a per-contract runbook under the
workflows directory; the live coverage mapping is enforced by the
`backlog-coverage` validator slice.

| Item | Outcome | Owner domain |
| --- | --- | --- |
| Brand and design token documentation | Documented brand and design tokens for the portal shell. | Platform |
| Portal information architecture | Agreed portal navigation and area structure. | Platform |
| Site catalog from safe XML facts | Site catalog derived from redacted reference facts. | Platform |
| Security baseline | Baseline security posture for the platform. | Security |
| RBAC and approval model | Role and approval model for governed actions. | Identity |
| Evidence and redaction model | Evidence capture and redaction guarantees. | Governance |
| Adapter readiness matrix | Readiness matrix across all integration adapters. | Integrations |
| Platform self-monitoring | Self-monitoring of the platform's own health. | Platform |
| Vault deployment and bootstrap | Vault deployment and bootstrap foundation. | Platform |
| Request preflight gate | Preflight readiness gate ahead of request execution. | Requests |
| Policy-as-code guardrails | Policy-as-code guardrails for governed actions. | Governance |
| Cluster capacity admission check | Capacity admission checks before placement. | Integrations |
| Customization spec governance | Governance of per-site customization specs. | Integrations |
| Backup coverage gap report | Backup coverage gap reporting. | Protect |
| Monitoring coverage gap report | Monitoring coverage gap reporting. | Observe |
| Alert routing model | Alert routing and escalation model. | Observe |
| Operator runbook launcher | Operator runbook launcher surface. | Operations |
| Incident context panel | Incident context panel for operators. | Operations |

## Core Workflow Backlog

Core workflows are the operator-facing capabilities the platform delivers. Each
row maps to a catalog contract, a per-contract runbook, and a mounted contract
endpoint; the live coverage mapping is enforced by the `backlog-coverage`
validator slice.

| Priority | Workflow | Outcome | Integrations |
| --- | --- | --- | --- |
| P0 | Request preflight and readiness gate | Preflight readiness gate ahead of execution. | Platform |
| P0 | Windows server deployment | Dry-run Windows server deployment planning. | VMware, Hyper-V, Proxmox |
| P0 | Linux server deployment | Dry-run Linux server deployment planning. | VMware, Hyper-V, Proxmox |
| P0 | Application environment deployment | Dry-run application environment deployment planning. | VMware, Hyper-V, Proxmox |
| P0 | SQL Server deployment | Dry-run SQL Server deployment planning. | VMware, Hyper-V, Proxmox |
| P0 | Datacenter readiness | Datacenter readiness review. | Platform |
| P1 | Azure VM and landing-zone validation | Static landing-zone validation planning. | Azure |
| P1 | Patch wave planning | Patch wave planning and scheduling. | Patching |
| P1 | Reboot orchestration | Dry-run reboot orchestration planning. | Patching |
| P1 | OS baseline compliance | OS baseline compliance review. | Inventory |
| P1 | Approved software deployment | Dry-run approved software deployment planning. | Software |
| P1 | VM day-2 change | Dry-run VM day-2 change planning. | VMware |
| P1 | Snapshot governance | Snapshot governance review. | VMware |
| P1 | Certificate lifecycle | Dry-run certificate lifecycle planning. | Operations |
| P1 | Dependency-aware maintenance calendar | Dependency-aware maintenance calendar. | Patching |
| P1 | Firmware compliance exceptions | Firmware compliance exception review. | Operations |
| P1 | Backup coverage gap report | Backup coverage gap reporting. | Veeam |
| P1 | Controlled restore request | Controlled restore request planning. | Veeam |
| P1 | Backup and DR assignment | Backup and DR assignment planning. | Veeam |
| P1 | Restore testing | Restore testing planning. | Veeam |
| P1 | Repository capacity forecasting | Repository capacity forecasting. | Veeam |
| P1 | Immutability and air-gap compliance | Immutability and air-gap compliance review. | Veeam |
| P1 | Application-aware backup validation | Application-aware backup validation planning. | Veeam |
| P1 | Legal hold and extended retention | Legal hold and extended retention planning. | Veeam |
| P1 | Zabbix onboarding | Zabbix onboarding planning. | Zabbix |
| P1 | Monitoring coverage gap report | Monitoring coverage gap reporting. | Zabbix |
| P1 | Alert routing and escalation | Alert routing and escalation planning. | Zabbix |
| P1 | Zabbix drift remediation | Zabbix drift remediation planning. | Zabbix |
| P1 | Synthetic service health checks | Synthetic service health check planning. | Zabbix |
| P1 | Noise and flapping remediation | Noise and flapping remediation planning. | Zabbix |
| P1 | Monitoring review queue SLA | Monitoring review queue SLA planning. | Zabbix |
| P1 | Log forwarder onboarding | Log forwarder onboarding planning. | Observe |
| P1 | CMDB Excel import | CMDB import file exchange planning. | ServiceNow |
| P1 | CMDB update export | CMDB update export file exchange planning. | ServiceNow |
| P1 | CMDB CI reconciliation | CMDB CI reconciliation planning. | CMDB |
| P1 | CMDB relationship graph | CMDB relationship graph review. | CMDB |
| P1 | Patch policy import | Patch policy import planning. | Patching |
| P1 | Incident context panel | Incident context panel for operators. | Operations |
| P2 | Future ServiceNow API integration | Future ServiceNow API integration planning. | ServiceNow |
| P2 | Knowledge suggestion from failed operations | Knowledge suggestion from failed operations. | Operations |
| P0 | Entra ID SSO and RBAC | Entra ID SSO and RBAC readiness. | Entra |
| P0 | Approval model | Approval decision readiness model. | Identity |
| P1 | AD computer object lifecycle | Dry-run AD computer object lifecycle planning. | Active Directory |
| P1 | gMSA lifecycle | Dry-run gMSA lifecycle planning. | Active Directory |
| P1 | Local admin and sudo access request | Local admin and sudo access request planning. | Identity |
| P1 | File share and NTFS recertification | File share and NTFS recertification planning. | Identity |
| P1 | Access review and ownership recertification | Access review and ownership recertification planning. | Identity |
| P1 | Cluster capacity admission | Cluster capacity admission check. | VMware |
| P1 | Customization spec governance | Customization spec governance review. | VMware |
| P1 | Object placement standards | Object placement standards review. | VMware |
| P1 | vSAN, ESXi, and host lifecycle | vSAN, ESXi, and host lifecycle review. | VMware |
| P1 | Hardware warranty and support lifecycle | Hardware warranty and support lifecycle review. | Operations |
| P1 | Network port and VLAN readiness | Network port and VLAN readiness review. | Operations |
| P1 | Out-of-band access validation | Out-of-band access validation planning. | Operations |
| P1 | VM decommission quarantine | VM decommission quarantine planning. | VMware |
| P1 | Operator runbook launcher | Operator runbook launcher surface. | Operations |
| P0 | Platform health dashboard | Platform health dashboard. | Platform |
| P1 | Break-glass emergency change | Break-glass emergency change planning. | Operations |
| P1 | Standard L1/L2 tasks | Standard L1/L2 task planning. | Operations |
| P1 | Handover and shift queue | Handover and shift queue management. | Operations |
| P1 | Maintenance and outage communications | Maintenance and outage communications planning. | Operations |
| P1 | Multi-site degradation mode | Multi-site degradation mode planning. | Operations |
| P0 | Local container skeleton | Local container readiness skeleton. | Platform |
| P0 | Kubernetes deployment skeleton | Kubernetes runtime readiness skeleton. | Platform |
| P0 | Vault deployment foundation | Vault deployment readiness foundation. | Platform |
| P1 | Platform release promotion | Platform release promotion planning. | Platform |
| P1 | Worker capability routing | Worker capability routing planning. | Platform |
| P1 | Adapter contract tests | Adapter contract test planning. | Integrations |
| P2 | Cost and capacity analytics | Cost and capacity analytics review. | Analytics |

## Information Architecture Backlog

The portal's information architecture groups capabilities into navigation areas.
Each area maps to one or more catalog contracts and runbooks; the live coverage
mapping is enforced by the `backlog-coverage` validator slice.

| Area | P0 views | Later views |
| --- | --- | --- |
| Dashboard | Global overview, risk heatmap | Trend analytics |
| Catalog | Offerings, recommendations, request form | Saved selections |
| Requests | Lifecycle, preflight, execution timeline, intake support | Bulk requests |
| Activity | Operation queue, run state, dependency replay | Live tail |
| Inventory | Site catalog, coverage, resource overview, ownership risk | Saved filters |
| CMDB | File exchange, reconciliation, relationship graph, impact analysis | Future ServiceNow API |
| Evidence | Redaction, export retention, compliance dashboard | Evidence packs |
| Operations | Runbook launcher, incident context, shift queue, emergency change, platform health, AIOps suggestions, knowledge suggestions | Operations analytics |
| Admin | RBAC, policy guardrails, adapter readiness, site catalog, worker capability, approval groups, feature flags, delegation boundary | Admin analytics |

## Data Model Themes

Data model themes are tracked per slice in the catalog contracts and the
per-contract runbooks under the workflows directory. This sheet links the source
inputs above to those decisions; it does not duplicate contract detail.
