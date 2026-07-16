# Catalog Index

Catalog files define safe seed data for requestable offerings, site facts, and future policy bindings. They must not contain credentials, tokens, tenant IDs, object IDs, private keys, encrypted XML values, or raw provider payloads.

| File | Purpose |
|---|---|
| [Site Catalog](site-catalog.yaml) | Safe XML-derived site, country, OU pattern, timezone, DHCP, organization, and Windows customization behavior facts. |
| [Offering Catalog](offering-catalog.yaml) | Planned requestable offerings grouped by lifecycle category with inputs, approvals, dry-run requirements, evidence, and integration data. |
| [Offering Recommendations Contract](offering-recommendations-contract.yaml) | Draft static recommended offerings by role, application profile, site, lifecycle category, guard, blocker, and evidence contract. |
| [Request Form Contract](request-form-contract.yaml) | Draft static request form sections, input kinds, offering input coverage, disabled submission paths, and evidence expectations. |
| [Request Lifecycle Contract](request-lifecycle-contract.yaml) | Draft intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, retire, approval, lock, and evidence contract. |
| [Request Execution Timeline Contract](request-execution-timeline-contract.yaml) | Draft request timeline, event type, evidence state, guard, blocker, and evidence-link contract. |
| [Request Intake Support Contract](request-intake-support-contract.yaml) | Draft static request template, duplicate signal, saved draft state, guard, blocker, and evidence contract. |
| [Request Preflight Contract](request-preflight-contract.yaml) | Draft static VMware, Hyper-V, and Proxmox preflight surface, stage, guard, blocker, and evidence readiness contract. |
| [Security Baseline Contract](security-baseline-contract.yaml) | Draft no-secret, RBAC, approval, dry-run, browser, network, redaction, least-privilege, and verification contract. |
| [Policy Guardrails](policy-guardrails.yaml) | Draft policy families, preflight rules, site bindings, decisions, remediation, and evidence expectations. |
| [Access Control Catalog](access-control-catalog.yaml) | Draft RBAC roles, approval actors, approval routes, execution guards, and evidence profile. |
| [Approval Decision Readiness Contract](approval-decision-readiness-contract.yaml) | Draft static approval route, decision state, delegated authority, emergency, and evidence readiness contract. |
| [RBAC Approval Model Contract](rbac-approval-model-contract.yaml) | Draft static role, capability, approval route, execution guard, separation-of-duties, and evidence contract. |
| [Entra RBAC Approval Readiness Contract](entra-rbac-approval-readiness-contract.yaml) | Draft Entra identity, role mapping, approval route, local mock boundary, break-glass, and evidence readiness contract. |
| [Access Review Recertification Contract](access-review-recertification-contract.yaml) | Draft ownership, support group, privileged access, service account, exception, and evidence review contract. |
| [AD Computer Lifecycle Contract](ad-computer-lifecycle-contract.yaml) | Draft AD computer prestage, move, disable, delete, recover, reconcile review contract. |
| [gMSA Lifecycle Contract](gmsa-lifecycle-contract.yaml) | Draft gMSA creation, assignment, validation, worker use, delegation, and retire review contract. |
| [Local Privilege Access Contract](local-privilege-access-contract.yaml) | Draft local administrator and sudo access request, expiry, approval, rollback, and evidence review contract. |
| [File Share And NTFS Recertification Contract](file-share-ntfs-recertification-contract.yaml) | Draft file share owner, group, NTFS ACL, stale access, exception, remediation, and evidence review contract. |
| [Dashboard Global Overview Contract](dashboard-global-overview-contract.yaml) | Draft static aggregate dashboard overview, status band, risk signal, and stale-data contract. |
| [Dashboard Risk Heatmap Contract](dashboard-risk-heatmap-contract.yaml) | Draft static aggregate dashboard risk heatmap, trend windows, risk bands, and stale-data contract. |
| [Evidence Manifest Catalog](evidence-manifest-catalog.yaml) | Draft evidence manifest fields, redaction states, export readiness, record types, and prohibited content. |
| [Evidence Redaction Contract](evidence-redaction-contract.yaml) | Draft static evidence redaction, export readiness, prohibited content, retention, and evidence reference contract. |
| [Evidence Export Retention Contract](evidence-export-retention-contract.yaml) | Draft static evidence export package, retention, and metadata-only audit search contract. |
| [Evidence Compliance Dashboard Contract](evidence-compliance-dashboard-contract.yaml) | Draft static aggregate evidence compliance dashboard, control status, trend, and redaction reference contract. |
| [Secret Reference Catalog](secret-reference-catalog.yaml) | Draft provider-neutral capability-registry contract for typed references, admitted provider classes, independent resolution/publication/materialization capabilities, readiness, rotation, and prohibited fields. |
| [Adapter Readiness Catalog](adapter-readiness-catalog.yaml) | Draft blocked-by-default adapter readiness contracts for VMware, Hyper-V, Proxmox, Veeam, Zabbix, and ServiceNow. |
| [Adapter Readiness Matrix Contract](adapter-readiness-matrix-contract.yaml) | Draft static adapter readiness dimensions, states, guards, blockers, and evidence contract. |
| [Adapter Contract Test Contract](adapter-contract-test-contract.yaml) | Draft mock-only adapter contract test targets, fixtures, guards, blockers, and evidence. |
| [Portal Information Architecture Contract](portal-information-architecture-contract.yaml) | Draft full-stack Leptos/Axum portal shell, primary navigation, persona, selector, browser isolation, same-origin server-function boundary, and evidence safety contract. |
| [Design System Contract](design-system-contract.yaml) | Draft Ryuki brand token, light/dark theme, accessibility, status, table, form, and evidence safety contract. |
| [UI Mockup Acceptance Contract](ui-mockup-acceptance-contract.yaml) | Draft Batch 2 shell, dashboard, catalog, request, inventory, CMDB, evidence, operations, admin, accessibility, browser isolation, and evidence safety contract. |
| [Platform Release Promotion Contract](platform-release-promotion-contract.yaml) | Draft static platform release promotion stages, render checks, approval, rollback, and evidence contract. |
| [Local Container Readiness Contract](local-container-readiness-contract.yaml) | Draft Compose file, service topology, build context, local port, network boundary, dependency, portal runtime boundary, excluded runtime, and redaction readiness contract. |
| [Kubernetes Runtime Readiness Contract](kubernetes-runtime-readiness-contract.yaml) | Draft namespace, Deployment, Service, Ingress, NetworkPolicy, ServiceAccount, image reference, runtime reference, runtime security, observability, and redaction readiness contract. |
| [Platform Database Readiness Contract](platform-database-readiness-contract.yaml) | Draft CloudNativePG PostgreSQL topology, storage, backup, restore, monitoring, secret-reference, network, and evidence readiness contract. |
| [Object Storage Readiness Contract](object-storage-readiness-contract.yaml) | Draft Azure Blob evidence, export, audit artifact, backup target, immutability, lifecycle, network, and redaction readiness contract. |
| [Registry Readiness Contract](registry-readiness-contract.yaml) | Draft Harbor project, RBAC, robot account, retention, scanner, immutability, quota, audit, and redaction readiness contract. |
| [Vault Deployment Readiness Contract](vault-deployment-readiness-contract.yaml) | Draft HashiCorp Vault Helm, HA Raft, TLS, audit, Kubernetes auth, auto-unseal, backup, workload secret delivery, and redaction readiness contract. |
| [Vault Secret Delivery Contract](vault-secret-delivery-contract.yaml) | Draft Vault Secrets Operator, VaultConnection, VaultAuth, VaultStaticSecret, destination, refresh, drift, transformation, rollout, and redaction readiness contract. |
| [CMDB File Exchange Contract](cmdb-file-exchange-contract.yaml) | Draft ServiceNow CMDB file import/export fields, evidence, rejection reasons, and no-live-API rules. |
| [ServiceNow Future API Contract](servicenow-future-api-contract.yaml) | Draft ServiceNow API readiness surfaces, guards, blockers, and redaction evidence before live API integration. |
| [Inventory Coverage Contract](inventory-coverage-contract.yaml) | Draft VMware, Hyper-V, and Proxmox inventory coverage domains, gap types, drift signals, stale-data states, and evidence requirements. |
| [Inventory Resource Overview Contract](inventory-resource-overview-contract.yaml) | Draft aggregate resource type, status signal, overview view, guard, blocker, and evidence contract. |
| [Inventory Ownership Risk Contract](inventory-ownership-risk-contract.yaml) | Draft ownership score, stale asset risk, drift timeline, guard, blocker, and evidence contract. |
| [OS Baseline Compliance Contract](os-baseline-compliance-contract.yaml) | Draft Windows/Linux baseline domains, drift signals, guards, blocked reasons, and evidence. |
| [Approved Software Deployment Contract](approved-software-deployment-contract.yaml) | Draft approved package actions, scopes, guards, blocked reasons, and evidence. |
| [Server Lifecycle Dry-Run Contract](server-lifecycle-dry-run-contract.yaml) | Draft Windows/Linux server lifecycle dry-run inputs, guards, plan sections, blocked reasons, and evidence. |
| [Application Environment Deployment Contract](application-environment-deployment-contract.yaml) | Draft tier topology, placement, DNS/IPAM, certificate, firewall, monitoring, backup, CMDB, rollback, and handover plan contract. |
| [Application Environment Retirement Contract](application-environment-retirement-contract.yaml) | Draft relationship, dependency, retention, access closure, monitoring disablement, CMDB retirement, rollback, and final hold contract. |
| [SQL Server Deployment Contract](sql-server-deployment-contract.yaml) | Draft standalone, cluster, availability, disk layout, runtime identity, SPN, backup, monitoring, CMDB, and rollback plan contract. |
| [Azure Landing-Zone Validation Contract](azure-landing-zone-validation-contract.yaml) | Draft ALZ source inventory, safe-facts, policy, naming, connectivity, identity, security, VM readiness, and CMDB validation contract. |
| [Cluster Capacity Admission Contract](cluster-capacity-admission-contract.yaml) | Draft cluster compute, storage, HA, DRS, reservation, guard, and evidence admission contract. |
| [Customization Spec Governance Contract](customization-spec-governance-contract.yaml) | Draft safe VMware, Hyper-V, and Proxmox guest customization facts, drift signals, OU derivation guards, blockers, and evidence. |
| [vCenter Object Placement Contract](vcenter-object-placement-contract.yaml) | Draft folder, cluster, resource pool, datastore, storage policy, network, tag, guard, and evidence contract. |
| [vSAN And ESXi Lifecycle Contract](vsan-esxi-lifecycle-contract.yaml) | Draft VMware, Hyper-V, and Proxmox host lifecycle, firmware, readiness, maintenance, rollback, guard, and evidence contract. |
| [VM Day-2 Change Contract](vm-day2-change-contract.yaml) | Draft VM resize, disk, NIC, cold/offline migration, tag, guard, blocked reason, and evidence contract. |
| [Snapshot Governance Contract](snapshot-governance-contract.yaml) | Draft snapshot exception, expiry, stale remediation, backup impact, guard, and evidence contract. |
| [VM Decommission Quarantine Contract](vm-decommission-quarantine-contract.yaml) | Draft VM retire quarantine, retention, monitoring, CMDB, rollback, and final disposition hold contract. |
| [Certificate Lifecycle Contract](certificate-lifecycle-contract.yaml) | Draft VMware, Hyper-V, and Proxmox certificate request, renewal, replacement, installation, rollback, guard, and evidence contract. |
| [Image Factory Contract](image-factory-contract.yaml) | Draft Windows/Linux image factory stages, promotion guards, blocked reasons, and evidence requirements. |
| [Patch Maintenance Contract](patch-maintenance-contract.yaml) | Draft patch wave and reboot orchestration dry-run inputs, guards, plan sections, blocked reasons, and evidence. |
| [Patch Policy Import Contract](patch-policy-import-contract.yaml) | Draft file-based patch policy fields, decisions, guards, blocked reasons, and wave seed evidence. |
| [Reboot Orchestration Contract](reboot-orchestration-contract.yaml) | Draft dependency-aware reboot queue states, sequencing rules, guards, blocked reasons, and evidence. |
| [Dependency-Aware Maintenance Calendar Contract](dependency-maintenance-calendar-contract.yaml) | Draft aggregate maintenance calendar, conflict review, communication draft, guard, and evidence contract. |
| [Controlled Restore Contract](controlled-restore-contract.yaml) | Draft controlled restore types, dry-run inputs, guards, plan sections, blocked reasons, and evidence. |
| [Backup Coverage Gap Contract](backup-coverage-gap-contract.yaml) | Draft aggregate backup coverage gap signals, guards, blockers, and evidence contract. |
| [Repository Capacity Forecast Contract](repository-capacity-forecast-contract.yaml) | Draft repository capacity, retention risk, growth trend, hub-spoke impact, guard, and evidence contract. |
| [Cost Capacity Analytics Contract](cost-capacity-analytics-contract.yaml) | Draft VMware, Hyper-V, and Proxmox aggregate compute, storage, backup, cost trend, efficiency, forecast, guard, and evidence contract. |
| [Immutability And Air-Gap Compliance Contract](immutability-air-gap-compliance-contract.yaml) | Draft repository immutability, air-gap, retention lock, isolation review, guard, and evidence contract. |
| [Application-Aware Backup Validation Contract](application-aware-backup-validation-contract.yaml) | Draft guest processing, SQL metadata, secret reference, policy exception, guard, and evidence contract. |
| [Backup And DR Assignment Contract](backup-dr-assignment-contract.yaml) | Draft backup policy, DR replica, tag-policy mapping, site-pairing, guard, and evidence contract. |
| [Restore Testing Contract](restore-testing-contract.yaml) | Draft restore test scheduling, restore point, verification, cadence, evidence, guard, and blocker contract. |
| [Legal Hold Retention Contract](legal-hold-retention-contract.yaml) | Draft legal hold, extended retention, approval, expiry, release, guard, and evidence contract. |
| [Zabbix Onboarding Contract](zabbix-onboarding-contract.yaml) | Draft Zabbix host group, template, proxy, maintenance, owner, dry-run plan, guard, and evidence contract. |
| [Alert Routing Contract](alert-routing-contract.yaml) | Draft alert routing dimensions, escalation stages, guards, blocked reasons, and evidence. |
| [Monitoring Coverage Gap Contract](monitoring-coverage-gap-contract.yaml) | Draft aggregate Zabbix host, group, template, proxy, maintenance, owner, routing gap, and evidence contract. |
| [Zabbix Drift Remediation Contract](zabbix-drift-remediation-contract.yaml) | Draft Zabbix group, template, proxy, maintenance-window drift, guard, and evidence contract. |
| [Synthetic Health Check Contract](synthetic-health-check-contract.yaml) | Draft web, API, DNS, certificate, load-balancer, IIS synthetic check guard and evidence contract. |
| [Noise And Flapping Remediation Contract](noise-flapping-remediation-contract.yaml) | Draft repeated alert, flapping trigger, threshold, suppression proposal, guard, and evidence contract. |
| [Monitoring Review Queue Contract](monitoring-review-queue-contract.yaml) | Draft ambiguous monitoring mapping, SLA aging, escalation draft, handover, guard, and evidence contract. |
| [Log Forwarder Onboarding Contract](log-forwarder-onboarding-contract.yaml) | Draft Windows/Linux log forwarder, SIEM routing, agent policy, guard, and evidence contract. |
| [CMDB Reconciliation Contract](cmdb-reconciliation-contract.yaml) | Draft file-based CMDB reconciliation signals, decisions, update-export fields, guards, and evidence. |
| [CMDB Relationship Graph Contract](cmdb-relationship-graph-contract.yaml) | Draft aggregate-safe CMDB graph node and edge types, guards, blocked reasons, and evidence. |
| [CMDB Impact Analysis Contract](cmdb-impact-analysis-contract.yaml) | Draft aggregate-safe impact analysis, app dependency quality, sync state, guard, and evidence contract. |
| [Operator Runbook Contract](operator-runbook-contract.yaml) | Draft runbook plan types, role and worker guards, blocked reasons, and evidence. |
| [Standard Task Contract](standard-task-contract.yaml) | Draft standard L1/L2 task types, scope summaries, worker routing, guards, blockers, and evidence. |
| [Emergency Change Contract](emergency-change-contract.yaml) | Draft break-glass modes, approval and audit guards, blocked reasons, and evidence. |
| [Shift Queue Contract](shift-queue-contract.yaml) | Draft operations queue sources, safe next action guards, blocked reasons, and handover evidence. |
| [Operation Dependency Replay Contract](operation-dependency-replay-contract.yaml) | Draft operation dependency graph, replay phases, lock state, retry policy, guard, and evidence contract. |
| [Activity Operation Queue Contract](activity-operation-queue-contract.yaml) | Draft Activity operation queue, queue state, lock, retry, blocked reason, and handover contract. |
| [Operation Run State Contract](operation-run-state-contract.yaml) | Draft operation run, child operation, lock, retry, redacted log, guard, and evidence contract. |
| [Datacenter Readiness Contract](datacenter-readiness-contract.yaml) | Draft rack, power, cooling, network, storage, firmware, support, and capacity readiness guards. |
| [Out-Of-Band Access Validation Contract](out-of-band-access-validation-contract.yaml) | Draft iLO, iDRAC, XCC access, certificate, role, break-glass, and evidence readiness contract. |
| [Network And VLAN Readiness Contract](network-vlan-readiness-contract.yaml) | Draft switchport, VLAN, port group, trunk, uplink, segmentation, guard, and evidence contract. |
| [Hardware Lifecycle Contract](hardware-lifecycle-contract.yaml) | Draft hardware profiles, lifecycle states, support and firmware guards, refresh evidence, and metadata-only rules. |
| [Firmware Compliance Exception Contract](firmware-compliance-exception-contract.yaml) | Draft firmware baseline deviation, support risk, criticality, remediation, approval, and evidence contract. |
| [Platform Health Contract](platform-health-contract.yaml) | Draft platform component health signals, degraded states, stale-data markers, safe remediation, and evidence. |
| [Incident Context Contract](incident-context-contract.yaml) | Draft aggregate-safe CI, app, VM, change, backup, monitoring, CMDB, and evidence context. |
| [Worker Capability Contract](worker-capability-contract.yaml) | Draft worker capability types, routing dimensions, identity-reference guards, blocked reasons, and evidence. |
| [Admin Feature Flag Governance Contract](admin-feature-flag-governance-contract.yaml) | Draft feature flag scope, rollout plan, approval, blast-radius, rollback, and evidence contract. |
| [Admin Approval Groups Contract](admin-approval-groups-contract.yaml) | Draft approval group scope, Datacenter fallback, delegation, separation-of-duties, guard, blocker, and evidence contract. |
| [Admin Delegation Boundary Contract](admin-delegation-boundary-contract.yaml) | Draft site delegation, role scope, approval route, expiry, separation-of-duties, and evidence contract. |
| [Maintenance Communications Contract](maintenance-communications-contract.yaml) | Draft maintenance and outage message types, channels, audience guards, and evidence. |
| [Degradation Mode Contract](degradation-mode-contract.yaml) | Draft fail-safe read-only degradation scopes, stale-data guards, safe capabilities, and evidence. |
| [AIOps Suggestion Contract](aiops-suggestion-contract.yaml) | Draft aggregate-safe AIOps signal, recommendation, owner route, review route, and safe next action contract. |
| [Knowledge Suggestion Contract](knowledge-suggestion-contract.yaml) | Draft failed-operation pattern, runbook gap, recommendation export, review route, guard, and evidence contract. |

## Catalog Rules

- Store stable product metadata and safe facts only.
- Use credential-reference concepts in product docs, not concrete secret paths or secret values in catalog data.
- Keep write-capable offerings dry-run first.
- Tie catalog entries back to the canonical request lifecycle and evidence model.
- Validate catalog changes from the repository root with `cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all` (the validator defaults to the current directory; pass `--root <path>` to validate another checkout). To validate a single slice, pipe its name to `batch-validate`, for example `echo catalog | cargo run --manifest-path scripts/validator-rs/Cargo.toml -- batch-validate`.
