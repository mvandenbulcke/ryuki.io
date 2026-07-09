#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::skip_while_next)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::unnecessary_filter_map)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::question_mark)]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

mod access_review_recertification;
mod activity_operation_queue;
mod ad_computer_lifecycle;
mod adapter_contract;
mod adapter_contract_test;
mod adapter_readiness_matrix;
mod admin_approval_groups;
mod admin_delegation_boundary;
mod admin_feature_flag;
mod aiops_suggestion;
mod alert_routing;
mod api_token_safety;
mod app_skeleton;
mod application_aware_backup;
mod application_environment_deployment;
mod application_environment_retirement;
mod approval_decision_readiness;
mod approved_software_deployment;
mod azure_landing_zone;
mod backlog_coverage;
mod backup_coverage_gap;
mod backup_dr_assignment;
mod catalog;
mod certificate_lifecycle;
mod check_config;
mod cluster_capacity_admission;
mod cmdb_file_exchange;
mod cmdb_impact_analysis;
mod cmdb_reconciliation;
mod cmdb_relationship_graph;
pub(crate) mod compose;
mod control_plane_db_backup;
mod controlled_restore;
mod cost_capacity;
mod customization_spec_governance;
mod dashboard_global_overview;
mod dashboard_risk_heatmap;
mod datacenter_readiness;
mod degradation_mode;
mod dependency_maintenance_calendar;
mod deployment_input_template;
mod design_system;
mod docker_image;
mod emergency_change;
mod entra_rbac_approval_readiness;
mod evidence_compliance_dashboard;
mod evidence_export_retention;
mod evidence_manifest;
mod evidence_redaction_contract;
mod file_share_ntfs_recertification;
mod firmware_compliance_exception;
mod gmsa_lifecycle;
mod governance_catalog_api;
mod hardware_lifecycle;
mod image_factory;
mod immutability_air_gap_compliance;
mod incident_context;
mod inventory_coverage;
mod inventory_ownership_risk;
mod inventory_resource_overview;
mod knowledge_suggestion;
mod kubernetes_manifest;
mod kubernetes_runtime_readiness;
mod legal_hold_retention;
mod local_auth;
mod local_container_readiness;
mod local_privilege_access;
mod log_forwarder_onboarding;
mod maintenance_communications;
mod monitoring_coverage_gap;
mod monitoring_review_queue;
mod network_vlan_readiness;
mod noise_flapping_remediation;
mod object_storage_readiness;
mod observability_deploy_wiring;
mod offering_catalog_api;
mod offering_recommendations;
mod operation_dependency_replay;
mod operation_run_state;
mod operations_endpoint_inventory;
mod operator_runbook;
mod os_baseline_compliance;
mod out_of_band_access;
mod patch_maintenance;
mod patch_policy_import;
mod platform_database_readiness;
mod platform_health;
mod platform_release_promotion;
mod policy_guardrail_api;
mod portal_information_architecture;
mod rbac_approval_model;
mod reboot_orchestration;
mod registry_readiness;
mod release_engineering;
mod release_image_builds;
mod repository_capacity_forecast;
mod request_execution_timeline;
mod request_form_contract;
mod request_intake_support;
mod request_lifecycle;
mod request_preflight;
mod restore_testing;
mod rust_contract;
mod ryuki_api;
mod ryuki_engine;
mod scaffold_docs;
mod secret_reference;
mod security_baseline;
mod sensitive_output_guardrails;
mod server_lifecycle;
mod servicenow_future_api;
mod shift_queue;
mod site_catalog_contract;
mod snapshot_governance;
mod sql_server_deployment;
mod standard_task;
mod synthetic_health_check;
mod ui_mockup_acceptance;
mod vault_deployment_readiness;
mod vault_foundation;
mod vault_secret_delivery;
mod vcenter_object_placement;
mod vm_day2_change;
mod vm_decommission_quarantine;
mod vsan_esxi_lifecycle;
mod worker_capability;
mod yaml_utils;
mod zabbix_drift_remediation;
mod zabbix_onboarding;

const BUILD_SHEET_PATH: &str = "docs/platform-build-sheet.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const WORKFLOW_README_PATH: &str = "docs/workflows/README.md";
// The legacy C# API (api/Ryuki.Platform.Api/*) was deleted when the platform
// was ported to Rust. The shared "program" input is now the Rust route/handler
// source and the shared "API readme" input is the generated endpoint inventory
// produced by the `generate-endpoints-doc` subcommand.
const RUST_API_CONTRACTS_PATH: &str = "sources/ryuki-api/src/contracts.rs";
const RUST_API_MAIN_PATH: &str = "sources/ryuki-api/src/main.rs";
const RUST_API_BOUNDARY_PATH: &str = "sources/ryuki-api/src/boundary.rs";
const API_ENDPOINTS_DOC_PATH: &str = "docs/api/endpoints.md";

// Registry invariants (enforced by the `coverage_registry_rows_reference_real_artifacts`
// self-check test):
// - column 3 (catalog file) must exist under catalog/
// - column 4 (workflow doc) must exist under docs/workflows/ or be listed in
//   PENDING_WORKFLOW_DOCS until the docs/workflows tree is authored
// - column 5 (endpoint) must appear in the Rust API sources
//
// Registry repair notes (C# API removal):
// - The legacy /api/status/* rows pointed at routes that only existed in the
//   deleted C# API. Each surviving row now references the mounted Rust route
//   that serves the slice's contract (module constants where the slice module
//   declares one, e.g. image-factory -> /api/images/factory-contract).
// - infrastructure slices without a contract route of their own reference the
//   mounted readiness/contract route that covers the same artifact: compose ->
//   local-container-readiness, kubernetes-manifest -> kubernetes-runtime-readiness,
//   docker-image and release-image-builds -> release-promotion, vault-foundation ->
//   vault-deployment-readiness, sensitive-output-guardrails -> evidence-redaction,
//   app-skeleton -> /health (the skeleton's liveness surface), backlog-coverage and
//   ryuki-api -> /api/platform/summary.
// - Deleted rows (no validating module or no real artifact/endpoint to check):
//   "Adapter contract coverage" (slice name resolved to no dispatcher entry; the
//   adapter contract surface is covered by the adapter-contracts and
//   adapter-contract-test rows), "Deployment input template" and "Operations
//   endpoint inventory" (their docs/source-inputs and docs/operations artifacts
//   were never created and no mounted route exists; re-register them when those
//   docs trees are authored).
const COVERAGE_TSV: &str = r#"
workflow	Request preflight and readiness gate	request-preflight-contract.yaml	request-preflight.md	/api/requests/preflight-contract
workflow	Windows server deployment	server-lifecycle-dry-run-contract.yaml	server-lifecycle-dry-run.md	/api/workflows/server-lifecycle/dry-run-contract
workflow	Linux server deployment	server-lifecycle-dry-run-contract.yaml	server-lifecycle-dry-run.md	/api/workflows/server-lifecycle/dry-run-contract
workflow	Application environment deployment	application-environment-deployment-contract.yaml	application-environment-deployment.md	/api/workflows/application-environment/deployment-contract
workflow	SQL Server deployment	sql-server-deployment-contract.yaml	sql-server-deployment.md	/api/workflows/sql-server/deployment-contract
workflow	Datacenter readiness	datacenter-readiness-contract.yaml	datacenter-readiness.md	/api/operations/datacenter-readiness-contract
workflow	Azure VM and landing-zone validation	azure-landing-zone-validation-contract.yaml	azure-landing-zone-validation.md	/api/workflows/azure-landing-zone/validation-contract
workflow	Patch wave planning	patch-maintenance-contract.yaml	patch-maintenance.md	/api/patching/maintenance-contract
workflow	Reboot orchestration	reboot-orchestration-contract.yaml	reboot-orchestration.md	/api/patching/reboot-orchestration-contract
workflow	OS baseline compliance	os-baseline-compliance-contract.yaml	os-baseline-compliance.md	/api/inventory/os-baseline-compliance-contract
workflow	Approved software deployment	approved-software-deployment-contract.yaml	approved-software-deployment.md	/api/software/approved-deployment-contract
workflow	VM day-2 change	vm-day2-change-contract.yaml	vm-day2-change.md	/api/integrations/vmware/day2-change-contract
workflow	Snapshot governance	snapshot-governance-contract.yaml	snapshot-governance.md	/api/integrations/vmware/snapshot-governance-contract
workflow	Certificate lifecycle	certificate-lifecycle-contract.yaml	certificate-lifecycle.md	/api/operations/certificate-lifecycle-contract
workflow	Dependency-aware maintenance calendar	dependency-maintenance-calendar-contract.yaml	dependency-maintenance-calendar.md	/api/patching/maintenance-calendar-contract
workflow	Firmware compliance exceptions	firmware-compliance-exception-contract.yaml	firmware-compliance-exception.md	/api/operations/firmware-compliance-exception-contract
workflow	Backup coverage gap report	backup-coverage-gap-contract.yaml	backup-coverage-gap.md	/api/protect/backup-coverage-gap-contract
workflow	Controlled restore request	controlled-restore-contract.yaml	controlled-restore.md	/api/protect/controlled-restore-contract
workflow	Backup and DR assignment	backup-dr-assignment-contract.yaml	backup-dr-assignment.md	/api/protect/backup-dr-assignment-contract
workflow	Restore testing	restore-testing-contract.yaml	restore-testing.md	/api/protect/restore-testing-contract
workflow	Repository capacity forecasting	repository-capacity-forecast-contract.yaml	repository-capacity-forecast.md	/api/protect/repository-capacity-contract
workflow	Immutability and air-gap compliance	immutability-air-gap-compliance-contract.yaml	immutability-air-gap-compliance.md	/api/protect/immutability-air-gap-compliance-contract
workflow	Application-aware backup validation	application-aware-backup-validation-contract.yaml	application-aware-backup-validation.md	/api/protect/application-aware-backup-validation-contract
workflow	Legal hold and extended retention	legal-hold-retention-contract.yaml	legal-hold-retention.md	/api/protect/legal-hold-retention-contract
workflow	Zabbix onboarding	zabbix-onboarding-contract.yaml	zabbix-onboarding.md	/api/observe/zabbix-onboarding-contract
workflow	Monitoring coverage gap report	monitoring-coverage-gap-contract.yaml	monitoring-coverage-gap.md	/api/observe/monitoring-coverage-gap-contract
workflow	Alert routing and escalation	alert-routing-contract.yaml	alert-routing.md	/api/observe/alert-routing-contract
workflow	Zabbix drift remediation	zabbix-drift-remediation-contract.yaml	zabbix-drift-remediation.md	/api/observe/zabbix-drift-remediation-contract
workflow	Synthetic service health checks	synthetic-health-check-contract.yaml	synthetic-health-checks.md	/api/observe/synthetic-health-check-contract
workflow	Noise and flapping remediation	noise-flapping-remediation-contract.yaml	noise-flapping-remediation.md	/api/observe/noise-flapping-remediation-contract
workflow	Monitoring review queue SLA	monitoring-review-queue-contract.yaml	monitoring-review-queue.md	/api/observe/monitoring-review-queue-contract
workflow	Log forwarder onboarding	log-forwarder-onboarding-contract.yaml	log-forwarder-onboarding.md	/api/observe/log-forwarder-onboarding-contract
workflow	CMDB Excel import	cmdb-file-exchange-contract.yaml	cmdb-file-exchange.md	/api/integrations/servicenow/cmdb-file-contract
workflow	CMDB update export	cmdb-file-exchange-contract.yaml	cmdb-file-exchange.md	/api/integrations/servicenow/cmdb-file-contract
workflow	CMDB CI reconciliation	cmdb-reconciliation-contract.yaml	cmdb-reconciliation.md	/api/cmdb/reconciliation-contract
workflow	CMDB relationship graph	cmdb-relationship-graph-contract.yaml	cmdb-relationship-graph.md	/api/cmdb/relationship-graph-contract
workflow	Patch policy import	patch-policy-import-contract.yaml	patch-policy-import.md	/api/patching/policy-import-contract
workflow	Incident context panel	incident-context-contract.yaml	incident-context.md	/api/operations/incident-context-contract
workflow	Future ServiceNow API integration	servicenow-future-api-contract.yaml	servicenow-future-api.md	/api/integrations/servicenow/future-api-contract
workflow	Knowledge suggestion from failed operations	knowledge-suggestion-contract.yaml	knowledge-suggestion.md	/api/operations/knowledge-suggestion-contract
workflow	Entra ID SSO and RBAC	entra-rbac-approval-readiness-contract.yaml	entra-rbac-approval-readiness.md	/api/identity/entra-rbac-approval-readiness-contract
workflow	Approval model	approval-decision-readiness-contract.yaml	approval-decision-readiness.md	/api/approvals/decision-readiness-contract
workflow	AD computer object lifecycle	ad-computer-lifecycle-contract.yaml	ad-computer-lifecycle.md	/api/identity/ad-computer-lifecycle-contract
workflow	gMSA lifecycle	gmsa-lifecycle-contract.yaml	gmsa-lifecycle.md	/api/identity/gmsa-lifecycle-contract
workflow	Local admin and sudo access request	local-privilege-access-contract.yaml	local-privilege-access.md	/api/identity/local-privilege-access-contract
workflow	File share and NTFS recertification	file-share-ntfs-recertification-contract.yaml	file-share-ntfs-recertification.md	/api/identity/file-share-ntfs-recertification-contract
workflow	Access review and ownership recertification	access-review-recertification-contract.yaml	access-review-recertification.md	/api/identity/access-review-recertification-contract
workflow	Cluster capacity admission	cluster-capacity-admission-contract.yaml	cluster-capacity-admission.md	/api/integrations/vmware/cluster-capacity-admission-contract
workflow	Customization spec governance	customization-spec-governance-contract.yaml	customization-spec-governance.md	/api/integrations/vmware/customization-spec-governance-contract
workflow	Object placement standards	vcenter-object-placement-contract.yaml	vcenter-object-placement.md	/api/integrations/vmware/object-placement-contract
workflow	vSAN, ESXi, and host lifecycle	vsan-esxi-lifecycle-contract.yaml	vsan-esxi-lifecycle.md	/api/integrations/vmware/vsan-esxi-lifecycle-contract
workflow	Hardware warranty and support lifecycle	hardware-lifecycle-contract.yaml	hardware-lifecycle.md	/api/operations/hardware-lifecycle-contract
workflow	Network port and VLAN readiness	network-vlan-readiness-contract.yaml	network-vlan-readiness.md	/api/operations/network-vlan-readiness-contract
workflow	Out-of-band access validation	out-of-band-access-validation-contract.yaml	out-of-band-access-validation.md	/api/operations/out-of-band-access-validation-contract
workflow	VM decommission quarantine	vm-decommission-quarantine-contract.yaml	vm-decommission-quarantine.md	/api/integrations/vmware/decommission-quarantine-contract
workflow	Operator runbook launcher	operator-runbook-contract.yaml	operator-runbook.md	/api/operations/runbook-launch-contract
workflow	Platform health dashboard	platform-health-contract.yaml	platform-health.md	/api/operations/platform-health-contract
workflow	Break-glass emergency change	emergency-change-contract.yaml	emergency-change.md	/api/operations/emergency-change-contract
workflow	Standard L1/L2 tasks	standard-task-contract.yaml	standard-tasks.md	/api/operations/standard-task-contract
workflow	Handover and shift queue	shift-queue-contract.yaml	shift-queue.md	/api/operations/shift-queue-contract
workflow	Maintenance and outage communications	maintenance-communications-contract.yaml	maintenance-communications.md	/api/operations/maintenance-communications-contract
workflow	Multi-site degradation mode	degradation-mode-contract.yaml	degradation-mode.md	/api/operations/degradation-mode-contract
workflow	Local container skeleton	local-container-readiness-contract.yaml	local-container-readiness.md	/api/platform/local-container-readiness-contract
workflow	Kubernetes deployment skeleton	kubernetes-runtime-readiness-contract.yaml	kubernetes-runtime-readiness.md	/api/platform/kubernetes-runtime-readiness-contract
workflow	Vault deployment foundation	vault-deployment-readiness-contract.yaml	vault-deployment-readiness.md	/api/platform/vault-deployment-readiness-contract
workflow	Platform release promotion	platform-release-promotion-contract.yaml	platform-release-promotion.md	/api/platform/release-promotion-contract
workflow	Worker capability routing	worker-capability-contract.yaml	worker-capability-routing.md	/api/admin/worker-capability-contract
workflow	Adapter contract tests	adapter-contract-test-contract.yaml	adapter-contract-tests.md	/api/integrations/adapter-contract-test-contract
workflow	Cost and capacity analytics	cost-capacity-analytics-contract.yaml	cost-capacity-analytics.md	/api/analytics/cost-capacity-contract
foundation	Brand and design token documentation	design-system-contract.yaml	design-system.md	/api/platform/design-system-contract
foundation	Portal information architecture	portal-information-architecture-contract.yaml	portal-information-architecture.md	/api/platform/portal-information-architecture-contract
foundation	Site catalog from safe XML facts	site-catalog.yaml	site-catalog.md	/api/catalog/site-catalog-contract
foundation	Security baseline	security-baseline-contract.yaml	security-baseline.md	/api/platform/security-baseline-contract
foundation	RBAC and approval model	rbac-approval-model-contract.yaml	rbac-approval-model.md	/api/identity/rbac-approval-model-contract
foundation	Evidence and redaction model	evidence-redaction-contract.yaml	evidence-redaction.md	/api/catalog/evidence-redaction-contract
foundation	Adapter readiness matrix	adapter-readiness-matrix-contract.yaml	adapter-readiness-matrix.md	/api/integrations/adapter-readiness-matrix-contract
foundation	Platform self-monitoring	platform-health-contract.yaml	platform-health.md	/api/operations/platform-health-contract
foundation	Vault deployment and bootstrap	vault-deployment-readiness-contract.yaml	vault-deployment-readiness.md	/api/platform/vault-deployment-readiness-contract
foundation	Request preflight gate	request-preflight-contract.yaml	request-preflight.md	/api/requests/preflight-contract
foundation	Policy-as-code guardrails	policy-guardrails.yaml	policy-guardrails.md	/api/catalog/policy-guardrails-contract
foundation	Cluster capacity admission check	cluster-capacity-admission-contract.yaml	cluster-capacity-admission.md	/api/integrations/vmware/cluster-capacity-admission-contract
foundation	Customization spec governance	customization-spec-governance-contract.yaml	customization-spec-governance.md	/api/integrations/vmware/customization-spec-governance-contract
foundation	Backup coverage gap report	backup-coverage-gap-contract.yaml	backup-coverage-gap.md	/api/protect/backup-coverage-gap-contract
foundation	Monitoring coverage gap report	monitoring-coverage-gap-contract.yaml	monitoring-coverage-gap.md	/api/observe/monitoring-coverage-gap-contract
foundation	Alert routing model	alert-routing-contract.yaml	alert-routing.md	/api/observe/alert-routing-contract
foundation	Operator runbook launcher	operator-runbook-contract.yaml	operator-runbook.md	/api/operations/runbook-launch-contract
foundation	Incident context panel	incident-context-contract.yaml	incident-context.md	/api/operations/incident-context-contract
ia	Dashboard	dashboard-global-overview-contract.yaml	dashboard-global-overview.md	/api/dashboard/global-overview-contract
ia	Dashboard	dashboard-risk-heatmap-contract.yaml	dashboard-risk-heatmap.md	/api/dashboard/risk-heatmap-contract
ia	Catalog	offering-catalog.yaml	offering-catalog.md	/api/catalog/offerings-contract
ia	Catalog	offering-recommendations-contract.yaml	offering-recommendations.md	/api/catalog/recommendations-contract
ia	Catalog	request-form-contract.yaml	request-form-contract.md	/api/catalog/request-form-contract
ia	Requests	request-lifecycle-contract.yaml	request-lifecycle.md	/api/requests/lifecycle-contract
ia	Requests	request-preflight-contract.yaml	request-preflight.md	/api/requests/preflight-contract
ia	Requests	request-execution-timeline-contract.yaml	request-execution-timeline.md	/api/requests/execution-timeline-contract
ia	Requests	request-intake-support-contract.yaml	request-intake-support.md	/api/requests/intake-support-contract
ia	Activity	activity-operation-queue-contract.yaml	activity-operation-queue.md	/api/operations/activity-queue-contract
ia	Activity	operation-run-state-contract.yaml	operation-run-state.md	/api/operations/run-state-contract
ia	Activity	operation-dependency-replay-contract.yaml	operation-dependency-replay.md	/api/operations/dependency-replay-contract
ia	Inventory	site-catalog.yaml	site-catalog.md	/api/catalog/site-catalog-contract
ia	Inventory	inventory-coverage-contract.yaml	inventory-coverage.md	/api/inventory/coverage-contract
ia	Inventory	inventory-resource-overview-contract.yaml	inventory-resource-overview.md	/api/inventory/resource-overview-contract
ia	Inventory	inventory-ownership-risk-contract.yaml	inventory-ownership-risk.md	/api/inventory/ownership-risk-contract
ia	CMDB	cmdb-file-exchange-contract.yaml	cmdb-file-exchange.md	/api/integrations/servicenow/cmdb-file-contract
ia	CMDB	cmdb-reconciliation-contract.yaml	cmdb-reconciliation.md	/api/cmdb/reconciliation-contract
ia	CMDB	cmdb-relationship-graph-contract.yaml	cmdb-relationship-graph.md	/api/cmdb/relationship-graph-contract
ia	CMDB	cmdb-impact-analysis-contract.yaml	cmdb-impact-analysis.md	/api/cmdb/impact-analysis-contract
ia	CMDB	servicenow-future-api-contract.yaml	servicenow-future-api.md	/api/integrations/servicenow/future-api-contract
ia	Evidence	evidence-redaction-contract.yaml	evidence-redaction.md	/api/catalog/evidence-redaction-contract
ia	Evidence	evidence-export-retention-contract.yaml	evidence-export-retention.md	/api/evidence/export-retention-contract
ia	Evidence	evidence-compliance-dashboard-contract.yaml	evidence-compliance-dashboard.md	/api/evidence/compliance-dashboard-contract
ia	Operations	operator-runbook-contract.yaml	operator-runbook.md	/api/operations/runbook-launch-contract
ia	Operations	incident-context-contract.yaml	incident-context.md	/api/operations/incident-context-contract
ia	Operations	shift-queue-contract.yaml	shift-queue.md	/api/operations/shift-queue-contract
ia	Operations	emergency-change-contract.yaml	emergency-change.md	/api/operations/emergency-change-contract
ia	Operations	platform-health-contract.yaml	platform-health.md	/api/operations/platform-health-contract
ia	Operations	aiops-suggestion-contract.yaml	aiops-suggestion.md	/api/operations/aiops-suggestion-contract
ia	Operations	knowledge-suggestion-contract.yaml	knowledge-suggestion.md	/api/operations/knowledge-suggestion-contract
ia	Admin	rbac-approval-model-contract.yaml	rbac-approval-model.md	/api/identity/rbac-approval-model-contract
ia	Admin	policy-guardrails.yaml	policy-guardrails.md	/api/catalog/policy-guardrails-contract
ia	Admin	adapter-readiness-matrix-contract.yaml	adapter-readiness-matrix.md	/api/integrations/adapter-readiness-matrix-contract
ia	Admin	site-catalog.yaml	site-catalog.md	/api/catalog/site-catalog-contract
ia	Admin	worker-capability-contract.yaml	worker-capability-routing.md	/api/admin/worker-capability-contract
ia	Admin	admin-approval-groups-contract.yaml	admin-approval-groups.md	/api/admin/approval-groups-contract
ia	Admin	admin-feature-flag-governance-contract.yaml	admin-feature-flag-governance.md	/api/admin/feature-flag-governance-contract
ia	Admin	admin-delegation-boundary-contract.yaml	admin-delegation-boundary.md	/api/admin/delegation-boundary-contract
engine	ryuki-engine	ryuki-engine-catalog.yaml	ryuki-engine.md	/api/integrations/adapter-readiness-matrix-contract
api	ryuki-api	ryuki-api-catalog.yaml	ryuki-api.md	/api/platform/summary
slice	Adapter readiness contracts	adapter-readiness-catalog.yaml	adapter-readiness-contracts.md	/api/integrations/readiness
slice	Build sheet backlog coverage	backlog-coverage-catalog.yaml	backlog-coverage.md	/api/platform/summary
slice	Docker image build contexts	docker-image-contract.yaml	docker-image.md	/api/platform/release-promotion-contract
slice	Evidence manifest	evidence-manifest-catalog.yaml	evidence-manifest.md	/api/catalog/evidence-manifest
slice	Image factory	image-factory-contract.yaml	image-factory.md	/api/images/factory-contract
slice	Registry readiness	registry-readiness-contract.yaml	registry-readiness.md	/api/platform/registry-readiness-contract
slice	Application environment retirement	application-environment-retirement-contract.yaml	application-environment-retirement.md	/api/workflows/application-environment/retirement-contract
slice	Object storage readiness	object-storage-readiness-contract.yaml	object-storage-readiness.md	/api/platform/object-storage-readiness-contract
slice	Secret reference catalog	secret-reference-catalog.yaml	secret-reference-model.md	/api/catalog/secret-references
slice	UI mockup acceptance	ui-mockup-acceptance-contract.yaml	ui-mockup-acceptance.md	/api/platform/ui-mockup-acceptance-contract
slice	Governance catalog API	governance-catalog-api-contract.yaml	governance-catalog-api.md	/api/catalog/access-control
slice	App skeleton	app-skeleton-contract.yaml	app-skeleton.md	/health
slice	Catalog	catalog-contract.yaml	catalog.md	/api/catalog/categories
slice	Compose	compose-contract.yaml	compose.md	/api/platform/local-container-readiness-contract
slice	Kubernetes manifest	kubernetes-manifest-contract.yaml	kubernetes-manifest.md	/api/platform/kubernetes-runtime-readiness-contract
slice	Local auth	local-auth-contract.yaml	local-auth.md	/api/auth/local/roles
slice	Platform database readiness	platform-database-readiness-contract.yaml	platform-database-readiness.md	/api/platform/database-readiness-contract
slice	Release image builds	release-image-builds-contract.yaml	release-image-builds.md	/api/platform/release-promotion-contract
slice	Sensitive output guardrails	sensitive-output-guardrails-contract.yaml	sensitive-output-guardrails.md	/api/catalog/evidence-redaction-contract
slice	Vault foundation	vault-foundation-contract.yaml	vault-foundation.md	/api/platform/vault-deployment-readiness-contract
slice	Vault secret delivery	vault-secret-delivery-contract.yaml	vault-secret-delivery.md	/api/platform/vault-secret-delivery-contract
"#;

// Workflow runbook docs that COVERAGE_TSV references but that have not been
// authored yet (missing-features.md, "Catalog, contract & documentation
// integrity", implementation step 4). The full docs/workflows/ tree was
// scaffolded with `ryuki-validator scaffold-docs`, so no docs are pending;
// add an entry here only when registering a new COVERAGE_TSV row before its
// runbook lands, and remove it once the doc exists (the registry self-check
// test fails on stale entries).
const PENDING_WORKFLOW_DOCS: &[&str] = &[];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CoverageEntry {
    catalog: String,
    doc: String,
    endpoint: String,
}

#[derive(Debug, Serialize)]
struct CoverageOutput {
    workflow: BTreeMap<String, CoverageEntry>,
    foundation: BTreeMap<String, CoverageEntry>,
    information_architecture: BTreeMap<String, Vec<CoverageEntry>>,
}

#[derive(Debug, Serialize)]
struct ErrorsOutput {
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct StatsOutput {
    workflow_rows: usize,
    foundation_rows: usize,
    information_architecture_rows: usize,
}

#[derive(Debug, Serialize, Clone)]
struct SliceResult {
    slice: String,
    passed: bool,
    errors: Vec<String>,
    duration_ms: u64,
}

#[derive(Debug, Serialize)]
struct RunAllOutput {
    total: usize,
    passed: usize,
    failed: usize,
    failures: Vec<SliceResult>,
    duration_ms: u64,
}

#[derive(Debug, Serialize)]
struct WorkflowRow {
    priority: String,
    workflow: String,
    outcome: String,
    integrations: String,
}

#[derive(Debug, Serialize)]
struct FoundationRow {
    item: String,
    outcome: String,
    owner_domain: String,
}

#[derive(Debug, Serialize)]
struct InformationArchitectureRow {
    area: String,
    p0_views: String,
    later_views: String,
}

#[derive(Debug, Deserialize)]
struct Context {
    build_sheet: String,
    catalog_readme: String,
    workflow_readme: String,
    api_readme: String,
    program: String,
    #[serde(default)]
    #[allow(dead_code)]
    rust_contracts: String,
    #[serde(default)]
    #[allow(dead_code)]
    rust_api_main: String,
}

#[derive(Debug, Deserialize)]
struct ShapeInput {
    workflow: String,
    coverage: CoverageEntry,
}

#[derive(Copy, Clone)]
enum CoverageKind {
    Workflow,
    Foundation,
    InformationArchitecture,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        return Err(usage());
    };

    match command {
        "coverage" => {
            require_slice(&args)?;
            print_json(&coverage_output())
        }
        "validate" => {
            let slice = require_slice(&args)?;
            let (root, context_json) = parse_root_args(&args[2..])?;
            let errors = match slice {
                "backlog-coverage" => {
                    let context = match context_json {
                        Some(path) => read_context_json(&path)?,
                        None => read_context(&root)?,
                    };
                    validate_context(&root, &context)
                }
                "server-lifecycle-dry-run" => {
                    let path = context_json.ok_or_else(|| {
                        "server-lifecycle-dry-run validation requires --context-json".to_string()
                    })?;
                    server_lifecycle::validate_context_file(&path)?
                }
                "shift-queue" => {
                    let path = context_json.ok_or_else(|| {
                        "shift-queue validation requires --context-json".to_string()
                    })?;
                    shift_queue::validate_context_file(&path)?
                }
                "aiops-suggestion" => {
                    let path = context_json.ok_or_else(|| {
                        "aiops-suggestion validation requires --context-json".to_string()
                    })?;
                    aiops_suggestion::validate_context_file(&path)?
                }
                "admin-feature-flag-governance" => {
                    let path = context_json.ok_or_else(|| {
                        "admin-feature-flag-governance validation requires --context-json"
                            .to_string()
                    })?;
                    admin_feature_flag::validate_context_file(&path)?
                }
                "admin-approval-groups" => {
                    let path = context_json.ok_or_else(|| {
                        "admin-approval-groups validation requires --context-json".to_string()
                    })?;
                    admin_approval_groups::validate_context_file(&path)?
                }
                "approval-decision-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "approval-decision-readiness validation requires --context-json".to_string()
                    })?;
                    approval_decision_readiness::validate_context_file(&path)?
                }
                "admin-delegation-boundary" => {
                    let path = context_json.ok_or_else(|| {
                        "admin-delegation-boundary validation requires --context-json".to_string()
                    })?;
                    admin_delegation_boundary::validate_context_file(&path)?
                }
                "activity-operation-queue" => {
                    let path = context_json.ok_or_else(|| {
                        "activity-operation-queue validation requires --context-json".to_string()
                    })?;
                    activity_operation_queue::validate_context_file(&path)?
                }
                "access-review-recertification" => {
                    let path = context_json.ok_or_else(|| {
                        "access-review-recertification validation requires --context-json"
                            .to_string()
                    })?;
                    access_review_recertification::validate_context_file(&path)?
                }
                "ad-computer-lifecycle" => {
                    let path = context_json.ok_or_else(|| {
                        "ad-computer-lifecycle validation requires --context-json".to_string()
                    })?;
                    ad_computer_lifecycle::validate_context_file(&path)?
                }
                "adapter-contracts" => {
                    let path = context_json.ok_or_else(|| {
                        "adapter-contracts validation requires --context-json".to_string()
                    })?;
                    adapter_contract::validate_context_file(&path)?
                }
                "adapter-contract-test" => {
                    let path = context_json.ok_or_else(|| {
                        "adapter-contract-test validation requires --context-json".to_string()
                    })?;
                    adapter_contract_test::validate_context_file(&path)?
                }
                "adapter-readiness-matrix" => {
                    let path = context_json.ok_or_else(|| {
                        "adapter-readiness-matrix validation requires --context-json".to_string()
                    })?;
                    adapter_readiness_matrix::validate_context_file(&path)?
                }
                "alert-routing" => {
                    let path = context_json.ok_or_else(|| {
                        "alert-routing validation requires --context-json".to_string()
                    })?;
                    alert_routing::validate_context_file(&path)?
                }
                "app-skeleton" => {
                    let path = context_json.ok_or_else(|| {
                        "app-skeleton validation requires --context-json".to_string()
                    })?;
                    app_skeleton::validate_context_file(&path)?
                }
                "control-plane-db-backup" => {
                    let path = context_json.ok_or_else(|| {
                        "control-plane-db-backup validation requires --context-json".to_string()
                    })?;
                    control_plane_db_backup::validate_context_file(&path)?
                }
                "release-engineering" => {
                    let path = context_json.ok_or_else(|| {
                        "release-engineering validation requires --context-json".to_string()
                    })?;
                    release_engineering::validate_context_file(&path)?
                }
                "approved-software-deployment" => {
                    let path = context_json.ok_or_else(|| {
                        "approved-software-deployment validation requires --context-json"
                            .to_string()
                    })?;
                    approved_software_deployment::validate_context_file(&path)?
                }
                "azure-landing-zone-validation" => {
                    let path = context_json.ok_or_else(|| {
                        "azure-landing-zone-validation validation requires --context-json"
                            .to_string()
                    })?;
                    azure_landing_zone::validate_context_file(&path)?
                }
                "backup-coverage-gap" => {
                    let path = context_json.ok_or_else(|| {
                        "backup-coverage-gap validation requires --context-json".to_string()
                    })?;
                    backup_coverage_gap::validate_context_file(&path)?
                }
                "backup-dr-assignment" => {
                    let path = context_json.ok_or_else(|| {
                        "backup-dr-assignment validation requires --context-json".to_string()
                    })?;
                    backup_dr_assignment::validate_context_file(&path)?
                }
                "application-environment-deployment" => {
                    let path = context_json.ok_or_else(|| {
                        "application-environment-deployment validation requires --context-json"
                            .to_string()
                    })?;
                    application_environment_deployment::validate_context_file(&path)?
                }
                "application-environment-retirement" => {
                    let path = context_json.ok_or_else(|| {
                        "application-environment-retirement validation requires --context-json"
                            .to_string()
                    })?;
                    application_environment_retirement::validate_context_file(&path)?
                }
                "application-aware-backup" => {
                    let path = context_json.ok_or_else(|| {
                        "application-aware-backup validation requires --context-json".to_string()
                    })?;
                    application_aware_backup::validate_context_file(&path)?
                }
                "immutability-air-gap-compliance" => {
                    let path = context_json.ok_or_else(|| {
                        "immutability-air-gap-compliance validation requires --context-json"
                            .to_string()
                    })?;
                    immutability_air_gap_compliance::validate_context_file(&path)?
                }
                "certificate-lifecycle" => {
                    let path = context_json.ok_or_else(|| {
                        "certificate-lifecycle validation requires --context-json".to_string()
                    })?;
                    certificate_lifecycle::validate_context_file(&path)?
                }
                "cluster-capacity-admission" => {
                    let path = context_json.ok_or_else(|| {
                        "cluster-capacity-admission validation requires --context-json".to_string()
                    })?;
                    cluster_capacity_admission::validate_context_file(&path)?
                }
                "dependency-maintenance-calendar" => {
                    let path = context_json.ok_or_else(|| {
                        "dependency-maintenance-calendar validation requires --context-json"
                            .to_string()
                    })?;
                    dependency_maintenance_calendar::validate_context_file(&path)?
                }
                "firmware-compliance-exception" => {
                    let path = context_json.ok_or_else(|| {
                        "firmware-compliance-exception validation requires --context-json"
                            .to_string()
                    })?;
                    firmware_compliance_exception::validate_context_file(&path)?
                }
                "vsan-esxi-lifecycle" => {
                    let path = context_json.ok_or_else(|| {
                        "vsan-esxi-lifecycle validation requires --context-json".to_string()
                    })?;
                    vsan_esxi_lifecycle::validate_context_file(&path)?
                }
                "vm-day2-change" => {
                    let path = context_json.ok_or_else(|| {
                        "vm-day2-change validation requires --context-json".to_string()
                    })?;
                    vm_day2_change::validate_context_file(&path)?
                }
                "vm-decommission-quarantine" => {
                    let path = context_json.ok_or_else(|| {
                        "vm-decommission-quarantine validation requires --context-json".to_string()
                    })?;
                    vm_decommission_quarantine::validate_context_file(&path)?
                }
                "cost-capacity-analytics" => {
                    let path = context_json.ok_or_else(|| {
                        "cost-capacity-analytics validation requires --context-json".to_string()
                    })?;
                    cost_capacity::validate_context_file(&path)?
                }
                "repository-capacity-forecast" => {
                    let path = context_json.ok_or_else(|| {
                        "repository-capacity-forecast validation requires --context-json"
                            .to_string()
                    })?;
                    repository_capacity_forecast::validate_context_file(&path)?
                }
                "patch-policy-import" => {
                    let path = context_json.ok_or_else(|| {
                        "patch-policy-import validation requires --context-json".to_string()
                    })?;
                    patch_policy_import::validate_context_file(&path)?
                }
                "patch-maintenance" => {
                    let path = context_json.ok_or_else(|| {
                        "patch-maintenance validation requires --context-json".to_string()
                    })?;
                    patch_maintenance::validate_context_file(&path)?
                }
                "datacenter-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "datacenter-readiness validation requires --context-json".to_string()
                    })?;
                    datacenter_readiness::validate_context_file(&path)?
                }
                "reboot-orchestration" => {
                    let path = context_json.ok_or_else(|| {
                        "reboot-orchestration validation requires --context-json".to_string()
                    })?;
                    reboot_orchestration::validate_context_file(&path)?
                }
                "dashboard-risk-heatmap" => {
                    let path = context_json.ok_or_else(|| {
                        "dashboard-risk-heatmap validation requires --context-json".to_string()
                    })?;
                    dashboard_risk_heatmap::validate_context_file(&path)?
                }
                "dashboard-global-overview" => {
                    let path = context_json.ok_or_else(|| {
                        "dashboard-global-overview validation requires --context-json".to_string()
                    })?;
                    dashboard_global_overview::validate_context_file(&path)?
                }
                "design-system" => {
                    let path = context_json.ok_or_else(|| {
                        "design-system validation requires --context-json".to_string()
                    })?;
                    design_system::validate_context_file(&path)?
                }
                "cmdb-impact-analysis" => {
                    let path = context_json.ok_or_else(|| {
                        "cmdb-impact-analysis validation requires --context-json".to_string()
                    })?;
                    cmdb_impact_analysis::validate_context_file(&path)?
                }
                "cmdb-file-exchange" => {
                    let path = context_json.ok_or_else(|| {
                        "cmdb-file-exchange validation requires --context-json".to_string()
                    })?;
                    cmdb_file_exchange::validate_context_file(&path)?
                }
                "cmdb-relationship-graph" => {
                    let path = context_json.ok_or_else(|| {
                        "cmdb-relationship-graph validation requires --context-json".to_string()
                    })?;
                    cmdb_relationship_graph::validate_context_file(&path)?
                }
                "cmdb-reconciliation" => {
                    let path = context_json.ok_or_else(|| {
                        "cmdb-reconciliation validation requires --context-json".to_string()
                    })?;
                    cmdb_reconciliation::validate_context_file(&path)?
                }
                "compose" => {
                    let path = context_json
                        .ok_or_else(|| "compose validation requires --context-json".to_string())?;
                    compose::validate_context_file(&path)?
                }
                "catalog" => {
                    let path = context_json
                        .ok_or_else(|| "catalog validation requires --context-json".to_string())?;
                    catalog::validate_context_file(&path)?
                }
                "deployment-input-template" => {
                    let path = context_json.ok_or_else(|| {
                        "deployment-input-template validation requires --context-json".to_string()
                    })?;
                    deployment_input_template::validate_context_file(&path)?
                }
                "emergency-change" => {
                    let path = context_json.ok_or_else(|| {
                        "emergency-change validation requires --context-json".to_string()
                    })?;
                    emergency_change::validate_context_file(&path)?
                }
                "vault-foundation" => {
                    let path = context_json.ok_or_else(|| {
                        "vault-foundation validation requires --context-json".to_string()
                    })?;
                    vault_foundation::validate_context_file(&path)?
                }
                "vault-deployment-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "vault-deployment-readiness validation requires --context-json".to_string()
                    })?;
                    vault_deployment_readiness::validate_context_file(&path)?
                }
                "vault-secret-delivery" => {
                    let path = context_json.ok_or_else(|| {
                        "vault-secret-delivery validation requires --context-json".to_string()
                    })?;
                    vault_secret_delivery::validate_context_file(&path)?
                }
                "secret-reference" => {
                    let path = context_json.ok_or_else(|| {
                        "secret-reference validation requires --context-json".to_string()
                    })?;
                    secret_reference::validate_context_file(&path)?
                }
                "security-baseline" => {
                    let path = context_json.ok_or_else(|| {
                        "security-baseline validation requires --context-json".to_string()
                    })?;
                    security_baseline::validate_context_file(&path)?
                }
                "sensitive-output-guardrails" => {
                    let path = context_json.ok_or_else(|| {
                        "sensitive-output-guardrails validation requires --context-json".to_string()
                    })?;
                    sensitive_output_guardrails::validate_context_file(&path)?
                }
                "local-auth" => {
                    let path = context_json.ok_or_else(|| {
                        "local-auth validation requires --context-json".to_string()
                    })?;
                    local_auth::validate_context_file(&path)?
                }
                "local-privilege-access" => {
                    let path = context_json.ok_or_else(|| {
                        "local-privilege-access validation requires --context-json".to_string()
                    })?;
                    local_privilege_access::validate_context_file(&path)?
                }
                "file-share-ntfs-recertification" => {
                    let path = context_json.ok_or_else(|| {
                        "file-share-ntfs-recertification validation requires --context-json"
                            .to_string()
                    })?;
                    file_share_ntfs_recertification::validate_context_file(&path)?
                }
                "gmsa-lifecycle" => {
                    let path = context_json.ok_or_else(|| {
                        "gmsa-lifecycle validation requires --context-json".to_string()
                    })?;
                    gmsa_lifecycle::validate_context_file(&path)?
                }
                "evidence-manifest" => {
                    let path = context_json.ok_or_else(|| {
                        "evidence-manifest validation requires --context-json".to_string()
                    })?;
                    evidence_manifest::validate_context_file(&path)?
                }
                "evidence-redaction-contract" => {
                    let path = context_json.ok_or_else(|| {
                        "evidence-redaction-contract validation requires --context-json".to_string()
                    })?;
                    evidence_redaction_contract::validate_context_file(&path)?
                }
                "evidence-compliance-dashboard" => {
                    let path = context_json.ok_or_else(|| {
                        "evidence-compliance-dashboard validation requires --context-json"
                            .to_string()
                    })?;
                    evidence_compliance_dashboard::validate_context_file(&path)?
                }
                "evidence-export-retention" => {
                    let path = context_json.ok_or_else(|| {
                        "evidence-export-retention validation requires --context-json".to_string()
                    })?;
                    evidence_export_retention::validate_context_file(&path)?
                }
                "governance-catalog-api" => {
                    let path = context_json.ok_or_else(|| {
                        "governance-catalog-api validation requires --context-json".to_string()
                    })?;
                    governance_catalog_api::validate_context_file(&path)?
                }
                "inventory-coverage" => {
                    let path = context_json.ok_or_else(|| {
                        "inventory-coverage validation requires --context-json".to_string()
                    })?;
                    inventory_coverage::validate_context_file(&path)?
                }
                "inventory-resource-overview" => {
                    let path = context_json.ok_or_else(|| {
                        "inventory-resource-overview validation requires --context-json".to_string()
                    })?;
                    inventory_resource_overview::validate_context_file(&path)?
                }
                "inventory-ownership-risk" => {
                    let path = context_json.ok_or_else(|| {
                        "inventory-ownership-risk validation requires --context-json".to_string()
                    })?;
                    inventory_ownership_risk::validate_context_file(&path)?
                }
                "os-baseline-compliance" => {
                    let path = context_json.ok_or_else(|| {
                        "os-baseline-compliance validation requires --context-json".to_string()
                    })?;
                    os_baseline_compliance::validate_context_file(&path)?
                }
                "operation-run-state" => {
                    let path = context_json.ok_or_else(|| {
                        "operation-run-state validation requires --context-json".to_string()
                    })?;
                    operation_run_state::validate_context_file(&path)?
                }
                "operation-dependency-replay" => {
                    let path = context_json.ok_or_else(|| {
                        "operation-dependency-replay validation requires --context-json".to_string()
                    })?;
                    operation_dependency_replay::validate_context_file(&path)?
                }
                "image-factory" => {
                    let path = context_json.ok_or_else(|| {
                        "image-factory validation requires --context-json".to_string()
                    })?;
                    image_factory::validate_context_file(&path)?
                }
                "operator-runbook" => {
                    let path = context_json.ok_or_else(|| {
                        "operator-runbook validation requires --context-json".to_string()
                    })?;
                    operator_runbook::validate_context_file(&path)?
                }
                "incident-context" => {
                    let path = context_json.ok_or_else(|| {
                        "incident-context validation requires --context-json".to_string()
                    })?;
                    incident_context::validate_context_file(&path)?
                }
                "degradation-mode" => {
                    let path = context_json.ok_or_else(|| {
                        "degradation-mode validation requires --context-json".to_string()
                    })?;
                    degradation_mode::validate_context_file(&path)?
                }
                "platform-health" => {
                    let path = context_json.ok_or_else(|| {
                        "platform-health validation requires --context-json".to_string()
                    })?;
                    platform_health::validate_context_file(&path)?
                }
                "portal-information-architecture" => {
                    let path = context_json.ok_or_else(|| {
                        "portal-information-architecture validation requires --context-json"
                            .to_string()
                    })?;
                    portal_information_architecture::validate_context_file(&path)?
                }
                "ui-mockup-acceptance" => {
                    let path = context_json.ok_or_else(|| {
                        "ui-mockup-acceptance validation requires --context-json".to_string()
                    })?;
                    ui_mockup_acceptance::validate_context_file(&path)?
                }
                "platform-release-promotion" => {
                    let path = context_json.ok_or_else(|| {
                        "platform-release-promotion validation requires --context-json".to_string()
                    })?;
                    platform_release_promotion::validate_context_file(&path)?
                }
                "request-execution-timeline" => {
                    let path = context_json.ok_or_else(|| {
                        "request-execution-timeline validation requires --context-json".to_string()
                    })?;
                    request_execution_timeline::validate_context_file(&path)?
                }
                "request-lifecycle" => {
                    let path = context_json.ok_or_else(|| {
                        "request-lifecycle validation requires --context-json".to_string()
                    })?;
                    request_lifecycle::validate_context_file(&path)?
                }
                "offering-catalog-api" => {
                    let path = context_json.ok_or_else(|| {
                        "offering-catalog-api validation requires --context-json".to_string()
                    })?;
                    offering_catalog_api::validate_context_file(&path)?
                }
                "offering-recommendations" => {
                    let path = context_json.ok_or_else(|| {
                        "offering-recommendations validation requires --context-json".to_string()
                    })?;
                    offering_recommendations::validate_context_file(&path)?
                }
                "policy-guardrail-api" => {
                    let path = context_json.ok_or_else(|| {
                        "policy-guardrail-api validation requires --context-json".to_string()
                    })?;
                    policy_guardrail_api::validate_context_file(&path)?
                }
                "knowledge-suggestion" => {
                    let path = context_json.ok_or_else(|| {
                        "knowledge-suggestion validation requires --context-json".to_string()
                    })?;
                    knowledge_suggestion::validate_context_file(&path)?
                }
                "kubernetes-manifest" => {
                    let path = context_json.ok_or_else(|| {
                        "kubernetes-manifest validation requires --context-json".to_string()
                    })?;
                    kubernetes_manifest::validate_context_file(&path)?
                }
                "kubernetes-runtime-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "kubernetes-runtime-readiness validation requires --context-json"
                            .to_string()
                    })?;
                    kubernetes_runtime_readiness::validate_context_file(&path)?
                }
                "local-container-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "local-container-readiness validation requires --context-json".to_string()
                    })?;
                    local_container_readiness::validate_context_file(&path)?
                }
                "observability-deploy-wiring" => {
                    let path = context_json.ok_or_else(|| {
                        "observability-deploy-wiring validation requires --context-json".to_string()
                    })?;
                    observability_deploy_wiring::validate_context_file(&path)?
                }
                "legal-hold-retention" => {
                    let path = context_json.ok_or_else(|| {
                        "legal-hold-retention validation requires --context-json".to_string()
                    })?;
                    legal_hold_retention::validate_context_file(&path)?
                }
                "request-form-contract" => {
                    let path = context_json.ok_or_else(|| {
                        "request-form-contract validation requires --context-json".to_string()
                    })?;
                    request_form_contract::validate_context_file(&path)?
                }
                "request-preflight" => {
                    let path = context_json.ok_or_else(|| {
                        "request-preflight validation requires --context-json".to_string()
                    })?;
                    request_preflight::validate_context_file(&path)?
                }
                "rbac-approval-model" => {
                    let path = context_json.ok_or_else(|| {
                        "rbac-approval-model validation requires --context-json".to_string()
                    })?;
                    rbac_approval_model::validate_context_file(&path)?
                }
                "entra-rbac-approval-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "entra-rbac-approval-readiness validation requires --context-json"
                            .to_string()
                    })?;
                    entra_rbac_approval_readiness::validate_context_file(&path)?
                }
                "registry-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "registry-readiness validation requires --context-json".to_string()
                    })?;
                    registry_readiness::validate_context_file(&path)?
                }
                "request-intake-support" => {
                    let path = context_json.ok_or_else(|| {
                        "request-intake-support validation requires --context-json".to_string()
                    })?;
                    request_intake_support::validate_context_file(&path)?
                }
                "restore-testing" => {
                    let path = context_json.ok_or_else(|| {
                        "restore-testing validation requires --context-json".to_string()
                    })?;
                    restore_testing::validate_context_file(&path)?
                }
                "controlled-restore" => {
                    let path = context_json.ok_or_else(|| {
                        "controlled-restore validation requires --context-json".to_string()
                    })?;
                    controlled_restore::validate_context_file(&path)?
                }
                "vcenter-object-placement" => {
                    let path = context_json.ok_or_else(|| {
                        "vcenter-object-placement validation requires --context-json".to_string()
                    })?;
                    vcenter_object_placement::validate_context_file(&path)?
                }
                "operations-endpoint-inventory" => {
                    let path = context_json.ok_or_else(|| {
                        "operations-endpoint-inventory validation requires --context-json"
                            .to_string()
                    })?;
                    operations_endpoint_inventory::validate_context_file(&path)?
                }
                "worker-capability" => {
                    let path = context_json.ok_or_else(|| {
                        "worker-capability validation requires --context-json".to_string()
                    })?;
                    worker_capability::validate_context_file(&path)?
                }
                "site-catalog-contract" => {
                    let path = context_json.ok_or_else(|| {
                        "site-catalog-contract validation requires --context-json".to_string()
                    })?;
                    site_catalog_contract::validate_context_file(&path)?
                }
                "snapshot-governance" => {
                    let path = context_json.ok_or_else(|| {
                        "snapshot-governance validation requires --context-json".to_string()
                    })?;
                    snapshot_governance::validate_context_file(&path)?
                }
                "standard-task" => {
                    let path = context_json.ok_or_else(|| {
                        "standard-task validation requires --context-json".to_string()
                    })?;
                    standard_task::validate_context_file(&path)?
                }
                "maintenance-communications" => {
                    let path = context_json.ok_or_else(|| {
                        "maintenance-communications validation requires --context-json".to_string()
                    })?;
                    maintenance_communications::validate_context_file(&path)?
                }
                "customization-spec-governance" => {
                    let path = context_json.ok_or_else(|| {
                        "customization-spec-governance validation requires --context-json"
                            .to_string()
                    })?;
                    customization_spec_governance::validate_context_file(&path)?
                }
                "synthetic-health-check" => {
                    let path = context_json.ok_or_else(|| {
                        "synthetic-health-check validation requires --context-json".to_string()
                    })?;
                    synthetic_health_check::validate_context_file(&path)?
                }
                "monitoring-review-queue" => {
                    let path = context_json.ok_or_else(|| {
                        "monitoring-review-queue validation requires --context-json".to_string()
                    })?;
                    monitoring_review_queue::validate_context_file(&path)?
                }
                "monitoring-coverage-gap" => {
                    let path = context_json.ok_or_else(|| {
                        "monitoring-coverage-gap validation requires --context-json".to_string()
                    })?;
                    monitoring_coverage_gap::validate_context_file(&path)?
                }
                "zabbix-drift-remediation" => {
                    let path = context_json.ok_or_else(|| {
                        "zabbix-drift-remediation validation requires --context-json".to_string()
                    })?;
                    zabbix_drift_remediation::validate_context_file(&path)?
                }
                "noise-flapping-remediation" => {
                    let path = context_json.ok_or_else(|| {
                        "noise-flapping-remediation validation requires --context-json".to_string()
                    })?;
                    noise_flapping_remediation::validate_context_file(&path)?
                }
                "zabbix-onboarding" => {
                    let path = context_json.ok_or_else(|| {
                        "zabbix-onboarding validation requires --context-json".to_string()
                    })?;
                    zabbix_onboarding::validate_context_file(&path)?
                }
                "log-forwarder-onboarding" => {
                    let path = context_json.ok_or_else(|| {
                        "log-forwarder-onboarding validation requires --context-json".to_string()
                    })?;
                    log_forwarder_onboarding::validate_context_file(&path)?
                }
                "hardware-lifecycle" => {
                    let path = context_json.ok_or_else(|| {
                        "hardware-lifecycle validation requires --context-json".to_string()
                    })?;
                    hardware_lifecycle::validate_context_file(&path)?
                }
                "sql-server-deployment" => {
                    let path = context_json.ok_or_else(|| {
                        "sql-server-deployment validation requires --context-json".to_string()
                    })?;
                    sql_server_deployment::validate_context_file(&path)?
                }
                "object-storage-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "object-storage-readiness validation requires --context-json".to_string()
                    })?;
                    object_storage_readiness::validate_context_file(&path)?
                }
                "platform-database-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "platform-database-readiness validation requires --context-json".to_string()
                    })?;
                    platform_database_readiness::validate_context_file(&path)?
                }
                "network-vlan-readiness" => {
                    let path = context_json.ok_or_else(|| {
                        "network-vlan-readiness validation requires --context-json".to_string()
                    })?;
                    network_vlan_readiness::validate_context_file(&path)?
                }
                "out-of-band-access-validation" => {
                    let path = context_json.ok_or_else(|| {
                        "out-of-band-access-validation validation requires --context-json"
                            .to_string()
                    })?;
                    out_of_band_access::validate_context_file(&path)?
                }
                "servicenow-future-api" => {
                    let path = context_json.ok_or_else(|| {
                        "servicenow-future-api validation requires --context-json".to_string()
                    })?;
                    servicenow_future_api::validate_context_file(&path)?
                }
                "release-image-builds" => {
                    let path = context_json.ok_or_else(|| {
                        "release-image-builds validation requires --context-json".to_string()
                    })?;
                    release_image_builds::validate_context_file(&path)?
                }
                "docker-image" => {
                    let path = context_json.ok_or_else(|| {
                        "docker-image validation requires --context-json".to_string()
                    })?;
                    docker_image::validate_context_file(&path)?
                }
                "ryuki-engine" => {
                    let path = context_json.ok_or_else(|| {
                        "ryuki-engine validation requires --context-json".to_string()
                    })?;
                    ryuki_engine::validate_context_file(&path)?
                }
                "ryuki-api" => {
                    let path = context_json.ok_or_else(|| {
                        "ryuki-api validation requires --context-json".to_string()
                    })?;
                    ryuki_api::validate_context_file(&path)?
                }
                "api-token-safety" => {
                    let path = context_json.ok_or_else(|| {
                        "api-token-safety validation requires --context-json".to_string()
                    })?;
                    api_token_safety::validate_context_file(&path)?
                }
                _ => return Err(format!("validate not implemented for slice: {slice}")),
            };
            print_json(&ErrorsOutput { errors })
        }
        "stats" => {
            require_slice(&args)?;
            let (root, _) = parse_root_args(&args[2..])?;
            let context = read_context(&root)?;
            print_json(&StatsOutput {
                workflow_rows: workflow_rows(&context.build_sheet).len(),
                foundation_rows: foundation_rows(&context.build_sheet).len(),
                information_architecture_rows: information_architecture_rows(&context.build_sheet)
                    .len(),
            })
        }
        "rows" => {
            let slice = require_slice(&args)?;
            if slice != "backlog-coverage" {
                return Err(format!("rows is not supported for {slice}"));
            }
            let Some(kind) = args.get(2).map(String::as_str) else {
                return Err(usage());
            };
            let mut markdown = String::new();
            io::stdin()
                .read_to_string(&mut markdown)
                .map_err(|error| format!("failed to read stdin: {error}"))?;

            match kind {
                "workflow" => print_json(&workflow_rows(&markdown)),
                "foundation" => print_json(&foundation_rows(&markdown)),
                "information_architecture" => print_json(&information_architecture_rows(&markdown)),
                _ => Err(format!("unknown rows kind: {kind}")),
            }
        }
        "check-shape" => {
            let slice = require_slice(&args)?;
            if slice != "backlog-coverage" {
                return Err(format!("check-shape is not supported for {slice}"));
            }
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .map_err(|error| format!("failed to read stdin: {error}"))?;
            let shape: ShapeInput = serde_json::from_str(&input)
                .map_err(|error| format!("invalid check-shape JSON: {error}"))?;
            let mut errors = Vec::new();
            validate_coverage_shape(&shape.workflow, &shape.coverage, &mut errors);
            print_json(&ErrorsOutput { errors })
        }
        "check-catalog" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "admin-approval-groups" => admin_approval_groups::validate_catalog_json(&input)?,
                "approval-decision-readiness" => {
                    approval_decision_readiness::validate_catalog_json(&input)?
                }
                "admin-delegation-boundary" => {
                    admin_delegation_boundary::validate_catalog_json(&input)?
                }
                "admin-feature-flag-governance" => {
                    admin_feature_flag::validate_catalog_json(&input)?
                }
                "aiops-suggestion" => aiops_suggestion::validate_catalog_json(&input)?,
                "activity-operation-queue" => {
                    activity_operation_queue::validate_catalog_json(&input)?
                }
                "access-review-recertification" => {
                    access_review_recertification::validate_catalog_json(&input)?
                }
                "ad-computer-lifecycle" => ad_computer_lifecycle::validate_catalog_json(&input)?,
                "adapter-contracts" => adapter_contract::validate_catalog_json(&input)?,
                "adapter-contract-test" => adapter_contract_test::validate_catalog_json(&input)?,
                "adapter-readiness-matrix" => {
                    adapter_readiness_matrix::validate_catalog_json(&input)?
                }
                "alert-routing" => alert_routing::validate_catalog_json(&input)?,
                "approved-software-deployment" => {
                    approved_software_deployment::validate_catalog_json(&input)?
                }
                "azure-landing-zone-validation" => {
                    azure_landing_zone::validate_catalog_json(&input)?
                }
                "backup-coverage-gap" => backup_coverage_gap::validate_catalog_json(&input)?,
                "application-environment-deployment" => {
                    application_environment_deployment::validate_catalog_json(&input)?
                }
                "application-environment-retirement" => {
                    application_environment_retirement::validate_catalog_json(&input)?
                }
                "application-aware-backup" => {
                    application_aware_backup::validate_catalog_json(&input)?
                }
                "immutability-air-gap-compliance" => {
                    immutability_air_gap_compliance::validate_catalog_json(&input)?
                }
                "backup-dr-assignment" => backup_dr_assignment::validate_catalog_json(&input)?,
                "certificate-lifecycle" => certificate_lifecycle::validate_catalog_json(&input)?,
                "cluster-capacity-admission" => {
                    cluster_capacity_admission::validate_catalog_json(&input)?
                }
                "dependency-maintenance-calendar" => {
                    dependency_maintenance_calendar::validate_catalog_json(&input)?
                }
                "firmware-compliance-exception" => {
                    firmware_compliance_exception::validate_catalog_json(&input)?
                }
                "vsan-esxi-lifecycle" => vsan_esxi_lifecycle::validate_catalog_json(&input)?,
                "vm-day2-change" => vm_day2_change::validate_catalog_json(&input)?,
                "vm-decommission-quarantine" => {
                    vm_decommission_quarantine::validate_catalog_json(&input)?
                }
                "cost-capacity-analytics" => cost_capacity::validate_catalog_json(&input)?,
                "repository-capacity-forecast" => {
                    repository_capacity_forecast::validate_catalog_json(&input)?
                }
                "patch-policy-import" => patch_policy_import::validate_catalog_json(&input)?,
                "patch-maintenance" => patch_maintenance::validate_catalog_json(&input)?,
                "datacenter-readiness" => datacenter_readiness::validate_catalog_json(&input)?,
                "reboot-orchestration" => reboot_orchestration::validate_catalog_json(&input)?,
                "catalog" => catalog::validate_catalog_json(&input)?,
                "dashboard-risk-heatmap" => dashboard_risk_heatmap::validate_catalog_json(&input)?,
                "dashboard-global-overview" => {
                    dashboard_global_overview::validate_catalog_json(&input)?
                }
                "design-system" => design_system::validate_catalog_json(&input)?,
                "inventory-resource-overview" => {
                    inventory_resource_overview::validate_catalog_json(&input)?
                }
                "inventory-ownership-risk" => {
                    inventory_ownership_risk::validate_catalog_json(&input)?
                }
                "os-baseline-compliance" => os_baseline_compliance::validate_catalog_json(&input)?,
                "incident-context" => incident_context::validate_catalog_json(&input)?,
                "degradation-mode" => degradation_mode::validate_catalog_json(&input)?,
                "operation-dependency-replay" => {
                    operation_dependency_replay::validate_catalog_json(&input)?
                }
                "image-factory" => image_factory::validate_catalog_json(&input)?,
                "operation-run-state" => operation_run_state::validate_catalog_json(&input)?,
                "operator-runbook" => operator_runbook::validate_catalog_json(&input)?,
                "platform-health" => platform_health::validate_catalog_json(&input)?,
                "vault-deployment-readiness" => {
                    vault_deployment_readiness::validate_catalog_json(&input)?
                }
                "vault-secret-delivery" => vault_secret_delivery::validate_catalog_json(&input)?,
                "portal-information-architecture" => {
                    portal_information_architecture::validate_catalog_json(&input)?
                }
                "ui-mockup-acceptance" => ui_mockup_acceptance::validate_catalog_json(&input)?,
                "platform-release-promotion" => {
                    platform_release_promotion::validate_catalog_json(&input)?
                }
                "request-execution-timeline" => {
                    request_execution_timeline::validate_catalog_json(&input)?
                }
                "request-lifecycle" => request_lifecycle::validate_catalog_json(&input)?,
                "cmdb-file-exchange" => cmdb_file_exchange::validate_catalog_json(&input)?,
                "cmdb-impact-analysis" => cmdb_impact_analysis::validate_catalog_json(&input)?,
                "cmdb-relationship-graph" => {
                    cmdb_relationship_graph::validate_catalog_json(&input)?
                }
                "cmdb-reconciliation" => cmdb_reconciliation::validate_catalog_json(&input)?,
                "evidence-compliance-dashboard" => {
                    evidence_compliance_dashboard::validate_catalog_json(&input)?
                }
                "evidence-export-retention" => {
                    evidence_export_retention::validate_catalog_json(&input)?
                }
                "evidence-manifest" => evidence_manifest::validate_catalog_json(&input)?,
                "evidence-redaction-contract" => {
                    evidence_redaction_contract::validate_catalog_json(&input)?
                }
                "emergency-change" => emergency_change::validate_catalog_json(&input)?,
                "inventory-coverage" => inventory_coverage::validate_catalog_json(&input)?,
                "offering-catalog-api" => offering_catalog_api::validate_catalog_json(&input)?,
                "offering-recommendations" => {
                    offering_recommendations::validate_catalog_json(&input)?
                }
                "policy-guardrail-api" => policy_guardrail_api::validate_catalog_json(&input)?,
                "knowledge-suggestion" => knowledge_suggestion::validate_catalog_json(&input)?,
                "kubernetes-runtime-readiness" => {
                    kubernetes_runtime_readiness::validate_catalog_json(&input)?
                }
                "local-container-readiness" => {
                    local_container_readiness::validate_catalog_json(&input)?
                }
                "legal-hold-retention" => legal_hold_retention::validate_catalog_json(&input)?,
                "request-form-contract" => request_form_contract::validate_catalog_json(&input)?,
                "request-intake-support" => request_intake_support::validate_catalog_json(&input)?,
                "request-preflight" => request_preflight::validate_catalog_json(&input)?,
                "rbac-approval-model" => rbac_approval_model::validate_catalog_json(&input)?,
                "entra-rbac-approval-readiness" => {
                    entra_rbac_approval_readiness::validate_catalog_json(&input)?
                }
                "registry-readiness" => registry_readiness::validate_catalog_json(&input)?,
                "restore-testing" => restore_testing::validate_catalog_json(&input)?,
                "controlled-restore" => controlled_restore::validate_catalog_json(&input)?,
                "vcenter-object-placement" => {
                    vcenter_object_placement::validate_catalog_json(&input)?
                }
                "security-baseline" => security_baseline::validate_catalog_json(&input)?,
                "secret-reference" => secret_reference::validate_catalog_json(&input)?,
                "local-auth" => local_auth::validate_catalog_json(&input)?,
                "local-privilege-access" => local_privilege_access::validate_catalog_json(&input)?,
                "file-share-ntfs-recertification" => {
                    file_share_ntfs_recertification::validate_catalog_json(&input)?
                }
                "gmsa-lifecycle" => gmsa_lifecycle::validate_catalog_json(&input)?,
                "server-lifecycle-dry-run" => server_lifecycle::validate_catalog_json(&input)?,
                "shift-queue" => shift_queue::validate_catalog_json(&input)?,
                "site-catalog-contract" => site_catalog_contract::validate_catalog_json(&input)?,
                "snapshot-governance" => snapshot_governance::validate_catalog_json(&input)?,
                "standard-task" => standard_task::validate_catalog_json(&input)?,
                "maintenance-communications" => {
                    maintenance_communications::validate_catalog_json(&input)?
                }
                "customization-spec-governance" => {
                    customization_spec_governance::validate_catalog_json(&input)?
                }
                "synthetic-health-check" => synthetic_health_check::validate_catalog_json(&input)?,
                "monitoring-review-queue" => {
                    monitoring_review_queue::validate_catalog_json(&input)?
                }
                "monitoring-coverage-gap" => {
                    monitoring_coverage_gap::validate_catalog_json(&input)?
                }
                "worker-capability" => worker_capability::validate_catalog_json(&input)?,
                "zabbix-drift-remediation" => {
                    zabbix_drift_remediation::validate_catalog_json(&input)?
                }
                "noise-flapping-remediation" => {
                    noise_flapping_remediation::validate_catalog_json(&input)?
                }
                "zabbix-onboarding" => zabbix_onboarding::validate_catalog_json(&input)?,
                "log-forwarder-onboarding" => {
                    log_forwarder_onboarding::validate_catalog_json(&input)?
                }
                "hardware-lifecycle" => hardware_lifecycle::validate_catalog_json(&input)?,
                "sql-server-deployment" => sql_server_deployment::validate_catalog_json(&input)?,
                "object-storage-readiness" => {
                    object_storage_readiness::validate_catalog_json(&input)?
                }
                "platform-database-readiness" => {
                    platform_database_readiness::validate_catalog_json(&input)?
                }
                "network-vlan-readiness" => network_vlan_readiness::validate_catalog_json(&input)?,
                "out-of-band-access-validation" => {
                    out_of_band_access::validate_catalog_json(&input)?
                }
                "servicenow-future-api" => servicenow_future_api::validate_catalog_json(&input)?,
                "ryuki-engine" => ryuki_engine::validate_catalog_json(&input)?,
                "ryuki-api" => ryuki_api::validate_catalog_json(&input)?,
                _ => return Err(format!("check-catalog is not supported for {slice}")),
            };
            print_json(&ErrorsOutput { errors })
        }
        "check-program" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "admin-approval-groups" => admin_approval_groups::validate_program_json(&input)?,
                "approval-decision-readiness" => {
                    approval_decision_readiness::validate_program_json(&input)?
                }
                "admin-delegation-boundary" => {
                    admin_delegation_boundary::validate_program_json(&input)?
                }
                "admin-feature-flag-governance" => {
                    admin_feature_flag::validate_program_json(&input)?
                }
                "aiops-suggestion" => aiops_suggestion::validate_program_json(&input)?,
                "activity-operation-queue" => {
                    activity_operation_queue::validate_program_json(&input)?
                }
                "access-review-recertification" => {
                    access_review_recertification::validate_program_json(&input)?
                }
                "ad-computer-lifecycle" => ad_computer_lifecycle::validate_program_json(&input)?,
                "adapter-contracts" => adapter_contract::validate_program_json(&input)?,
                "adapter-contract-test" => adapter_contract_test::validate_program_json(&input)?,
                "adapter-readiness-matrix" => {
                    adapter_readiness_matrix::validate_program_json(&input)?
                }
                "alert-routing" => alert_routing::validate_program_json(&input)?,
                "app-skeleton" => app_skeleton::validate_program_json(&input)?,
                "approved-software-deployment" => {
                    approved_software_deployment::validate_program_json(&input)?
                }
                "azure-landing-zone-validation" => {
                    azure_landing_zone::validate_program_json(&input)?
                }
                "backup-coverage-gap" => backup_coverage_gap::validate_program_json(&input)?,
                "application-environment-deployment" => {
                    application_environment_deployment::validate_program_json(&input)?
                }
                "application-environment-retirement" => {
                    application_environment_retirement::validate_program_json(&input)?
                }
                "application-aware-backup" => {
                    application_aware_backup::validate_program_json(&input)?
                }
                "immutability-air-gap-compliance" => {
                    immutability_air_gap_compliance::validate_program_json(&input)?
                }
                "backup-dr-assignment" => backup_dr_assignment::validate_program_json(&input)?,
                "certificate-lifecycle" => certificate_lifecycle::validate_program_json(&input)?,
                "cluster-capacity-admission" => {
                    cluster_capacity_admission::validate_program_json(&input)?
                }
                "dependency-maintenance-calendar" => {
                    dependency_maintenance_calendar::validate_program_json(&input)?
                }
                "firmware-compliance-exception" => {
                    firmware_compliance_exception::validate_program_json(&input)?
                }
                "vsan-esxi-lifecycle" => vsan_esxi_lifecycle::validate_program_json(&input)?,
                "vm-day2-change" => vm_day2_change::validate_program_json(&input)?,
                "vm-decommission-quarantine" => {
                    vm_decommission_quarantine::validate_program_json(&input)?
                }
                "cost-capacity-analytics" => cost_capacity::validate_program_json(&input)?,
                "repository-capacity-forecast" => {
                    repository_capacity_forecast::validate_program_json(&input)?
                }
                "patch-policy-import" => patch_policy_import::validate_program_json(&input)?,
                "patch-maintenance" => patch_maintenance::validate_program_json(&input)?,
                "datacenter-readiness" => datacenter_readiness::validate_program_json(&input)?,
                "reboot-orchestration" => reboot_orchestration::validate_program_json(&input)?,
                "dashboard-risk-heatmap" => dashboard_risk_heatmap::validate_program_json(&input)?,
                "dashboard-global-overview" => {
                    dashboard_global_overview::validate_program_json(&input)?
                }
                "design-system" => design_system::validate_program_json(&input)?,
                "inventory-resource-overview" => {
                    inventory_resource_overview::validate_program_json(&input)?
                }
                "inventory-ownership-risk" => {
                    inventory_ownership_risk::validate_program_json(&input)?
                }
                "os-baseline-compliance" => os_baseline_compliance::validate_program_json(&input)?,
                "incident-context" => incident_context::validate_program_json(&input)?,
                "degradation-mode" => degradation_mode::validate_program_json(&input)?,
                "operation-dependency-replay" => {
                    operation_dependency_replay::validate_program_json(&input)?
                }
                "image-factory" => image_factory::validate_program_json(&input)?,
                "operation-run-state" => operation_run_state::validate_program_json(&input)?,
                "operator-runbook" => operator_runbook::validate_program_json(&input)?,
                "platform-health" => platform_health::validate_program_json(&input)?,
                "vault-deployment-readiness" => {
                    vault_deployment_readiness::validate_program_json(&input)?
                }
                "vault-secret-delivery" => vault_secret_delivery::validate_program_json(&input)?,
                "portal-information-architecture" => {
                    portal_information_architecture::validate_program_json(&input)?
                }
                "ui-mockup-acceptance" => ui_mockup_acceptance::validate_program_json(&input)?,
                "platform-release-promotion" => {
                    platform_release_promotion::validate_program_json(&input)?
                }
                "request-execution-timeline" => {
                    request_execution_timeline::validate_program_json(&input)?
                }
                "request-lifecycle" => request_lifecycle::validate_program_json(&input)?,
                "cmdb-file-exchange" => cmdb_file_exchange::validate_program_json(&input)?,
                "cmdb-impact-analysis" => cmdb_impact_analysis::validate_program_json(&input)?,
                "cmdb-relationship-graph" => {
                    cmdb_relationship_graph::validate_program_json(&input)?
                }
                "cmdb-reconciliation" => cmdb_reconciliation::validate_program_json(&input)?,
                "evidence-compliance-dashboard" => {
                    evidence_compliance_dashboard::validate_program_json(&input)?
                }
                "evidence-export-retention" => {
                    evidence_export_retention::validate_program_json(&input)?
                }
                "evidence-redaction-contract" => {
                    evidence_redaction_contract::validate_program_json(&input)?
                }
                "emergency-change" => emergency_change::validate_program_json(&input)?,
                "governance-catalog-api" => governance_catalog_api::validate_program_json(&input)?,
                "inventory-coverage" => inventory_coverage::validate_program_json(&input)?,
                "offering-catalog-api" => offering_catalog_api::validate_program_json(&input)?,
                "offering-recommendations" => {
                    offering_recommendations::validate_program_json(&input)?
                }
                "policy-guardrail-api" => policy_guardrail_api::validate_program_json(&input)?,
                "knowledge-suggestion" => knowledge_suggestion::validate_program_json(&input)?,
                "kubernetes-runtime-readiness" => {
                    kubernetes_runtime_readiness::validate_program_json(&input)?
                }
                "local-container-readiness" => {
                    local_container_readiness::validate_program_json(&input)?
                }
                "legal-hold-retention" => legal_hold_retention::validate_program_json(&input)?,
                "request-form-contract" => request_form_contract::validate_program_json(&input)?,
                "request-intake-support" => request_intake_support::validate_program_json(&input)?,
                "request-preflight" => request_preflight::validate_program_json(&input)?,
                "rbac-approval-model" => rbac_approval_model::validate_program_json(&input)?,
                "entra-rbac-approval-readiness" => {
                    entra_rbac_approval_readiness::validate_program_json(&input)?
                }
                "registry-readiness" => registry_readiness::validate_program_json(&input)?,
                "restore-testing" => restore_testing::validate_program_json(&input)?,
                "controlled-restore" => controlled_restore::validate_program_json(&input)?,
                "vcenter-object-placement" => {
                    vcenter_object_placement::validate_program_json(&input)?
                }
                "security-baseline" => security_baseline::validate_program_json(&input)?,
                "local-auth" => local_auth::validate_program_json(&input)?,
                "local-privilege-access" => local_privilege_access::validate_program_json(&input)?,
                "file-share-ntfs-recertification" => {
                    file_share_ntfs_recertification::validate_program_json(&input)?
                }
                "gmsa-lifecycle" => gmsa_lifecycle::validate_program_json(&input)?,
                "server-lifecycle-dry-run" => server_lifecycle::validate_program_json(&input)?,
                "shift-queue" => shift_queue::validate_program_json(&input)?,
                "site-catalog-contract" => site_catalog_contract::validate_program_json(&input)?,
                "snapshot-governance" => snapshot_governance::validate_program_json(&input)?,
                "standard-task" => standard_task::validate_program_json(&input)?,
                "maintenance-communications" => {
                    maintenance_communications::validate_program_json(&input)?
                }
                "customization-spec-governance" => {
                    customization_spec_governance::validate_program_json(&input)?
                }
                "synthetic-health-check" => synthetic_health_check::validate_program_json(&input)?,
                "monitoring-review-queue" => {
                    monitoring_review_queue::validate_program_json(&input)?
                }
                "monitoring-coverage-gap" => {
                    monitoring_coverage_gap::validate_program_json(&input)?
                }
                "worker-capability" => worker_capability::validate_program_json(&input)?,
                "zabbix-drift-remediation" => {
                    zabbix_drift_remediation::validate_program_json(&input)?
                }
                "noise-flapping-remediation" => {
                    noise_flapping_remediation::validate_program_json(&input)?
                }
                "zabbix-onboarding" => zabbix_onboarding::validate_program_json(&input)?,
                "log-forwarder-onboarding" => {
                    log_forwarder_onboarding::validate_program_json(&input)?
                }
                "hardware-lifecycle" => hardware_lifecycle::validate_program_json(&input)?,
                "sql-server-deployment" => sql_server_deployment::validate_program_json(&input)?,
                "object-storage-readiness" => {
                    object_storage_readiness::validate_program_json(&input)?
                }
                "platform-database-readiness" => {
                    platform_database_readiness::validate_program_json(&input)?
                }
                "network-vlan-readiness" => network_vlan_readiness::validate_program_json(&input)?,
                "out-of-band-access-validation" => {
                    out_of_band_access::validate_program_json(&input)?
                }
                "servicenow-future-api" => servicenow_future_api::validate_program_json(&input)?,
                "ryuki-engine" => ryuki_engine::validate_program_json(&input)?,
                "ryuki-api" => ryuki_api::validate_program_json(&input)?,
                _ => return Err(format!("check-program is not supported for {slice}")),
            };
            print_json(&ErrorsOutput { errors })
        }
        "check-values" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "compose" => compose::validate_values_json(&input)?,
                "evidence-redaction-contract" => {
                    evidence_redaction_contract::validate_values_json(&input)?
                }
                "evidence-export-retention" => {
                    evidence_export_retention::validate_manifest_alignment_json(&input)?
                }
                "design-system" => design_system::validate_values_json(&input)?,
                "inventory-coverage" => inventory_coverage::validate_values_json(&input)?,
                "kubernetes-manifest" => kubernetes_manifest::validate_values_json(&input)?,
                "os-baseline-compliance" => os_baseline_compliance::validate_values_json(&input)?,
                "portal-information-architecture" => {
                    portal_information_architecture::validate_values_json(&input)?
                }
                "rbac-approval-model" => rbac_approval_model::validate_access_catalog_json(&input)?,
                "vault-foundation" => vault_foundation::validate_values_json(&input)?,
                _ => return Err(format!("check-values is not supported for {slice}")),
            };
            print_json(&ErrorsOutput { errors })
        }
        "check-controls" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "access-review-recertification" => {
                    access_review_recertification::validate_controls_json(&input)?
                }
                _ => return Err(format!("check-controls is not supported for {slice}")),
            };
            print_json(&ErrorsOutput { errors })
        }
        "check-yaml-duplicates" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "kubernetes-runtime-readiness" => {
                    kubernetes_runtime_readiness::validate_yaml_duplicates_json(&input)?
                }
                "compose" => compose::validate_yaml_duplicates_json(&input)?,
                "vault-foundation" => vault_foundation::validate_yaml_duplicates_json(&input)?,
                "vault-secret-delivery" => {
                    vault_secret_delivery::validate_yaml_duplicates_json(&input)?
                }
                _ => {
                    return Err(format!(
                        "check-yaml-duplicates is not supported for {slice}"
                    ))
                }
            };
            print_json(&ErrorsOutput { errors })
        }
        "check-build-sheet-source-inputs" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "security-baseline" => {
                    security_baseline::validate_build_sheet_source_inputs_json(&input)?
                }
                _ => {
                    return Err(format!(
                        "check-build-sheet-source-inputs is not supported for {slice}"
                    ))
                }
            };
            print_json(&ErrorsOutput { errors })
        }
        "check-source-inventory" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "azure-landing-zone-validation" => {
                    azure_landing_zone::validate_source_inventory_json(&input)?
                }
                _ => {
                    return Err(format!(
                        "check-source-inventory is not supported for {slice}"
                    ))
                }
            };
            print_json(&ErrorsOutput { errors })
        }
        "check-source-literals" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "sql-server-deployment" => {
                    sql_server_deployment::validate_source_literals_json(&input)?
                }
                _ => {
                    return Err(format!(
                        "check-source-literals is not supported for {slice}"
                    ))
                }
            };
            print_json(&ErrorsOutput { errors })
        }
        "check-docs" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "access-review-recertification" => {
                    access_review_recertification::validate_docs_json(&input)?
                }
                "ad-computer-lifecycle" => ad_computer_lifecycle::validate_docs_json(&input)?,
                "admin-approval-groups" => admin_approval_groups::validate_docs_json(&input)?,
                "approval-decision-readiness" => {
                    approval_decision_readiness::validate_docs_json(&input)?
                }
                "admin-delegation-boundary" => {
                    admin_delegation_boundary::validate_docs_json(&input)?
                }
                "admin-feature-flag-governance" => admin_feature_flag::validate_docs_json(&input)?,
                "aiops-suggestion" => aiops_suggestion::validate_docs_json(&input)?,
                "activity-operation-queue" => activity_operation_queue::validate_docs_json(&input)?,
                "adapter-contracts" => adapter_contract::validate_docs_json(&input)?,
                "adapter-contract-test" => adapter_contract_test::validate_docs_json(&input)?,
                "adapter-readiness-matrix" => adapter_readiness_matrix::validate_docs_json(&input)?,
                "alert-routing" => alert_routing::validate_docs_json(&input)?,
                "app-skeleton" => app_skeleton::validate_docs_json(&input)?,
                "approved-software-deployment" => {
                    approved_software_deployment::validate_docs_json(&input)?
                }
                "azure-landing-zone-validation" => azure_landing_zone::validate_docs_json(&input)?,
                "backup-coverage-gap" => backup_coverage_gap::validate_docs_json(&input)?,
                "application-environment-deployment" => {
                    application_environment_deployment::validate_docs_json(&input)?
                }
                "application-environment-retirement" => {
                    application_environment_retirement::validate_docs_json(&input)?
                }
                "application-aware-backup" => application_aware_backup::validate_docs_json(&input)?,
                "immutability-air-gap-compliance" => {
                    immutability_air_gap_compliance::validate_docs_json(&input)?
                }
                "backup-dr-assignment" => backup_dr_assignment::validate_docs_json(&input)?,
                "certificate-lifecycle" => certificate_lifecycle::validate_docs_json(&input)?,
                "cluster-capacity-admission" => {
                    cluster_capacity_admission::validate_docs_json(&input)?
                }
                "dependency-maintenance-calendar" => {
                    dependency_maintenance_calendar::validate_docs_json(&input)?
                }
                "firmware-compliance-exception" => {
                    firmware_compliance_exception::validate_docs_json(&input)?
                }
                "vsan-esxi-lifecycle" => vsan_esxi_lifecycle::validate_docs_json(&input)?,
                "vm-day2-change" => vm_day2_change::validate_docs_json(&input)?,
                "vm-decommission-quarantine" => {
                    vm_decommission_quarantine::validate_docs_json(&input)?
                }
                "cost-capacity-analytics" => cost_capacity::validate_docs_json(&input)?,
                "repository-capacity-forecast" => {
                    repository_capacity_forecast::validate_docs_json(&input)?
                }
                "patch-policy-import" => patch_policy_import::validate_docs_json(&input)?,
                "patch-maintenance" => patch_maintenance::validate_docs_json(&input)?,
                "datacenter-readiness" => datacenter_readiness::validate_docs_json(&input)?,
                "reboot-orchestration" => reboot_orchestration::validate_docs_json(&input)?,
                "dashboard-risk-heatmap" => dashboard_risk_heatmap::validate_docs_json(&input)?,
                "dashboard-global-overview" => {
                    dashboard_global_overview::validate_docs_json(&input)?
                }
                "design-system" => design_system::validate_docs_json(&input)?,
                "inventory-resource-overview" => {
                    inventory_resource_overview::validate_docs_json(&input)?
                }
                "inventory-ownership-risk" => inventory_ownership_risk::validate_docs_json(&input)?,
                "os-baseline-compliance" => os_baseline_compliance::validate_docs_json(&input)?,
                "incident-context" => incident_context::validate_docs_json(&input)?,
                "degradation-mode" => degradation_mode::validate_docs_json(&input)?,
                "operation-dependency-replay" => {
                    operation_dependency_replay::validate_docs_json(&input)?
                }
                "image-factory" => image_factory::validate_docs_json(&input)?,
                "operation-run-state" => operation_run_state::validate_docs_json(&input)?,
                "operator-runbook" => operator_runbook::validate_docs_json(&input)?,
                "platform-health" => platform_health::validate_docs_json(&input)?,
                "vault-deployment-readiness" => {
                    vault_deployment_readiness::validate_docs_json(&input)?
                }
                "vault-secret-delivery" => vault_secret_delivery::validate_docs_json(&input)?,
                "portal-information-architecture" => {
                    portal_information_architecture::validate_docs_json(&input)?
                }
                "ui-mockup-acceptance" => ui_mockup_acceptance::validate_docs_json(&input)?,
                "platform-release-promotion" => {
                    platform_release_promotion::validate_docs_json(&input)?
                }
                "request-execution-timeline" => {
                    request_execution_timeline::validate_docs_json(&input)?
                }
                "request-lifecycle" => request_lifecycle::validate_docs_json(&input)?,
                "cmdb-file-exchange" => cmdb_file_exchange::validate_docs_json(&input)?,
                "cmdb-impact-analysis" => cmdb_impact_analysis::validate_docs_json(&input)?,
                "cmdb-relationship-graph" => cmdb_relationship_graph::validate_docs_json(&input)?,
                "cmdb-reconciliation" => cmdb_reconciliation::validate_docs_json(&input)?,
                "deployment-input-template" => {
                    deployment_input_template::validate_docs_json(&input)?
                }
                "evidence-compliance-dashboard" => {
                    evidence_compliance_dashboard::validate_docs_json(&input)?
                }
                "evidence-export-retention" => {
                    evidence_export_retention::validate_docs_json(&input)?
                }
                "evidence-manifest" => evidence_manifest::validate_docs_json(&input)?,
                "evidence-redaction-contract" => {
                    evidence_redaction_contract::validate_docs_json(&input)?
                }
                "emergency-change" => emergency_change::validate_docs_json(&input)?,
                "governance-catalog-api" => governance_catalog_api::validate_docs_json(&input)?,
                "inventory-coverage" => inventory_coverage::validate_docs_json(&input)?,
                "offering-catalog-api" => offering_catalog_api::validate_docs_json(&input)?,
                "offering-recommendations" => offering_recommendations::validate_docs_json(&input)?,
                "policy-guardrail-api" => policy_guardrail_api::validate_docs_json(&input)?,
                "knowledge-suggestion" => knowledge_suggestion::validate_docs_json(&input)?,
                "kubernetes-runtime-readiness" => {
                    kubernetes_runtime_readiness::validate_docs_json(&input)?
                }
                "local-container-readiness" => {
                    local_container_readiness::validate_docs_json(&input)?
                }
                "legal-hold-retention" => legal_hold_retention::validate_docs_json(&input)?,
                "request-form-contract" => request_form_contract::validate_docs_json(&input)?,
                "request-intake-support" => request_intake_support::validate_docs_json(&input)?,
                "request-preflight" => request_preflight::validate_docs_json(&input)?,
                "rbac-approval-model" => rbac_approval_model::validate_docs_json(&input)?,
                "entra-rbac-approval-readiness" => {
                    entra_rbac_approval_readiness::validate_docs_json(&input)?
                }
                "registry-readiness" => registry_readiness::validate_docs_json(&input)?,
                "restore-testing" => restore_testing::validate_docs_json(&input)?,
                "controlled-restore" => controlled_restore::validate_docs_json(&input)?,
                "vcenter-object-placement" => vcenter_object_placement::validate_docs_json(&input)?,
                "security-baseline" => security_baseline::validate_docs_json(&input)?,
                "operations-endpoint-inventory" => {
                    operations_endpoint_inventory::validate_docs_json(&input)?
                }
                "secret-reference" => secret_reference::validate_docs_json(&input)?,
                "local-auth" => local_auth::validate_docs_json(&input)?,
                "local-privilege-access" => local_privilege_access::validate_docs_json(&input)?,
                "file-share-ntfs-recertification" => {
                    file_share_ntfs_recertification::validate_docs_json(&input)?
                }
                "gmsa-lifecycle" => gmsa_lifecycle::validate_docs_json(&input)?,
                "server-lifecycle-dry-run" => server_lifecycle::validate_docs_json(&input)?,
                "shift-queue" => shift_queue::validate_docs_json(&input)?,
                "site-catalog-contract" => site_catalog_contract::validate_docs_json(&input)?,
                "snapshot-governance" => snapshot_governance::validate_docs_json(&input)?,
                "standard-task" => standard_task::validate_docs_json(&input)?,
                "maintenance-communications" => {
                    maintenance_communications::validate_docs_json(&input)?
                }
                "customization-spec-governance" => {
                    customization_spec_governance::validate_docs_json(&input)?
                }
                "synthetic-health-check" => synthetic_health_check::validate_docs_json(&input)?,
                "vault-foundation" => vault_foundation::validate_docs_json(&input)?,
                "monitoring-review-queue" => monitoring_review_queue::validate_docs_json(&input)?,
                "monitoring-coverage-gap" => monitoring_coverage_gap::validate_docs_json(&input)?,
                "worker-capability" => worker_capability::validate_docs_json(&input)?,
                "zabbix-drift-remediation" => zabbix_drift_remediation::validate_docs_json(&input)?,
                "noise-flapping-remediation" => {
                    noise_flapping_remediation::validate_docs_json(&input)?
                }
                "zabbix-onboarding" => zabbix_onboarding::validate_docs_json(&input)?,
                "log-forwarder-onboarding" => log_forwarder_onboarding::validate_docs_json(&input)?,
                "hardware-lifecycle" => hardware_lifecycle::validate_docs_json(&input)?,
                "sql-server-deployment" => sql_server_deployment::validate_docs_json(&input)?,
                "object-storage-readiness" => object_storage_readiness::validate_docs_json(&input)?,
                "platform-database-readiness" => {
                    platform_database_readiness::validate_docs_json(&input)?
                }
                "network-vlan-readiness" => network_vlan_readiness::validate_docs_json(&input)?,
                "out-of-band-access-validation" => out_of_band_access::validate_docs_json(&input)?,
                "servicenow-future-api" => servicenow_future_api::validate_docs_json(&input)?,
                "ryuki-engine" => ryuki_engine::validate_docs_json(&input)?,
                "ryuki-api" => ryuki_api::validate_docs_json(&input)?,
                _ => return Err(format!("check-docs is not supported for {slice}")),
            };
            print_json(&ErrorsOutput { errors })
        }
        "scan-prohibited" => {
            let slice = require_slice(&args)?;
            let input = read_stdin()?;
            let errors = match slice {
                "admin-approval-groups" => admin_approval_groups::scan_prohibited_json(&input)?,
                "approval-decision-readiness" => {
                    approval_decision_readiness::scan_prohibited_json(&input)?
                }
                "admin-delegation-boundary" => {
                    admin_delegation_boundary::scan_prohibited_json(&input)?
                }
                "admin-feature-flag-governance" => {
                    admin_feature_flag::scan_prohibited_json(&input)?
                }
                "aiops-suggestion" => aiops_suggestion::scan_prohibited_json(&input)?,
                "activity-operation-queue" => {
                    activity_operation_queue::scan_prohibited_json(&input)?
                }
                "access-review-recertification" => {
                    access_review_recertification::scan_prohibited_json(&input)?
                }
                "ad-computer-lifecycle" => ad_computer_lifecycle::scan_prohibited_json(&input)?,
                "adapter-contracts" => adapter_contract::scan_prohibited_json(&input)?,
                "adapter-contract-test" => adapter_contract_test::scan_prohibited_json(&input)?,
                "adapter-readiness-matrix" => {
                    adapter_readiness_matrix::scan_prohibited_json(&input)?
                }
                "alert-routing" => alert_routing::scan_prohibited_json(&input)?,
                "app-skeleton" => app_skeleton::scan_prohibited_json(&input)?,
                "approved-software-deployment" => {
                    approved_software_deployment::scan_prohibited_json(&input)?
                }
                "azure-landing-zone-validation" => {
                    azure_landing_zone::scan_prohibited_json(&input)?
                }
                "backup-coverage-gap" => backup_coverage_gap::scan_prohibited_json(&input)?,
                "application-environment-deployment" => {
                    application_environment_deployment::scan_prohibited_json(&input)?
                }
                "application-environment-retirement" => {
                    application_environment_retirement::scan_prohibited_json(&input)?
                }
                "application-aware-backup" => {
                    application_aware_backup::scan_prohibited_json(&input)?
                }
                "immutability-air-gap-compliance" => {
                    immutability_air_gap_compliance::scan_prohibited_json(&input)?
                }
                "backup-dr-assignment" => backup_dr_assignment::scan_prohibited_json(&input)?,
                "certificate-lifecycle" => certificate_lifecycle::scan_prohibited_json(&input)?,
                "cluster-capacity-admission" => {
                    cluster_capacity_admission::scan_prohibited_json(&input)?
                }
                "dependency-maintenance-calendar" => {
                    dependency_maintenance_calendar::scan_prohibited_json(&input)?
                }
                "firmware-compliance-exception" => {
                    firmware_compliance_exception::scan_prohibited_json(&input)?
                }
                "vsan-esxi-lifecycle" => vsan_esxi_lifecycle::scan_prohibited_json(&input)?,
                "vm-day2-change" => vm_day2_change::scan_prohibited_json(&input)?,
                "vm-decommission-quarantine" => {
                    vm_decommission_quarantine::scan_prohibited_json(&input)?
                }
                "cost-capacity-analytics" => cost_capacity::scan_prohibited_json(&input)?,
                "repository-capacity-forecast" => {
                    repository_capacity_forecast::scan_prohibited_json(&input)?
                }
                "patch-policy-import" => patch_policy_import::scan_prohibited_json(&input)?,
                "patch-maintenance" => patch_maintenance::scan_prohibited_json(&input)?,
                "datacenter-readiness" => datacenter_readiness::scan_prohibited_json(&input)?,
                "reboot-orchestration" => reboot_orchestration::scan_prohibited_json(&input)?,
                "compose" => compose::scan_prohibited_json(&input)?,
                "catalog" => catalog::scan_prohibited_json(&input)?,
                "dashboard-risk-heatmap" => dashboard_risk_heatmap::scan_prohibited_json(&input)?,
                "dashboard-global-overview" => {
                    dashboard_global_overview::scan_prohibited_json(&input)?
                }
                "design-system" => design_system::scan_prohibited_json(&input)?,
                "inventory-resource-overview" => {
                    inventory_resource_overview::scan_prohibited_json(&input)?
                }
                "inventory-ownership-risk" => {
                    inventory_ownership_risk::scan_prohibited_json(&input)?
                }
                "os-baseline-compliance" => os_baseline_compliance::scan_prohibited_json(&input)?,
                "incident-context" => incident_context::scan_prohibited_json(&input)?,
                "degradation-mode" => degradation_mode::scan_prohibited_json(&input)?,
                "operation-dependency-replay" => {
                    operation_dependency_replay::scan_prohibited_json(&input)?
                }
                "image-factory" => image_factory::scan_prohibited_json(&input)?,
                "operation-run-state" => operation_run_state::scan_prohibited_json(&input)?,
                "operator-runbook" => operator_runbook::scan_prohibited_json(&input)?,
                "platform-health" => platform_health::scan_prohibited_json(&input)?,
                "vault-deployment-readiness" => {
                    vault_deployment_readiness::scan_prohibited_json(&input)?
                }
                "vault-secret-delivery" => vault_secret_delivery::scan_prohibited_json(&input)?,
                "portal-information-architecture" => {
                    portal_information_architecture::scan_prohibited_json(&input)?
                }
                "ui-mockup-acceptance" => ui_mockup_acceptance::scan_prohibited_json(&input)?,
                "platform-release-promotion" => {
                    platform_release_promotion::scan_prohibited_json(&input)?
                }
                "request-execution-timeline" => {
                    request_execution_timeline::scan_prohibited_json(&input)?
                }
                "request-lifecycle" => request_lifecycle::scan_prohibited_json(&input)?,
                "cmdb-file-exchange" => cmdb_file_exchange::scan_prohibited_json(&input)?,
                "cmdb-impact-analysis" => cmdb_impact_analysis::scan_prohibited_json(&input)?,
                "cmdb-relationship-graph" => cmdb_relationship_graph::scan_prohibited_json(&input)?,
                "cmdb-reconciliation" => cmdb_reconciliation::scan_prohibited_json(&input)?,
                "deployment-input-template" => {
                    deployment_input_template::scan_prohibited_json(&input)?
                }
                "evidence-compliance-dashboard" => {
                    evidence_compliance_dashboard::scan_prohibited_json(&input)?
                }
                "evidence-export-retention" => {
                    evidence_export_retention::scan_prohibited_json(&input)?
                }
                "evidence-manifest" => evidence_manifest::scan_prohibited_json(&input)?,
                "evidence-redaction-contract" => {
                    evidence_redaction_contract::scan_prohibited_json(&input)?
                }
                "emergency-change" => emergency_change::scan_prohibited_json(&input)?,
                "governance-catalog-api" => governance_catalog_api::scan_prohibited_json(&input)?,
                "inventory-coverage" => inventory_coverage::scan_prohibited_json(&input)?,
                "offering-catalog-api" => offering_catalog_api::scan_prohibited_json(&input)?,
                "offering-recommendations" => {
                    offering_recommendations::scan_prohibited_json(&input)?
                }
                "policy-guardrail-api" => policy_guardrail_api::scan_prohibited_json(&input)?,
                "knowledge-suggestion" => knowledge_suggestion::scan_prohibited_json(&input)?,
                "kubernetes-manifest" => kubernetes_manifest::scan_prohibited_json(&input)?,
                "kubernetes-runtime-readiness" => {
                    kubernetes_runtime_readiness::scan_prohibited_json(&input)?
                }
                "local-container-readiness" => {
                    local_container_readiness::scan_prohibited_json(&input)?
                }
                "legal-hold-retention" => legal_hold_retention::scan_prohibited_json(&input)?,
                "request-form-contract" => request_form_contract::scan_prohibited_json(&input)?,
                "request-intake-support" => request_intake_support::scan_prohibited_json(&input)?,
                "request-preflight" => request_preflight::scan_prohibited_json(&input)?,
                "rbac-approval-model" => rbac_approval_model::scan_prohibited_json(&input)?,
                "entra-rbac-approval-readiness" => {
                    entra_rbac_approval_readiness::scan_prohibited_json(&input)?
                }
                "registry-readiness" => registry_readiness::scan_prohibited_json(&input)?,
                "restore-testing" => restore_testing::scan_prohibited_json(&input)?,
                "controlled-restore" => controlled_restore::scan_prohibited_json(&input)?,
                "vcenter-object-placement" => {
                    vcenter_object_placement::scan_prohibited_json(&input)?
                }
                "security-baseline" => security_baseline::scan_prohibited_json(&input)?,
                "operations-endpoint-inventory" => {
                    operations_endpoint_inventory::scan_prohibited_json(&input)?
                }
                "secret-reference" => secret_reference::scan_prohibited_json(&input)?,
                "local-auth" => local_auth::scan_prohibited_json(&input)?,
                "local-privilege-access" => local_privilege_access::scan_prohibited_json(&input)?,
                "file-share-ntfs-recertification" => {
                    file_share_ntfs_recertification::scan_prohibited_json(&input)?
                }
                "gmsa-lifecycle" => gmsa_lifecycle::scan_prohibited_json(&input)?,
                "server-lifecycle-dry-run" => server_lifecycle::scan_prohibited_json(&input)?,
                "shift-queue" => shift_queue::scan_prohibited_json(&input)?,
                "site-catalog-contract" => site_catalog_contract::scan_prohibited_json(&input)?,
                "snapshot-governance" => snapshot_governance::scan_prohibited_json(&input)?,
                "standard-task" => standard_task::scan_prohibited_json(&input)?,
                "maintenance-communications" => {
                    maintenance_communications::scan_prohibited_json(&input)?
                }
                "customization-spec-governance" => {
                    customization_spec_governance::scan_prohibited_json(&input)?
                }
                "synthetic-health-check" => synthetic_health_check::scan_prohibited_json(&input)?,
                "vault-foundation" => vault_foundation::scan_prohibited_json(&input)?,
                "monitoring-review-queue" => monitoring_review_queue::scan_prohibited_json(&input)?,
                "monitoring-coverage-gap" => monitoring_coverage_gap::scan_prohibited_json(&input)?,
                "worker-capability" => worker_capability::scan_prohibited_json(&input)?,
                "zabbix-drift-remediation" => {
                    zabbix_drift_remediation::scan_prohibited_json(&input)?
                }
                "noise-flapping-remediation" => {
                    noise_flapping_remediation::scan_prohibited_json(&input)?
                }
                "zabbix-onboarding" => zabbix_onboarding::scan_prohibited_json(&input)?,
                "log-forwarder-onboarding" => {
                    log_forwarder_onboarding::scan_prohibited_json(&input)?
                }
                "hardware-lifecycle" => hardware_lifecycle::scan_prohibited_json(&input)?,
                "sql-server-deployment" => sql_server_deployment::scan_prohibited_json(&input)?,
                "object-storage-readiness" => {
                    object_storage_readiness::scan_prohibited_json(&input)?
                }
                "platform-database-readiness" => {
                    platform_database_readiness::scan_prohibited_json(&input)?
                }
                "network-vlan-readiness" => network_vlan_readiness::scan_prohibited_json(&input)?,
                "out-of-band-access-validation" => {
                    out_of_band_access::scan_prohibited_json(&input)?
                }
                "servicenow-future-api" => servicenow_future_api::scan_prohibited_json(&input)?,
                "ryuki-engine" => ryuki_engine::scan_prohibited_json(&input)?,
                "ryuki-api" => ryuki_api::scan_prohibited_json(&input)?,
                _ => return Err(format!("scan-prohibited is not supported for {slice}")),
            };
            print_json(&ErrorsOutput { errors })
        }
        "server" => {
            let stdin = io::stdin();
            let stdout = std::io::stdout();
            let mut line = String::new();
            loop {
                line.clear();
                match stdin.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let request: serde_json::Value = serde_json::from_str(trimmed)
                    .map_err(|error| format!("invalid server request: {error}"))?;
                let sub = request
                    .get("sub")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let slice = request
                    .get("slice")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");

                if sub == "batch" {
                    let items = request
                        .get("items")
                        .and_then(serde_json::Value::as_array)
                        .ok_or("batch requires items array")?;
                    let mut responses = Vec::with_capacity(items.len());
                    for item in items {
                        let item_sub = item
                            .get("sub")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        let item_data = item.get("data");
                        let errors = match item_sub {
                            "check-catalog" => {
                                let input = item_data
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or("missing data")?;
                                request_preflight::validate_catalog_json(input)?
                            }
                            "check-program" => {
                                let input = item_data
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or("missing data")?;
                                request_preflight::validate_program_json(input)?
                            }
                            "check-docs" => {
                                let input = item_data
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or("missing data")?;
                                request_preflight::validate_docs_json(input)?
                            }
                            "scan-prohibited" => {
                                let input = item_data
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or("missing data")?;
                                request_preflight::scan_prohibited_json(input)?
                            }
                            _ => return Err(format!("unsupported batch sub: {item_sub}")),
                        };
                        responses.push(serde_json::json!({"errors": errors}));
                    }
                    let response = serde_json::json!({"results": responses});
                    writeln!(
                        stdout.lock(),
                        "{}",
                        serde_json::to_string(&response).unwrap()
                    )
                    .map_err(|error| format!("failed to write server response: {error}"))?;
                    stdout
                        .lock()
                        .flush()
                        .map_err(|error| format!("failed to flush server response: {error}"))?;
                    continue;
                }

                let data_val = request.get("data");
                let errors = match (sub, slice) {
                    ("check-catalog", "request-preflight") => {
                        let input = data_val
                            .and_then(serde_json::Value::as_str)
                            .ok_or("missing data")?;
                        request_preflight::validate_catalog_json(input)?
                    }
                    ("check-program", "request-preflight") => {
                        let input = data_val
                            .and_then(serde_json::Value::as_str)
                            .ok_or("missing data")?;
                        request_preflight::validate_program_json(input)?
                    }
                    ("check-docs", "request-preflight") => {
                        let input = data_val
                            .and_then(serde_json::Value::as_str)
                            .ok_or("missing data")?;
                        request_preflight::validate_docs_json(input)?
                    }
                    ("scan-prohibited", "request-preflight") => {
                        let input = data_val
                            .and_then(serde_json::Value::as_str)
                            .ok_or("missing data")?;
                        request_preflight::scan_prohibited_json(input)?
                    }
                    _ => return Err(format!("unsupported server command: {sub} {slice}")),
                };
                let response = serde_json::json!({"errors": errors});
                writeln!(
                    stdout.lock(),
                    "{}",
                    serde_json::to_string(&response).unwrap()
                )
                .map_err(|error| format!("failed to write server response: {error}"))?;
                stdout
                    .lock()
                    .flush()
                    .map_err(|error| format!("failed to flush server response: {error}"))?;
            }
            Ok(())
        }
        "run-all" => {
            let (root, _) = parse_root_args(&args[1..])?;
            let output = run_all_validate(&root, true)?;
            print_json(&output)
        }
        "generate-endpoints-doc" => {
            let (root, _) = parse_root_args(&args[1..])?;
            let (document, route_count) = generate_endpoints_doc(&root)?;
            let output_path = root.join(API_ENDPOINTS_DOC_PATH);
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
            }
            fs::write(&output_path, &document)
                .map_err(|error| format!("failed to write {}: {error}", output_path.display()))?;
            print_json(&serde_json::json!({
                "written": API_ENDPOINTS_DOC_PATH,
                "routes": route_count,
            }))
        }
        "scaffold-docs" => {
            let (root, _) = parse_root_args(&args[1..])?;
            let output = scaffold_docs::scaffold(&root, &registry_rows())?;
            print_json(&output)
        }
        "batch-validate" => {
            let (root, _) = parse_root_args(&args[1..])?;
            let slice_names = read_stdin()?;
            let slices: Vec<&str> = slice_names
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect();
            let output = run_batch_validate(&root, &slices)?;
            print_json(&output)
        }
        "check-config" => {
            check_config::run();
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: ryuki-validator <coverage|validate|stats|rows|check-shape|check-catalog|check-program|check-values|check-controls|check-yaml-duplicates|check-build-sheet-source-inputs|check-source-inventory|check-source-literals|check-docs|scan-prohibited|server|run-all|batch-validate|generate-endpoints-doc|scaffold-docs|check-config> <slice> [options]"
        .to_string()
}

fn require_slice(args: &[String]) -> Result<&str, String> {
    match args.get(1).map(String::as_str) {
        Some(
            "backlog-coverage"
            | "server-lifecycle-dry-run"
            | "access-review-recertification"
            | "ad-computer-lifecycle"
            | "aiops-suggestion"
            | "alert-routing"
            | "app-skeleton"
            | "approved-software-deployment"
            | "azure-landing-zone-validation"
            | "application-environment-deployment"
            | "application-environment-retirement"
            | "application-aware-backup"
            | "backup-coverage-gap"
            | "backup-dr-assignment"
            | "certificate-lifecycle"
            | "cluster-capacity-admission"
            | "dependency-maintenance-calendar"
            | "firmware-compliance-exception"
            | "vsan-esxi-lifecycle"
            | "vm-day2-change"
            | "vm-decommission-quarantine"
            | "activity-operation-queue"
            | "adapter-contracts"
            | "adapter-contract-test"
            | "adapter-readiness-matrix"
            | "admin-approval-groups"
            | "admin-delegation-boundary"
            | "api-token-safety"
            | "approval-decision-readiness"
            | "catalog"
            | "cmdb-file-exchange"
            | "cmdb-impact-analysis"
            | "cmdb-relationship-graph"
            | "cmdb-reconciliation"
            | "cost-capacity-analytics"
            | "dashboard-global-overview"
            | "dashboard-risk-heatmap"
            | "design-system"
            | "compose"
            | "deployment-input-template"
            | "emergency-change"
            | "entra-rbac-approval-readiness"
            | "evidence-compliance-dashboard"
            | "evidence-export-retention"
            | "evidence-manifest"
            | "evidence-redaction-contract"
            | "governance-catalog-api"
            | "image-factory"
            | "inventory-coverage"
            | "inventory-ownership-risk"
            | "inventory-resource-overview"
            | "immutability-air-gap-compliance"
            | "incident-context"
            | "degradation-mode"
            | "knowledge-suggestion"
            | "kubernetes-manifest"
            | "kubernetes-runtime-readiness"
            | "local-container-readiness"
            | "legal-hold-retention"
            | "local-auth"
            | "local-privilege-access"
            | "file-share-ntfs-recertification"
            | "gmsa-lifecycle"
            | "monitoring-coverage-gap"
            | "monitoring-review-queue"
            | "offering-catalog-api"
            | "offering-recommendations"
            | "os-baseline-compliance"
            | "operation-dependency-replay"
            | "operation-run-state"
            | "operator-runbook"
            | "operations-endpoint-inventory"
            | "platform-health"
            | "portal-information-architecture"
            | "platform-release-promotion"
            | "policy-guardrail-api"
            | "request-execution-timeline"
            | "request-form-contract"
            | "request-intake-support"
            | "request-lifecycle"
            | "request-preflight"
            | "rbac-approval-model"
            | "registry-readiness"
            | "repository-capacity-forecast"
            | "patch-policy-import"
            | "patch-maintenance"
            | "datacenter-readiness"
            | "reboot-orchestration"
            | "release-image-builds"
            | "docker-image"
            | "restore-testing"
            | "controlled-restore"
            | "control-plane-db-backup"
            | "release-engineering"
            | "vcenter-object-placement"
            | "security-baseline"
            | "sensitive-output-guardrails"
            | "secret-reference"
            | "servicenow-future-api"
            | "shift-queue"
            | "site-catalog-contract"
            | "sql-server-deployment"
            | "object-storage-readiness"
            | "observability-deploy-wiring"
            | "platform-database-readiness"
            | "network-vlan-readiness"
            | "out-of-band-access-validation"
            | "snapshot-governance"
            | "standard-task"
            | "maintenance-communications"
            | "customization-spec-governance"
            | "synthetic-health-check"
            | "ui-mockup-acceptance"
            | "zabbix-onboarding"
            | "log-forwarder-onboarding"
            | "hardware-lifecycle"
            | "zabbix-drift-remediation"
            | "noise-flapping-remediation",
        ) => Ok(args.get(1).expect("slice checked").as_str()),
        Some("ryuki-engine") => Ok(args.get(1).expect("slice checked").as_str()),
        Some("ryuki-api") => Ok(args.get(1).expect("slice checked").as_str()),
        Some("vault-deployment-readiness") => Ok(args.get(1).expect("slice checked").as_str()),
        Some("vault-secret-delivery") => Ok(args.get(1).expect("slice checked").as_str()),
        Some("vault-foundation") => Ok(args.get(1).expect("slice checked").as_str()),
        Some("admin-feature-flag-governance") => Ok(args.get(1).expect("slice checked").as_str()),
        Some("worker-capability") => Ok(args.get(1).expect("slice checked").as_str()),
        Some(slice) => Err(format!("unknown slice: {slice}")),
        None => Err(usage()),
    }
}

fn read_stdin() -> Result<String, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    Ok(input)
}

fn parse_root_args(args: &[String]) -> Result<(PathBuf, Option<PathBuf>), String> {
    let mut root = None;
    let mut context_json = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--root" => {
                index += 1;
                root = args.get(index).map(PathBuf::from);
            }
            "--context-json" => {
                index += 1;
                context_json = args.get(index).map(PathBuf::from);
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
        index += 1;
    }

    // Default to the current working directory so `make validate`, the
    // documented invocations, and a plain `run-all` work from a clean
    // checkout; `--root` stays available as an explicit override.
    let root = match root {
        Some(path) => path,
        None => env::current_dir()
            .map_err(|error| format!("failed to resolve current directory: {error}"))?,
    };
    Ok((root, context_json))
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let json = serde_json::to_string(value).map_err(|error| format!("JSON error: {error}"))?;
    println!("{json}");
    Ok(())
}

fn coverage_output() -> CoverageOutput {
    let all = coverage_by_kind();
    let workflow = single_entry_map(all.get("workflow"));
    let foundation = single_entry_map(all.get("foundation"));
    let information_architecture = all.get("ia").cloned().unwrap_or_default();

    CoverageOutput {
        workflow,
        foundation,
        information_architecture,
    }
}

fn single_entry_map(
    source: Option<&BTreeMap<String, Vec<CoverageEntry>>>,
) -> BTreeMap<String, CoverageEntry> {
    source
        .into_iter()
        .flat_map(|map| map.iter())
        .filter_map(|(name, entries)| entries.first().cloned().map(|entry| (name.clone(), entry)))
        .collect()
}

fn coverage_by_kind() -> BTreeMap<String, BTreeMap<String, Vec<CoverageEntry>>> {
    let mut result: BTreeMap<String, BTreeMap<String, Vec<CoverageEntry>>> = BTreeMap::new();

    for line in COVERAGE_TSV
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let cells: Vec<&str> = line.split('\t').collect();
        if cells.len() != 5 {
            continue;
        }

        let entry = CoverageEntry {
            catalog: cells[2].to_string(),
            doc: cells[3].to_string(),
            endpoint: cells[4].to_string(),
        };
        result
            .entry(cells[0].to_string())
            .or_default()
            .entry(cells[1].to_string())
            .or_default()
            .push(entry);
    }

    result
}

fn read_context(root: &Path) -> Result<Context, String> {
    Ok(Context {
        build_sheet: read(root, BUILD_SHEET_PATH)?,
        catalog_readme: read(root, CATALOG_README_PATH)?,
        workflow_readme: read(root, WORKFLOW_README_PATH)?,
        api_readme: read(root, API_ENDPOINTS_DOC_PATH).unwrap_or_default(),
        program: read(root, RUST_API_CONTRACTS_PATH).unwrap_or_default(),
        rust_contracts: read(root, RUST_API_CONTRACTS_PATH).unwrap_or_default(),
        rust_api_main: read(root, RUST_API_MAIN_PATH).unwrap_or_default(),
    })
}

fn read_context_json(path: &Path) -> Result<Context, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&payload).map_err(|error| format!("invalid context JSON: {error}"))
}

fn read(root: &Path, path: &str) -> Result<String, String> {
    let full_path = root.join(path);
    fs::read_to_string(&full_path)
        .map_err(|error| format!("failed to read {}: {error}", full_path.display()))
}

fn validate_context(root: &Path, context: &Context) -> Vec<String> {
    let mut errors = Vec::new();
    let coverage = coverage_by_kind();

    validate_rows(
        root,
        "build sheet workflows",
        workflow_rows(&context.build_sheet)
            .iter()
            .map(|row| row.workflow.as_str())
            .collect(),
        CoverageKind::Workflow,
        coverage.get("workflow").unwrap_or(&BTreeMap::new()),
        context,
        &mut errors,
    );
    validate_rows(
        root,
        "foundation backlog items",
        foundation_rows(&context.build_sheet)
            .iter()
            .map(|row| row.item.as_str())
            .collect(),
        CoverageKind::Foundation,
        coverage.get("foundation").unwrap_or(&BTreeMap::new()),
        context,
        &mut errors,
    );
    validate_rows(
        root,
        "information architecture areas",
        information_architecture_rows(&context.build_sheet)
            .iter()
            .map(|row| row.area.as_str())
            .collect(),
        CoverageKind::InformationArchitecture,
        coverage.get("ia").unwrap_or(&BTreeMap::new()),
        context,
        &mut errors,
    );

    errors
}

fn validate_rows(
    root: &Path,
    label: &str,
    names: Vec<&str>,
    kind: CoverageKind,
    coverage_map: &BTreeMap<String, Vec<CoverageEntry>>,
    context: &Context,
    errors: &mut Vec<String>,
) {
    let name_set: BTreeSet<&str> = names.iter().copied().collect();
    let coverage_keys: BTreeSet<&str> = coverage_map.keys().map(String::as_str).collect();

    let missing: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| !coverage_keys.contains(name))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("{label} missing coverage mapping: {}", missing.join(", ")),
    );

    let stale: Vec<&str> = coverage_map
        .keys()
        .map(String::as_str)
        .filter(|name| !name_set.contains(name))
        .collect();
    expect(
        stale.is_empty(),
        errors,
        format!("coverage mappings without {label}: {}", stale.join(", ")),
    );

    for name in names {
        let Some(entries) = coverage_map.get(name) else {
            continue;
        };
        for entry in entries {
            validate_coverage_shape(name, entry, errors);
            validate_coverage_artifacts(root, name, kind, entry, context, errors);
        }
    }
}

fn workflow_rows(markdown: &str) -> Vec<WorkflowRow> {
    markdown
        .lines()
        .filter_map(markdown_cells)
        .filter(|cells| cells.len() >= 4 && priority_cell(&cells[0]))
        .map(|cells| WorkflowRow {
            priority: cells[0].clone(),
            workflow: cells[1].clone(),
            outcome: cells[2].clone(),
            integrations: cells[3].clone(),
        })
        .collect()
}

fn foundation_rows(markdown: &str) -> Vec<FoundationRow> {
    let mut rows = Vec::new();
    let mut in_section = false;

    for line in markdown.lines() {
        if line.starts_with("## P0 Foundation Backlog") {
            in_section = true;
        }
        if in_section && line.starts_with("## Core Workflow Backlog") {
            break;
        }
        if !in_section {
            continue;
        }

        let Some(cells) = markdown_cells(line) else {
            continue;
        };
        if cells.len() < 3 || cells[0] == "Item" || cells[0].starts_with("---") {
            continue;
        }

        rows.push(FoundationRow {
            item: cells[0].clone(),
            outcome: cells[1].clone(),
            owner_domain: cells[2].clone(),
        });
    }

    rows
}

fn information_architecture_rows(markdown: &str) -> Vec<InformationArchitectureRow> {
    let mut rows = Vec::new();
    let mut in_section = false;

    for line in markdown.lines() {
        if line.starts_with("## Information Architecture Backlog") {
            in_section = true;
        }
        if in_section && line.starts_with("## Data Model Themes") {
            break;
        }
        if !in_section {
            continue;
        }

        let Some(cells) = markdown_cells(line) else {
            continue;
        };
        if cells.len() < 3 || cells[0] == "Area" || cells[0].starts_with("---") {
            continue;
        }

        rows.push(InformationArchitectureRow {
            area: cells[0].clone(),
            p0_views: cells[1].clone(),
            later_views: cells[2].clone(),
        });
    }

    rows
}

fn markdown_cells(line: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(
        parts[1..parts.len() - 1]
            .iter()
            .map(|cell| cell.trim().to_string())
            .collect(),
    )
}

fn priority_cell(value: &str) -> bool {
    matches!(value, "P0" | "P1" | "P2" | "P3")
}

fn validate_coverage_shape(workflow: &str, coverage: &CoverageEntry, errors: &mut Vec<String>) {
    expect(
        safe_artifact_path(&coverage.catalog),
        errors,
        format!("{workflow} catalog coverage path is unsafe"),
    );
    expect(
        safe_artifact_path(&coverage.doc),
        errors,
        format!("{workflow} workflow doc coverage path is unsafe"),
    );
    expect(
        safe_endpoint(&coverage.endpoint),
        errors,
        format!("{workflow} API endpoint coverage path is unsafe"),
    );
}

fn validate_coverage_artifacts(
    root: &Path,
    workflow: &str,
    kind: CoverageKind,
    coverage: &CoverageEntry,
    context: &Context,
    errors: &mut Vec<String>,
) {
    let catalog_path = Path::new("catalog").join(&coverage.catalog);
    let doc_path = Path::new("docs/workflows").join(&coverage.doc);

    expect(
        root.join(&catalog_path).is_file(),
        errors,
        format!(
            "{workflow} missing catalog artifact {}",
            catalog_path.display()
        ),
    );
    expect(
        root.join(&doc_path).is_file(),
        errors,
        format!(
            "{workflow} missing workflow document {}",
            doc_path.display()
        ),
    );
    expect(
        context.catalog_readme.contains(&coverage.catalog),
        errors,
        format!(
            "{} missing catalog README entry {}",
            display_name(workflow, kind),
            coverage.catalog
        ),
    );
    expect(
        context.workflow_readme.contains(&coverage.doc),
        errors,
        format!(
            "{} missing workflow README entry {}",
            display_name(workflow, kind),
            coverage.doc
        ),
    );
    expect(
        context.api_readme.contains(&coverage.endpoint),
        errors,
        format!(
            "{} missing API README endpoint {}",
            display_name(workflow, kind),
            coverage.endpoint
        ),
    );
    let active_routes = active_route_registrations(&context.program);
    expect(
        active_routes.contains(coverage.endpoint.as_str()),
        errors,
        format!(
            "{} missing API endpoint {}",
            display_name(workflow, kind),
            coverage.endpoint
        ),
    );
}

fn display_name(name: &str, kind: CoverageKind) -> String {
    match kind {
        CoverageKind::Workflow => name.to_string(),
        CoverageKind::Foundation => name.to_string(),
        CoverageKind::InformationArchitecture => name.to_string(),
    }
}

fn safe_artifact_path(path: &str) -> bool {
    let Some(stem) = path
        .strip_suffix(".md")
        .or_else(|| path.strip_suffix(".yaml"))
    else {
        return false;
    };
    if stem.is_empty() || stem.starts_with('-') || stem.ends_with('-') {
        return false;
    }
    stem.split('-').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    })
}

fn safe_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("/api/") else {
        return false;
    };
    let Some(first) = rest.bytes().next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && rest.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'/' || byte == b'-'
        })
}

// Extracts the route paths registered through axum `.route("...", ...)` calls
// in the Rust API sources, ignoring commented-out registrations.
fn active_route_registrations(source: &str) -> BTreeSet<String> {
    let source = strip_source_comments(source);
    source
        .split(".route(")
        .skip(1)
        .filter_map(|candidate| {
            let rest = candidate.trim_start();
            let route = rest.strip_prefix('"')?;
            let end = route.find('"')?;
            Some(route[..end].to_string())
        })
        .collect()
}

const RUST_API_ROUTE_SOURCES: &[&str] = &[
    RUST_API_CONTRACTS_PATH,
    RUST_API_MAIN_PATH,
    RUST_API_BOUNDARY_PATH,
];
const ROUTE_METHOD_TOKENS: &[(&str, &str)] = &[
    ("get(", "GET"),
    ("post(", "POST"),
    ("put(", "PUT"),
    ("patch(", "PATCH"),
    ("delete(", "DELETE"),
    ("head(", "HEAD"),
    ("options(", "OPTIONS"),
    ("any(", "ANY"),
];

// Builds the generated API endpoint inventory (docs/api/endpoints.md) from the
// axum `.route("...", method(handler))` registrations in the Rust API sources.
// The document doubles as the shared "API readme" context for slice checks.
fn generate_endpoints_doc(root: &Path) -> Result<(String, usize), String> {
    let mut routes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for source_path in RUST_API_ROUTE_SOURCES {
        let source = read(root, source_path)?;
        for (path, methods) in extract_route_methods(&source) {
            routes.entry(path).or_default().extend(methods);
        }
    }

    // Group routes by API area (the first path segment after /api/; the few
    // non-/api paths such as /health group under "platform") so the published
    // reference gets navigable sections instead of one flat table.
    let mut sections: BTreeMap<String, Vec<(&String, &BTreeSet<String>)>> = BTreeMap::new();
    for (path, methods) in &routes {
        sections
            .entry(endpoints_doc_section(path))
            .or_default()
            .push((path, methods));
    }
    let route_count: usize = routes.values().map(BTreeSet::len).sum();

    let mut document = String::new();
    document.push_str("# Ryuki API Endpoints\n\n");
    document.push_str(&format!(
        "The control plane serves {route_count} routes across {} areas. Most routes \
         require an authenticated session or an API bearer token; a small set is \
         deliberately unauthenticated, such as health probes, agent registration, and \
         the control-plane public key. Authorization is tiered per route (admin, \
         approve, execute, request, audit) and reads are narrowed by the caller's \
         site and environment scopes; [RBAC & Scoping](rbac-and-scoping.md) documents \
         the enforcement semantics.\n\n",
        sections.len()
    ));
    document.push_str(
        "Generated by `ryuki-validator generate-endpoints-doc` from the route \
         registrations in:\n\n",
    );
    for source_path in RUST_API_ROUTE_SOURCES {
        document.push_str(&format!("- `{source_path}`\n"));
    }
    document.push_str(
        "\nRegenerate with `cargo run --manifest-path scripts/validator-rs/Cargo.toml -- \
         generate-endpoints-doc`. Do not edit by hand.\n\n",
    );
    document.push_str("## Contents\n\n");
    for (name, entries) in &sections {
        let section_routes: usize = entries.iter().map(|(_, methods)| methods.len()).sum();
        let noun = if section_routes == 1 { "route" } else { "routes" };
        document.push_str(&format!("- [{name}](#{name}) ({section_routes} {noun})\n"));
    }
    for (name, entries) in &sections {
        let prefix = if name == "platform" {
            "Routes outside the `/api` prefix.".to_string()
        } else {
            format!("Routes under `/api/{name}`.")
        };
        document.push_str(&format!("\n## {name}\n\n{prefix}\n\n"));
        document.push_str("| Method | Path |\n| --- | --- |\n");
        for (path, methods) in entries {
            for method in methods.iter() {
                document.push_str(&format!("| {method} | `{path}` |\n"));
            }
        }
    }
    Ok((document, route_count))
}

// The grouping key for the endpoint inventory: first segment after /api/,
// or "platform" for the few paths registered outside the /api prefix.
fn endpoints_doc_section(path: &str) -> String {
    let mut parts = path.trim_start_matches('/').split('/');
    match parts.next() {
        Some("api") => parts
            .next()
            .filter(|segment| !segment.is_empty())
            .unwrap_or("api")
            .to_string(),
        _ => "platform".to_string(),
    }
}

// Extracts (path, methods) pairs from active `.route("path", get(handler))`
// registrations, including chained registrations like `get(a).post(b)`.
fn extract_route_methods(source: &str) -> Vec<(String, Vec<String>)> {
    let source = strip_source_comments(source);
    let mut results = Vec::new();
    for candidate in source.split(".route(").skip(1) {
        let rest = candidate.trim_start();
        let Some(route) = rest.strip_prefix('"') else {
            continue;
        };
        let Some(end) = route.find('"') else {
            continue;
        };
        let path = route[..end].to_string();
        let arguments = route_call_arguments(&route[end + 1..]);
        let methods = route_methods_in(&arguments);
        results.push((path, methods));
    }
    results
}

// Returns the text between the route path and the closing parenthesis of the
// `.route(...)` call, tracking nested parentheses.
fn route_call_arguments(after_path: &str) -> String {
    let mut depth: usize = 1;
    let mut arguments = String::new();
    for ch in after_path.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        arguments.push(ch);
    }
    arguments
}

fn route_methods_in(arguments: &str) -> Vec<String> {
    let mut methods = Vec::new();
    for (token, method) in ROUTE_METHOD_TOKENS {
        for (index, _) in arguments.match_indices(token) {
            let boundary_ok = arguments[..index]
                .chars()
                .next_back()
                .is_none_or(|ch| !ch.is_ascii_alphanumeric() && ch != '_');
            if boundary_ok && !methods.contains(&(*method).to_string()) {
                methods.push((*method).to_string());
            }
        }
    }
    if methods.is_empty() {
        methods.push("ANY".to_string());
    }
    methods
}

// Strips `//` line comments and `/* */` block comments while preserving string
// literals; the syntax is shared by Rust (and the retired C# sources).
fn strip_source_comments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                output.push(ch);
            }
            continue;
        }

        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            } else if ch == '\n' {
                output.push(ch);
            }
            continue;
        }

        if in_string {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            output.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
        } else {
            output.push(ch);
        }
    }

    output
}

fn expect(condition: bool, errors: &mut Vec<String>, message: String) {
    if !condition {
        errors.push(message);
    }
}

type ValidateFn = fn(&Path) -> Result<Vec<String>, String>;

fn validate_dispatch_table() -> std::collections::HashMap<&'static str, ValidateFn> {
    let mut m = std::collections::HashMap::new();
    m.insert(
        "access-review-recertification",
        access_review_recertification::validate_context_file as ValidateFn,
    );
    m.insert(
        "activity-operation-queue",
        activity_operation_queue::validate_context_file as ValidateFn,
    );
    m.insert(
        "api-token-safety",
        api_token_safety::validate_context_file as ValidateFn,
    );
    m.insert(
        "ad-computer-lifecycle",
        ad_computer_lifecycle::validate_context_file as ValidateFn,
    );
    m.insert(
        "adapter-contracts",
        adapter_contract::validate_context_file as ValidateFn,
    );
    m.insert(
        "adapter-contract-test",
        adapter_contract_test::validate_context_file as ValidateFn,
    );
    m.insert(
        "adapter-readiness-matrix",
        adapter_readiness_matrix::validate_context_file as ValidateFn,
    );
    m.insert(
        "admin-approval-groups",
        admin_approval_groups::validate_context_file as ValidateFn,
    );
    m.insert(
        "admin-delegation-boundary",
        admin_delegation_boundary::validate_context_file as ValidateFn,
    );
    m.insert(
        "admin-feature-flag-governance",
        admin_feature_flag::validate_context_file as ValidateFn,
    );
    m.insert(
        "aiops-suggestion",
        aiops_suggestion::validate_context_file as ValidateFn,
    );
    m.insert(
        "alert-routing",
        alert_routing::validate_context_file as ValidateFn,
    );
    m.insert(
        "app-skeleton",
        app_skeleton::validate_context_file as ValidateFn,
    );
    m.insert(
        "application-aware-backup",
        application_aware_backup::validate_context_file as ValidateFn,
    );
    m.insert(
        "application-environment-deployment",
        application_environment_deployment::validate_context_file as ValidateFn,
    );
    m.insert(
        "application-environment-retirement",
        application_environment_retirement::validate_context_file as ValidateFn,
    );
    m.insert(
        "approval-decision-readiness",
        approval_decision_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "approved-software-deployment",
        approved_software_deployment::validate_context_file as ValidateFn,
    );
    m.insert(
        "azure-landing-zone-validation",
        azure_landing_zone::validate_context_file as ValidateFn,
    );
    m.insert(
        "backup-coverage-gap",
        backup_coverage_gap::validate_context_file as ValidateFn,
    );
    m.insert(
        "backup-dr-assignment",
        backup_dr_assignment::validate_context_file as ValidateFn,
    );
    m.insert("catalog", catalog::validate_context_file as ValidateFn);
    m.insert(
        "certificate-lifecycle",
        certificate_lifecycle::validate_context_file as ValidateFn,
    );
    m.insert(
        "cluster-capacity-admission",
        cluster_capacity_admission::validate_context_file as ValidateFn,
    );
    m.insert(
        "cmdb-file-exchange",
        cmdb_file_exchange::validate_context_file as ValidateFn,
    );
    m.insert(
        "cmdb-impact-analysis",
        cmdb_impact_analysis::validate_context_file as ValidateFn,
    );
    m.insert(
        "cmdb-reconciliation",
        cmdb_reconciliation::validate_context_file as ValidateFn,
    );
    m.insert(
        "cmdb-relationship-graph",
        cmdb_relationship_graph::validate_context_file as ValidateFn,
    );
    m.insert("compose", compose::validate_context_file as ValidateFn);
    m.insert(
        "controlled-restore",
        controlled_restore::validate_context_file as ValidateFn,
    );
    m.insert(
        "control-plane-db-backup",
        control_plane_db_backup::validate_context_file as ValidateFn,
    );
    m.insert(
        "release-engineering",
        release_engineering::validate_context_file as ValidateFn,
    );
    m.insert(
        "cost-capacity-analytics",
        cost_capacity::validate_context_file as ValidateFn,
    );
    m.insert(
        "customization-spec-governance",
        customization_spec_governance::validate_context_file as ValidateFn,
    );
    m.insert(
        "dashboard-global-overview",
        dashboard_global_overview::validate_context_file as ValidateFn,
    );
    m.insert(
        "dashboard-risk-heatmap",
        dashboard_risk_heatmap::validate_context_file as ValidateFn,
    );
    m.insert(
        "datacenter-readiness",
        datacenter_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "degradation-mode",
        degradation_mode::validate_context_file as ValidateFn,
    );
    m.insert(
        "dependency-maintenance-calendar",
        dependency_maintenance_calendar::validate_context_file as ValidateFn,
    );
    // "deployment-input-template" and "operations-endpoint-inventory" were
    // unregistered together with their COVERAGE_TSV rows: the docs/source-inputs
    // and docs/operations artifacts they validate were never created and no
    // mounted route serves them. Re-register when those docs trees exist
    // (their standalone validate/validate-docs subcommand arms remain usable).
    m.insert(
        "design-system",
        design_system::validate_context_file as ValidateFn,
    );
    m.insert(
        "docker-image",
        docker_image::validate_context_file as ValidateFn,
    );
    m.insert(
        "emergency-change",
        emergency_change::validate_context_file as ValidateFn,
    );
    m.insert(
        "entra-rbac-approval-readiness",
        entra_rbac_approval_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "evidence-compliance-dashboard",
        evidence_compliance_dashboard::validate_context_file as ValidateFn,
    );
    m.insert(
        "evidence-export-retention",
        evidence_export_retention::validate_context_file as ValidateFn,
    );
    m.insert(
        "evidence-manifest",
        evidence_manifest::validate_context_file as ValidateFn,
    );
    m.insert(
        "evidence-redaction-contract",
        evidence_redaction_contract::validate_context_file as ValidateFn,
    );
    m.insert(
        "file-share-ntfs-recertification",
        file_share_ntfs_recertification::validate_context_file as ValidateFn,
    );
    m.insert(
        "firmware-compliance-exception",
        firmware_compliance_exception::validate_context_file as ValidateFn,
    );
    m.insert(
        "gmsa-lifecycle",
        gmsa_lifecycle::validate_context_file as ValidateFn,
    );
    m.insert(
        "governance-catalog-api",
        governance_catalog_api::validate_context_file as ValidateFn,
    );
    m.insert(
        "hardware-lifecycle",
        hardware_lifecycle::validate_context_file as ValidateFn,
    );
    m.insert(
        "image-factory",
        image_factory::validate_context_file as ValidateFn,
    );
    m.insert(
        "immutability-air-gap-compliance",
        immutability_air_gap_compliance::validate_context_file as ValidateFn,
    );
    m.insert(
        "incident-context",
        incident_context::validate_context_file as ValidateFn,
    );
    m.insert(
        "inventory-coverage",
        inventory_coverage::validate_context_file as ValidateFn,
    );
    m.insert(
        "inventory-ownership-risk",
        inventory_ownership_risk::validate_context_file as ValidateFn,
    );
    m.insert(
        "inventory-resource-overview",
        inventory_resource_overview::validate_context_file as ValidateFn,
    );
    m.insert(
        "knowledge-suggestion",
        knowledge_suggestion::validate_context_file as ValidateFn,
    );
    m.insert(
        "kubernetes-manifest",
        kubernetes_manifest::validate_context_file as ValidateFn,
    );
    m.insert(
        "kubernetes-runtime-readiness",
        kubernetes_runtime_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "legal-hold-retention",
        legal_hold_retention::validate_context_file as ValidateFn,
    );
    m.insert(
        "local-auth",
        local_auth::validate_context_file as ValidateFn,
    );
    m.insert(
        "local-container-readiness",
        local_container_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "local-privilege-access",
        local_privilege_access::validate_context_file as ValidateFn,
    );
    m.insert(
        "log-forwarder-onboarding",
        log_forwarder_onboarding::validate_context_file as ValidateFn,
    );
    m.insert(
        "maintenance-communications",
        maintenance_communications::validate_context_file as ValidateFn,
    );
    m.insert(
        "monitoring-coverage-gap",
        monitoring_coverage_gap::validate_context_file as ValidateFn,
    );
    m.insert(
        "monitoring-review-queue",
        monitoring_review_queue::validate_context_file as ValidateFn,
    );
    m.insert(
        "network-vlan-readiness",
        network_vlan_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "noise-flapping-remediation",
        noise_flapping_remediation::validate_context_file as ValidateFn,
    );
    m.insert(
        "object-storage-readiness",
        object_storage_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "observability-deploy-wiring",
        observability_deploy_wiring::validate_context_file as ValidateFn,
    );
    m.insert(
        "offering-catalog-api",
        offering_catalog_api::validate_context_file as ValidateFn,
    );
    m.insert(
        "offering-recommendations",
        offering_recommendations::validate_context_file as ValidateFn,
    );
    m.insert(
        "operation-dependency-replay",
        operation_dependency_replay::validate_context_file as ValidateFn,
    );
    m.insert(
        "operation-run-state",
        operation_run_state::validate_context_file as ValidateFn,
    );
    m.insert(
        "operator-runbook",
        operator_runbook::validate_context_file as ValidateFn,
    );
    m.insert(
        "os-baseline-compliance",
        os_baseline_compliance::validate_context_file as ValidateFn,
    );
    m.insert(
        "out-of-band-access-validation",
        out_of_band_access::validate_context_file as ValidateFn,
    );
    m.insert(
        "patch-maintenance",
        patch_maintenance::validate_context_file as ValidateFn,
    );
    m.insert(
        "patch-policy-import",
        patch_policy_import::validate_context_file as ValidateFn,
    );
    m.insert(
        "platform-database-readiness",
        platform_database_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "platform-health",
        platform_health::validate_context_file as ValidateFn,
    );
    m.insert(
        "platform-release-promotion",
        platform_release_promotion::validate_context_file as ValidateFn,
    );
    m.insert(
        "policy-guardrail-api",
        policy_guardrail_api::validate_context_file as ValidateFn,
    );
    m.insert(
        "portal-information-architecture",
        portal_information_architecture::validate_context_file as ValidateFn,
    );
    m.insert(
        "rbac-approval-model",
        rbac_approval_model::validate_context_file as ValidateFn,
    );
    m.insert(
        "reboot-orchestration",
        reboot_orchestration::validate_context_file as ValidateFn,
    );
    m.insert(
        "registry-readiness",
        registry_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "release-image-builds",
        release_image_builds::validate_context_file as ValidateFn,
    );
    m.insert(
        "repository-capacity-forecast",
        repository_capacity_forecast::validate_context_file as ValidateFn,
    );
    m.insert(
        "request-execution-timeline",
        request_execution_timeline::validate_context_file as ValidateFn,
    );
    m.insert(
        "request-form-contract",
        request_form_contract::validate_context_file as ValidateFn,
    );
    m.insert(
        "request-intake-support",
        request_intake_support::validate_context_file as ValidateFn,
    );
    m.insert(
        "request-lifecycle",
        request_lifecycle::validate_context_file as ValidateFn,
    );
    m.insert(
        "request-preflight",
        request_preflight::validate_context_file as ValidateFn,
    );
    m.insert(
        "restore-testing",
        restore_testing::validate_context_file as ValidateFn,
    );
    m.insert(
        "secret-reference",
        secret_reference::validate_context_file as ValidateFn,
    );
    m.insert(
        "security-baseline",
        security_baseline::validate_context_file as ValidateFn,
    );
    m.insert(
        "sensitive-output-guardrails",
        sensitive_output_guardrails::validate_context_file as ValidateFn,
    );
    m.insert(
        "server-lifecycle-dry-run",
        server_lifecycle::validate_context_file as ValidateFn,
    );
    m.insert(
        "servicenow-future-api",
        servicenow_future_api::validate_context_file as ValidateFn,
    );
    m.insert(
        "shift-queue",
        shift_queue::validate_context_file as ValidateFn,
    );
    m.insert("ryuki-api", ryuki_api::validate_context_file as ValidateFn);
    m.insert(
        "ryuki-engine",
        ryuki_engine::validate_context_file as ValidateFn,
    );
    m.insert(
        "site-catalog-contract",
        site_catalog_contract::validate_context_file as ValidateFn,
    );
    m.insert(
        "snapshot-governance",
        snapshot_governance::validate_context_file as ValidateFn,
    );
    m.insert(
        "sql-server-deployment",
        sql_server_deployment::validate_context_file as ValidateFn,
    );
    m.insert(
        "standard-task",
        standard_task::validate_context_file as ValidateFn,
    );
    m.insert(
        "synthetic-health-check",
        synthetic_health_check::validate_context_file as ValidateFn,
    );
    m.insert(
        "ui-mockup-acceptance",
        ui_mockup_acceptance::validate_context_file as ValidateFn,
    );
    m.insert(
        "vault-deployment-readiness",
        vault_deployment_readiness::validate_context_file as ValidateFn,
    );
    m.insert(
        "vault-foundation",
        vault_foundation::validate_context_file as ValidateFn,
    );
    m.insert(
        "vault-secret-delivery",
        vault_secret_delivery::validate_context_file as ValidateFn,
    );
    m.insert(
        "vcenter-object-placement",
        vcenter_object_placement::validate_context_file as ValidateFn,
    );
    m.insert(
        "vm-day2-change",
        vm_day2_change::validate_context_file as ValidateFn,
    );
    m.insert(
        "vm-decommission-quarantine",
        vm_decommission_quarantine::validate_context_file as ValidateFn,
    );
    m.insert(
        "vsan-esxi-lifecycle",
        vsan_esxi_lifecycle::validate_context_file as ValidateFn,
    );
    m.insert(
        "worker-capability",
        worker_capability::validate_context_file as ValidateFn,
    );
    m.insert(
        "zabbix-drift-remediation",
        zabbix_drift_remediation::validate_context_file as ValidateFn,
    );
    m.insert(
        "zabbix-onboarding",
        zabbix_onboarding::validate_context_file as ValidateFn,
    );
    m
}

fn validate_slice_inner(
    slice: &str,
    root: &Path,
    context_json: Option<&Path>,
) -> Result<Vec<String>, String> {
    match slice {
        "backlog-coverage" => {
            let context = match context_json {
                Some(path) => read_context_json(path)?,
                None => read_context(root)?,
            };
            Ok(validate_context(root, &context))
        }
        other => {
            let path = context_json
                .ok_or_else(|| format!("{other} validation requires --context-json"))?;
            let dispatch = validate_dispatch_table();
            match dispatch.get(other) {
                Some(func) => func(path),
                None => Err(format!("unknown slice: {other}")),
            }
        }
    }
}

fn catalog_to_slice(catalog: &str) -> String {
    let stem = catalog.strip_suffix(".yaml").unwrap_or(catalog);
    match stem {
        "application-aware-backup-validation-contract" => "application-aware-backup".to_string(),
        "site-catalog" => "site-catalog-contract".to_string(),
        "policy-guardrails" => "policy-guardrail-api".to_string(),
        "offering-catalog" => "offering-catalog-api".to_string(),
        "ryuki-engine-catalog" => "ryuki-engine".to_string(),
        "ryuki-api-catalog" => "ryuki-api".to_string(),
        "secret-reference-catalog" => "secret-reference".to_string(),
        "adapter-readiness-catalog" => "adapter-contracts".to_string(),
        "evidence-manifest-catalog" => "evidence-manifest".to_string(),
        "backlog-coverage-catalog" => "backlog-coverage".to_string(),
        // Keep -contract because the slice name includes it (no valid slice without it)
        "evidence-redaction-contract" => "evidence-redaction-contract".to_string(),
        "request-form-contract" => "request-form-contract".to_string(),
        // Default: strip trailing -contract to get slice name
        s if s.ends_with("-contract") => s.strip_suffix("-contract").unwrap().to_string(),
        other => other.to_string(),
    }
}

pub(crate) struct SliceEntry {
    pub(crate) slice: String,
    pub(crate) catalog_file: String,
    pub(crate) doc_file: String,
    pub(crate) endpoint: String,
}

pub(crate) fn slices_from_coverage() -> Vec<SliceEntry> {
    let mut seen: std::collections::BTreeMap<String, SliceEntry> =
        std::collections::BTreeMap::new();
    for line in COVERAGE_TSV
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        let cells: Vec<&str> = line.split('\t').collect();
        if cells.len() != 5 {
            continue;
        }
        let slice = catalog_to_slice(cells[2]);
        seen.entry(slice.clone()).or_insert(SliceEntry {
            slice,
            catalog_file: cells[2].to_string(),
            doc_file: cells[3].to_string(),
            endpoint: cells[4].to_string(),
        });
    }
    seen.into_values().collect()
}

// Every COVERAGE_TSV row (without slice-level dedupe) with its resolved
// slice name; input for the `scaffold-docs` subcommand and its tests.
pub(crate) fn registry_rows() -> Vec<scaffold_docs::RegistryRow> {
    COVERAGE_TSV
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            if cells.len() != 5 {
                return None;
            }
            Some(scaffold_docs::RegistryRow {
                kind: cells[0].to_string(),
                workflow: cells[1].to_string(),
                catalog_file: cells[2].to_string(),
                doc_file: cells[3].to_string(),
                endpoint: cells[4].to_string(),
                slice: catalog_to_slice(cells[2]),
            })
        })
        .collect()
}

struct SharedContext {
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    ryuki_engine_cargo: String,
    ryuki_engine_lib: String,
    ryuki_engine_adapter_framework: String,
    ryuki_api_cargo: String,
    ryuki_api_contracts: String,
    ryuki_api_main: String,
    ryuki_api_boundary: String,
}

fn load_shared_context(root: &Path) -> SharedContext {
    SharedContext {
        // "program" is the Rust API route/handler source; "api_readme" is the
        // generated endpoint inventory (docs/api/endpoints.md).
        program: read(root, RUST_API_CONTRACTS_PATH).unwrap_or_default(),
        api_readme: read(root, API_ENDPOINTS_DOC_PATH).unwrap_or_default(),
        catalog_readme: read(root, CATALOG_README_PATH).unwrap_or_default(),
        doc_readme: read(root, WORKFLOW_README_PATH).unwrap_or_default(),
        ryuki_engine_cargo: read(root, "sources/ryuki-engine/Cargo.toml").unwrap_or_default(),
        ryuki_engine_lib: read(root, "sources/ryuki-engine/src/lib.rs").unwrap_or_default(),
        ryuki_engine_adapter_framework: read(root, "sources/ryuki-engine/src/adapter_framework.rs")
            .unwrap_or_default(),
        ryuki_api_cargo: read(root, "sources/ryuki-api/Cargo.toml").unwrap_or_default(),
        ryuki_api_contracts: read(root, RUST_API_CONTRACTS_PATH).unwrap_or_default(),
        ryuki_api_main: read(root, RUST_API_MAIN_PATH).unwrap_or_default(),
        ryuki_api_boundary: read(root, RUST_API_BOUNDARY_PATH).unwrap_or_default(),
    }
}

fn readme_key_for_slice(slice: &str) -> &str {
    match slice {
        "server-lifecycle-dry-run" | "aiops-suggestion" | "inventory-coverage" => "readme",
        _ => "api_readme",
    }
}

// Reads a context input file, defaulting to an empty string when the file is
// missing so slice modules report the missing artifact as a validation error
// instead of failing context deserialization.
fn read_string_value(root: &Path, path: &str) -> serde_json::Value {
    serde_json::Value::String(fs::read_to_string(root.join(path)).unwrap_or_default())
}

fn build_slice_context(
    root: &Path,
    entry: &SliceEntry,
    shared: &SharedContext,
) -> serde_json::Value {
    let catalog_path = Path::new("catalog").join(&entry.catalog_file);
    let doc_path = Path::new("docs/workflows").join(&entry.doc_file);

    let catalog_raw = fs::read_to_string(root.join(&catalog_path)).unwrap_or_default();
    let catalog_value: serde_json::Value = if catalog_raw.is_empty() {
        serde_json::Value::Null
    } else {
        serde_yaml::from_str(&catalog_raw).unwrap_or(serde_json::Value::Null)
    };
    let doc_content = fs::read_to_string(root.join(&doc_path)).unwrap_or_default();

    let is_ryuki_engine = entry.slice == "ryuki-engine";
    let is_ryuki_api = entry.slice == "ryuki-api";
    let readme_key = readme_key_for_slice(&entry.slice);

    let mut map = serde_json::Map::new();
    map.insert("catalog".to_string(), catalog_value);
    map.insert(
        "catalog_text".to_string(),
        serde_json::Value::String(catalog_raw),
    );
    map.insert(
        "program".to_string(),
        serde_json::Value::String(shared.program.clone()),
    );
    map.insert(
        "catalog_readme".to_string(),
        serde_json::Value::String(shared.catalog_readme.clone()),
    );
    map.insert(
        "doc_readme".to_string(),
        serde_json::Value::String(shared.doc_readme.clone()),
    );
    map.insert("doc".to_string(), serde_json::Value::String(doc_content));
    map.insert(
        "endpoint".to_string(),
        serde_json::Value::String(entry.endpoint.clone()),
    );
    map.insert(
        "cargo_toml".to_string(),
        serde_json::Value::String(if is_ryuki_engine {
            shared.ryuki_engine_cargo.clone()
        } else if is_ryuki_api {
            shared.ryuki_api_cargo.clone()
        } else {
            String::new()
        }),
    );
    map.insert(
        "lib_rs".to_string(),
        serde_json::Value::String(shared.ryuki_engine_lib.clone()),
    );
    map.insert(
        "contracts_rs".to_string(),
        serde_json::Value::String(shared.ryuki_api_contracts.clone()),
    );
    map.insert(
        "main_rs".to_string(),
        serde_json::Value::String(shared.ryuki_api_main.clone()),
    );
    map.insert(
        "boundary_rs".to_string(),
        serde_json::Value::String(shared.ryuki_api_boundary.clone()),
    );
    map.insert(
        "adapter_framework_rs".to_string(),
        serde_json::Value::String(shared.ryuki_engine_adapter_framework.clone()),
    );
    map.insert(
        readme_key.to_string(),
        serde_json::Value::String(shared.api_readme.clone()),
    );

    // Per-slice extra fields
    match entry.slice.as_str() {
        "backlog-coverage" => {
            map.insert(
                "build_sheet".to_string(),
                read_string_value(root, BUILD_SHEET_PATH),
            );
            map.insert(
                "workflow_readme".to_string(),
                serde_json::Value::String(shared.doc_readme.clone()),
            );
        }
        "governance-catalog-api" => {
            map.insert(
                "readme".to_string(),
                serde_json::Value::String(shared.api_readme.clone()),
            );
            for (key, path) in &[
                ("access_catalog", "catalog/access-control-catalog.yaml"),
                ("secret_catalog", "catalog/secret-reference-catalog.yaml"),
                ("evidence_catalog", "catalog/evidence-manifest-catalog.yaml"),
            ] {
                let raw = fs::read_to_string(root.join(path)).unwrap_or_default();
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert(key.to_string(), val);
            }
        }
        "approval-decision-readiness" => {
            if let Ok(raw) = fs::read_to_string(root.join("catalog/access-control-catalog.yaml")) {
                map.insert("access_text".to_string(), serde_json::Value::String(raw));
            }
        }
        "azure-landing-zone-validation" => {
            // Inserted unconditionally: when the source inventory doc is
            // missing the slice should report that as a validation error,
            // not fail context deserialization.
            map.insert(
                "source_inventory".to_string(),
                read_string_value(
                    root,
                    "docs/source-inputs/azure-landing-zone-source-inventory.md",
                ),
            );
        }
        "synthetic-health-check" => {
            if let Ok(raw) =
                fs::read_to_string(root.join("sources/ryuki-engine/src/synthetic_health.rs"))
            {
                map.insert(
                    "synthetic_health_rs".to_string(),
                    serde_json::Value::String(raw),
                );
            }
        }
        "design-system" => {
            for (key, path) in &[
                ("ui_design", "docs/ui/design-system.md"),
                ("accessibility", "docs/ui/accessibility-checklist.md"),
                ("portal_css", "portal/portal-ui/styles.css"),
            ] {
                map.insert(key.to_string(), read_string_value(root, path));
            }
        }
        "ui-mockup-acceptance" => {
            for (key, path) in &[
                ("ui_readme", "docs/ui/README.md"),
                ("shell_mockup", "docs/ui/mockups-shell-dashboard.md"),
                ("catalog_mockup", "docs/ui/mockups-catalog-requests.md"),
                ("inventory_mockup", "docs/ui/mockups-inventory-cmdb.md"),
                (
                    "evidence_mockup",
                    "docs/ui/mockups-evidence-operations-admin.md",
                ),
                ("accessibility", "docs/ui/accessibility-checklist.md"),
                ("ui_ia", "docs/ui/portal-information-architecture.md"),
                ("ui_design", "docs/ui/design-system.md"),
            ] {
                map.insert(key.to_string(), read_string_value(root, path));
            }
        }
        "evidence-manifest" => {
            for (key, path) in &[
                ("access_catalog", "catalog/access-control-catalog.yaml"),
                ("offering_catalog", "catalog/offering-catalog.yaml"),
            ] {
                let raw = fs::read_to_string(root.join(path)).unwrap_or_default();
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert(key.to_string(), val);
            }
        }
        "evidence-export-retention" | "evidence-redaction-contract" => {
            if let Ok(raw) = fs::read_to_string(root.join("catalog/evidence-manifest-catalog.yaml"))
            {
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert("manifest".to_string(), val);
                map.insert("manifest_text".to_string(), serde_json::Value::String(raw));
            }
        }
        "inventory-coverage" => {
            if let Ok(raw) =
                fs::read_to_string(root.join("fixtures/inventory/coverage-sample.yaml"))
            {
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert("fixture".to_string(), val);
            }
        }
        "local-container-readiness" => {
            if let Ok(raw) = fs::read_to_string(root.join("portal/portal-ui/Dockerfile")) {
                map.insert(
                    "portal_dockerfile".to_string(),
                    serde_json::Value::String(raw),
                );
            }
            if let Ok(raw) = fs::read_to_string(root.join("portal/portal-ui/Cargo.toml")) {
                map.insert("portal_cargo".to_string(), serde_json::Value::String(raw));
            }
            if let Ok(raw) = fs::read_to_string(root.join("portal/portal-ui/src/main.rs")) {
                map.insert("portal_main".to_string(), serde_json::Value::String(raw));
            }
            if let Ok(raw) =
                fs::read_to_string(root.join("portal/portal-ui/src/server_boundary.rs"))
            {
                map.insert(
                    "portal_server_boundary".to_string(),
                    serde_json::Value::String(raw),
                );
            }
            if let Ok(raw) = fs::read_to_string(root.join("deploy/compose/compose.yaml")) {
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert("compose".to_string(), val);
            }
        }
        "portal-information-architecture" => {
            for (key, path) in &[
                ("portal_dockerfile", "portal/portal-ui/Dockerfile"),
                ("ui_ia", "docs/ui/portal-information-architecture.md"),
                ("ui_design", "docs/ui/design-system.md"),
                ("portal_cargo", "portal/portal-ui/Cargo.toml"),
                ("portal_main", "portal/portal-ui/src/main.rs"),
                ("portal_lib", "portal/portal-ui/src/lib.rs"),
                ("portal_app", "portal/portal-ui/src/app.rs"),
                ("portal_shell", "portal/portal-ui/src/shell.rs"),
                (
                    "workspace_catalog",
                    "portal/portal-ui/src/workspace_catalog.rs",
                ),
                (
                    "portal_workspaces",
                    "portal/portal-ui/src/views/workspaces.rs",
                ),
                ("portal_api", "portal/portal-ui/src/api.rs"),
                (
                    "portal_server_boundary",
                    "portal/portal-ui/src/server_boundary.rs",
                ),
            ] {
                map.insert(key.to_string(), read_string_value(root, path));
            }
        }
        "rbac-approval-model" => {
            if let Ok(raw) = fs::read_to_string(root.join("catalog/access-control-catalog.yaml")) {
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert("access_catalog".to_string(), val);
                map.insert("access_text".to_string(), serde_json::Value::String(raw));
            }
        }
        "request-form-contract" => {
            if let Ok(raw) = fs::read_to_string(root.join("catalog/offering-catalog.yaml")) {
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert("offering_catalog".to_string(), val);
            }
        }
        "security-baseline" => {
            for (key, path) in &[
                ("architecture_doc", "docs/architecture/security-baseline.md"),
                ("architecture_readme", "docs/architecture/README.md"),
                ("no_secret_scan", "scripts/no-secret-scan.sh"),
                ("build_sheet", BUILD_SHEET_PATH),
            ] {
                map.insert(key.to_string(), read_string_value(root, path));
            }
        }
        "ryuki-engine" => {
            if let Ok(raw) =
                fs::read_to_string(root.join("sources/ryuki-engine/src/adapter_framework.rs"))
            {
                map.insert(
                    "adapter_framework_rs".to_string(),
                    serde_json::Value::String(raw),
                );
            }
        }
        "app-skeleton" => {
            map.insert(
                "root".to_string(),
                serde_json::Value::String(root.to_string_lossy().to_string()),
            );
        }
        "observability-deploy-wiring" => {
            map.insert(
                "root".to_string(),
                serde_json::Value::String(root.to_string_lossy().to_string()),
            );
        }
        "control-plane-db-backup" => {
            map.insert(
                "root".to_string(),
                serde_json::Value::String(root.to_string_lossy().to_string()),
            );
        }
        "release-engineering" => {
            map.insert(
                "root".to_string(),
                serde_json::Value::String(root.to_string_lossy().to_string()),
            );
        }
        "catalog" => {
            for (key, path) in &[
                ("site_catalog", "catalog/site-catalog.yaml"),
                ("offering_catalog", "catalog/offering-catalog.yaml"),
                ("policy_catalog", "catalog/policy-guardrails.yaml"),
                ("access_catalog", "catalog/access-control-catalog.yaml"),
            ] {
                if let Ok(raw) = fs::read_to_string(root.join(path)) {
                    let val: serde_json::Value =
                        serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                    map.insert(key.to_string(), val);
                }
            }
        }
        "compose" => {
            if let Ok(raw) = fs::read_to_string(root.join("deploy/compose/compose.yaml")) {
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert("compose".to_string(), val);
            }
        }
        "kubernetes-manifest" => {
            // The deployment skeleton lives in deploy/kubernetes/base/*.yaml.
            // Load every base manifest file, split multi-document YAML on `---`,
            // and parse each document into a JSON value for the slice validator.
            // The configmap file is intentionally excluded: ConfigMaps carry app
            // configuration and are not part of the validated skeleton kinds.
            const BASE_MANIFEST_FILES: &[&str] = &[
                "deploy/kubernetes/base/namespace.yaml",
                "deploy/kubernetes/base/serviceaccounts.yaml",
                "deploy/kubernetes/base/deployments.yaml",
                "deploy/kubernetes/base/services.yaml",
                "deploy/kubernetes/base/ingress.yaml",
                "deploy/kubernetes/base/networkpolicies.yaml",
            ];
            let mut manifests = Vec::new();
            let mut source_texts = Vec::new();
            for rel in BASE_MANIFEST_FILES {
                let Ok(raw) = fs::read_to_string(root.join(rel)) else {
                    continue;
                };
                source_texts.push(serde_json::Value::String(raw.clone()));
                for document in raw.split("\n---") {
                    let trimmed = document.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(value) = serde_yaml::from_str::<serde_json::Value>(trimmed) {
                        if value.is_object() {
                            manifests.push(value);
                        }
                    }
                }
            }
            map.insert("manifests".to_string(), serde_json::Value::Array(manifests));
            map.insert(
                "source_texts".to_string(),
                serde_json::Value::Array(source_texts),
            );
        }
        "local-auth" => {
            if let Ok(raw) = fs::read_to_string(root.join("catalog/access-control-catalog.yaml")) {
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert("access_catalog".to_string(), val);
                map.insert(
                    "access_catalog_text".to_string(),
                    serde_json::Value::String(raw),
                );
            }
        }
        "platform-database-readiness" => {
            if let Ok(raw) =
                fs::read_to_string(root.join("deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml"))
            {
                map.insert(
                    "cnpg_cluster_text".to_string(),
                    serde_json::Value::String(raw),
                );
            }
        }
        "docker-image" => {
            if let Ok(raw) = fs::read_to_string(root.join("Cargo.toml")) {
                map.insert(
                    "workspace_manifest".to_string(),
                    serde_json::Value::String(raw),
                );
            }
            if let Ok(raw) = fs::read_to_string(root.join("sources/ryuki-api/Dockerfile")) {
                map.insert("api_dockerfile".to_string(), serde_json::Value::String(raw));
            }
            if let Ok(raw) = fs::read_to_string(root.join("portal/portal-ui/Dockerfile")) {
                map.insert(
                    "portal_dockerfile".to_string(),
                    serde_json::Value::String(raw),
                );
            }
            if let Ok(raw) = fs::read_to_string(root.join("deploy/ci/Dockerfile.validator")) {
                map.insert(
                    "validator_dockerfile".to_string(),
                    serde_json::Value::String(raw),
                );
            }
        }
        "release-image-builds" => {
            if let Ok(raw) = fs::read_to_string(root.join("sources/ryuki-api/Dockerfile")) {
                map.insert("api_dockerfile".to_string(), serde_json::Value::String(raw));
            }
            if let Ok(raw) = fs::read_to_string(root.join("portal/portal-ui/Dockerfile")) {
                map.insert(
                    "portal_dockerfile".to_string(),
                    serde_json::Value::String(raw),
                );
            }
            if let Ok(raw) = fs::read_to_string(root.join("deploy/compose/compose.yaml")) {
                map.insert("compose_yaml".to_string(), serde_json::Value::String(raw));
            }
            if let Ok(raw) = fs::read_to_string(root.join("deploy/ci/azure-pipelines.yml")) {
                map.insert("ci_yaml".to_string(), serde_json::Value::String(raw));
            }
            if let Ok(raw) = fs::read_to_string(root.join(".dockerignore")) {
                map.insert("dockerignore".to_string(), serde_json::Value::String(raw));
            }
        }
        "sensitive-output-guardrails" => {
            if let Ok(raw) = fs::read_to_string(root.join("sources/ryuki-api/src/main.rs")) {
                map.insert("auth_main".to_string(), serde_json::Value::String(raw));
            }
            if let Ok(raw) =
                fs::read_to_string(root.join("sources/ryuki-engine/src/evidence_pipeline.rs"))
            {
                map.insert(
                    "evidence_pipeline".to_string(),
                    serde_json::Value::String(raw),
                );
            }
            if let Ok(raw) =
                fs::read_to_string(root.join("sources/ryuki-engine/src/adapter_framework.rs"))
            {
                map.insert(
                    "adapter_framework".to_string(),
                    serde_json::Value::String(raw),
                );
            }
            if let Ok(raw) = fs::read_to_string(root.join("scripts/no-secret-scan.sh")) {
                map.insert("no_secret_scan".to_string(), serde_json::Value::String(raw));
            }
        }
        "vault-foundation" => {
            if let Ok(raw) =
                fs::read_to_string(root.join("deploy/kubernetes/vault/values-ha-raft.yaml"))
            {
                let val: serde_json::Value =
                    serde_yaml::from_str(&raw).unwrap_or(serde_json::Value::Null);
                map.insert("values_text".to_string(), serde_json::Value::String(raw));
                map.insert("values".to_string(), val);
            } else {
                map.insert(
                    "values_text".to_string(),
                    serde_json::Value::String(String::new()),
                );
                map.insert("values".to_string(), serde_json::Value::Null);
            }
            // The vault-foundation slice's content checks (README_PATH /
            // RUNBOOK_PATH constants) validate the Vault deployment artifacts
            // that live alongside the Helm values under deploy/kubernetes/vault/.
            // Earlier repair work repointed these at docs/architecture/README.md
            // and a never-created docs/operations/vault-operations.md, which made
            // the slice fail against the wrong (empty) inputs. Feed the real,
            // content-complete deploy artifacts the slice was written for.
            map.insert(
                "readme".to_string(),
                serde_json::Value::String(
                    fs::read_to_string(root.join("deploy/kubernetes/vault/README.md"))
                        .unwrap_or_default(),
                ),
            );
            map.insert(
                "runbook".to_string(),
                serde_json::Value::String(
                    fs::read_to_string(root.join("deploy/kubernetes/vault/bootstrap-runbook.md"))
                        .unwrap_or_default(),
                ),
            );
        }
        _ => {}
    }

    serde_json::Value::Object(map)
}

fn run_one_slice(root: &Path, entry: &SliceEntry, shared: &SharedContext) -> SliceResult {
    let start = Instant::now();

    let context_json = build_slice_context(root, entry, shared);
    let ctx_path = std::env::temp_dir().join(format!(
        "ryuki-ctx-{}-{}.json",
        std::process::id(),
        entry.slice
    ));
    if let Err(e) = fs::write(
        &ctx_path,
        serde_json::to_string(&context_json).unwrap_or_default(),
    ) {
        return SliceResult {
            slice: entry.slice.clone(),
            passed: false,
            errors: vec![format!("write error: {e}")],
            duration_ms: start.elapsed().as_millis() as u64,
        };
    }

    // Slice modules are isolated: a panic inside one module (for example a
    // byte-boundary bug while scanning sources) is reported as that slice's
    // failure instead of aborting the whole run.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        validate_slice_inner(&entry.slice, root, Some(&ctx_path))
    }));
    let result = match outcome {
        Ok(Ok(errors)) => SliceResult {
            slice: entry.slice.clone(),
            passed: errors.is_empty(),
            errors,
            duration_ms: start.elapsed().as_millis() as u64,
        },
        Ok(Err(e)) => SliceResult {
            slice: entry.slice.clone(),
            passed: false,
            errors: vec![e],
            duration_ms: start.elapsed().as_millis() as u64,
        },
        Err(panic) => {
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            SliceResult {
                slice: entry.slice.clone(),
                passed: false,
                errors: vec![format!("slice validator panicked: {message}")],
                duration_ms: start.elapsed().as_millis() as u64,
            }
        }
    };

    let _ = fs::remove_file(&ctx_path);
    result
}

fn run_all_validate(root: &Path, parallel: bool) -> Result<RunAllOutput, String> {
    let shared = load_shared_context(root);
    let slices = slices_from_coverage();
    let start = Instant::now();

    let results: Vec<SliceResult> = if parallel {
        slices
            .par_iter()
            .map(|entry| run_one_slice(root, entry, &shared))
            .collect()
    } else {
        slices
            .iter()
            .map(|entry| run_one_slice(root, entry, &shared))
            .collect()
    };

    let total_duration = start.elapsed().as_millis() as u64;
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;
    let failures: Vec<_> = results.iter().filter(|r| !r.passed).cloned().collect();

    Ok(RunAllOutput {
        total: results.len(),
        passed,
        failed,
        failures,
        duration_ms: total_duration,
    })
}

fn run_batch_validate(root: &Path, slices: &[&str]) -> Result<RunAllOutput, String> {
    // Build a lookup from slice name to SliceEntry using COVERAGE_TSV
    let coverage = slices_from_coverage();
    let entry_map: std::collections::HashMap<&str, &SliceEntry> =
        coverage.iter().map(|e| (e.slice.as_str(), e)).collect();

    let shared = load_shared_context(root);
    let start = Instant::now();

    let mut results = Vec::new();
    for slice in slices {
        let entry = match entry_map.get(slice) {
            Some(e) => SliceEntry {
                slice: e.slice.clone(),
                catalog_file: e.catalog_file.clone(),
                doc_file: e.doc_file.clone(),
                endpoint: e.endpoint.clone(),
            },
            None => SliceEntry {
                slice: slice.to_string(),
                catalog_file: String::new(),
                doc_file: String::new(),
                endpoint: String::new(),
            },
        };
        results.push(run_one_slice(root, &entry, &shared));
    }

    let total_duration = start.elapsed().as_millis() as u64;
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;
    let failures: Vec<_> = results.iter().filter(|r| !r.passed).cloned().collect();

    Ok(RunAllOutput {
        total: results.len(),
        passed,
        failed,
        failures,
        duration_ms: total_duration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn unsafe_endpoint_is_rejected() {
        let mut errors = Vec::new();
        validate_coverage_shape(
            "Synthetic unsafe workflow",
            &CoverageEntry {
                catalog: "safe-contract.yaml".to_string(),
                doc: "safe.md".to_string(),
                endpoint: "https://example.invalid/api".to_string(),
            },
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("API endpoint coverage path is unsafe")));
    }

    #[test]
    fn endpoint_rejects_unsafe_suffix_after_safe_prefix() {
        assert!(!safe_endpoint("/api/safe?query=value"));
        assert!(!safe_endpoint("/api/Safe"));
    }

    #[test]
    fn program_route_check_ignores_commented_decoys() {
        let routes = active_route_registrations(
            r#"
            // .route("/api/commented/decoy", get(decoy))
            /*
            .route("/api/block/decoy", get(decoy))
            */
            .route("/api/active/route", get(active_route))
            "#,
        );

        assert!(routes.contains("/api/active/route"));
        assert!(!routes.contains("/api/commented/decoy"));
        assert!(!routes.contains("/api/block/decoy"));
    }

    // Registry self-check: every COVERAGE_TSV row must point at artifacts
    // that exist — its catalog YAML under catalog/, its workflow doc under
    // docs/workflows/ (or an explicit PENDING_WORKFLOW_DOCS entry while the
    // docs tree is being authored), and an endpoint string that appears in
    // the Rust API sources. Rows must also resolve to a runnable slice.
    #[test]
    fn coverage_registry_rows_reference_real_artifacts() {
        let root = root();
        let api_sources: String = RUST_API_ROUTE_SOURCES
            .iter()
            .map(|path| read(&root, path).expect("API source must be readable"))
            .collect::<Vec<_>>()
            .join("\n");
        let dispatch = validate_dispatch_table();
        let mut problems = Vec::new();

        for line in COVERAGE_TSV
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let cells: Vec<&str> = line.split('\t').collect();
            assert_eq!(cells.len(), 5, "malformed COVERAGE_TSV row: {line}");
            let (catalog_file, doc_file, endpoint) = (cells[2], cells[3], cells[4]);

            if !root.join("catalog").join(catalog_file).is_file() {
                problems.push(format!("missing catalog file catalog/{catalog_file}"));
            }
            let doc_exists = root.join("docs/workflows").join(doc_file).is_file();
            if !doc_exists && !PENDING_WORKFLOW_DOCS.contains(&doc_file) {
                problems.push(format!(
                    "doc docs/workflows/{doc_file} missing and not marked pending"
                ));
            }
            if !api_sources.contains(&format!("\"{endpoint}\"")) {
                problems.push(format!(
                    "endpoint {endpoint} does not appear in the Rust API sources"
                ));
            }

            let slice = catalog_to_slice(catalog_file);
            if slice != "backlog-coverage" && !dispatch.contains_key(slice.as_str()) {
                problems.push(format!("row resolves to unknown slice {slice}: {line}"));
            }
        }

        // Pending entries must be removed once the doc is authored, and must
        // correspond to a registered row.
        let registered_docs: BTreeSet<&str> = COVERAGE_TSV
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter_map(|line| line.split('\t').nth(3))
            .collect();
        for doc_file in PENDING_WORKFLOW_DOCS {
            if root.join("docs/workflows").join(doc_file).is_file() {
                problems.push(format!(
                    "{doc_file} exists; remove it from PENDING_WORKFLOW_DOCS"
                ));
            }
            if !registered_docs.contains(doc_file) {
                problems.push(format!(
                    "{doc_file} is pending but not referenced by any COVERAGE_TSV row"
                ));
            }
        }

        assert!(
            problems.is_empty(),
            "COVERAGE_TSV registry self-check failed:\n{}",
            problems.join("\n")
        );
    }

    #[test]
    fn shared_aliases_use_same_entries() {
        let coverage = coverage_output();

        assert_eq!(
            coverage.workflow.get("Windows server deployment"),
            coverage.workflow.get("Linux server deployment")
        );
        assert_eq!(
            coverage.workflow.get("CMDB Excel import"),
            coverage.workflow.get("CMDB update export")
        );
        assert!(
            coverage
                .information_architecture
                .get("Admin")
                .expect("admin IA coverage")
                .len()
                > 1
        );
    }
}
