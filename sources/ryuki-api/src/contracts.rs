use axum::{
    extract::{Path, Query},
    http::StatusCode,
    routing::delete,
    routing::put,
    routing::{get, post},
    Json, Router,
};
use ryuki_core::config::AuthMode;
use ryuki_core::types::{ApiError, PlatformConfig};
use ryuki_engine::auth::{check_permission, get_rbac_roles, AuthSession};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::OnceLock;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::database::get_db;
use crate::problem_details;
use crate::ProblemDetails;

#[derive(Debug, Deserialize)]
struct PaginationParams {
    limit: Option<usize>,
    offset: Option<usize>,
}
use ryuki_engine::access_recertification;
use ryuki_engine::ad_computer_lifecycle;
use ryuki_engine::aiops;
use ryuki_engine::alert_routing_engine;
use ryuki_engine::app_environment;
use ryuki_engine::backup_engine;
use ryuki_engine::certificate_lifecycle;
use ryuki_engine::cmdb_engine;
use ryuki_engine::cmdb_impact;
use ryuki_engine::compliance_reporting;
use ryuki_engine::container_namespace;
use ryuki_engine::cost_capacity;
use ryuki_engine::datacenter_readiness;
use ryuki_engine::degradation_mode;
use ryuki_engine::dns_ipam;
use ryuki_engine::dr_testing;
use ryuki_engine::emergency_change;
use ryuki_engine::evidence_pipeline;
use ryuki_engine::file_share_ntfs;
use ryuki_engine::firewall_rules;
use ryuki_engine::firmware_lifecycle;
use ryuki_engine::gmsa_lifecycle;
use ryuki_engine::hardware_lifecycle;
use ryuki_engine::health_monitor;
use ryuki_engine::image_factory;
use ryuki_engine::immutability_compliance;
use ryuki_engine::incident_context;
use ryuki_engine::inventory_sync;
use ryuki_engine::legal_hold;
use ryuki_engine::linux_deployment;
use ryuki_engine::load_balancer;
use ryuki_engine::log_forwarder;
use ryuki_engine::maintenance_calendar;
use ryuki_engine::network_readiness;
use ryuki_engine::noise_remediation;
use ryuki_engine::oob_access;
use ryuki_engine::os_baseline;
use ryuki_engine::outage_comms;
use ryuki_engine::patch_engine;
use ryuki_engine::repository_capacity;
use ryuki_engine::request_lifecycle;
use ryuki_engine::runbook_execution;
use ryuki_engine::secrets_rotation;
use ryuki_engine::server_decommission;
use ryuki_engine::servicenow_api;
use ryuki_engine::shift_queue;
use ryuki_engine::site_registry;
use ryuki_engine::snapshot_engine;
use ryuki_engine::software_deployment;
use ryuki_engine::sql_deployment;
use ryuki_engine::storage_provisioning;
use ryuki_engine::synthetic_health;
use ryuki_engine::vm_operations;
use ryuki_engine::zabbix_drift;

pub fn routes() -> Router {
    Router::new()
        .route("/api/platform/summary", get(platform_summary))
        .route("/api/platform/status", get(platform_status))
        .route(
            "/api/dashboard/global-overview-contract",
            get(dashboard_global_overview),
        )
        .route(
            "/api/dashboard/risk-heatmap-contract",
            get(dashboard_risk_heatmap),
        )
        .route("/api/requests/lifecycle-contract", get(requests_lifecycle))
        .route(
            "/api/requests/execution-timeline-contract",
            get(requests_execution_timeline),
        )
        .route("/api/requests/intake-form", get(requests_intake_form))
        .route(
            "/api/requests/intake-support-contract",
            get(requests_intake_support),
        )
        .route("/api/requests/preflight-contract", get(requests_preflight))
        // ─── Request lifecycle endpoints (mock/dry-run) ───
        .route("/api/requests", post(requests_create))
        .route("/api/requests", get(requests_list))
        .route("/api/requests/{id}", get(requests_get))
        .route("/api/requests/{id}/validate", post(requests_validate))
        .route("/api/requests/{id}/plan", post(requests_plan))
        .route("/api/requests/{id}/approve", post(requests_approve))
        .route("/api/requests/{id}/lock", post(requests_lock))
        .route("/api/requests/{id}/execute", post(requests_execute))
        .route("/api/requests/{id}/verify", post(requests_verify))
        .route(
            "/api/platform/security-baseline-contract",
            get(platform_security_baseline),
        )
        .route(
            "/api/platform/portal-information-architecture-contract",
            get(platform_portal_ia),
        )
        .route(
            "/api/platform/design-system-contract",
            get(platform_design_system),
        )
        .route(
            "/api/platform/ui-mockup-acceptance-contract",
            get(platform_ui_mockup),
        )
        .route(
            "/api/platform/release-promotion-contract",
            get(platform_release_promotion),
        )
        .route(
            "/api/platform/database-readiness-contract",
            get(platform_database_readiness),
        )
        .route(
            "/api/platform/object-storage-readiness-contract",
            get(platform_object_storage),
        )
        .route(
            "/api/platform/registry-readiness-contract",
            get(platform_registry_readiness),
        )
        .route(
            "/api/platform/vault-deployment-readiness-contract",
            get(platform_vault_deployment),
        )
        .route(
            "/api/platform/vault-secret-delivery-contract",
            get(platform_vault_secret_delivery),
        )
        .route(
            "/api/platform/kubernetes-runtime-readiness-contract",
            get(platform_k8s_runtime),
        )
        .route(
            "/api/platform/local-container-readiness-contract",
            get(platform_local_container),
        )
        .route("/api/catalog/categories", get(catalog_categories))
        .route("/api/catalog/offerings-contract", get(catalog_offerings))
        .route(
            "/api/catalog/recommendations-contract",
            get(catalog_recommendations),
        )
        .route(
            "/api/catalog/request-form-contract",
            get(catalog_request_form),
        )
        .route(
            "/api/catalog/site-catalog-contract",
            get(catalog_site_catalog),
        )
        .route(
            "/api/catalog/policy-guardrails-contract",
            get(catalog_policy_guardrails),
        )
        .route("/api/catalog/access-control", get(catalog_access_control))
        .route("/api/catalog/approval-routes", get(catalog_approval_routes))
        .route(
            "/api/catalog/evidence-manifest",
            get(catalog_evidence_manifest),
        )
        .route(
            "/api/catalog/evidence-redaction-contract",
            get(catalog_evidence_redaction),
        )
        .route(
            "/api/catalog/secret-references",
            get(catalog_secret_references),
        )
        .route(
            "/api/approvals/decision-readiness-contract",
            get(approvals_decision_readiness),
        )
        .route(
            "/api/identity/rbac-approval-model-contract",
            get(identity_rbac_approval_model),
        )
        .route(
            "/api/identity/entra-rbac-approval-readiness-contract",
            get(identity_entra_rbac),
        )
        // ─── Access Recertification Engine ───
        .route(
            "/api/identity/access-review/reviews",
            get(access_reviews_list),
        )
        .route(
            "/api/identity/access-review/review/{id}",
            get(access_review_get),
        )
        .route("/api/identity/access-review/due", get(access_reviews_due))
        .route(
            "/api/identity/access-review/expiring",
            get(access_reviews_expiring),
        )
        .route(
            "/api/identity/access-review/{id}/start",
            post(access_review_start),
        )
        .route(
            "/api/identity/access-review/{id}/approve",
            post(access_review_approve),
        )
        .route(
            "/api/identity/access-review/{id}/revoke",
            post(access_review_revoke),
        )
        .route(
            "/api/identity/access-review/{id}/exempt",
            post(access_review_exempt),
        )
        .route(
            "/api/identity/access-review/summary",
            get(access_review_summary),
        )
        .route(
            "/api/identity/access-review/campaign",
            post(access_campaign_create),
        )
        .route(
            "/api/identity/access-review/campaign/{id}",
            get(access_campaign_get),
        )
        .route(
            "/api/identity/access-review/campaigns",
            get(access_campaigns_list),
        )
        .route(
            "/api/identity/access-review-contract",
            get(access_review_contract),
        )
        .route(
            "/api/identity/access-review-recertification-contract",
            get(identity_access_review),
        )
        .route(
            "/api/identity/ad-computer-lifecycle-contract",
            get(identity_ad_computer),
        )
        .route("/api/identity/ad/prestage", post(ad_prestage))
        .route("/api/identity/ad/validate", post(ad_validate))
        .route("/api/identity/ad/move/{name}", post(ad_move))
        .route("/api/identity/ad/disable/{name}", post(ad_disable))
        .route("/api/identity/ad/enable/{name}", post(ad_enable))
        .route("/api/identity/ad/delete/{name}", post(ad_delete))
        .route("/api/identity/ad/reconcile", get(ad_reconcile))
        .route("/api/identity/ad/orphaned", get(ad_orphaned))
        .route(
            "/api/identity/ad-computer-contract",
            get(ad_computer_contract),
        )
        .route(
            "/api/identity/gmsa-lifecycle-contract",
            get(identity_gmsa_lifecycle),
        )
        .route("/api/identity/gmsa/create", post(gmsa_create))
        .route("/api/identity/gmsa/validate", post(gmsa_validate))
        .route("/api/identity/gmsa/assign/{name}/{host}", post(gmsa_assign))
        .route("/api/identity/gmsa/remove/{name}/{host}", post(gmsa_remove))
        .route("/api/identity/gmsa/rotate/{name}", post(gmsa_rotate))
        .route("/api/identity/gmsa/test/{name}/{host}", post(gmsa_test))
        .route("/api/identity/gmsa/inventory", get(gmsa_inventory))
        .route("/api/identity/gmsa/expiring", get(gmsa_expiring))
        .route("/api/identity/gmsa-contract", get(gmsa_contract))
        .route(
            "/api/identity/local-privilege-access-contract",
            get(identity_local_privilege),
        )
        .route(
            "/api/identity/file-share-ntfs-recertification-contract",
            get(identity_file_share_ntfs),
        )
        .route("/api/identity/shares", get(shares_list))
        .route("/api/identity/shares/{id}", get(shares_get))
        .route(
            "/api/identity/shares/recertification-due",
            get(shares_recertification_due),
        )
        .route(
            "/api/identity/shares/recertify/{id}",
            post(shares_recertify),
        )
        .route(
            "/api/identity/shares/open-access/{id}",
            get(shares_open_access),
        )
        .route(
            "/api/identity/shares/stale-owners",
            get(shares_stale_owners),
        )
        .route(
            "/api/identity/shares/permissions/{id}",
            get(shares_permission_report),
        )
        .route(
            "/api/identity/shares/revoke/{id}/{group}",
            post(shares_revoke),
        )
        .route("/api/identity/shares-contract", get(shares_contract))
        // ─── Compliance Reporting Engine ───
        .route(
            "/api/audit/compliance/frameworks",
            get(compliance_frameworks),
        )
        .route(
            "/api/audit/compliance/frameworks/{id}",
            get(compliance_framework_get),
        )
        .route(
            "/api/audit/compliance/controls",
            get(compliance_controls_list),
        )
        .route(
            "/api/audit/compliance/controls/{id}",
            get(compliance_control_get),
        )
        .route(
            "/api/audit/compliance/controls/{id}/assess",
            post(compliance_control_assess),
        )
        .route(
            "/api/audit/compliance/reports/generate",
            post(compliance_report_generate),
        )
        .route(
            "/api/audit/compliance/reports/{id}",
            get(compliance_report_get),
        )
        .route(
            "/api/audit/compliance/findings",
            get(compliance_findings_list),
        )
        .route(
            "/api/audit/compliance/findings/{id}/resolve",
            post(compliance_finding_resolve),
        )
        .route(
            "/api/audit/compliance/findings/{id}/waive",
            post(compliance_finding_waive),
        )
        .route("/api/audit/compliance/summary", get(compliance_summary))
        .route("/api/audit/compliance-contract", get(compliance_contract))
        // ─── Evidence Pipeline Engine ───
        .route("/api/evidence/collect", post(evidence_collect))
        .route("/api/evidence/redact", post(evidence_redact))
        .route("/api/evidence/export", get(evidence_export))
        .route(
            "/api/evidence/verify-compliance",
            post(evidence_verify_compliance),
        )
        .route(
            "/api/evidence/export-retention-contract",
            get(evidence_export_retention),
        )
        .route(
            "/api/evidence/compliance-dashboard-contract",
            get(evidence_compliance_dashboard),
        )
        .route("/api/integrations/readiness", get(integrations_readiness))
        .route(
            "/api/integrations/adapter-readiness-matrix-contract",
            get(integrations_adapter_matrix),
        )
        .route(
            "/api/integrations/adapter-contract-test-contract",
            get(integrations_adapter_contract_test),
        )
        .route(
            "/api/integrations/vmware/readiness",
            get(integrations_vmware_readiness),
        )
        .route(
            "/api/integrations/vmware/cluster-capacity-admission-contract",
            get(integrations_vmware_cluster_capacity),
        )
        .route(
            "/api/integrations/vmware/customization-spec-governance-contract",
            get(integrations_vmware_customization_spec),
        )
        .route(
            "/api/integrations/vmware/object-placement-contract",
            get(integrations_vmware_object_placement),
        )
        .route(
            "/api/integrations/vmware/vsan-esxi-lifecycle-contract",
            get(integrations_vmware_vsan_esxi),
        )
        .route(
            "/api/integrations/vmware/day2-change-contract",
            get(integrations_vmware_day2),
        )
        .route(
            "/api/integrations/vmware/snapshot-governance-contract",
            get(integrations_vmware_snapshot),
        )
        .route(
            "/api/integrations/vmware/decommission-quarantine-contract",
            get(integrations_vmware_decommission),
        )
        .route(
            "/api/integrations/hyperv/readiness",
            get(integrations_hyperv_readiness),
        )
        .route(
            "/api/integrations/proxmox/readiness",
            get(integrations_proxmox_readiness),
        )
        .route(
            "/api/integrations/veeam/readiness",
            get(integrations_veeam_readiness),
        )
        .route(
            "/api/integrations/zabbix/readiness",
            get(integrations_zabbix_readiness),
        )
        .route(
            "/api/integrations/prometheus/readiness",
            get(integrations_prometheus_readiness),
        )
        .route(
            "/api/integrations/datadog/readiness",
            get(integrations_datadog_readiness),
        )
        .route(
            "/api/integrations/grafana/readiness",
            get(integrations_grafana_readiness),
        )
        .route(
            "/api/integrations/solarwinds/readiness",
            get(integrations_solarwinds_readiness),
        )
        .route(
            "/api/integrations/servicenow/readiness",
            get(integrations_servicenow_readiness),
        )
        .route(
            "/api/integrations/nutanix/readiness",
            get(integrations_nutanix_readiness),
        )
        .route(
            "/api/integrations/xen/readiness",
            get(integrations_xen_readiness),
        )
        .route(
            "/api/integrations/kvm/readiness",
            get(integrations_kvm_readiness),
        )
        .route(
            "/api/integrations/commvault/readiness",
            get(integrations_commvault_readiness),
        )
        .route(
            "/api/integrations/rubrik/readiness",
            get(integrations_rubrik_readiness),
        )
        .route(
            "/api/integrations/cohesity/readiness",
            get(integrations_cohesity_readiness),
        )
        .route(
            "/api/integrations/netbackup/readiness",
            get(integrations_netbackup_readiness),
        )
        .route(
            "/api/integrations/servicenow/cmdb-file-contract",
            get(integrations_servicenow_cmdb_file),
        )
        .route(
            "/api/integrations/servicenow/future-api-contract",
            get(integrations_servicenow_future_api),
        )
        // ─── Inventory Sync Engine ───
        .route("/api/inventory/sync", post(inventory_run_sync))
        .route(
            "/api/inventory/reconcile",
            post(inventory_run_reconciliation),
        )
        .route(
            "/api/inventory/ownership-risks",
            get(inventory_ownership_risks),
        )
        .route("/api/inventory/coverage-contract", get(inventory_coverage))
        .route(
            "/api/inventory/resource-overview-contract",
            get(inventory_resource_overview),
        )
        .route(
            "/api/inventory/coverage/local/summary",
            get(inventory_coverage_local),
        )
        .route(
            "/api/inventory/ownership-risk-contract",
            get(inventory_ownership_risk),
        )
        .route(
            "/api/inventory/os-baseline-compliance-contract",
            get(inventory_os_baseline),
        )
        .route(
            "/api/software/approved-deployment-contract",
            get(software_approved_deployment),
        )
        .route(
            "/api/workflows/server-lifecycle/dry-run-contract",
            get(workflows_server_lifecycle),
        )
        .route(
            "/api/workflows/application-environment/deployment-contract",
            get(workflows_app_env_deployment),
        )
        .route(
            "/api/workflows/application-environment/retirement-contract",
            get(workflows_app_env_retirement),
        )
        .route(
            "/api/workflows/sql-server/deployment-contract",
            get(workflows_sql_server),
        )
        // ─── SQL Server Deployment Engine ───
        .route("/api/build/sql/plan", post(sql_deploy_plan))
        .route("/api/build/sql/validate", post(sql_deploy_validate))
        .route("/api/build/sql/install/{id}", post(sql_deploy_install))
        .route("/api/build/sql/configure/{id}", post(sql_deploy_configure))
        .route("/api/build/sql/verify/{id}", post(sql_deploy_verify))
        .route("/api/build/sql/backup/{id}", post(sql_deploy_backup))
        .route(
            "/api/build/sql/monitoring/{id}",
            post(sql_deploy_monitoring),
        )
        .route("/api/build/sql/inventory", get(sql_deploy_inventory))
        .route("/api/build/sql-contract", get(sql_deployment_contract))
        .route(
            "/api/workflows/azure-landing-zone/validation-contract",
            get(workflows_azure_lz),
        )
        .route(
            "/api/workflows/preflight/local/decision",
            get(workflows_preflight_local_decision),
        )
        .route(
            "/api/operations/certificate-lifecycle-contract",
            get(operations_certificate_lifecycle),
        )
        // ─── Runbook Execution Engine ───
        .route("/api/ops/runbook/catalog", get(runbook_catalog))
        .route("/api/ops/runbook/start", post(runbook_start))
        .route(
            "/api/ops/runbook/execution/{id}",
            get(runbook_get_execution),
        )
        .route(
            "/api/ops/runbook/step/{id}/{step}",
            post(runbook_execute_step),
        )
        .route("/api/ops/runbook/approve/{id}", post(runbook_approve))
        .route("/api/ops/runbook/complete/{id}", post(runbook_complete))
        .route("/api/ops/runbook/fail/{id}", post(runbook_fail))
        .route("/api/ops/runbook/rollback/{id}", post(runbook_rollback))
        .route("/api/ops/runbook/executions", get(runbook_executions_list))
        .route("/api/ops/runbook/active", get(runbook_active))
        .route("/api/ops/runbook-contract", get(runbook_contract))
        .route(
            "/api/operations/runbook-launch-contract",
            get(operations_runbook_launch),
        )
        .route(
            "/api/operations/standard-task-contract",
            get(operations_standard_task),
        )
        .route(
            "/api/operations/emergency-change-contract",
            get(operations_emergency_change),
        )
        .route(
            "/api/operations/shift-queue-contract",
            get(operations_shift_queue),
        )
        .route("/api/ops/shift/summary", get(shift_summary))
        .route("/api/ops/shift/acknowledge/{id}", post(shift_acknowledge))
        .route("/api/ops/shift/assign/{id}", post(shift_assign))
        .route("/api/ops/shift/escalate/{id}", post(shift_escalate))
        .route("/api/ops/shift/resolve/{id}", post(shift_resolve))
        .route("/api/ops/shift/handover", get(shift_handover))
        .route("/api/ops/shift/my-items", get(shift_my_items))
        .route("/api/ops/shift/stale", get(shift_stale))
        .route("/api/ops/shift-contract", get(shift_contract))
        // ─── Emergency Change (Break-Glass) Engine ───
        .route("/api/ops/emergency/initiate", post(emergency_initiate))
        .route("/api/ops/emergency/approve/{id}", post(emergency_approve))
        .route("/api/ops/emergency/execute/{id}", post(emergency_execute))
        .route("/api/ops/emergency/verify/{id}", post(emergency_verify))
        .route("/api/ops/emergency/close/{id}", post(emergency_close))
        .route("/api/ops/emergency/active", get(emergency_active))
        .route("/api/ops/emergency/history", get(emergency_history))
        .route("/api/ops/emergency/stats", get(emergency_stats))
        .route("/api/ops/emergency-contract", get(emergency_contract))
        .route(
            "/api/operations/dependency-replay-contract",
            get(operations_dependency_replay),
        )
        .route(
            "/api/operations/activity-queue-contract",
            get(operations_activity_queue),
        )
        .route(
            "/api/operations/run-state-contract",
            get(operations_run_state),
        )
        .route(
            "/api/operations/datacenter-readiness-contract",
            get(operations_datacenter_readiness),
        )
        .route(
            "/api/operations/out-of-band-access-validation-contract",
            get(operations_oob_access),
        )
        .route(
            "/api/operations/network-vlan-readiness-contract",
            get(operations_network_vlan),
        )
        .route(
            "/api/operations/hardware-lifecycle-contract",
            get(operations_hardware_lifecycle),
        )
        .route(
            "/api/operations/firmware-compliance-exception-contract",
            get(operations_firmware_compliance),
        )
        .route(
            "/api/operations/platform-health-contract",
            get(operations_platform_health),
        )
        // ─── Incident Context Engine ───
        .route("/api/ops/incident/assemble", post(incident_assemble))
        .route("/api/ops/incident/{id}", get(incident_get))
        .route("/api/ops/incident/active", get(incident_active))
        .route("/api/ops/incident/{id}/services", get(incident_services))
        .route("/api/ops/incident/{id}/oncall", get(incident_oncall))
        .route("/api/ops/incident/{id}/changes", get(incident_changes))
        .route("/api/ops/incident/{id}/resolve", post(incident_resolve))
        .route("/api/ops/incident/{id}/add-ci", post(incident_add_ci))
        .route("/api/ops/incident/{id}/escalate", post(incident_escalate))
        .route(
            "/api/ops/incident-context-contract",
            get(incident_context_contract),
        )
        .route(
            "/api/operations/incident-context-contract",
            get(operations_incident_context),
        )
        .route(
            "/api/operations/maintenance-communications-contract",
            get(operations_maintenance_comm),
        )
        .route(
            "/api/operations/outage-comms/notices",
            get(outage_notices_list),
        )
        .route(
            "/api/operations/outage-comms/notices",
            post(outage_notices_create),
        )
        .route(
            "/api/operations/outage-comms/notices/{id}",
            get(outage_notices_get),
        )
        .route(
            "/api/operations/outage-comms/notices/{id}/preview",
            get(outage_notices_preview),
        )
        .route(
            "/api/operations/outage-comms/notices/{id}/send",
            post(outage_notices_send),
        )
        .route(
            "/api/operations/outage-comms/notices/{id}/acknowledge",
            post(outage_notices_acknowledge),
        )
        .route(
            "/api/operations/outage-comms/notices/{id}/complete",
            post(outage_notices_complete),
        )
        .route(
            "/api/operations/outage-comms/notices/{id}/cancel",
            post(outage_notices_cancel),
        )
        .route(
            "/api/operations/outage-comms/active",
            get(outage_notices_active),
        )
        .route(
            "/api/operations/outage-comms/history",
            get(outage_notices_history),
        )
        .route(
            "/api/operations/outage-comms/upcoming",
            get(outage_notices_upcoming),
        )
        .route(
            "/api/operations/outage-comms-contract",
            get(outage_contract),
        )
        .route(
            "/api/operations/degradation-mode-contract",
            get(operations_degradation_mode),
        )
        .route(
            "/api/platform/degradation/check/{site}",
            post(degradation_check),
        )
        .route("/api/platform/degradation/global", get(degradation_global))
        .route(
            "/api/platform/degradation/degraded",
            get(degradation_degraded),
        )
        .route(
            "/api/platform/degradation/enter/{site}",
            post(degradation_enter),
        )
        .route(
            "/api/platform/degradation/exit/{site}",
            post(degradation_exit),
        )
        .route("/api/platform/degradation/rules", get(degradation_rules))
        .route(
            "/api/platform/degradation-contract",
            get(degradation_contract),
        )
        .route(
            "/api/operations/aiops-suggestion-contract",
            get(operations_aiops_suggestion),
        )
        .route(
            "/api/operations/knowledge-suggestion-contract",
            get(operations_knowledge_suggestion),
        )
        .route("/api/images/factory-contract", get(images_factory))
        .route(
            "/api/patching/maintenance-contract",
            get(patching_maintenance),
        )
        .route(
            "/api/patching/policy-import-contract",
            get(patching_policy_import),
        )
        .route(
            "/api/patching/reboot-orchestration-contract",
            get(patching_reboot_orch),
        )
        .route(
            "/api/patching/maintenance-calendar-contract",
            get(patching_maintenance_calendar),
        )
        // ─── Patch wave orchestration ───
        .route("/api/maintain/patch/plan", post(patch_plan))
        .route("/api/maintain/patch/validate", post(patch_validate))
        .route("/api/maintain/patch/approve", post(patch_approve))
        .route("/api/maintain/patch/execute", post(patch_execute))
        .route("/api/maintain/patch/verify", post(patch_verify))
        .route("/api/maintain/patch/compliance", get(patch_compliance))
        .route(
            "/api/maintain/patch/pending-reboots",
            get(patch_pending_reboots),
        )
        .route("/api/maintain/patch-contract", get(patch_contract))
        // ─── Software deployment ───
        .route(
            "/api/maintain/software/packages",
            get(software_packages_list),
        )
        .route("/api/maintain/software/validate", post(software_validate))
        .route("/api/maintain/software/plan", post(software_plan))
        .route(
            "/api/maintain/software/approve/{id}",
            post(software_approve),
        )
        .route(
            "/api/maintain/software/execute/{id}",
            post(software_execute),
        )
        .route("/api/maintain/software/verify/{id}", post(software_verify))
        .route(
            "/api/maintain/software/history/{server}",
            get(software_history),
        )
        .route(
            "/api/maintain/software/compliance",
            get(software_compliance),
        )
        .route("/api/maintain/software-contract", get(software_contract))
        // ─── OS baseline compliance ───
        .route(
            "/api/maintain/baseline/check/{server}",
            post(baseline_check),
        )
        .route(
            "/api/maintain/baseline/compliance",
            get(baseline_compliance),
        )
        .route(
            "/api/maintain/baseline/noncompliant",
            get(baseline_noncompliant),
        )
        .route("/api/maintain/baseline/trend", get(baseline_trend))
        .route("/api/maintain/baseline/coverage", get(baseline_coverage))
        .route(
            "/api/maintain/baseline/remediate/{server}/{check_id}",
            post(baseline_remediate),
        )
        .route("/api/maintain/baseline-contract", get(baseline_contract))
        .route(
            "/api/protect/controlled-restore-contract",
            get(protect_controlled_restore),
        )
        .route(
            "/api/protect/backup-coverage-gap-contract",
            get(protect_backup_coverage_gap),
        )
        .route(
            "/api/protect/repository-capacity-contract",
            get(protect_repository_capacity),
        )
        .route("/api/protect/repository-capacity", get(repo_capacity_list))
        .route(
            "/api/protect/repository-capacity/update/{id}",
            post(repo_capacity_update),
        )
        .route(
            "/api/protect/repository-capacity/forecast/{id}",
            get(repo_capacity_forecast),
        )
        .route(
            "/api/protect/repository-capacity/at-risk",
            get(repo_capacity_at_risk),
        )
        .route(
            "/api/protect/repository-capacity/report",
            get(repo_capacity_report),
        )
        .route(
            "/api/protect/repository-capacity/trend/{id}",
            get(repo_capacity_trend),
        )
        .route(
            "/api/protect/repository-capacity/recommendations/{id}",
            get(repo_capacity_recommendations),
        )
        // ─── Secrets Rotation Engine ───
        .route("/api/protect/secrets", get(secrets_list))
        .route("/api/protect/secrets", post(secrets_register))
        .route("/api/protect/secrets/{id}", get(secrets_get))
        .route("/api/protect/secrets/{id}/rotate", post(secrets_rotate))
        .route(
            "/api/protect/secrets/{id}/history",
            get(secrets_rotation_history),
        )
        .route("/api/protect/secrets/due", get(secrets_due_rotations))
        .route("/api/protect/secrets/expiring", get(secrets_expiring))
        .route("/api/protect/secrets/rotate-all", post(secrets_rotate_all))
        .route(
            "/api/protect/secrets/summary",
            get(secrets_rotation_summary),
        )
        .route("/api/protect/secrets/fail", post(secrets_rotation_fail))
        .route("/api/protect/secrets-contract", get(secrets_contract))
        .route(
            "/api/protect/immutability-air-gap-compliance-contract",
            get(protect_immutability_air_gap),
        )
        .route(
            "/api/protect/immutability/check/{id}",
            post(immutability_check),
        )
        .route(
            "/api/protect/immutability/retention-lock/{id}",
            post(immutability_retention_lock),
        )
        .route(
            "/api/protect/immutability/air-gap/{id}",
            post(immutability_air_gap),
        )
        .route(
            "/api/protect/immutability/verify-all",
            post(immutability_verify_all),
        )
        .route(
            "/api/protect/immutability/compliance",
            get(immutability_compliance_report),
        )
        .route(
            "/api/protect/immutability/noncompliant",
            get(immutability_noncompliant),
        )
        .route(
            "/api/protect/immutability/retention-risk",
            get(immutability_retention_risk),
        )
        .route(
            "/api/protect/immutability/remediation/{id}",
            get(immutability_remediation),
        )
        .route(
            "/api/protect/immutability-contract",
            get(immutability_contract),
        )
        .route(
            "/api/protect/application-aware-backup-validation-contract",
            get(protect_app_aware_backup),
        )
        .route(
            "/api/protect/backup-dr-assignment-contract",
            get(protect_backup_dr_assignment),
        )
        .route(
            "/api/protect/restore-testing-contract",
            get(protect_restore_testing),
        )
        // ─── Legal Hold & Extended Retention Engine ───
        .route("/api/protect/legal-hold/place", post(legal_hold_place))
        .route(
            "/api/protect/legal-hold/validate/{id}",
            post(legal_hold_validate),
        )
        .route(
            "/api/protect/legal-hold/extend/{id}",
            post(legal_hold_extend),
        )
        .route(
            "/api/protect/legal-hold/release/{id}",
            post(legal_hold_release),
        )
        .route("/api/protect/legal-hold/active", get(legal_hold_active))
        .route("/api/protect/legal-hold/expiring", get(legal_hold_expiring))
        .route(
            "/api/protect/legal-hold/evidence/{id}",
            get(legal_hold_evidence),
        )
        .route(
            "/api/protect/legal-hold/compliance/{server}",
            get(legal_hold_compliance),
        )
        .route("/api/protect/legal-hold-contract", get(legal_hold_contract))
        .route(
            "/api/protect/legal-hold-retention-contract",
            get(protect_legal_hold),
        )
        .route(
            "/api/observe/zabbix-onboarding-contract",
            get(observe_zabbix_onboarding),
        )
        .route(
            "/api/observe/alert-routing-contract",
            get(observe_alert_routing),
        )
        .route(
            "/api/observe/monitoring-coverage-gap-contract",
            get(observe_monitoring_coverage_gap),
        )
        .route(
            "/api/observe/zabbix-drift-remediation-contract",
            get(observe_zabbix_drift),
        )
        .route(
            "/api/observe/synthetic-health-check-contract",
            get(observe_synthetic_health_check_contract),
        )
        .route(
            "/api/observe/synthetic/run/{check_id}",
            post(synthetic_run_check),
        )
        .route("/api/observe/synthetic/run-all", post(synthetic_run_all))
        .route(
            "/api/observe/synthetic/status/{check_id}",
            get(synthetic_status),
        )
        .route("/api/observe/synthetic/dashboard", get(synthetic_dashboard))
        .route("/api/observe/synthetic/outages", get(synthetic_outages))
        .route(
            "/api/observe/noise-flapping-remediation-contract",
            get(observe_noise_flapping),
        )
        .route(
            "/api/observe/monitoring-review-queue-contract",
            get(observe_monitoring_review_queue),
        )
        .route(
            "/api/observe/log-forwarder-onboarding-contract",
            get(observe_log_forwarder),
        )
        // ─── Log Forwarder Onboarding Engine ───
        .route("/api/observe/logs/onboard", post(logs_onboard))
        .route("/api/observe/logs/validate/{hostname}", post(logs_validate))
        .route("/api/observe/logs/verify/{hostname}", post(logs_verify))
        .route("/api/observe/logs/coverage", get(logs_coverage))
        .route("/api/observe/logs/gaps", get(logs_gaps))
        .route("/api/observe/logs/volume", get(logs_volume))
        .route("/api/observe/logs/retention", get(logs_retention))
        .route("/api/observe/logs/disable/{hostname}", post(logs_disable))
        .route("/api/observe/logs-contract", get(logs_contract))
        // ─── CMDB Engine ───
        .route("/api/cmdb/import", post(cmdb_import_records))
        .route("/api/cmdb/reconcile", post(cmdb_run_reconciliation))
        .route("/api/cmdb/export", get(cmdb_export_records))
        .route(
            "/api/cmdb/reconciliation-contract",
            get(cmdb_reconciliation),
        )
        .route(
            "/api/cmdb/relationship-graph-contract",
            get(cmdb_relationship_graph),
        )
        .route(
            "/api/cmdb/impact-analysis-contract",
            get(cmdb_impact_analysis),
        )
        .route("/api/cmdb/impact/analyze", post(cmdb_impact_analyze))
        .route("/api/cmdb/impact/graph", get(cmdb_impact_graph))
        .route(
            "/api/cmdb/impact/upstream/{ci_name}",
            get(cmdb_impact_upstream),
        )
        .route(
            "/api/cmdb/impact/downstream/{ci_name}",
            get(cmdb_impact_downstream),
        )
        .route("/api/cmdb/impact-contract", get(cmdb_impact_contract))
        // ─── ServiceNow API Integration ───
        .route("/api/cmdb/servicenow/incident", post(servicenow_incident))
        .route("/api/cmdb/servicenow/change", post(servicenow_change))
        .route("/api/cmdb/servicenow/request", post(servicenow_request))
        .route(
            "/api/cmdb/servicenow/validate/{id}",
            post(servicenow_validate),
        )
        .route(
            "/api/cmdb/servicenow/approve/{id}",
            post(servicenow_approve),
        )
        .route("/api/cmdb/servicenow/submit/{id}", post(servicenow_submit))
        .route("/api/cmdb/servicenow/status/{id}", get(servicenow_status))
        .route("/api/cmdb/servicenow/pending", get(servicenow_pending))
        .route("/api/cmdb/servicenow/cancel/{id}", post(servicenow_cancel))
        .route("/api/cmdb/servicenow/history/{ci}", get(servicenow_history))
        .route("/api/cmdb/servicenow-contract", get(servicenow_contract))
        .route(
            "/api/admin/worker-capability-contract",
            get(admin_worker_capability),
        )
        .route(
            "/api/admin/feature-flag-governance-contract",
            get(admin_feature_flag),
        )
        .route(
            "/api/admin/approval-groups-contract",
            get(admin_approval_groups),
        )
        // ─── Site Registry (UN/LOCODE) ───
        .route("/api/admin/sites", get(site_registry_list))
        .route("/api/admin/sites/countries", get(site_registry_countries))
        .route(
            "/api/admin/sites/countries/{code}/cities",
            get(site_registry_cities_by_country),
        )
        .route("/api/admin/sites/{unlocode}", get(site_registry_get))
        .route(
            "/api/admin/sites/{unlocode}/activate",
            post(site_registry_activate),
        )
        .route(
            "/api/admin/sites/{unlocode}/deactivate",
            post(site_registry_deactivate),
        )
        .route("/api/admin/sites/search", get(site_registry_search))
        .route(
            "/api/admin/site-registry-contract",
            get(site_registry_contract),
        )
        .route(
            "/api/admin/delegation-boundary-contract",
            get(admin_delegation_boundary),
        )
        .route("/api/auth/local/roles", get(auth_local_roles))
        .route("/api/auth/local/me", get(auth_local_me))
        .route("/api/auth/local/decision", get(auth_local_decision))
        .route("/api/auth/local/login", get(auth_local_login))
        .route("/api/auth/local/logout", get(auth_local_logout))
        .route("/api/auth/status", get(auth_status))
        .route("/api/auth/session", get(auth_session))
        .route("/api/auth/roles", get(auth_roles))
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/admin/rbac-roles", get(admin_rbac_roles))
        .route("/api/admin/platform-settings", get(admin_platform_settings))
        .route(
            "/api/admin/platform-settings",
            put(admin_platform_settings_update),
        )
        .route(
            "/api/admin/platform-settings/reset",
            post(admin_platform_settings_reset),
        )
        .route(
            "/api/analytics/cost-capacity-contract",
            get(analytics_cost_capacity),
        )
        .route("/api/analytics/capacity", get(analytics_capacity))
        .route(
            "/api/analytics/capacity/cluster",
            get(analytics_capacity_cluster),
        )
        .route(
            "/api/analytics/capacity/forecast",
            get(analytics_capacity_forecast),
        )
        .route("/api/analytics/cost/summary", get(analytics_cost_summary))
        .route("/api/analytics/waste", get(analytics_waste))
        .route("/api/analytics/rightsizing", get(analytics_rightsizing))
        .route("/api/analytics/trend", get(analytics_trend))
        .route("/api/analytics/contract", get(analytics_contract))
        .route("/api/analytics/aiops/generate", post(aiops_generate))
        .route("/api/analytics/aiops/review/{id}", post(aiops_review))
        .route("/api/analytics/aiops/accept/{id}", post(aiops_accept))
        .route("/api/analytics/aiops/reject/{id}", post(aiops_reject))
        .route("/api/analytics/aiops/implement/{id}", post(aiops_implement))
        .route("/api/analytics/aiops/type", get(aiops_type))
        .route("/api/analytics/aiops/savings", get(aiops_savings))
        .route("/api/analytics/aiops/stats", get(aiops_stats))
        .route("/api/analytics/aiops-contract", get(aiops_contract))
        // ─── Health Monitor Engine ───
        .route("/api/platform/health/all", get(platform_health_all_checks))
        .route(
            "/api/platform/health/check/{adapter}",
            get(platform_health_check_adapter),
        )
        .route(
            "/api/platform/health/metrics",
            get(platform_health_metrics_text),
        )
        .route("/api/platform/health", get(platform_health))
        .route(
            "/api/platform/health/components",
            get(platform_health_components),
        )
        .route(
            "/api/platform/health/adapters",
            get(platform_health_adapters),
        )
        .route(
            "/api/monitoring/alert-routing-contract",
            get(monitoring_alert_routing_contract),
        )
        .route("/api/monitoring/alert-routes", post(alert_routes_create))
        .route("/api/monitoring/alert-routes", get(alert_routes_list))
        .route("/api/monitoring/alert-routes/{id}", get(alert_routes_get))
        .route(
            "/api/monitoring/alert-routes/{id}",
            put(alert_routes_update),
        )
        .route(
            "/api/monitoring/alert-routes/{id}",
            delete(alert_routes_delete),
        )
        .route("/api/monitoring/alerts/resolve", post(alert_resolve))
        .route("/api/monitoring/alerts/unrouted", get(alert_unrouted))
        // ─── Zabbix Drift Remediation ───
        .route("/api/monitoring/zabbix/drift", get(zabbix_drift_summary))
        .route(
            "/api/monitoring/zabbix/drift/detect",
            post(zabbix_drift_detect),
        )
        .route(
            "/api/monitoring/zabbix/drift/plan/{drift_id}",
            post(zabbix_drift_plan),
        )
        .route(
            "/api/monitoring/zabbix/drift/execute/{drift_id}",
            post(zabbix_drift_execute),
        )
        .route(
            "/api/monitoring/zabbix/drift/verify/{drift_id}",
            post(zabbix_drift_verify),
        )
        .route(
            "/api/monitoring/zabbix-drift-contract",
            get(zabbix_drift_contract),
        )
        // ─── Noise Remediation ───
        .route("/api/monitoring/noise/detect", post(noise_detect))
        .route(
            "/api/monitoring/noise/flapping",
            post(noise_flapping_detect),
        )
        .route("/api/monitoring/noise/suggest/{id}", post(noise_suggest))
        .route("/api/monitoring/noise/suppress/{id}", post(noise_suppress))
        .route("/api/monitoring/noise/resolve/{id}", post(noise_resolve))
        .route("/api/monitoring/noise/report", get(noise_report))
        .route(
            "/api/monitoring/noise/suppressed",
            get(noise_suppressed_list),
        )
        .route("/api/monitoring/noise-contract", get(noise_contract))
        // ─── Certificate Lifecycle ───
        .route(
            "/api/maintain/certificates/request",
            post(certificates_request),
        )
        .route(
            "/api/maintain/certificates/validate",
            post(certificates_validate),
        )
        .route(
            "/api/maintain/certificates/approve/{id}",
            post(certificates_approve),
        )
        .route(
            "/api/maintain/certificates/install/{id}",
            post(certificates_install),
        )
        .route(
            "/api/maintain/certificates/verify/{id}",
            post(certificates_verify),
        )
        .route(
            "/api/maintain/certificates/renew/{id}",
            post(certificates_renew),
        )
        .route(
            "/api/maintain/certificates/revoke/{id}",
            post(certificates_revoke),
        )
        .route(
            "/api/maintain/certificates/expiring",
            get(certificates_expiring),
        )
        .route(
            "/api/maintain/certificates/inventory",
            get(certificates_inventory),
        )
        .route("/api/maintain/certificates/{id}", get(certificates_get))
        .route(
            "/api/maintain/certificate-contract",
            get(certificate_lifecycle_contract),
        )
        // ─── VM Day-2 Operations ───
        .route("/api/vm/day2/plan", post(vm_day2_plan))
        .route("/api/vm/day2/validate", post(vm_day2_validate))
        .route("/api/vm/day2/execute", post(vm_day2_execute))
        .route("/api/vm/day2/verify", post(vm_day2_verify))
        .route("/api/vm/day2-change-contract", get(vm_day2_change_contract))
        // ─── DR Testing Engine ───
        .route("/api/protect/dr/plans", get(dr_plans_list))
        .route("/api/protect/dr/plans", post(dr_plan_create))
        .route("/api/protect/dr/plans/{id}", get(dr_plan_get))
        .route(
            "/api/protect/dr/plans/{id}/rpo-rto",
            post(dr_plan_update_rpo_rto),
        )
        .route("/api/protect/dr/tests/start", post(dr_test_start))
        .route("/api/protect/dr/tests/complete", post(dr_test_complete))
        .route("/api/protect/dr/tests/results/{id}", get(dr_test_results))
        .route("/api/protect/dr/due-tests", get(dr_tests_due))
        .route("/api/protect/dr/readiness", get(dr_readiness))
        .route("/api/protect/dr/scenarios", get(dr_scenarios))
        .route("/api/protect/dr-contract", get(dr_contract))
        // ─── Snapshot Governance ───
        .route("/api/protect/snapshot/plan", post(snapshot_plan))
        .route("/api/protect/snapshot/validate", post(snapshot_validate))
        .route("/api/protect/snapshot/review", post(snapshot_review))
        .route(
            "/api/protect/snapshot/flag-stale",
            post(snapshot_flag_stale),
        )
        .route("/api/protect/snapshot/remediate", post(snapshot_remediate))
        .route(
            "/api/protect/snapshot-governance-contract",
            get(snapshot_governance_contract),
        )
        // ─── Backup Coverage & Restore ───
        .route(
            "/api/protect/backup/coverage-report",
            post(backup_coverage_report),
        )
        .route(
            "/api/protect/backup/restore-plan",
            post(backup_restore_plan),
        )
        .route(
            "/api/protect/backup/restore-validate",
            post(backup_restore_validate),
        )
        .route(
            "/api/protect/backup/restore-approve",
            post(backup_restore_approve),
        )
        .route(
            "/api/protect/backup/restore-execute",
            post(backup_restore_execute),
        )
        .route(
            "/api/protect/backup-coverage-contract",
            get(backup_coverage_contract),
        )
        // ─── K8s Container Namespace Engine ───
        .route("/api/build/k8s/namespaces", get(k8s_namespaces_list))
        .route("/api/build/k8s/namespaces", post(k8s_namespace_provision))
        .route("/api/build/k8s/namespaces/{id}", get(k8s_namespace_get))
        .route(
            "/api/build/k8s/namespaces/{id}/quota",
            post(k8s_namespace_update_quota),
        )
        .route(
            "/api/build/k8s/namespaces/{id}/suspend",
            post(k8s_namespace_suspend),
        )
        .route(
            "/api/build/k8s/namespaces/{id}/resume",
            post(k8s_namespace_resume),
        )
        .route(
            "/api/build/k8s/namespaces/{id}/terminate",
            post(k8s_namespace_terminate),
        )
        .route("/api/build/k8s/utilization", get(k8s_cluster_utilization))
        .route("/api/build/k8s/validate-name", post(k8s_validate_name))
        .route("/api/build/k8s/summary", get(k8s_summary))
        .route("/api/build/k8s-contract", get(k8s_contract))
        // ─── Linux Deployment ───
        .route("/api/build/linux/plan", post(linux_deploy_plan))
        .route("/api/build/linux/validate", post(linux_deploy_validate))
        .route("/api/build/linux/execute", post(linux_deploy_execute))
        .route("/api/build/linux/verify", post(linux_deploy_verify))
        .route(
            "/api/build/linux/supported-distros",
            get(linux_supported_distros),
        )
        .route(
            "/api/build/linux-deploy-contract",
            get(linux_deploy_contract),
        )
        // ─── Application Environment Deployment ───
        .route("/api/build/app-environment/plan", post(app_env_plan))
        .route(
            "/api/build/app-environment/validate",
            post(app_env_validate),
        )
        .route(
            "/api/build/app-environment/approve/{id}",
            post(app_env_approve),
        )
        .route(
            "/api/build/app-environment/deploy/{id}",
            post(app_env_deploy),
        )
        .route(
            "/api/build/app-environment/verify/{id}",
            post(app_env_verify),
        )
        .route(
            "/api/build/app-environment/status/{id}",
            get(app_env_status),
        )
        .route("/api/build/app-environment/list", get(app_env_list))
        .route(
            "/api/build/app-environment/retire/{id}",
            post(app_env_retire),
        )
        .route("/api/build/app-environment-contract", get(app_env_contract))
        // ─── Server Decommission ───
        .route("/api/retire/decommission/plan", post(decommission_plan))
        .route(
            "/api/retire/decommission/validate",
            post(decommission_validate),
        )
        .route(
            "/api/retire/decommission/approve/{id}",
            post(decommission_approve),
        )
        .route(
            "/api/retire/decommission/quarantine/{id}",
            post(decommission_quarantine),
        )
        .route(
            "/api/retire/decommission/execute/{id}",
            post(decommission_execute),
        )
        .route(
            "/api/retire/decommission/verify/{id}",
            post(decommission_verify),
        )
        .route(
            "/api/retire/decommission/rollback/{id}",
            post(decommission_rollback),
        )
        .route(
            "/api/retire/decommission/quarantine",
            get(decommission_quarantine_inventory),
        )
        .route("/api/retire/decommission/{id}", get(decommission_get))
        .route(
            "/api/retire/decommission-contract",
            get(decommission_contract),
        )
        // ─── Maintenance Calendar ───
        .route(
            "/api/maintain/calendar/schedule",
            post(maintenance_calendar_schedule),
        )
        .route(
            "/api/maintain/calendar/conflicts",
            get(maintenance_calendar_conflicts),
        )
        .route(
            "/api/maintain/calendar/upcoming",
            get(maintenance_calendar_upcoming),
        )
        .route(
            "/api/maintain/calendar/active",
            get(maintenance_calendar_active),
        )
        .route(
            "/api/maintain/calendar/month",
            get(maintenance_calendar_month),
        )
        .route(
            "/api/maintain/calendar/cancel/{id}",
            post(maintenance_calendar_cancel),
        )
        .route(
            "/api/maintain/calendar-contract",
            get(maintenance_calendar_contract),
        )
        // ─── Datacenter Readiness ───
        .route(
            "/api/datacenter/readiness-score-contract",
            get(datacenter_readiness_score_endpoint),
        )
        .route(
            "/api/datacenter/site-report-contract",
            get(datacenter_site_report_endpoint),
        )
        .route(
            "/api/datacenter/failing-checks-contract",
            get(datacenter_failing_checks_endpoint),
        )
        .route(
            "/api/datacenter/check-power-contract",
            get(datacenter_check_power_endpoint),
        )
        .route(
            "/api/datacenter/check-cooling-contract",
            get(datacenter_check_cooling_endpoint),
        )
        .route(
            "/api/datacenter/check-rack-space-contract",
            get(datacenter_check_rack_space_endpoint),
        )
        .route(
            "/api/datacenter/check-switchports-contract",
            get(datacenter_check_switchports_endpoint),
        )
        .route(
            "/api/datacenter/full-readiness-contract",
            get(datacenter_full_readiness_endpoint),
        )
        .route(
            "/api/datacenter/sites-contract",
            get(datacenter_sites_endpoint),
        )
        // ─── DNS & IPAM Engine ───
        .route("/api/network/dns/records", get(dns_records_list))
        .route("/api/network/dns/records", post(dns_record_create))
        .route("/api/network/dns/records/{id}", get(dns_record_get))
        .route("/api/network/dns/records/{id}", delete(dns_record_delete))
        .route("/api/network/ipam/subnets", get(ipam_subnets_list))
        .route("/api/network/ipam/subnets/{id}", get(ipam_subnet_get))
        .route("/api/network/ipam/reserve", post(ipam_reserve_ip))
        .route("/api/network/ipam/release/{id}", post(ipam_release_ip))
        .route("/api/network/ipam/summary", get(ipam_summary))
        .route(
            "/api/network/ipam/availability/{id}",
            get(ipam_check_availability),
        )
        .route("/api/network/dns-ipam-contract", get(dns_ipam_contract))
        // ─── Firewall Rules Engine ───
        .route("/api/network/firewall/rules", get(firewall_rules_list))
        .route("/api/network/firewall/rules", post(firewall_rule_create))
        .route("/api/network/firewall/rules/{id}", get(firewall_rule_get))
        .route(
            "/api/network/firewall/rules/{id}",
            delete(firewall_rule_delete),
        )
        .route(
            "/api/network/firewall/rules/{id}/update",
            post(firewall_rule_update),
        )
        .route(
            "/api/network/firewall/validate",
            post(firewall_rule_validate),
        )
        .route(
            "/api/network/firewall/rule-sets",
            post(firewall_rule_set_create),
        )
        .route(
            "/api/network/firewall/rule-sets/{id}/apply",
            post(firewall_rule_set_apply),
        )
        .route(
            "/api/network/firewall/rule-sets/{id}/revoke",
            post(firewall_rule_set_revoke),
        )
        .route("/api/network/firewall/conflicts", get(firewall_conflicts))
        .route("/api/network/firewall-contract", get(firewall_contract))
        // ─── Load Balancer Engine ───
        .route("/api/network/loadbalancer/vs", get(lb_vs_list))
        .route("/api/network/loadbalancer/vs", post(lb_provision))
        .route("/api/network/loadbalancer/vs/{id}", get(lb_vs_get))
        .route(
            "/api/network/loadbalancer/vs/{id}/member",
            post(lb_pool_member_add),
        )
        .route(
            "/api/network/loadbalancer/vs/{id}/member/{hostname}",
            delete(lb_pool_member_remove),
        )
        .route("/api/network/loadbalancer/vs/{id}/drain", post(lb_vs_drain))
        .route(
            "/api/network/loadbalancer/vs/{id}/disable",
            post(lb_vs_disable),
        )
        .route(
            "/api/network/loadbalancer/vs/{id}/enable",
            post(lb_vs_enable),
        )
        .route("/api/network/loadbalancer/status", get(lb_status))
        .route(
            "/api/network/loadbalancer/validate-vip",
            post(lb_validate_vip),
        )
        .route("/api/network/loadbalancer-contract", get(lb_contract))
        // ─── Network Port & VLAN Readiness ───
        .route(
            "/api/datacenter/network/readiness",
            get(network_readiness_check),
        )
        .route(
            "/api/datacenter/network/reserve-ports",
            post(network_reserve_ports),
        )
        .route(
            "/api/datacenter/network/reserve-ips",
            post(network_reserve_ips),
        )
        .route(
            "/api/datacenter/network/release/{id}",
            post(network_release),
        )
        .route("/api/datacenter/network/capacity", get(network_capacity))
        .route(
            "/api/datacenter/network/ports",
            get(network_ports_inventory),
        )
        .route(
            "/api/datacenter/network/vlans",
            get(network_vlans_inventory),
        )
        .route("/api/datacenter/network-contract", get(network_contract))
        // ─── OOB Access Validation ───
        .route("/api/datacenter/oob/test/{id}", post(oob_test_endpoint))
        .route(
            "/api/datacenter/oob/validate-cert/{id}",
            post(oob_validate_cert),
        )
        .route(
            "/api/datacenter/oob/check-defaults/{id}",
            post(oob_check_defaults),
        )
        .route("/api/datacenter/oob/inventory", get(oob_inventory))
        .route("/api/datacenter/oob/failing", get(oob_failing))
        .route("/api/datacenter/oob/cert-expiring", get(oob_cert_expiring))
        .route(
            "/api/datacenter/oob/firmware-outdated",
            get(oob_firmware_outdated),
        )
        .route(
            "/api/datacenter/oob/validate-site/{site}",
            post(oob_validate_site),
        )
        .route("/api/datacenter/oob-contract", get(oob_contract))
        // ─── Storage Provisioning Engine ───
        .route("/api/datacenter/storage/volumes", get(storage_volumes_list))
        .route(
            "/api/datacenter/storage/volumes",
            post(storage_volume_provision),
        )
        .route(
            "/api/datacenter/storage/volumes/{id}",
            get(storage_volume_get),
        )
        .route(
            "/api/datacenter/storage/volumes/{id}/extend",
            post(storage_volume_extend),
        )
        .route(
            "/api/datacenter/storage/volumes/{id}/map",
            post(storage_volume_map),
        )
        .route(
            "/api/datacenter/storage/volumes/{id}/unmap",
            post(storage_volume_unmap),
        )
        .route(
            "/api/datacenter/storage/volumes/{id}/retire",
            post(storage_volume_retire),
        )
        .route("/api/datacenter/storage/arrays", get(storage_arrays_list))
        .route(
            "/api/datacenter/storage/arrays/{id}",
            get(storage_array_get),
        )
        .route(
            "/api/datacenter/storage/check-capacity",
            post(storage_check_capacity),
        )
        .route("/api/datacenter/storage/report", get(storage_report))
        .route("/api/datacenter/storage-contract", get(storage_contract))
        // ─── Hardware Lifecycle ───
        .route(
            "/api/datacenter/hardware/inventory",
            get(hardware_inventory),
        )
        .route(
            "/api/datacenter/hardware/warranty-expiring",
            get(hardware_warranty_expiring),
        )
        .route(
            "/api/datacenter/hardware/firmware-check/{id}",
            post(hardware_firmware_check),
        )
        .route(
            "/api/datacenter/hardware/firmware-gaps",
            get(hardware_firmware_gaps),
        )
        .route(
            "/api/datacenter/hardware/support-risk",
            get(hardware_support_risk),
        )
        .route(
            "/api/datacenter/hardware/refresh-plan",
            get(hardware_refresh_plan),
        )
        .route(
            "/api/datacenter/hardware/lifecycle-report",
            get(hardware_lifecycle_report),
        )
        .route("/api/datacenter/hardware/add", post(hardware_add))
        .route(
            "/api/datacenter/hardware/update-firmware/{id}",
            post(hardware_update_firmware),
        )
        .route("/api/datacenter/hardware-contract", get(hardware_contract))
        // ─── Firmware Lifecycle Engine ───
        .route(
            "/api/datacenter/firmware/devices",
            get(firmware_devices_list),
        )
        .route(
            "/api/datacenter/firmware/device/{id}",
            get(firmware_device_get),
        )
        .route(
            "/api/datacenter/firmware/check/{id}",
            post(firmware_check_compliance),
        )
        .route(
            "/api/datacenter/firmware/noncompliant",
            get(firmware_noncompliant),
        )
        .route("/api/datacenter/firmware/eol", get(firmware_eol))
        .route(
            "/api/datacenter/firmware/exception",
            post(firmware_request_exception),
        )
        .route(
            "/api/datacenter/firmware/exceptions",
            get(firmware_exceptions_list),
        )
        .route(
            "/api/datacenter/firmware/revoke/{id}",
            post(firmware_revoke_exception),
        )
        .route(
            "/api/datacenter/firmware/report",
            get(firmware_compliance_report),
        )
        .route(
            "/api/datacenter/firmware/vendor-summary",
            get(firmware_vendor_summary),
        )
        .route("/api/datacenter/firmware-contract", get(firmware_contract))
        .route(
            "/api/datacenter/image-factory/initiate-build",
            post(image_factory_initiate_build),
        )
        .route(
            "/api/datacenter/image-factory/run-tests/{id}",
            post(image_factory_run_tests),
        )
        .route(
            "/api/datacenter/image-factory/promote/{id}",
            post(image_factory_promote),
        )
        .route(
            "/api/datacenter/image-factory/reject/{id}",
            post(image_factory_reject),
        )
        .route(
            "/api/datacenter/image-factory/active/{site}",
            get(image_factory_active),
        )
        .route(
            "/api/datacenter/image-factory/history/{site}",
            get(image_factory_history),
        )
        .route(
            "/api/datacenter/image-factory/superseded",
            get(image_factory_superseded),
        )
        .route(
            "/api/datacenter/image-factory/schedule-monthly",
            post(image_factory_schedule_monthly),
        )
        .route(
            "/api/datacenter/image-factory-contract",
            get(image_factory_contract),
        )
}

// ─── Shared data ───

#[derive(Deserialize)]
pub struct PreflightQuery {
    #[serde(rename = "requestedOffering")]
    pub requested_offering: Option<String>,
    pub owner: Option<String>,
    pub site: Option<String>,
    pub environment: Option<String>,
    pub criticality: Option<String>,
    #[serde(rename = "dryRunPlan")]
    pub dry_run_plan: Option<String>,
    #[serde(rename = "approvalRoute")]
    pub approval_route: Option<String>,
    #[serde(rename = "evidenceManifest")]
    pub evidence_manifest: Option<String>,
    #[serde(rename = "secretReferenceState")]
    pub secret_reference_state: Option<String>,
}

// ─── VM Day-2 request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VmDay2PlanRequest {
    #[serde(rename = "targetCiKey")]
    target_ci_key: String,
    #[serde(rename = "changeType")]
    change_type: String,
    #[serde(rename = "targetValue")]
    target_value: u32,
    site: String,
    environment: String,
    owner: String,
    #[serde(rename = "maintenanceWindow")]
    maintenance_window: String,
}

// ─── Snapshot request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SnapshotPlanRequest {
    #[serde(rename = "platformCiKey")]
    platform_ci_key: String,
    #[serde(rename = "snapshotPurpose")]
    snapshot_purpose: String,
    #[serde(rename = "requestedExpiry")]
    requested_expiry: String,
    owner: String,
    #[serde(rename = "supportGroup")]
    support_group: String,
    #[serde(rename = "changeContext")]
    change_context: String,
}

// ─── Backup request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CoverageReportRequest {
    #[serde(rename = "siteScope")]
    site_scope: Vec<String>,
    #[serde(rename = "environmentScope")]
    environment_scope: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RestorePlanRequest {
    #[serde(rename = "sourceCiKey")]
    source_ci_key: String,
    #[serde(rename = "restoreType")]
    restore_type: String,
    #[serde(rename = "restorePoint")]
    restore_point: String,
    #[serde(rename = "targetSite")]
    target_site: String,
    #[serde(rename = "targetEnvironment")]
    target_environment: String,
    owner: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RestoreActionRequest {
    #[serde(rename = "restoreId")]
    restore_id: String,
    approver: Option<String>,
}

// ─── Legal hold request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LegalHoldPlaceRequest {
    target: String,
    #[serde(rename = "holdType")]
    hold_type: String,
    reason: String,
    by: String,
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LegalHoldExtendRequest {
    #[serde(rename = "newExpiry")]
    new_expiry: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LegalHoldReleaseRequest {
    #[serde(rename = "releasedBy")]
    released_by: String,
}

// ─── Immutability compliance request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ImmutabilityVerifyAllQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ImmutabilityComplianceQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LegalHoldActiveQuery {
    site: Option<String>,
}

// ─── Linux deployment request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LinuxDeployPlanRequest {
    distro: String,
    version: String,
    site: String,
    cpu: u32,
    #[serde(rename = "memoryGb")]
    memory_gb: u32,
    #[serde(rename = "diskGb")]
    disk_gb: u32,
    hostname: String,
    network: String,
    #[serde(rename = "hardeningProfile")]
    hardening_profile: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LinuxDeployValidateRequest {
    distro: String,
    version: String,
    site: String,
    cpu: u32,
    #[serde(rename = "memoryGb")]
    memory_gb: u32,
    #[serde(rename = "diskGb")]
    disk_gb: u32,
    hostname: String,
    network: String,
    #[serde(rename = "hardeningProfile")]
    hardening_profile: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LinuxDeployExecuteRequest {
    distro: String,
    version: String,
    site: String,
    cpu: u32,
    #[serde(rename = "memoryGb")]
    memory_gb: u32,
    #[serde(rename = "diskGb")]
    disk_gb: u32,
    hostname: String,
    network: String,
    #[serde(rename = "hardeningProfile")]
    hardening_profile: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LinuxDeployVerifyRequest {
    distro: String,
    version: String,
    site: String,
    cpu: u32,
    #[serde(rename = "memoryGb")]
    memory_gb: u32,
    #[serde(rename = "diskGb")]
    disk_gb: u32,
    hostname: String,
    network: String,
    #[serde(rename = "hardeningProfile")]
    hardening_profile: String,
}

// ─── Application environment request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AppEnvPlanRequest {
    #[serde(rename = "appName")]
    app_name: String,
    environment: String,
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AppEnvValidateRequest {
    #[serde(rename = "appName")]
    app_name: String,
    environment: String,
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AppEnvListQuery {
    site: Option<String>,
}

// ─── Alert routing request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AlertRouteCreateRequest {
    #[serde(rename = "triggerName")]
    trigger_name: String,
    severity: String,
    #[serde(rename = "hostGroup")]
    host_group: String,
    #[serde(rename = "supportGroup")]
    support_group: String,
    priority: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AlertRouteUpdateRequest {
    #[serde(rename = "triggerName")]
    trigger_name: Option<String>,
    severity: Option<String>,
    #[serde(rename = "hostGroup")]
    host_group: Option<String>,
    #[serde(rename = "supportGroup")]
    support_group: Option<String>,
    priority: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AlertResolveRequest {
    #[serde(rename = "triggerName")]
    trigger_name: String,
    severity: String,
    #[serde(rename = "hostGroup")]
    host_group: String,
}

// ─── Certificate lifecycle request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CertificateRequestRequest {
    #[serde(rename = "commonName")]
    common_name: String,
    subject: String,
    #[serde(rename = "serviceType")]
    service_type: String,
    hostname: String,
    site: String,
    #[serde(rename = "validityDays")]
    validity_days: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CertificateValidateRequest {
    #[serde(rename = "commonName")]
    common_name: String,
    subject: String,
    #[serde(rename = "serviceType")]
    service_type: String,
    hostname: String,
    site: String,
    #[serde(rename = "validityDays")]
    validity_days: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CertificateRenewRequest {
    #[serde(rename = "validityDays")]
    validity_days: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CertificateExpiringQuery {
    site: Option<String>,
    days: Option<i64>,
}

// ─── AD computer lifecycle request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AdPrestageRequest {
    name: String,
    site: String,
    #[serde(rename = "ouPath")]
    ou_path: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AdValidateRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AdMoveRequest {
    #[serde(rename = "targetOu")]
    target_ou: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AdDisableRequest {
    reason: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AdReconcileQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AdOrphanedQuery {
    site: Option<String>,
}

// ─── gMSA lifecycle request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GmsaCreateRequest {
    name: String,
    hosts: Vec<String>,
    spns: Vec<String>,
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GmsaValidateRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GmsaInventoryQuery {
    site: Option<String>,
}

// ─── File Share NTFS recertification request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SharesQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SharesRecertificationDueQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SharesStaleOwnersQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RecertifyShareRequest {
    reviewer: String,
}

// ─── Patch wave request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PatchPlanRequest {
    site: String,
    #[serde(rename = "osFamily")]
    os_family: String,
    criticality: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PatchActionRequest {
    #[serde(rename = "waveId")]
    wave_id: String,
}

// ─── Zabbix drift request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ZabbixDriftSiteRequest {
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ZabbixDriftQuery {
    site: Option<String>,
}

// ─── Noise remediation request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NoiseSiteRequest {
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NoiseSiteQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NoiseSuppressRequest {
    duration_minutes: u32,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NoiseResolveRequest {
    resolution: String,
}

// ─── Network readiness request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NetworkReadinessQuery {
    site: Option<String>,
    ports: Option<u32>,
    vlan: Option<u32>,
    ips: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NetworkReservePortsRequest {
    site: String,
    count: u32,
    purpose: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NetworkReserveIpsRequest {
    site: String,
    vlan_id: u32,
    count: u32,
    purpose: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NetworkSwitchQuery {
    #[serde(rename = "switch")]
    switch: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NetworkSiteQuery {
    site: Option<String>,
}

// ─── OOB Access request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OobInventoryQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OobFailingQuery {
    site: Option<String>,
}

// ─── Hardware lifecycle request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HardwareInventoryQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HardwareFirmwareGapsQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HardwareSupportRiskQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HardwareRefreshPlanQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HardwareLifecycleReportQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HardwareAddRequest {
    vendor: String,
    model: String,
    site: String,
    cluster: String,
    serial: String,
    #[serde(rename = "warrantyExpiry")]
    warranty_expiry: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HardwareUpdateFirmwareRequest {
    version: String,
}

// ─── Outage comms request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OutageNoticeCreateRequest {
    site: String,
    #[serde(rename = "affectedSystems")]
    affected_systems: Vec<String>,
    #[serde(rename = "startTime")]
    start_time: String,
    #[serde(rename = "endTime")]
    end_time: String,
    #[serde(rename = "impactLevel")]
    impact_level: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OutageNoticeListQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OutageNoticeActiveQuery {
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OutageNoticeHistoryQuery {
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OutageNoticeUpcomingQuery {
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OutageNoticeAcknowledgeRequest {
    user: String,
}

// ─── Request lifecycle types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CreateRequest {
    request_type: String,
    site: String,
    environment: String,
    name: String,
    cpu: u32,
    memory_gb: u32,
    justification: String,
}

#[derive(Debug, sqlx::FromRow)]
struct DbRequestRow {
    id: Uuid,
    request_type: String,
    status: String,
    stage: String,
    site: String,
    environment: String,
    name: String,
    cpu: i32,
    memory_gb: i32,
    justification: Option<String>,
    created_by: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

// ─── Request store (in-memory fallback) ───

static REQUEST_STORE: OnceLock<Mutex<Vec<ryuki_engine::models::Request>>> = OnceLock::new();

fn request_store() -> &'static Mutex<Vec<ryuki_engine::models::Request>> {
    REQUEST_STORE.get_or_init(|| Mutex::new(Vec::new()))
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn lifecycle_stages() -> Value {
    json!([
        "intake", "validate", "plan", "approve", "lock", "execute", "verify", "protect", "publish",
        "maintain", "retire"
    ])
}
fn components() -> Value {
    json!([
        "portal-ui",
        "platform-api",
        "platform-db",
        "platform-vault",
        "vault-secrets-operator",
        "platform-worker",
        "inventory-sync",
        "vmware-adapter",
        "nutanix-ahv-adapter",
        "xen-adapter",
        "kvm-adapter",
        "veeam-br-adapter",
        "veeam-one-adapter",
        "commvault-adapter",
        "rubrik-adapter",
        "cohesity-adapter",
        "netbackup-adapter",
        "zabbix-adapter",
        "prometheus-adapter",
        "datadog-adapter",
        "grafana-adapter",
        "solarwinds-adapter",
        "servicenow-adapter",
        "image-factory-controller",
        "evidence-service"
    ])
}
fn guardrails() -> Value {
    json!([
        "no-hardcoded-secrets",
        "browser-isolation",
        "dry-run-first",
        "approval-gated-execution",
        "least-privilege-adapters",
        "redacted-evidence",
        "safe-degraded-read-only-mode"
    ])
}
fn categories() -> Value {
    json!(["Build", "Maintain", "Protect", "Observe", "Operate", "Retire"])
}

fn rql_stages() -> Value {
    json!([
        "intake", "validate", "plan", "approve", "lock", "execute", "verify", "protect", "publish",
        "maintain", "retire"
    ])
}
fn rql_guards() -> Value {
    json!([
        "intake-complete",
        "validation-passed",
        "dry-run-reviewed",
        "approval-route-assigned",
        "lock-scope-ready",
        "evidence-redacted",
        "provider-safe-plan-ready",
        "status-callback-ready",
        "fail-safe-state-reviewed"
    ])
}
fn rql_plan_sections() -> Value {
    json!([
        "intakeSummary",
        "validationSummary",
        "dryRunPlan",
        "approvalDecisions",
        "lockRecord",
        "executionPlan",
        "verificationPlan",
        "protectionPlan",
        "publishPlan",
        "maintainPlan",
        "retirePlan",
        "evidenceReferences"
    ])
}
fn rql_blocked() -> Value {
    json!([
        "live-execution-disabled",
        "provider-calls-disabled",
        "workflow-mutation-disabled",
        "approval-mutation-disabled",
        "lock-mutation-disabled",
        "raw-request-payloads-disabled",
        "raw-execution-logs-disabled",
        "raw-evidence-payloads-disabled",
        "raw-provider-payloads-disabled",
        "credential-values-disabled",
        "secret-values-disabled",
        "access-token-values-disabled",
        "raw-recipient-data-disabled",
        "intake-incomplete",
        "validation-missing",
        "dry-run-plan-missing",
        "approval-route-missing",
        "lock-scope-missing",
        "evidence-not-redacted",
        "status-callback-missing"
    ])
}

fn ret_stages() -> Value {
    json!([
        "intake",
        "validation",
        "dry-run-plan",
        "approval",
        "lock",
        "execution",
        "verification",
        "protection",
        "publish",
        "handover"
    ])
}
fn ret_events() -> Value {
    json!([
        "request-state",
        "validation-result",
        "dry-run-plan",
        "approval-decision",
        "lock-record",
        "child-operation",
        "evidence-reference",
        "blocker",
        "status-callback",
        "handover-note"
    ])
}
fn ret_evidence_states() -> Value {
    json!([
        "not-required",
        "pending",
        "redacted-ready",
        "blocked",
        "export-ready"
    ])
}
fn ret_views() -> Value {
    json!([
        "request-summary",
        "timeline",
        "approval-history",
        "operation-links",
        "evidence-links",
        "blocker-summary",
        "handover-summary"
    ])
}
fn ret_guards() -> Value {
    json!([
        "request-scope-known",
        "timeline-source-reviewed",
        "evidence-redacted",
        "approval-state-known",
        "lock-state-known",
        "operation-link-safe",
        "status-callback-safe",
        "raw-detail-blocked"
    ])
}
fn ret_blocked() -> Value {
    json!([
        "request-timeline-live-query-disabled",
        "request-timeline-mutation-disabled",
        "request-workflow-mutation-disabled",
        "request-operation-mutation-disabled",
        "request-provider-calls-disabled",
        "request-notification-dispatch-disabled",
        "request-raw-request-payloads-disabled",
        "request-raw-timeline-rows-disabled",
        "request-raw-approval-data-disabled",
        "request-raw-operation-rows-disabled",
        "request-raw-evidence-payloads-disabled",
        "request-raw-provider-payloads-disabled",
        "request-raw-log-content-disabled",
        "request-raw-recipient-data-disabled",
        "request-credential-values-disabled",
        "request-token-values-disabled",
        "request-tenant-identifiers-disabled",
        "request-object-identifiers-disabled",
        "request-principal-identifiers-disabled",
        "request-private-network-values-disabled",
        "request-scope-missing",
        "timeline-source-missing",
        "evidence-not-redacted"
    ])
}

// ─── Log forwarder request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LogsOnboardRequest {
    hostname: String,
    #[serde(rename = "sourceTypes", default)]
    source_types: Vec<String>,
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LogsSiteQuery {
    site: String,
}

// ─── Endpoint handlers ───

async fn platform_summary() -> Json<Value> {
    let config = crate::config_store::get_app_config();
    Json(json!({
        "productName": config.platform_name,
        "lifecycleStages": lifecycle_stages(),
        "components": components(),
        "guardrails": guardrails(),
        "browserIsolation": true,
        "localAuthorization": {
            "authenticationMode": config.auth_mode,
            "configuredForProduction": false,
            "entraGroupsConfigured": !config.entra_tenant_id.is_empty(),
            "roleHeader": "X-Ryuki-Local-Role",
            "requiredProductionProvider": "Microsoft Entra ID"
        }
    }))
}

async fn platform_status() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "mode": "static-dry-run",
        "status": "healthy",
        "providerCallsAllowed": false,
        "liveExecutionAllowed": false,
        "workflowMutationAllowed": false,
        "credentialValuesAllowed": false,
        "secretValuesAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "rawRecipientDataAllowed": false,
        "tenantIdentifiersAllowed": false,
        "objectIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false,
        "guards": guardrails(),
        "blockedReasons": [
            "live-execution-disabled",
            "provider-calls-disabled",
            "workflow-mutation-disabled",
            "credential-values-disabled",
            "secret-values-disabled",
            "raw-provider-payloads-disabled",
            "raw-recipient-data-disabled",
            "tenant-identifiers-disabled",
            "object-identifiers-disabled",
            "private-network-values-disabled"
        ]
    }))
}

async fn dashboard_global_overview() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "dashboardGlobalOverviewMode": "static-dashboard-global-overview",
        "dashboardSummaryAggregateOnly": true,
        "siteReadinessAggregateOnly": true,
        "riskSignalsReadOnly": true,
        "evidenceReferencesOnly": true,
        "liveQueryAllowed": false,
        "dashboardMutationAllowed": false,
        "providerCallsAllowed": false,
        "notificationDispatchAllowed": false,
        "rawRequestRowsAllowed": false,
        "rawOperationRowsAllowed": false,
        "rawInventoryRowsAllowed": false,
        "rawCmdbRowsAllowed": false,
        "rawBackupRowsAllowed": false,
        "rawMonitoringRowsAllowed": false,
        "rawUserDataAllowed": false,
        "rawRecipientDataAllowed": false,
        "credentialValuesAllowed": false,
        "tokenValuesAllowed": false,
        "tenantIdentifiersAllowed": false,
        "objectIdentifiersAllowed": false,
        "principalIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false,
        "summaryDomains": ["global-health","site-readiness","open-requests","failed-operations","patch-risk","backup-risk","monitoring-gaps","cmdb-risk","evidence-readiness"],
        "statusBands": ["healthy","attention","risk","blocked","stale","unknown"],
        "lenses": ["by-site","by-environment","by-owner-domain","by-service-criticality","by-time-window"],
        "requiredGuards": ["aggregate-only","stale-data-marked","evidence-redacted","owner-domain-safe","scope-known","live-query-blocked","raw-detail-blocked"],
        "blockedReasons": ["dashboard-live-query-disabled","dashboard-mutation-disabled","dashboard-provider-calls-disabled","dashboard-notification-dispatch-disabled","dashboard-raw-request-rows-disabled","dashboard-raw-operation-rows-disabled","dashboard-raw-inventory-rows-disabled","dashboard-raw-cmdb-rows-disabled","dashboard-raw-backup-rows-disabled","dashboard-raw-monitoring-rows-disabled","dashboard-raw-user-data-disabled","dashboard-raw-recipient-data-disabled","dashboard-credential-values-disabled","dashboard-token-values-disabled","dashboard-tenant-identifiers-disabled","dashboard-object-identifiers-disabled","dashboard-principal-identifiers-disabled","dashboard-private-network-values-disabled","scope-missing","stale-data-unmarked","evidence-not-redacted","raw-detail-requested"],
        "requiredEvidence": ["Dashboard summary","Site readiness summary","Request backlog summary","Failed operation summary","Patch risk summary","Backup risk summary","Monitoring gap summary","CMDB risk summary","Evidence references"],
        "rules": [
            {"id":"global-dashboard-aggregate-only","decision":"block","requirement":"Global dashboard summaries are aggregate-only and must not run live queries or expose raw request, operation, inventory, CMDB, backup, or monitoring rows.","evidence":"Dashboard summary"},
            {"id":"risk-signals-read-only","decision":"block","requirement":"Patch, backup, monitoring, CMDB, and evidence risk signals are read-only and must not mutate dashboards, workflows, providers, or notification state.","evidence":"Patch risk summary"},
            {"id":"stale-data-explicit","decision":"block","requirement":"Dashboard freshness and stale-data markers must be explicit so operators do not mistake cached aggregate state for live provider state.","evidence":"Site readiness summary"},
            {"id":"raw-dashboard-data-not-exposed","decision":"block","requirement":"Dashboard evidence must not expose raw request rows, raw operation rows, raw inventory rows, raw CMDB rows, raw backup rows, raw monitoring rows, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.","evidence":"Evidence references"}
        ]
    }))
}

async fn dashboard_risk_heatmap() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "riskHeatmapMode": "static-dashboard-risk-heatmap",
        "heatmapReadOnly": true,
        "trendSummaryReadOnly": true,
        "riskBandSummaryOnly": true,
        "evidenceReferencesReadOnly": true,
        "liveMetricsQueryAllowed": false,
        "liveDashboardQueryAllowed": false,
        "dashboardMutationAllowed": false,
        "workflowMutationAllowed": false,
        "providerCallsAllowed": false,
        "notificationDispatchAllowed": false,
        "rawMetricRowsAllowed": false,
        "rawRequestRowsAllowed": false,
        "rawOperationRowsAllowed": false,
        "rawInventoryRowsAllowed": false,
        "rawCmdbRowsAllowed": false,
        "rawBackupRowsAllowed": false,
        "rawMonitoringRowsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "rawUserDataAllowed": false,
        "rawRecipientDataAllowed": false,
        "credentialValuesAllowed": false,
        "tokenValuesAllowed": false,
        "tenantIdentifiersAllowed": false,
        "objectIdentifiersAllowed": false,
        "principalIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false,
        "dimensions": ["site","environment","service-criticality","owner-domain","risk-domain","time-window"],
        "riskDomains": ["patch-risk","backup-risk","monitoring-risk","cmdb-risk","capacity-risk","evidence-risk","incident-risk"],
        "riskBands": ["healthy","attention","risk","blocked","stale","unknown"],
        "trendWindows": ["now","seven-day","thirty-day","quarter"],
        "requiredGuards": ["aggregate-only","stale-data-marked","risk-band-reviewed","trend-window-reviewed","evidence-redacted","live-query-blocked","raw-detail-blocked"],
        "blockedReasons": ["risk-heatmap-live-metrics-query-disabled","risk-heatmap-live-dashboard-query-disabled","risk-heatmap-dashboard-mutation-disabled","risk-heatmap-workflow-mutation-disabled","risk-heatmap-provider-calls-disabled","risk-heatmap-notification-dispatch-disabled","risk-heatmap-raw-metric-rows-disabled","risk-heatmap-raw-request-rows-disabled","risk-heatmap-raw-operation-rows-disabled","risk-heatmap-raw-inventory-rows-disabled","risk-heatmap-raw-cmdb-rows-disabled","risk-heatmap-raw-backup-rows-disabled","risk-heatmap-raw-monitoring-rows-disabled","risk-heatmap-raw-provider-payloads-disabled","risk-heatmap-raw-user-data-disabled","risk-heatmap-raw-recipient-data-disabled","risk-heatmap-credential-values-disabled","risk-heatmap-token-values-disabled","risk-heatmap-tenant-identifiers-disabled","risk-heatmap-object-identifiers-disabled","risk-heatmap-principal-identifiers-disabled","risk-heatmap-private-network-values-disabled","scope-missing","trend-window-missing","risk-band-unknown","evidence-not-redacted"],
        "requiredEvidence": ["Risk heatmap summary","Trend window summary","Risk band summary","Stale-data marker summary","Evidence references"],
        "rules": [
            {"id":"risk-heatmap-aggregate-only","decision":"block","requirement":"Risk heatmaps are aggregate-only and may not run live metrics queries or dashboard reads for operational mutation.","evidence":"Risk heatmap summary"},
            {"id":"trend-window-read-only","decision":"block","requirement":"Trend-window summaries are read-only and must be reviewed before any deployment or remediation planning.","evidence":"Trend window summary"},
            {"id":"stale-risk-markers-required","decision":"block","requirement":"Stale-data markers must be explicit for each risk band and trend window before trust.","evidence":"Stale-data marker summary"},
            {"id":"raw-risk-heatmap-data-not-exposed","decision":"block","requirement":"Risk heatmap evidence must expose only aggregate risk summaries and must not include raw metric rows, raw request rows, raw operation rows, raw inventory rows, raw CMDB rows, raw backup rows, raw monitoring rows, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, provider payloads, or URLs.","evidence":"Evidence references"}
        ]
    }))
}

async fn requests_lifecycle() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "lifecycleMode": "static-request-lifecycle",
        "dryRunRequired": true,
        "approvalRequired": true,
        "lockRequired": true,
        "redactedEvidenceRequired": true,
        "liveExecutionAllowed": false,
        "providerCallsAllowed": false,
        "workflowMutationAllowed": false,
        "approvalMutationAllowed": false,
        "lockMutationAllowed": false,
        "rawRequestPayloadsAllowed": false,
        "rawExecutionLogsAllowed": false,
        "rawEvidencePayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "credentialValuesAllowed": false,
        "secretValuesAllowed": false,
        "accessTokenValuesAllowed": false,
        "rawRecipientDataAllowed": false,
        "lifecycleStages": rql_stages(),
        "requiredInputs": ["requestContext","requesterRole","offering","site","environment","owner","criticality","dryRunPlan","approvalRoute","lockScope","evidenceManifest","statusCallback"],
        "requiredGuards": rql_guards(),
        "planSections": rql_plan_sections(),
        "blockedReasons": rql_blocked(),
        "requiredEvidence": ["Request payload summary","Validation result","Provider-safe dry-run plan","Approval decisions","Lock record","Execution plan summary","Verification plan","Protection policy summary","Publish plan","Lifecycle handover notes","Evidence references"],
        "rules": [
            {"id":"canonical-lifecycle-required","decision":"block","requirement":"Request lifecycle readiness requires intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire stages to remain explicit.","evidence":"Request payload summary"},
            {"id":"dry-run-before-approval-required","decision":"block","requirement":"Write-capable requests must include a provider-safe dry-run plan before approval readiness can be represented.","evidence":"Provider-safe dry-run plan"},
            {"id":"approval-lock-evidence-required","decision":"block","requirement":"Approval route, lock scope, and redacted evidence references must be ready before a request can move beyond planning.","evidence":"Approval decisions"},
            {"id":"fail-safe-state-required","decision":"block","requirement":"Missing validation, stale data, degraded dependency, or incomplete evidence must block execution readiness and expose safe remediation.","evidence":"Lifecycle handover notes"},
            {"id":"raw-request-data-not-exposed","decision":"block","requirement":"Request lifecycle evidence must use safe summaries only and must not expose direct provider routes, organization-scope identifiers, provider-side identifiers, private network details, sensitive auth material, raw request content, raw execution content, raw evidence content, raw provider content, stack traces, recipient details, or implementation internals.","evidence":"Evidence references"}
        ]
    }))
}

async fn requests_execution_timeline() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "requestTimelineMode": "static-request-execution-timeline",
        "timelineReadOnly": true,
        "evidenceReferencesReadOnly": true,
        "operationLinksReadOnly": true,
        "liveRequestQueryAllowed": false,
        "requestMutationAllowed": false,
        "workflowMutationAllowed": false,
        "operationMutationAllowed": false,
        "providerCallsAllowed": false,
        "notificationDispatchAllowed": false,
        "rawRequestPayloadsAllowed": false,
        "rawTimelineRowsAllowed": false,
        "rawApprovalDataAllowed": false,
        "rawOperationRowsAllowed": false,
        "rawEvidencePayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "rawLogContentAllowed": false,
        "rawRecipientDataAllowed": false,
        "credentialValuesAllowed": false,
        "tokenValuesAllowed": false,
        "tenantIdentifiersAllowed": false,
        "objectIdentifiersAllowed": false,
        "principalIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false,
        "timelineStages": ret_stages(),
        "timelineEventTypes": ret_events(),
        "evidenceStates": ret_evidence_states(),
        "timelineViews": ret_views(),
        "requiredGuards": ret_guards(),
        "blockedReasons": ret_blocked(),
        "requiredEvidence": ["Request timeline summary","Approval state summary","Operation link summary","Evidence reference summary","Blocked reason summary"],
        "rules": [
            {"id":"request-execution-timeline-read-only","decision":"block","requirement":"Request execution timeline summaries are read-only and must not run live request queries, mutate requests, mutate operations, call providers, or dispatch notifications.","evidence":"Request timeline summary"},
            {"id":"evidence-reference-only","decision":"block","requirement":"Request evidence links expose redacted evidence reference states only and must not expose raw evidence payloads or raw log content.","evidence":"Evidence reference summary"},
            {"id":"approval-operation-links-safe","decision":"block","requirement":"Approval, lock, child operation, status callback, blocker, and handover timeline items must remain safe summaries without raw approval data or operation rows.","evidence":"Operation link summary"},
            {"id":"raw-request-timeline-data-not-exposed","decision":"block","requirement":"Request timeline evidence must not expose raw request payloads, raw timeline rows, raw approval data, raw operation rows, raw evidence payloads, raw provider payloads, raw logs, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.","evidence":"Blocked reason summary"}
        ]
    }))
}

async fn requests_intake_support() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "intakeSupportMode": "static-intake-support",
        "templateCatalogReadOnly": true,
        "duplicateDetectionDryRunOnly": true,
        "draftStateReadOnly": true,
        "liveSubmissionAllowed": false,
        "draftPersistenceAllowed": false,
        "duplicateQueryAllowed": false,
        "workflowMutationAllowed": false,
        "approvalMutationAllowed": false,
        "providerCallsAllowed": false,
        "rawRequestPayloadsAllowed": false,
        "rawDraftPayloadsAllowed": false,
        "rawDuplicateRowsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "rawLogContentAllowed": false,
        "rawRowsAllowed": false,
        "rawRecipientDataAllowed": false,
        "credentialValuesAllowed": false,
        "tenantIdentifiersAllowed": false,
        "objectIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false,
        "supportSurfaces": ["request-templates","duplicate-detection","saved-draft-states","intake-precheck","evidence-summary"],
        "templateTypes": ["offering-template","site-default-template","role-default-template","maintenance-template","retirement-template"],
        "duplicateSignals": ["same-offering-scope","same-target-resource","same-site-environment-owner","overlapping-maintenance-window","active-request-open","recent-build-or-retirement"],
        "draftStates": ["not-started","in-progress","stale","blocked","ready-for-validation","expired"],
        "requiredGuards": ["template-source-reviewed","duplicate-signals-reviewed","draft-state-read-only","request-submission-blocked","draft-persistence-blocked","raw-payloads-blocked","recipient-data-blocked","evidence-redacted"],
        "blockedReasons": ["live-submission-disabled","draft-persistence-disabled","duplicate-query-disabled","workflow-mutation-disabled","approval-mutation-disabled","provider-calls-disabled","raw-request-payloads-disabled","raw-draft-payloads-disabled","raw-duplicate-rows-disabled","raw-provider-payloads-disabled","raw-log-content-disabled","raw-rows-disabled","raw-recipient-data-disabled","credential-values-disabled","tenant-identifiers-disabled","object-identifiers-disabled","private-network-values-disabled","template-source-missing","duplicate-signal-missing","draft-state-unknown","evidence-not-redacted"],
        "requiredEvidence": ["Template catalog review","Duplicate signal review","Draft state summary","Intake precheck summary","Evidence references"],
        "rules": [
            {"id":"template-catalog-read-only","decision":"block","requirement":"Request intake support exposes template metadata only and must not create, update, or persist request drafts.","evidence":"Template catalog review"},
            {"id":"duplicate-detection-dry-run-only","decision":"block","requirement":"Duplicate detection remains a static signal contract and must not query live request stores, provider systems, or raw request payloads.","evidence":"Duplicate signal review"},
            {"id":"submission-and-approval-mutation-disabled","decision":"block","requirement":"Intake support cannot submit requests, mutate workflows, mutate approvals, or start live execution.","evidence":"Intake precheck summary"},
            {"id":"raw-intake-data-not-exposed","decision":"block","requirement":"Request intake support evidence must use safe summaries only and must not expose raw request payloads, raw draft payloads, raw duplicate rows, raw provider payloads, raw logs, raw rows, recipient data, credential values, tenant identifiers, object identifiers, private network values, live endpoints, or URLs.","evidence":"Evidence references"}
        ]
    }))
}

async fn requests_intake_form() -> Json<Value> {
    Json(json!({
        "title": "Request Intake",
        "description": "Review-only preview — submission available in next release",
        "source": "static-seed",
        "formMode": "static-request-form-preview",
        "formSubmissionAllowed": false,
        "liveRequestCreationAllowed": false,
        "inputKinds": ["text", "select", "number"],
        "fields": [
            {
                "label": "Request type",
                "field_type": "select",
                "required": true,
                "options": ["VM", "Application", "SQL", "Network", "Storage"],
                "placeholder": "Select request type"
            },
            {
                "label": "Site",
                "field_type": "select",
                "required": true,
                "options": ["site-alpha", "site-bravo"],
                "placeholder": "Select site"
            },
            {
                "label": "Environment",
                "field_type": "select",
                "required": true,
                "options": ["dev", "test", "staging", "prod"],
                "placeholder": "Select environment"
            },
            {
                "label": "Server name",
                "field_type": "text",
                "required": true,
                "options": [],
                "placeholder": "e.g. srv-app-01"
            },
            {
                "label": "CPU cores",
                "field_type": "number",
                "required": true,
                "options": [],
                "placeholder": "e.g. 4"
            },
            {
                "label": "Memory GB",
                "field_type": "number",
                "required": true,
                "options": [],
                "placeholder": "e.g. 16"
            },
            {
                "label": "Business justification",
                "field_type": "text",
                "required": true,
                "options": [],
                "placeholder": "Brief business justification for this request"
            }
        ],
        "blockedReasons": ["live-submission-disabled", "form-submission-disabled", "live-request-creation-disabled"],
        "requiredEvidence": ["Form preview review", "Safe summary boundary"]
    }))
}

async fn requests_preflight() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "preflightMode": "static-preflight-readiness",
        "inputSchemaReadOnly": true,
        "dryRunDecisionRequired": true,
        "evidenceRedactionRequired": true,
        "liveSubmissionAllowed": false,
        "liveExecutionAllowed": false,
        "providerCallsAllowed": false,
        "providerValidationAllowed": false,
        "livePolicyEvaluationAllowed": false,
        "requestMutationAllowed": false,
        "workflowMutationAllowed": false,
        "approvalMutationAllowed": false,
        "workerDispatchAllowed": false,
        "rawRequestPayloadsAllowed": false,
        "rawValidationRowsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "rawInventoryRowsAllowed": false,
        "rawCmdbRowsAllowed": false,
        "rawApprovalDataAllowed": false,
        "rawUserDataAllowed": false,
        "rawRecipientDataAllowed": false,
        "credentialValuesAllowed": false,
        "tokenValuesAllowed": false,
        "tenantIdentifiersAllowed": false,
        "objectIdentifiersAllowed": false,
        "principalIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false,
        "hypervisorScope": ["vmware","hyperv","proxmox","nutanix-ahv","xen","kvm"],
        "preflightSurfaces": ["input-completeness","catalog-policy-readiness","site-context-readiness","dependency-readiness","approval-route-readiness","dry-run-plan-readiness","evidence-redaction-readiness"],
        "validationStages": ["site","owner","capacity","network","backup","monitoring","cmdb","approval","dry-run","evidence"],
        "requiredInputs": ["requestedOffering","owner","site","environment","criticality","dryRunPlan","approvalRoute","evidenceManifest","secretReferenceState"],
        "requiredGuards": ["requested-offering-known","owner-known","site-known","environment-known","criticality-known","dry-run-plan-ready","approval-route-assigned","evidence-redacted","secret-reference-configured","provider-calls-blocked","live-execution-blocked"],
        "blockedReasons": ["missing-requested-offering","owner-missing","site-missing","environment-missing","criticality-missing","provider-safe-dry-run-not-ready","approval-route-missing","redacted-evidence-not-ready","secret-reference-not-configured","provider-calls-disabled","live-execution-disabled","request-mutation-disabled","workflow-mutation-disabled","approval-mutation-disabled","raw-request-payloads-disabled","raw-validation-rows-disabled","raw-provider-payloads-disabled","raw-inventory-rows-disabled","raw-cmdb-rows-disabled","raw-approval-data-disabled","raw-user-data-disabled","raw-recipient-data-disabled","credential-values-disabled","token-values-disabled","tenant-identifiers-disabled","object-identifiers-disabled","private-network-values-disabled"],
        "requiredEvidence": ["Request input summary","Validation stage summary","Provider-safe dry-run decision","Approval route summary","Redacted evidence manifest","Secret reference state"],
        "rules": [
            {"id":"no-live-provider-preflight","decision":"block","requirement":"Preflight readiness is static and must not call providers, validate live provider state, or query live inventory, CMDB, ticket, backup, monitoring, or identity systems.","evidence":"Validation stage summary"},
            {"id":"live-execution-disabled","decision":"block","requirement":"Preflight may return block or review readiness only and must never submit requests, start workflows, mutate approvals, dispatch workers, or run live execution.","evidence":"Provider-safe dry-run decision"},
            {"id":"required-inputs-and-guards-reviewed","decision":"block","requirement":"Requested offering, owner, site, environment, criticality, dry-run plan, approval route, evidence manifest, and secret reference state must be reviewed before approval readiness.","evidence":"Request input summary"},
            {"id":"redacted-evidence-required","decision":"block","requirement":"Preflight evidence must be redacted before any approval or lifecycle handoff.","evidence":"Redacted evidence manifest"},
            {"id":"raw-preflight-data-not-exposed","decision":"block","requirement":"Preflight evidence must use safe summaries only and must not expose raw request payloads, raw validation rows, raw provider payloads, raw inventory rows, raw CMDB rows, raw approval data, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.","evidence":"Redacted evidence manifest"}
        ]
    }))
}

async fn platform_security_baseline() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "baselineMode": "static-security-baseline",
        "noSecretPolicyRequired": true,
        "browserIsolationRequired": true,
        "networkIsolationRequired": true,
        "rbacApprovalRequired": true,
        "dryRunRequired": true,
        "redactedEvidenceRequired": true,
        "verificationGatesRequired": true,
        "providerCallsAllowed": false,
        "liveAuthenticationAllowed": false,
        "workflowMutationAllowed": false,
        "policyMutationAllowed": false,
        "approvalBypassAllowed": false,
        "rbacBypassAllowed": false,
        "browserVendorEndpointAllowed": false,
        "rawRequestPayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "rawEvidencePayloadsAllowed": false,
        "rawLogContentAllowed": false,
        "credentialValuesAllowed": false,
        "secretValuesAllowed": false,
        "accessTokenValuesAllowed": false,
        "rawRecipientDataAllowed": false,
        "securityControls": ["no-secrets","identity-rbac-approval","dry-run-first","request-lifecycle-gates","vault-secret-reference","browser-isolation","network-isolation","evidence-redaction","least-privilege-adapters","safe-failure-degraded-mode","verification-gates"],
        "verificationGates": ["markdown-review","no-secret-scan","diff-check","unit-tests","contract-tests","build","container-build","kubernetes-validation","browser-checks"],
        "requiredInputs": ["securityScope","controlSummary","rbacApprovalSummary","dryRunSummary","networkIsolationSummary","evidenceRedactionSummary","verificationSummary","evidenceManifest"],
        "requiredGuards": ["no-secret-scan-ready","rbac-approval-reviewed","dry-run-gates-reviewed","browser-isolation-reviewed","network-isolation-reviewed","redaction-reviewed","least-privilege-reviewed","verification-gates-reviewed","safe-failure-reviewed"],
        "planSections": ["noSecretsPolicy","identityRbacApproval","dryRunLifecycle","secretReferenceModel","browserNetworkIsolation","evidenceRedaction","adapterLeastPrivilege","degradedMode","verificationGates","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","live-authentication-disabled","workflow-mutation-disabled","policy-mutation-disabled","approval-bypass-disabled","rbac-bypass-disabled","browser-vendor-endpoint-disabled","raw-request-payloads-disabled","raw-provider-payloads-disabled","raw-evidence-payloads-disabled","raw-log-content-disabled","credential-values-disabled","secret-values-disabled","access-token-values-disabled","raw-recipient-data-disabled","no-secret-scan-missing","rbac-approval-review-missing","dry-run-gate-review-missing","browser-isolation-review-missing","network-isolation-review-missing","redaction-review-missing","verification-gates-missing"],
        "requiredEvidence": ["Security baseline summary","No-secret scan result","RBAC and approval review","Dry-run gate review","Browser isolation review","Network isolation review","Evidence redaction review","Least privilege review","Verification gate review","Evidence references"],
        "rules": [
            {"id":"no-secrets-required","decision":"block","requirement":"Security baseline readiness requires no committed sensitive auth material, deployment-specific identifiers, private network details, direct provider routes, or raw provider content.","evidence":"No-secret scan result"},
            {"id":"rbac-approval-required","decision":"block","requirement":"Role mapping, least privilege, approval route, execution authority, and emergency handling must be reviewed before live execution can be considered.","evidence":"RBAC and approval review"},
            {"id":"dry-run-lifecycle-required","decision":"block","requirement":"Write-capable workflows must keep dry-run planning, approval, lock, verification, status callback, and redacted evidence gates before execution readiness.","evidence":"Dry-run gate review"},
            {"id":"browser-network-isolation-required","decision":"block","requirement":"Browser access must remain limited to portal-ui and platform-api while namespace traffic stays deny-by-default with reviewed allowances.","evidence":"Network isolation review"},
            {"id":"redaction-and-verification-required","decision":"block","requirement":"Evidence redaction and appropriate verification gates must pass before any implementation slice can be accepted.","evidence":"Verification gate review"}
        ]
    }))
}

async fn platform_portal_ia() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "architectureMode": "full-stack-leptos-ssr-hydration",
        "portalRuntime": "axum-leptos-server",
        "browserIsolationRequired": true,
        "stableNavigationRequired": true,
        "sameOriginApiRoutingRequired": true,
        "ssrRequired": true,
        "hydrationRequired": true,
        "serverFunctionBoundaryRequired": true,
        "browserProviderCallsAllowed": false,
        "externalApiCallsAllowed": false,
        "staticOnlyHostingAllowed": false,
        "roleBypassAllowed": false,
        "unsafeAdminDetailAllowed": false,
        "rawSearchRowsAllowed": false,
        "rawEvidencePayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "credentialValuesAllowed": false,
        "secretValuesAllowed": false,
        "accessTokenValuesAllowed": false,
        "rawRecipientDataAllowed": false,
        "architectureSurfaces": ["product-shell","primary-navigation","persona-defaults","dashboard-summary","catalog-offering-flow","request-lifecycle","activity-operations-queue","inventory-cmdb-evidence","operations-admin-boundary","global-search-command-palette","selector-scope-readiness","evidence-redaction-readiness"],
        "primaryNavigation": ["Dashboard","Catalog","Requests","Activity","Inventory","CMDB","Evidence","Operations","Admin"],
        "personaViews": ["system-engineer","datacenter-engineer","vmware-administrator","backup-administrator","monitoring-administrator","service-desk-operations","application-owner","security-audit"],
        "requiredInputs": ["shellSummary","navigationSummary","personaSummary","dashboardSummary","catalogSummary","requestLifecycleSummary","inventoryCmdbEvidenceSummary","operationsAdminSummary","searchPaletteSummary","scopeSelectorSummary","evidenceManifest"],
        "requiredGuards": ["product-shell-reviewed","primary-navigation-reviewed","browser-isolation-reviewed","same-origin-routing-reviewed","role-visibility-reviewed","scope-selector-reviewed","freshness-state-reviewed","evidence-redaction-reviewed","admin-boundary-reviewed"],
        "planSections": ["shellStructure","navigationModel","personaDefaults","dashboardModel","catalogRequestModel","activityInventoryCmdbEvidence","operationsAdminBoundary","searchAndCommandPalette","scopeAndFreshness","evidenceSafety"],
        "blockedReasons": ["browser-provider-calls-disabled","external-api-calls-disabled","role-bypass-disabled","unsafe-admin-detail-disabled","raw-search-rows-disabled","raw-evidence-payloads-disabled","raw-provider-payloads-disabled","credential-values-disabled","secret-values-disabled","access-token-values-disabled","raw-recipient-data-disabled","product-shell-review-missing","primary-navigation-review-missing","browser-isolation-review-missing","same-origin-routing-review-missing","role-visibility-review-missing","scope-selector-review-missing","freshness-state-review-missing","evidence-redaction-review-missing","admin-boundary-review-missing"],
        "requiredEvidence": ["Portal shell review","Navigation model review","Persona defaults review","Dashboard model review","Catalog and request model review","Activity, inventory, CMDB, and evidence review","Operations and admin boundary review","Search and command palette review","Scope and freshness review","Evidence safety review"],
        "rules": [
            {"id":"browser-isolation-required","decision":"block","requirement":"Portal information architecture keeps browser access limited to portal-ui and same-origin platform-api routes; it never introduces direct browser calls to vendors, adapters, workers, data stores, Vault, or provider services.","evidence":"Portal shell review"},
            {"id":"stable-navigation-required","decision":"block","requirement":"Dashboard, Catalog, Requests, Activity, Inventory, CMDB, Evidence, Operations, and Admin remain the stable primary navigation model across personas.","evidence":"Navigation model review"},
            {"id":"persona-and-scope-context-required","decision":"block","requirement":"Site, environment, role, data freshness, execution authority, and persona defaults must stay visible before risky workflows can be represented as ready.","evidence":"Scope and freshness review"},
            {"id":"operations-admin-boundary-required","decision":"block","requirement":"Operations workflows and Admin configuration are separated by role visibility, approval context, and evidence expectations.","evidence":"Operations and admin boundary review"},
            {"id":"raw-portal-data-not-exposed","decision":"block","requirement":"Portal IA evidence must use safe summaries only and must not expose vendor endpoints, URLs, tenant IDs, object IDs, private IPs, credential values, secret values, access tokens, raw provider payloads, raw evidence payloads, raw search rows, stack traces, recipient addresses, or implementation internals.","evidence":"Evidence safety review"}
        ]
    }))
}

async fn platform_design_system() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "designMode": "static-design-system",
        "lightModeRequired": true,
        "darkModeRequired": true,
        "accessibilityReviewRequired": true,
        "evidenceSafetyRequired": true,
        "liveThemeMutationAllowed": false,
        "externalFontFetchAllowed": false,
        "unsafeErrorDetailAllowed": false,
        "rawUiDiagnosticRowsAllowed": false,
        "rawEvidencePayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "credentialValuesAllowed": false,
        "secretValuesAllowed": false,
        "accessTokenValuesAllowed": false,
        "rawRecipientDataAllowed": false,
        "brandTokens": ["configurable-branding"],
        "designSurfaces": ["light-theme","dark-theme","accessibility-notes","branding-configuration","neutral-surfaces","status-badges","dense-tables","request-forms","error-evidence-presentation"],
        "statusFamilies": ["lifecycle","risk","health","evidence","protection","monitoring"],
        "requiredInputs": ["themeSummary","accessibilitySummary","brandingSummary","surfaceSummary","statusBadgeSummary","tableGuidanceSummary","formGuidanceSummary","errorEvidenceSummary","evidenceManifest"],
        "requiredGuards": ["light-theme-reviewed","dark-theme-reviewed","contrast-reviewed","focus-treatment-reviewed","non-color-status-reviewed","branding-reviewed","table-density-reviewed","form-safety-reviewed","evidence-presentation-reviewed"],
        "planSections": ["themeUsage","accessibilityNotes","brandingConfiguration","uiSurfaces","statusBadges","tables","forms","errorEvidencePresentation"],
        "blockedReasons": ["live-theme-mutation-disabled","external-font-fetch-disabled","unsafe-error-detail-disabled","raw-ui-diagnostic-rows-disabled","raw-evidence-payloads-disabled","raw-provider-payloads-disabled","credential-values-disabled","secret-values-disabled","access-token-values-disabled","raw-recipient-data-disabled","light-theme-review-missing","dark-theme-review-missing","contrast-review-missing","focus-treatment-review-missing","non-color-status-review-missing","branding-review-missing","table-density-review-missing","form-safety-review-missing","evidence-presentation-review-missing"],
        "requiredEvidence": ["Light theme review","Dark theme review","Accessibility review","Branding configuration review","UI surface review","Status badge review","Table guidance review","Form guidance review","Error and evidence presentation review"],
        "rules": [
            {"id":"branding-admin-configurable","decision":"block","requirement":"Branding is admin-configurable through the admin portal. Accent color and logo are set by the administrator. Neutral operational defaults are shown until configured. No specific brand colors or logo assets are committed to the repository.","evidence":"Branding configuration review"},
            {"id":"light-dark-theme-required","decision":"block","requirement":"Light and dark mode must be reviewed for text, badges, focus states, table surfaces, empty states, and error and evidence states before UI readiness is accepted.","evidence":"Dark theme review"},
            {"id":"accessibility-status-required","decision":"block","requirement":"Status presentation must use text and visible focus treatment, not color alone, and must make stale, degraded, blocked, failed, and emergency states explicit.","evidence":"Accessibility review"},
            {"id":"evidence-error-safety-required","decision":"block","requirement":"UI error and evidence presentation must show safe summaries and redaction state instead of raw implementation or provider detail.","evidence":"Error and evidence presentation review"},
            {"id":"raw-design-data-not-exposed","decision":"block","requirement":"Design system evidence must use safe summaries only and must not expose external font URLs, logo asset URLs, tenant IDs, object IDs, private IPs, credential values, secret values, access tokens, raw provider payloads, raw evidence payloads, raw UI diagnostic rows, stack traces, recipient addresses, or implementation internals.","evidence":"Error and evidence presentation review"}
        ]
    }))
}

async fn platform_ui_mockup() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "acceptanceMode": "static-ui-documentation",
        "mockupCoverageRequired": true,
        "accessibilityReviewRequired": true,
        "browserIsolationRequired": true,
        "evidenceSafetyRequired": true,
        "liveUiExecutionAllowed": false,
        "browserProviderCallsAllowed": false,
        "externalAssetFetchAllowed": false,
        "directVendorApiAllowed": false,
        "unsafeDebugDetailAllowed": false,
        "rawMockupRowsAllowed": false,
        "rawEvidencePayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "credentialValuesAllowed": false,
        "secretValuesAllowed": false,
        "accessTokenValuesAllowed": false,
        "rawRecipientDataAllowed": false,
        "mockupDocuments": ["shell-dashboard","catalog-requests","inventory-cmdb","evidence-operations-admin"],
        "mockupSurfaces": ["product-shell","dashboard","catalog","request-detail","inventory","cmdb","evidence","operations","admin","accessibility-acceptance"],
        "requiredInputs": ["shellDashboardReview","catalogRequestReview","inventoryCmdbReview","evidenceOperationsAdminReview","accessibilitySummary","browserIsolationSummary","evidenceSafetySummary","statusBehaviorSummary","themeSummary","evidenceManifest"],
        "requiredGuards": ["shell-dashboard-reviewed","catalog-requests-reviewed","inventory-cmdb-reviewed","evidence-operations-admin-reviewed","browser-isolation-reviewed","accessibility-reviewed","status-behavior-reviewed","evidence-redaction-reviewed","raw-detail-exclusion-reviewed"],
        "planSections": ["shellDashboardMockup","catalogRequestMockup","inventoryCmdbMockup","evidenceOperationsAdminMockup","accessibilityAcceptance","browserIsolationReview","statusBehaviorReview","themeBehaviorReview","evidenceSafety","rawDetailExclusion"],
        "blockedReasons": ["live-ui-execution-disabled","browser-provider-calls-disabled","external-asset-fetch-disabled","direct-vendor-api-disabled","unsafe-debug-detail-disabled","raw-mockup-rows-disabled","raw-evidence-payloads-disabled","raw-provider-payloads-disabled","credential-values-disabled","secret-values-disabled","access-token-values-disabled","raw-recipient-data-disabled","shell-dashboard-review-missing","catalog-requests-review-missing","inventory-cmdb-review-missing","evidence-operations-admin-review-missing","browser-isolation-review-missing","accessibility-review-missing","status-behavior-review-missing","evidence-redaction-review-missing","raw-detail-exclusion-review-missing"],
        "requiredEvidence": ["Shell and dashboard mockup review","Catalog and request mockup review","Inventory and CMDB mockup review","Evidence operations and admin mockup review","Accessibility acceptance review","Browser isolation review","Status behavior review","Theme behavior review","Evidence safety review","Raw detail exclusion review"],
        "rules": [
            {"id":"batch-two-mockup-coverage-required","decision":"block","requirement":"Batch 2 UI acceptance requires shell, dashboard, catalog, request, inventory, CMDB, evidence, operations, and admin mockups before implementation readiness is accepted.","evidence":"Shell and dashboard mockup review"},
            {"id":"browser-isolation-required","decision":"block","requirement":"Mockup acceptance keeps browser behavior limited to portal-ui and platform-api, with vendor and infrastructure access represented only as server-side platform summaries.","evidence":"Browser isolation review"},
            {"id":"accessibility-status-required","decision":"block","requirement":"Mockups must show keyboard focus, contrast, non-color status signals, stale states, degraded states, blocked states, and safe error states before UI readiness is accepted.","evidence":"Accessibility acceptance review"},
            {"id":"evidence-redaction-required","decision":"block","requirement":"Evidence and request mockups must show redaction state, export readiness, safe summaries, and controlled accepted or rejected counts before UI readiness is accepted.","evidence":"Evidence safety review"},
            {"id":"raw-ui-mockup-data-not-exposed","decision":"block","requirement":"UI mockup acceptance evidence must use safe summaries only and must not expose direct vendor routes, external asset locations, organization-scope identifiers, provider-side identifiers, private network details, sensitive auth material, raw provider content, raw evidence content, raw mockup rows, stack traces, recipient details, or implementation internals.","evidence":"Raw detail exclusion review"}
        ]
    }))
}

async fn platform_release_promotion() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "promotionMode": "approval-evidence-only",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveDeploymentAllowed": false,
        "registryPushAllowed": false,
        "helmUpgradeAllowed": false,
        "kubectlApplyAllowed": false,
        "clusterMutationAllowed": false,
        "credentialValuesAllowed": false,
        "rawPipelineLogsAllowed": false,
        "rawRegistryPayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "promotionStages": ["dev-render","test-render","release-candidate-review","approval-gate","prod-render","evidence-export","rollback-readiness","publish-decision"],
        "validationSignals": ["helm-lint","helm-template-render","kustomize-build-render","image-reference-policy","manifest-diff-review","rollback-plan-ready","approval-evidence-ready"],
        "requiredInputs": ["releaseScope","sourceVersionSummary","environmentStage","manifestRenderSummary","chartLintSummary","kustomizeBuildSummary","approvalRoute","rollbackPlan","owner","evidenceManifest"],
        "requiredGuards": ["release-scope-known","source-version-summarized","manifest-render-reviewed","chart-lint-reviewed","kustomize-build-reviewed","image-reference-policy-reviewed","approval-route-assigned","rollback-plan-ready","evidence-redacted"],
        "planSections": ["releaseSummary","sourceVersionSummary","manifestRender","chartLint","kustomizeBuild","manifestDiff","approvalRoute","rollbackReadiness","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","live-deployment-disabled","registry-push-disabled","helm-upgrade-disabled","kubectl-apply-disabled","cluster-mutation-disabled","credential-values-disabled","raw-pipeline-logs-disabled","raw-registry-payloads-disabled","raw-provider-payloads-disabled","release-scope-missing","manifest-render-missing","chart-lint-missing","kustomize-build-missing","approval-missing","rollback-plan-missing","evidence-not-redacted"],
        "requiredEvidence": ["Release summary","Source version summary","Helm lint summary","Helm template render summary","Kustomize build summary","Manifest diff review","Approval route","Rollback readiness","Evidence references"],
        "rules": [
            {"id":"no-live-release-deployment","decision":"block","requirement":"Platform release promotion records approval and evidence only and never deploys, upgrades, applies, or mutates clusters.","evidence":"Release summary"},
            {"id":"static-render-validation-required","decision":"block","requirement":"Helm lint, Helm template render, and Kustomize build summaries must be reviewed before promotion approval.","evidence":"Manifest diff review"},
            {"id":"no-registry-or-cluster-mutation","decision":"block","requirement":"Promotion review never pushes registry artifacts and never applies manifests to live clusters.","evidence":"Release summary"},
            {"id":"approval-and-rollback-required","decision":"block","requirement":"Approval route and rollback readiness must be present before a publish decision can be recorded.","evidence":"Rollback readiness"},
            {"id":"raw-release-data-not-exposed","decision":"block","requirement":"Release promotion evidence must use safe summaries only and must not expose registry URLs, image digests, commit SHAs, pipeline run IDs, raw release identifiers, committed image refs, cluster names, namespace names, tenant IDs, object IDs, private IPs, serial numbers, raw pipeline logs, raw registry payloads, credentials, secret values, access tokens, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn platform_database_readiness() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "readinessMode": "static-readiness", "databaseProvider": "CloudNativePG PostgreSQL",
        "providerCallsEnabled": false, "kubernetesApplyAllowed": false, "cnpgClusterCreationAllowed": false, "databaseMutationAllowed": false,
        "schemaMigrationAllowed": false, "backupExecutionAllowed": false, "restoreExecutionAllowed": false, "objectStorageAccessAllowed": false,
        "credentialValuesAllowed": false, "connectionStringsAllowed": false, "rawDatabaseRowsAllowed": false, "rawBackupPayloadsAllowed": false,
        "rawKubernetesPayloadsAllowed": false, "rawProviderPayloadsAllowed": false,
        "readinessSurfaces": ["cnpg-operator-readiness","postgres-cluster-topology","storage-class-readiness","backup-archive-readiness","restore-test-readiness","monitoring-readiness","vault-secret-reference-readiness","network-policy-readiness","failover-drain-readiness","evidence-redaction-readiness"],
        "requiredInputs": ["runtimeProfile","clusterTopologySummary","storageProfile","backupArchiveSummary","restoreTestSummary","monitoringProfile","vaultReferenceSummary","networkPolicySummary","maintenanceWindow","approvalRoute","evidenceManifest"],
        "requiredGuards": ["operator-install-reviewed","three-instance-topology-reviewed","storage-class-reviewed","wal-archive-reviewed","object-backup-reviewed","restore-test-reviewed","monitoring-reviewed","vault-reference-reviewed","network-policy-reviewed","evidence-redacted"],
        "planSections": ["readinessSummary","clusterTopology","storageReadiness","backupArchiveReadiness","restoreTestReadiness","monitoringReadiness","secretReferenceReadiness","networkPolicyReadiness","failoverMaintenanceReview","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","kubernetes-apply-disabled","cnpg-cluster-creation-disabled","database-mutation-disabled","schema-migration-disabled","backup-execution-disabled","restore-execution-disabled","object-storage-access-disabled","credential-values-disabled","connection-strings-disabled","raw-database-rows-disabled","raw-backup-payloads-disabled","raw-kubernetes-payloads-disabled","raw-provider-payloads-disabled","operator-readiness-missing","topology-review-missing","storage-review-missing","backup-archive-missing","restore-test-missing","monitoring-missing","vault-reference-missing","network-policy-missing","evidence-not-redacted"],
        "requiredEvidence": ["Database readiness summary","Cluster topology review","Storage readiness","Backup archive review","Restore test review","Monitoring readiness","Secret reference review","Network policy review","Evidence references"],
        "rules": [
            {"id":"no-live-database-or-kubernetes-actions","decision":"block","requirement":"Platform database readiness reports static readiness only and never applies Kubernetes manifests, creates CloudNativePG clusters, mutates databases, runs schema migrations, executes backups, executes restores, accesses object storage, or changes provider state.","evidence":"Database readiness summary"},
            {"id":"ha-topology-and-storage-required","decision":"block","requirement":"Three-instance topology, storage class, anti-affinity posture, and maintenance behavior must be reviewed before production database readiness can be accepted.","evidence":"Cluster topology review"},
            {"id":"backup-restore-monitoring-required","decision":"block","requirement":"WAL archive, object backup, restore test, monitoring, and evidence readiness must be reviewed before database readiness can be accepted.","evidence":"Restore test review"},
            {"id":"secret-and-network-boundary-required","decision":"block","requirement":"Vault secret references and network policy posture must be reviewed before workloads can use the database.","evidence":"Secret reference review"},
            {"id":"raw-database-data-not-exposed","decision":"block","requirement":"Database readiness evidence must use safe summaries only and must not expose database names, usernames, credential values, connection strings, endpoints, private IPs, raw database rows, raw Kubernetes payloads, raw backup payloads, object-storage payloads, tokens, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn platform_object_storage() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "readinessMode": "static-readiness", "storageProvider": "Azure Blob Storage",
        "providerCallsEnabled": false, "azureApiCallsAllowed": false, "storageAccountMutationAllowed": false, "containerMutationAllowed": false,
        "blobReadWriteAllowed": false, "lifecyclePolicyMutationAllowed": false, "immutabilityPolicyMutationAllowed": false, "publicNetworkAccessAllowed": false,
        "sharedKeyUsageAllowed": false, "sasTokenValuesAllowed": false, "credentialValuesAllowed": false, "connectionStringsAllowed": false,
        "rawBlobPayloadsAllowed": false, "rawStoragePayloadsAllowed": false, "rawProviderPayloadsAllowed": false, "storageIdentifiersAllowed": false,
        "readinessSurfaces": ["azure-blob-account-readiness","container-topology-readiness","evidence-pack-retention-readiness","export-retention-readiness","cloudnativepg-backup-target-readiness","immutability-versioning-readiness","lifecycle-management-readiness","private-network-readiness","vault-secret-reference-readiness","monitoring-diagnostic-readiness","evidence-redaction-readiness"],
        "requiredInputs": ["storageUseCaseSummary","containerRoleSummary","retentionPolicySummary","immutabilityPolicySummary","lifecyclePolicySummary","privateEndpointSummary","vaultReferenceSummary","monitoringProfile","backupTargetSummary","approvalRoute","evidenceManifest"],
        "requiredGuards": ["azure-blob-provider-reviewed","container-purpose-reviewed","retention-policy-reviewed","immutability-versioning-reviewed","lifecycle-management-reviewed","private-endpoint-reviewed","shared-key-disabled-reviewed","vault-reference-reviewed","diagnostic-logging-reviewed","evidence-redacted"],
        "planSections": ["readinessSummary","accountSecurityPosture","containerRolePlan","retentionAndLifecycleReadiness","immutabilityReadiness","privateNetworkReadiness","secretReferenceReadiness","backupTargetReadiness","monitoringReadiness","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","azure-api-calls-disabled","storage-account-mutation-disabled","container-mutation-disabled","blob-read-write-disabled","lifecycle-policy-mutation-disabled","immutability-policy-mutation-disabled","public-network-access-disabled","shared-key-usage-disabled","sas-token-values-disabled","credential-values-disabled","connection-strings-disabled","raw-blob-payloads-disabled","raw-storage-payloads-disabled","raw-provider-payloads-disabled","storage-identifiers-disabled","provider-review-missing","container-role-missing","retention-policy-missing","immutability-review-missing","lifecycle-review-missing","private-network-review-missing","vault-reference-missing","diagnostics-missing","evidence-not-redacted"],
        "requiredEvidence": ["Object storage readiness summary","Account security review","Container role review","Retention policy review","Immutability and versioning review","Lifecycle management review","Private network review","Secret reference review","Backup target review","Monitoring diagnostics review","Evidence references"],
        "rules": [
            {"id":"no-live-object-storage-actions","decision":"block","requirement":"Object storage readiness reports static readiness only and never calls Azure APIs, mutates storage accounts, mutates containers, reads or writes blobs, changes lifecycle policies, changes immutability policies, or changes provider state.","evidence":"Object storage readiness summary"},
            {"id":"container-retention-purpose-required","decision":"block","requirement":"Evidence, export, audit artifact, and CloudNativePG backup use cases must have container purpose, retention, lifecycle, and backup target readiness reviewed before acceptance.","evidence":"Retention policy review"},
            {"id":"security-and-network-boundary-required","decision":"block","requirement":"Public network access, shared key usage, managed identity posture, private endpoint posture, and Vault secret references must be reviewed before object storage readiness can be accepted.","evidence":"Account security review"},
            {"id":"immutability-lifecycle-required","decision":"block","requirement":"Versioning, immutability, protected append posture, lifecycle management, and monitoring diagnostics must be reviewed before retained evidence or backups can depend on object storage.","evidence":"Immutability and versioning review"},
            {"id":"raw-object-storage-data-not-exposed","decision":"block","requirement":"Object storage readiness evidence must use safe summaries only and must not expose storage account names, container names, blob names, URLs, endpoints, subscription IDs, resource group names, tenant IDs, object IDs, private IPs, access keys, shared keys, SAS tokens, connection strings, raw blob payloads, raw storage payloads, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn platform_registry_readiness() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "readinessMode": "static-readiness", "registryProvider": "Harbor",
        "providerCallsEnabled": false, "harborApiCallsAllowed": false, "registryPushAllowed": false, "registryPullAllowed": false,
        "projectMutationAllowed": false, "robotAccountMutationAllowed": false, "retentionPolicyMutationAllowed": false, "immutabilityRuleMutationAllowed": false,
        "scannerMutationAllowed": false, "replicationMutationAllowed": false, "webhookMutationAllowed": false, "credentialValuesAllowed": false,
        "robotSecretValuesAllowed": false, "registryUrlsAllowed": false, "imageDigestsAllowed": false, "rawRegistryPayloadsAllowed": false,
        "rawScannerPayloadsAllowed": false, "rawProviderPayloadsAllowed": false, "registryIdentifiersAllowed": false,
        "readinessSurfaces": ["harbor-system-readiness","project-topology-readiness","rbac-readiness","robot-account-readiness","retention-policy-readiness","vulnerability-scanning-readiness","tag-immutability-readiness","quota-readiness","audit-log-readiness","replication-webhook-readiness","evidence-redaction-readiness"],
        "requiredInputs": ["registryUseCaseSummary","projectTopologySummary","rbacModelSummary","robotAccountScopeSummary","retentionPolicySummary","immutabilityRuleSummary","scannerProfile","quotaSummary","auditLogSummary","replicationWebhookSummary","approvalRoute","evidenceManifest"],
        "requiredGuards": ["harbor-provider-reviewed","project-creation-reviewed","project-rbac-reviewed","robot-account-scope-reviewed","retention-policy-reviewed","vulnerability-scanner-reviewed","immutability-rule-reviewed","quota-reviewed","audit-log-reviewed","evidence-redacted"],
        "planSections": ["readinessSummary","systemSecurityPosture","projectTopology","rbacAndRobotScope","retentionAndQuotaReadiness","immutabilityReadiness","scannerReadiness","replicationWebhookReadiness","auditMonitoringReadiness","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","harbor-api-calls-disabled","registry-push-disabled","registry-pull-disabled","project-mutation-disabled","robot-account-mutation-disabled","retention-policy-mutation-disabled","immutability-rule-mutation-disabled","scanner-mutation-disabled","replication-mutation-disabled","webhook-mutation-disabled","credential-values-disabled","robot-secret-values-disabled","registry-urls-disabled","image-digests-disabled","raw-registry-payloads-disabled","raw-scanner-payloads-disabled","raw-provider-payloads-disabled","registry-identifiers-disabled","provider-review-missing","project-rbac-missing","robot-scope-missing","retention-policy-missing","scanner-review-missing","immutability-review-missing","quota-review-missing","audit-log-missing","evidence-not-redacted"],
        "requiredEvidence": ["Registry readiness summary","System security review","Project topology review","RBAC and robot scope review","Retention policy review","Immutability rule review","Scanner readiness review","Quota review","Audit log review","Evidence references"],
        "rules": [
            {"id":"no-live-registry-actions","decision":"block","requirement":"Registry readiness reports static readiness only and never calls Harbor APIs, pushes images, pulls images, mutates projects, changes robot accounts, changes retention policies, changes immutability rules, changes scanners, changes replication, changes webhooks, or changes provider state.","evidence":"Registry readiness summary"},
            {"id":"project-rbac-and-robot-scope-required","decision":"block","requirement":"Harbor project topology, project creation restriction, project RBAC, robot account scope, and quota posture must be reviewed before registry readiness can be accepted.","evidence":"RBAC and robot scope review"},
            {"id":"retention-scanning-immutability-required","decision":"block","requirement":"Tag retention, vulnerability scanning, vulnerability allowlist posture, tag immutability, and audit logging must be reviewed before platform images can depend on the registry.","evidence":"Scanner readiness review"},
            {"id":"replication-webhook-readiness-required","decision":"block","requirement":"Replication, webhook, proxy cache, and monitoring posture must be summarized before future registry automation can be accepted.","evidence":"Audit log review"},
            {"id":"raw-registry-data-not-exposed","decision":"block","requirement":"Registry readiness evidence must use safe summaries only and must not expose registry URLs, project names, repository names, image tags, image digests, robot account names, robot secrets, user names, group names, OIDC identifiers, LDAP identifiers, CVE rows, webhook URLs, replication endpoints, tenant IDs, object IDs, private IPs, credentials, tokens, raw registry payloads, raw scanner payloads, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn platform_vault_deployment() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "readinessMode": "static-readiness", "vaultProvider": "HashiCorp Vault", "deploymentTarget": "Kubernetes Helm",
        "providerCallsEnabled": false, "vaultApiCallsAllowed": false, "helmInstallAllowed": false, "helmUpgradeAllowed": false, "kubectlApplyAllowed": false,
        "vaultInitAllowed": false, "vaultUnsealAllowed": false, "vaultPolicyMutationAllowed": false, "kubernetesAuthMutationAllowed": false,
        "secretWriteAllowed": false, "injectorMutationAllowed": false, "autoUnsealMutationAllowed": false, "auditLogReadAllowed": false,
        "rawVaultPayloadsAllowed": false, "rawKubernetesPayloadsAllowed": false, "rawProviderPayloadsAllowed": false, "secretValuesAllowed": false, "vaultIdentifiersAllowed": false,
        "readinessSurfaces": ["helm-chart-readiness","ha-raft-topology-readiness","tls-readiness","persistent-storage-readiness","audit-logging-readiness","network-policy-readiness","kubernetes-auth-readiness","auto-unseal-overlay-readiness","backup-restore-readiness","workload-secret-delivery-readiness","monitoring-readiness","evidence-redaction-readiness"],
        "requiredInputs": ["helmChartSummary","valuesBaselineSummary","haRaftTopologySummary","tlsCertificateReferenceSummary","storageClassSummary","auditLoggingSummary","networkPolicySummary","kubernetesAuthSummary","autoUnsealOverlaySummary","backupRestoreSummary","workloadSecretDeliverySummary","monitoringSummary","approvalRoute","evidenceManifest"],
        "requiredGuards": ["helm-chart-reviewed","ha-raft-reviewed","tls-reviewed","audit-storage-reviewed","network-policy-reviewed","kubernetes-auth-reviewed","auto-unseal-overlay-reviewed","backup-restore-reviewed","workload-secret-delivery-reviewed","evidence-redacted"],
        "planSections": ["readinessSummary","helmChartReview","haRaftTopology","tlsAndCertificateReview","persistentStorageReview","auditLoggingReview","networkPolicyReview","kubernetesAuthReview","autoUnsealOverlayReview","backupRestoreReview","workloadSecretDeliveryReview","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","vault-api-calls-disabled","helm-install-disabled","helm-upgrade-disabled","kubectl-apply-disabled","vault-init-disabled","vault-unseal-disabled","vault-policy-mutation-disabled","kubernetes-auth-mutation-disabled","secret-write-disabled","injector-mutation-disabled","auto-unseal-mutation-disabled","audit-log-read-disabled","secret-values-disabled","raw-vault-payloads-disabled","raw-kubernetes-payloads-disabled","raw-provider-payloads-disabled","vault-identifiers-disabled","helm-chart-review-missing","ha-raft-review-missing","tls-review-missing","audit-storage-missing","network-policy-missing","kubernetes-auth-missing","auto-unseal-overlay-missing","backup-restore-missing","workload-secret-delivery-missing","evidence-not-redacted"],
        "requiredEvidence": ["Vault deployment readiness summary","Helm chart review","HA Raft topology review","TLS and certificate reference review","Persistent storage review","Audit logging review","Network policy review","Kubernetes auth review","Auto-unseal overlay review","Backup and restore review","Workload secret delivery review","Evidence references"],
        "rules": [
            {"id":"no-live-vault-or-cluster-actions","decision":"block","requirement":"Vault deployment readiness reports static readiness only and never calls Vault APIs, installs or upgrades Helm releases, applies Kubernetes manifests, initializes or unseals Vault, mutates policies, mutates Kubernetes auth, writes secrets, changes injectors, changes auto-unseal, reads audit logs, or changes provider state.","evidence":"Vault deployment readiness summary"},
            {"id":"ha-raft-tls-audit-required","decision":"block","requirement":"Official Helm chart review, three-replica HA Raft topology, TLS posture, persistent storage, audit storage, PodDisruptionBudget, and anti-affinity posture must be reviewed before Vault deployment readiness can be accepted.","evidence":"HA Raft topology review"},
            {"id":"kubernetes-auth-and-workload-delivery-required","decision":"block","requirement":"Kubernetes auth, workload secret delivery, injector boundary, service account posture, and secret-reference behavior must be reviewed before workloads can depend on Vault.","evidence":"Kubernetes auth review"},
            {"id":"auto-unseal-backup-restore-required","decision":"block","requirement":"Production auto-unseal overlay, backup and restore runbooks, monitoring posture, and bootstrap evidence boundaries must be reviewed before production Vault readiness can be accepted.","evidence":"Backup and restore review"},
            {"id":"raw-vault-data-not-exposed","decision":"block","requirement":"Vault deployment readiness evidence must use safe summaries only and must not expose Vault URLs, namespaces, mount paths, secret paths, policy names, role names, service account token data, TLS material, root tokens, recovery keys, unseal keys, audit log lines, storage class names, tenant IDs, object IDs, private IPs, credentials, tokens, raw Vault payloads, raw Kubernetes payloads, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn platform_vault_secret_delivery() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "readinessMode": "static-readiness", "deliveryProvider": "Vault Secrets Operator",
        "providerCallsEnabled": false, "vaultApiCallsAllowed": false, "kubernetesApplyAllowed": false, "helmInstallAllowed": false, "helmUpgradeAllowed": false,
        "crdApplyAllowed": false, "vaultConnectionMutationAllowed": false, "vaultAuthMutationAllowed": false, "vaultStaticSecretMutationAllowed": false,
        "kubernetesSecretMutationAllowed": false, "secretDataReadAllowed": false, "secretDataWriteAllowed": false, "rolloutRestartAllowed": false,
        "transformationTemplateAllowed": false, "rawVaultPayloadsAllowed": false, "rawKubernetesPayloadsAllowed": false, "rawProviderPayloadsAllowed": false,
        "secretValuesAllowed": false, "vaultIdentifiersAllowed": false,
        "deliverySurfaces": ["vault-secrets-operator-readiness","vaultconnection-readiness","vaultauth-readiness","vaultstaticsecret-readiness","destination-secret-readiness","refresh-drift-readiness","transformation-readiness","rollout-restart-readiness","namespace-scope-readiness","monitoring-readiness","evidence-redaction-readiness"],
        "requiredInputs": ["operatorChartSummary","vaultConnectionSummary","vaultAuthSummary","namespaceScopeSummary","staticSecretSummary","destinationSecretSummary","refreshPolicySummary","hmacDriftSummary","transformationSummary","rolloutRestartSummary","monitoringSummary","approvalRoute","evidenceManifest"],
        "requiredGuards": ["operator-chart-reviewed","vault-connection-reviewed","vault-auth-reviewed","namespace-scope-reviewed","destination-secret-reviewed","hmac-drift-reviewed","transformation-reviewed","rollout-restart-reviewed","rotation-refresh-reviewed","evidence-redacted"],
        "planSections": ["deliverySummary","operatorChartReview","connectionBoundary","authBoundary","staticSecretPlan","destinationSecretPlan","refreshAndDriftReview","transformationReview","rolloutRestartReview","namespaceScopeReview","monitoringReview","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","vault-api-calls-disabled","kubernetes-apply-disabled","helm-install-disabled","helm-upgrade-disabled","crd-apply-disabled","vaultconnection-mutation-disabled","vaultauth-mutation-disabled","vaultstaticsecret-mutation-disabled","kubernetes-secret-mutation-disabled","secret-data-read-disabled","secret-data-write-disabled","rollout-restart-disabled","transformation-template-disabled","raw-vault-payloads-disabled","raw-kubernetes-payloads-disabled","raw-provider-payloads-disabled","secret-values-disabled","vault-identifiers-disabled","operator-chart-review-missing","vault-connection-review-missing","vault-auth-review-missing","namespace-scope-missing","destination-secret-review-missing","hmac-drift-review-missing","transformation-review-missing","rollout-restart-review-missing","rotation-refresh-review-missing","evidence-not-redacted"],
        "requiredEvidence": ["Vault secret delivery summary","Operator chart review","VaultConnection review","VaultAuth review","Namespace scope review","VaultStaticSecret review","Destination secret review","Refresh and HMAC drift review","Transformation review","Rollout restart review","Monitoring review","Evidence references"],
        "rules": [
            {"id":"no-live-vault-secret-delivery","decision":"block","requirement":"Vault secret delivery readiness reports static readiness only and never calls Vault APIs, applies Kubernetes resources, installs or upgrades Helm releases, applies CRDs, mutates VaultConnection, mutates VaultAuth, mutates VaultStaticSecret, mutates Kubernetes Secrets, reads or writes secret data, restarts workloads, changes transformations, or changes provider state.","evidence":"Vault secret delivery summary"},
            {"id":"operator-connection-auth-required","decision":"block","requirement":"Vault Secrets Operator chart posture, VaultConnection boundary, VaultAuth boundary, namespace scope, and workload auth identity posture must be reviewed before delivery readiness can be accepted.","evidence":"VaultAuth review"},
            {"id":"destination-refresh-drift-required","decision":"block","requirement":"VaultStaticSecret plan, destination behavior, refresh interval, HMAC drift detection, transformation posture, and rotation handling must be reviewed before workloads can depend on synchronized material.","evidence":"Refresh and HMAC drift review"},
            {"id":"rollout-monitoring-required","decision":"block","requirement":"Rollout restart targets, monitoring posture, stale delivery handling, and fail-closed behavior must be reviewed before delivery readiness can be accepted.","evidence":"Rollout restart review"},
            {"id":"raw-vault-secret-data-not-exposed","decision":"block","requirement":"Vault secret delivery evidence must use safe summaries only and must not expose Vault URLs, namespaces, mount paths, secret paths, auth roles, Kubernetes target names, token data, secret data, secret keys, destination names, template text, rollout target names, tenant IDs, object IDs, private IPs, credentials, tokens, raw Vault payloads, raw Kubernetes Secret payloads, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn platform_k8s_runtime() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "readinessMode": "static-readiness", "runtimeProvider": "Kubernetes", "deploymentTarget": "portable-base-manifests",
        "providerCallsEnabled": false, "kubectlApplyAllowed": false, "helmInstallAllowed": false, "helmUpgradeAllowed": false, "kustomizeBuildAllowed": false,
        "clusterMutationAllowed": false, "namespaceMutationAllowed": false, "deploymentMutationAllowed": false, "serviceMutationAllowed": false,
        "ingressMutationAllowed": false, "networkPolicyMutationAllowed": false, "serviceAccountMutationAllowed": false, "sensitiveResourceMutationAllowed": false,
        "imagePullAllowed": false, "registryAccessAllowed": false, "rawKubernetesPayloadsAllowed": false, "rawProviderPayloadsAllowed": false,
        "kubeconfigValuesAllowed": false, "clusterIdentifiersAllowed": false, "sensitiveValuesAllowed": false,
        "readinessSurfaces": ["namespace-readiness","deployment-readiness","service-readiness","ingress-readiness","ingress-front-tier-readiness","network-policy-readiness","serviceaccount-readiness","image-reference-readiness","runtime-reference-readiness","runtime-security-readiness","observability-readiness","evidence-redaction-readiness"],
        "ingressFrontTierProfiles": ["haproxy-vip-front-tier","nginx-ingress-controller","same-origin-api-route"],
        "ingressRoutePostures": ["placeholder-dns-only","tls-posture-reviewed","health-check-summary-required","failover-owner-reviewed","approval-route-reviewed"],
        "requiredInputs": ["runtimeScopeSummary","namespaceSummary","componentTopologySummary","serviceRoutingSummary","frontTierSummary","controllerClassSummary","ingressRouteSummary","sameOriginRouteSummary","certificatePostureSummary","healthCheckPostureSummary","failoverOwnershipSummary","networkPolicySummary","serviceAccountSummary","imageReferenceSummary","runtimeReferenceSummary","runtimeSecuritySummary","observabilitySummary","approvalRoute","evidenceManifest"],
        "requiredGuards": ["namespace-reviewed","deployment-topology-reviewed","service-routing-reviewed","front-tier-reviewed","controller-class-reviewed","ingress-routing-reviewed","same-origin-route-reviewed","certificate-posture-reviewed","health-check-reviewed","failover-owner-reviewed","default-deny-reviewed","egress-allowlist-reviewed","service-account-reviewed","image-reference-reviewed","runtime-reference-reviewed","runtime-security-reviewed","observability-reviewed","evidence-redacted"],
        "planSections": ["runtimeSummary","namespaceReview","componentTopology","serviceRouting","ingressFrontTier","ingressRouting","sameOriginRouting","healthCheckFailover","networkPolicyReview","serviceAccountReview","imageReferenceReview","runtimeReferenceReview","runtimeSecurityReview","observabilityReview","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","kubectl-apply-disabled","helm-install-disabled","helm-upgrade-disabled","kustomize-build-disabled","cluster-mutation-disabled","namespace-mutation-disabled","deployment-mutation-disabled","service-mutation-disabled","ingress-mutation-disabled","network-policy-mutation-disabled","service-account-mutation-disabled","sensitive-resource-mutation-disabled","image-pull-disabled","registry-access-disabled","raw-kubernetes-payloads-disabled","raw-provider-payloads-disabled","kubeconfig-values-disabled","cluster-identifiers-disabled","sensitive-values-disabled","namespace-review-missing","deployment-topology-missing","service-routing-missing","front-tier-review-missing","controller-class-review-missing","ingress-routing-missing","same-origin-route-missing","certificate-posture-missing","health-check-posture-missing","failover-owner-missing","default-deny-missing","egress-allowlist-missing","service-account-review-missing","image-reference-review-missing","runtime-reference-review-missing","runtime-security-missing","observability-missing","evidence-not-redacted"],
        "requiredEvidence": ["Kubernetes runtime readiness summary","Namespace review","Deployment topology review","Service routing review","Ingress front tier review","Ingress routing review","Same-origin route review","Health check and failover review","Network policy review","Service account review","Image reference review","Runtime reference review","Runtime security review","Observability review","Evidence references"],
        "rules": [
            {"id":"no-live-kubernetes-runtime-actions","decision":"block","requirement":"Kubernetes runtime readiness reports static readiness only and never calls providers, applies manifests, installs or upgrades Helm releases, builds overlays, mutates namespaces, mutates workloads, mutates Services, mutates Ingress, mutates NetworkPolicies, mutates ServiceAccounts, creates sensitive resources, pulls images, accesses registries, or changes provider state.","evidence":"Kubernetes runtime readiness summary"},
            {"id":"namespace-and-workload-topology-required","decision":"block","requirement":"Namespace scope, component topology, Deployment selector posture, Service selector posture, placeholder image posture, and workload exposure boundaries must be reviewed before runtime readiness can be accepted.","evidence":"Deployment topology review"},
            {"id":"ingress-and-network-policy-required","decision":"block","requirement":"Same-origin Ingress routing, TLS placeholder posture, default deny posture, explicit ingress allowances, explicit egress allowances, and DNS allowance must be reviewed before runtime readiness can be accepted.","evidence":"Network policy review"},
            {"id":"haproxy-nginx-ingress-model-required","decision":"block","requirement":"HAProxy VIP front tier posture, NGINX ingress controller class, same-origin API route, certificate posture, health checks, failover ownership, approval route, and redacted evidence must be reviewed as safe summaries before ingress readiness can pass.","evidence":"Ingress front tier review"},
            {"id":"identity-image-runtime-reference-required","decision":"block","requirement":"ServiceAccount posture, identity automount posture, image reference posture, registry access boundary, and external runtime reference posture must be reviewed before workloads can depend on the runtime skeleton.","evidence":"Service account review"},
            {"id":"raw-kubernetes-data-not-exposed","decision":"block","requirement":"Kubernetes runtime readiness evidence must use safe summaries only and must not expose kubeconfigs, cluster identifiers, context identifiers, namespace identifiers, ingress identifiers, TLS material identifiers, workload identity identifiers, identity material, pod identifiers, image pull material, registry material, organization-scope identifiers, provider-side identifiers, private network details, sensitive auth material, raw Kubernetes payloads, or provider-returned content.","evidence":"Evidence references"}
        ]
    }))
}

async fn platform_local_container() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "readinessMode": "static-readiness", "runtimeProvider": "Docker Compose", "deploymentTarget": "local-compose-skeleton",
        "providerCallsEnabled": false, "dockerComposeUpAllowed": false, "dockerComposeBuildAllowed": false, "dockerRunAllowed": false, "imagePushAllowed": false,
        "registryAccessAllowed": false, "serviceMutationAllowed": false, "networkMutationAllowed": false, "portBindingMutationAllowed": false,
        "environmentValuesAllowed": false, "envFileAllowed": false, "volumeMountsAllowed": false, "providerServiceAllowed": false, "externalEgressAllowed": false,
        "rawRuntimePayloadsAllowed": false, "providerReturnedContentAllowed": false, "sensitiveAuthValuesAllowed": false, "runtimeIdentifiersAllowed": false,
        "readinessSurfaces": ["compose-file-readiness","service-topology-readiness","build-context-readiness","local-port-readiness","network-boundary-readiness","dependency-readiness","portal-runtime-boundary-readiness","excluded-runtime-readiness","evidence-redaction-readiness"],
        "requiredInputs": ["composeSummary","serviceTopologySummary","buildContextSummary","localPortSummary","networkBoundarySummary","dependencySummary","portalRuntimeSummary","excludedRuntimeSummary","approvalRoute","evidenceManifest"],
        "requiredGuards": ["compose-file-reviewed","service-topology-reviewed","build-context-reviewed","local-port-reviewed","network-boundary-reviewed","dependency-reviewed","portal-runtime-boundary-reviewed","excluded-runtime-reviewed","evidence-redacted"],
        "planSections": ["localRuntimeSummary","composeFileReview","serviceTopology","buildContextReview","localPortReview","networkBoundaryReview","dependencyReview","portalRuntimeBoundaryReview","excludedRuntimeReview","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","docker-compose-up-disabled","docker-compose-build-disabled","docker-run-disabled","image-push-disabled","registry-access-disabled","service-mutation-disabled","network-mutation-disabled","port-binding-mutation-disabled","environment-values-disabled","env-file-disabled","volume-mounts-disabled","provider-service-disabled","external-egress-disabled","raw-runtime-payloads-disabled","provider-returned-content-disabled","sensitive-auth-values-disabled","runtime-identifiers-disabled","compose-file-review-missing","service-topology-missing","build-context-review-missing","local-port-review-missing","network-boundary-review-missing","dependency-review-missing","portal-runtime-boundary-review-missing","excluded-runtime-review-missing","evidence-not-redacted"],
        "requiredEvidence": ["Local container readiness summary","Compose file review","Service topology review","Build context review","Local port review","Network boundary review","Dependency review","Portal runtime boundary review","Excluded runtime review","Evidence references"],
        "rules": [
            {"id":"no-live-local-container-actions","decision":"block","requirement":"Local container readiness reports static readiness only and never calls providers, runs compose up, builds images, runs containers, pushes images, accesses registries, mutates services, mutates networks, changes local port bindings, enables environment value material, mounts volumes, creates provider-backed services, enables external egress, or changes runtime state.","evidence":"Local container readiness summary"},
            {"id":"two-service-local-topology-required","decision":"block","requirement":"Local compose posture must keep the browser-facing portal and server-side API as the only active services until worker, adapter, database, and Vault bootstrap slices are approved.","evidence":"Service topology review"},
            {"id":"local-routing-and-network-required","decision":"block","requirement":"Local port bindings, full-stack portal runtime boundary, service dependency order, and bridge-network boundary must be reviewed before local runtime readiness can be accepted.","evidence":"Network boundary review"},
            {"id":"runtime-expansion-excluded","decision":"block","requirement":"Database, Vault, provider adapters, worker execution, provider-backed resources, environment value material, local volume mounts, registry access, and external egress must stay excluded from the local skeleton until separately approved.","evidence":"Excluded runtime review"},
            {"id":"raw-local-runtime-data-not-exposed","decision":"block","requirement":"Local container readiness evidence must use safe summaries only and must not expose runtime endpoints, private network details, environment value material, registry material, organization-scope identifiers, provider-side identifiers, sensitive auth material, raw runtime payloads, or provider-returned content.","evidence":"Evidence references"}
        ]
    }))
}

async fn catalog_categories() -> Json<Value> {
    Json(categories())
}

async fn catalog_offerings() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "catalogMode": "planned-offerings", "catalogReadOnly": true, "providerCallsAllowed": false, "workflowMutationAllowed": false,
        "liveRequestCreationAllowed": false, "liveApprovalExecutionAllowed": false, "liveExecutionAllowed": false, "rawRequestPayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false, "rawLogContentAllowed": false, "rawRowsAllowed": false, "rawRecipientDataAllowed": false,
        "credentialValuesAllowed": false, "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "privateNetworkValuesAllowed": false,
        "categories": categories(),
        "offerings": [
            {"id":"windows-server-deployment","title":"Windows server deployment","category":"Build","priority":"P0","persona":["Requester","System engineer","VMware administrator","Hyper-V administrator","Proxmox administrator","Backup administrator","Monitoring administrator","Application owner"],"requiredInputs":["businessPurpose","requester","owner","site","environment","criticality","imageVersion","vmSizing","network","backupPolicy","monitoringProfile","cmdbContext"],"approvals":["Datacenter Approver","Application owner","Wintel/Linux Operator"],"dryRunRequired":true,"evidence":["Request payload summary","Validation result","Provider-safe plan","Approval decisions","Lock record","Redacted execution log","Before/after inventory","Policy assignments","CMDB export package"],"integrationData":["vCenter","Hyper-V","Proxmox","Customization specs","gMSA worker","Veeam","Zabbix","ServiceNow CMDB export","Site catalog","Policy catalog"],"status":"planned"},
            {"id":"linux-server-deployment","title":"Linux server deployment","category":"Build","priority":"P0","persona":["Requester","System engineer","VMware administrator","Hyper-V administrator","Proxmox administrator","Backup administrator","Monitoring administrator","Application owner"],"requiredInputs":["businessPurpose","requester","owner","site","environment","criticality","distribution","imageVersion","vmSizing","network","backupPolicy","monitoringProfile","cmdbContext"],"approvals":["Datacenter Approver","Application owner","Wintel/Linux Operator"],"dryRunRequired":true,"evidence":["Request payload summary","Validation result","Provider-safe plan","Approval decisions","Lock record","Redacted execution log","Before/after inventory","Policy assignments","CMDB export package"],"integrationData":["vCenter","Hyper-V","Proxmox","Ansible","Veeam","Zabbix","ServiceNow CMDB export","Site catalog","Policy catalog"],"status":"planned"},
            {"id":"request-preflight","title":"Request preflight and readiness gate","category":"Build","priority":"P0","persona":["Requester","System engineer","Datacenter engineer","VMware administrator","Hyper-V administrator","Proxmox administrator","Backup administrator","Monitoring administrator","Application owner"],"requiredInputs":["requestedOffering","requester","owner","site","environment","criticality","capacityScope","network","backupPolicy","monitoringProfile","cmdbContext"],"approvals":["Datacenter Approver"],"dryRunRequired":true,"evidence":["Request payload summary","Validation result","Failed rules","Remediation hints","Plan summary","Policy decision record"],"integrationData":["vCenter","Hyper-V","Proxmox","ServiceNow CMDB export","Zabbix","Veeam","AD OU map","Site catalog","Policy catalog"],"status":"planned"},
            {"id":"patch-wave-planning","title":"Patch wave planning","category":"Maintain","priority":"P0","persona":["System engineer","Service desk and operations","Application owner","Security and audit"],"requiredInputs":["patchCycle","siteScope","applicationScope","environmentScope","criticality","dependencyContext","maintenanceWindow","rebootPolicy","blackoutDates"],"approvals":["Datacenter Approver","Application owner","Wintel/Linux Operator"],"dryRunRequired":true,"evidence":["Request payload summary","Validation result","Wave plan summary","Risk notes","Approval decisions","Handover notes","Compliance state"],"integrationData":["ServiceNow patch policy export","CMDB graph","vCenter","Hyper-V","Proxmox","Zabbix maintenance","Veeam backup state","Policy catalog"],"status":"planned"},
            {"id":"controlled-restore-request","title":"Controlled restore request","category":"Protect","priority":"P0","persona":["Requester","Backup administrator","Application owner","Security and audit"],"requiredInputs":["businessPurpose","requester","restoreType","sourceResource","restorePoint","targetSelection","owner","site","environment","verificationPlan","retentionNeed"],"approvals":["Datacenter Approver","Backup Operator","Application owner"],"dryRunRequired":true,"evidence":["Request payload summary","Validation result","Restore plan summary","Approval decisions","Lock record","Redacted execution log","Verification result","Evidence references"],"integrationData":["Veeam","ServiceNow ticket context","Target VM or network","Application owner catalog","Evidence service"],"status":"planned"},
            {"id":"zabbix-onboarding","title":"Zabbix onboarding","category":"Observe","priority":"P0","persona":["System engineer","Monitoring administrator","Application owner","Service desk and operations"],"requiredInputs":["requester","hostIdentity","owner","site","environment","hostGroup","templateProfile","proxyOrServer","alertGroup","maintenanceWindow"],"approvals":["Datacenter Approver","Monitoring Operator","Application owner"],"dryRunRequired":true,"evidence":["Request payload summary","Validation result","Onboarding plan summary","Approval decisions","Redacted execution log","Before/after monitoring state","Zabbix reference"],"integrationData":["Zabbix","vCenter","Hyper-V","Proxmox","Site catalog","CMDB export","ServiceNow ticket context","Policy catalog"],"status":"planned"},
            {"id":"cmdb-import","title":"CMDB Excel import","category":"Operate","priority":"P0","persona":["Service desk and operations","Application owner","Security and audit","System engineer"],"requiredInputs":["requester","sourceFileReference","headerMapping","importScope","reviewer","validationMode"],"approvals":["Datacenter Approver","Auditor"],"dryRunRequired":true,"evidence":["File hash","Header mapping","Validation result","Accepted row count","Rejected rows","Import user","Evidence references"],"integrationData":["ServiceNow CMDB Excel export","Portal import mapper","Policy engine","CMDB mapping"],"status":"planned"},
            {"id":"cmdb-update-export","title":"CMDB update export","category":"Operate","priority":"P0","persona":["Service desk and operations","System engineer","Application owner","Security and audit"],"requiredInputs":["requester","exportScope","changeReason","owner","reviewer","targetFormat","evidenceReferences"],"approvals":["Datacenter Approver","Application owner","Auditor"],"dryRunRequired":true,"evidence":["Request payload summary","Validation result","Export package","Accepted/rejected rows","Reviewer approval","Evidence references"],"integrationData":["Portal inventory","Operation evidence","CMDB mapping","Owner catalog","ServiceNow CMDB export"],"status":"planned"},
            {"id":"operator-runbook-launch","title":"Operator runbook launcher","category":"Operate","priority":"P0","persona":["Service desk and operations","System engineer","Backup administrator","Monitoring administrator","Security and audit"],"requiredInputs":["requester","runbookId","targetResource","ticketContext","operationScope","riskLevel","rollbackNotes"],"approvals":["Datacenter Approver","Service Desk"],"dryRunRequired":true,"evidence":["Request payload summary","Validation result","Runbook plan summary","Approval decisions","Lock record","Redacted execution log","Child operation results","Handover notes"],"integrationData":["Runbook catalog","RBAC","ServiceNow ticket context","Workers","Evidence service"],"status":"planned"},
            {"id":"platform-health-dashboard","title":"Platform health dashboard","category":"Operate","priority":"P0","persona":["Service desk and operations","Platform Admin","System engineer","Monitoring administrator","Security and audit"],"requiredInputs":["viewerContext","siteScope","componentScope","freshnessWindow"],"approvals":["Platform Admin"],"dryRunRequired":false,"evidence":["Health snapshot","Stale-data markers","Dependency status","Alert references","Dashboard timestamp"],"integrationData":["Kubernetes or VKS","CloudNativePG PostgreSQL","Queue or outbox","Zabbix","Logs","Metrics","Traces"],"status":"planned"},
            {"id":"vm-decommission-quarantine","title":"VM decommission quarantine","category":"Retire","priority":"P1","persona":["VMware administrator","Hyper-V administrator","Proxmox administrator","System engineer","Backup administrator","Monitoring administrator","Application owner","Security and audit"],"requiredInputs":["requester","targetResource","owner","site","environment","businessJustification","dependencyReview","backupRetentionNeed","quarantineWindow","cmdbContext"],"approvals":["Datacenter Approver","Application owner","Backup Operator"],"dryRunRequired":true,"evidence":["Request payload summary","Dependency review","Backup retention proof","Approval decisions","Quarantine plan","Redacted execution log","Monitoring disablement proof","CMDB closure export","Final evidence references"],"integrationData":["vCenter","Hyper-V","Proxmox","Veeam","Zabbix","ServiceNow CMDB export","DNS or IPAM workflow","Evidence service","Policy catalog"],"status":"planned"},
            {"id":"application-environment-retirement","title":"Application environment retirement","category":"Retire","priority":"P1","persona":["Application owner","System engineer","VMware administrator","Hyper-V administrator","Proxmox administrator","Backup administrator","Monitoring administrator","Security and audit"],"requiredInputs":["requester","application","environment","owner","serviceCriticality","dependencyGraph","dataRetentionNeed","backupRetentionNeed","accessClosureScope","cmdbContext"],"approvals":["Datacenter Approver","Application owner","Auditor"],"dryRunRequired":true,"evidence":["Request payload summary","Relationship review","Data retention decision","Approval decisions","Retirement plan","Redacted execution log","Backup retention proof","CMDB relationship closure export","Final evidence references"],"integrationData":["CMDB graph","vCenter","Hyper-V","Proxmox","Veeam","Zabbix","ServiceNow CMDB export","Evidence service","Policy catalog"],"status":"planned"}
        ]
    }))
}

async fn catalog_recommendations() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "recommendationMode": "static-offering-recommendations", "recommendationsReadOnly": true, "roleDefaultsReadOnly": true,
        "siteDefaultsReadOnly": true, "evidenceReferencesReadOnly": true, "livePersonalizationAllowed": false, "liveCatalogQueryAllowed": false,
        "liveRequestCreationAllowed": false, "workflowMutationAllowed": false, "providerCallsAllowed": false, "identityLookupAllowed": false,
        "rawUserDataAllowed": false, "rawApplicationDataAllowed": false, "rawSiteDataAllowed": false, "rawRequestPayloadsAllowed": false,
        "rawProviderPayloadsAllowed": false, "rawRecipientDataAllowed": false, "credentialValuesAllowed": false, "tokenValuesAllowed": false,
        "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "principalIdentifiersAllowed": false, "privateNetworkValuesAllowed": false,
        "recommendedOfferingIds": ["windows-server-deployment","request-preflight","patch-wave-planning","controlled-restore-request","zabbix-onboarding","cmdb-import","operator-runbook-launch","platform-health-dashboard"],
        "recommendationDimensions": ["role","application-profile","site","lifecycle-category","risk-context","freshness-state"],
        "recommendationSignals": ["role-fit","site-readiness","service-lifecycle-fit","dry-run-required","approval-route-known","evidence-profile-known"],
        "recommendationViews": ["role-defaults","application-profile-defaults","site-defaults","lifecycle-category-defaults","safe-next-offerings"],
        "requiredGuards": ["catalog-source-reviewed","role-scope-summarized","application-profile-summarized","site-scope-summarized","approval-route-known","dry-run-required","evidence-redacted","live-personalization-blocked"],
        "blockedReasons": ["catalog-recommendation-live-personalization-disabled","catalog-live-query-disabled","request-creation-disabled","workflow-mutation-disabled","provider-calls-disabled","identity-lookup-disabled","raw-user-data-disabled","raw-application-data-disabled","raw-site-data-disabled","raw-request-payloads-disabled","raw-provider-payloads-disabled","raw-recipient-data-disabled","credential-values-disabled","token-values-disabled","tenant-identifiers-disabled","object-identifiers-disabled","principal-identifiers-disabled","private-network-values-disabled","role-scope-missing","application-profile-missing","site-scope-missing","recommendation-signal-missing","evidence-not-redacted"],
        "requiredEvidence": ["Recommendation summary","Role fit summary","Application profile summary","Site fit summary","Evidence references"],
        "rules": [
            {"id":"recommendations-read-only","decision":"block","requirement":"Offering recommendations are static summaries and must not perform live personalization, query live catalogs, create requests, call providers, or mutate workflows.","evidence":"Recommendation summary"},
            {"id":"catalog-source-alignment-required","decision":"block","requirement":"Recommended offering IDs must stay aligned to the static offering catalog and preserve dry-run, approval, and evidence expectations.","evidence":"Recommendation summary"},
            {"id":"role-app-site-summary-required","decision":"block","requirement":"Role, application profile, site, lifecycle category, risk context, freshness state, approval route, and evidence profile must be safe summaries before recommendations are shown.","evidence":"Role fit summary"},
            {"id":"raw-recommendation-data-not-exposed","decision":"block","requirement":"Offering recommendation evidence must not expose raw user data, raw application data, raw site data, raw request payloads, raw provider payloads, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.","evidence":"Evidence references"}
        ]
    }))
}

async fn catalog_request_form() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "formMode": "static-request-form-schema", "formSchemaReadOnly": true, "schemaDerivedFromOfferings": true,
        "liveRequestCreationAllowed": false, "formSubmissionAllowed": false, "approvalExecutionAllowed": false, "workflowMutationAllowed": false,
        "providerCallsAllowed": false, "rawRequestPayloadsAllowed": false, "rawFormSubmissionsAllowed": false, "rawProviderPayloadsAllowed": false,
        "rawLogContentAllowed": false, "rawRowsAllowed": false, "rawRecipientDataAllowed": false, "credentialValuesAllowed": false,
        "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "privateNetworkValuesAllowed": false,
        "formSections": ["requester-context","scope-context","business-context","technical-plan","protection-observe-cmdb","evidence-approval"],
        "inputKinds": ["text","textarea","select","multi-select","reference-summary","policy-reference","schedule-summary","evidence-reference"],
        "requiredInputNames": ["accessClosureScope","alertGroup","application","applicationScope","backupPolicy","backupRetentionNeed","blackoutDates","businessJustification","businessPurpose","capacityScope","changeReason","cmdbContext","componentScope","criticality","dataRetentionNeed","dependencyContext","dependencyGraph","dependencyReview","distribution","environment","environmentScope","evidenceReferences","exportScope","freshnessWindow","headerMapping","hostGroup","hostIdentity","imageVersion","importScope","maintenanceWindow","monitoringProfile","network","operationScope","owner","patchCycle","proxyOrServer","quarantineWindow","rebootPolicy","requestedOffering","requester","restorePoint","restoreType","retentionNeed","reviewer","riskLevel","rollbackNotes","runbookId","serviceCriticality","site","siteScope","sourceFileReference","sourceResource","targetFormat","targetResource","targetSelection","templateProfile","ticketContext","validationMode","verificationPlan","viewerContext","vmSizing"],
        "offeringForms": [
            {"offeringId":"windows-server-deployment","title":"Windows server deployment","category":"Build","requiredInputNames":["businessPurpose","requester","owner","site","environment","criticality","imageVersion","vmSizing","network","backupPolicy","monitoringProfile","cmdbContext"],"dryRunRequired":true},
            {"offeringId":"linux-server-deployment","title":"Linux server deployment","category":"Build","requiredInputNames":["businessPurpose","requester","owner","site","environment","criticality","distribution","imageVersion","vmSizing","network","backupPolicy","monitoringProfile","cmdbContext"],"dryRunRequired":true},
            {"offeringId":"request-preflight","title":"Request preflight and readiness gate","category":"Build","requiredInputNames":["requestedOffering","requester","owner","site","environment","criticality","capacityScope","network","backupPolicy","monitoringProfile","cmdbContext"],"dryRunRequired":true},
            {"offeringId":"patch-wave-planning","title":"Patch wave planning","category":"Maintain","requiredInputNames":["patchCycle","siteScope","applicationScope","environmentScope","criticality","dependencyContext","maintenanceWindow","rebootPolicy","blackoutDates"],"dryRunRequired":true},
            {"offeringId":"controlled-restore-request","title":"Controlled restore request","category":"Protect","requiredInputNames":["businessPurpose","requester","restoreType","sourceResource","restorePoint","targetSelection","owner","site","environment","verificationPlan","retentionNeed"],"dryRunRequired":true},
            {"offeringId":"zabbix-onboarding","title":"Zabbix onboarding","category":"Observe","requiredInputNames":["requester","hostIdentity","owner","site","environment","hostGroup","templateProfile","proxyOrServer","alertGroup","maintenanceWindow"],"dryRunRequired":true},
            {"offeringId":"cmdb-import","title":"CMDB Excel import","category":"Operate","requiredInputNames":["requester","sourceFileReference","headerMapping","importScope","reviewer","validationMode"],"dryRunRequired":true},
            {"offeringId":"cmdb-update-export","title":"CMDB update export","category":"Operate","requiredInputNames":["requester","exportScope","changeReason","owner","reviewer","targetFormat","evidenceReferences"],"dryRunRequired":true},
            {"offeringId":"operator-runbook-launch","title":"Operator runbook launcher","category":"Operate","requiredInputNames":["requester","runbookId","targetResource","ticketContext","operationScope","riskLevel","rollbackNotes"],"dryRunRequired":true},
            {"offeringId":"platform-health-dashboard","title":"Platform health dashboard","category":"Operate","requiredInputNames":["viewerContext","siteScope","componentScope","freshnessWindow"],"dryRunRequired":false},
            {"offeringId":"vm-decommission-quarantine","title":"VM decommission quarantine","category":"Retire","requiredInputNames":["requester","targetResource","owner","site","environment","businessJustification","dependencyReview","backupRetentionNeed","quarantineWindow","cmdbContext"],"dryRunRequired":true},
            {"offeringId":"application-environment-retirement","title":"Application environment retirement","category":"Retire","requiredInputNames":["requester","application","environment","owner","serviceCriticality","dependencyGraph","dataRetentionNeed","backupRetentionNeed","accessClosureScope","cmdbContext"],"dryRunRequired":true}
        ],
        "rules": [
            {"id":"offering-required-inputs-covered","decision":"block","requirement":"Request form schema readiness requires every catalog offering required input to be represented by the static form contract.","evidence":"Form schema review"},
            {"id":"form-schema-read-only","decision":"block","requirement":"The request form contract is read-only metadata and cannot persist drafts, submit requests, mutate approvals, or start workflows.","evidence":"Static schema boundary"},
            {"id":"dry-run-first-preserved","decision":"block","requirement":"Write-capable request forms must preserve dry-run-first workflow expectations before approval or execution readiness is represented.","evidence":"Dry-run policy review"},
            {"id":"raw-form-data-not-exposed","decision":"block","requirement":"Request form schema evidence must use safe summaries only and must not expose raw request payloads, raw form submissions, raw provider payloads, raw logs, raw rows, recipient details, credential values, tenant identifiers, object identifiers, private network values, live endpoints, or URLs.","evidence":"Evidence references"}
        ]
    }))
}

async fn catalog_site_catalog() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "catalogMode": "safe-site-facts", "domain": "CORP.local",
        "ouPattern": "OU=Servers,OU=<SITE>,OU=<COUNTRY>,DC=corp,DC=local", "network": "DHCP", "organization": "Ryuki EU",
        "safeXmlFactsOnly": true, "providerCallsAllowed": false, "liveValidationAllowed": false, "xmlParsingAllowed": false,
        "workflowMutationAllowed": false, "rawXmlAllowed": false, "encryptedValuesAllowed": false, "passwordValuesAllowed": false,
        "credentialIdentifiersAllowed": false, "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "privateNetworkValuesAllowed": false,
        "rawProviderPayloadsAllowed": false, "rawSiteInventoryRowsAllowed": false, "rawRecipientDataAllowed": false,
        "windowsBehavior": ["Sysprep","VM-name generator","Change SID"],
        "sites": [
            {"spec":"deber-windows-customization","country":"DE","site":"DEBER","timezoneCode":105},
            {"spec":"defra-windows-customization","country":"DE","site":"DEFRA","timezoneCode":105},
            {"spec":"frpar-windows-customization","country":"FR","site":"FRPAR","timezoneCode":105},
            {"spec":"gblon-windows-customization","country":"GB","site":"GBLON","timezoneCode":85},
            {"spec":"nlams-windows-customization","country":"NL","site":"NLAMS","timezoneCode":105}
        ],
        "requiredEvidence": ["Site catalog summary","Safe XML fact review","OU pattern review","Windows behavior review","Validation result","Evidence references"]
    }))
}

async fn catalog_policy_guardrails() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "evaluationMode": "static-readiness", "providerCallsEnabled": false, "livePolicyEvaluationAllowed": false,
        "liveProviderValidationAllowed": false, "requestPayloadEvaluationAllowed": false, "policyMutationAllowed": false,
        "rawRequestPayloadsAllowed": false, "rawPolicyInputsAllowed": false, "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false, "credentialValuesAllowed": false, "rawProviderPayloadsAllowed": false,
        "policyFamilies": ["naming","tagging","ownership","sitePlacement","backup","monitoring","cmdb","patching","approvals","evidence","dryRun","capacity"],
        "priorities": ["P0","P1"], "decisions": ["block","warn","review"],
        "ruleIds": ["p0-preflight-required-fields","p0-site-ou-catalog-match","p0-prod-critical-backup-policy","p0-monitoring-profile-required","p0-cmdb-context-required","p0-dry-run-before-approval","p0-redacted-evidence-state","p0-capacity-admission-check","p1-naming-standard-review","p1-tagging-standard-review","p1-patch-context-required","p0-approval-authority-required"],
        "requiredGuards": ["policy-catalog-present","policy-families-known","rule-targets-validated","site-bindings-validated","dry-run-rule-present","approval-rule-present","evidence-rule-present","capacity-rule-present","redacted-evidence-required"],
        "blockedReasons": ["provider-calls-disabled","live-policy-evaluation-disabled","live-provider-validation-disabled","request-payload-evaluation-disabled","policy-mutation-disabled","raw-request-payloads-disabled","raw-policy-inputs-disabled","tenant-identifiers-disabled","object-identifiers-disabled","private-network-values-disabled","credential-values-disabled","raw-provider-payloads-disabled","policy-catalog-missing","policy-family-missing","rule-target-invalid","site-binding-invalid","dry-run-rule-missing","approval-rule-missing","evidence-rule-missing"],
        "requiredEvidence": ["Policy guardrail summary","Rule catalog summary","Site binding summary","Dry-run rule","Approval rule","Evidence rule","Capacity rule","Evidence references"],
        "rules": [
            {"id":"no-live-policy-execution","decision":"block","requirement":"Policy guardrails report static readiness only and never evaluate live request payloads, call providers, validate provider state, mutate policies, or change workflow state.","evidence":"Policy guardrail summary"},
            {"id":"catalog-relationships-validated","decision":"block","requirement":"Policy families, rule targets, site bindings, dry-run rule, approval rule, evidence rule, and capacity rule must validate before guardrails can be consumed.","evidence":"Rule catalog summary"},
            {"id":"raw-policy-data-not-exposed","decision":"block","requirement":"Policy guardrail evidence must use safe summaries only and must not expose raw request payloads, raw policy inputs, tenant IDs, object IDs, private network values, credentials, tokens, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn catalog_access_control() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "configuredForProduction": false, "entraGroupsConfigured": false,
        "requiredProductionProvider": "Microsoft Entra ID",
        "actions": ["request","approve","execute","admin","audit"],
        "roles": [
            {"id":"platform-admin","title":"Platform Admin","visibility":"all","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":true,"canAudit":true,"executionDomains":["platform","governance","emergency"]},
            {"id":"datacenter-approver","title":"Datacenter Approver","visibility":"site-scope","canRequest":true,"canApprove":true,"canExecute":false,"canAdmin":false,"canAudit":true,"executionDomains":["datacenter","capacity","live-execution-final"]},
            {"id":"vmware-operator","title":"VMware Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["vmware","placement","lifecycle"]},
            {"id":"hyper-v-operator","title":"Hyper-V Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["hyper-v","placement","lifecycle"]},
            {"id":"proxmox-operator","title":"Proxmox Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["proxmox","placement","lifecycle"]},
            {"id":"nutanix-operator","title":"Nutanix AHV Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["nutanix-ahv","placement","lifecycle"]},
            {"id":"xen-operator","title":"Xen Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["xen","placement","lifecycle"]},
            {"id":"kvm-operator","title":"KVM Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["kvm","placement","lifecycle"]},
            {"id":"wintel-linux-operator","title":"Wintel/Linux Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["windows","linux","patching","baseline"]},
            {"id":"backup-operator","title":"Backup Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["backup","restore","dr"]},
            {"id":"monitoring-operator","title":"Monitoring Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["monitoring","alert-routing","maintenance-window"]},
            {"id":"service-desk","title":"Service Desk","visibility":"ticket-scope","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["approved-runbook","incident-context","handover"]},
            {"id":"auditor","title":"Auditor","visibility":"audit-scope","canRequest":false,"canApprove":false,"canExecute":false,"canAdmin":false,"canAudit":true,"executionDomains":["evidence-review","export-review","compliance"]},
            {"id":"requester","title":"Requester","visibility":"own-requests","canRequest":true,"canApprove":false,"canExecute":false,"canAdmin":false,"canAudit":false,"executionDomains":["request-intake","evidence-view"]}
        ],
        "executionGuards": [
            {"id":"validation-passed","decision":"block","evidence":"Validation result"},
            {"id":"provider-safe-dry-run","decision":"block","evidence":"Provider-safe plan"},
            {"id":"required-approvals","decision":"block","evidence":"Approval decisions"},
            {"id":"active-lock","decision":"block","evidence":"Lock record"},
            {"id":"redacted-evidence-ready","decision":"block","evidence":"Evidence manifest"},
            {"id":"dependency-health-known","decision":"block","evidence":"Dependency status"},
            {"id":"secret-reference-approved","decision":"block","evidence":"Reference configured state"}
        ]
    }))
}

async fn catalog_approval_routes() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "configuredForProduction": false,
        "routes": [
            {"id":"p0-live-execution-default","appliesTo":["request-preflight","windows-server-deployment","linux-server-deployment","patch-wave-planning","controlled-restore-request","zabbix-onboarding","operator-runbook-launch"],"requiredActors":["Datacenter Approver"],"conditionalActors":["Application owner","Wintel/Linux Operator","Backup Operator","Monitoring Operator","Service Desk"],"emergencyAllowed":true,"evidence":["Approval decisions","Delegated authority","Emergency flag","Policy decision record"]},
            {"id":"p0-cmdb-file-exchange","appliesTo":["cmdb-import","cmdb-update-export"],"requiredActors":["Datacenter Approver"],"conditionalActors":["Application owner"],"emergencyAllowed":false,"evidence":["Approval decisions","Reviewer approval","File hash","Accepted/rejected rows"]},
            {"id":"p0-platform-admin-readiness","appliesTo":["platform-health-dashboard"],"requiredActors":["Platform Admin"],"conditionalActors":["Auditor"],"emergencyAllowed":false,"evidence":["Approval decisions","Health snapshot","Stale-data markers","Dependency status"]},
            {"id":"p1-retirement-governance","appliesTo":["vm-decommission-quarantine","application-environment-retirement"],"requiredActors":["Datacenter Approver","Application owner"],"conditionalActors":["Backup Operator","Auditor"],"emergencyAllowed":true,"evidence":["Approval decisions","Delegated authority","Emergency flag","Dependency review","Backup retention proof","Final evidence references"]}
        ]
    }))
}

async fn catalog_evidence_manifest() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "recordTypes": ["Request payload summary","Validation result","Provider-safe plan","Approval decisions","Lock record","Redacted execution log","Evidence references","File hash","Accepted/rejected rows","Health snapshot","Dependency status"],
        "prohibitedContent": ["credential values","bearer material","private key material","generated certificates","Vault initialization material","raw provider payloads","unfiltered logs","stack traces","tenant identifiers","object identifiers","private network addresses","raw recipient data"],
        "redactionStates": ["pending","redacted","blocked"],
        "exportReadiness": ["draft","redaction-pending","ready-for-audit","ready-for-cab","ready-for-incident-review","ready-for-handover","blocked"],
        "requiredManifestFields": ["evidenceId","evidenceType","requestReference","operationReference","exporter","createdAt","redactionState","exportReadiness","recordTypes","evidenceReferences","retentionClass"],
        "requiredChecks": ["no-secret-pattern-scan","provider-summary-only","stack-trace-suppression","identifier-redaction","private-network-redaction","log-line-filtering","export-readiness-gate"],
        "safeExportTargets": ["audit-review","cab-review","incident-review","handover","cmdb-file-exchange"],
        "retentionClasses": ["operational-review","audit-retained","cab-retained","incident-retained","handover-retained","cmdb-exchange-retained"],
        "requiredEvidence": ["Evidence manifest summary","Redaction check summary","Export readiness decision","Prohibited content review","Retention class decision","Evidence references"],
        "blockedReasons": ["provider-calls-disabled","live-evidence-mutation-disabled","evidence-payloads-disabled","raw-request-payloads-disabled","raw-provider-payloads-disabled","raw-evidence-payloads-disabled","raw-log-content-disabled","unfiltered-logs-disabled","stack-traces-disabled","export-without-redaction-disabled","credential-values-disabled","secret-values-disabled","token-values-disabled","tenant-identifiers-disabled","object-identifiers-disabled","private-network-values-disabled","raw-recipient-data-disabled","manifest-fields-missing","redaction-check-missing","export-readiness-missing","retention-class-missing"]
    }))
}

async fn catalog_evidence_redaction() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "redactionMode": "static-evidence-redaction",
        "noSecretScanRequired": true,
        "providerSummaryOnly": true,
        "stackTraceSuppression": true,
        "identifierRedaction": true,
        "privateNetworkRedaction": true,
        "logLineFiltering": true,
        "exportReadinessGate": true,
        "safeExportTargets": ["audit-review","cab-review","incident-review","handover","cmdb-file-exchange"],
        "redactionStates": ["pending","redacted","blocked"],
        "exportReadiness": ["draft","redaction-pending","ready-for-audit","ready-for-cab","ready-for-incident-review","ready-for-handover","blocked"],
        "prohibitedContent": ["credential values","bearer material","private key material","generated certificates","Vault initialization material","raw provider payloads","unfiltered logs","stack traces","tenant identifiers","object identifiers","private network addresses","raw recipient data"],
        "requiredChecks": ["no-secret-pattern-scan","provider-summary-only","stack-trace-suppression","identifier-redaction","private-network-redaction","log-line-filtering","export-readiness-gate"],
        "retentionClasses": ["operational-review","audit-retained","cab-retained","incident-retained","handover-retained","cmdb-exchange-retained"],
        "blockedReasons": ["provider-calls-disabled","live-evidence-mutation-disabled","evidence-payloads-disabled","raw-request-payloads-disabled","raw-provider-payloads-disabled","raw-evidence-payloads-disabled","raw-log-content-disabled","unfiltered-logs-disabled","stack-traces-disabled","export-without-redaction-disabled","credential-values-disabled","secret-values-disabled","token-values-disabled","tenant-identifiers-disabled","object-identifiers-disabled","private-network-values-disabled","raw-recipient-data-disabled","manifest-fields-missing","redaction-check-missing","export-readiness-missing","retention-class-missing"],
        "requiredEvidence": ["Evidence manifest summary","Redaction check summary","Export readiness decision","Prohibited content review","Retention class decision","Evidence references"]
    }))
}

async fn catalog_secret_references() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "secretValuesAllowed": false,
        "secretReferenceKinds": ["adapter-credential","worker-credential","database-credential","object-storage-credential","pki-material","recovery-material","signing-material"],
        "readinessStates": ["missing","pending-approval","configured","rotation-due","blocked"],
        "rotationPolicies": ["deployment-managed","scheduled-rotation","emergency-rotation","certificate-renewal","manual-break-glass-review"]
    }))
}

async fn approvals_decision_readiness() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "approvalReadinessMode": "static-approval-decision-readiness", "identityProvider": "Microsoft Entra ID",
        "configuredForProduction": false, "decisionQueueReadOnly": true, "routeCatalogReadOnly": true, "evidenceRequired": true,
        "localMockAuthAllowed": true, "providerCallsAllowed": false, "liveAuthenticationAllowed": false, "graphCallsAllowed": false,
        "entraGroupLookupAllowed": false, "serviceNowApprovalMutationAllowed": false, "approvalExecutionAllowed": false,
        "approvalQueueMutationAllowed": false, "approvalDecisionMutationAllowed": false, "notificationDispatchAllowed": false, "workflowMutationAllowed": false,
        "rawApproverDataAllowed": false, "rawApprovalPayloadsAllowed": false, "rawRequestPayloadsAllowed": false, "rawRecipientDataAllowed": false,
        "rawProviderPayloadsAllowed": false, "rawLogContentAllowed": false, "rawRowsAllowed": false,
        "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "principalIdentifiersAllowed": false, "groupIdentifiersAllowed": false,
        "serviceNowIdentifiersAllowed": false, "privateNetworkValuesAllowed": false, "credentialValuesAllowed": false, "tokenValuesAllowed": false,
        "approvalRoutes": ["p0-live-execution-default","p0-cmdb-file-exchange","p0-platform-admin-readiness","p1-retirement-governance"],
        "decisionStates": ["not-required","pending-approval","approved","rejected","delegated","emergency-approved","expired","blocked"],
        "decisionTypes": ["technical-approval","business-approval","risk-acceptance","emergency-approval","cmdb-review","audit-review"],
        "routeStages": ["route-selected","preflight-reviewed","technical-review","business-review","risk-review","emergency-review","final-approval","evidence-ready"],
        "approvalScopes": ["request","workflow","change","cmdb-file-exchange","platform-admin","retirement"],
        "escalationStates": ["none","needs-delegation","needs-final-approval","expired","blocked"],
        "requiredGuards": ["approval-route-known","request-scope-summarized","decision-state-known","datacenter-final-approval","delegated-authority-reviewed","emergency-flag-reviewed","separation-of-duties-reviewed","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-authentication-disabled","graph-calls-disabled","entra-group-lookup-disabled","servicenow-approval-mutation-disabled","approval-execution-disabled","approval-queue-mutation-disabled","approval-decision-mutation-disabled","notification-dispatch-disabled","workflow-mutation-disabled","raw-approver-data-disabled","raw-approval-payloads-disabled","raw-request-payloads-disabled","raw-recipient-data-disabled","raw-provider-payloads-disabled","raw-log-content-disabled","raw-rows-disabled","tenant-identifiers-disabled","object-identifiers-disabled","principal-identifiers-disabled","group-identifiers-disabled","servicenow-identifiers-disabled","private-network-values-disabled","credential-values-disabled","token-values-disabled","approval-route-missing","decision-state-missing","approval-evidence-missing"],
        "requiredEvidence": ["Approval route summary","Decision state summary","Delegated authority review","Emergency flag review","Separation of duties review","Approval evidence references"],
        "rules": [
            {"id":"approval-route-readiness-required","decision":"block","requirement":"Approval decisions require route, scope, decision state, delegated authority posture, emergency posture, and evidence references before workflow approval can be represented.","evidence":"Approval route summary"},
            {"id":"datacenter-final-approval-required","decision":"block","requirement":"Live execution readiness requires Datacenter final approval unless a future delegated approval model is explicitly configured outside this static contract.","evidence":"Decision state summary"},
            {"id":"no-live-approval-execution","decision":"block","requirement":"Approval readiness is read-only and never executes approvals, mutates queues, dispatches notifications, calls identity providers, calls ServiceNow, or changes workflow state.","evidence":"Approval evidence references"},
            {"id":"raw-approval-data-not-exposed","decision":"block","requirement":"Approval readiness evidence must use safe summaries only and must not expose approver records, raw approval payloads, raw request payloads, raw recipient data, raw provider payloads, raw logs, raw rows, tenant IDs, object IDs, principal IDs, group IDs, ServiceNow identifiers, private network values, credentials, or tokens.","evidence":"Approval evidence references"}
        ]
    }))
}

async fn identity_rbac_approval_model() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "modelMode": "static-rbac-approval-model", "identityProvider": "Microsoft Entra ID", "configuredForProduction": false,
        "localMockAuthAllowed": true, "providerCallsAllowed": false, "liveAuthenticationAllowed": false, "graphCallsAllowed": false,
        "entraGroupLookupAllowed": false, "serviceNowApprovalMutationAllowed": false, "approvalExecutionAllowed": false, "roleAssignmentMutationAllowed": false,
        "policyMutationAllowed": false, "workflowMutationAllowed": false, "rawUserDataAllowed": false, "rawClaimPayloadsAllowed": false,
        "rawGroupRowsAllowed": false, "rawApprovalPayloadsAllowed": false, "tenantIdentifiersAllowed": false, "appIdentifiersAllowed": false,
        "clientIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "principalIdentifiersAllowed": false, "groupIdentifiersAllowed": false,
        "credentialValuesAllowed": false, "tokenValuesAllowed": false, "rawProviderPayloadsAllowed": false,
        "roles": ["platform-admin","datacenter-approver","vmware-operator","hyper-v-operator","proxmox-operator","wintel-linux-operator","backup-operator","monitoring-operator","service-desk","auditor","requester"],
        "capabilities": ["request","approve","execute","admin","audit"],
        "approvalRoutes": ["p0-live-execution-default","p0-cmdb-file-exchange","p0-platform-admin-readiness","p1-retirement-governance"],
        "executionGuards": ["validation-passed","provider-safe-dry-run","required-approvals","active-lock","redacted-evidence-ready","dependency-health-known","secret-reference-approved"],
        "requiredInputs": ["roleActionMatrix","approvalRouteSummary","executionGuardSummary","requestContext","approvalDecisionSummary","emergencyApprovalSummary","evidenceManifest"],
        "separationOfDutiesControls": ["requester-cannot-execute","executor-cannot-final-approve-own-request","datacenter-final-approval-required","break-glass-audited","auditor-read-only","platform-admin-break-glass-reviewed"],
        "blockedReasons": ["provider-calls-disabled","live-authentication-disabled","graph-lookup-disabled","entra-group-lookup-disabled","servicenow-mutation-disabled","approval-execution-disabled","role-assignment-mutation-disabled","policy-mutation-disabled","workflow-mutation-disabled","raw-user-data-disabled","raw-claim-payloads-disabled","raw-group-rows-disabled","raw-approval-payloads-disabled","tenant-identifiers-disabled","app-identifiers-disabled","client-identifiers-disabled","object-identifiers-disabled","principal-identifiers-disabled","group-identifiers-disabled","credential-values-disabled","token-values-disabled","raw-provider-payloads-disabled","missing-role-mapping","missing-approval-route","missing-execution-guard","missing-separation-of-duties","evidence-not-redacted"],
        "requiredEvidence": ["RBAC model summary","Role action matrix","Approval route summary","Execution guard summary","Segregation of duties review","Emergency approval review","Evidence references"],
        "rules": [
            {"id":"no-live-rbac-provider-execution","decision":"block","requirement":"RBAC approval model reports static readiness only and never calls identity providers, Microsoft Graph, ServiceNow, policy engines, approval systems, or provider APIs.","evidence":"RBAC model summary"},
            {"id":"access-catalog-alignment-required","decision":"block","requirement":"Model roles, capabilities, approval routes, execution guards, and evidence records must align with the static access-control catalog before workflow consumption.","evidence":"Role action matrix"},
            {"id":"separation-of-duties-required","decision":"block","requirement":"Requester, executor, approver, administrator, emergency, and audit duties must preserve least privilege and prevent approval or execution bypasses.","evidence":"Segregation of duties review"},
            {"id":"raw-rbac-data-not-exposed","decision":"block","requirement":"RBAC approval evidence must use safe summaries only and must not expose user records, claim payloads, group rows, tenant IDs, app IDs, client IDs, object IDs, principal IDs, group IDs, credentials, tokens, approval payloads, ServiceNow payloads, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn identity_entra_rbac() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "readinessMode": "static-readiness", "identityProvider": "Microsoft Entra ID", "configuredForProduction": false,
        "localMockAuthAllowed": true, "providerCallsEnabled": false, "liveAuthenticationEnabled": false, "tokenValidationEnabled": false,
        "graphCallsAllowed": false, "entraGroupLookupAllowed": false, "appRegistrationChangesAllowed": false, "roleAssignmentChangesAllowed": false,
        "approvalExecutionAllowed": false, "serviceNowApprovalChangesAllowed": false, "rawUserDataAllowed": false, "rawClaimPayloadsAllowed": false,
        "rawGroupRowsAllowed": false, "tenantIdentifiersAllowed": false, "appIdentifiersAllowed": false, "clientIdentifiersAllowed": false,
        "objectIdentifiersAllowed": false, "principalIdentifiersAllowed": false, "groupIdentifiersAllowed": false, "credentialValuesAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "readinessSurfaces": ["oidc-configuration-readiness","protected-api-readiness","app-role-readiness","group-claim-readiness","role-action-matrix-readiness","approval-route-readiness","local-mock-boundary-readiness","audit-evidence-readiness","break-glass-readiness"],
        "requiredInputs": ["identityProviderDecision","runtimeConfigurationSummary","protectedApiProfile","appRoleMappingSummary","groupClaimMappingSummary","roleActionMatrix","approvalRouteSummary","localMockBoundary","breakGlassSummary","evidenceManifest"],
        "requiredGuards": ["identity-provider-confirmed","runtime-config-externalized","protected-api-profile-reviewed","app-role-mapping-reviewed","group-claim-mapping-reviewed","role-action-matrix-reviewed","approval-routes-reviewed","local-mock-boundary-enforced","break-glass-reviewed","evidence-redacted"],
        "planSections": ["readinessSummary","identityProviderBoundary","runtimeConfiguration","protectedApiReadiness","roleMappingReview","approvalRouteReview","localMockBoundary","breakGlassReview","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","live-authentication-disabled","token-validation-disabled","graph-calls-disabled","entra-group-lookup-disabled","app-registration-change-disabled","role-assignment-change-disabled","approval-execution-disabled","servicenow-approval-change-disabled","raw-user-data-disabled","raw-claim-payloads-disabled","raw-group-rows-disabled","tenant-identifiers-disabled","app-identifiers-disabled","client-identifiers-disabled","object-identifiers-disabled","principal-identifiers-disabled","group-identifiers-disabled","credential-values-disabled","raw-provider-payloads-disabled","runtime-config-missing","protected-api-profile-missing","role-mapping-missing","approval-route-missing","local-mock-boundary-missing","break-glass-review-missing","evidence-not-redacted"],
        "requiredEvidence": ["Identity readiness summary","Runtime configuration review","Protected API readiness","Role mapping review","Approval route review","Local mock boundary","Break-glass review","Evidence references"],
        "rules": [
            {"id":"no-live-auth-provider-execution","decision":"block","requirement":"Entra RBAC approval readiness reports static readiness only and never validates live sign-ins, calls Microsoft Graph, looks up groups, changes app registrations, assigns roles, executes approvals, changes ServiceNow approvals, or mutates provider state.","evidence":"Identity readiness summary"},
            {"id":"runtime-config-externalized","decision":"block","requirement":"Runtime identity configuration, protected API settings, app role mapping, and group claim mapping must remain deployment configuration outside committed files.","evidence":"Runtime configuration review"},
            {"id":"role-and-approval-readiness-required","decision":"block","requirement":"Role action matrix, approval routes, break-glass handling, and local mock boundary must be reviewed before production authentication can be accepted.","evidence":"Approval route review"},
            {"id":"raw-entra-readiness-data-not-exposed","decision":"block","requirement":"Readiness evidence must use safe summaries only and must not expose user records, claim payloads, group rows, tenant IDs, app IDs, client IDs, object IDs, principal IDs, group IDs, credentials, tokens, Microsoft Graph payloads, ServiceNow payloads, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn identity_access_review() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "reviewMode": "review-only", "providerCallsEnabled": false, "liveDirectoryChangesAllowed": false,
        "liveServiceNowChangesAllowed": false, "rawUserDataAllowed": false, "rawGroupDataAllowed": false, "principalIdentifiersAllowed": false,
        "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "rawProviderPayloadsAllowed": false,
        "reviewScopes": ["ownership-recertification","support-group-recertification","privileged-role-review","service-account-review","stale-access-review","exception-review"],
        "reviewSignals": ["owner-missing","support-group-missing","privileged-role-aging","service-account-unknown","orphaned-access","recertification-overdue","exception-expiring"],
        "requiredInputs": ["reviewScopeSummary","recertificationCycle","accessScope","roleProfile","ownershipSummary","supportGroup","riskTier","reviewCadence","approvalRoute","evidenceManifest"],
        "requiredGuards": ["review-scope-summarized","owner-known","support-group-known","approval-route-assigned","evidence-redacted","raw-identity-data-blocked","expiry-date-set","remediation-plan-ready"],
        "planSections": ["reviewSummary","scopeReview","ownershipDecision","privilegedAccessReview","serviceAccountReview","exceptionDecision","remediationPlan","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","live-directory-change-disabled","live-servicenow-change-disabled","raw-user-data-disabled","raw-group-data-disabled","principal-identifiers-disabled","tenant-identifiers-disabled","object-identifiers-disabled","raw-provider-payloads-disabled","review-scope-missing","owner-unknown","support-group-unknown","approval-missing","expiry-missing","remediation-plan-missing","evidence-not-redacted"],
        "requiredEvidence": ["Access review summary","Scope review","Ownership decision","Privileged access review","Service account review","Exception decision","Remediation plan","Evidence references"],
        "rules": [
            {"id":"no-live-access-changes","decision":"block","requirement":"Access recertification reports review state only and never changes Entra groups, AD groups, ServiceNow records, local memberships, or provider state.","evidence":"Access review summary"},
            {"id":"redacted-scope-required","decision":"block","requirement":"Review scope must be summarized before recertification can be accepted.","evidence":"Scope review"},
            {"id":"ownership-and-approval-required","decision":"block","requirement":"Ownership, support group, approval route, expiry, and review cadence must be known before acceptance.","evidence":"Ownership decision"},
            {"id":"privileged-access-reviewed","decision":"block","requirement":"Privileged access and service account scope must be reviewed before exception or remediation decisions.","evidence":"Privileged access review"},
            {"id":"raw-identity-data-not-exposed","decision":"block","requirement":"Access recertification evidence must use safe summaries only and must not expose raw user records, group membership rows, principal IDs, tenant IDs, object IDs, account names, email addresses, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

async fn identity_ad_computer() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "lifecycleMode": "metadata-only", "providerCallsEnabled": false, "workerExecutionAllowed": false,
        "liveDirectoryChangesAllowed": false, "computerPrestageAllowed": false, "computerMoveAllowed": false, "computerDisableAllowed": false,
        "computerDeleteAllowed": false, "computerRecoverAllowed": false, "rawComputerDataAllowed": false, "principalIdentifiersAllowed": false,
        "distinguishedNamesAllowed": false, "domainIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "securityIdentifiersAllowed": false,
        "computerIdentifiersAllowed": false, "rawProviderPayloadsAllowed": false,
        "lifecycleActions": ["computer-prestage-review","computer-move-review","computer-disable-review","computer-delete-review","computer-recover-review","computer-reconcile-review"],
        "lifecycleSignals": ["ou-policy-match","lifecycle-state-match","cmdb-state-match","approval-state","rollback-window-ready","stale-object-risk","evidence-redaction"],
        "requiredInputs": ["computerScope","targetOu","currentOu","lifecycleAction","owner","cmdbContext","site","environment","approvalRoute","rollbackPlan","evidenceManifest"],
        "requiredGuards": ["request-context-known","target-scope-summarized","ou-policy-reviewed","lifecycle-action-supported","cmdb-state-reviewed","approval-route-assigned","rollback-plan-ready","evidence-redacted"],
        "planSections": ["lifecycleSummary","targetScope","ouPolicyReview","cmdbReconciliation","approvalRoute","rollbackPlan","recoveryReadiness","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","worker-execution-disabled","live-directory-change-disabled","computer-prestage-disabled","computer-move-disabled","computer-disable-disabled","computer-delete-disabled","computer-recover-disabled","raw-computer-data-disabled","principal-identifiers-disabled","distinguished-names-disabled","domain-identifiers-disabled","object-identifiers-disabled","security-identifiers-disabled","computer-identifiers-disabled","raw-provider-payloads-disabled","approval-missing","rollback-plan-missing","evidence-not-redacted"],
        "requiredEvidence": ["Computer lifecycle summary","Target scope","OU policy review","CMDB reconciliation","Approval route","Rollback plan","Recovery readiness","Evidence references"]
    }))
}

// ─── AD computer lifecycle handlers ───

async fn ad_prestage(Json(body): Json<AdPrestageRequest>) -> ApiResult {
    match ad_computer_lifecycle::prestage_computer(&body.name, &body.site, &body.ou_path) {
        Ok(computer) => Ok(Json(serde_json::to_value(computer).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn ad_validate(Json(body): Json<AdValidateRequest>) -> ApiResult {
    match ad_computer_lifecycle::validate_computer(&body.name) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn ad_move(Path(name): Path<String>, Json(body): Json<AdMoveRequest>) -> ApiResult {
    match ad_computer_lifecycle::move_computer(&name, &body.target_ou) {
        Ok(computer) => Ok(Json(serde_json::to_value(computer).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn ad_disable(Path(name): Path<String>, Json(body): Json<AdDisableRequest>) -> ApiResult {
    match ad_computer_lifecycle::disable_computer(&name, &body.reason) {
        Ok(computer) => Ok(Json(serde_json::to_value(computer).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn ad_enable(Path(name): Path<String>) -> ApiResult {
    match ad_computer_lifecycle::enable_computer(&name) {
        Ok(computer) => Ok(Json(serde_json::to_value(computer).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn ad_delete(Path(name): Path<String>) -> ApiResult {
    match ad_computer_lifecycle::delete_computer(&name) {
        Ok(()) => Ok(Json(
            serde_json::json!({"deleted": true, "computer": name, "dry_run": true}),
        )),
        Err(e) => Err(status_400(&e)),
    }
}

async fn ad_reconcile(Query(query): Query<AdReconcileQuery>) -> ApiResult {
    let site = query.site.as_deref().unwrap_or("DEFRA");
    match ad_computer_lifecycle::reconcile_computers(site) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn ad_orphaned(Query(query): Query<AdOrphanedQuery>) -> ApiResult {
    let site = query.site.as_deref().unwrap_or("DEFRA");
    match ad_computer_lifecycle::get_orphaned(site) {
        Ok(computers) => Ok(Json(serde_json::to_value(computers).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn ad_computer_contract() -> Json<Value> {
    let examples = ad_computer_lifecycle::seed_examples();
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionAllowed": false,
        "dryRunRequired": true,
        "lifecycleModes": ["prestage", "validate", "move", "disable", "enable", "delete", "reconcile"],
        "computerStatuses": ["Active", "Disabled", "Quarantined", "Deleted"],
        "supportedOs": ["Windows Server 2022", "Windows Server 2019", "Windows Server 2016", "Windows 11", "Windows 10"],
        "validSites": ["DEBER","DEFRA","DEDUS","DEMUC","FRPAR","FRMRS","GBLON","GBMAN","NLAMS","NLEIN","ESMAD","ESBCN","ITMIL","ITROM","CHZRH","ATVIE","BEBRU","SE STO","DKCPH","IE DUB"],
        "namingPattern": "SITE-ROLE-NN (e.g. DEFRA-SRV-01, GBLON-DB-01)",
        "validRoles": ["SRV", "WS", "DC", "MGMT", "TEST", "DEV"],
        "validOuPrefixes": ["OU=Servers", "OU=Workstations", "OU=DMZ", "OU=Management", "OU=Testing", "OU=Development"],
        "requiredInputs": ["name", "site", "ouPath"],
        "blockedReasons": ["provider-calls-disabled", "live-execution-disabled", "live-directory-changes-disabled", "raw-ad-data-disabled"],
        "examples": serde_json::to_value(examples).unwrap()
    }))
}

// ─── gMSA lifecycle handlers ───

async fn gmsa_create(Json(body): Json<GmsaCreateRequest>) -> ApiResult {
    match gmsa_lifecycle::create_gmsa(&body.name, body.hosts, body.spns, &body.site) {
        Ok(account) => Ok(Json(serde_json::to_value(account).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn gmsa_validate(Json(body): Json<GmsaValidateRequest>) -> ApiResult {
    match gmsa_lifecycle::validate_gmsa(&body.name) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn gmsa_assign(Path((name, host)): Path<(String, String)>) -> ApiResult {
    match gmsa_lifecycle::assign_to_host(&name, &host) {
        Ok(account) => Ok(Json(serde_json::to_value(account).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn gmsa_remove(Path((name, host)): Path<(String, String)>) -> ApiResult {
    match gmsa_lifecycle::remove_from_host(&name, &host) {
        Ok(account) => Ok(Json(serde_json::to_value(account).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn gmsa_rotate(Path(name): Path<String>) -> ApiResult {
    match gmsa_lifecycle::rotate_password(&name) {
        Ok(account) => Ok(Json(serde_json::to_value(account).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn gmsa_test(Path((name, host)): Path<(String, String)>) -> ApiResult {
    match gmsa_lifecycle::test_retrieval(&name, &host) {
        Ok(account) => Ok(Json(serde_json::to_value(account).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn gmsa_inventory(Query(query): Query<GmsaInventoryQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let inventory = gmsa_lifecycle::get_gmsa_inventory(site);
    Json(serde_json::to_value(inventory).unwrap())
}

async fn gmsa_expiring() -> Json<Value> {
    let expiring = gmsa_lifecycle::get_expiring();
    Json(serde_json::to_value(expiring).unwrap())
}

async fn gmsa_contract() -> Json<Value> {
    let examples = gmsa_lifecycle::seed_examples();
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionAllowed": false,
        "dryRunRequired": true,
        "supportedWorkflows": ["gmsa-create", "gmsa-validate", "gmsa-assign", "gmsa-remove", "gmsa-rotate", "gmsa-test-retrieval", "gmsa-inventory", "gmsa-expiring"],
        "validStatuses": ["Active", "Expiring", "Expired", "Revoked"],
        "namingConvention": "svc-PURPOSE-SITE (e.g. svc-webappool-gblon)",
        "requiredInputs": ["name", "hosts", "spns", "site"],
        "blockedReasons": ["provider-calls-disabled", "live-execution-disabled", "live-directory-changes-disabled", "raw-service-account-data-disabled"],
        "examples": serde_json::to_value(examples).unwrap()
    }))
}

async fn identity_gmsa_lifecycle() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "lifecycleMode": "metadata-only", "providerCallsEnabled": false, "workerExecutionAllowed": false,
        "liveDirectoryChangesAllowed": false, "gmsaCreationAllowed": false, "gmsaAssignmentAllowed": false, "gmsaValidationAllowed": false,
        "gmsaRetireAllowed": false, "passwordRetrievalAllowed": false, "managedPasswordMaterialAllowed": false, "spnChangeAllowed": false,
        "delegationChangeAllowed": false, "rawServiceAccountDataAllowed": false, "rawLogContentAllowed": false, "rawRowsAllowed": false,
        "serialNumbersAllowed": false, "rawRecipientDataAllowed": false, "principalIdentifiersAllowed": false, "distinguishedNamesAllowed": false,
        "domainIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "securityIdentifiersAllowed": false, "targetIdentifiersAllowed": false,
        "credentialValuesAllowed": false, "rawProviderPayloadsAllowed": false,
        "lifecycleActions": ["gmsa-create-review","gmsa-assign-review","gmsa-validate-review","gmsa-worker-use-review","gmsa-delegation-review","gmsa-retire-review"],
        "lifecycleSignals": ["kds-root-key-readiness","retrieval-scope-summary","kerberos-encryption-policy","spn-policy-match","delegation-risk","worker-capability-match","approval-state","evidence-redaction"],
        "requiredInputs": ["serviceAccountScope","gmsaName","hostScope","kdsReadiness","kerberosPolicy","spnProfile","workerCapability","site","environment","approvalRoute","rollbackPlan","recoveryPlan","evidenceManifest"],
        "requiredGuards": ["request-context-known","service-account-scope-summarized","kds-root-key-readiness-reviewed","retrieval-scope-reviewed","kerberos-policy-reviewed","spn-policy-reviewed","delegation-risk-reviewed","worker-capability-reviewed","approval-route-assigned","rollback-plan-ready","recovery-readiness-reviewed","evidence-redacted"],
        "planSections": ["lifecycleSummary","serviceAccountScope","retrievalScopeReview","kerberosPolicyReview","spnPolicyReview","delegationRiskReview","workerRoutingReview","approvalRoute","rollbackPlan","recoveryReadiness","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","worker-execution-disabled","live-directory-change-disabled","gmsa-creation-disabled","gmsa-assignment-disabled","gmsa-validation-disabled","gmsa-retire-disabled","password-retrieval-disabled","managed-password-material-disabled","spn-change-disabled","delegation-change-disabled","raw-service-account-data-disabled","raw-log-content-disabled","raw-rows-disabled","serial-numbers-disabled","raw-recipient-data-disabled","principal-identifiers-disabled","distinguished-names-disabled","domain-identifiers-disabled","object-identifiers-disabled","security-identifiers-disabled","target-identifiers-disabled","credential-values-disabled","raw-provider-payloads-disabled","approval-missing","rollback-plan-missing","recovery-readiness-missing","evidence-not-redacted"]
    }))
}

async fn identity_local_privilege() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "accessReviewMode": "metadata-only", "providerCallsEnabled": false, "workerExecutionAllowed": false,
        "liveDirectoryChangesAllowed": false, "liveLocalAdminChangesAllowed": false, "liveSudoersChangesAllowed": false, "liveServiceNowChangesAllowed": false,
        "adGroupMembershipChangeAllowed": false, "sudoersFileChangeAllowed": false, "privilegeGrantAllowed": false, "privilegeRemovalAllowed": false,
        "rawUserDataAllowed": false, "rawGroupDataAllowed": false, "rawMembershipRowsAllowed": false, "rawSudoersContentAllowed": false,
        "rawRequestPayloadsAllowed": false, "rawProviderPayloadsAllowed": false, "principalIdentifiersAllowed": false, "targetIdentifiersAllowed": false,
        "privilegeHostIdentifiersAllowed": false, "credentialValuesAllowed": false,
        "accessActions": ["local-admin-grant-review","local-admin-remove-review","sudo-grant-review","sudo-remove-review","expiry-review","break-glass-review"],
        "accessScopes": ["windows-local-admin","linux-sudo","directory-group-membership","privileged-role-expiry","break-glass-access","service-desk-escalation"],
        "requiredInputs": ["ticketContext","requester","targetScope","osFamily","privilegeLevel","expiryWindow","serviceDeskReason","approvalRoute","workerCapability","rollbackPlan","evidenceManifest"],
        "requiredGuards": ["ticket-context-known","requester-authorized","target-scope-summarized","privilege-profile-reviewed","os-family-supported","expiry-window-reviewed","approval-route-assigned","worker-capability-reviewed","rollback-plan-ready","evidence-redacted"],
        "planSections": ["accessSummary","targetScope","privilegeProfileReview","directoryGroupReview","sudoersReview","expiryAndReview","workerRouting","rollbackPlan","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","worker-execution-disabled","live-directory-change-disabled","live-local-admin-change-disabled","live-sudoers-change-disabled","live-servicenow-change-disabled","ad-group-membership-change-disabled","sudoers-file-change-disabled","privilege-grant-disabled","privilege-removal-disabled","raw-user-data-disabled","raw-group-data-disabled","raw-membership-rows-disabled","raw-sudoers-content-disabled","raw-request-payloads-disabled","raw-provider-payloads-disabled","principal-identifiers-disabled","target-identifiers-disabled","privilege-host-identifiers-disabled","credential-values-disabled","unsupported-access-action","requester-not-authorized","approval-missing","expiry-missing","worker-capability-unknown","rollback-plan-missing","evidence-not-redacted"]
    }))
}

async fn identity_file_share_ntfs() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "recertificationMode": "metadata-only", "providerCallsEnabled": false, "workerExecutionAllowed": false,
        "liveDirectoryChangesAllowed": false, "liveShareChangesAllowed": false, "liveNtfsAclChangesAllowed": false, "liveServiceNowChangesAllowed": false,
        "adGroupMembershipChangeAllowed": false, "sharePermissionChangeAllowed": false, "ntfsAclChangeAllowed": false, "inheritanceChangeAllowed": false,
        "ownerChangeAllowed": false, "rawShareDataAllowed": false, "rawAclRowsAllowed": false, "rawMembershipRowsAllowed": false,
        "rawPathDataAllowed": false, "rawProviderPayloadsAllowed": false, "principalIdentifiersAllowed": false, "shareIdentifiersAllowed": false,
        "pathValuesAllowed": false, "credentialValuesAllowed": false,
        "recertificationActions": ["owner-recertification-review","group-access-review","ntfs-acl-review","share-permission-review","stale-access-review","exception-review"],
        "recertificationScopes": ["windows-file-share","ntfs-acl","share-permission","ad-group-membership","owner-attestation","stale-access-exception"],
        "requiredInputs": ["shareScope","ownerAttestation","groupAccessSummary","ntfsAclSummary","sharePermissionSummary","exceptionReason","approvalRoute","remediationPlan","evidenceManifest"],
        "requiredGuards": ["recertification-scope-summarized","owner-attestation-reviewed","group-access-reviewed","ntfs-acl-reviewed","share-permission-reviewed","stale-access-reviewed","exception-route-assigned","approval-route-assigned","remediation-plan-ready","evidence-redacted"],
        "planSections": ["recertificationSummary","shareScope","ownershipReview","groupAccessReview","ntfsAclReview","sharePermissionReview","staleAccessReview","exceptionDecision","remediationPlan","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","worker-execution-disabled","live-directory-change-disabled","live-share-change-disabled","live-ntfs-acl-change-disabled","live-servicenow-change-disabled","ad-group-membership-change-disabled","share-permission-change-disabled","ntfs-acl-change-disabled","inheritance-change-disabled","owner-change-disabled","raw-share-data-disabled","raw-acl-rows-disabled","raw-membership-rows-disabled","raw-path-data-disabled","raw-provider-payloads-disabled","principal-identifiers-disabled","share-identifiers-disabled","path-values-disabled","credential-values-disabled","recertification-scope-missing","owner-attestation-missing","approval-missing","remediation-plan-missing","evidence-not-redacted"]
    }))
}

// ─── File Share NTFS recertification handlers ───

async fn shares_list(Query(query): Query<SharesQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let shares = file_share_ntfs::get_shares(site);
    Json(serde_json::to_value(shares).unwrap())
}

async fn shares_get(Path(id): Path<String>) -> ApiResult {
    match file_share_ntfs::get_share_detail(&id) {
        Some(detail) => Ok(Json(serde_json::to_value(detail).unwrap())),
        None => Err(status_404(&id)),
    }
}

async fn shares_recertification_due(
    Query(query): Query<SharesRecertificationDueQuery>,
) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let due = file_share_ntfs::check_recertification_due(site);
    Json(serde_json::to_value(due).unwrap())
}

async fn shares_recertify(
    Path(id): Path<String>,
    Json(body): Json<RecertifyShareRequest>,
) -> ApiResult {
    match file_share_ntfs::recertify_share(&id, &body.reviewer) {
        Ok(share) => Ok(Json(serde_json::to_value(share).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn shares_open_access(Path(id): Path<String>) -> Json<Value> {
    let open = file_share_ntfs::detect_open_access(&id);
    Json(serde_json::to_value(open).unwrap())
}

async fn shares_stale_owners(Query(query): Query<SharesStaleOwnersQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let stale = file_share_ntfs::get_owner_stale(site);
    Json(serde_json::to_value(stale).unwrap())
}

async fn shares_permission_report(Path(id): Path<String>) -> ApiResult {
    match file_share_ntfs::get_permission_report(&id) {
        Ok(report) => Ok(Json(serde_json::to_value(report).unwrap())),
        Err(e) => Err(status_404(&e)),
    }
}

async fn shares_revoke(Path((id, group)): Path<(String, String)>) -> ApiResult {
    match file_share_ntfs::revoke_permission(&id, &group) {
        Ok(msg) => Ok(Json(
            serde_json::json!({"message": msg, "share_id": id, "ad_group": group, "dry_run": true}),
        )),
        Err(e) => Err(status_404(&e)),
    }
}

async fn shares_contract() -> Json<Value> {
    let shares = file_share_ntfs::get_shares("");
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveDirectoryChangesAllowed": false,
        "liveShareChangesAllowed": false,
        "liveNtfsAclChangesAllowed": false,
        "dryRunRequired": true,
        "totalShares": shares.len(),
        "endpoints": {
            "GET /api/identity/shares": "List file shares, optionally filtered by site",
            "GET /api/identity/shares/{id}": "Get share detail with NTFS permissions",
            "GET /api/identity/shares/recertification-due": "Shares needing recertification",
            "POST /api/identity/shares/recertify/{id}": "Mark share as recertified",
            "GET /api/identity/shares/open-access/{id}": "Detect open access (Everyone/Domain Users FullControl)",
            "GET /api/identity/shares/stale-owners": "Shares where owner hasn't recertified in 365+ days",
            "GET /api/identity/shares/permissions/{id}": "Permission report with risk levels",
            "POST /api/identity/shares/revoke/{id}/{group}": "Revoke permission (dry-run)",
            "GET /api/identity/shares-contract": "File share NTFS recertification contract"
        },
        "validSites": ["DEBER","DEFRA","DEDUS","DEMUC","FRPAR","FRMRS","GBLON","GBMAN","NLAMS","NLEIN","ESMAD","ESBCN","ITMIL","ITROM","CHZRH","ATVIE","BEBRU","SE STO","DKCPH","IE DUB"],
        "validStatuses": ["Compliant", "Overdue", "NeedsRecertification"],
        "validPermissionTypes": ["Read", "Write", "Modify", "FullControl"],
        "riskLevels": ["Critical", "High", "Medium", "Low"],
        "blockedReasons": ["provider-calls-disabled", "live-directory-change-disabled", "live-share-change-disabled", "live-ntfs-acl-change-disabled", "raw-share-data-disabled", "raw-acl-rows-disabled", "principal-identifiers-disabled", "share-identifiers-disabled", "path-values-disabled", "credential-values-disabled", "recertification-scope-missing", "owner-attestation-missing", "evidence-not-redacted"]
    }))
}

async fn evidence_export_retention() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "exportRetentionMode": "static-evidence-export-retention", "redactionRequired": true, "providerCallsEnabled": false,
        "liveEvidenceMutationAllowed": false, "exportPackageMutationAllowed": false, "retentionPolicyMutationAllowed": false, "liveAuditSearchAllowed": false,
        "auditSearchQueryAllowed": false, "evidencePayloadsAllowed": false, "rawRequestPayloadsAllowed": false, "rawProviderPayloadsAllowed": false,
        "rawEvidencePayloadsAllowed": false, "rawLogContentAllowed": false, "unfilteredLogsAllowed": false, "stackTracesAllowed": false,
        "rawRowsAllowed": false, "serialNumbersAllowed": false, "exportWithoutRedactionAllowed": false, "credentialValuesAllowed": false,
        "secretValuesAllowed": false, "tokenValuesAllowed": false, "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false, "rawRecipientDataAllowed": false,
        "redactionStates": ["pending","redacted","blocked"],
        "exportReadiness": ["draft","redaction-pending","ready-for-audit","ready-for-cab","ready-for-incident-review","ready-for-handover","blocked"],
        "safeExportTargets": ["audit-review","cab-review","incident-review","handover","cmdb-file-exchange"],
        "prohibitedContent": ["credential values","bearer material","private key material","generated certificates","Vault initialization material","raw provider payloads","unfiltered logs","stack traces","tenant identifiers","object identifiers","private network addresses","raw recipient data","raw rows","serial numbers"],
        "retentionClasses": ["operational-review","audit-retained","cab-retained","incident-retained","handover-retained","cmdb-exchange-retained"],
        "auditSearchStates": ["query-draft","redaction-filtered","metadata-only","ready-for-review","blocked"],
        "searchFacets": ["workflow-family","redaction-state","export-readiness","retention-class","record-type","review-state","created-bucket"],
        "packageFields": ["packageReference","workflowFamily","redactionState","exportReadiness","retentionClass","recordTypes","safeExportTarget","reviewState","createdBucket","evidenceReferences"],
        "requiredGuards": ["redaction-state-redacted","export-readiness-approved","retention-class-assigned","metadata-only-search","no-raw-payloads","recipient-data-redacted","provider-payloads-blocked","retention-review-recorded"],
        "requiredEvidence": ["Export package summary","Redaction state review","Retention class decision","Audit search scope summary","Prohibited content review","Evidence references"],
        "blockedReasons": ["provider-calls-disabled","live-evidence-mutation-disabled","export-package-mutation-disabled","retention-policy-mutation-disabled","live-audit-search-disabled","audit-search-query-disabled","evidence-payloads-disabled","raw-request-payloads-disabled","raw-provider-payloads-disabled","raw-evidence-payloads-disabled","raw-log-content-disabled","unfiltered-logs-disabled","stack-traces-disabled","raw-rows-disabled","serial-numbers-disabled","export-without-redaction-disabled","credential-values-disabled","secret-values-disabled","token-values-disabled","tenant-identifiers-disabled","object-identifiers-disabled","private-network-values-disabled","raw-recipient-data-disabled","retention-class-missing","metadata-only-search-missing","redaction-review-missing"]
    }))
}

async fn evidence_compliance_dashboard() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "complianceDashboardMode": "static-evidence-compliance-dashboard", "evidenceRequired": true,
        "providerCallsEnabled": false, "liveEvaluationAllowed": false, "evidenceMutationAllowed": false, "exportMutationAllowed": false,
        "retentionMutationAllowed": false, "workflowMutationAllowed": false, "notificationDispatchAllowed": false,
        "rawEvidencePayloadsAllowed": false, "rawControlRowsAllowed": false, "rawAuditLogsAllowed": false, "rawUserDataAllowed": false,
        "rawProviderPayloadsAllowed": false, "rawRecipientDataAllowed": false, "credentialValuesAllowed": false, "tokenValuesAllowed": false,
        "tenantIdentifiersAllowed": false, "objectIdentifiersAllowed": false, "principalIdentifiersAllowed": false, "privateNetworkValuesAllowed": false,
        "domains": ["security-baseline","rbac-approvals","evidence-redaction","backup-coverage","monitoring-coverage","cmdb-readiness","patch-readiness","restore-testing"],
        "statusBands": ["compliant","attention","gap","blocked","not-assessed"],
        "trendWindows": ["current","seven-day","thirty-day","quarterly"],
        "requiredGuards": ["control-scope-known","evidence-pack-referenced","redaction-state-reviewed","stale-data-marked","owner-assigned","live-evaluation-blocked","evidence-redacted"],
        "blockedReasons": ["compliance-live-evaluation-disabled","compliance-evidence-mutation-disabled","compliance-export-mutation-disabled","compliance-retention-mutation-disabled","compliance-workflow-mutation-disabled","compliance-provider-calls-disabled","compliance-notification-dispatch-disabled","compliance-raw-evidence-payloads-disabled","compliance-raw-control-rows-disabled","compliance-raw-audit-logs-disabled","compliance-raw-user-data-disabled","compliance-raw-provider-payloads-disabled","compliance-raw-recipient-data-disabled","compliance-credential-values-disabled","compliance-token-values-disabled","compliance-tenant-identifiers-disabled","compliance-object-identifiers-disabled","compliance-principal-identifiers-disabled","compliance-private-network-values-disabled","control-scope-missing","evidence-pack-missing","redaction-state-unknown","stale-data-unmarked","owner-missing","evidence-not-redacted"],
        "requiredEvidence": ["Compliance summary","Domain control summary","Evidence pack reference","Redaction state review","Stale-data markers","Owner assignment","Evidence references"]
    }))
}

async fn integrations_readiness() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "providerCallsEnabled": false, "externalAccessBlocked": true,
        "adapters": [
            {"id":"vmware","component":"vmware-adapter","apiGroup":"/api/integrations/vmware","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"hyperv","component":"hyperv-adapter","apiGroup":"/api/integrations/hyperv","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"proxmox","component":"proxmox-adapter","apiGroup":"/api/integrations/proxmox","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"nutanix","component":"nutanix-ahv-adapter","apiGroup":"/api/integrations/nutanix","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"xen","component":"xen-adapter","apiGroup":"/api/integrations/xen","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"kvm","component":"kvm-adapter","apiGroup":"/api/integrations/kvm","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"veeam","component":"veeam-br-adapter","apiGroup":"/api/integrations/veeam","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"commvault","component":"commvault-adapter","apiGroup":"/api/integrations/commvault","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"rubrik","component":"rubrik-adapter","apiGroup":"/api/integrations/rubrik","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"cohesity","component":"cohesity-adapter","apiGroup":"/api/integrations/cohesity","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"netbackup","component":"netbackup-adapter","apiGroup":"/api/integrations/netbackup","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"zabbix","component":"zabbix-adapter","apiGroup":"/api/integrations/zabbix","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"prometheus","component":"prometheus-adapter","apiGroup":"/api/integrations/prometheus","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"datadog","component":"datadog-adapter","apiGroup":"/api/integrations/datadog","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"grafana","component":"grafana-adapter","apiGroup":"/api/integrations/grafana","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"solarwinds","component":"solarwinds-adapter","apiGroup":"/api/integrations/solarwinds","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
            {"id":"servicenow","component":"servicenow-adapter","apiGroup":"/api/integrations/servicenow","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","file-exchange-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","live-api-not-approved","approval-route-required"]}
        ]
    }))
}

fn adapter_json(id: &str) -> Value {
    let adapters = json!([
        {"id":"vmware","component":"vmware-adapter","apiGroup":"/api/integrations/vmware","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"hyperv","component":"hyperv-adapter","apiGroup":"/api/integrations/hyperv","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"proxmox","component":"proxmox-adapter","apiGroup":"/api/integrations/proxmox","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"nutanix","component":"nutanix-ahv-adapter","apiGroup":"/api/integrations/nutanix","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"xen","component":"xen-adapter","apiGroup":"/api/integrations/xen","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"kvm","component":"kvm-adapter","apiGroup":"/api/integrations/kvm","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"veeam","component":"veeam-br-adapter","apiGroup":"/api/integrations/veeam","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"commvault","component":"commvault-adapter","apiGroup":"/api/integrations/commvault","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"rubrik","component":"rubrik-adapter","apiGroup":"/api/integrations/rubrik","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"cohesity","component":"cohesity-adapter","apiGroup":"/api/integrations/cohesity","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"netbackup","component":"netbackup-adapter","apiGroup":"/api/integrations/netbackup","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"zabbix","component":"zabbix-adapter","apiGroup":"/api/integrations/zabbix","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"prometheus","component":"prometheus-adapter","apiGroup":"/api/integrations/prometheus","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"datadog","component":"datadog-adapter","apiGroup":"/api/integrations/datadog","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"grafana","component":"grafana-adapter","apiGroup":"/api/integrations/grafana","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"solarwinds","component":"solarwinds-adapter","apiGroup":"/api/integrations/solarwinds","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","dry-run-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","provider-endpoint-unconfigured","approval-route-required"]},
        {"id":"servicenow","component":"servicenow-adapter","apiGroup":"/api/integrations/servicenow","status":"blocked","readinessState":"missing-secret-reference","providerCallsEnabled":false,"dryRunOnly":true,"requiresSecretReference":true,"requiresApproval":true,"safeCapabilities":["readiness","file-exchange-contract","stale-data-marker"],"blockedReasons":["secret-reference-missing","live-api-not-approved","approval-route-required"]}
    ]);
    let adapter = adapters
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == id)
        .cloned();
    match adapter {
        Some(a) => {
            json!({"source":"static-seed","providerCallsEnabled":false,"externalAccessBlocked":true,"adapter":a})
        }
        None => {
            json!({"source":"static-seed","providerCallsEnabled":false,"status":"blocked","reason":"unknown-adapter"})
        }
    }
}

async fn integrations_vmware_readiness() -> Json<Value> {
    Json(adapter_json("vmware"))
}
async fn integrations_hyperv_readiness() -> Json<Value> {
    Json(adapter_json("hyperv"))
}
async fn integrations_proxmox_readiness() -> Json<Value> {
    Json(adapter_json("proxmox"))
}
async fn integrations_veeam_readiness() -> Json<Value> {
    Json(adapter_json("veeam"))
}
async fn integrations_zabbix_readiness() -> Json<Value> {
    Json(adapter_json("zabbix"))
}
async fn integrations_prometheus_readiness() -> Json<Value> {
    Json(adapter_json("prometheus"))
}
async fn integrations_datadog_readiness() -> Json<Value> {
    Json(adapter_json("datadog"))
}
async fn integrations_grafana_readiness() -> Json<Value> {
    Json(adapter_json("grafana"))
}
async fn integrations_solarwinds_readiness() -> Json<Value> {
    Json(adapter_json("solarwinds"))
}
async fn integrations_servicenow_readiness() -> Json<Value> {
    Json(adapter_json("servicenow"))
}

async fn integrations_nutanix_readiness() -> Json<Value> {
    Json(json!({
        "provider": "nutanix",
        "adapter": "nutanix-ahv",
        "status": "available",
        "mode": "static-dry-run",
        "capabilities": ["inventory", "health", "provisioning", "lifecycle", "templates"],
        "last_checked": chrono::Utc::now().to_rfc3339(),
        "source": "static-seed"
    }))
}

async fn integrations_xen_readiness() -> Json<Value> {
    Json(json!({
        "provider": "xen",
        "adapter": "xen",
        "status": "available",
        "mode": "static-dry-run",
        "capabilities": ["inventory", "health", "provisioning", "lifecycle", "templates"],
        "last_checked": chrono::Utc::now().to_rfc3339(),
        "source": "static-seed"
    }))
}

async fn integrations_kvm_readiness() -> Json<Value> {
    Json(json!({
        "provider": "kvm",
        "adapter": "kvm",
        "status": "available",
        "mode": "static-dry-run",
        "capabilities": ["inventory", "health", "provisioning", "lifecycle", "templates"],
        "last_checked": chrono::Utc::now().to_rfc3339(),
        "source": "static-seed"
    }))
}

async fn integrations_commvault_readiness() -> Json<Value> {
    Json(json!({
        "provider": "commvault",
        "adapter": "commvault",
        "status": "available",
        "mode": "static-dry-run",
        "capabilities": ["backup", "restore", "policy", "reporting", "retention"],
        "last_checked": chrono::Utc::now().to_rfc3339(),
        "source": "static-seed"
    }))
}

async fn integrations_rubrik_readiness() -> Json<Value> {
    Json(json!({
        "provider": "rubrik",
        "adapter": "rubrik",
        "status": "available",
        "mode": "static-dry-run",
        "capabilities": ["backup", "restore", "policy", "reporting", "retention"],
        "last_checked": chrono::Utc::now().to_rfc3339(),
        "source": "static-seed"
    }))
}

async fn integrations_cohesity_readiness() -> Json<Value> {
    Json(json!({
        "provider": "cohesity",
        "adapter": "cohesity",
        "status": "available",
        "mode": "static-dry-run",
        "capabilities": ["backup", "restore", "policy", "reporting", "retention"],
        "last_checked": chrono::Utc::now().to_rfc3339(),
        "source": "static-seed"
    }))
}

async fn integrations_netbackup_readiness() -> Json<Value> {
    Json(json!({
        "provider": "netbackup",
        "adapter": "netbackup",
        "status": "available",
        "mode": "static-dry-run",
        "capabilities": ["backup", "restore", "policy", "reporting", "retention"],
        "last_checked": chrono::Utc::now().to_rfc3339(),
        "source": "static-seed"
    }))
}

async fn integrations_adapter_matrix() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "providerCallsEnabled": false,
        "adapters": ["vmware","hyperv","proxmox","nutanix","xen","kvm","veeam-br","veeam-one","commvault","rubrik","cohesity","netbackup","zabbix","prometheus","datadog","grafana","solarwinds","servicenow-file-exchange"],
        "states": ["ready","degraded","stale","blocked","unknown"],
        "dimensions": ["secretReference","endpointReachability","apiVersionCompatibility","permissionScope","dryRunCapability","staleDataMarker","ownerSupport","evidenceReadiness"],
        "guards": ["secret-reference-known","endpoint-not-raw","api-version-reviewed","permissions-reviewed","stale-data-marked","owner-known","support-group-known","evidence-redacted"],
        "planSections": ["readinessSummary","adapterScope","authReadiness","compatibilityReadiness","permissionReadiness","reachabilityReadiness","staleDataReview","safeCapabilities","evidenceReferences"],
        "blockedReasons": ["provider-calls-disabled","live-provider-validation-disabled","secret-reference-missing","endpoint-unconfigured","api-version-unknown","permission-scope-unknown","stale-data-unmarked","owner-unknown","support-group-unknown","evidence-not-redacted"],
        "capabilities": ["readiness","read-only","dry-run","stale-data-marker","evidence-reference"]
    }))
}

async fn integrations_adapter_contract_test() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "providerCallsEnabled": false,
        "targets": ["vmware-readiness","hyperv-readiness","proxmox-readiness","nutanix-readiness","xen-readiness","kvm-readiness","veeam-readiness","commvault-readiness","rubrik-readiness","cohesity-readiness","netbackup-readiness","zabbix-readiness","servicenow-file-exchange","adapter-readiness-matrix","dry-run-plan"],
        "testTypes": ["readiness-contract","dry-run-contract","blocked-default","secret-reference-contract","stale-data-marker","redaction-contract","evidence-contract"],
        "fixtureTypes": ["static-json-fixture","static-yaml-fixture","mock-provider-result","negative-case-fixture","redacted-evidence-fixture"],
        "requiredGuards": ["fixture-set-redacted","provider-calls-blocked","credential-values-absent","network-egress-blocked","expected-state-declared","blocked-reasons-declared","stale-data-marked","evidence-redacted"],
        "planSections": ["testSummary","fixtureScope","readinessAssertions","dryRunAssertions","blockedDefaultAssertions","redactionAssertions","evidenceAssertions","handoverNotes"],
        "blockedReasons": ["provider-calls-disabled","live-provider-validation-disabled","live-credentials-disabled","credential-values-disabled","network-egress-disabled","raw-provider-payloads-disabled","raw-fixture-rows-disabled","provider-mutation-disabled","fixture-set-missing","expected-state-missing","blocked-reasons-missing","evidence-not-redacted"]
    }))
}

async fn integrations_servicenow_cmdb_file() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "providerCallsEnabled": false, "liveApiDisabled": true, "rawFileContentAllowed": false,
        "normalizedImportFields": ["ciName","fqdn","ciClass","lifecycleStatus","environment","application","businessOwner","technicalOwner","supportGroup","country","siteCode","datacenter","osFamily","osVersion","criticality","patchGroup","maintenanceWindow","rebootPolicy","backupPolicy","monitoringProfile","relationshipKey"],
        "workbookShape": ["worksheet-count-one","row-count-fifteen","data-row-count-fourteen","column-count-twenty-eight"],
        "sanitizedFieldCategories": ["identity","ownership","classification","governance-evidence","operating-system","lifecycle","service-context","location","normalized-fallback"],
        "normalizedHeaderExpectations": ["actual-headers-remain-deployment-configuration","map-to-normalized-import-fields","unmapped-columns-require-review","duplicate-normalized-fields-require-review","actual-header-value-storage-disabled"],
        "syntheticCategoryExamples": ["identity synthetic-ci-name","ownership synthetic-business-owner","classification synthetic-ci-class","governance-evidence synthetic-file-hash-reference","operating-system synthetic-os-family","lifecycle synthetic-lifecycle-state","service-context synthetic-environment","location synthetic-site-code","normalized-fallback synthetic-review-note"],
        "rejectionReasons": ["missing-ci-identity","ambiguous-ci-identity","unknown-site-code","missing-owner","missing-support-group","invalid-environment","missing-evidence-reference"]
    }))
}

async fn integrations_servicenow_future_api() -> Json<Value> {
    Json(json!({
        "source": "static-seed", "providerCallsEnabled": false,
        "apiSurfaces": ["request-callback-readiness","change-callback-readiness","cmdb-update-readiness","import-set-readiness","status-sync-readiness","approval-sync-readiness","knowledge-link-readiness"],
        "signals": ["api-approval-recorded","secret-reference-ready","instance-config-externalized","table-mapping-reviewed","payload-redaction-reviewed","rate-limit-policy-reviewed","rollback-plan-ready"],
        "requiredGuards": ["live-api-approval-recorded","secret-reference-ready","instance-identifiers-externalized","table-mapping-reviewed","payload-redaction-reviewed","dry-run-contract-reviewed","rollback-plan-ready","evidence-redacted"],
        "planSections": ["integrationSummary","authReference","instanceConfiguration","tableMapping","callbackPlan","importSetPlan","statusSyncPlan","rollbackReadiness","evidenceReferences"],
        "blockedReasons": ["live-api-disabled","provider-calls-disabled","request-callbacks-disabled","change-callbacks-disabled","cmdb-updates-disabled","import-set-writes-disabled","status-sync-disabled","table-api-calls-disabled","credential-values-disabled","instance-identifiers-disabled","table-identifiers-disabled","sys-identifiers-disabled","raw-request-payloads-disabled","raw-response-payloads-disabled","raw-ticket-data-disabled","raw-recipient-data-disabled","raw-provider-payloads-disabled","approval-missing","secret-reference-missing","table-mapping-missing","payload-redaction-missing","rollback-plan-missing","evidence-not-redacted"]
    }))
}

// ─── Remaining endpoints (inventory, software, workflows, integrations-vmware, operations, images, patching, protect, observe, cmdb, admin, auth, analytics) ───

async fn inventory_coverage() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"domains":["vmware","hyperv","proxmox","nutanix-ahv","xen","kvm","veeam","commvault","rubrik","cohesity","netbackup","zabbix","servicenow-cmdb","site-catalog","policy-catalog"],"freshnessStates":["current","stale","unknown","blocked"],"gapTypes":["backup-coverage-gap","monitoring-coverage-gap","cmdb-drift","stale-data","ownership-gap","policy-gap"],"driftSignals":["identity-mismatch","owner-mismatch","backup-policy-mismatch","monitoring-profile-mismatch","site-placement-mismatch"],"evidence":["Inventory snapshot","Coverage gap list","Stale-data markers","CMDB reconciliation summary","Evidence references"]}),
    )
}

async fn inventory_coverage_local() -> Json<Value> {
    Json(
        json!({"source":"static-seed","coverage":"local-static-seed","domains":["vmware","hyperv","proxmox","nutanix-ahv","xen","kvm","veeam","commvault","rubrik","cohesity","netbackup","zabbix","servicenow-cmdb","site-catalog","policy-catalog"],"providerCallsEnabled":false}),
    )
}

async fn inventory_resource_overview() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"resourceTypes":["site","vm","application","cluster","host","network","backup","monitoring","cmdb-ci"],"statusSignals":["inventory-freshness","backup-status","monitoring-status","cmdb-status","ownership-status","lifecycle-state","policy-state"],"views":["site-summary","vm-summary","application-summary","cluster-summary","host-summary","network-summary","protection-observability-summary","cmdb-status-summary"],"requiredGuards":["inventory-snapshot-reviewed","site-scope-reviewed","resource-type-summary-reviewed","freshness-state-reviewed","backup-status-reviewed","monitoring-status-reviewed","cmdb-status-reviewed","evidence-redacted"],"blockedReasons":["inventory-overview-live-sync-disabled","inventory-overview-live-query-disabled","inventory-overview-provider-calls-disabled","inventory-overview-mutation-disabled","inventory-overview-remediation-disabled","inventory-overview-workflow-mutation-disabled","inventory-overview-raw-rows-disabled","inventory-overview-raw-provider-payloads-disabled","inventory-overview-raw-owner-data-disabled","inventory-overview-raw-log-content-disabled","inventory-overview-raw-recipient-data-disabled","inventory-overview-credential-values-disabled","inventory-overview-token-values-disabled","inventory-overview-tenant-identifiers-disabled","inventory-overview-object-identifiers-disabled","inventory-overview-principal-identifiers-disabled","inventory-overview-private-network-values-disabled","inventory-overview-serials-disabled","scope-missing","resource-type-summary-missing","freshness-state-unknown","evidence-not-redacted"]}),
    )
}
// Auto-generated; append to end of contracts.rs

async fn inventory_ownership_risk() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"riskDomains":["vm","application","cluster","host","network","backup","monitoring","cmdb-ci"],"scoreSignals":["owner-present","support-group-present","cmdb-match","backup-policy-match","monitoring-profile-match","freshness-current","lifecycle-state-known"],"riskBands":["low","medium","high","blocked"],"timelineEvents":["inventory-seen","owner-changed","cmdb-drift-detected","backup-gap-detected","monitoring-gap-detected","stale-marker-set","risk-band-changed"],"requiredGuards":["inventory-snapshot-reviewed","ownership-summary-reviewed","support-group-reviewed","drift-timeline-reviewed","stale-marker-reviewed","risk-band-reviewed","evidence-redacted"],"blockedReasons":["inventory-risk-provider-sync-disabled","inventory-risk-owner-lookup-disabled","inventory-risk-cmdb-mutation-disabled","inventory-risk-remediation-mutation-disabled","inventory-risk-workflow-mutation-disabled","inventory-risk-provider-calls-disabled","inventory-risk-raw-rows-disabled","inventory-risk-raw-owner-data-disabled","inventory-risk-raw-provider-payloads-disabled","inventory-risk-raw-timeline-rows-disabled","inventory-risk-raw-log-content-disabled","inventory-risk-raw-recipient-data-disabled","inventory-risk-credential-values-disabled","inventory-risk-tenant-identifiers-disabled","inventory-risk-object-identifiers-disabled","inventory-risk-private-network-values-disabled","inventory-risk-serials-disabled","inventory-snapshot-missing","ownership-summary-missing","support-group-unknown","stale-marker-missing","risk-band-unknown","evidence-not-redacted"]}),
    )
}

async fn inventory_os_baseline() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"osFamilies":["windows","linux"],"domains":["tools","vmware-tools","hyper-v-integration-services","proxmox-qemu-guest-agent","agents","local-groups","firewall","security-baseline","hardening-state","patch-state","monitoring-agent","backup-agent"],"driftSignals":["missing-agent","vmware-tools-missing","vmware-tools-unsupported","hyper-v-integration-service-disabled","proxmox-qemu-guest-agent-missing","unsupported-version","unauthorized-local-admin","firewall-rule-drift","hardening-rule-drift","pending-reboot","patch-level-drift","evidence-missing"],"requiredGuards":["inventory-coverage-current","baseline-profile-known","os-family-supported","owner-known","platform-guest-tooling-posture-known","worker-capability-known","remediation-plan-dry-run","approval-route-assigned","evidence-redacted"],"planSections":["complianceSummary","baselineProfile","platformGuestTooling","driftFindings","riskNotes","remediationPlan","approvalRoute","handoverNotes","evidenceReferences"],"blockedReasons":["provider-calls-disabled","worker-execution-disabled","stale-inventory","unsupported-os-family","missing-baseline-profile","owner-unknown","platform-guest-tooling-posture-missing","worker-capability-unknown","remediation-plan-missing","approval-missing","evidence-not-redacted"]}),
    )
}

async fn software_approved_deployment() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"actions":["install","update","remove","verify-version","reboot-required-review"],"scopes":["windows-package","linux-package","agent","utility","security-tool","monitoring-tool"],"requiredGuards":["package-approved","version-policy-known","target-scope-known","os-family-supported","worker-capability-known","reboot-impact-reviewed","approval-route-assigned","rollback-plan-ready","evidence-redacted"],"planSections":["deploymentSummary","packagePolicy","targetScope","versionDecision","rebootImpact","rollbackPlan","verificationPlan","handoverNotes"],"blockedReasons":["package-not-approved","unsupported-action","target-scope-unknown","version-policy-missing","worker-execution-disabled","reboot-impact-unknown","approval-missing","rollback-plan-missing","evidence-not-redacted"]}),
    )
}

async fn workflows_server_lifecycle() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"workflows":["windows-server-deployment","linux-server-deployment"],"supportedHypervisors":["VMware","Hyper-V","Proxmox","Nutanix AHV","Xen","KVM"],"supportedLinuxDistributions":["sles","rhel","rocky-linux","alma-linux","ubuntu","debian"],"requiredInputs":["businessPurpose","requester","owner","site","environment","criticality","hypervisorPlatform","imageVersion","vmSizing","network","backupPolicy","monitoringProfile","cmdbContext"],"requiredGuards":["request-preflight-ready","capacity-admission-ready","inventory-coverage-current","approval-route-assigned","evidence-redacted","secret-reference-configured"],"planSections":["placementPlan","osCustomizationPlan","backupPlan","monitoringPlan","cmdbUpdatePlan","riskNotes","rollbackNotes"],"blockedReasons":["missing-required-input","stale-inventory","capacity-not-approved","backup-policy-missing","monitoring-profile-missing","cmdb-context-ambiguous","unsupported-hypervisor","live-hypervisor-execution-disabled","live-execution-disabled"]}),
    )
}

async fn workflows_app_env_deployment() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"deploymentPlans":["tier-topology-plan","vm-placement-plan","dns-ipam-plan","certificate-plan","firewall-rule-plan","monitoring-plan","backup-plan","cmdb-relationship-plan","handover-plan"],"tiers":["front-tier","mid-tier","back-tier","data-tier","shared-service-tier"],"supportedHypervisors":["VMware","Hyper-V","Proxmox","Nutanix AHV","Xen","KVM"],"requiredGuards":["request-preflight-ready","tier-topology-reviewed","placement-plan-reviewed","dns-ipam-plan-reviewed","certificate-plan-reviewed","network-flow-reviewed","monitoring-plan-reviewed","backup-plan-reviewed","cmdb-relationship-reviewed","approval-route-assigned","rollback-plan-ready","evidence-redacted"],"planSections":["environmentSummary","tierTopology","placementPlan","dnsIpamPlan","certificatePlan","networkFlowPlan","monitoringPlan","backupPlan","cmdbRelationshipPlan","rollbackPlan","handoverPlan","evidenceReferences"],"blockedReasons":["provider-calls-disabled","worker-execution-disabled","live-deployment-disabled","live-vmware-change-disabled","live-hyperv-change-disabled","live-proxmox-change-disabled","live-dns-ipam-change-disabled","live-certificate-change-disabled","live-firewall-change-disabled","live-monitoring-change-disabled","live-backup-change-disabled","live-cmdb-change-disabled","raw-network-data-disabled","raw-dns-records-disabled","raw-certificate-data-disabled","raw-firewall-rules-disabled","raw-cmdb-rows-disabled","raw-provider-payloads-disabled","app-env-host-identifiers-disabled","fqdn-values-disabled","ip-address-values-disabled","credential-values-disabled","raw-recipient-data-disabled","tier-topology-missing","dns-ipam-plan-missing","certificate-plan-missing","firewall-plan-missing","monitoring-plan-missing","backup-plan-missing","cmdb-relationship-missing","approval-missing","rollback-plan-missing","evidence-not-redacted"]}),
    )
}

async fn workflows_app_env_retirement() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"phases":["intake-review","relationship-review","dependency-freeze-plan","data-retention-plan","backup-retention-plan","access-closure-plan","monitoring-disable-plan","cmdb-retirement-plan","rollback-window-review","final-closure-hold"],"domains":["application-environment","dependency-graph","data-retention","backup-retention","access-closure","monitoring-state","cmdb-relationship","owner-approval","rollback-window","evidence-readiness"],"supportedHypervisors":["VMware","Hyper-V","Proxmox","Nutanix AHV","Xen","KVM"],"requiredGuards":["request-preflight-ready","relationship-graph-reviewed","dependency-impact-reviewed","data-retention-reviewed","backup-retention-reviewed","access-closure-reviewed","monitoring-disable-reviewed","cmdb-retirement-reviewed","rollback-window-reviewed","final-closure-blocked","approval-route-assigned","evidence-redacted"],"planSections":["retirementSummary","relationshipReview","dependencyImpact","dataRetentionPlan","backupRetentionPlan","accessClosurePlan","monitoringDisablePlan","cmdbRetirementPlan","rollbackWindow","finalClosureHold","evidenceReferences"],"blockedReasons":["provider-calls-disabled","worker-execution-disabled","live-retirement-disabled","live-vmware-change-disabled","live-hyperv-change-disabled","live-proxmox-change-disabled","live-monitoring-change-disabled","live-backup-change-disabled","live-cmdb-change-disabled","live-access-change-disabled","live-data-deletion-disabled","raw-dependency-rows-disabled","raw-relationship-rows-disabled","raw-inventory-rows-disabled","raw-backup-rows-disabled","raw-monitoring-rows-disabled","raw-cmdb-rows-disabled","raw-provider-payloads-disabled","application-identifiers-disabled","environment-identifiers-disabled","app-env-host-identifiers-disabled","object-identifiers-disabled","private-network-values-disabled","credential-values-disabled","raw-recipient-data-disabled","dependency-review-missing","data-retention-missing","backup-retention-missing","access-closure-review-missing","monitoring-disable-review-missing","cmdb-retirement-review-missing","rollback-window-missing","final-closure-blocked","approval-missing","evidence-not-redacted"]}),
    )
}

async fn workflows_sql_server() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"deploymentPlans":["standalone-instance-plan","failover-cluster-plan","availability-group-plan","disk-layout-plan","runtime-identity-plan","spn-policy-review","backup-policy-plan","monitoring-plan","cmdb-publication-plan"],"topologies":["standalone","failover-cluster","availability-group"],"supportedHypervisors":["VMware","Hyper-V","Proxmox","Nutanix AHV","Xen","KVM"],"requiredGuards":["request-preflight-ready","topology-reviewed","capacity-admission-ready","disk-layout-reviewed","runtime-identity-reviewed","spn-policy-reviewed","backup-plan-reviewed","monitoring-plan-reviewed","cmdb-publication-reviewed","approval-route-assigned","rollback-plan-ready","evidence-redacted"],"planSections":["deploymentSummary","topologyReview","placementPlan","diskLayoutPlan","runtimeIdentityPlan","spnPolicyReview","backupPlan","monitoringPlan","cmdbPublicationPlan","rollbackPlan","evidenceReferences"],"blockedReasons":["provider-calls-disabled","worker-execution-disabled","live-deployment-disabled","live-vmware-change-disabled","live-hyperv-change-disabled","live-proxmox-change-disabled","live-sql-change-disabled","live-directory-change-disabled","live-dns-change-disabled","live-backup-change-disabled","live-monitoring-change-disabled","live-cmdb-change-disabled","availability-group-change-disabled","sql-runtime-identity-change-disabled","spn-change-disabled","database-creation-disabled","sql-agent-job-change-disabled","raw-sql-instance-data-disabled","raw-database-data-disabled","raw-path-data-disabled","raw-backup-rows-disabled","raw-provider-payloads-disabled","principal-identifiers-disabled","sql-host-identifiers-disabled","sql-listener-identifiers-disabled","credential-values-disabled","port-values-disabled","topology-missing","disk-layout-missing","runtime-identity-missing","spn-policy-missing","backup-plan-missing","monitoring-plan-missing","cmdb-context-missing","approval-missing","rollback-plan-missing","evidence-not-redacted"]}),
    )
}

async fn workflows_azure_lz() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"validationSurfaces":["source-inventory-review","management-group-taxonomy-review","subscription-readiness-review","policy-baseline-review","naming-tagging-review","connectivity-guardrail-review","identity-guardrail-review","security-guardrail-review","azure-vm-readiness-review","cmdb-servicenow-file-exchange-review"],"requiredGuards":["source-inventory-acknowledged","safe-facts-extraction-required","raw-alz-sources-blocked","tenant-identifiers-blocked","subscription-identifiers-blocked","policy-baseline-reviewed","naming-tagging-reviewed","connectivity-reviewed","identity-reviewed","security-reviewed","azure-vm-readiness-reviewed","approval-route-assigned","evidence-redacted"],"planSections":["validationSummary","sourceInventoryReview","landingZoneScope","policyBaselineReview","namingTaggingReview","connectivityReview","identityReview","securityReview","azureVmReadiness","cmdbPublicationPlan","evidenceReferences"],"blockedReasons":["provider-calls-disabled","terraform-execution-disabled","terraform-plan-against-tenant-disabled","terraform-apply-disabled","azure-resource-change-disabled","management-group-change-disabled","subscription-change-disabled","policy-assignment-change-disabled","role-assignment-change-disabled","network-change-disabled","vm-deployment-disabled","cmdb-change-disabled","servicenow-change-disabled","raw-alz-sources-disabled","raw-terraform-state-disabled","raw-terraform-plan-disabled","raw-azure-payloads-disabled","tenant-identifiers-disabled","subscription-identifiers-disabled","object-identifiers-disabled","principal-identifiers-disabled","resource-identifiers-disabled","private-ip-values-disabled","credential-values-disabled","safe-facts-review-missing","policy-baseline-missing","naming-tagging-missing","connectivity-review-missing","identity-review-missing","security-review-missing","vm-readiness-missing","approval-missing","evidence-not-redacted"]}),
    )
}

async fn workflows_preflight_local_decision(Query(q): Query<PreflightQuery>) -> Json<Value> {
    let mut missing = Vec::new();
    if q.requested_offering
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        missing.push("requestedOffering");
    }
    if q.owner.as_deref().unwrap_or("").trim().is_empty() {
        missing.push("owner");
    }
    if q.site.as_deref().unwrap_or("").trim().is_empty() {
        missing.push("site");
    }
    if q.environment.as_deref().unwrap_or("").trim().is_empty() {
        missing.push("environment");
    }
    if q.criticality.as_deref().unwrap_or("").trim().is_empty() {
        missing.push("criticality");
    }
    if q.dry_run_plan.as_deref().unwrap_or("").trim().is_empty() {
        missing.push("dryRunPlan");
    }
    if q.approval_route.as_deref().unwrap_or("").trim().is_empty() {
        missing.push("approvalRoute");
    }
    if q.evidence_manifest
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        missing.push("evidenceManifest");
    }
    if q.secret_reference_state
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        missing.push("secretReferenceState");
    }
    let mut guard_blocks = Vec::new();
    if q.dry_run_plan.as_deref().map(|s| s.to_lowercase()) != Some("ready".into()) {
        guard_blocks.push("provider-safe-dry-run-not-ready");
    }
    if q.evidence_manifest.as_deref().map(|s| s.to_lowercase()) != Some("redacted".into()) {
        guard_blocks.push("redacted-evidence-not-ready");
    }
    if q.secret_reference_state
        .as_deref()
        .map(|s| s.to_lowercase())
        != Some("configured".into())
    {
        guard_blocks.push("secret-reference-not-configured");
    }
    let blocked = !missing.is_empty() || !guard_blocks.is_empty();
    Json(
        json!({"source":"local-mock","providerCallsEnabled":false,"liveExecutionAllowed":false,"decision":if blocked{"block"}else{"review"},"status":if blocked{"blocked"}else{"ready-for-approval-review"},"requestedOffering":q.requested_offering,"requiredInputs":["requestedOffering","owner","site","environment","criticality","dryRunPlan","approvalRoute","evidenceManifest","secretReferenceState"],"missingInputs":missing,"guardBlocks":guard_blocks,"remediation":if blocked{"Complete missing inputs and guard evidence before approval."}else{"Route to approval; live execution remains disabled in local mode."},"evidence":["Validation result","Provider-safe plan","Approval decisions","Evidence manifest","Reference configured state"]}),
    )
}

async fn integrations_vmware_cluster_capacity() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"livePlacementEnabled":false,"workflows":["windows-server-deployment","linux-server-deployment","vm-day2-change","cluster-placement-review","capacity-exception-review"],"decisions":["admit","review","block","defer"],"signals":["cpu-headroom","memory-headroom","datastore-headroom","vsan-headroom","ha-failover-headroom","drs-balance","reservation-impact","stale-capacity-data"],"requiredGuards":["cluster-summary-known","compute-headroom-reviewed","datastore-headroom-reviewed","vsan-headroom-reviewed","ha-failover-reviewed","drs-balance-reviewed","reservation-impact-reviewed","growth-window-set","owner-known","evidence-redacted"],"planSections":["admissionSummary","clusterScope","computeHeadroom","storageHeadroom","haDrsRisk","reservationImpact","placementDecision","exceptionsAndRemediation","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-provider-validation-disabled","live-placement-disabled","cluster-summary-missing","compute-headroom-unknown","storage-headroom-unknown","ha-failover-headroom-insufficient","drs-balance-unknown","reservation-impact-unknown","stale-capacity-data","owner-unknown","evidence-not-redacted"],"requiredEvidence":["Capacity admission summary","Cluster scope summary","Compute headroom","Storage headroom","HA and DRS risk","Reservation impact","Placement decision","Exceptions and remediation","Evidence references"]}),
    )
}

async fn integrations_vmware_customization_spec() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["request-preflight","windows-server-deployment","ou-placement-review","customization-spec-drift-review","site-catalog-review"],"supportedHypervisors":["VMware","Hyper-V","Proxmox","Nutanix AHV","Xen","KVM"],"guestCustomizationParity":["vmware-vcenter-customization-spec-safe-facts","hyper-v-answer-file-safe-facts","proxmox-cloud-init-safe-facts","nutanix-ahv-cloud-init-safe-facts","xen-cloud-init-safe-facts","kvm-cloud-init-safe-facts"],"safeFacts":["customizationSpecReference","countryCode","siteCode","domainReference","ouPatternReference","timezoneCode","dhcpNetworkBehavior","organizationLabel","windowsBehavior"],"driftSignals":["missing-expected-spec","unknown-spec","country-site-mismatch","ou-pattern-mismatch","domain-mismatch","timezone-mismatch","network-behavior-mismatch","windows-behavior-mismatch","stale-spec-inventory"],"requiredGuards":["site-known","safe-facts-from-catalog","ou-pattern-derived","free-form-ou-blocked","encrypted-xml-excluded","drift-check-reviewed","stale-data-marked","owner-known","evidence-redacted"],"planSections":["safeFactSummary","siteMapping","ouPlacementDecision","timezoneAndNetworkBehavior","windowsBehaviorReview","driftReview","blockedFindings","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-provider-validation-disabled","live-guest-customization-disabled","unsupported-hypervisor","raw-xml-blocked","encrypted-xml-blocked","credential-material-blocked","site-unknown","spec-reference-unknown","ou-pattern-mismatch","stale-spec-inventory","owner-unknown","evidence-not-redacted"]}),
    )
}

async fn integrations_vmware_object_placement() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"livePlacementEnabled":false,"vcenterDimensions":["folder","cluster","resource-pool","datastore","storage-policy","network","tag-policy","site","environment"],"hyperVDimensions":["folder","cluster","resource-pool","storage-policy","network","tag-policy","site","environment"],"proxmoxDimensions":["folder","cluster","resource-pool","datastore","network","tag-policy","site","environment"],"nutanixAhvDimensions":["folder","cluster","resource-pool","datastore","network","tag-policy","site","environment"],"xenDimensions":["folder","cluster","resource-pool","datastore","network","tag-policy","site","environment"],"kvmDimensions":["folder","cluster","resource-pool","datastore","network","tag-policy","site","environment"],"requiredGuards":["site-known","environment-known","folder-policy-known","cluster-capacity-admitted","resource-pool-policy-known","datastore-policy-known","storage-policy-known","network-profile-known","tag-policy-known","dry-run-plan-produced","evidence-redacted"],"planSections":["placementSummary","folderPlan","clusterResourcePoolPlan","datastoreStoragePolicyPlan","networkPlan","tagPolicyPlan","policyExceptions","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-placement-disabled","raw-inventory-rows-disabled","object-identifiers-disabled","site-unknown","environment-unknown","folder-policy-missing","cluster-capacity-missing","resource-pool-policy-missing","datastore-policy-missing","storage-policy-missing","network-profile-missing","tag-policy-missing","evidence-not-redacted"]}),
    )
}

async fn integrations_vmware_vsan_esxi() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["vsan-cluster-lifecycle","esxi-patch-lifecycle","firmware-baseline-review","hardware-readiness-review","maintenance-mode-plan","lifecycle-exception-review"],"supportedHypervisors":["VMware","Hyper-V","Proxmox","Nutanix AHV","Xen","KVM"],"platformLifecycleParity":["vmware-vsan-esxi-lifecycle-safe-summary","hyper-v-cluster-host-lifecycle-safe-summary","proxmox-cluster-node-lifecycle-safe-summary","nutanix-ahv-cluster-lifecycle-safe-summary","xen-cluster-host-lifecycle-safe-summary","kvm-cluster-host-lifecycle-safe-summary"],"domains":["vsan-health","esxi-version","firmware-baseline","driver-compatibility","hardware-hcl","cluster-maintenance","network-readiness","storage-policy"],"requiredGuards":["cluster-scope-known","site-known","platform-profile-known","target-baseline-known","hardware-readiness-reviewed","network-readiness-reviewed","capacity-admission-ready","maintenance-window-approved","rollback-plan-ready","dry-run-plan-produced","evidence-redacted"],"planSections":["lifecycleSummary","currentBaseline","targetBaseline","hardwareFirmwareReview","networkStorageReadiness","maintenanceModePlan","capacityAndFailureDomainImpact","rollbackPlan","policyExceptions","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-lifecycle-disabled","unsupported-hypervisor","raw-inventory-rows-disabled","host-identifiers-disabled","cluster-scope-missing","site-unknown","platform-profile-missing","target-baseline-missing","hardware-readiness-missing","network-readiness-missing","capacity-admission-missing","maintenance-window-missing","rollback-plan-missing","evidence-not-redacted"]}),
    )
}

async fn integrations_vmware_day2() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveChangeEnabled":false,"actions":["resize-cpu","resize-memory","add-disk","extend-disk","add-nic","remove-nic","move-network","migrate-storage","migrate-host","update-tags","plan-cross-hypervisor-migration"],"requiredGuards":["request-preflight-ready","capacity-admission-ready","cmdb-ci-known","backup-state-known","monitoring-impact-reviewed","approval-route-assigned","lock-scope-defined","rollback-plan-ready","cold-offline-default","source-backup-verified","source-quarantine-planned","downtime-window-approved","target-guest-tooling-planned","cutover-validation-ready","evidence-redacted"],"planSections":["changeSummary","currentState","desiredState","capacityImpact","networkImpact","backupMonitoringImpact","cmdbUpdatePlan","lockPlan","rollbackNotes","verificationPlan","migrationMethodMatrix","downtimePlan","sourceQuarantine","targetGuestTooling","cutoverValidation"],"blockedReasons":["provider-calls-disabled","live-change-disabled","stale-inventory","capacity-not-approved","cmdb-context-ambiguous","backup-state-unknown","monitoring-impact-unknown","maintenance-window-missing","lock-scope-missing","rollback-plan-missing","migration-method-unknown","downtime-class-missing","source-backup-unverified","source-quarantine-missing","target-guest-tooling-missing","cutover-validation-missing","approval-missing","evidence-not-redacted"]}),
    )
}

async fn integrations_vmware_snapshot() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["planned-snapshot-exception","snapshot-expiry-review","stale-snapshot-remediation","owner-attestation","backup-conflict-review"],"signals":["planned-exception","expiry-due","stale-snapshot","owner-unknown","backup-conflict","policy-exception","evidence-missing"],"requiredGuards":["cmdb-ci-known","owner-known","backup-state-known","expiry-policy-known","approval-route-assigned","lock-scope-defined","rollback-notes-ready","evidence-redacted"],"planSections":["snapshotSummary","policyDecision","expiryReview","backupImpact","remediationPlan","approvalRoute","lockPlan","handoverNotes"],"blockedReasons":["provider-calls-disabled","live-snapshot-disabled","live-deletion-disabled","stale-inventory","missing-owner","missing-expiry","backup-conflict-unknown","approval-missing","lock-scope-missing","rollback-notes-missing","evidence-not-redacted"]}),
    )
}

async fn integrations_vmware_decommission() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"stages":["intake-review","dependency-review","backup-retention-review","monitoring-disable-plan","cmdb-retirement-plan","quarantine-window-plan","rollback-window-review","final-disposition-review"],"domains":["vcenter-placement","backup-retention","monitoring-state","cmdb-state","dns-dependency","owner-approval","rollback-window","evidence-readiness"],"requiredGuards":["request-preflight-ready","cmdb-ci-known","owner-approval-assigned","dependency-impact-reviewed","backup-retention-reviewed","monitoring-disable-reviewed","quarantine-window-approved","rollback-plan-ready","final-disposition-blocked","evidence-redacted"],"planSections":["quarantineSummary","dependencyReview","backupRetentionReview","monitoringPlan","cmdbRetirementPlan","quarantineWindow","rollbackPlan","finalDispositionHold","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-decommission-disabled","live-delete-disabled","raw-inventory-rows-disabled","object-identifiers-disabled","cmdb-ci-unknown","owner-approval-missing","dependency-review-missing","backup-retention-missing","monitoring-disable-review-missing","quarantine-window-missing","rollback-plan-missing","final-disposition-blocked","evidence-not-redacted"]}),
    )
}

async fn operations_certificate_lifecycle() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"targets":["platform-ingress","web-service","iis-site","vcenter-appliance","hyperv-management-service","proxmox-management-service","infrastructure-appliance","hardware-management","database-listener"],"actions":["request-plan","renew-plan","replace-plan","install-plan","revoke-plan","evidence-review"],"requiredGuards":["certificate-scope-known","target-profile-known","issuer-profile-known","subject-policy-reviewed","private-key-material-blocked","approval-route-assigned","maintenance-window-known","rollback-plan-ready","evidence-redacted"],"planSections":["certificateSummary","scopeReview","issuerReadiness","subjectPolicyReview","renewalOrReplacementPlan","installationDryRun","rollbackPlan","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-certificate-action-disabled","certificate-scope-unknown","target-profile-unknown","issuer-profile-missing","subject-policy-unreviewed","private-key-material-present","csr-pem-present","certificate-identifier-present","approval-missing","maintenance-window-missing","rollback-plan-missing","evidence-not-redacted"]}),
    )
}

async fn operations_runbook_launch() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workerExecutionEnabled":false,"workflows":["operator-runbook-launch","standard-l1-l2-task","incident-context-review"],"planTypes":["health-check-plan","collect-logs-plan","restart-service-plan","clear-disk-plan","trigger-backup-plan","alert-suppression-plan"],"requiredGuards":["role-authorized","approval-route-assigned","worker-capability-known","dry-run-ready","dependency-health-known","evidence-redacted"],"planSections":["runbookSummary","targetScope","workerCapability","expectedActions","riskNotes","rollbackNotes","handoverNotes"],"blockedReasons":["worker-execution-disabled","unsupported-runbook","role-not-authorized","approval-missing","worker-capability-unknown","dependency-health-unknown","evidence-not-redacted"]}),
    )
}

async fn operations_standard_task() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"taskTypes":["health-check-plan","collect-logs-plan","restart-service-plan","clear-disk-plan","trigger-backup-plan","alert-suppression-plan"],"scopes":["windows-service","linux-service","filesystem-capacity","log-collection","backup-request","monitoring-maintenance","application-health"],"requiredGuards":["ticket-context-known","requester-authorized","task-type-supported","target-scope-summarized","worker-capability-known","dry-run-plan-reviewed","approval-route-assigned","maintenance-window-reviewed","rollback-or-handover-ready","evidence-redacted"],"planSections":["taskSummary","targetScope","workerRouting","preChecks","plannedActions","riskAndImpact","rollbackOrHandover","evidenceReferences"],"blockedReasons":["provider-calls-disabled","worker-execution-disabled","live-service-change-disabled","live-disk-change-disabled","live-backup-action-disabled","live-alert-suppression-disabled","raw-target-data-disabled","raw-log-content-disabled","raw-recipient-data-disabled","raw-worker-payloads-disabled","raw-provider-payloads-disabled","unsupported-task-type","requester-not-authorized","approval-missing","worker-capability-unknown","maintenance-window-missing","rollback-or-handover-missing","evidence-not-redacted"]}),
    )
}

async fn operations_emergency_change() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"modes":["break-glass","urgent-remediation","incident-containment","service-restoration"],"requiredGuards":["emergency-role-authorized","incident-or-ticket-linked","emergency-approver-assigned","scope-bounded","dry-run-ready","lock-record-ready","evidence-redacted"],"planSections":["emergencySummary","businessImpact","targetScope","riskJustification","approvalPath","rollbackNotes","verificationPlan","handoverNotes"],"blockedReasons":["live-execution-disabled","privileged-worker-disabled","role-not-authorized","incident-context-missing","approval-missing","scope-too-broad","lock-conflict","evidence-not-redacted"]}),
    )
}

async fn operations_shift_queue() -> Json<Value> {
    Json(
        json!({"source":"static-seed","queueMode":"aggregate-safe","providerCallsEnabled":false,"liveExecutionAllowed":false,"rawProviderPayloadsAllowed":false,"queueSources":["blocked-request","failed-operation","pending-approval","active-incident","backup-failure","monitoring-problem","handover-note"],"queueStates":["new","triage","owner-assigned","waiting-approval","waiting-dependency","ready-for-handover","closed"],"requiredInputs":["queueItemSource","severity","owner","supportGroup","safeNextAction","handoverNotes","evidenceManifest"],"requiredGuards":["owner-known","support-group-known","severity-assigned","safe-next-action-set","evidence-redacted","stale-data-marked"],"blockedReasons":["owner-unknown","support-group-unknown","missing-safe-next-action","approval-pending","dependency-unhealthy","stale-data","evidence-not-redacted"],"requiredEvidence":["Queue item summary","Owner assignment","Safe next action","Approval state","Dependency health","Handover notes","Evidence references"],"rules":[{"id":"no-raw-provider-payloads","decision":"block","requirement":"Shift queue items summarize provider state without exposing raw provider payloads.","evidence":"Queue item summary"},{"id":"safe-next-action-required","decision":"block","requirement":"Every visible queue item must include a safe next action for the assigned team.","evidence":"Safe next action"},{"id":"owner-and-support-required","decision":"block","requirement":"Owner and support group must be known before a queue item can leave triage.","evidence":"Owner assignment"},{"id":"handover-evidence-required","decision":"block","requirement":"Queue items that cross shifts must keep handover notes and evidence references.","evidence":"Handover notes"}]}),
    )
}

#[derive(Debug, Deserialize)]
struct ShiftActionRequest {
    user: String,
}

#[derive(Debug, Deserialize)]
struct ShiftEscalateRequest {
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ShiftResolveRequest {
    resolution: String,
}

#[derive(Debug, Deserialize)]
struct ShiftMyItemsQuery {
    user: Option<String>,
}

async fn shift_summary() -> Json<Value> {
    Json(shift_queue::get_shift_summary())
}

async fn shift_acknowledge(
    Path(id): Path<String>,
    Json(body): Json<ShiftActionRequest>,
) -> Json<Value> {
    Json(
        shift_queue::acknowledge_item(&id, &body.user)
            .map_err(|e| json!({"error": e}))
            .unwrap_or_default(),
    )
}

async fn shift_assign(Path(id): Path<String>, Json(body): Json<ShiftActionRequest>) -> Json<Value> {
    Json(
        shift_queue::assign_item(&id, &body.user)
            .map_err(|e| json!({"error": e}))
            .unwrap_or_default(),
    )
}

async fn shift_escalate(
    Path(id): Path<String>,
    Json(body): Json<ShiftEscalateRequest>,
) -> Json<Value> {
    Json(
        shift_queue::escalate_item(&id, &body.reason)
            .map_err(|e| json!({"error": e}))
            .unwrap_or_default(),
    )
}

async fn shift_resolve(
    Path(id): Path<String>,
    Json(body): Json<ShiftResolveRequest>,
) -> Json<Value> {
    Json(
        shift_queue::resolve_item(&id, &body.resolution)
            .map_err(|e| json!({"error": e}))
            .unwrap_or_default(),
    )
}

async fn shift_handover() -> Json<Value> {
    Json(shift_queue::get_handover_report())
}

async fn shift_my_items(Query(params): Query<ShiftMyItemsQuery>) -> Json<Value> {
    let user = params.user.unwrap_or_default();
    Json(shift_queue::get_my_items(&user))
}

async fn shift_stale() -> Json<Value> {
    Json(shift_queue::get_stale_items())
}

async fn shift_contract() -> Json<Value> {
    Json(shift_queue::get_shift_contract())
}

// ─── Emergency Change (Break-Glass) request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EmergencyInitiateRequest {
    description: String,
    systems: Vec<String>,
    #[serde(rename = "initiatedBy")]
    initiated_by: String,
    reason: String,
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EmergencyCloseRequest {
    #[serde(rename = "postReviewNotes")]
    post_review_notes: String,
}

#[derive(Debug, Deserialize)]
struct EmergencySiteQuery {
    site: Option<String>,
}

// ─── Emergency Change (Break-Glass) handlers ───

async fn emergency_initiate(
    Json(body): Json<EmergencyInitiateRequest>,
) -> Result<Json<Value>, ProblemDetails> {
    match emergency_change::initiate_emergency(
        &body.description,
        body.systems,
        &body.initiated_by,
        &body.reason,
        &body.site,
    ) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(problem_details(
            StatusCode::BAD_REQUEST,
            "EMERGENCY_INITIATE_FAILED",
            e,
            None::<&str>,
        )),
    }
}

async fn emergency_approve(Path(id): Path<String>) -> Result<Json<Value>, ProblemDetails> {
    match emergency_change::auto_approve(&id) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(problem_details(
            StatusCode::BAD_REQUEST,
            "EMERGENCY_APPROVE_FAILED",
            e,
            None::<&str>,
        )),
    }
}

async fn emergency_execute(Path(id): Path<String>) -> Result<Json<Value>, ProblemDetails> {
    match emergency_change::execute_emergency(&id) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(problem_details(
            StatusCode::BAD_REQUEST,
            "EMERGENCY_EXECUTE_FAILED",
            e,
            None::<&str>,
        )),
    }
}

async fn emergency_verify(Path(id): Path<String>) -> Result<Json<Value>, ProblemDetails> {
    match emergency_change::verify_emergency(&id) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(problem_details(
            StatusCode::BAD_REQUEST,
            "EMERGENCY_VERIFY_FAILED",
            e,
            None::<&str>,
        )),
    }
}

async fn emergency_close(
    Path(id): Path<String>,
    Json(body): Json<EmergencyCloseRequest>,
) -> Result<Json<Value>, ProblemDetails> {
    match emergency_change::close_emergency(&id, &body.post_review_notes) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(problem_details(
            StatusCode::BAD_REQUEST,
            "EMERGENCY_CLOSE_FAILED",
            e,
            None::<&str>,
        )),
    }
}

async fn emergency_active() -> Result<Json<Value>, ProblemDetails> {
    match emergency_change::get_active_emergencies() {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(problem_details(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMERGENCY_ACTIVE_FAILED",
            e,
            None::<&str>,
        )),
    }
}

async fn emergency_history(
    Query(params): Query<EmergencySiteQuery>,
) -> Result<Json<Value>, ProblemDetails> {
    let site = params.site.unwrap_or_default();
    match emergency_change::get_emergency_history(&site) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(problem_details(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMERGENCY_HISTORY_FAILED",
            e,
            None::<&str>,
        )),
    }
}

async fn emergency_stats(
    Query(params): Query<EmergencySiteQuery>,
) -> Result<Json<Value>, ProblemDetails> {
    let site = params.site.unwrap_or_default();
    match emergency_change::get_emergency_stats(&site) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(problem_details(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMERGENCY_STATS_FAILED",
            e,
            None::<&str>,
        )),
    }
}

async fn emergency_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "modes": ["break-glass", "urgent-remediation", "incident-containment", "service-restoration"],
        "requiredGuards": ["emergency-role-authorized", "incident-or-ticket-linked", "emergency-approver-assigned", "scope-bounded", "dry-run-ready", "lock-record-ready", "evidence-redacted"],
        "planSections": ["emergencySummary", "businessImpact", "targetScope", "riskJustification", "approvalPath", "rollbackNotes", "verificationPlan", "handoverNotes"],
        "blockedReasons": ["live-execution-disabled", "privileged-worker-disabled", "role-not-authorized", "incident-context-missing", "approval-missing", "scope-too-broad", "lock-conflict", "evidence-not-redacted"],
        "endpoints": {
            "initiate": {"method": "POST", "path": "/api/ops/emergency/initiate"},
            "approve": {"method": "POST", "path": "/api/ops/emergency/approve/{id}"},
            "execute": {"method": "POST", "path": "/api/ops/emergency/execute/{id}"},
            "verify": {"method": "POST", "path": "/api/ops/emergency/verify/{id}"},
            "close": {"method": "POST", "path": "/api/ops/emergency/close/{id}"},
            "active": {"method": "GET", "path": "/api/ops/emergency/active"},
            "history": {"method": "GET", "path": "/api/ops/emergency/history"},
            "stats": {"method": "GET", "path": "/api/ops/emergency/stats"}
        },
        "rules": [
            {"id": "no-live-emergency-execution", "decision": "block", "requirement": "Emergency changes remain dry-run only until live execution is explicitly enabled by policy.", "evidence": "Dry-run plan summary"},
            {"id": "emergency-approval-required", "decision": "block", "requirement": "Emergency approval and delegated authority must be recorded before execution can be considered.", "evidence": "Approval decisions"},
            {"id": "bounded-scope-required", "decision": "block", "requirement": "Emergency scope must be bounded and locked to avoid uncontrolled blast radius.", "evidence": "Scope and lock record"},
            {"id": "audit-evidence-required", "decision": "block", "requirement": "Redacted evidence, verification, and privileged worker log references are mandatory for audit.", "evidence": "Evidence references"}
        ]
    }))
}

async fn operations_dependency_replay() -> Json<Value> {
    Json(
        json!({"source":"static-seed","operationDependencyReplayMode":"static-dependency-replay","dependencyGraphReadOnly":true,"replaySimulationDryRunOnly":true,"lockStateReadOnly":true,"liveReplayAllowed":false,"operationMutationAllowed":false,"childOperationMutationAllowed":false,"lockMutationAllowed":false,"retryMutationAllowed":false,"providerCallsAllowed":false,"workflowMutationAllowed":false,"rawOperationRowsAllowed":false,"rawExecutionLogsAllowed":false,"rawReplayPayloadsAllowed":false,"rawProviderPayloadsAllowed":false,"rawRecipientDataAllowed":false,"credentialValuesAllowed":false,"tenantIdentifiersAllowed":false,"objectIdentifiersAllowed":false,"privateNetworkValuesAllowed":false,"serialNumbersAllowed":false,"graphNodeTypes":["operation-run","child-operation","lock-scope","dependency","blocked-reason","evidence-reference","retry-policy"],"graphEdgeTypes":["depends-on","blocks","owns-lock","emits-evidence","retries-after","resolves-blocker"],"replayPhases":["snapshot-load","dependency-sort","lock-evaluation","blocker-evaluation","retry-evaluation","evidence-preview","decision-summary"],"requiredGuards":["graph-source-reviewed","dependency-order-reviewed","lock-scope-reviewed","blocker-state-reviewed","retry-policy-reviewed","replay-dry-run-only","evidence-redacted"],"blockedReasons":["operation-replay-live-disabled","operation-mutation-disabled","operation-child-mutation-disabled","operation-lock-mutation-disabled","operation-retry-mutation-disabled","operation-provider-calls-disabled","operation-workflow-mutation-disabled","operation-raw-rows-disabled","operation-raw-logs-disabled","operation-raw-replay-payloads-disabled","operation-raw-provider-payloads-disabled","operation-raw-recipient-data-disabled","operation-credential-values-disabled","operation-tenant-identifiers-disabled","operation-object-identifiers-disabled","operation-private-network-values-disabled","operation-serials-disabled","dependency-graph-missing","replay-snapshot-missing","lock-scope-unknown","blocker-state-unknown","evidence-not-redacted"],"requiredEvidence":["Dependency graph summary","Replay phase summary","Lock evaluation summary","Blocked reason summary","Retry policy summary","Evidence references"],"rules":[{"id":"dependency-graph-read-only","decision":"block","requirement":"Operation dependency graph summaries are read-only and must not mutate operation runs, child operations, locks, retries, or workflow state.","evidence":"Dependency graph summary"},{"id":"replay-simulation-dry-run-only","decision":"block","requirement":"Replay simulation uses static snapshots only and must not replay live work, call providers, or emit live execution steps.","evidence":"Replay phase summary"},{"id":"operation-mutations-disabled","decision":"block","requirement":"Dependency replay cannot create, update, retry, unlock, close, or re-order operation runs or child operations.","evidence":"Lock evaluation summary"},{"id":"raw-activity-data-not-exposed","decision":"block","requirement":"Operation dependency replay evidence must use safe summaries only and must not expose raw operation rows, raw execution logs, raw replay payloads, raw provider payloads, recipient data, credential values, tenant identifiers, object identifiers, private network values, serial numbers, live endpoints, or URLs.","evidence":"Evidence references"}]}),
    )
}

async fn operations_activity_queue() -> Json<Value> {
    Json(
        json!({"source":"static-seed","activityOperationQueueMode":"static-activity-operation-queue","queueSummaryReadOnly":true,"childOperationSummaryReadOnly":true,"lockStateReadOnly":true,"retryStateReadOnly":true,"blockedReasonSummaryOnly":true,"liveQueueQueryAllowed":false,"operationMutationAllowed":false,"workflowMutationAllowed":false,"workerDispatchAllowed":false,"providerCallsAllowed":false,"notificationDispatchAllowed":false,"rawOperationRowsAllowed":false,"rawChildOperationRowsAllowed":false,"rawLockRowsAllowed":false,"rawRetryRowsAllowed":false,"rawExecutionLogsAllowed":false,"rawProviderPayloadsAllowed":false,"rawUserDataAllowed":false,"rawRecipientDataAllowed":false,"credentialValuesAllowed":false,"tokenValuesAllowed":false,"tenantIdentifiersAllowed":false,"objectIdentifiersAllowed":false,"principalIdentifiersAllowed":false,"privateNetworkValuesAllowed":false,"queueItemTypes":["parent-operation","child-operation","lock","retry","blocked-reason","handover-note","evidence-reference"],"queueStates":["queued","running","blocked","retrying","waiting-approval","completed","failed","canceled","stale"],"queueLenses":["by-site","by-workflow","by-owner-domain","by-priority","by-risk","by-staleness"],"requiredGuards":["operation-scope-known","queue-state-known","lock-state-known","retry-policy-known","blocked-reason-present","stale-data-marked","evidence-redacted","live-query-blocked"],"blockedReasons":["activity-live-query-disabled","activity-operation-mutation-disabled","activity-workflow-mutation-disabled","activity-worker-dispatch-disabled","activity-provider-calls-disabled","activity-notification-dispatch-disabled","activity-raw-operation-rows-disabled","activity-raw-child-operation-rows-disabled","activity-raw-lock-rows-disabled","activity-raw-retry-rows-disabled","activity-raw-execution-logs-disabled","activity-raw-provider-payloads-disabled","activity-raw-user-data-disabled","activity-raw-recipient-data-disabled","activity-credential-values-disabled","activity-token-values-disabled","activity-tenant-identifiers-disabled","activity-object-identifiers-disabled","activity-principal-identifiers-disabled","activity-private-network-values-disabled","operation-scope-missing","queue-state-unknown","lock-state-unknown","retry-policy-missing","blocked-reason-missing","evidence-not-redacted"],"requiredEvidence":["Activity queue summary","Parent operation summary","Child operation summary","Lock state summary","Retry state summary","Blocked reason summary","Handover notes","Evidence references"],"rules":[{"id":"activity-queue-read-only","decision":"block","requirement":"Activity queue summaries are read-only and must not run live queue queries, dispatch workers, call providers, or mutate operations.","evidence":"Activity queue summary"},{"id":"operation-state-not-mutated","decision":"block","requirement":"Parent operation, child operation, lock, retry, and workflow state must remain unchanged by the Activity queue view.","evidence":"Parent operation summary"},{"id":"blocked-reason-required","decision":"block","requirement":"Blocked and stale queue items require known operation scope, queue state, lock state, retry policy, blocked reason, and redacted evidence before handover.","evidence":"Blocked reason summary"},{"id":"raw-activity-queue-data-not-exposed","decision":"block","requirement":"Activity queue evidence must not expose raw operation rows, raw child operation rows, raw lock rows, raw retry rows, raw execution logs, raw provider payloads, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.","evidence":"Evidence references"}]}),
    )
}

async fn operations_run_state() -> Json<Value> {
    Json(
        json!({"source":"static-seed","operationRunStateMode":"static-operation-run-state","operationStateReadOnly":true,"childOperationStateReadOnly":true,"lockStateReadOnly":true,"retryStateReadOnly":true,"redactedLogSummaryOnly":true,"liveExecutionAllowed":false,"workerDispatchAllowed":false,"providerCallsAllowed":false,"operationMutationAllowed":false,"childOperationMutationAllowed":false,"lockMutationAllowed":false,"retryMutationAllowed":false,"workflowMutationAllowed":false,"rawOperationRowsAllowed":false,"rawChildOperationRowsAllowed":false,"rawExecutionLogsAllowed":false,"rawLockRowsAllowed":false,"rawRetryRowsAllowed":false,"rawProviderPayloadsAllowed":false,"rawRecipientDataAllowed":false,"credentialValuesAllowed":false,"tokenValuesAllowed":false,"tenantIdentifiersAllowed":false,"objectIdentifiersAllowed":false,"privateNetworkValuesAllowed":false,"serialNumbersAllowed":false,"operationStates":["queued","blocked","planning","approval-wait","locked","executing","verifying","succeeded","failed","cancelled","degraded"],"childOperationStates":["pending","blocked","ready","running","retry-wait","succeeded","failed","skipped"],"lockStates":["not-required","pending","active","conflict","expired","released"],"retryStates":["not-retryable","retry-pending","backoff-wait","retry-exhausted","manual-review"],"logStates":["not-started","redacted-summary-ready","redaction-pending","blocked"],"requiredGuards":["operation-scope-known","child-operations-summarized","lock-scope-reviewed","retry-policy-reviewed","redacted-log-summary-ready","evidence-redacted","live-execution-blocked"],"blockedReasons":["run-state-live-execution-disabled","run-state-worker-dispatch-disabled","run-state-provider-calls-disabled","run-state-operation-mutation-disabled","run-state-child-operation-mutation-disabled","run-state-lock-mutation-disabled","run-state-retry-mutation-disabled","run-state-workflow-mutation-disabled","run-state-raw-operation-rows-disabled","run-state-raw-child-operation-rows-disabled","run-state-raw-execution-logs-disabled","run-state-raw-lock-rows-disabled","run-state-raw-retry-rows-disabled","run-state-raw-provider-payloads-disabled","run-state-raw-recipient-data-disabled","run-state-credential-values-disabled","run-state-token-values-disabled","run-state-tenant-identifiers-disabled","run-state-object-identifiers-disabled","run-state-private-network-values-disabled","run-state-serials-disabled","operation-scope-missing","child-operation-state-unknown","lock-conflict","retry-policy-missing","redacted-log-missing","evidence-not-redacted"],"requiredEvidence":["Operation run summary","Child operation summary","Lock state summary","Retry state summary","Redacted log summary","Evidence references"],"rules":[{"id":"operation-run-state-read-only","decision":"block","requirement":"Operation run state summaries are read-only and must not execute, retry, cancel, close, or mutate operation runs.","evidence":"Operation run summary"},{"id":"child-lock-retry-state-read-only","decision":"block","requirement":"Child operation, lock, and retry state summaries are read-only and must not dispatch workers, acquire locks, release locks, or update retry state.","evidence":"Lock state summary"},{"id":"redacted-log-summary-required","decision":"block","requirement":"Run-state evidence must use redacted log summaries only and must not expose raw execution logs or provider payloads.","evidence":"Redacted log summary"},{"id":"raw-operation-run-data-not-exposed","decision":"block","requirement":"Operation run-state evidence must not expose raw operation rows, child operation rows, lock rows, retry rows, recipient data, credential values, token values, tenant identifiers, object identifiers, private network values, serial numbers, live endpoints, or URLs.","evidence":"Evidence references"}]}),
    )
}

async fn operations_datacenter_readiness() -> Json<Value> {
    Json(
        json!({"source":"static-seed","readinessMode":"review-only","providerCallsEnabled":false,"liveExecutionAllowed":false,"rawInventoryRowsAllowed":false,"readinessDomains":["rack-space","power","cooling","switchport","vlan","storage-pathing","firmware-baseline","support-coverage","site-capacity"],"requiredInputs":["site","requester","owner","hardwareProfile","clusterProfile","networkScope","storageScope","capacityNeed","evidenceManifest"],"requiredGuards":["site-known","owner-known","rack-capacity-known","power-cooling-reviewed","network-readiness-known","storage-readiness-known","firmware-baseline-known","evidence-redacted"],"planSections":["siteSummary","capacityReadiness","networkReadiness","storageReadiness","firmwareAndSupport","riskNotes","remediationPlan","handoverNotes"],"blockedReasons":["site-unknown","owner-unknown","rack-capacity-unknown","power-cooling-not-reviewed","network-readiness-unknown","storage-readiness-unknown","firmware-baseline-unknown","support-coverage-unknown","evidence-not-redacted"],"requiredEvidence":["Site readiness summary","Rack and power review","Cooling review","Network readiness summary","Storage readiness summary","Firmware and support baseline","Capacity decision","Risk notes","Evidence references"],"rules":[{"id":"no-live-datacenter-actions","decision":"block","requirement":"Datacenter readiness contracts report review state only and never execute provider, switch, storage, or hardware actions.","evidence":"Site readiness summary"},{"id":"network-storage-readiness-required","decision":"block","requirement":"Network and storage readiness must be known before hardware or cluster work proceeds.","evidence":"Network readiness summary"},{"id":"capacity-decision-required","decision":"block","requirement":"Capacity decision must show rack, power, cooling, and site headroom before approval.","evidence":"Capacity decision"},{"id":"firmware-support-baseline-required","decision":"block","requirement":"Firmware and support baseline must be known before datacenter execution can be considered.","evidence":"Firmware and support baseline"}]}),
    )
}

async fn operations_oob_access() -> Json<Value> {
    Json(
        json!({"source":"static-seed","validationMode":"review-only","providerCallsEnabled":false,"liveAccessChecksAllowed":false,"liveCertificateChecksAllowed":false,"rawInventoryRowsAllowed":false,"endpointIdentifiersAllowed":false,"serialNumbersAllowed":false,"accountIdentifiersAllowed":false,"supportedConsoleTypes":["hpe-ilo","dell-idrac","lenovo-xcc"],"supportedWorkflows":["oob-access-readiness","hardware-console-review","oob-certificate-review","role-assignment-review","break-glass-readiness-review","incident-readiness-review"],"readinessDomains":["console-access","certificate-readiness","role-readiness","break-glass-readiness","network-reachability","hardware-cmdb","evidence-readiness"],"requiredInputs":["site","hardwareProfile","platformRole","owner","supportGroup","accessProfile","certificateProfile","breakGlassProfile","cmdbContext","evidenceManifest"],"requiredGuards":["site-known","hardware-profile-known","support-owner-known","access-profile-reviewed","certificate-profile-reviewed","role-model-reviewed","break-glass-procedure-reviewed","incident-runbook-linked","evidence-redacted"],"planSections":["readinessSummary","accessProfileReview","certificateReadiness","roleModelReview","breakGlassReadiness","incidentReadiness","exceptionDecision","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-access-checks-disabled","live-certificate-checks-disabled","raw-inventory-rows-disabled","endpoint-identifiers-disabled","serial-numbers-disabled","account-identifiers-disabled","site-unknown","hardware-profile-unknown","access-profile-missing","certificate-profile-missing","role-model-missing","break-glass-profile-missing","incident-runbook-missing","evidence-not-redacted"],"requiredEvidence":["OOB readiness summary","Access profile review","Certificate readiness review","Role model review","Break-glass readiness review","Incident readiness review","Exception decision","Evidence references"],"rules":[{"id":"no-live-oob-access-checks","decision":"block","requirement":"Out-of-band access validation reports review state only and never logs in to consoles, tests credentials, changes roles, or calls hardware controllers.","evidence":"OOB readiness summary"},{"id":"certificate-readiness-required","decision":"block","requirement":"Certificate profile and renewal readiness must be reviewed before incident readiness can be accepted.","evidence":"Certificate readiness review"},{"id":"role-model-review-required","decision":"block","requirement":"Role assignment intent and access profile must be reviewed without exposing account names or group identifiers.","evidence":"Role model review"},{"id":"break-glass-readiness-required","decision":"block","requirement":"Break-glass procedure, ownership, and incident runbook linkage must be reviewed before readiness is accepted.","evidence":"Break-glass readiness review"},{"id":"raw-oob-inventory-not-exposed","decision":"block","requirement":"OOB readiness evidence must use safe summaries only and must not expose endpoint names, hostnames, private IPs, serials, asset tags, account names, access group identifiers, raw inventory rows, or provider payloads.","evidence":"Evidence references"}]}),
    )
}

async fn operations_network_vlan() -> Json<Value> {
    Json(
        json!({"source":"static-seed","readinessMode":"review-only","providerCallsEnabled":false,"liveNetworkChangesAllowed":false,"rawInventoryRowsAllowed":false,"networkIdentifiersAllowed":false,"supportedWorkflows":["host-network-readiness","workload-vlan-readiness","switchport-capacity-review","portgroup-policy-review","vlan-catalog-review","network-exception-review"],"readinessDomains":["switchport-capacity","vlan-catalog","portgroup-policy","trunk-policy","uplink-redundancy","mtu-policy","network-segmentation","evidence-readiness"],"requiredInputs":["site","networkScope","workloadProfile","platformProfile","vlanPolicy","portgroupPolicy","redundancyRequirement","maintenanceWindow","owner","evidenceManifest"],"requiredGuards":["site-known","network-scope-known","vlan-catalog-reviewed","portgroup-policy-reviewed","switchport-capacity-reviewed","uplink-redundancy-reviewed","segmentation-reviewed","maintenance-window-known","owner-known","evidence-redacted"],"planSections":["readinessSummary","vlanPolicyReview","portgroupPolicyReview","switchportCapacityReview","uplinkAndTrunkReview","segmentationReview","exceptionDecision","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-network-change-disabled","raw-inventory-rows-disabled","network-identifiers-disabled","site-unknown","network-scope-missing","vlan-catalog-missing","portgroup-policy-missing","switchport-capacity-unknown","uplink-redundancy-unknown","segmentation-unknown","maintenance-window-missing","owner-unknown","evidence-not-redacted"],"requiredEvidence":["Readiness summary","VLAN policy review","Portgroup policy review","Switchport capacity review","Uplink and trunk review","Segmentation review","Exception decision","Evidence references"],"rules":[{"id":"no-live-network-changes","decision":"block","requirement":"Network and VLAN readiness contracts report review state only and never configure switches, port groups, VLANs, trunks, uplinks, or provider networking.","evidence":"Readiness summary"},{"id":"vlan-catalog-required","decision":"block","requirement":"VLAN and port group policy decisions must come from reviewed catalog summaries before host or workload placement can proceed.","evidence":"VLAN policy review"},{"id":"switchport-capacity-required","decision":"block","requirement":"Switchport capacity, uplink redundancy, and trunk policy summaries must be reviewed before network readiness can be accepted.","evidence":"Switchport capacity review"},{"id":"segmentation-review-required","decision":"block","requirement":"Segmentation and environment policy decisions must be reviewed before readiness can be accepted.","evidence":"Segmentation review"},{"id":"raw-network-inventory-not-exposed","decision":"block","requirement":"Network readiness evidence must use safe summaries only and must not expose switch IDs, switchport IDs, MAC addresses, VLAN IDs, endpoint names, private IPs, raw network inventory rows, serials, or provider payloads.","evidence":"Evidence references"}]}),
    )
}

async fn operations_hardware_lifecycle() -> Json<Value> {
    Json(
        json!({"source":"static-seed","lifecycleMode":"metadata-only","providerCallsEnabled":false,"liveExecutionAllowed":false,"serialNumbersAllowed":false,"supportedProfiles":["hpe-dl360-msa","hpe-simplivity-dl380","lenovo-sr","lenovo-vx","lenovo-mx"],"lifecycleStates":["planned","ordered","received","staged","in-service","maintenance","refresh-planned","decommissioned"],"requiredInputs":["hardwareProfile","lifecycleState","site","owner","capacityRole","supportStatus","firmwareBaseline","refreshWindow","evidenceManifest"],"requiredGuards":["model-known","site-known","support-status-known","firmware-baseline-known","capacity-role-known","cmdb-owner-known","evidence-redacted"],"planSections":["hardwareSummary","lifecycleState","sitePlacement","firmwareAndSupport","capacityRole","riskNotes","refreshPlan","handoverNotes"],"blockedReasons":["model-unknown","site-unknown","support-status-unknown","firmware-baseline-unknown","capacity-role-unknown","support-risk","cmdb-owner-unknown","evidence-not-redacted"],"requiredEvidence":["Hardware lifecycle summary","Site placement","Support status","Firmware baseline","Capacity role","Refresh decision","Risk notes","Evidence references"],"rules":[{"id":"no-live-hardware-actions","decision":"block","requirement":"Hardware lifecycle contracts track metadata only and never execute vendor, out-of-band, storage, or cluster actions.","evidence":"Hardware lifecycle summary"},{"id":"no-serial-or-asset-identifiers","decision":"block","requirement":"Committed hardware lifecycle metadata must not contain serial numbers, asset tags, or device identifiers.","evidence":"Hardware lifecycle summary"},{"id":"support-and-firmware-required","decision":"block","requirement":"Support status and the approved N-1 firmware baseline strategy must be known before operational changes can be considered.","evidence":"Firmware baseline"},{"id":"refresh-risk-review-required","decision":"block","requirement":"Hardware with support or capacity risk needs refresh review and owner evidence.","evidence":"Refresh decision"}]}),
    )
}

async fn operations_firmware_compliance() -> Json<Value> {
    Json(
        json!({"source":"static-seed","exceptionMode":"review-only","dryRunRequired":true,"providerCallsEnabled":false,"liveFirmwareChangesAllowed":false,"rawInventoryRowsAllowed":false,"hostIdentifiersAllowed":false,"serialNumbersAllowed":false,"exactFirmwareVersionsAllowed":false,"rawVendorPayloadsAllowed":false,"supportedProfiles":["hpe-dl360-msa","hpe-simplivity-dl380","lenovo-sr","lenovo-vx","lenovo-mx"],"exceptionTypes":["firmware-baseline-deviation","driver-baseline-deviation","hardware-support-deviation","compatibility-evidence-gap","maintenance-window-deferral","vendor-baseline-pending"],"riskLevels":["low","medium","high","emergency"],"requiredInputs":["site","hardwareProfile","platformRole","targetBaseline","observedBaselineSummary","exceptionReason","clusterCriticality","supportStatus","remediationWindow","expiryDate","reviewCadence","owner","evidenceManifest"],"requiredGuards":["site-known","hardware-profile-known","target-baseline-known","observed-baseline-summarized","compatibility-impact-reviewed","support-risk-reviewed","cluster-criticality-reviewed","maintenance-window-known","exception-owner-assigned","expiry-date-set","remediation-plan-ready","evidence-redacted"],"planSections":["exceptionSummary","baselineDecision","compatibilityImpact","supportRisk","clusterCriticality","remediationPlan","approvalRoute","expiryAndReview","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-firmware-change-disabled","raw-inventory-rows-disabled","host-identifiers-disabled","serial-numbers-disabled","exact-firmware-versions-disabled","raw-vendor-payloads-disabled","site-unknown","hardware-profile-unknown","target-baseline-missing","observed-baseline-missing","compatibility-impact-unknown","support-risk-unknown","cluster-criticality-unknown","expiry-missing","remediation-plan-missing","approval-missing","evidence-not-redacted"],"requiredEvidence":["Firmware exception summary","Target baseline summary","Observed baseline summary","Compatibility impact review","Support risk review","Cluster criticality review","Remediation plan","Approval route","Expiry and review date","Evidence references"],"rules":[{"id":"no-live-firmware-actions","decision":"block","requirement":"Firmware compliance exceptions report risk acceptance only and never patch firmware, remediate drivers, reconfigure hardware, or call live vendor tools.","evidence":"Firmware exception summary"},{"id":"baseline-evidence-required","decision":"block","requirement":"Target and observed baseline evidence must be summarized before a firmware exception can be reviewed.","evidence":"Baseline summary"},{"id":"compatibility-support-risk-required","decision":"block","requirement":"Compatibility impact, support status, and cluster criticality must be reviewed before exception approval.","evidence":"Support risk review"},{"id":"expiry-remediation-required","decision":"block","requirement":"Exceptions require owner, expiry date, remediation window, and review cadence before acceptance.","evidence":"Expiry and review date"},{"id":"raw-firmware-inventory-not-exposed","decision":"block","requirement":"Firmware exception evidence must use safe summaries only and must not expose host identifiers, endpoint names, private IPs, exact observed firmware versions, serials, asset tags, raw inventory rows, raw logs, or vendor payloads.","evidence":"Evidence references"}]}),
    )
}

async fn operations_platform_health() -> Json<Value> {
    Json(
        json!({"source":"static-seed","healthMode":"degraded-read-only","providerCallsEnabled":false,"liveExecutionAllowed":false,"rawLogsAllowed":false,"components":["portal-ui","platform-api","platform-worker","inventory-sync","adapters","queue","platform-db","platform-vault","ingress","object-storage"],"healthSignals":["readiness","liveness","stale-data","dependency-health","queue-depth","adapter-readiness","backup-state","secret-reference-readiness","evidence-export-readiness"],"healthStates":["healthy","degraded","stale","blocked","unknown"],"requiredInputs":["component","owner","healthSignal","healthState","staleDataMarker","safeRemediation","evidenceManifest"],"requiredGuards":["component-registered","owner-known","stale-data-marked","dependency-status-known","safe-remediation-set","evidence-redacted"],"blockedReasons":["component-unknown","owner-unknown","dependency-status-unknown","stale-data-unmarked","unsafe-remediation","raw-log-exposure","evidence-not-redacted"],"requiredEvidence":["Health summary","Component owner","Dependency state","Stale-data marker","Safe remediation","Handover notes","Evidence references"],"rules":[{"id":"no-live-health-remediation","decision":"block","requirement":"Platform health reporting can suggest safe remediation but must not execute live remediation.","evidence":"Safe remediation"},{"id":"raw-logs-not-exposed","decision":"block","requirement":"Dashboard health output must not expose raw logs, provider payloads, credentials, or endpoint details.","evidence":"Health summary"},{"id":"stale-data-must-be-marked","decision":"block","requirement":"Stale data must be explicit so operators do not mistake cached state for live health.","evidence":"Stale-data marker"},{"id":"owner-and-remediation-required","decision":"block","requirement":"Health items must identify an owner and safe next action before leaving triage.","evidence":"Component owner"}]}),
    )
}

async fn operations_incident_context() -> Json<Value> {
    Json(
        json!({"source":"static-seed","panelMode":"aggregate-safe","providerCallsEnabled":false,"liveExecutionAllowed":false,"rawProviderPayloadsAllowed":false,"contextDomains":["ci","application","vm","change","backup","monitoring","cmdb","evidence"],"panelSections":["incidentSummary","serviceContext","assetContext","changeContext","backupContext","monitoringContext","cmdbContext","evidenceContext","safeNextActions"],"requiredInputs":["incidentContext","ciIdentity","application","owner","supportGroup","site","environment","evidenceManifest"],"requiredGuards":["incident-linked","ci-identity-known","owner-known","support-group-known","stale-data-marked","evidence-redacted","safe-next-action-set"],"blockedReasons":["incident-missing","ci-identity-unknown","owner-unknown","support-group-unknown","stale-data-unmarked","raw-provider-payload","evidence-not-redacted","missing-safe-next-action"],"requiredEvidence":["Incident summary","CI identity summary","Owner and support group","Change context","Backup state","Monitoring state","CMDB relationship summary","Safe next actions","Evidence references"],"rules":[{"id":"no-live-context-lookup","decision":"block","requirement":"Incident context panel uses existing platform state only and never performs live provider lookup.","evidence":"Incident summary"},{"id":"no-raw-provider-payloads","decision":"block","requirement":"Panel output must summarize context without raw provider payloads, logs, credentials, or identifiers.","evidence":"CI identity summary"},{"id":"stale-data-must-be-marked","decision":"block","requirement":"Stale or cached context must be marked before operators use it for incident decisions.","evidence":"Monitoring state"},{"id":"safe-next-action-required","decision":"block","requirement":"Incident context must include safe next actions for the assigned owner or support group.","evidence":"Safe next actions"}]}),
    )
}

async fn operations_maintenance_comm() -> Json<Value> {
    Json(
        json!({"source":"static-seed","communicationMode":"draft-only","providerCallsEnabled":false,"liveNotificationAllowed":false,"rawRecipientDataAllowed":false,"messageTypes":["planned-maintenance","outage-advisory","degraded-service","completion-notice","extension-notice","cancellation-notice"],"communicationChannels":["portal-announcement","email-draft","service-desk-note","handover-note","cab-summary"],"requiredInputs":["maintenanceWindow","affectedServices","ciRelationshipSummary","owner","supportGroup","audience","messageType","approvalRoute","evidenceManifest"],"requiredGuards":["maintenance-window-known","affected-ci-known","owner-known","audience-approved","message-template-approved","approval-route-assigned","evidence-redacted"],"blockedReasons":["maintenance-window-missing","affected-ci-unknown","owner-unknown","audience-unapproved","message-template-missing","approval-missing","raw-recipient-data","evidence-not-redacted"],"requiredEvidence":["Communication draft","Affected CI summary","Audience decision","Owner approval","Maintenance window","Channel plan","Handover notes","Evidence references"],"rules":[{"id":"no-live-notification-send","decision":"block","requirement":"Maintenance communication contract creates drafts only and never sends live notifications.","evidence":"Communication draft"},{"id":"approved-audience-required","decision":"block","requirement":"Audience scope must be approved before communication can be published or exported.","evidence":"Audience decision"},{"id":"affected-ci-summary-required","decision":"block","requirement":"Affected CI and application relationship summary must exist before message generation.","evidence":"Affected CI summary"},{"id":"no-sensitive-recipient-data","decision":"block","requirement":"Drafts and channel plans must not expose raw recipient data, credentials, or provider payloads.","evidence":"Channel plan"}]}),
    )
}

async fn operations_degradation_mode() -> Json<Value> {
    Json(
        json!({"source":"static-seed","degradationMode":"fail-safe-read-only","providerCallsEnabled":false,"liveExecutionAllowed":false,"failoverAutomationAllowed":false,"rawProviderPayloadsAllowed":false,"degradationScopes":["site","provider","adapter","dependency","workflow","evidence"],"degradationStates":["normal","degraded-read-only","stale-read-only","blocked","recovering"],"safeCapabilities":["read-only-inventory","evidence-read","request-intake","plan-only","handover","remediation-guidance"],"requiredInputs":["affectedScope","degradationState","dependencyStatus","staleDataMarker","owner","safeRemediation","evidenceManifest"],"requiredGuards":["affected-scope-known","dependency-status-known","stale-data-marked","write-execution-blocked","safe-remediation-set","owner-known","evidence-redacted"],"blockedReasons":["affected-scope-unknown","dependency-status-unknown","stale-data-unmarked","write-execution-requested","unsafe-remediation","owner-unknown","evidence-not-redacted"],"requiredEvidence":["Degradation summary","Affected scope","Dependency state","Stale-data marker","Blocked execution decision","Safe remediation","Handover notes","Evidence references"],"rules":[{"id":"write-execution-blocked-when-degraded","decision":"block","requirement":"Write-capable workflows remain blocked while affected scope is degraded or stale.","evidence":"Blocked execution decision"},{"id":"stale-data-must-be-marked","decision":"block","requirement":"Cached or stale data must be marked before read-only views can be shown.","evidence":"Stale-data marker"},{"id":"affected-scope-required","decision":"block","requirement":"Degraded site, provider, adapter, dependency, workflow, or evidence scope must be explicit.","evidence":"Affected scope"},{"id":"no-automatic-failover","decision":"block","requirement":"Degradation mode can suggest safe remediation but must not perform automatic failover.","evidence":"Safe remediation"}]}),
    )
}

// ─── Degradation Mode functional endpoints ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DegradationEnterRequest {
    reason: String,
}

async fn degradation_check(Path(site): Path<String>) -> Json<Value> {
    let status = degradation_mode::check_site_health(&site);
    Json(serde_json::to_value(status).unwrap())
}

async fn degradation_global() -> Json<Value> {
    let global = degradation_mode::get_global_status();
    Json(serde_json::to_value(global).unwrap())
}

async fn degradation_degraded() -> Json<Value> {
    let degraded = degradation_mode::get_degraded_sites();
    Json(serde_json::to_value(degraded).unwrap())
}

async fn degradation_enter(
    Path(site): Path<String>,
    Json(body): Json<DegradationEnterRequest>,
) -> Json<Value> {
    let status = degradation_mode::enter_degradation_mode(&site, &body.reason);
    Json(serde_json::to_value(status).unwrap())
}

async fn degradation_exit(Path(site): Path<String>) -> Json<Value> {
    let status = degradation_mode::exit_degradation_mode(&site);
    Json(serde_json::to_value(status).unwrap())
}

async fn degradation_rules() -> Json<Value> {
    let rules = degradation_mode::get_degradation_rules();
    Json(serde_json::to_value(rules).unwrap())
}

async fn degradation_contract() -> Json<Value> {
    Json(degradation_mode::get_degradation_contract())
}

async fn operations_aiops_suggestion() -> Json<Value> {
    Json(
        json!({"source":"static-seed","suggestionMode":"recommendation-only","dryRunRequired":true,"providerCallsEnabled":false,"liveCorrelationAllowed":false,"liveRemediationAllowed":false,"liveTicketMutationAllowed":false,"automationDispatchAllowed":false,"rawOperationRowsAllowed":false,"rawHealthRowsAllowed":false,"rawLogPayloadsAllowed":false,"rawUserDataAllowed":false,"rawRecipientDataAllowed":false,"rawProviderPayloadsAllowed":false,"suggestionSources":["operation-health-pattern","platform-health-pattern","incident-context-pattern","shift-queue-pattern","failed-run-pattern","degradation-pattern","evidence-gap-pattern"],"suggestionSignals":["repeat-failure","blocked-workflow","correlated-degradation","rising-risk","stale-data","evidence-gap","owner-unknown"],"requiredInputs":["signalSummary","affectedWorkflow","healthDomain","impactBand","owner","supportGroup","reviewer","evidenceManifest"],"requiredGuards":["signal-summary-redacted","correlation-static-only","impact-band-known","owner-route-known","reviewer-assigned","recommendation-redacted","automation-disabled","evidence-redacted"],"planSections":["signalSummary","correlationSummary","impactAssessment","recommendationCandidate","ownerRoute","reviewRoute","safeNextAction","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-correlation-disabled","live-remediation-disabled","live-ticket-mutation-disabled","automation-dispatch-disabled","raw-operation-rows-disabled","raw-health-rows-disabled","raw-log-payloads-disabled","raw-user-data-disabled","raw-recipient-data-disabled","raw-provider-payloads-disabled","signal-summary-missing","reviewer-missing","recommendation-not-redacted","evidence-not-redacted"],"requiredEvidence":["AIOps signal summary","Static correlation summary","Impact assessment","Recommendation candidate","Owner route","Review route","Safe next action","Evidence references"],"rules":[{"id":"no-live-correlation","decision":"block","requirement":"AIOps suggestions use static, aggregate, or manually reviewed summaries only and never query live provider, ticket, monitoring, backup, inventory, or log systems.","evidence":"Static correlation summary"},{"id":"no-live-remediation","decision":"block","requirement":"AIOps suggestions recommend safe next actions only and never dispatch workers, mutate workflows, suppress alerts, restart services, remediate providers, or create tickets.","evidence":"Safe next action"},{"id":"reviewer-route-required","decision":"block","requirement":"Each suggestion requires a reviewer, owner route, support group, impact band, and redacted evidence before it can be exported or shown as actionable.","evidence":"Review route"},{"id":"raw-aiops-data-not-exposed","decision":"block","requirement":"AIOps suggestion evidence must use safe summaries only and must not expose raw operation rows, raw health rows, raw logs, raw user data, raw recipient data, ticket IDs, incident IDs, change IDs, tenant IDs, object IDs, private IPs, serial numbers, live endpoints, or provider payloads.","evidence":"Evidence references"}]}),
    )
}

async fn operations_knowledge_suggestion() -> Json<Value> {
    Json(
        json!({"source":"static-seed","suggestionMode":"recommendation-export-only","dryRunRequired":true,"providerCallsEnabled":false,"liveKnowledgePublishAllowed":false,"liveTicketMutationAllowed":false,"rawOperationRowsAllowed":false,"rawLogPayloadsAllowed":false,"rawErrorDetailsAllowed":false,"rawUserDataAllowed":false,"rawRecipientDataAllowed":false,"rawProviderPayloadsAllowed":false,"suggestionSources":["failed-operation-pattern","blocked-request-pattern","repeat-incident-pattern","runbook-gap","evidence-gap","handover-friction","known-error-pattern"],"suggestionSignals":["repeated-failure","common-blocker","manual-workaround","missing-runbook","ambiguous-owner","evidence-gap","training-need"],"requiredInputs":["failurePatternSummary","operationTaxonomy","affectedWorkflow","safeRecommendation","owner","supportGroup","reviewer","evidenceManifest"],"requiredGuards":["pattern-summary-redacted","taxonomy-known","frequency-threshold-met","impact-summary-known","reviewer-assigned","recommendation-redacted","export-package-ready","evidence-redacted"],"planSections":["patternSummary","taxonomyMapping","impactSummary","knowledgeCandidate","runbookCandidate","reviewRoute","exportPackage","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-knowledge-publish-disabled","live-ticket-mutation-disabled","raw-operation-rows-disabled","raw-log-payloads-disabled","raw-error-details-disabled","raw-user-data-disabled","raw-recipient-data-disabled","raw-provider-payloads-disabled","pattern-summary-missing","taxonomy-unknown","reviewer-missing","recommendation-not-redacted","evidence-not-redacted"],"requiredEvidence":["Failure pattern summary","Operation taxonomy","Impact summary","Knowledge candidate","Runbook candidate","Review route","Recommendation export package","Evidence references"],"rules":[{"id":"no-live-knowledge-publish","decision":"block","requirement":"Knowledge suggestions create reviewable recommendation exports only and never publish knowledge articles or runbooks.","evidence":"Knowledge candidate"},{"id":"no-live-ticket-mutation","decision":"block","requirement":"Knowledge suggestions never create, update, or close ServiceNow tickets, incidents, changes, tasks, or knowledge records.","evidence":"Review route"},{"id":"safe-summaries-required","decision":"block","requirement":"Repeated failure patterns must be summarized and redacted before recommendation export.","evidence":"Failure pattern summary"},{"id":"reviewer-route-required","decision":"block","requirement":"Each suggestion requires an assigned reviewer and support group before export.","evidence":"Review route"},{"id":"raw-operation-data-not-exposed","decision":"block","requirement":"Knowledge suggestion evidence must use safe summaries only and must not expose raw operation rows, raw logs, raw error details, raw user data, raw recipient data, ticket IDs, incident IDs, change IDs, ServiceNow sys IDs, tenant IDs, object IDs, private IPs, serial numbers, or provider payloads.","evidence":"Evidence references"}]}),
    )
}

async fn images_factory() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"imageFamilies":["windows","linux"],"distributions":["windows-server","sles","rhel","rocky-linux","alma-linux","ubuntu","debian"],"stages":["intake","build-plan","patch","scan","test","approve","promote","publish","supersede"],"promotionGuards":["vulnerability-scan-clean","baseline-test-passed","agent-validation-passed","approval-route-assigned","rollback-image-available","evidence-redacted"],"blockedReasons":["provider-calls-disabled","missing-test-result","scan-not-clean","approval-missing","rollback-image-missing","evidence-not-redacted"]}),
    )
}

async fn patching_maintenance() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["patch-wave-planning","reboot-orchestration"],"waveDimensions":["site","application","environment","criticality","dependencyGroup","backupState","maintenanceWindow"],"requiredGuards":["patch-policy-imported","inventory-coverage-current","backup-state-known","monitoring-maintenance-ready","approval-route-assigned","evidence-redacted"],"planSections":["waveSummary","dependencyOrder","maintenanceWindows","rebootQueue","backupReadiness","monitoringSuppression","riskNotes","rollbackNotes"],"blockedReasons":["provider-calls-disabled","stale-inventory","missing-maintenance-window","backup-state-unknown","dependency-context-missing","blackout-window-conflict","approval-missing"]}),
    )
}

async fn patching_policy_import() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"fields":["platformCiKey","patchGroup","maintenanceWindow","rebootPolicy","blackoutDates","owner","supportGroup","site","environment","application","criticality","dependencyGroup"],"decisions":["accept","reject","review","normalize","export-exception"],"requiredGuards":["cmdb-file-contract-validated","header-mapping-complete","ci-identity-known","maintenance-window-known","reboot-policy-known","owner-known","evidence-redacted"],"blockedReasons":["live-api-disabled","missing-ci-identity","missing-patch-group","missing-maintenance-window","ambiguous-reboot-policy","blackout-window-conflict","owner-unknown","evidence-not-redacted"]}),
    )
}

async fn patching_reboot_orch() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"targets":["windows-server","linux-server","application-tier","dependency-group","patch-wave"],"queueStates":["planned","waiting-approval","waiting-window","ready-for-dispatch","blocked","handed-over","plan-complete"],"sequencingRules":["dependency-order","site-window","criticality-tier","application-tier","rollback-window","handover-required"],"requiredGuards":["patch-policy-imported","dependency-order-known","maintenance-window-approved","blackout-window-clear","backup-state-known","monitoring-maintenance-ready","approval-route-assigned","lock-scope-defined","evidence-redacted"],"planSections":["scopeSummary","dependencyOrder","maintenanceWindow","rebootBatches","backupReadiness","monitoringSuppression","lockPlan","rollbackNotes","handoverNotes"],"blockedReasons":["provider-calls-disabled","live-reboot-disabled","stale-inventory","missing-maintenance-window","dependency-order-unknown","backup-state-unknown","monitoring-maintenance-missing","blackout-window-conflict","approval-missing","lock-scope-missing","evidence-not-redacted"]}),
    )
}

async fn patching_maintenance_calendar() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["patch-calendar","reboot-calendar","sql-maintenance-calendar","application-tier-maintenance","outage-communications-draft","conflict-review"],"dimensions":["application","environment","site","dependencyGroup","maintenanceWindow","criticality","owner","supportGroup","changeContext"],"requiredGuards":["cmdb-relationship-graph-ready","patch-policy-imported","maintenance-window-known","dependency-order-known","blackout-window-clear","owner-known","communications-draft-only","approval-route-assigned","evidence-redacted"],"planSections":["calendarSummary","affectedServiceSummary","dependencyOrder","conflictReview","communicationsDraft","approvalRoute","handoverNotes","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-scheduling-disabled","live-notification-disabled","missing-maintenance-window","dependency-order-unknown","blackout-window-conflict","owner-unknown","conflict-review-missing","approval-missing","evidence-not-redacted"]}),
    )
}

// ─── Maintenance Calendar handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MaintenanceCalendarScheduleRequest {
    site: String,
    #[serde(rename = "startTime")]
    start_time: String,
    #[serde(rename = "endTime")]
    end_time: String,
    reason: String,
    #[serde(rename = "affectedCis")]
    affected_cis: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MaintenanceCalendarConflictsQuery {
    site: String,
    start: String,
    end: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MaintenanceCalendarSiteQuery {
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MaintenanceCalendarMonthQuery {
    site: String,
    month: String,
}

async fn maintenance_calendar_schedule(
    Json(body): Json<MaintenanceCalendarScheduleRequest>,
) -> ApiResult {
    match maintenance_calendar::schedule_window(
        &body.site,
        &body.start_time,
        &body.end_time,
        &body.reason,
        body.affected_cis,
    ) {
        Ok(window) => Ok(Json(serde_json::to_value(window).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn maintenance_calendar_conflicts(
    Query(q): Query<MaintenanceCalendarConflictsQuery>,
) -> Json<Value> {
    let conflicts = maintenance_calendar::check_conflicts(&q.site, &q.start, &q.end);
    Json(serde_json::to_value(conflicts).unwrap())
}

async fn maintenance_calendar_upcoming(
    Query(q): Query<MaintenanceCalendarSiteQuery>,
) -> Json<Value> {
    let windows = maintenance_calendar::get_upcoming(&q.site);
    Json(serde_json::to_value(windows).unwrap())
}

async fn maintenance_calendar_active(Query(q): Query<MaintenanceCalendarSiteQuery>) -> Json<Value> {
    let windows = maintenance_calendar::get_active(&q.site);
    Json(serde_json::to_value(windows).unwrap())
}

async fn maintenance_calendar_month(Query(q): Query<MaintenanceCalendarMonthQuery>) -> ApiResult {
    match maintenance_calendar::get_calendar(&q.site, &q.month) {
        Ok(windows) => Ok(Json(serde_json::to_value(windows).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn maintenance_calendar_cancel(Path(id): Path<String>) -> ApiResult {
    match maintenance_calendar::cancel_window(&id) {
        Ok(window) => Ok(Json(serde_json::to_value(window).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn maintenance_calendar_contract() -> Json<Value> {
    Json(maintenance_calendar::get_calendar_contract())
}

// ─── Patch wave orchestration handlers ───

async fn patch_plan(Json(body): Json<PatchPlanRequest>) -> ApiResult {
    match patch_engine::plan_patch_wave(&body.site, &body.os_family, &body.criticality) {
        Ok(wave) => Ok(Json(serde_json::to_value(wave).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn patch_validate(Json(body): Json<PatchActionRequest>) -> ApiResult {
    match patch_engine::validate_patch_wave(&body.wave_id) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn patch_approve(Json(body): Json<PatchActionRequest>) -> ApiResult {
    match patch_engine::approve_patch_wave(&body.wave_id) {
        Ok(wave) => Ok(Json(serde_json::to_value(wave).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn patch_execute(Json(body): Json<PatchActionRequest>) -> ApiResult {
    match patch_engine::execute_patch_wave(&body.wave_id) {
        Ok(evidence) => Ok(Json(serde_json::to_value(evidence).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn patch_verify(Json(body): Json<PatchActionRequest>) -> ApiResult {
    match patch_engine::verify_patch_wave(&body.wave_id) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn patch_compliance() -> ApiResult {
    match patch_engine::get_patch_compliance() {
        Ok(compliance) => Ok(Json(compliance)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn patch_pending_reboots() -> ApiResult {
    match patch_engine::get_pending_reboots() {
        Ok(reboots) => Ok(Json(reboots)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn patch_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "patchMode": "dry-run-orchestration",
        "dryRunRequired": true,
        "liveExecutionAllowed": false,
        "supportedWorkflows": ["patch-plan","patch-validate","patch-approve","patch-execute","patch-verify","patch-compliance","pending-reboots"],
        "waveDimensions": ["site","osFamily","criticality","maintenanceWindow","rebootPolicy","dependencyGroup","backupState"],
        "validOsFamilies": ["windows","linux"],
        "validSites": ["DEBER","DEFRA","DEDUS","FRPAR","GBLON","NLAMS","ESMAD","ITMIL","CHZRH","ATVIE","BEBRU","SE STO","DKCPH","IE DUB"],
        "requiredInputs": ["site","osFamily","criticality"],
        "requiredGuards": ["patch-policy-imported","inventory-coverage-current","backup-state-known","maintenance-window-known","approval-route-assigned","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-execution-disabled","unknown-site","invalid-os-family","backup-state-unknown","maintenance-window-missing","approval-missing","evidence-not-redacted"],
        "requiredEvidence": ["Patch wave plan summary","Validation result","Approval decisions","Redacted execution evidence","Post-patch compliance report","Evidence references"]
    }))
}

// ─── Software deployment handlers ───

#[derive(Debug, Deserialize)]
struct SoftwarePackagesQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SoftwareActionRequest {
    #[serde(rename = "requestId")]
    request_id: String,
    approver: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SoftwareComplianceQuery {
    site: String,
}

async fn software_packages_list(Query(query): Query<SoftwarePackagesQuery>) -> ApiResult {
    let site = query.site.as_deref();
    let packages = software_deployment::get_approved_packages(site);
    Ok(Json(serde_json::to_value(packages).unwrap()))
}

async fn software_validate(Json(body): Json<software_deployment::DeploymentRequest>) -> ApiResult {
    match software_deployment::validate_deployment(&body) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn software_plan(Json(body): Json<software_deployment::DeploymentRequest>) -> ApiResult {
    match software_deployment::plan_deployment(&body) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn software_approve(
    Path(id): Path<String>,
    Json(body): Json<SoftwareActionRequest>,
) -> ApiResult {
    let approver = body.approver.unwrap_or_else(|| "admin".into());
    match software_deployment::approve_deployment(&id, &approver) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn software_execute(Path(id): Path<String>) -> ApiResult {
    match software_deployment::execute_deployment(&id) {
        Ok(evidence) => Ok(Json(serde_json::to_value(evidence).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn software_verify(Path(id): Path<String>) -> ApiResult {
    match software_deployment::verify_deployment(&id) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn software_history(Path(server): Path<String>) -> ApiResult {
    let history = software_deployment::get_deployment_history(&server);
    Ok(Json(serde_json::to_value(history).unwrap()))
}

async fn software_compliance(Query(query): Query<SoftwareComplianceQuery>) -> ApiResult {
    match software_deployment::get_package_compliance(&query.site) {
        Ok(compliance) => Ok(Json(compliance)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn software_contract() -> Json<Value> {
    Json(software_deployment::get_software_contract())
}

// ─── OS baseline compliance handlers ───

#[derive(Debug, Deserialize)]
struct BaselineQuery {
    site: Option<String>,
}

async fn baseline_check(Path(server): Path<String>) -> ApiResult {
    let results = os_baseline::check_server_compliance(&server);
    Ok(Json(serde_json::to_value(results).unwrap()))
}

async fn baseline_compliance(Query(query): Query<BaselineQuery>) -> ApiResult {
    let site = query.site.unwrap_or_else(|| "DEFRA".to_string());
    match os_baseline::check_site_compliance(&site) {
        Ok(summary) => Ok(Json(serde_json::to_value(summary).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn baseline_noncompliant(Query(query): Query<BaselineQuery>) -> ApiResult {
    let site = query.site.unwrap_or_else(|| "DEFRA".to_string());
    match os_baseline::get_noncompliant(&site) {
        Ok(servers) => Ok(Json(serde_json::to_value(servers).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn baseline_trend(Query(query): Query<BaselineQuery>) -> ApiResult {
    let site = query.site.unwrap_or_else(|| "DEFRA".to_string());
    match os_baseline::get_compliance_trend(&site) {
        Ok(trend) => Ok(Json(serde_json::to_value(trend).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn baseline_coverage() -> Json<Value> {
    let coverage = os_baseline::get_check_coverage();
    Json(serde_json::to_value(coverage).unwrap())
}

async fn baseline_remediate(Path((server, check_id)): Path<(String, String)>) -> ApiResult {
    match os_baseline::remediate_finding(&server, &check_id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn baseline_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveRemediationAllowed": false,
        "dryRunRequired": true,
        "supportedWorkflows": [
            "baseline-check",
            "baseline-compliance",
            "baseline-noncompliant",
            "baseline-trend",
            "baseline-coverage",
            "baseline-remediate"
        ],
        "baselineChecks": [
            {"id": "bc-001", "check_name": "CrowdStrike Falcon Agent", "category": "Security", "severity": "Critical"},
            {"id": "bc-002", "check_name": "VMware Tools", "category": "Tools", "severity": "High"},
            {"id": "bc-003", "check_name": "Zabbix Agent", "category": "Monitoring", "severity": "High"},
            {"id": "bc-004", "check_name": "Windows Firewall", "category": "Configuration", "severity": "Critical"}
        ],
        "validSites": ["DEBER","DEFRA","DEDUS","FRPAR","GBLON","NLAMS","ESMAD","ITMIL","CHZRH","ATVIE","BEBRU","SE STO","DKCPH","IE DUB"],
        "requiredGuards": [
            "site-known",
            "server-name-known",
            "check-id-known",
            "dry-run-only",
            "evidence-redacted"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-remediation-disabled",
            "unknown-site",
            "unknown-server",
            "unknown-check",
            "evidence-not-redacted"
        ]
    }))
}

async fn protect_controlled_restore() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"restoreTypes":["file","vm","application","sql"],"requiredGuards":["restore-point-known","target-isolation-reviewed","owner-approval-assigned","backup-operator-approval-assigned","verification-plan-ready","evidence-redacted"],"planSections":["restoreScope","restorePointSummary","targetSelection","isolationPlan","verificationPlan","riskNotes","rollbackNotes"],"blockedReasons":["provider-calls-disabled","restore-point-unknown","target-selection-missing","target-isolation-not-reviewed","approval-missing","verification-plan-missing","evidence-not-redacted"]}),
    )
}

async fn protect_backup_coverage_gap() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"gapScopes":["vm","application","policy","site","environment"],"gapSignals":["missing-backup-policy","missing-restore-point-evidence","missing-replica","retention-mismatch","criticality-policy-mismatch","stale-backup-inventory","owner-unknown","cmdb-criticality-unknown"],"requiredGuards":["inventory-coverage-current","backup-policy-known","retention-policy-known","replica-requirement-reviewed","criticality-known","owner-known","support-group-known","stale-data-marked","evidence-redacted"],"planSections":["coverageSummary","gapClassification","policyComparison","retentionReview","replicaReview","ownerRouting","remediationDraft","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-remediation-disabled","live-backup-changes-disabled","raw-inventory-rows-disabled","raw-backup-rows-disabled","raw-provider-payloads-disabled","asset-scope-unknown","backup-policy-missing","retention-policy-missing","replica-requirement-unknown","stale-backup-inventory","owner-unknown","support-group-unknown","evidence-not-redacted"]}),
    )
}

async fn protect_repository_capacity() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["capacity-forecast","retention-risk-review","growth-trend-review","hub-spoke-capacity-review","immutability-headroom-review"],"signals":["capacity-threshold-risk","retention-risk","growth-anomaly","hub-capacity-risk","stale-usage-data","immutability-headroom-risk"],"requiredGuards":["repository-summary-known","retention-policy-known","growth-trend-known","backup-policy-known","site-pairing-known","forecast-window-set","owner-known","evidence-redacted"],"planSections":["capacitySummary","growthTrend","retentionRisk","hubSpokeImpact","immutabilityHeadroom","remediationOptions","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-remediation-disabled","repository-summary-missing","retention-policy-missing","growth-trend-unknown","site-pairing-unknown","forecast-window-missing","owner-unknown","evidence-not-redacted"]}),
    )
}

async fn protect_immutability_air_gap() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["immutability-posture-review","air-gap-readiness-review","retention-lock-review","copy-isolation-review","compliance-evidence-review","repository-transition-readiness-review","current-storeonce-posture-review","hardened-linux-repository-readiness-review","cutover-readiness-review","capacity-runway-review","rollback-fallback-review"],"signals":["immutability-disabled","retention-lock-missing","air-gap-gap","policy-mismatch","stale-evidence","unsupported-repository-type","repository-transition-risk","backup-copy-isolation-gap","immutable-retention-gap","capacity-runway-risk","rollback-fallback-gap"],"repositoryPostureProfiles":["current-storeonce-appliance","planned-hardened-repository-2027"],"repositoryTransitionStates":["current-storeonce-protected","hardened-repository-target-planned","transition-readiness-review-required"],"requiredGuards":["repository-summary-known","immutability-policy-known","retention-policy-known","air-gap-strategy-known","repository-transition-reviewed","isolation-path-reviewed","backup-copy-isolation-known","immutable-retention-known","capacity-runway-known","rollback-fallback-known","cutover-readiness-reviewed","owner-known","evidence-redacted"],"planSections":["postureSummary","currentStoreOncePosture","hardenedLinuxRepositoryReadiness","immutabilityControls","airGapControls","retentionLock","isolationReview","repositoryTransitionReadiness","cutoverReadiness","backupCopyIsolation","immutableRetention","capacityRunway","rollbackFallback","policyExceptions","remediationOptions","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-remediation-disabled","repository-summary-missing","immutability-policy-missing","retention-policy-missing","air-gap-strategy-missing","repository-transition-review-missing","isolation-path-unknown","backup-copy-isolation-missing","immutable-retention-missing","capacity-runway-missing","rollback-fallback-missing","cutover-readiness-review-missing","owner-unknown","evidence-not-redacted"]}),
    )
}

// ─── Immutability Compliance Engine Handlers ───

async fn immutability_check(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match immutability_compliance::check_immutability(&id) {
        Ok(check) => Ok(Json(serde_json::to_value(check).unwrap())),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn immutability_retention_lock(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match immutability_compliance::check_retention_lock(&id) {
        Ok(check) => Ok(Json(serde_json::to_value(check).unwrap())),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn immutability_air_gap(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match immutability_compliance::check_air_gap(&id) {
        Ok(check) => Ok(Json(serde_json::to_value(check).unwrap())),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn immutability_verify_all(
    Query(q): Query<ImmutabilityVerifyAllQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = q.site.unwrap_or_default();
    if site.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Query parameter 'site' is required"})),
        ));
    }
    match immutability_compliance::verify_all_repositories(&site) {
        Ok(repos) => Ok(Json(serde_json::to_value(repos).unwrap())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn immutability_compliance_report(
    Query(q): Query<ImmutabilityComplianceQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = q.site.unwrap_or_default();
    if site.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Query parameter 'site' is required"})),
        ));
    }
    match immutability_compliance::get_compliance_report(&site) {
        Ok(report) => Ok(Json(serde_json::to_value(report).unwrap())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn immutability_noncompliant() -> Json<Value> {
    let repos = immutability_compliance::get_noncompliant();
    Json(serde_json::to_value(repos).unwrap())
}

async fn immutability_retention_risk() -> Json<Value> {
    let repos = immutability_compliance::get_retention_risk();
    Json(serde_json::to_value(repos).unwrap())
}

async fn immutability_remediation(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match immutability_compliance::get_remediation_plan(&id) {
        Ok(plan) => Ok(Json(serde_json::to_value(plan).unwrap())),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn immutability_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "exceptionMode": "review-only",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveRemediationAllowed": false,
        "veeamMutationAllowed": false,
        "rawRepositoryDataAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "credentialValuesAllowed": false,
        "tenantIdentifiersAllowed": false,
        "privateNetworkValuesAllowed": false,
        "workflows": [
            "immutability-verification",
            "retention-lock-verification",
            "air-gap-verification",
            "site-compliance-reporting",
            "compliance-remediation"
        ],
        "requiredGuards": [
            "repository-summary-known",
            "immutability-policy-known",
            "retention-policy-known",
            "air-gap-strategy-known",
            "compliance-status-reviewed",
            "owner-known",
            "evidence-redacted"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-remediation-disabled",
            "veeam-mutation-disabled",
            "raw-repository-data-disabled",
            "raw-provider-payloads-disabled",
            "credential-values-disabled",
            "tenant-identifiers-disabled",
            "private-network-values-disabled",
            "repository-summary-missing",
            "immutability-policy-missing",
            "retention-policy-missing",
            "air-gap-strategy-missing",
            "owner-unknown",
            "evidence-not-redacted"
        ]
    }))
}

async fn protect_app_aware_backup() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["guest-processing-readiness","application-aware-success-review","sql-backup-metadata-review","credential-reference-review","policy-exception-review","evidence-pack-review"],"signals":["guest-processing-disabled","app-aware-failure","sql-log-truncation-risk","credential-reference-missing","policy-mismatch","stale-backup-evidence","unsupported-workload"],"requiredGuards":["backup-policy-known","workload-supported","guest-processing-policy-known","secret-reference-approved","sql-metadata-reviewed","owner-known","evidence-redacted"],"planSections":["validationSummary","workloadScope","guestProcessingControls","secretReferenceReview","sqlMetadataReview","policyExceptions","remediationOptions","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-backup-disabled","guest-processing-execution-disabled","credential-access-disabled","backup-policy-missing","unsupported-workload","secret-reference-missing","sql-metadata-missing","owner-unknown","evidence-not-redacted"]}),
    )
}

async fn protect_backup_dr_assignment() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["backup-policy-assignment","dr-replica-assignment","tag-policy-mapping","site-pairing-review","exception-review","evidence-pack-review"],"signals":["missing-backup-policy","missing-dr-replica","tag-policy-mismatch","site-pairing-mismatch","retention-mismatch","rpo-rto-mismatch","stale-policy-evidence"],"requiredGuards":["policy-catalog-known","site-pairing-known","tags-reviewed","owner-known","backup-operator-review-assigned","dr-impact-reviewed","evidence-redacted"],"planSections":["assignmentSummary","tagPolicyMapping","backupPolicyDecision","drReplicaDecision","sitePairingImpact","policyExceptions","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-assignment-disabled","replica-creation-disabled","policy-catalog-missing","tag-policy-mapping-missing","site-pairing-unknown","owner-unknown","approval-missing","evidence-not-redacted"]}),
    )
}

async fn protect_restore_testing() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["restore-test-schedule","restore-point-validation","verification-plan-review","critical-app-cadence","evidence-pack-review"],"requiredGuards":["restore-point-known","target-isolation-reviewed","verification-plan-ready","owner-approval-assigned","backup-operator-approval-assigned","schedule-window-known","evidence-redacted"],"planSections":["testScope","restorePointSummary","isolationPlan","verificationPlan","scheduleCadence","evidencePack","approvalRoute","handoverNotes"],"blockedReasons":["provider-calls-disabled","live-restore-disabled","test-execution-disabled","restore-point-unknown","target-isolation-not-reviewed","verification-plan-missing","schedule-window-missing","approval-missing","evidence-not-redacted"]}),
    )
}

async fn protect_legal_hold() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["legal-hold-intake-review","extended-retention-exception","protected-scope-review","expiration-review","release-readiness-review","evidence-pack-review"],"signals":["legal-hold-requested","retention-extension-needed","scope-ambiguity","approval-missing","expiry-missing","release-review-due","stale-evidence"],"requiredGuards":["hold-scope-summarized","retention-policy-known","approval-route-assigned","backup-impact-reviewed","expiry-date-set","review-cadence-set","release-process-defined","evidence-redacted"],"planSections":["holdSummary","scopeReview","retentionDecision","backupImpactReview","approvalRoute","expiryAndReview","releaseReadiness","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-retention-change-disabled","veeam-mutation-disabled","servicenow-mutation-disabled","raw-case-data-disabled","raw-recipient-data-disabled","raw-backup-rows-disabled","raw-provider-payloads-disabled","hold-scope-missing","retention-policy-missing","approval-missing","expiry-missing","release-process-missing","evidence-not-redacted"]}),
    )
}

// ─── Legal Hold Engine Handlers ───

async fn legal_hold_place(
    Json(req): Json<LegalHoldPlaceRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let hold_type = match req.hold_type.to_lowercase().as_str() {
        "investigation" => legal_hold::HoldType::Investigation,
        "litigation" => legal_hold::HoldType::Litigation,
        "compliance" => legal_hold::HoldType::Compliance,
        "retention" => legal_hold::HoldType::Retention,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error": format!("Invalid hold_type: {}. Must be Investigation, Litigation, Compliance, or Retention.", req.hold_type)}),
                ),
            ))
        }
    };
    match legal_hold::place_hold(&req.target, hold_type, &req.reason, &req.by, &req.site) {
        Ok(hold) => Ok(Json(serde_json::to_value(hold).unwrap())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn legal_hold_validate(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match legal_hold::validate_hold(&id) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn legal_hold_extend(
    Path(id): Path<String>,
    Json(req): Json<LegalHoldExtendRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match legal_hold::extend_hold(&id, &req.new_expiry) {
        Ok(hold) => Ok(Json(serde_json::to_value(hold).unwrap())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn legal_hold_release(
    Path(id): Path<String>,
    Json(req): Json<LegalHoldReleaseRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match legal_hold::release_hold(&id, &req.released_by) {
        Ok(hold) => Ok(Json(serde_json::to_value(hold).unwrap())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn legal_hold_active(Query(q): Query<LegalHoldActiveQuery>) -> Json<Value> {
    let site = q.site.unwrap_or_default();
    let holds = legal_hold::get_active_holds(&site);
    Json(serde_json::to_value(holds).unwrap())
}

async fn legal_hold_expiring() -> Json<Value> {
    let holds = legal_hold::get_expiring_holds();
    Json(serde_json::to_value(holds).unwrap())
}

async fn legal_hold_evidence(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match legal_hold::get_hold_evidence(&id) {
        Ok(evidence) => Ok(Json(serde_json::to_value(evidence).unwrap())),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn legal_hold_compliance(
    Path(server): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match legal_hold::check_compliance(&server) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn legal_hold_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "exceptionMode": "review-only",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveRetentionChangesAllowed": false,
        "veeamMutationAllowed": false,
        "serviceNowMutationAllowed": false,
        "rawCaseDataAllowed": false,
        "rawRecipientDataAllowed": false,
        "rawBackupRowsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "supportedWorkflows": [
            "legal-hold-place",
            "legal-hold-validate",
            "legal-hold-extend",
            "legal-hold-release",
            "legal-hold-active-query",
            "legal-hold-expiring-alert",
            "legal-hold-evidence-audit",
            "legal-hold-compliance-check"
        ],
        "requiredGuards": [
            "hold-scope-summarized",
            "retention-policy-known",
            "approval-route-assigned",
            "backup-impact-reviewed",
            "expiry-date-set",
            "review-cadence-set",
            "release-process-defined",
            "evidence-redacted"
        ],
        "planSections": [
            "holdSummary",
            "scopeReview",
            "retentionDecision",
            "backupImpactReview",
            "approvalRoute",
            "expiryAndReview",
            "releaseReadiness",
            "evidenceReferences"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-retention-change-disabled",
            "veeam-mutation-disabled",
            "servicenow-mutation-disabled",
            "raw-case-data-disabled",
            "raw-recipient-data-disabled",
            "raw-backup-rows-disabled",
            "raw-provider-payloads-disabled"
        ]
    }))
}

async fn observe_zabbix_onboarding() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["host-onboarding-intake","host-group-template-selection","proxy-or-server-selection","maintenance-window-assignment","owner-routing-review","dry-run-onboarding-plan","evidence-pack-review"],"signals":["missing-zabbix-host","host-group-required","template-required","proxy-or-server-required","maintenance-window-required","owner-required","support-group-required","stale-inventory-review"],"requiredGuards":["inventory-source-known","monitoring-profile-known","host-summary-known","host-group-known","template-known","proxy-or-server-known","maintenance-window-known","owner-known","support-group-known","dry-run-plan-produced","approval-route-assigned","evidence-redacted"],"planSections":["onboardingSummary","hostSummaryReview","hostGroupTemplatePlan","proxyOrServerPlan","maintenanceWindowPlan","ownerRouting","approvalRoute","dryRunOnboardingPlan","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-onboarding-disabled","zabbix-mutation-disabled","raw-host-rows-disabled","raw-provider-payloads-disabled","host-summary-unknown","monitoring-profile-missing","host-group-missing","template-missing","proxy-or-server-unknown","maintenance-window-missing","owner-unknown","support-group-unknown","approval-missing","evidence-not-redacted"]}),
    )
}

async fn observe_alert_routing() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["alert-routing-and-escalation","zabbix-onboarding","monitoring-coverage-gap-report"],"dimensions":["site","environment","application","criticality","supportGroup","maintenanceWindow","alertSeverity","ownershipState"],"requiredGuards":["owner-known","support-group-known","maintenance-window-known","alert-template-mapped","escalation-policy-assigned","evidence-redacted"],"escalationStages":["suppress-during-maintenance","notify-support-group","escalate-critical-service","create-review-task","handover-unresolved"],"blockedReasons":["provider-calls-disabled","unknown-owner","unknown-support-group","missing-maintenance-window","unmapped-alert-template","escalation-policy-missing","evidence-not-redacted"]}),
    )
}

async fn observe_monitoring_coverage_gap() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"gapScopes":["host","application","site","environment","monitoring-profile","support-group"],"gapSignals":["missing-zabbix-host","missing-host-group","missing-template","missing-proxy-or-server","missing-maintenance-window","missing-owner","missing-support-group","alert-routing-gap","stale-monitoring-inventory"],"requiredGuards":["inventory-coverage-current","monitoring-profile-known","host-summary-known","host-group-known","template-known","proxy-or-server-known","maintenance-window-known","owner-known","support-group-known","alert-routing-reviewed","stale-data-marked","evidence-redacted"],"planSections":["coverageSummary","hostOnboardingState","hostGroupTemplateReview","proxyOrServerReview","maintenanceWindowReview","alertRoutingReview","ownerRouting","remediationDraft","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-remediation-disabled","zabbix-mutation-disabled","live-task-creation-disabled","raw-host-rows-disabled","raw-alert-payloads-disabled","raw-problem-rows-disabled","raw-provider-payloads-disabled","asset-scope-unknown","monitoring-profile-missing","host-summary-unknown","host-group-missing","template-missing","proxy-or-server-unknown","maintenance-window-missing","alert-routing-unknown","owner-unknown","support-group-unknown","stale-monitoring-inventory","evidence-not-redacted"]}),
    )
}

async fn observe_zabbix_drift() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["host-group-drift-review","template-drift-review","proxy-drift-review","maintenance-window-drift-review","remediation-request-draft","evidence-pack-review"],"signals":["host-group-mismatch","template-mismatch","proxy-mismatch","maintenance-window-mismatch","owner-mismatch","stale-monitoring-data","policy-exception"],"requiredGuards":["monitoring-profile-known","host-identity-known","zabbix-mapping-reviewed","owner-known","remediation-request-dry-run","approval-route-assigned","evidence-redacted"],"planSections":["driftSummary","expectedMapping","observedMapping","remediationRequest","maintenanceImpact","ownerReview","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-remediation-disabled","zabbix-mutation-disabled","host-identity-unknown","monitoring-profile-missing","mapping-ambiguous","owner-unknown","approval-missing","evidence-not-redacted"]}),
    )
}

// ─── Zabbix drift remediation endpoints ───

async fn zabbix_drift_summary(
    Query(query): Query<ZabbixDriftQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = query.site.unwrap_or_else(|| "DEFRA".to_string());
    match zabbix_drift::get_drift_summary(&site) {
        Ok(summary) => Ok(Json(summary)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn zabbix_drift_detect(
    Json(body): Json<ZabbixDriftSiteRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match zabbix_drift::detect_drift(&body.site) {
        Ok(reports) => Ok(Json(serde_json::to_value(reports).unwrap_or_default())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn zabbix_drift_plan(
    Path(drift_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match zabbix_drift::plan_remediation(&drift_id) {
        Ok(planned) => Ok(Json(serde_json::to_value(planned).unwrap_or_default())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn zabbix_drift_execute(
    Path(drift_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match zabbix_drift::execute_remediation(&drift_id) {
        Ok(evidence) => Ok(Json(serde_json::to_value(evidence).unwrap_or_default())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn zabbix_drift_verify(
    Path(drift_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match zabbix_drift::verify_remediation(&drift_id) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn zabbix_drift_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveRemediationAllowed": false,
        "zabbixMutationAllowed": false,
        "rawEventPayloadsAllowed": false,
        "dryRunRequired": true,
        "workflows": [
            "host-group-drift-review",
            "template-drift-review",
            "proxy-drift-review",
            "maintenance-window-drift-review",
            "remediation-request-draft",
            "evidence-pack-review"
        ],
        "signals": [
            "host-group-mismatch",
            "template-mismatch",
            "proxy-mismatch",
            "maintenance-window-mismatch",
            "owner-mismatch",
            "stale-monitoring-data",
            "policy-exception"
        ],
        "requiredGuards": [
            "monitoring-profile-known",
            "host-identity-known",
            "zabbix-mapping-reviewed",
            "owner-known",
            "remediation-request-dry-run",
            "approval-route-assigned",
            "evidence-redacted"
        ],
        "planSections": [
            "driftSummary",
            "expectedMapping",
            "observedMapping",
            "remediationRequest",
            "maintenanceImpact",
            "ownerReview",
            "approvalRoute",
            "evidenceReferences"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-remediation-disabled",
            "zabbix-mutation-disabled",
            "host-identity-unknown",
            "monitoring-profile-missing",
            "mapping-ambiguous",
            "owner-unknown",
            "approval-missing",
            "evidence-not-redacted"
        ],
        "endpoints": {
            "GET /api/monitoring/zabbix/drift": "Get per-site Zabbix drift summary",
            "POST /api/monitoring/zabbix/drift/detect": "Detect Zabbix configuration drift for a site",
            "POST /api/monitoring/zabbix/drift/plan/{drift_id}": "Plan remediation steps for a drift report",
            "POST /api/monitoring/zabbix/drift/execute/{drift_id}": "Execute remediation for a drift report",
            "POST /api/monitoring/zabbix/drift/verify/{drift_id}": "Verify remediation was applied successfully"
        }
    }))
}

// ─── Noise remediation handlers ───

async fn noise_detect(
    Json(body): Json<NoiseSiteRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match noise_remediation::detect_noise(&body.site) {
        Ok(triggers) => Ok(Json(serde_json::to_value(triggers).unwrap_or_default())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn noise_flapping_detect(
    Json(body): Json<NoiseSiteRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match noise_remediation::detect_flapping(&body.site) {
        Ok(triggers) => Ok(Json(serde_json::to_value(triggers).unwrap_or_default())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn noise_suggest(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match noise_remediation::suggest_remediation(&id) {
        Ok(suggestions) => Ok(Json(suggestions)),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn noise_suppress(
    Path(id): Path<String>,
    Json(body): Json<NoiseSuppressRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match noise_remediation::suppress_trigger(&id, body.duration_minutes, &body.reason) {
        Ok(trigger) => Ok(Json(serde_json::to_value(trigger).unwrap_or_default())),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn noise_resolve(
    Path(id): Path<String>,
    Json(body): Json<NoiseResolveRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match noise_remediation::resolve_noise(&id, &body.resolution) {
        Ok(trigger) => Ok(Json(serde_json::to_value(trigger).unwrap_or_default())),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn noise_report(
    Query(q): Query<NoiseSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = q.site.unwrap_or_else(|| "DEFRA".to_string());
    match noise_remediation::get_noise_report(&site) {
        Ok(report) => Ok(Json(report)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn noise_suppressed_list() -> Json<Value> {
    match noise_remediation::get_suppressed_triggers() {
        Ok(triggers) => Json(serde_json::to_value(triggers).unwrap_or_default()),
        Err(e) => Json(json!({"error": e})),
    }
}

async fn noise_contract() -> Json<Value> {
    Json(noise_remediation::get_noise_contract())
}

async fn observe_synthetic_health_check_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","checkMode":"dry-run-definition","dryRunRequired":true,"providerCallsEnabled":false,"liveChecksAllowed":false,"externalProbesAllowed":false,"zabbixMutationAllowed":false,"rawProbeOutputAllowed":false,"supportedWorkflows":["web-endpoint-check","api-check","dns-resolution-check","certificate-expiry-check","load-balancer-check","iis-service-check","evidence-pack-review"],"checkSignals":["endpoint-unreachable","api-error","dns-resolution-risk","certificate-expiry-risk","load-balancer-risk","iis-service-risk","stale-check-definition"],"requiredInputs":["serviceName","application","site","environment","checkType","targetSummary","owner","supportGroup","evidenceManifest"],"requiredGuards":["check-target-reviewed","check-type-supported","owner-known","maintenance-window-known","synthetic-definition-dry-run","approval-route-assigned","evidence-redacted"],"planSections":["checkSummary","targetScope","syntheticDefinition","expectedResult","alertImpact","maintenanceImpact","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-checks-disabled","external-probes-disabled","zabbix-mutation-disabled","target-scope-unknown","unsupported-check-type","owner-unknown","approval-missing","evidence-not-redacted"],"requiredEvidence":["Synthetic check summary","Target scope summary","Synthetic definition draft","Expected result","Alert impact","Maintenance impact","Approval route","Evidence references"],"rules":[{"id":"no-live-synthetic-probes","decision":"block","requirement":"Synthetic health checks produce definition drafts only, never running live probes or calling external endpoints.","evidence":"Synthetic definition draft"},{"id":"no-zabbix-mutation","decision":"block","requirement":"Synthetic definitions do not create, update, or delete Zabbix checks until live integration gates exist.","evidence":"Synthetic definition draft"},{"id":"target-scope-required","decision":"block","requirement":"Target scope must be reviewed and aggregate-safe before a synthetic check can be drafted.","evidence":"Target scope summary"},{"id":"maintenance-impact-required","decision":"block","requirement":"Maintenance-window and alert-impact behavior must be reviewed before check definitions are approved.","evidence":"Maintenance impact"},{"id":"raw-probe-output-not-exposed","decision":"block","requirement":"Operators receive synthetic check summaries only, not raw probe output, alert payloads, certificate serials, or provider output.","evidence":"Synthetic check summary"}]}),
    )
}

async fn synthetic_run_check(Path(check_id): Path<String>) -> ApiResult {
    let result = synthetic_health::run_check(&check_id);
    Ok(Json(serde_json::to_value(result).unwrap()))
}

#[derive(Deserialize)]
struct SyntheticRunAllQuery {
    site: Option<String>,
}

async fn synthetic_run_all(Query(query): Query<SyntheticRunAllQuery>) -> ApiResult {
    let site = query.site.as_deref().unwrap_or("DEFRA");
    let results = synthetic_health::run_all_checks(site);
    Ok(Json(serde_json::to_value(results).unwrap()))
}

async fn synthetic_status(Path(check_id): Path<String>) -> ApiResult {
    match synthetic_health::get_check_status(&check_id) {
        Some(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        None => Err(status_404(&check_id)),
    }
}

#[derive(Deserialize)]
struct SyntheticDashboardQuery {
    site: Option<String>,
}

async fn synthetic_dashboard(Query(query): Query<SyntheticDashboardQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("DEFRA");
    let dashboard = synthetic_health::get_dashboard(site);
    Json(serde_json::to_value(dashboard).unwrap())
}

async fn synthetic_outages(Query(query): Query<SyntheticDashboardQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("DEFRA");
    let outages = synthetic_health::get_outage_report(site);
    Json(serde_json::to_value(outages).unwrap())
}

async fn observe_noise_flapping() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["flapping-pattern-review","noise-threshold-review","trigger-tuning-review","suppression-window-review","escalation-quality-review","remediation-request-draft","evidence-pack-review"],"signals":["repeated-alert","flapping-trigger","noisy-threshold","stale-maintenance-window","missing-owner","escalation-loop","policy-exception"],"requiredGuards":["alert-pattern-summary-known","monitoring-profile-known","owner-known","maintenance-window-reviewed","remediation-request-dry-run","approval-route-assigned","evidence-redacted"],"planSections":["noiseSummary","flappingPattern","thresholdReview","suppressionWindow","escalationReview","remediationRequest","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-remediation-disabled","alert-suppression-disabled","zabbix-mutation-disabled","raw-alert-history-disabled","alert-pattern-unknown","monitoring-profile-missing","owner-unknown","approval-missing","evidence-not-redacted"]}),
    )
}

async fn observe_monitoring_review_queue() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["ambiguous-onboarding-review","mapping-owner-assignment","sla-aging-review","escalation-draft","queue-handover","evidence-pack-review"],"signals":["ambiguous-host-mapping","missing-owner","missing-support-group","stale-review","sla-breach-risk","escalation-needed","evidence-missing"],"requiredGuards":["queue-item-summary-known","mapping-ambiguity-marked","owner-known","support-group-known","sla-policy-known","escalation-route-assigned","evidence-redacted"],"planSections":["queueSummary","mappingAmbiguity","ownershipReview","slaStatus","escalationDraft","handoverNotes","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-task-creation-disabled","live-escalation-disabled","zabbix-mutation-disabled","queue-item-unknown","owner-unknown","support-group-unknown","sla-policy-missing","escalation-route-missing","evidence-not-redacted"]}),
    )
}

async fn observe_log_forwarder() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["windows-event-forwarding-readiness","linux-rsyslog-readiness","linux-auditd-readiness","siem-routing-review","agent-policy-review","evidence-pack-review"],"signals":["missing-log-forwarder","unsupported-agent","policy-mismatch","stale-log-source","routing-missing","owner-missing","evidence-missing"],"requiredGuards":["os-family-supported","log-profile-known","forwarding-policy-known","owner-known","support-group-known","route-reviewed","installation-plan-dry-run","evidence-redacted"],"planSections":["onboardingSummary","logSourceScope","forwardingPolicy","routeReview","agentReadiness","remediationPlan","approvalRoute","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-agent-install-disabled","live-config-change-disabled","log-platform-mutation-disabled","unsupported-os-family","log-profile-missing","forwarding-policy-missing","owner-unknown","support-group-unknown","evidence-not-redacted"]}),
    )
}

// ─── Log Forwarder Onboarding Engine handlers ───

fn parse_source_types(raw: &[String]) -> Result<Vec<log_forwarder::LogSourceType>, String> {
    raw.iter()
        .map(|s| match s.as_str() {
            "windows-event-log" | "WindowsEventLog" => {
                Ok(log_forwarder::LogSourceType::WindowsEventLog)
            }
            "syslog" | "Syslog" => Ok(log_forwarder::LogSourceType::Syslog),
            "auditd" | "Auditd" => Ok(log_forwarder::LogSourceType::Auditd),
            "iis" | "IIS" => Ok(log_forwarder::LogSourceType::IIS),
            "apache" | "Apache" => Ok(log_forwarder::LogSourceType::Apache),
            other => Err(format!("Unknown source type: {}", other)),
        })
        .collect()
}

async fn logs_onboard(
    Json(body): Json<LogsOnboardRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let source_types = match parse_source_types(&body.source_types) {
        Ok(types) => types,
        Err(e) => return Err(status_400(&e)),
    };
    match log_forwarder::onboard_host(&body.hostname, &source_types, &body.site) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn logs_validate(
    Path(hostname): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match log_forwarder::validate_config(&hostname) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn logs_verify(
    Path(hostname): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match log_forwarder::verify_forwarding(&hostname) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn logs_coverage(
    Query(params): Query<LogsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match log_forwarder::get_coverage_report(&params.site) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn logs_gaps(
    Query(params): Query<LogsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match log_forwarder::get_gap_report(&params.site) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn logs_volume(
    Query(params): Query<LogsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match log_forwarder::get_volume_report(&params.site) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn logs_retention(
    Query(params): Query<LogsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match log_forwarder::get_retention_status(&params.site) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn logs_disable(
    Path(hostname): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match log_forwarder::disable_forwarding(&hostname) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_default())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn logs_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "endpoints": {
            "onboard": "POST /api/observe/logs/onboard",
            "validate": "POST /api/observe/logs/validate/{hostname}",
            "verify": "POST /api/observe/logs/verify/{hostname}",
            "coverage": "GET /api/observe/logs/coverage?site=",
            "gaps": "GET /api/observe/logs/gaps?site=",
            "volume": "GET /api/observe/logs/volume?site=",
            "retention": "GET /api/observe/logs/retention?site=",
            "disable": "POST /api/observe/logs/disable/{hostname}"
        },
        "sourceTypes": ["windows-event-log", "syslog", "auditd", "iis", "apache"],
        "statuses": ["not-configured", "configured", "active", "failed"],
        "hosts": log_forwarder::seed_hosts(),
        "workflows": ["windows-event-forwarding-readiness","linux-rsyslog-readiness","linux-auditd-readiness","siem-routing-review","agent-policy-review","evidence-pack-review"],
        "signals": ["missing-log-forwarder","unsupported-agent","policy-mismatch","stale-log-source","routing-missing","owner-missing","evidence-missing"],
        "requiredGuards": ["os-family-supported","log-profile-known","forwarding-policy-known","owner-known","support-group-known","route-reviewed","installation-plan-dry-run","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-agent-install-disabled","live-config-change-disabled","log-platform-mutation-disabled","unsupported-os-family","log-profile-missing","forwarding-policy-missing","owner-unknown","support-group-unknown","evidence-not-redacted"]
    }))
}

async fn cmdb_reconciliation() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"workflows":["cmdb-import","cmdb-update-export","cmdb-ci-reconciliation"],"signals":["identity-match","owner-match","support-group-match","site-placement-match","backup-policy-match","monitoring-profile-match","relationship-match"],"decisions":["accept","reject","review","export-update"],"requiredGuards":["cmdb-file-contract-validated","header-mapping-complete","inventory-coverage-current","relationship-evidence-ready","reviewer-approval-assigned","evidence-redacted"],"blockedReasons":["live-api-disabled","missing-ci-identity","ambiguous-ci-identity","stale-inventory","relationship-evidence-missing","reviewer-approval-missing","evidence-not-redacted"]}),
    )
}

async fn cmdb_relationship_graph() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"nodeTypes":["application","environment","vm","database","network","storage","backup-policy","monitoring-profile","owner"],"edgeTypes":["contains","depends-on","runs-on","connects-to","protected-by","monitored-by","owned-by","supports"],"requiredGuards":["cmdb-file-contract-validated","ci-identity-known","relationship-source-known","relationship-direction-known","stale-data-marked","reviewer-approval-assigned","evidence-redacted"],"blockedReasons":["live-api-disabled","missing-ci-identity","ambiguous-relationship","relationship-source-unknown","relationship-direction-unknown","stale-data-unmarked","reviewer-approval-missing","evidence-not-redacted"]}),
    )
}

async fn cmdb_impact_analysis() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"domains":["application","environment","vm","database","network","storage","backup","monitoring","owner","service"],"impactSignals":["upstream-dependency","downstream-dependency","single-point-of-failure","missing-owner","stale-relationship","criticality-mismatch","monitoring-gap","backup-gap"],"qualitySignals":["relationship-complete","direction-known","owner-known","criticality-known","source-current","duplicate-free","evidence-redacted"],"syncStates":["file-imported","update-export-pending","ready-for-review","blocked","future-api-disabled"],"requiredGuards":["cmdb-file-contract-validated","relationship-graph-reviewed","impact-scope-reviewed","dependency-quality-reviewed","sync-state-reviewed","reviewer-approval-assigned","evidence-redacted"],"blockedReasons":["cmdb-impact-live-api-disabled","cmdb-impact-cmdb-mutation-disabled","cmdb-impact-relationship-mutation-disabled","cmdb-impact-provider-calls-disabled","cmdb-impact-raw-rows-disabled","cmdb-impact-raw-relationship-rows-disabled","cmdb-impact-raw-impact-rows-disabled","cmdb-impact-raw-provider-payloads-disabled","cmdb-impact-raw-log-content-disabled","cmdb-impact-raw-recipient-data-disabled","cmdb-impact-credential-values-disabled","cmdb-impact-tenant-identifiers-disabled","cmdb-impact-object-identifiers-disabled","cmdb-impact-private-network-values-disabled","cmdb-impact-serials-disabled","impact-scope-missing","dependency-quality-unknown","sync-state-unknown","reviewer-approval-missing","evidence-not-redacted"]}),
    )
}

async fn cmdb_impact_analyze(
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let change_description = body
        .get("changeDescription")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let target_cis: Vec<String> = body
        .get("targetCis")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    match cmdb_impact::analyze_impact(&change_description, &target_cis) {
        Ok(analysis) => Ok(Json(serde_json::to_value(analysis).unwrap_or_default())),
        Err(err) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": err})))),
    }
}

async fn cmdb_impact_graph() -> Json<Value> {
    let graph = cmdb_impact::get_ci_graph();
    Json(serde_json::to_value(&graph).unwrap_or_default())
}

async fn cmdb_impact_upstream(Path(ci_name): Path<String>) -> Json<Value> {
    let deps = cmdb_impact::get_upstream_dependencies(&ci_name);
    Json(serde_json::to_value(&deps).unwrap_or_default())
}

async fn cmdb_impact_downstream(Path(ci_name): Path<String>) -> Json<Value> {
    let deps = cmdb_impact::get_downstream_dependencies(&ci_name);
    Json(serde_json::to_value(&deps).unwrap_or_default())
}

async fn cmdb_impact_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "impactEngineMode": "mock-graph-traversal",
        "providerCallsEnabled": false,
        "liveCmdbMutationAllowed": false,
        "liveRelationshipMutationAllowed": false,
        "endpoints": {
            "analyze": "POST /api/cmdb/impact/analyze",
            "graph": "GET /api/cmdb/impact/graph",
            "upstream": "GET /api/cmdb/impact/upstream/{ci_name}",
            "downstream": "GET /api/cmdb/impact/downstream/{ci_name}"
        },
        "ciTypes": ["Server", "Application", "Database", "Network", "Storage"],
        "criticalityLevels": ["Low", "Medium", "High", "Critical"],
        "riskLevels": ["Low", "Medium", "High", "Critical"],
        "requiredGuards": [
            "provider-calls-disabled",
            "live-cmdb-mutation-disabled",
            "target-cis-known",
            "impact-scope-reviewed",
            "dry-run-only",
            "evidence-redacted"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-cmdb-mutation-disabled",
            "target-cis-missing",
            "impact-scope-not-reviewed",
            "evidence-not-redacted"
        ]
    }))
}

async fn admin_worker_capability() -> Json<Value> {
    Json(
        json!({"source":"static-seed","routingMode":"metadata-only","providerCallsEnabled":false,"liveDispatchAllowed":false,"secretValuesAllowed":false,"capabilityTypes":["generic-worker","windows-gmsa","powercli","linux-ansible","protected-network"],"routingDimensions":["workflowType","osFamily","site","networkZone","providerDomain","riskLevel","approvalState"],"requiredInputs":["workflowType","requestedCapability","site","environment","networkZone","riskLevel","approvalRoute","evidenceManifest"],"requiredGuards":["worker-registered","capability-tag-known","identity-reference-ready","network-zone-approved","approval-route-assigned","dry-run-ready","evidence-redacted"],"blockedReasons":["worker-unknown","capability-missing","identity-reference-missing","protected-network-unapproved","route-ambiguous","approval-missing","worker-health-unknown","evidence-not-redacted"],"requiredEvidence":["Routing request summary","Capability match","Worker readiness","Identity reference decision","Network zone decision","Approval route","Dry-run readiness","Evidence references"],"rules":[{"id":"no-live-worker-dispatch","decision":"block","requirement":"Worker capability routing returns metadata decisions only and never dispatches live jobs.","evidence":"Routing request summary"},{"id":"secret-values-not-allowed","decision":"block","requirement":"Worker identity state must use secret references only and never expose credential values.","evidence":"Identity reference decision"},{"id":"protected-network-approval-required","decision":"block","requirement":"Protected network routes require explicit approval and network-zone decision evidence.","evidence":"Network zone decision"},{"id":"ambiguous-route-blocks-dispatch","decision":"block","requirement":"Ambiguous or missing capability matches block dispatch until reviewed.","evidence":"Capability match"}]}),
    )
}

async fn admin_feature_flag() -> Json<Value> {
    Json(
        json!({"source":"static-seed","featureFlagGovernanceMode":"static-feature-flag-governance","flagCatalogReadOnly":true,"rolloutPlanReadOnly":true,"approvalRouteReadOnly":true,"auditSummaryOnly":true,"liveToggleAllowed":false,"rolloutMutationAllowed":false,"targetingMutationAllowed":false,"policyMutationAllowed":false,"workflowMutationAllowed":false,"providerCallsAllowed":false,"notificationDispatchAllowed":false,"rawFlagRowsAllowed":false,"rawTargetingRowsAllowed":false,"rawUserRowsAllowed":false,"rawGroupRowsAllowed":false,"rawAuditLogsAllowed":false,"rawProviderPayloadsAllowed":false,"rawRecipientDataAllowed":false,"credentialValuesAllowed":false,"tokenValuesAllowed":false,"tenantIdentifiersAllowed":false,"objectIdentifiersAllowed":false,"principalIdentifiersAllowed":false,"groupIdentifiersAllowed":false,"privateNetworkValuesAllowed":false,"flagScopes":["platform-shell","catalog","request-lifecycle","operations","inventory","cmdb","evidence","admin"],"flagStates":["proposed","approved-disabled","approved-enabled","rollout-planned","deprecated","blocked"],"rolloutStrategies":["off-by-default","allowlist-by-role","site-ring","percentage-simulation","rollback-ready"],"requiredGuards":["owner-assigned","approval-route-assigned","blast-radius-reviewed","rollback-plan-ready","evidence-redacted","live-toggle-blocked"],"blockedReasons":["feature-live-toggle-disabled","feature-rollout-mutation-disabled","feature-targeting-mutation-disabled","feature-policy-mutation-disabled","feature-workflow-mutation-disabled","feature-provider-calls-disabled","feature-notification-dispatch-disabled","feature-raw-flag-rows-disabled","feature-raw-targeting-rows-disabled","feature-raw-user-rows-disabled","feature-raw-group-rows-disabled","feature-raw-audit-logs-disabled","feature-raw-provider-payloads-disabled","feature-raw-recipient-data-disabled","feature-credential-values-disabled","feature-token-values-disabled","feature-tenant-identifiers-disabled","feature-object-identifiers-disabled","feature-principal-identifiers-disabled","feature-group-identifiers-disabled","feature-private-network-values-disabled","feature-owner-missing","approval-route-missing","blast-radius-unknown","rollback-plan-missing","evidence-not-redacted"],"requiredEvidence":["Feature flag summary","Rollout plan summary","Approval route summary","Blast radius summary","Rollback plan summary","Evidence references"],"rules":[{"id":"feature-flag-catalog-read-only","decision":"block","requirement":"Feature flag catalog summaries are read-only and must not create, update, enable, disable, or delete flags.","evidence":"Feature flag summary"},{"id":"rollout-plan-approval-required","decision":"block","requirement":"Rollout plans require owner assignment, approval routing, blast-radius review, rollback readiness, and redacted evidence before live use.","evidence":"Rollout plan summary"},{"id":"live-toggle-and-targeting-disabled","decision":"block","requirement":"Admin feature flag governance cannot toggle live flags, mutate targeting, dispatch notifications, call providers, or mutate policy or workflow state.","evidence":"Approval route summary"},{"id":"raw-targeting-data-not-exposed","decision":"block","requirement":"Feature flag governance evidence must not expose raw flag rows, raw targeting rows, raw user rows, raw group rows, raw audit logs, raw provider payloads, recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, group identifiers, private network values, live endpoints, or URLs.","evidence":"Evidence references"}]}),
    )
}

async fn admin_approval_groups() -> Json<Value> {
    Json(
        json!({"source":"static-seed","approvalGroupsMode":"static-admin-approval-groups","groupMappingReadOnly":true,"datacenterFallbackRequired":true,"delegationReviewRequired":true,"separationOfDutiesReviewRequired":true,"liveIdentityLookupAllowed":false,"graphCallsAllowed":false,"roleAssignmentMutationAllowed":false,"groupMembershipMutationAllowed":false,"approvalMutationAllowed":false,"policyMutationAllowed":false,"workflowMutationAllowed":false,"providerCallsAllowed":false,"notificationDispatchAllowed":false,"rawUserDataAllowed":false,"rawGroupDataAllowed":false,"rawMembershipRowsAllowed":false,"rawApprovalPayloadsAllowed":false,"rawProviderPayloadsAllowed":false,"rawRecipientDataAllowed":false,"tenantIdentifiersAllowed":false,"objectIdentifiersAllowed":false,"principalIdentifiersAllowed":false,"groupIdentifiersAllowed":false,"credentialValuesAllowed":false,"tokenValuesAllowed":false,"privateNetworkValuesAllowed":false,"groupScopes":["datacenter-final-approval","technical-approval","business-approval","risk-approval","emergency-approval","audit-review","service-specific-delegation"],"groupStates":["not-created","planned","pending-review","approved","delegated","expired","blocked"],"mappingDimensions":["role","site","service","workflow","criticality","emergency","separation-of-duties"],"requiredGuards":["default-datacenter-approver-reviewed","group-purpose-reviewed","delegation-boundary-reviewed","separation-of-duties-reviewed","break-glass-reviewed","expiry-review-set","evidence-redacted","live-identity-lookup-blocked"],"blockedReasons":["approval-groups-live-identity-lookup-disabled","approval-groups-graph-calls-disabled","approval-groups-role-assignment-disabled","approval-groups-group-membership-mutation-disabled","approval-groups-approval-mutation-disabled","approval-groups-policy-mutation-disabled","approval-groups-workflow-mutation-disabled","approval-groups-provider-calls-disabled","approval-groups-notification-dispatch-disabled","approval-groups-raw-user-data-disabled","approval-groups-raw-group-data-disabled","approval-groups-raw-membership-rows-disabled","approval-groups-raw-approval-payloads-disabled","approval-groups-raw-provider-payloads-disabled","approval-groups-raw-recipient-data-disabled","approval-groups-tenant-identifiers-disabled","approval-groups-object-identifiers-disabled","approval-groups-principal-identifiers-disabled","approval-groups-group-identifiers-disabled","approval-groups-credential-values-disabled","approval-groups-token-values-disabled","approval-groups-private-network-values-disabled","group-scope-missing","delegation-boundary-missing","separation-of-duties-missing","evidence-not-redacted"],"requiredEvidence":["Approval group mapping summary","Datacenter fallback summary","Delegation boundary summary","Separation of duties summary","Evidence references"],"rules":[{"id":"approval-groups-read-only","decision":"block","requirement":"Admin approval group mappings are static summaries and must not look up live identity groups, mutate membership, assign roles, or execute approvals.","evidence":"Approval group mapping summary"},{"id":"datacenter-fallback-required","decision":"block","requirement":"Datacenter final approval remains the default live-execution authority until delegated service-specific approval groups are formally reviewed.","evidence":"Datacenter fallback summary"},{"id":"delegation-boundary-required","decision":"block","requirement":"Approval group delegation requires group purpose, role, site, service, workflow, criticality, emergency scope, expiry, and separation-of-duties review.","evidence":"Delegation boundary summary"},{"id":"raw-approval-group-data-not-exposed","decision":"block","requirement":"Approval group evidence must not expose raw user data, raw group data, raw membership rows, raw approval payloads, raw provider payloads, raw recipient data, tenant identifiers, object identifiers, principal identifiers, group identifiers, credential values, token values, private network values, live endpoints, or URLs.","evidence":"Evidence references"}]}),
    )
}

async fn admin_delegation_boundary() -> Json<Value> {
    Json(
        json!({"source":"static-seed","delegationBoundaryMode":"static-delegation-boundary","siteDelegationReadOnly":true,"roleScopeReadOnly":true,"approvalRouteReadOnly":true,"breakGlassReviewOnly":true,"liveDelegationChangeAllowed":false,"roleAssignmentMutationAllowed":false,"approvalMutationAllowed":false,"policyMutationAllowed":false,"workflowMutationAllowed":false,"graphCallsAllowed":false,"providerCallsAllowed":false,"notificationDispatchAllowed":false,"rawUserDataAllowed":false,"rawGroupDataAllowed":false,"rawDelegationRowsAllowed":false,"rawApprovalPayloadsAllowed":false,"rawProviderPayloadsAllowed":false,"rawRecipientDataAllowed":false,"tenantIdentifiersAllowed":false,"objectIdentifiersAllowed":false,"principalIdentifiersAllowed":false,"groupIdentifiersAllowed":false,"credentialValuesAllowed":false,"tokenValuesAllowed":false,"privateNetworkValuesAllowed":false,"delegationDomains":["catalog","requests","approvals","operations","inventory","cmdb","evidence","admin"],"delegationScopes":["global-read","site-admin","site-approver","workflow-delegate","break-glass-review","audit-review"],"delegationStates":["proposed","pending-approval","approved","expired","revoked","blocked"],"requiredGuards":["delegate-role-known","site-scope-known","approval-route-assigned","expiry-set","separation-of-duties-reviewed","break-glass-reviewed","evidence-redacted","live-delegation-blocked"],"blockedReasons":["delegation-live-change-disabled","delegation-role-assignment-disabled","delegation-approval-mutation-disabled","delegation-policy-mutation-disabled","delegation-workflow-mutation-disabled","delegation-graph-calls-disabled","delegation-provider-calls-disabled","delegation-notification-dispatch-disabled","delegation-raw-user-data-disabled","delegation-raw-group-data-disabled","delegation-raw-delegation-rows-disabled","delegation-raw-approval-payloads-disabled","delegation-raw-provider-payloads-disabled","delegation-raw-recipient-data-disabled","delegation-tenant-identifiers-disabled","delegation-object-identifiers-disabled","delegation-principal-identifiers-disabled","delegation-group-identifiers-disabled","delegation-credential-values-disabled","delegation-token-values-disabled","delegation-private-network-values-disabled","delegate-role-missing","site-scope-missing","approval-route-missing","expiry-missing","separation-of-duties-missing","break-glass-review-missing","evidence-not-redacted"],"requiredEvidence":["Delegation boundary summary","Site scope summary","Role scope summary","Approval route summary","Expiry and review summary","Evidence references"],"rules":[{"id":"delegation-boundary-read-only","decision":"block","requirement":"Delegation boundary summaries are read-only and must not grant, revoke, mutate, or synchronize delegated authority.","evidence":"Delegation boundary summary"},{"id":"site-scope-and-expiry-required","decision":"block","requirement":"Delegation decisions require known site scope, delegate role, approval route, expiry, separation-of-duties review, and redacted evidence.","evidence":"Site scope summary"},{"id":"live-delegation-disabled","decision":"block","requirement":"Admin delegation boundary review cannot change live delegation, mutate role assignments, call Graph or providers, dispatch notifications, or mutate approval, policy, or workflow state.","evidence":"Approval route summary"},{"id":"raw-delegation-data-not-exposed","decision":"block","requirement":"Delegation boundary evidence must not expose raw user data, raw group data, raw delegation rows, raw approval payloads, raw provider payloads, recipient data, tenant identifiers, object identifiers, principal identifiers, group identifiers, credential values, token values, private network values, live endpoints, or URLs.","evidence":"Evidence references"}]}),
    )
}

async fn auth_local_roles() -> Json<Value> {
    Json(
        json!({"authenticationMode":"local-mock","configuredForProduction":false,"entraGroupsConfigured":false,"requiredProductionProvider":"Microsoft Entra ID","actions":["request","approve","execute","admin","audit"],"roles":[{"id":"platform-admin","title":"Platform Admin","visibility":"all","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":true,"canAudit":true,"executionDomains":["platform","governance","emergency"]},{"id":"datacenter-approver","title":"Datacenter Approver","visibility":"site-scope","canRequest":true,"canApprove":true,"canExecute":false,"canAdmin":false,"canAudit":true,"executionDomains":["datacenter","capacity","live-execution-final"]},{"id":"vmware-operator","title":"VMware Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["vmware","placement","lifecycle"]},{"id":"hyper-v-operator","title":"Hyper-V Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["hyper-v","placement","lifecycle"]},{"id":"proxmox-operator","title":"Proxmox Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["proxmox","placement","lifecycle"]},{"id":"nutanix-operator","title":"Nutanix AHV Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["nutanix-ahv","placement","lifecycle"]},{"id":"xen-operator","title":"Xen Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["xen","placement","lifecycle"]},{"id":"kvm-operator","title":"KVM Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":false,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["kvm","placement","lifecycle"]},{"id":"wintel-linux-operator","title":"Wintel/Linux Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["windows","linux","patching","baseline"]},{"id":"backup-operator","title":"Backup Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["backup","restore","dr"]},{"id":"monitoring-operator","title":"Monitoring Operator","visibility":"assigned-site-scope","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["monitoring","alert-routing","maintenance-window"]},{"id":"service-desk","title":"Service Desk","visibility":"ticket-scope","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":false,"canAudit":false,"executionDomains":["approved-runbook","incident-context","handover"]},{"id":"auditor","title":"Auditor","visibility":"audit-scope","canRequest":false,"canApprove":false,"canExecute":false,"canAdmin":false,"canAudit":true,"executionDomains":["evidence-review","export-review","compliance"]},{"id":"requester","title":"Requester","visibility":"own-requests","canRequest":true,"canApprove":false,"canExecute":false,"canAdmin":false,"canAudit":false,"executionDomains":["request-intake","evidence-view"]}]}),
    )
}

async fn auth_local_me() -> Json<Value> {
    let role = json!({"id":"platform-admin","title":"Platform Admin","visibility":"all","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":true,"canAudit":true,"executionDomains":["platform","governance","emergency"]});
    Json(
        json!({"authenticationMode":"local-mock","configuredForProduction":false,"entraGroupsConfigured":false,"requiredProductionProvider":"Microsoft Entra ID","user":"local-operator","requestedRole":null,"roleFallbackApplied":false,"role":role,"externalAccessBlocked":true}),
    )
}

async fn auth_local_decision() -> Json<Value> {
    Json(
        json!({"authenticationMode":"local-mock","configuredForProduction":false,"entraGroupsConfigured":false,"requiredProductionProvider":"Microsoft Entra ID","role":{"id":"platform-admin","title":"Platform Admin","visibility":"all","canRequest":true,"canApprove":true,"canExecute":true,"canAdmin":true,"canAudit":true,"executionDomains":["platform","governance","emergency"]},"action":"request","allowed":true,"decision":"allow","reason":"local-role-capability"}),
    )
}

async fn auth_local_login() -> Json<Value> {
    let session = ryuki_engine::auth::AuthSession::static_dry_run();
    Json(serde_json::to_value(session).unwrap_or_default())
}

async fn auth_local_logout() -> Json<Value> {
    Json(json!({"status": "logged_out"}))
}

async fn auth_status() -> Json<Value> {
    let app_cfg = crate::config_store::get_app_config();
    let tenant_configured = !app_cfg.entra_tenant_id.is_empty();
    let client_configured = !app_cfg.entra_client_id.is_empty();
    Json(json!({
        "tenant_configured": tenant_configured,
        "client_configured": client_configured,
        "enabled": tenant_configured && client_configured,
        "instance": app_cfg.entra_authority,
    }))
}

async fn auth_session() -> Json<Value> {
    let session = ryuki_engine::auth::AuthSession::static_dry_run();
    Json(serde_json::to_value(session).unwrap_or_default())
}

async fn auth_roles() -> Json<Value> {
    let roles = ryuki_engine::auth::get_rbac_roles();
    Json(serde_json::to_value(roles).unwrap_or_default())
}

async fn auth_login() -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let app_cfg = crate::config_store::get_app_config();
    if app_cfg.auth_mode == AuthMode::MockDryRun || app_cfg.entra_tenant_id.is_empty() {
        let session_id = Uuid::new_v4();
        let session_data = json!({
            "session_id": session_id.to_string(),
            "user_id": "platform-engineer",
            "display_name": "Platform Engineer",
            "email": "platform-engineer@ryuki.local",
            "roles": ["platform-engineer", "operator", "viewer"],
            "token_valid": false,
            "provider_mode": "static-dry-run"
        });

        if let Some(pool) = get_db() {
            let _ = sqlx::query(
                "INSERT INTO sessions (id, user_id, display_name, email, roles) VALUES ($1, $2, $3, $4, $5)"
            )
            .bind(session_id)
            .bind("platform-engineer")
            .bind("Platform Engineer")
            .bind("platform-engineer@ryuki.local")
            .bind(&["platform-engineer", "operator", "viewer"] as &[&str])
            .execute(pool)
            .await;
        }

        return Ok(Json(session_data));
    }
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError::new(
            "ENTRA_NOT_CONFIGURED",
            "Entra SSO not configured",
        )),
    ))
}

async fn auth_logout(
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let session_id = body
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if session_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "MISSING_SESSION_ID",
                "Session ID is required for logout",
            )),
        ));
    }
    if let Some(pool) = get_db() {
        if let Ok(uid) = Uuid::parse_str(session_id) {
            let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
                .bind(uid)
                .execute(pool)
                .await;
        }
    }
    Ok(Json(json!({"status": "logged_out"})))
}

async fn analytics_cost_capacity() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"platformScope":["vmware","hyperv","proxmox","nutanix-ahv","xen","kvm"],"domains":["compute-capacity","storage-capacity","backup-capacity","growth-trend","cost-trend","efficiency-opportunity","forecast-risk"],"signals":["capacity-pressure","storage-growth-risk","backup-growth-risk","cost-anomaly","underutilization-signal","stale-usage-data","forecast-window-missing"],"requiredGuards":["analytics-scope-summarized","aggregate-usage-known","cost-band-known","growth-trend-known","forecast-window-set","owner-known","remediation-plan-ready","evidence-redacted"],"planSections":["analyticsSummary","capacityForecast","storageForecast","backupForecast","costTrend","efficiencyOpportunities","remediationOptions","evidenceReferences"],"blockedReasons":["provider-calls-disabled","live-remediation-disabled","billing-export-ingestion-disabled","raw-cost-rows-disabled","raw-inventory-rows-disabled","resource-identifiers-disabled","tenant-identifiers-disabled","object-identifiers-disabled","raw-provider-payloads-disabled","analytics-scope-missing","aggregate-usage-missing","cost-band-missing","growth-trend-unknown","forecast-window-missing","owner-unknown","evidence-not-redacted"]}),
    )
}

#[derive(Deserialize)]
struct AnalyticsSiteQuery {
    site: Option<String>,
}

#[derive(Deserialize)]
struct AnalyticsClusterQuery {
    site: Option<String>,
    cluster: Option<String>,
}

#[derive(Deserialize)]
struct AnalyticsForecastQuery {
    site: Option<String>,
    months: Option<u32>,
}

#[derive(Deserialize)]
struct AnalyticsTrendQuery {
    site: Option<String>,
    metric: Option<String>,
}

async fn analytics_capacity(
    Query(params): Query<AnalyticsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    cost_capacity::get_site_capacity(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn analytics_capacity_cluster(
    Query(params): Query<AnalyticsClusterQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    let cluster = params.cluster.as_deref().unwrap_or("defra-general-cluster");
    cost_capacity::get_cluster_capacity(site, cluster)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn analytics_capacity_forecast(
    Query(params): Query<AnalyticsForecastQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    let months = params.months.unwrap_or(6);
    cost_capacity::forecast_capacity(site, months)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn analytics_cost_summary(
    Query(params): Query<AnalyticsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    cost_capacity::get_cost_summary(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn analytics_waste(
    Query(params): Query<AnalyticsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    cost_capacity::get_waste_report(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn analytics_rightsizing(
    Query(params): Query<AnalyticsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    cost_capacity::get_rightsizing_recommendations(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn analytics_trend(
    Query(params): Query<AnalyticsTrendQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    let metric = params.metric.as_deref().unwrap_or("cpu");
    cost_capacity::get_trend_report(site, metric)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn analytics_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "domains": [
            "compute-capacity",
            "storage-capacity",
            "cost-trend",
            "waste-identification",
            "rightsizing-recommendation",
            "capacity-forecast",
            "trend-analysis"
        ],
        "endpoints": {
            "capacity": "/api/analytics/capacity?site=",
            "capacity_cluster": "/api/analytics/capacity/cluster?site=&cluster=",
            "capacity_forecast": "/api/analytics/capacity/forecast?site=&months=",
            "cost_summary": "/api/analytics/cost/summary?site=",
            "waste": "/api/analytics/waste?site=",
            "rightsizing": "/api/analytics/rightsizing?site=",
            "trend": "/api/analytics/trend?site=&metric=",
            "contract": "/api/analytics/contract"
        },
        "metrics": ["cpu", "memory", "storage"],
        "sites": ["DEFRA", "GBLON"],
        "signals": [
            "capacity-pressure",
            "underutilization-signal",
            "idle-vm-detected",
            "oversized-vm-detected",
            "orphaned-disk-detected",
            "cost-anomaly",
            "forecast-risk"
        ],
        "requiredGuards": [
            "aggregate-usage-only",
            "no-live-provider-calls",
            "cost-bands-summarized",
            "evidence-redacted"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-remediation-disabled",
            "raw-cost-rows-disabled",
            "resource-identifiers-disabled",
            "tenant-identifiers-disabled"
        ]
    }))
}

// ─── AIOps Suggestion Engine handlers ───

#[derive(Deserialize)]
struct AiopsSiteQuery {
    site: Option<String>,
}

#[derive(Deserialize)]
struct AiopsTypeQuery {
    #[serde(rename = "type")]
    suggestion_type: String,
}

#[derive(Deserialize)]
struct AiopsReviewRequest {
    reviewer: String,
}

#[derive(Deserialize)]
struct AiopsRejectRequest {
    reason: String,
}

async fn aiops_generate(
    Query(params): Query<AiopsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    aiops::generate_suggestions(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn aiops_review(
    Path(id): Path<String>,
    Json(body): Json<AiopsReviewRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    aiops::review_suggestion(&id, &body.reviewer)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn aiops_accept(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    aiops::accept_suggestion(&id)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn aiops_reject(
    Path(id): Path<String>,
    Json(body): Json<AiopsRejectRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    aiops::reject_suggestion(&id, &body.reason)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn aiops_implement(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    aiops::implement_suggestion(&id)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn aiops_type(
    Query(params): Query<AiopsTypeQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    aiops::get_suggestions_by_type(&params.suggestion_type)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn aiops_savings(
    Query(params): Query<AiopsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    aiops::get_savings_summary(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn aiops_stats(
    Query(params): Query<AiopsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    aiops::get_suggestion_stats(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn aiops_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveCorrelationAllowed": false,
        "liveRemediationAllowed": false,
        "automationDispatchAllowed": false,
        "rawOperationRowsAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "suggestionTypes": [
            "right-sizing",
            "migration",
            "consolidation",
            "risk-reduction",
            "cost-optimization",
            "performance-improvement"
        ],
        "suggestionStatuses": [
            "new",
            "reviewed",
            "accepted",
            "rejected",
            "implemented"
        ],
        "endpoints": {
            "generate": "POST /api/analytics/aiops/generate?site=",
            "review": "POST /api/analytics/aiops/review/{id}",
            "accept": "POST /api/analytics/aiops/accept/{id}",
            "reject": "POST /api/analytics/aiops/reject/{id}",
            "implement": "POST /api/analytics/aiops/implement/{id}",
            "by_type": "GET /api/analytics/aiops/type?type=",
            "savings": "GET /api/analytics/aiops/savings?site=",
            "stats": "GET /api/analytics/aiops/stats?site=",
            "contract": "GET /api/analytics/aiops-contract"
        },
        "sites": ["DEFRA", "GBLON"],
        "requiredGuards": [
            "suggestion-static-analysis-only",
            "no-live-provider-calls",
            "reviewer-required-for-acceptance",
            "confidence-score-explicit",
            "evidence-redacted"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-correlation-disabled",
            "live-remediation-disabled",
            "automation-dispatch-disabled",
            "raw-operation-rows-disabled",
            "raw-provider-payloads-disabled"
        ]
    }))
}

async fn platform_health() -> Json<Value> {
    let health = ryuki_engine::health_monitor::run_all_checks();
    Json(serde_json::to_value(health).unwrap_or_default())
}

async fn platform_health_components() -> Json<Value> {
    let health = ryuki_engine::health_monitor::run_all_checks();
    let component_map: Vec<serde_json::Value> = health
        .checks
        .iter()
        .map(|check| {
            json!({
                "component": check.component,
                "name": check.name,
                "status": check.status.to_string(),
                "source": check.source.to_string(),
                "message": check.message,
                "last_check": check.last_check
            })
        })
        .collect();
    Json(json!({
        "source": health.source.to_string(),
        "overall_status": health.overall_status.to_string(),
        "timestamp": health.timestamp,
        "components": component_map
    }))
}

async fn platform_health_adapters() -> Json<Value> {
    let adapters = [
        "vmware",
        "hyperv",
        "proxmox",
        "nutanix",
        "xen",
        "kvm",
        "veeam",
        "commvault",
        "rubrik",
        "cohesity",
        "netbackup",
        "zabbix",
        "servicenow",
    ];
    let checks: Vec<serde_json::Value> = adapters
        .iter()
        .map(|adapter| {
            let check = ryuki_engine::health_monitor::check_adapter_health(adapter);
            json!({
                "adapter": adapter,
                "name": check.name,
                "component": check.component,
                "status": check.status.to_string(),
                "source": check.source.to_string(),
                "message": check.message,
                "last_check": check.last_check
            })
        })
        .collect();
    Json(json!({
        "source": "simulated",
        "adapters": checks
    }))
}

async fn admin_rbac_roles() -> Json<Value> {
    let roles = get_rbac_roles();
    Json(serde_json::to_value(roles).unwrap_or_default())
}

async fn admin_platform_settings() -> Json<Value> {
    if let Some(pool) = get_db() {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM platform_config")
            .fetch_all(pool)
            .await
            .unwrap_or_default();
        let mut config = PlatformConfig::default();
        for (key, value) in &rows {
            match key.as_str() {
                "entra_tenant_id" => config.entra_tenant_id = value.clone(),
                "entra_client_id" => config.entra_client_id = value.clone(),
                "entra_authority" => config.entra_authority = value.clone(),
                "auth_mode" => config.auth_mode = value.clone(),
                "database_provider" => config.database_provider = value.clone(),
                "secret_provider" => config.secret_provider = value.clone(),
                "kubernetes_runtime" => config.kubernetes_runtime = value.clone(),
                "monitoring_provider" => config.monitoring_provider = value.clone(),
                "backup_provider" => config.backup_provider = value.clone(),
                "platform_name" => config.platform_name = value.clone(),
                "platform_url" => config.platform_url = value.clone(),
                _ => {}
            }
        }
        return Json(serde_json::to_value(config).unwrap_or_default());
    }
    let config = crate::config_store::load_config().await;
    Json(serde_json::to_value(config).unwrap_or_default())
}

async fn admin_platform_settings_update(
    Json(body): Json<PlatformConfig>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let validation_errors = ryuki_core::types::validate_platform_config(&body);
    if !validation_errors.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::with_detail(
                "CONFIG_VALIDATION_FAILED",
                "Platform configuration validation failed",
                validation_errors.join("; "),
            )),
        ));
    }

    if let Some(pool) = get_db() {
        let entries = [
            ("entra_tenant_id", &body.entra_tenant_id),
            ("entra_client_id", &body.entra_client_id),
            ("entra_authority", &body.entra_authority),
            ("auth_mode", &body.auth_mode),
            ("database_provider", &body.database_provider),
            ("secret_provider", &body.secret_provider),
            ("kubernetes_runtime", &body.kubernetes_runtime),
            ("monitoring_provider", &body.monitoring_provider),
            ("backup_provider", &body.backup_provider),
            ("platform_name", &body.platform_name),
            ("platform_url", &body.platform_url),
        ];
        for (key, value) in &entries {
            let _ = sqlx::query(
                "INSERT INTO platform_config (key, value, updated_at) VALUES ($1, $2, NOW()) \
                 ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await;
        }
    }
    let _ = crate::config_store::save_config(&body).await;
    let config = if get_db().is_some() {
        body
    } else {
        crate::config_store::load_config().await
    };
    Ok(Json(serde_json::to_value(config).unwrap_or_default()))
}

async fn admin_platform_settings_reset() -> Json<Value> {
    let defaults = PlatformConfig::default();
    if let Some(pool) = get_db() {
        let entries = [
            ("entra_tenant_id", &defaults.entra_tenant_id),
            ("entra_client_id", &defaults.entra_client_id),
            ("entra_authority", &defaults.entra_authority),
            ("auth_mode", &defaults.auth_mode),
            ("database_provider", &defaults.database_provider),
            ("secret_provider", &defaults.secret_provider),
            ("kubernetes_runtime", &defaults.kubernetes_runtime),
            ("monitoring_provider", &defaults.monitoring_provider),
            ("backup_provider", &defaults.backup_provider),
            ("platform_name", &defaults.platform_name),
            ("platform_url", &defaults.platform_url),
        ];
        for (key, value) in &entries {
            let _ = sqlx::query(
                "INSERT INTO platform_config (key, value, updated_at) VALUES ($1, $2, NOW()) \
                 ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await;
        }
    }
    let _ = crate::config_store::save_config(&defaults).await;
    Json(serde_json::to_value(defaults).unwrap_or_default())
}

// ─── Request lifecycle handlers ───

/// Custom extractor: pulls AuthSession from request extensions injected by auth middleware.
struct AuthExtractor(AuthSession);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AuthExtractor {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthSession>()
            .cloned()
            .map(AuthExtractor)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "No session found"})),
                )
            })
    }
}

type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

fn status_400(msg: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg})))
}

fn status_404(id: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": format!("Request {id} not found")})),
    )
}

fn status_403() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "Admin role required for approval"})),
    )
}

fn status_409(msg: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::CONFLICT, Json(json!({"error": msg})))
}

fn map_engine_error(e: String) -> (StatusCode, Json<Value>) {
    status_400(&e)
}

fn parse_request_type(
    s: &str,
) -> Result<ryuki_engine::models::RequestType, (StatusCode, Json<Value>)> {
    use ryuki_engine::models::RequestType;
    match s {
        "server-deployment" => Ok(RequestType::ServerDeployment),
        "patch-maintenance" => Ok(RequestType::PatchMaintenance),
        "reboot-orchestration" => Ok(RequestType::RebootOrchestration),
        "controlled-restore" => Ok(RequestType::ControlledRestore),
        "zabbix-onboarding" => Ok(RequestType::ZabbixOnboarding),
        "cmdb-import" => Ok(RequestType::CmdbImport),
        "cmdb-update-export" => Ok(RequestType::CmdbUpdateExport),
        "operator-runbook-launch" => Ok(RequestType::OperatorRunbookLaunch),
        "application-environment-retirement" => Ok(RequestType::ApplicationEnvironmentRetirement),
        "vm-decommission-quarantine" => Ok(RequestType::VmDecommissionQuarantine),
        "request-preflight" => Ok(RequestType::RequestPreflight),
        "vm-day2-change" => Ok(RequestType::VmDay2Change),
        "snapshot-governance" => Ok(RequestType::SnapshotGovernance),
        "backup-coverage-report" => Ok(RequestType::BackupCoverageReport),
        _ => Err(status_400(&format!("Unknown request type: {}", s))),
    }
}

fn db_status_to_request_status(s: &str) -> ryuki_engine::models::RequestStatus {
    use ryuki_engine::models::RequestStatus;
    match s {
        "intake" => RequestStatus::Intake,
        "validated" => RequestStatus::Validated,
        "planned" => RequestStatus::Planned,
        "approved" => RequestStatus::Approved,
        "locked" => RequestStatus::Locked,
        "executing" | "executed" => RequestStatus::Executing,
        "verifying" | "verified" => RequestStatus::Verifying,
        "completed" => RequestStatus::Completed,
        "failed" => RequestStatus::Failed,
        _ => RequestStatus::Draft,
    }
}

fn request_status_to_db(s: &ryuki_engine::models::RequestStatus) -> &'static str {
    use ryuki_engine::models::RequestStatus;
    match s {
        RequestStatus::Draft => "draft",
        RequestStatus::Intake => "intake",
        RequestStatus::Validated => "validated",
        RequestStatus::Planned => "planned",
        RequestStatus::Approved => "approved",
        RequestStatus::Locked => "locked",
        RequestStatus::Executing => "executing",
        RequestStatus::Verifying => "verifying",
        RequestStatus::Completed => "completed",
        RequestStatus::Failed => "failed",
    }
}

fn db_row_to_request(row: &DbRequestRow, request_id: &str) -> ryuki_engine::models::Request {
    use ryuki_engine::models::Request;
    Request {
        id: request_id.to_string(),
        offering_id: row.request_type.clone(),
        request_type: parse_request_type(&row.request_type)
            .unwrap_or(ryuki_engine::models::RequestType::RequestPreflight),
        status: db_status_to_request_status(&row.status),
        requester: row.name.clone(),
        owner: row.name.clone(),
        site: row.site.clone(),
        environment: row.environment.clone(),
        criticality: "standard".into(),
        stages: Vec::new(),
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
        dry_run_required: true,
        approval_route: Vec::new(),
        evidence_manifest_id: None,
        metadata: std::collections::HashMap::new(),
    }
}

async fn requests_create(Json(body): Json<CreateRequest>) -> ApiResult {
    let request_type = parse_request_type(&body.request_type)?;
    let request = request_lifecycle::create_request(
        &body.request_type,
        request_type,
        &body.name,
        &body.name,
        &body.site,
        &body.environment,
        "standard",
    )
    .map_err(map_engine_error)?;

    if let Some(pool) = get_db() {
        let row = sqlx::query_as::<_, DbRequestRow>(
            "INSERT INTO requests (request_type, site, environment, name, cpu, memory_gb, justification) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at"
        )
        .bind(&body.request_type)
        .bind(&body.site)
        .bind(&body.environment)
        .bind(&body.name)
        .bind(body.cpu as i32)
        .bind(body.memory_gb as i32)
        .bind(&body.justification)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;
        let mut response = request;
        response.id = row.id.to_string();
        response.created_at = row.created_at.to_rfc3339();
        response.updated_at = row.updated_at.to_rfc3339();
        return Ok(Json(serde_json::to_value(&response).unwrap_or_default()));
    }

    request_store().lock().await.push(request.clone());
    Ok(Json(serde_json::to_value(&request).unwrap_or_default()))
}

async fn requests_list(Query(params): Query<PaginationParams>) -> Json<Value> {
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    if let Some(pool) = get_db() {
        let rows: Vec<DbRequestRow> = sqlx::query_as(
            "SELECT id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at FROM requests ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        let summaries: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "request_id": r.id.to_string(),
                    "request_type": r.request_type,
                    "status": r.status,
                    "name": r.name,
                    "site": r.site,
                    "created_at": r.created_at.to_rfc3339()
                })
            })
            .collect();
        return Json(json!(summaries));
    }

    let store = request_store().lock().await;
    let summaries: Vec<Value> = store
        .iter()
        .skip(offset)
        .take(limit)
        .map(|r| {
            json!({
                "request_id": r.id,
                "request_type": r.request_type.to_string(),
                "status": r.status.as_str(),
                "name": r.requester,
                "site": r.site,
                "created_at": r.created_at
            })
        })
        .collect();
    Json(json!(summaries))
}

async fn requests_get(Path(request_id): Path<String>) -> ApiResult {
    if let Some(pool) = get_db() {
        let uid = Uuid::parse_str(&request_id).map_err(|_| status_404(&request_id))?;
        let row: DbRequestRow = sqlx::query_as(
            "SELECT id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at FROM requests WHERE id = $1"
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| status_404(&request_id))?;
        return Ok(Json(json!({
            "request_id": row.id.to_string(),
            "request_type": row.request_type,
            "status": row.status,
            "stage": row.stage,
            "site": row.site,
            "environment": row.environment,
            "name": row.name,
            "cpu": row.cpu,
            "memory_gb": row.memory_gb,
            "justification": row.justification,
            "created_by": row.created_by,
            "created_at": row.created_at.to_rfc3339(),
            "updated_at": row.updated_at.to_rfc3339()
        })));
    }

    let store = request_store().lock().await;
    let record = store.iter().find(|r| r.id == request_id);
    match record {
        Some(r) => Ok(Json(serde_json::to_value(r).unwrap_or_default())),
        None => Err(status_404(&request_id)),
    }
}

async fn requests_validate(Path(request_id): Path<String>) -> ApiResult {
    if let Some(pool) = get_db() {
        let uid = Uuid::parse_str(&request_id).map_err(|_| status_404(&request_id))?;
        let current: DbRequestRow = sqlx::query_as(
            "SELECT id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at FROM requests WHERE id = $1"
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| status_404(&request_id))?;

        let request = db_row_to_request(&current, &request_id);
        let result = request_lifecycle::validate_request(&request).map_err(map_engine_error)?;

        let db_status = request_status_to_db(&ryuki_engine::models::RequestStatus::Validated);
        let _row: DbRequestRow = sqlx::query_as(
            "UPDATE requests SET status = $1, stage = 'validate', updated_at = NOW() WHERE id = $2 RETURNING id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at"
        )
        .bind(db_status)
        .bind(uid)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

        return Ok(Json(serde_json::to_value(&result).unwrap_or_default()));
    }

    let mut store = request_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == request_id)
        .ok_or_else(|| status_404(&request_id))?;

    let result = request_lifecycle::validate_request(&store[idx]).map_err(map_engine_error)?;

    store[idx].status = ryuki_engine::models::RequestStatus::Validated;
    store[idx].updated_at = now_iso();

    Ok(Json(serde_json::to_value(&result).unwrap_or_default()))
}

async fn requests_plan(Path(request_id): Path<String>) -> ApiResult {
    if let Some(pool) = get_db() {
        let uid = Uuid::parse_str(&request_id).map_err(|_| status_404(&request_id))?;
        let current: DbRequestRow = sqlx::query_as(
            "SELECT id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at FROM requests WHERE id = $1"
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| status_404(&request_id))?;

        let request = db_row_to_request(&current, &request_id);
        let stages = request_lifecycle::plan_request(&request).map_err(map_engine_error)?;

        let db_status = request_status_to_db(&ryuki_engine::models::RequestStatus::Planned);
        let _row: DbRequestRow = sqlx::query_as(
            "UPDATE requests SET status = $1, stage = 'plan', updated_at = NOW() WHERE id = $2 RETURNING id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at"
        )
        .bind(db_status)
        .bind(uid)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

        return Ok(Json(serde_json::to_value(&stages).unwrap_or_default()));
    }

    let mut store = request_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == request_id)
        .ok_or_else(|| status_404(&request_id))?;

    let stages = request_lifecycle::plan_request(&store[idx]).map_err(map_engine_error)?;

    store[idx].status = ryuki_engine::models::RequestStatus::Planned;
    store[idx].stages = stages.clone();
    store[idx].updated_at = now_iso();

    Ok(Json(serde_json::to_value(&stages).unwrap_or_default()))
}

async fn requests_approve(
    Path(request_id): Path<String>,
    AuthExtractor(session): AuthExtractor,
) -> ApiResult {
    if !check_permission(&session, "approve") {
        return Err(status_403());
    }
    if let Some(pool) = get_db() {
        let uid = Uuid::parse_str(&request_id).map_err(|_| status_404(&request_id))?;
        let current: DbRequestRow = sqlx::query_as(
            "SELECT id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at FROM requests WHERE id = $1"
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| status_404(&request_id))?;

        let request = db_row_to_request(&current, &request_id);
        let approved =
            request_lifecycle::approve_request(&request, "admin").map_err(map_engine_error)?;

        let db_status = request_status_to_db(&ryuki_engine::models::RequestStatus::Approved);
        let _row: DbRequestRow = sqlx::query_as(
            "UPDATE requests SET status = $1, stage = 'approve', updated_at = NOW() WHERE id = $2 RETURNING id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at"
        )
        .bind(db_status)
        .bind(uid)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

        return Ok(Json(serde_json::to_value(&approved).unwrap_or_default()));
    }

    let mut store = request_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == request_id)
        .ok_or_else(|| status_404(&request_id))?;

    let approved =
        request_lifecycle::approve_request(&store[idx], "admin").map_err(map_engine_error)?;

    store[idx] = approved.clone();

    Ok(Json(serde_json::to_value(&approved).unwrap_or_default()))
}

async fn requests_lock(
    Path(request_id): Path<String>,
    AuthExtractor(session): AuthExtractor,
) -> ApiResult {
    if !check_permission(&session, "execute") {
        return Err(status_403());
    }
    if let Some(pool) = get_db() {
        let uid = Uuid::parse_str(&request_id).map_err(|_| status_404(&request_id))?;
        let current: DbRequestRow = sqlx::query_as(
            "SELECT id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at FROM requests WHERE id = $1"
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| status_404(&request_id))?;

        let request = db_row_to_request(&current, &request_id);
        let locked = request_lifecycle::lock_request(&request).map_err(map_engine_error)?;

        let db_status = request_status_to_db(&ryuki_engine::models::RequestStatus::Locked);
        let _row: DbRequestRow = sqlx::query_as(
            "UPDATE requests SET status = $1, stage = 'lock', updated_at = NOW() WHERE id = $2 RETURNING id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at"
        )
        .bind(db_status)
        .bind(uid)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

        return Ok(Json(serde_json::to_value(&locked).unwrap_or_default()));
    }

    let mut store = request_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == request_id)
        .ok_or_else(|| status_404(&request_id))?;

    let locked = request_lifecycle::lock_request(&store[idx]).map_err(map_engine_error)?;

    store[idx] = locked.clone();

    Ok(Json(serde_json::to_value(&locked).unwrap_or_default()))
}

async fn requests_execute(
    Path(request_id): Path<String>,
    AuthExtractor(session): AuthExtractor,
) -> ApiResult {
    if !check_permission(&session, "execute") {
        return Err(status_403());
    }
    if let Some(pool) = get_db() {
        let uid = Uuid::parse_str(&request_id).map_err(|_| status_404(&request_id))?;
        let current: DbRequestRow = sqlx::query_as(
            "SELECT id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at FROM requests WHERE id = $1"
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| status_404(&request_id))?;

        let request = db_row_to_request(&current, &request_id);
        let executed = request_lifecycle::execute_request(&request).map_err(map_engine_error)?;

        let db_status = request_status_to_db(&executed.status);
        let _row: DbRequestRow = sqlx::query_as(
            "UPDATE requests SET status = $1, stage = 'execute', updated_at = NOW() WHERE id = $2 RETURNING id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at"
        )
        .bind(db_status)
        .bind(uid)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

        return Ok(Json(serde_json::to_value(&executed).unwrap_or_default()));
    }

    let mut store = request_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == request_id)
        .ok_or_else(|| status_404(&request_id))?;

    let executed = request_lifecycle::execute_request(&store[idx]).map_err(map_engine_error)?;

    store[idx] = executed.clone();

    Ok(Json(serde_json::to_value(&executed).unwrap_or_default()))
}

async fn requests_verify(
    Path(request_id): Path<String>,
    AuthExtractor(session): AuthExtractor,
) -> ApiResult {
    if !check_permission(&session, "execute") {
        return Err(status_403());
    }
    if let Some(pool) = get_db() {
        let uid = Uuid::parse_str(&request_id).map_err(|_| status_404(&request_id))?;
        let current: DbRequestRow = sqlx::query_as(
            "SELECT id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at FROM requests WHERE id = $1"
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| status_404(&request_id))?;

        let request = db_row_to_request(&current, &request_id);
        let evidence = request_lifecycle::verify_request(&request).map_err(map_engine_error)?;
        let completed = request_lifecycle::transition_status(
            &request,
            ryuki_engine::models::RequestStatus::Completed,
        )
        .map_err(map_engine_error)?;

        let db_status = request_status_to_db(&completed.status);
        let _row: DbRequestRow = sqlx::query_as(
            "UPDATE requests SET status = $1, stage = 'verify', updated_at = NOW() WHERE id = $2 RETURNING id, request_type, status, stage, site, environment, name, cpu, memory_gb, justification, created_by, created_at, updated_at"
        )
        .bind(db_status)
        .bind(uid)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

        return Ok(Json(serde_json::to_value(&evidence).unwrap_or_default()));
    }

    let mut store = request_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == request_id)
        .ok_or_else(|| status_404(&request_id))?;

    let evidence = request_lifecycle::verify_request(&store[idx]).map_err(map_engine_error)?;

    let completed = request_lifecycle::transition_status(
        &store[idx],
        ryuki_engine::models::RequestStatus::Completed,
    )
    .map_err(map_engine_error)?;

    store[idx] = completed;

    Ok(Json(serde_json::to_value(&evidence).unwrap_or_default()))
}

// ─── VM Day-2 Operations handlers ───

async fn vm_day2_plan(Json(body): Json<VmDay2PlanRequest>) -> ApiResult {
    let change_type = match body.change_type.as_str() {
        "resize-cpu" => ryuki_engine::models::VmChangeType::ResizeCpu,
        "resize-memory" => ryuki_engine::models::VmChangeType::ResizeMemory,
        "add-disk" => ryuki_engine::models::VmChangeType::AddDisk,
        "extend-disk" => ryuki_engine::models::VmChangeType::ExtendDisk,
        "migrate-host" => ryuki_engine::models::VmChangeType::MigrateHost,
        "migrate-storage" => ryuki_engine::models::VmChangeType::MigrateStorage,
        _ => return Err(status_400("Invalid change type")),
    };
    match vm_operations::plan_vm_day2_change(
        &body.target_ci_key,
        change_type,
        body.target_value,
        &body.site,
        &body.environment,
        &body.owner,
        &body.maintenance_window,
    ) {
        Ok(change) => Ok(Json(serde_json::to_value(change).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn vm_day2_validate(Json(body): Json<VmDay2PlanRequest>) -> ApiResult {
    let change_type = match body.change_type.as_str() {
        "resize-cpu" => ryuki_engine::models::VmChangeType::ResizeCpu,
        "resize-memory" => ryuki_engine::models::VmChangeType::ResizeMemory,
        "add-disk" => ryuki_engine::models::VmChangeType::AddDisk,
        "extend-disk" => ryuki_engine::models::VmChangeType::ExtendDisk,
        "migrate-host" => ryuki_engine::models::VmChangeType::MigrateHost,
        "migrate-storage" => ryuki_engine::models::VmChangeType::MigrateStorage,
        _ => return Err(status_400("Invalid change type")),
    };
    let change = vm_operations::plan_vm_day2_change(
        &body.target_ci_key,
        change_type,
        body.target_value,
        &body.site,
        &body.environment,
        &body.owner,
        &body.maintenance_window,
    )
    .map_err(|e| status_400(&e))?;
    match vm_operations::validate_vm_day2_change(&change) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn vm_day2_execute(Json(body): Json<VmDay2PlanRequest>) -> ApiResult {
    let change_type = match body.change_type.as_str() {
        "resize-cpu" => ryuki_engine::models::VmChangeType::ResizeCpu,
        "resize-memory" => ryuki_engine::models::VmChangeType::ResizeMemory,
        "add-disk" => ryuki_engine::models::VmChangeType::AddDisk,
        "extend-disk" => ryuki_engine::models::VmChangeType::ExtendDisk,
        "migrate-host" => ryuki_engine::models::VmChangeType::MigrateHost,
        "migrate-storage" => ryuki_engine::models::VmChangeType::MigrateStorage,
        _ => return Err(status_400("Invalid change type")),
    };
    let change = vm_operations::plan_vm_day2_change(
        &body.target_ci_key,
        change_type,
        body.target_value,
        &body.site,
        &body.environment,
        &body.owner,
        &body.maintenance_window,
    )
    .map_err(|e| status_400(&e))?;
    match vm_operations::execute_vm_day2_change(&change) {
        Ok(executed) => Ok(Json(serde_json::to_value(executed).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn vm_day2_verify(Json(body): Json<VmDay2PlanRequest>) -> ApiResult {
    let change_type = match body.change_type.as_str() {
        "resize-cpu" => ryuki_engine::models::VmChangeType::ResizeCpu,
        "resize-memory" => ryuki_engine::models::VmChangeType::ResizeMemory,
        "add-disk" => ryuki_engine::models::VmChangeType::AddDisk,
        "extend-disk" => ryuki_engine::models::VmChangeType::ExtendDisk,
        "migrate-host" => ryuki_engine::models::VmChangeType::MigrateHost,
        "migrate-storage" => ryuki_engine::models::VmChangeType::MigrateStorage,
        _ => return Err(status_400("Invalid change type")),
    };
    let change = vm_operations::plan_vm_day2_change(
        &body.target_ci_key,
        change_type,
        body.target_value,
        &body.site,
        &body.environment,
        &body.owner,
        &body.maintenance_window,
    )
    .map_err(|e| status_400(&e))?;
    match vm_operations::verify_vm_day2_change(&change) {
        Ok(evidence) => Ok(Json(serde_json::to_value(evidence).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn vm_day2_change_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "changeMode": "dry-run-plan",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveChangeAllowed": false,
        "supportedActions": ["resize-cpu","resize-memory","add-disk","extend-disk","migrate-host","migrate-storage"],
        "requiredInputs": ["targetCiKey","changeType","targetValue","site","environment","owner","maintenanceWindow"],
        "requiredGuards": ["request-preflight-ready","capacity-admission-ready","cmdb-ci-known","backup-state-known","monitoring-impact-reviewed","approval-route-assigned","lock-scope-defined","rollback-plan-ready","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-change-disabled","stale-inventory","capacity-not-approved","cmdb-context-ambiguous","backup-state-unknown","maintenance-window-missing"],
        "requiredEvidence": ["VM change dry-run plan","Capacity impact","Backup and monitoring impact","Verification plan","Evidence references"]
    }))
}

// ─── Snapshot Governance handlers ───

async fn snapshot_plan(Json(body): Json<SnapshotPlanRequest>) -> ApiResult {
    match snapshot_engine::plan_snapshot(
        &body.platform_ci_key,
        &body.snapshot_purpose,
        &body.requested_expiry,
        &body.owner,
        &body.support_group,
        &body.change_context,
    ) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn snapshot_validate(Json(body): Json<SnapshotPlanRequest>) -> ApiResult {
    let record = snapshot_engine::plan_snapshot(
        &body.platform_ci_key,
        &body.snapshot_purpose,
        &body.requested_expiry,
        &body.owner,
        &body.support_group,
        &body.change_context,
    )
    .map_err(|e| status_400(&e))?;
    match snapshot_engine::validate_snapshot(&record) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn snapshot_review(Json(body): Json<SnapshotPlanRequest>) -> ApiResult {
    let record = snapshot_engine::plan_snapshot(
        &body.platform_ci_key,
        &body.snapshot_purpose,
        &body.requested_expiry,
        &body.owner,
        &body.support_group,
        &body.change_context,
    )
    .map_err(|e| status_400(&e))?;
    match snapshot_engine::review_snapshot_policy(&record) {
        Ok(reviewed) => Ok(Json(serde_json::to_value(reviewed).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn snapshot_flag_stale(Json(body): Json<SnapshotPlanRequest>) -> ApiResult {
    let record = snapshot_engine::plan_snapshot(
        &body.platform_ci_key,
        &body.snapshot_purpose,
        "2020-01-01T00:00:00Z",
        &body.owner,
        &body.support_group,
        &body.change_context,
    )
    .map_err(|e| status_400(&e))?;
    match snapshot_engine::flag_stale_snapshots(&[record]) {
        Ok(flagged) => Ok(Json(serde_json::to_value(flagged).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn snapshot_remediate(Json(body): Json<SnapshotPlanRequest>) -> ApiResult {
    let mut record = snapshot_engine::plan_snapshot(
        &body.platform_ci_key,
        &body.snapshot_purpose,
        "2020-01-01T00:00:00Z",
        &body.owner,
        &body.support_group,
        &body.change_context,
    )
    .map_err(|e| status_400(&e))?;
    record.status = ryuki_engine::models::SnapshotStatus::StaleFlagged;
    match snapshot_engine::plan_snapshot_remediation(&record) {
        Ok(remediated) => Ok(Json(serde_json::to_value(remediated).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn snapshot_governance_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "governanceMode": "dry-run-review",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveSnapshotAllowed": false,
        "liveDeletionAllowed": false,
        "supportedWorkflows": ["planned-snapshot-exception","snapshot-expiry-review","stale-snapshot-remediation","owner-attestation","backup-conflict-review"],
        "requiredInputs": ["platformCiKey","snapshotPurpose","requestedExpiry","owner","supportGroup","changeContext","backupState","maintenanceWindow","evidenceManifest"],
        "requiredGuards": ["cmdb-ci-known","owner-known","backup-state-known","expiry-policy-known","approval-route-assigned","lock-scope-defined","rollback-notes-ready","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-snapshot-disabled","live-deletion-disabled","stale-inventory","missing-owner","missing-expiry","backup-conflict-unknown"],
        "requiredEvidence": ["Snapshot summary","Policy decision","Expiry review","Backup impact","Remediation dry-run plan","Approval decisions","Lock record","Handover notes","Evidence references"]
    }))
}

// ─── Backup Coverage & Restore handlers ───

async fn backup_coverage_report(Json(body): Json<CoverageReportRequest>) -> ApiResult {
    match backup_engine::generate_backup_coverage_report(&body.site_scope, &body.environment_scope)
    {
        Ok(report) => Ok(Json(serde_json::to_value(report).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn backup_restore_plan(Json(body): Json<RestorePlanRequest>) -> ApiResult {
    let restore_type = match body.restore_type.as_str() {
        "full-vm" => ryuki_engine::models::RestoreType::FullVm,
        "file-level" => ryuki_engine::models::RestoreType::FileLevel,
        "application-item" => ryuki_engine::models::RestoreType::ApplicationItem,
        "instant-vm-recovery" => ryuki_engine::models::RestoreType::InstantVmRecovery,
        _ => return Err(status_400("Invalid restore type")),
    };
    match backup_engine::plan_restore(
        &body.source_ci_key,
        restore_type,
        &body.restore_point,
        &body.target_site,
        &body.target_environment,
        &body.owner,
    ) {
        Ok(restore) => Ok(Json(serde_json::to_value(restore).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn backup_restore_validate(Json(body): Json<RestorePlanRequest>) -> ApiResult {
    let restore_type = match body.restore_type.as_str() {
        "full-vm" => ryuki_engine::models::RestoreType::FullVm,
        "file-level" => ryuki_engine::models::RestoreType::FileLevel,
        "application-item" => ryuki_engine::models::RestoreType::ApplicationItem,
        "instant-vm-recovery" => ryuki_engine::models::RestoreType::InstantVmRecovery,
        _ => return Err(status_400("Invalid restore type")),
    };
    let restore = backup_engine::plan_restore(
        &body.source_ci_key,
        restore_type,
        &body.restore_point,
        &body.target_site,
        &body.target_environment,
        &body.owner,
    )
    .map_err(|e| status_400(&e))?;
    match backup_engine::validate_restore_request(&restore) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn backup_restore_approve(Json(body): Json<RestoreActionRequest>) -> ApiResult {
    let restore = ryuki_engine::models::RestoreRequest {
        id: body.restore_id,
        source_ci_key: "ci-001".to_string(),
        restore_type: ryuki_engine::models::RestoreType::FullVm,
        restore_point: "2026-06-10T02:00:00Z".to_string(),
        target_site: "DEFRA".to_string(),
        target_environment: "production".to_string(),
        verification_plan: String::new(),
        retention_need: String::new(),
        owner: "backup-team".to_string(),
        status: ryuki_engine::models::RestoreStatus::Planned,
        dry_run_plan: None,
        created_at: String::new(),
        metadata: std::collections::HashMap::new(),
    };
    let approver = body.approver.as_deref().unwrap_or("Backup Operator");
    match backup_engine::approve_restore(&restore, approver) {
        Ok(approved) => Ok(Json(serde_json::to_value(approved).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn backup_restore_execute(Json(body): Json<RestoreActionRequest>) -> ApiResult {
    let restore = ryuki_engine::models::RestoreRequest {
        id: body.restore_id,
        source_ci_key: "ci-001".to_string(),
        restore_type: ryuki_engine::models::RestoreType::FullVm,
        restore_point: "2026-06-10T02:00:00Z".to_string(),
        target_site: "DEFRA".to_string(),
        target_environment: "production".to_string(),
        verification_plan: String::new(),
        retention_need: String::new(),
        owner: "backup-team".to_string(),
        status: ryuki_engine::models::RestoreStatus::Approved,
        dry_run_plan: None,
        created_at: String::new(),
        metadata: std::collections::HashMap::new(),
    };
    match backup_engine::execute_restore(&restore) {
        Ok(evidence) => Ok(Json(serde_json::to_value(evidence).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn backup_coverage_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "coverageMode": "dry-run-report",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveBackupQueryAllowed": false,
        "supportedWorkflows": ["backup-coverage-report","restore-plan","restore-validation","restore-approval","restore-execution"],
        "requiredInputs": ["siteScope","environmentScope","sourceCiKey","restoreType","restorePoint","targetSite","targetEnvironment","owner"],
        "requiredGuards": ["backup-state-known","restore-point-verified","target-capacity-reviewed","network-isolation-reviewed","approval-route-assigned","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-backup-query-disabled","backup-state-unknown","restore-point-not-verified","target-capacity-not-reviewed"],
        "requiredEvidence": ["Coverage report summary","Restore dry-run plan","Backup integrity check","Restore execution log","Post-restore verification","Evidence references"]
    }))
}

// ─── Server Decommission request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DecommissionPlanRequest {
    #[serde(rename = "serverName")]
    server_name: String,
    site: String,
    #[serde(rename = "osFamily")]
    os_family: String,
    #[serde(rename = "serverType")]
    server_type: String,
    reason: String,
    #[serde(rename = "finalBackupRequired")]
    final_backup_required: bool,
    #[serde(rename = "quarantineDays")]
    quarantine_days: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DecommissionApproveRequest {
    approver: String,
}

// ─── Server Decommission store (in-memory) ───

static DECOMMISSION_STORE: OnceLock<Mutex<Vec<ryuki_engine::models::DecommissionRequest>>> =
    OnceLock::new();

fn decommission_store() -> &'static Mutex<Vec<ryuki_engine::models::DecommissionRequest>> {
    DECOMMISSION_STORE.get_or_init(|| Mutex::new(Vec::new()))
}

// ─── Server Decommission handlers ───

async fn decommission_plan(Json(body): Json<DecommissionPlanRequest>) -> ApiResult {
    let server_type = match body.server_type.as_str() {
        "VM" => ryuki_engine::models::ServerType::VM,
        "Physical" => ryuki_engine::models::ServerType::Physical,
        _ => return Err(status_400("Invalid server type. Use VM or Physical.")),
    };
    match server_decommission::plan_decommission(
        &body.server_name,
        &body.site,
        &body.os_family,
        server_type,
        &body.reason,
        body.final_backup_required,
        body.quarantine_days,
    ) {
        Ok(req) => {
            let json = serde_json::to_value(&req).unwrap();
            let mut store = decommission_store().lock().await;
            store.push(req);
            Ok(Json(json))
        }
        Err(e) => Err(status_400(&e)),
    }
}

async fn decommission_validate(Json(body): Json<DecommissionPlanRequest>) -> ApiResult {
    let server_type = match body.server_type.as_str() {
        "VM" => ryuki_engine::models::ServerType::VM,
        "Physical" => ryuki_engine::models::ServerType::Physical,
        _ => return Err(status_400("Invalid server type")),
    };
    let req = server_decommission::plan_decommission(
        &body.server_name,
        &body.site,
        &body.os_family,
        server_type,
        &body.reason,
        body.final_backup_required,
        body.quarantine_days,
    )
    .map_err(|e| status_400(&e))?;
    match server_decommission::validate_decommission(&req) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn decommission_approve(
    Path(id): Path<String>,
    Json(body): Json<DecommissionApproveRequest>,
) -> ApiResult {
    let mut store = decommission_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| status_400("Decommission request not found"))?;
    let mut req = store[idx].clone();
    req.approvals_collected.push(body.approver);
    req.status = ryuki_engine::models::DecommissionStatus::Approved;
    req.updated_at = chrono::Utc::now().to_rfc3339();
    store[idx] = req.clone();
    Ok(Json(serde_json::to_value(req).unwrap()))
}

async fn decommission_quarantine(Path(id): Path<String>) -> ApiResult {
    let mut store = decommission_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| status_400("Decommission request not found"))?;
    match server_decommission::quarantine_server(&store[idx]) {
        Ok(quarantined) => {
            store[idx] = quarantined.clone();
            Ok(Json(serde_json::to_value(quarantined).unwrap()))
        }
        Err(e) => Err(status_400(&e)),
    }
}

async fn decommission_execute(Path(id): Path<String>) -> ApiResult {
    let mut store = decommission_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| status_400("Decommission request not found"))?;
    match server_decommission::execute_decommission(&store[idx]) {
        Ok(executed) => {
            store[idx] = executed.clone();
            Ok(Json(serde_json::to_value(executed).unwrap()))
        }
        Err(e) => Err(status_400(&e)),
    }
}

async fn decommission_verify(Path(id): Path<String>) -> ApiResult {
    let store = decommission_store().lock().await;
    let req = store
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| status_400("Decommission request not found"))?;
    match server_decommission::verify_decommission(req) {
        Ok(evidence) => Ok(Json(serde_json::to_value(evidence).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn decommission_rollback(Path(id): Path<String>) -> ApiResult {
    let mut store = decommission_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| status_400("Decommission request not found"))?;
    match server_decommission::rollback_decommission(&store[idx]) {
        Ok(rolled_back) => {
            store[idx] = rolled_back.clone();
            Ok(Json(serde_json::to_value(rolled_back).unwrap()))
        }
        Err(e) => Err(status_400(&e)),
    }
}

async fn decommission_quarantine_inventory() -> ApiResult {
    let store = decommission_store().lock().await;
    let requests: Vec<_> = store.clone();
    let inventory = server_decommission::get_quarantine_inventory(&requests);
    Ok(Json(serde_json::to_value(inventory).unwrap()))
}

async fn decommission_get(Path(id): Path<String>) -> ApiResult {
    let store = decommission_store().lock().await;
    let req = store
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| status_400("Decommission request not found"))?;
    Ok(Json(serde_json::to_value(req).unwrap()))
}

async fn decommission_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "decommissionMode": "dry-run-quarantine",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveDecommissionAllowed": false,
        "liveDeletionAllowed": false,
        "supportedActions": ["plan","validate","approve","quarantine","execute","verify","rollback"],
        "requiredInputs": ["serverName","site","osFamily","serverType","reason","finalBackupRequired","quarantineDays"],
        "workflowStages": ["draft","planned","validated","approved","quarantined","executed","verified","completed","rolledBack","failed"],
        "dependencyCategories": ["backup-retention","dns-records","monitoring","cmdb","network-firewall","certificates","scheduled-tasks","service-accounts","group-policy","file-shares"],
        "requiredGuards": ["dependencies-identified","backup-confirmed","approvals-collected","quarantine-period-set","monitoring-removed","dns-removed","cmdb-removed","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-decommission-disabled","live-deletion-disabled","dependencies-not-identified","backup-not-confirmed","approvals-missing","quarantine-expired"],
        "requiredEvidence": ["Decommission plan summary","Dependency review","Backup retention proof","Approval decisions","Quarantine plan","Redacted execution log","Monitoring disablement proof","CMDB closure export","Final evidence references"]
    }))
}

// ─── Linux Deployment handlers ───

fn parse_linux_distro(d: &str) -> ryuki_engine::models::LinuxDistro {
    match d {
        "sles" => ryuki_engine::models::LinuxDistro::Sles,
        "rhel" => ryuki_engine::models::LinuxDistro::Rhel,
        "rocky" => ryuki_engine::models::LinuxDistro::Rocky,
        "alma" => ryuki_engine::models::LinuxDistro::Alma,
        "ubuntu" => ryuki_engine::models::LinuxDistro::Ubuntu,
        "debian" => ryuki_engine::models::LinuxDistro::Debian,
        _ => ryuki_engine::models::LinuxDistro::Ubuntu,
    }
}

fn parse_hardening_profile(p: &str) -> ryuki_engine::models::HardeningProfile {
    match p {
        "cis-level-1" => ryuki_engine::models::HardeningProfile::CisLevel1,
        "cis-level-2" => ryuki_engine::models::HardeningProfile::CisLevel2,
        "stig" => ryuki_engine::models::HardeningProfile::Stig,
        "custom" => ryuki_engine::models::HardeningProfile::Custom,
        _ => ryuki_engine::models::HardeningProfile::CisLevel1,
    }
}

async fn linux_deploy_plan(Json(body): Json<LinuxDeployPlanRequest>) -> ApiResult {
    let distro = parse_linux_distro(&body.distro);
    let hardening = parse_hardening_profile(&body.hardening_profile);
    match linux_deployment::plan_linux_deployment(
        distro,
        &body.version,
        &body.site,
        body.cpu,
        body.memory_gb,
        body.disk_gb,
        &body.hostname,
        &body.network,
        hardening,
    ) {
        Ok(req) => Ok(Json(serde_json::to_value(req).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn linux_deploy_validate(Json(body): Json<LinuxDeployValidateRequest>) -> ApiResult {
    let distro = parse_linux_distro(&body.distro);
    let hardening = parse_hardening_profile(&body.hardening_profile);
    let req = linux_deployment::plan_linux_deployment(
        distro,
        &body.version,
        &body.site,
        body.cpu,
        body.memory_gb,
        body.disk_gb,
        &body.hostname,
        &body.network,
        hardening,
    )
    .map_err(|e| status_400(&e))?;
    match linux_deployment::validate_linux_deployment(&req) {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn linux_deploy_execute(Json(body): Json<LinuxDeployExecuteRequest>) -> ApiResult {
    let distro = parse_linux_distro(&body.distro);
    let hardening = parse_hardening_profile(&body.hardening_profile);
    let req = linux_deployment::plan_linux_deployment(
        distro,
        &body.version,
        &body.site,
        body.cpu,
        body.memory_gb,
        body.disk_gb,
        &body.hostname,
        &body.network,
        hardening,
    )
    .map_err(|e| status_400(&e))?;
    match linux_deployment::execute_linux_deployment(&req) {
        Ok(executed) => Ok(Json(serde_json::to_value(executed).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn linux_deploy_verify(Json(body): Json<LinuxDeployVerifyRequest>) -> ApiResult {
    let distro = parse_linux_distro(&body.distro);
    let hardening = parse_hardening_profile(&body.hardening_profile);
    let mut req = linux_deployment::plan_linux_deployment(
        distro,
        &body.version,
        &body.site,
        body.cpu,
        body.memory_gb,
        body.disk_gb,
        &body.hostname,
        &body.network,
        hardening,
    )
    .map_err(|e| status_400(&e))?;
    req.status = ryuki_engine::models::LinuxDeploymentStatus::Executed;
    match linux_deployment::verify_linux_deployment(&req) {
        Ok(verification) => Ok(Json(serde_json::to_value(verification).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn linux_supported_distros() -> Json<Value> {
    let catalog = linux_deployment::supported_distro_catalog();
    Json(serde_json::to_value(catalog).unwrap())
}

async fn linux_deploy_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "deployMode": "dry-run-deployment",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveDeploymentAllowed": false,
        "liveHypervisorCallsAllowed": false,
        "supportedDistros": ["sles","rhel","rocky","alma","ubuntu","debian"],
        "supportedHardeningProfiles": ["cis-level-1","cis-level-2","stig","custom"],
        "requiredInputs": ["distro","version","site","cpu","memoryGb","diskGb","hostname","network","hardeningProfile"],
        "requiredGuards": ["site-known","distro-version-supported","capacity-admission-ready","network-profile-known","hostname-valid","hardening-profile-known","approval-route-assigned","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-deployment-disabled","live-hypervisor-calls-disabled","site-unknown","distro-version-not-supported","capacity-not-approved","network-profile-missing","hostname-invalid","hardening-profile-unknown","raw-hypervisor-payloads-disabled","credential-values-disabled","object-identifiers-disabled","private-network-values-disabled","evidence-not-redacted"],
        "requiredEvidence": ["Linux deployment plan","Placement decision","Cloud-init configuration","Validation result","Execution evidence","Post-deploy verification","Evidence references"]
    }))
}

// ─── Application environment handlers ───

fn parse_environment_type(e: &str) -> app_environment::EnvironmentType {
    match e {
        "dev" => app_environment::EnvironmentType::Dev,
        "test" => app_environment::EnvironmentType::Test,
        "staging" => app_environment::EnvironmentType::Staging,
        "prod" => app_environment::EnvironmentType::Prod,
        _ => app_environment::EnvironmentType::Dev,
    }
}

async fn app_env_plan(Json(body): Json<AppEnvPlanRequest>) -> ApiResult {
    let env_type = parse_environment_type(&body.environment);
    match app_environment::plan_environment(&body.app_name, env_type, &body.site) {
        Ok(tiers) => Ok(Json(serde_json::to_value(tiers).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn app_env_validate(Json(body): Json<AppEnvValidateRequest>) -> ApiResult {
    let env_type = parse_environment_type(&body.environment);
    let tiers = app_environment::plan_environment(&body.app_name, env_type, &body.site)
        .map_err(|e| status_400(&e))?;
    let mut results = Vec::new();
    for tier in &tiers {
        match app_environment::validate_environment(tier) {
            Ok(result) => results.push(serde_json::to_value(result).unwrap()),
            Err(e) => return Err(status_400(&e)),
        }
    }
    Ok(Json(serde_json::json!({
        "validated": true,
        "tiers": tiers.len(),
        "results": results
    })))
}

async fn app_env_approve(Path(id): Path<String>) -> ApiResult {
    let tiers = app_environment::seed_examples();
    let target = tiers
        .iter()
        .find(|t| t.id == id)
        .ok_or_else(|| status_404(&id))?;
    match app_environment::approve_environment(target) {
        Ok(approved) => Ok(Json(serde_json::to_value(approved).unwrap())),
        Err(e) => Err(status_409(&e)),
    }
}

async fn app_env_deploy(Path(id): Path<String>) -> ApiResult {
    let tiers = app_environment::seed_examples();
    let target = tiers
        .iter()
        .find(|t| t.id == id)
        .ok_or_else(|| status_404(&id))?;
    if !matches!(target.status, app_environment::EnvironmentStatus::Approved) {
        return Err(status_409("Environment must be approved before deployment"));
    }
    match app_environment::deploy_environment(target) {
        Ok(deployed) => Ok(Json(serde_json::to_value(deployed).unwrap())),
        Err(e) => Err(status_409(&e)),
    }
}

async fn app_env_verify(Path(id): Path<String>) -> ApiResult {
    let tiers = app_environment::seed_examples();
    let target = tiers
        .iter()
        .find(|t| t.id == id)
        .ok_or_else(|| status_404(&id))?;
    match app_environment::verify_environment(target) {
        Ok(verification) => Ok(Json(serde_json::to_value(verification).unwrap())),
        Err(e) => Err(status_409(&e)),
    }
}

async fn app_env_status(Path(id): Path<String>) -> ApiResult {
    let tiers = app_environment::seed_examples();
    let target = tiers
        .iter()
        .find(|t| t.id == id)
        .ok_or_else(|| status_404(&id))?;
    Ok(Json(serde_json::json!({
        "id": target.id,
        "app_name": target.app_name,
        "environment": target.environment.to_string(),
        "tier": target.tier.to_string(),
        "status": target.status.to_string(),
        "site": target.site,
        "vm_count": target.vm_count,
        "network_zone": target.network_zone,
        "updated_at": target.updated_at
    })))
}

async fn app_env_list(Query(query): Query<AppEnvListQuery>) -> Json<Value> {
    let all = app_environment::seed_examples();
    let filtered: Vec<&app_environment::AppEnvironment> = if let Some(ref site) = query.site {
        all.iter().filter(|e| e.site == *site).collect()
    } else {
        all.iter().collect()
    };
    let summaries: Vec<Value> = filtered
        .iter()
        .map(|e| {
            json!({
                "id": e.id,
                "app_name": e.app_name,
                "environment": e.environment.to_string(),
                "tier": e.tier.to_string(),
                "site": e.site,
                "status": e.status.to_string()
            })
        })
        .collect();
    Json(json!(summaries))
}

async fn app_env_retire(Path(id): Path<String>) -> ApiResult {
    let tiers = app_environment::seed_examples();
    let target = tiers
        .iter()
        .find(|t| t.id == id)
        .ok_or_else(|| status_404(&id))?;
    match app_environment::retire_environment(target) {
        Ok(retired) => Ok(Json(serde_json::to_value(retired).unwrap())),
        Err(e) => Err(status_409(&e)),
    }
}

async fn app_env_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "deployMode": "dry-run-deployment",
        "dryRunRequired": true,
        "providerCallsEnabled": false,
        "liveDeploymentAllowed": false,
        "environmentTypes": ["dev","test","staging","prod"],
        "tiers": ["front","mid","back"],
        "requiredInputs": ["appName","environment","site"],
        "requiredGuards": ["site-known","network-zone-valid","capacity-admission-ready","approval-route-assigned","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-deployment-disabled","live-hypervisor-calls-disabled","site-unknown","network-zone-missing","capacity-not-approved","approval-missing","evidence-not-redacted"],
        "requiredEvidence": ["Environment plan","Tier topology","Validation result","Deployment evidence","Verification report","Evidence references"]
    }))
}

// ─── Certificate lifecycle handlers ───

async fn certificates_request(Json(body): Json<CertificateRequestRequest>) -> ApiResult {
    let req = certificate_lifecycle::CertificateRequest {
        common_name: body.common_name,
        subject: body.subject,
        service_type: body.service_type,
        hostname: body.hostname,
        site: body.site,
        validity_days: body.validity_days,
    };
    match certificate_lifecycle::request_certificate(&req) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn certificates_validate(Json(body): Json<CertificateValidateRequest>) -> ApiResult {
    let req = certificate_lifecycle::CertificateRequest {
        common_name: body.common_name,
        subject: body.subject,
        service_type: body.service_type,
        hostname: body.hostname,
        site: body.site,
        validity_days: body.validity_days,
    };
    match certificate_lifecycle::validate_certificate_request(&req) {
        Ok(()) => Ok(Json(
            serde_json::json!({"valid": true, "message": "Certificate request is valid"}),
        )),
        Err(e) => Err(status_400(&e)),
    }
}

async fn certificates_approve(Path(id): Path<String>) -> ApiResult {
    match certificate_lifecycle::approve_certificate(&id) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_404(&e)),
    }
}

async fn certificates_install(Path(id): Path<String>) -> ApiResult {
    match certificate_lifecycle::install_certificate(&id) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_404(&e)),
    }
}

async fn certificates_verify(Path(id): Path<String>) -> ApiResult {
    match certificate_lifecycle::verify_certificate(&id) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_404(&e)),
    }
}

async fn certificates_renew(
    Path(id): Path<String>,
    Json(body): Json<CertificateRenewRequest>,
) -> ApiResult {
    match certificate_lifecycle::renew_certificate(&id, body.validity_days) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn certificates_revoke(Path(id): Path<String>) -> ApiResult {
    match certificate_lifecycle::revoke_certificate(&id) {
        Ok(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        Err(e) => Err(status_404(&e)),
    }
}

async fn certificates_expiring(Query(query): Query<CertificateExpiringQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let days = query.days.unwrap_or(90);
    let results = certificate_lifecycle::check_expiry(site, days);
    Json(serde_json::to_value(results).unwrap())
}

async fn certificates_inventory() -> Json<Value> {
    let inventory = certificate_lifecycle::get_inventory();
    Json(serde_json::to_value(inventory).unwrap())
}

async fn certificates_get(Path(id): Path<String>) -> ApiResult {
    match certificate_lifecycle::get_certificate(&id) {
        Some(record) => Ok(Json(serde_json::to_value(record).unwrap())),
        None => Err(status_404(&id)),
    }
}

async fn certificate_lifecycle_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionAllowed": false,
        "dryRunRequired": true,
        "supportedWorkflows": ["certificate-request","certificate-validate","certificate-approve","certificate-install","certificate-verify","certificate-renew","certificate-revoke","certificate-expiry-check","certificate-inventory"],
        "validStatuses": ["Active","Expiring","Expired","Revoked"],
        "validServiceTypes": ["IIS","VMware","ESXi","RDP","SQL Server","Apache","Nginx","LDAP","SMTP","Custom"],
        "requiredInputs": ["commonName","subject","serviceType","hostname","site","validityDays"],
        "requiredGuards": ["common-name-known","subject-known","service-type-known","hostname-known","site-known","validity-days-valid","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-execution-disabled","unknown-certificate","invalid-validity-days","missing-common-name","missing-service-type","missing-hostname","missing-site","evidence-not-redacted"],
        "requiredEvidence": ["Certificate request summary","Validation result","Approval decision","Install evidence","Post-install verification","Expiry report","Inventory summary","Evidence references"],
        "rules": [
            {"id":"no-live-certificate-action","decision":"block","requirement":"Certificate lifecycle returns dry-run decisions only and never calls a live CA, mutates certificate stores, or deploys certificates to endpoints.","evidence":"Certificate request summary"},
            {"id":"validation-before-approval-required","decision":"block","requirement":"Every certificate request must pass field validation before approval readiness can be represented.","evidence":"Validation result"},
            {"id":"post-install-verification-required","decision":"block","requirement":"Certificate install must be followed by a verify step before the lifecycle can move to maintain.","evidence":"Post-install verification"},
            {"id":"expiry-monitoring-required","decision":"block","requirement":"Expiring and expired certificates must be surfaced through the expiry check endpoint with site and days-window filtering.","evidence":"Expiry report"},
            {"id":"raw-certificate-data-not-exposed","decision":"block","requirement":"Certificate lifecycle evidence must use safe summaries only and must not expose private keys, certificate signing requests, CA endpoints, raw certificate blobs, or provider payloads.","evidence":"Evidence references"}
        ]
    }))
}

// ─── Alert routing handlers ───

async fn alert_routes_create(Json(body): Json<AlertRouteCreateRequest>) -> ApiResult {
    match alert_routing_engine::build_alert_route(
        &body.trigger_name,
        &body.severity,
        &body.host_group,
        &body.support_group,
        &body.priority,
    ) {
        Ok(route) => Ok(Json(serde_json::to_value(route).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn alert_routes_list() -> Json<Value> {
    let routes = alert_routing_engine::list_routes();
    Json(serde_json::to_value(routes).unwrap())
}

async fn alert_routes_get(Path(id): Path<String>) -> ApiResult {
    match alert_routing_engine::get_route(&id) {
        Some(route) => Ok(Json(serde_json::to_value(route).unwrap())),
        None => Err(status_404(&id)),
    }
}

async fn alert_routes_update(
    Path(id): Path<String>,
    Json(body): Json<AlertRouteUpdateRequest>,
) -> ApiResult {
    match alert_routing_engine::update_route(
        &id,
        body.trigger_name.as_deref(),
        body.severity.as_deref(),
        body.host_group.as_deref(),
        body.support_group.as_deref(),
        body.priority.as_deref(),
        body.enabled,
    ) {
        Ok(route) => Ok(Json(serde_json::to_value(route).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn alert_routes_delete(Path(id): Path<String>) -> ApiResult {
    match alert_routing_engine::delete_route(&id) {
        Ok(()) => Ok(Json(serde_json::json!({"deleted": true, "id": id}))),
        Err(e) => Err(status_404(&e)),
    }
}

async fn alert_resolve(Json(body): Json<AlertResolveRequest>) -> ApiResult {
    match alert_routing_engine::resolve_alert_route(
        &body.trigger_name,
        &body.severity,
        &body.host_group,
    ) {
        Ok(decision) => Ok(Json(serde_json::to_value(decision).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn alert_unrouted() -> Json<Value> {
    let unrouted = alert_routing_engine::get_unrouted_alerts();
    Json(serde_json::to_value(unrouted).unwrap())
}

async fn monitoring_alert_routing_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveRoutingAllowed": false,
        "dryRunRequired": true,
        "supportedWorkflows": ["alert-routing-create","alert-routing-list","alert-routing-update","alert-routing-delete","alert-resolve"],
        "routeDimensions": ["triggerName","severity","hostGroup","supportGroup","priority"],
        "validSeverities": ["info","warning","average","high","disaster"],
        "validPriorities": ["P1","P2","P3","P4"],
        "requiredInputs": ["triggerName","severity","hostGroup","supportGroup","priority"],
        "requiredGuards": ["trigger-name-known","severity-valid","host-group-known","support-group-known","priority-valid","evidence-redacted"],
        "blockedReasons": ["provider-calls-disabled","live-routing-disabled","unknown-trigger","invalid-severity","unknown-host-group","unknown-support-group","invalid-priority","evidence-not-redacted"],
        "requiredEvidence": ["Alert route summary","Validation result","Route decision","Coverage gap report","Evidence references"],
        "rules": [
            {"id":"no-live-alert-action","decision":"block","requirement":"Alert routing returns dry-run route decisions only and never changes Zabbix or ServiceNow actions.","evidence":"Alert route summary"},
            {"id":"support-group-required","decision":"block","requirement":"Every alert route requires a known support group before routing can proceed.","evidence":"Validation result"},
            {"id":"severity-must-be-valid","decision":"block","requirement":"Alert severity must be one of: info, warning, average, high, disaster.","evidence":"Validation result"},
            {"id":"raw-data-not-exposed","decision":"block","requirement":"Alert routing evidence must use safe summaries only and must not expose raw Zabbix or ServiceNow payloads.","evidence":"Evidence references"}
        ]
    }))
}

// ─── Network Port & VLAN Readiness handlers ───

async fn network_readiness_check(
    Query(query): Query<NetworkReadinessQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = query.site.unwrap_or_else(|| "DEFRA".to_string());
    let port_count = query.ports.unwrap_or(1);
    let vlan = query.vlan;
    let ip_count = query.ips.unwrap_or(1);

    let port_result = network_readiness::check_port_readiness(&site, port_count);

    let mut response = json!({
        "source": "dry-run",
        "site": site,
        "port_readiness": null,
        "vlan_readiness": null,
        "dry_run": true
    });

    match port_result {
        Ok(pr) => {
            response["port_readiness"] = pr;
        }
        Err(e) => {
            response["port_readiness"] = json!({"error": e});
        }
    }

    if let Some(vlan_id) = vlan {
        match network_readiness::check_vlan_readiness(&site, vlan_id, ip_count) {
            Ok(vr) => {
                response["vlan_readiness"] = vr;
            }
            Err(e) => {
                response["vlan_readiness"] = json!({"error": e});
            }
        }
    }

    Ok(Json(response))
}

async fn network_reserve_ports(
    Json(body): Json<NetworkReservePortsRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match network_readiness::reserve_ports(&body.site, body.count, &body.purpose) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn network_reserve_ips(
    Json(body): Json<NetworkReserveIpsRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match network_readiness::reserve_ips(&body.site, body.vlan_id, body.count, &body.purpose) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn network_release(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match network_readiness::release_reservation(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn network_capacity(
    Query(query): Query<NetworkSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = query.site.unwrap_or_else(|| "DEFRA".to_string());
    match network_readiness::get_site_capacity(&site) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn network_ports_inventory(
    Query(query): Query<NetworkSwitchQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let switch = query.switch.unwrap_or_else(|| "defra-sw-01".to_string());
    match network_readiness::get_port_inventory(&switch) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn network_vlans_inventory(
    Query(query): Query<NetworkSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = query.site.unwrap_or_else(|| "DEFRA".to_string());
    match network_readiness::get_vlan_inventory(&site) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn network_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveNetworkChangesAllowed": false,
        "rawInventoryRowsAllowed": false,
        "networkIdentifiersAllowed": false,
        "dryRunRequired": true,
        "workflows": [
            "host-network-readiness",
            "workload-vlan-readiness",
            "switchport-capacity-review",
            "portgroup-policy-review",
            "vlan-catalog-review",
            "network-exception-review"
        ],
        "requiredGuards": [
            "site-known",
            "network-scope-known",
            "vlan-catalog-reviewed",
            "switchport-capacity-reviewed",
            "evidence-redacted"
        ],
        "planSections": [
            "readinessSummary",
            "vlanPolicyReview",
            "portgroupPolicyReview",
            "switchportCapacityReview",
            "exceptionDecision",
            "evidenceReferences"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-network-change-disabled",
            "raw-inventory-rows-disabled",
            "network-identifiers-disabled",
            "site-unknown",
            "vlan-catalog-missing",
            "evidence-not-redacted"
        ],
        "endpoints": {
            "GET /api/datacenter/network/readiness": "Check network port and VLAN readiness for a site",
            "POST /api/datacenter/network/reserve-ports": "Reserve ports for a site (dry-run)",
            "POST /api/datacenter/network/reserve-ips": "Reserve IPs on a VLAN (dry-run)",
            "POST /api/datacenter/network/release/{id}": "Release a port or IP reservation",
            "GET /api/datacenter/network/capacity": "Get site port and VLAN capacity summary",
            "GET /api/datacenter/network/ports": "Get port inventory for a switch",
            "GET /api/datacenter/network/vlans": "Get VLAN inventory for a site",
            "GET /api/datacenter/network-contract": "Network readiness contract"
        }
    }))
}

// ─── OOB Access Validation handlers ───

async fn oob_test_endpoint(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match oob_access::test_endpoint(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn oob_validate_cert(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match oob_access::validate_certificate(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn oob_check_defaults(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match oob_access::check_default_credentials(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(json!({"error": e})))),
    }
}

async fn oob_inventory(
    Query(query): Query<OobInventoryQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = query.site.unwrap_or_default();
    match oob_access::get_inventory(&site) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn oob_failing(
    Query(query): Query<OobFailingQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = query.site.unwrap_or_default();
    match oob_access::get_failing(&site) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn oob_cert_expiring() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match oob_access::get_cert_expiring() {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn oob_firmware_outdated() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match oob_access::get_firmware_outdated() {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn oob_validate_site(
    Path(site): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match oob_access::run_site_validation(&site) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

async fn oob_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveAccessChecksAllowed": false,
        "liveCertificateChecksAllowed": false,
        "rawInventoryRowsAllowed": false,
        "endpointIdentifiersAllowed": false,
        "serialNumbersAllowed": false,
        "dryRunRequired": true,
        "supportedConsoleTypes": ["iLO", "iDRAC", "XCC", "IPMI"],
        "workflows": [
            "oob-access-test",
            "oob-certificate-verify",
            "oob-default-credentials-check",
            "oob-inventory",
            "oob-failing-endpoints",
            "oob-cert-expiry-scan",
            "oob-firmware-baseline",
            "oob-site-validation"
        ],
        "requiredGuards": [
            "site-known",
            "endpoint-type-known",
            "certificate-reviewed",
            "default-credentials-reviewed",
            "firmware-baseline-reviewed",
            "evidence-redacted"
        ],
        "planSections": [
            "readinessSummary",
            "accessTestResults",
            "certificateReview",
            "credentialReview",
            "firmwareBaseline",
            "exceptionDecision",
            "evidenceReferences"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-access-checks-disabled",
            "live-certificate-checks-disabled",
            "raw-inventory-rows-disabled",
            "endpoint-identifiers-disabled",
            "serial-numbers-disabled",
            "site-unknown",
            "evidence-not-redacted"
        ],
        "endpoints": {
            "POST /api/datacenter/oob/test/{id}": "Mock connectivity test for an OOB endpoint",
            "POST /api/datacenter/oob/validate-cert/{id}": "Check certificate validity for an OOB endpoint",
            "POST /api/datacenter/oob/check-defaults/{id}": "Verify default credentials changed",
            "GET /api/datacenter/oob/inventory": "List all OOB endpoints (optional ?site= filter)",
            "GET /api/datacenter/oob/failing": "List endpoints that failed last test (optional ?site= filter)",
            "GET /api/datacenter/oob/cert-expiring": "Certificates expiring within 30 days",
            "GET /api/datacenter/oob/firmware-outdated": "Endpoints behind current firmware baseline",
            "POST /api/datacenter/oob/validate-site/{site}": "Run validation for all endpoints at a site",
            "GET /api/datacenter/oob-contract": "OOB access validation contract"
        }
    }))
}

// ─── ServiceNow API request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ServicenowIncidentRequest {
    #[serde(rename = "ciName")]
    ci_name: String,
    description: String,
    urgency: String,
    #[serde(rename = "assignmentGroup")]
    assignment_group: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ServicenowChangeRequest {
    #[serde(rename = "ciName")]
    ci_name: String,
    #[serde(rename = "changeType")]
    change_type: String,
    description: String,
    #[serde(rename = "plannedStart")]
    planned_start: String,
    #[serde(rename = "plannedEnd")]
    planned_end: String,
    risk: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ServicenowRequestRequest {
    #[serde(rename = "ciName")]
    ci_name: String,
    #[serde(rename = "requestType")]
    request_type: String,
    description: String,
}

// ─── ServiceNow API handlers ───

async fn servicenow_incident(Json(body): Json<ServicenowIncidentRequest>) -> ApiResult {
    match servicenow_api::prepare_incident(
        &body.ci_name,
        &body.description,
        &body.urgency,
        &body.assignment_group,
    ) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn servicenow_change(Json(body): Json<ServicenowChangeRequest>) -> ApiResult {
    match servicenow_api::prepare_change(
        &body.ci_name,
        &body.change_type,
        &body.description,
        &body.planned_start,
        &body.planned_end,
        &body.risk,
    ) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn servicenow_request(Json(body): Json<ServicenowRequestRequest>) -> ApiResult {
    match servicenow_api::prepare_request(&body.ci_name, &body.request_type, &body.description) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn servicenow_validate(Path(id): Path<String>) -> ApiResult {
    match servicenow_api::validate_request(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn servicenow_approve(Path(id): Path<String>) -> ApiResult {
    match servicenow_api::approve_request(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn servicenow_submit(Path(id): Path<String>) -> ApiResult {
    match servicenow_api::queue_for_submission(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn servicenow_status(Path(id): Path<String>) -> ApiResult {
    match servicenow_api::get_submission_status(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_404(&e)),
    }
}

async fn servicenow_pending() -> Json<Value> {
    Json(servicenow_api::get_pending_submissions())
}

async fn servicenow_cancel(Path(id): Path<String>) -> ApiResult {
    match servicenow_api::cancel_request(&id) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(status_400(&e)),
    }
}

async fn servicenow_history(Path(ci): Path<String>) -> Json<Value> {
    Json(servicenow_api::get_submission_history(&ci))
}

async fn servicenow_contract() -> Json<Value> {
    Json(servicenow_api::get_snow_contract())
}

// ─── Repository Capacity Forecasting ───

#[derive(Deserialize)]
struct RepoCapacitySiteQuery {
    site: Option<String>,
}

#[derive(Deserialize)]
struct RepoCapacityUpdateBody {
    used_tb: Option<f64>,
}

#[derive(Deserialize)]
struct RepoCapacityForecastQuery {
    days: Option<u32>,
}

#[derive(Deserialize)]
struct RepoCapacityTrendQuery {
    months: Option<u32>,
}

async fn repo_capacity_list(
    Query(params): Query<RepoCapacitySiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    repository_capacity::get_repositories(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn repo_capacity_update(
    Path(id): Path<String>,
    Json(body): Json<RepoCapacityUpdateBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let used_tb = body.used_tb.unwrap_or(0.0);
    repository_capacity::update_usage(&id, used_tb)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn repo_capacity_forecast(
    Path(id): Path<String>,
    Query(params): Query<RepoCapacityForecastQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let days = params.days.unwrap_or(30);
    repository_capacity::forecast_capacity(&id, days)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn repo_capacity_at_risk() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    repository_capacity::get_at_risk()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn repo_capacity_report(
    Query(params): Query<RepoCapacitySiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("DEFRA");
    repository_capacity::get_capacity_report(site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn repo_capacity_trend(
    Path(id): Path<String>,
    Query(params): Query<RepoCapacityTrendQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let months = params.months.unwrap_or(3);
    repository_capacity::get_trend(&id, months)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn repo_capacity_recommendations(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    repository_capacity::get_recommendations(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

// ─── Hardware lifecycle handlers ───

async fn hardware_inventory(Query(query): Query<HardwareInventoryQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let inventory = hardware_lifecycle::get_inventory(site);
    Json(serde_json::to_value(inventory).unwrap())
}

async fn hardware_warranty_expiring() -> Json<Value> {
    let expiring = hardware_lifecycle::get_warranty_expiring();
    Json(serde_json::to_value(expiring).unwrap())
}

async fn hardware_firmware_check(Path(id): Path<String>) -> ApiResult {
    match hardware_lifecycle::check_firmware_compliance(&id) {
        Ok(check) => Ok(Json(serde_json::to_value(check).unwrap())),
        Err(e) => Err(status_404(&e)),
    }
}

async fn hardware_firmware_gaps(Query(query): Query<HardwareFirmwareGapsQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let gaps = hardware_lifecycle::get_firmware_gaps(site);
    Json(serde_json::to_value(gaps).unwrap())
}

async fn hardware_support_risk(Query(query): Query<HardwareSupportRiskQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let risk = hardware_lifecycle::get_support_risk(site);
    Json(serde_json::to_value(risk).unwrap())
}

async fn hardware_refresh_plan(Query(query): Query<HardwareRefreshPlanQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let plan = hardware_lifecycle::get_refresh_plan(site);
    Json(serde_json::to_value(plan).unwrap())
}

async fn hardware_lifecycle_report(
    Query(query): Query<HardwareLifecycleReportQuery>,
) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let report = hardware_lifecycle::get_lifecycle_report(site);
    Json(serde_json::to_value(report).unwrap())
}

async fn hardware_add(Json(body): Json<HardwareAddRequest>) -> ApiResult {
    match hardware_lifecycle::add_asset(
        &body.vendor,
        &body.model,
        &body.site,
        &body.cluster,
        &body.serial,
        &body.warranty_expiry,
    ) {
        Ok(asset) => Ok(Json(serde_json::to_value(asset).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn hardware_update_firmware(
    Path(id): Path<String>,
    Json(body): Json<HardwareUpdateFirmwareRequest>,
) -> ApiResult {
    match hardware_lifecycle::update_firmware(&id, &body.version) {
        Ok(asset) => Ok(Json(serde_json::to_value(asset).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn hardware_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "lifecycleMode": "metadata-only",
        "providerCallsEnabled": false,
        "liveExecutionAllowed": false,
        "serialNumbersAllowed": false,
        "supportedWorkflows": [
            "hardware-inventory",
            "warranty-expiry-check",
            "firmware-compliance-check",
            "firmware-gap-analysis",
            "support-risk-assessment",
            "refresh-planning",
            "lifecycle-reporting"
        ],
        "validVendors": ["HPE", "Lenovo"],
        "validModels": ["DL360 Gen10", "DL380 Gen10", "DL380 Gen9", "SR635"],
        "lifecycleStates": ["Production", "Extended", "Retiring", "Retired"],
        "supportStatuses": ["Supported", "Expiring", "Expired"],
        "requiredInputs": [
            "vendor",
            "model",
            "serialNumber",
            "site",
            "cluster",
            "warrantyExpiry",
            "firmwareBaseline",
            "firmwareInstalled"
        ],
        "requiredGuards": [
            "vendor-known",
            "model-known",
            "site-known",
            "support-status-known",
            "firmware-baseline-known",
            "evidence-redacted"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-execution-disabled",
            "serial-numbers-disabled",
            "vendor-unknown",
            "model-unknown",
            "site-unknown",
            "support-status-unknown",
            "firmware-baseline-unknown",
            "evidence-not-redacted"
        ],
        "requiredEvidence": [
            "Hardware inventory summary",
            "Warranty expiry report",
            "Firmware compliance check",
            "Firmware gap analysis",
            "Support risk assessment",
            "Refresh plan",
            "Lifecycle report",
            "Evidence references"
        ],
        "rules": [
            {
                "id": "no-live-hardware-mutation",
                "decision": "block",
                "requirement": "Hardware lifecycle returns dry-run decisions only and never calls vendor APIs, mutates firmware, or executes hardware changes.",
                "evidence": "Hardware inventory summary"
            },
            {
                "id": "no-serial-or-asset-identifiers",
                "decision": "block",
                "requirement": "Committed hardware lifecycle metadata must not contain serial numbers, asset tags, or device identifiers.",
                "evidence": "Hardware inventory summary"
            },
            {
                "id": "support-and-firmware-required",
                "decision": "block",
                "requirement": "Support status and firmware baseline must be known before operational changes can be considered.",
                "evidence": "Firmware compliance check"
            },
            {
                "id": "refresh-risk-review-required",
                "decision": "block",
                "requirement": "Hardware with support or capacity risk needs refresh plan review before continued operation.",
                "evidence": "Refresh plan"
            }
        ]
    }))
}

// ─── Outage communications handlers ───

async fn outage_notices_list(Query(query): Query<OutageNoticeListQuery>) -> Json<Value> {
    let site = query.site.as_deref().unwrap_or("");
    let notices = outage_comms::get_all_notices(site);
    Json(serde_json::to_value(notices).unwrap())
}

async fn outage_notices_create(Json(body): Json<OutageNoticeCreateRequest>) -> ApiResult {
    match outage_comms::create_notice(
        &body.site,
        body.affected_systems,
        &body.start_time,
        &body.end_time,
        &body.impact_level,
    ) {
        Ok(notice) => Ok(Json(serde_json::to_value(notice).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn outage_notices_get(Path(id): Path<String>) -> ApiResult {
    match outage_comms::get_notice(&id) {
        Ok(notice) => Ok(Json(serde_json::to_value(notice).unwrap())),
        Err(e) => Err(status_404(&e)),
    }
}

async fn outage_notices_preview(Path(id): Path<String>) -> ApiResult {
    match outage_comms::preview_notice(&id) {
        Ok(preview) => Ok(Json(preview)),
        Err(e) => Err(status_404(&e)),
    }
}

async fn outage_notices_send(Path(id): Path<String>) -> ApiResult {
    match outage_comms::send_notice(&id) {
        Ok(notice) => Ok(Json(serde_json::to_value(notice).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn outage_notices_acknowledge(
    Path(id): Path<String>,
    Json(body): Json<OutageNoticeAcknowledgeRequest>,
) -> ApiResult {
    match outage_comms::acknowledge_notice(&id, &body.user) {
        Ok(ack) => Ok(Json(serde_json::to_value(ack).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn outage_notices_complete(Path(id): Path<String>) -> ApiResult {
    match outage_comms::complete_notice(&id) {
        Ok(notice) => Ok(Json(serde_json::to_value(notice).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn outage_notices_cancel(Path(id): Path<String>) -> ApiResult {
    match outage_comms::cancel_notice(&id) {
        Ok(notice) => Ok(Json(serde_json::to_value(notice).unwrap())),
        Err(e) => Err(status_400(&e)),
    }
}

async fn outage_notices_active(Query(query): Query<OutageNoticeActiveQuery>) -> Json<Value> {
    let active = outage_comms::get_active_notices(&query.site);
    Json(serde_json::to_value(active).unwrap())
}

async fn outage_notices_history(Query(query): Query<OutageNoticeHistoryQuery>) -> Json<Value> {
    let history = outage_comms::get_notice_history(&query.site);
    Json(serde_json::to_value(history).unwrap())
}

async fn outage_notices_upcoming(Query(query): Query<OutageNoticeUpcomingQuery>) -> Json<Value> {
    let upcoming = outage_comms::get_upcoming(&query.site);
    Json(serde_json::to_value(upcoming).unwrap())
}

async fn outage_contract() -> Json<Value> {
    Json(outage_comms::get_outage_contract())
}

// ─── Image factory handlers ───

#[derive(Deserialize)]
struct ImageFactoryBuildBody {
    image_name: String,
    os_family: String,
    distro: String,
    version: String,
    site: String,
}

#[derive(Deserialize)]
struct ImageFactoryRejectBody {
    reason: String,
}

#[derive(Deserialize)]
struct ImageFactoryScheduleBody {
    site: String,
    os_family: String,
    distro: String,
}

async fn image_factory_initiate_build(Json(body): Json<ImageFactoryBuildBody>) -> ApiResult {
    image_factory::initiate_build(
        &body.image_name,
        &body.os_family,
        &body.distro,
        &body.version,
        &body.site,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn image_factory_run_tests(Path(id): Path<String>) -> ApiResult {
    image_factory::run_tests(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn image_factory_promote(Path(id): Path<String>) -> ApiResult {
    image_factory::promote_image(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn image_factory_reject(
    Path(id): Path<String>,
    Json(body): Json<ImageFactoryRejectBody>,
) -> ApiResult {
    image_factory::reject_image(&id, &body.reason)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn image_factory_active(Path(site): Path<String>) -> ApiResult {
    image_factory::get_active_images(&site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn image_factory_history(Path(site): Path<String>) -> ApiResult {
    image_factory::get_build_history(&site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn image_factory_superseded() -> ApiResult {
    image_factory::get_superseded()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn image_factory_schedule_monthly(Json(body): Json<ImageFactoryScheduleBody>) -> ApiResult {
    image_factory::schedule_monthly_build(&body.site, &body.os_family, &body.distro)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn image_factory_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionAllowed": false,
        "supportedWorkflows": [
            "initiate-build",
            "run-tests",
            "promote-image",
            "reject-image",
            "active-images",
            "build-history",
            "superseded-images",
            "schedule-monthly-build"
        ],
        "imageStatuses": ["building", "testing", "promoted", "superseded", "failed"],
        "testPhases": ["security-scan", "agent-checks", "baseline-compliance"],
        "validOsFamilies": ["Windows", "Linux"],
        "requiredInputs": [
            "image_name",
            "os_family",
            "os_version",
            "distro",
            "site_scope"
        ],
        "requiredGuards": [
            "os-family-known",
            "site-scope-known",
            "test-phases-completed",
            "compliance-baseline-met",
            "superseded-images-marked"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "live-execution-disabled",
            "os-family-unknown",
            "site-scope-unknown",
            "tests-not-completed",
            "baseline-not-compliant"
        ],
        "requiredEvidence": [
            "Golden image build log",
            "Security scan results",
            "Agent check results",
            "Baseline compliance report",
            "Promotion record",
            "Supersedence chain"
        ],
        "rules": [
            {
                "id": "no-live-image-mutation",
                "decision": "block",
                "requirement": "Image factory returns dry-run decisions only and never mutates live images or calls provider APIs.",
                "evidence": "Golden image build log"
            },
            {
                "id": "tests-required-before-promotion",
                "decision": "block",
                "requirement": "An image must pass security scan, agent checks, and baseline compliance before it can be promoted.",
                "evidence": "Security scan results"
            },
            {
                "id": "supersedence-chain-required",
                "decision": "block",
                "requirement": "Promoting a new image for a site+os pair must supersede the previous active image.",
                "evidence": "Promotion record"
            },
            {
                "id": "monthly-cadence-enforced",
                "decision": "block",
                "requirement": "Scheduled builds follow a monthly cadence to ensure fresh security baselines.",
                "evidence": "Golden image build log"
            }
        ]
    }))
}

// ─── CMDB Engine handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CmdbImportRequest {
    source: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CmdbExportQuery {
    format: Option<String>,
}

async fn cmdb_import_records(
    Json(body): Json<CmdbImportRequest>,
) -> Result<Json<Vec<ryuki_engine::models::CmdbRecord>>, (StatusCode, Json<Value>)> {
    cmdb_engine::import_cmdb_records(&body.source)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn cmdb_run_reconciliation() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let inventory = inventory_sync::sync_inventory_sources()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))?;
    let cmdb_records = cmdb_engine::import_cmdb_records("cmdb-excel-export")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))?;
    cmdb_engine::reconcile_cmdb(&inventory, &cmdb_records)
        .map(|results| Json(json!({"source": "dry-run", "reconciliation_results": results})))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn cmdb_export_records(
    Query(params): Query<CmdbExportQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let records = cmdb_engine::import_cmdb_records("cmdb-excel-export")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))?;
    let format_str = params.format.as_deref().unwrap_or("json");
    cmdb_engine::export_cmdb(&records, format_str)
        .map(|s| Json(json!({"source": "dry-run", "format": format_str, "data": s})))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

// ─── Inventory Sync handlers ───

async fn inventory_run_sync(
) -> Result<Json<Vec<ryuki_engine::models::InventoryItem>>, (StatusCode, Json<Value>)> {
    inventory_sync::sync_inventory_sources()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn inventory_run_reconciliation() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let items = inventory_sync::sync_inventory_sources()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))?;
    let source = "all-sources";
    inventory_sync::reconcile_inventory(source, &items)
        .map(|diffs| Json(json!({"source": "dry-run", "differences": diffs})))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn inventory_ownership_risks() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let items = inventory_sync::sync_inventory_sources()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))?;
    inventory_sync::detect_ownership_risks(&items)
        .map(|risks| Json(json!({"source": "dry-run", "risks": risks})))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

// ─── Evidence Pipeline handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EvidenceRedactRequest {
    pack: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EvidenceExportQuery {
    format: Option<String>,
}

async fn evidence_collect(
) -> Result<Json<ryuki_engine::models::EvidencePack>, (StatusCode, Json<Value>)> {
    let req = ryuki_engine::models::Request::new(
        "req-evidence-001".into(),
        "offering-vm".into(),
        ryuki_engine::models::RequestType::ServerDeployment,
        "system-engineer".into(),
        "app-team-web".into(),
        "DEFRA".into(),
        "production".into(),
        "high".into(),
    );
    evidence_pipeline::collect_evidence(&req)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn evidence_redact(
    Json(body): Json<EvidenceRedactRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut pack: ryuki_engine::models::EvidencePack =
        serde_json::from_value(body.pack).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
        })?;
    evidence_pipeline::redact_evidence(&mut pack)
        .map(|_| Json(serde_json::to_value(&pack).unwrap_or_default()))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn evidence_export(
    Query(params): Query<EvidenceExportQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let req = ryuki_engine::models::Request::new(
        "req-evidence-export".into(),
        "offering-vm".into(),
        ryuki_engine::models::RequestType::ServerDeployment,
        "system-engineer".into(),
        "app-team-web".into(),
        "DEFRA".into(),
        "production".into(),
        "high".into(),
    );
    let pack = evidence_pipeline::collect_evidence(&req)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))?;
    let format_str = params.format.as_deref().unwrap_or("json");
    evidence_pipeline::export_evidence(&pack, format_str)
        .map(|data| Json(json!({"source": "dry-run", "format": format_str, "data": data})))
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn evidence_verify_compliance(
    Json(body): Json<EvidenceRedactRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let pack: ryuki_engine::models::EvidencePack =
        serde_json::from_value(body.pack).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
        })?;
    evidence_pipeline::verify_evidence_compliance(&pack)
        .map(|issues| {
            Json(json!({"source": "dry-run", "compliant": issues.is_empty(), "issues": issues}))
        })
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

// ─── Health Monitor handlers ───

async fn platform_health_all_checks() -> Json<ryuki_engine::health_monitor::PlatformHealth> {
    Json(health_monitor::run_all_checks())
}

async fn platform_health_check_adapter(
    Path(adapter): Path<String>,
) -> Json<ryuki_engine::health_monitor::HealthCheck> {
    Json(health_monitor::check_adapter_health(&adapter))
}

async fn platform_health_metrics_text() -> axum::response::Response {
    axum::response::Response::builder()
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(axum::body::Body::from(health_monitor::metrics_text()))
        .unwrap()
}

// ─── Site Registry (UN/LOCODE) handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SiteSearchQuery {
    q: String,
}

async fn site_registry_list() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    site_registry::list_sites(false)
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn site_registry_get(
    Path(unlocode): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    site_registry::get_site(&unlocode)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn site_registry_activate(
    Path(unlocode): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    site_registry::activate_site(&unlocode)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn site_registry_deactivate(
    Path(unlocode): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    site_registry::deactivate_site(&unlocode)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn site_registry_search(
    Query(params): Query<SiteSearchQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    site_registry::search_sites(&params.q)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn site_registry_countries() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    site_registry::list_countries()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn site_registry_cities_by_country(
    Path(code): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    site_registry::list_cities_by_country(&code)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn site_registry_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionEnabled": false,
        "description": "UN/LOCODE-based site registry. Sites are identified by 5-character UN/LOCODE codes (e.g. DEFRA for Frankfurt, GBLON for London). Activate sites to make them available for engine operations.",
        "referenceData": "UN/LOCODE — United Nations Code for Trade and Transport Locations",
        "endpoints": [
            {"method":"GET","path":"/api/admin/sites","description":"List all reference sites with active status"},
            {"method":"GET","path":"/api/admin/sites/{unlocode}","description":"Get single site details"},
            {"method":"POST","path":"/api/admin/sites/{unlocode}/activate","description":"Activate a site for use"},
            {"method":"POST","path":"/api/admin/sites/{unlocode}/deactivate","description":"Deactivate a site"},
            {"method":"GET","path":"/api/admin/sites/search?q={query}","description":"Search by unlocode, city name, country, or country code"}
        ],
        "activeSites": ["DEBER","DEFRA","FRPAR","GBLON","NLAMS"],
        "supportedCountries": ["DE","FR","GB","NL","ES","IT","CH","AT","BE","SE","DK","IE"]
    }))
}

// ─── Runbook Execution handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RunbookStartRequest {
    #[serde(rename = "runbookId")]
    runbook_id: String,
    site: String,
    #[serde(rename = "startedBy")]
    started_by: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RunbookApproveRequest {
    approver: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RunbookFailRequest {
    reason: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RunbookListQuery {
    site: Option<String>,
}

async fn runbook_catalog() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::list_runbooks()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn runbook_start(
    Json(body): Json<RunbookStartRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::start_runbook(&body.runbook_id, &body.site, &body.started_by)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn runbook_get_execution(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::get_execution(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn runbook_execute_step(
    Path(params): Path<(String, u32)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (id, step) = params;
    runbook_execution::execute_step(&id, step)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn runbook_approve(
    Path(id): Path<String>,
    Json(body): Json<RunbookApproveRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::approve_execution(&id, &body.approver)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn runbook_complete(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::complete_execution(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn runbook_fail(
    Path(id): Path<String>,
    Json(body): Json<RunbookFailRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::fail_execution(&id, &body.reason)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn runbook_rollback(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::rollback_execution(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn runbook_executions_list(
    Query(params): Query<RunbookListQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::list_executions(params.site.as_deref())
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn runbook_active() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    runbook_execution::get_active_executions()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn runbook_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionEnabled": false,
        "endpoints": [
            {"method":"GET","path":"/api/ops/runbook/catalog"},
            {"method":"POST","path":"/api/ops/runbook/start"},
            {"method":"GET","path":"/api/ops/runbook/execution/{id}"},
            {"method":"POST","path":"/api/ops/runbook/step/{id}/{step}"},
            {"method":"POST","path":"/api/ops/runbook/approve/{id}"},
            {"method":"POST","path":"/api/ops/runbook/complete/{id}"},
            {"method":"POST","path":"/api/ops/runbook/fail/{id}"},
            {"method":"POST","path":"/api/ops/runbook/rollback/{id}"},
            {"method":"GET","path":"/api/ops/runbook/executions"},
            {"method":"GET","path":"/api/ops/runbook/active"}
        ]
    }))
}

// ─── Firmware Lifecycle handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FirmwareDeviceQuery {
    site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FirmwareExceptionRequest {
    #[serde(rename = "deviceId")]
    device_id: String,
    reason: String,
    #[serde(rename = "approvedBy")]
    approved_by: String,
    #[serde(rename = "expiryDays")]
    expiry_days: i64,
}

async fn firmware_devices_list(
    Query(params): Query<FirmwareDeviceQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::list_devices(params.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn firmware_device_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::get_device(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn firmware_check_compliance(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::check_compliance(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn firmware_noncompliant() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::get_noncompliant()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn firmware_eol() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::get_eol_devices()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn firmware_request_exception(
    Json(body): Json<FirmwareExceptionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::request_exception(
        &body.device_id,
        &body.reason,
        &body.approved_by,
        body.expiry_days,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn firmware_exceptions_list() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::list_exceptions()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn firmware_revoke_exception(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::revoke_exception(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn firmware_compliance_report() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::get_compliance_report()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn firmware_vendor_summary() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firmware_lifecycle::get_vendor_summary()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn firmware_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionEnabled": false,
        "endpoints": [
            {"method":"GET","path":"/api/datacenter/firmware/devices"},
            {"method":"GET","path":"/api/datacenter/firmware/device/{id}"},
            {"method":"POST","path":"/api/datacenter/firmware/check/{id}"},
            {"method":"GET","path":"/api/datacenter/firmware/noncompliant"},
            {"method":"GET","path":"/api/datacenter/firmware/eol"},
            {"method":"POST","path":"/api/datacenter/firmware/exception"},
            {"method":"GET","path":"/api/datacenter/firmware/exceptions"},
            {"method":"POST","path":"/api/datacenter/firmware/revoke/{id}"},
            {"method":"GET","path":"/api/datacenter/firmware/report"},
            {"method":"GET","path":"/api/datacenter/firmware/vendor-summary"}
        ]
    }))
}

// ─── Incident Context handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IncidentAssembleRequest {
    #[serde(rename = "incidentTitle")]
    incident_title: String,
    severity: String,
    #[serde(rename = "affectedCiNames")]
    affected_ci_names: Vec<String>,
    site: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IncidentResolveRequest {
    resolution: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IncidentAddCiRequest {
    #[serde(rename = "ciName")]
    ci_name: String,
    #[serde(rename = "ciType")]
    ci_type: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IncidentEscalateRequest {
    reason: String,
}

async fn incident_assemble(
    Json(body): Json<IncidentAssembleRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::assemble_context(
        &body.incident_title,
        &body.severity,
        body.affected_ci_names,
        &body.site,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn incident_get(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::get_context(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn incident_active() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::list_active_incidents()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn incident_services(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::get_affected_services(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn incident_oncall(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::get_on_call(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn incident_changes(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::get_recent_changes(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn incident_resolve(
    Path(id): Path<String>,
    Json(body): Json<IncidentResolveRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::resolve_incident(&id, &body.resolution)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn incident_add_ci(
    Path(id): Path<String>,
    Json(body): Json<IncidentAddCiRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::add_affected_ci(&id, &body.ci_name, &body.ci_type)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn incident_escalate(
    Path(id): Path<String>,
    Json(body): Json<IncidentEscalateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    incident_context::escalate(&id, &body.reason)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn incident_context_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionEnabled": false,
        "endpoints": [
            {"method":"POST","path":"/api/ops/incident/assemble"},
            {"method":"GET","path":"/api/ops/incident/{id}"},
            {"method":"GET","path":"/api/ops/incident/active"},
            {"method":"GET","path":"/api/ops/incident/{id}/services"},
            {"method":"GET","path":"/api/ops/incident/{id}/oncall"},
            {"method":"GET","path":"/api/ops/incident/{id}/changes"},
            {"method":"POST","path":"/api/ops/incident/{id}/resolve"},
            {"method":"POST","path":"/api/ops/incident/{id}/add-ci"},
            {"method":"POST","path":"/api/ops/incident/{id}/escalate"}
        ]
    }))
}

// ─── Access Recertification handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccessReviewQuery {
    site: Option<String>,
    #[serde(rename = "reviewType")]
    review_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccessReviewActionRequest {
    reviewer: String,
    justification: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccessReviewExemptRequest {
    reviewer: String,
    justification: String,
    #[serde(rename = "exemptionExpiry")]
    exemption_expiry: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccessReviewExpiringQuery {
    days: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccessCampaignCreateRequest {
    name: String,
    #[serde(rename = "reviewType")]
    review_type: String,
    #[serde(rename = "reviewerGroup")]
    reviewer_group: String,
    days: i64,
}

async fn access_reviews_list(
    Query(params): Query<AccessReviewQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::list_reviews(
        params.site.as_deref().unwrap_or(""),
        params.review_type.as_deref().unwrap_or(""),
    )
    .map(Json)
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn access_review_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::get_review(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn access_reviews_due() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::list_due_reviews()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn access_reviews_expiring(
    Query(params): Query<AccessReviewExpiringQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::list_expiring(params.days.unwrap_or(30))
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn access_review_start(
    Path(id): Path<String>,
    Json(body): Json<AccessReviewActionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::start_review(&id, &body.reviewer)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn access_review_approve(
    Path(id): Path<String>,
    Json(body): Json<AccessReviewActionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::approve_review(
        &id,
        &body.reviewer,
        &body.justification.unwrap_or_default(),
    )
    .map(Json)
    .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn access_review_revoke(
    Path(id): Path<String>,
    Json(body): Json<AccessReviewActionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::revoke_review(&id, &body.reviewer, &body.reason.unwrap_or_default())
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn access_review_exempt(
    Path(id): Path<String>,
    Json(body): Json<AccessReviewExemptRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::exempt_review(
        &id,
        &body.reviewer,
        &body.justification,
        &body.exemption_expiry,
    )
    .map(Json)
    .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn access_review_summary() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::get_summary()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn access_campaign_create(
    Json(body): Json<AccessCampaignCreateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::create_campaign(
        &body.name,
        &body.review_type,
        &body.reviewer_group,
        body.days,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn access_campaign_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::get_campaign(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn access_campaigns_list() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    access_recertification::list_campaigns()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn access_review_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionEnabled": false,
        "endpoints": [
            {"method":"GET","path":"/api/identity/access-review/reviews"},
            {"method":"GET","path":"/api/identity/access-review/review/{id}"},
            {"method":"GET","path":"/api/identity/access-review/due"},
            {"method":"GET","path":"/api/identity/access-review/expiring"},
            {"method":"POST","path":"/api/identity/access-review/{id}/start"},
            {"method":"POST","path":"/api/identity/access-review/{id}/approve"},
            {"method":"POST","path":"/api/identity/access-review/{id}/revoke"},
            {"method":"POST","path":"/api/identity/access-review/{id}/exempt"},
            {"method":"GET","path":"/api/identity/access-review/summary"},
            {"method":"POST","path":"/api/identity/access-review/campaign"},
            {"method":"GET","path":"/api/identity/access-review/campaign/{id}"},
            {"method":"GET","path":"/api/identity/access-review/campaigns"}
        ]
    }))
}

// ─── DNS & IPAM handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DnsListQuery {
    site: Option<String>,
    #[serde(rename = "recordType")]
    record_type: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DnsCreateRequest {
    name: String,
    #[serde(rename = "recordType")]
    record_type: String,
    value: String,
    zone: String,
    ttl: u32,
    site: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IpamReserveRequest {
    #[serde(rename = "subnetId")]
    subnet_id: String,
    hostname: String,
    purpose: String,
    #[serde(rename = "reservedBy")]
    reserved_by: String,
    #[serde(rename = "ttlDays")]
    ttl_days: u64,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IpamAvailabilityQuery {
    count: Option<u32>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IpamSiteQuery {
    site: Option<String>,
}

async fn dns_records_list(
    Query(q): Query<DnsListQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::list_dns_records(
        q.site.as_deref().unwrap_or(""),
        q.record_type.as_deref().unwrap_or(""),
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn dns_record_create(
    Json(b): Json<DnsCreateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::create_dns_record(&b.name, &b.record_type, &b.value, &b.zone, b.ttl, &b.site)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn dns_record_get(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::get_dns_record(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn dns_record_delete(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::delete_dns_record(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn ipam_subnets_list(
    Query(q): Query<IpamSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::list_subnets(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn ipam_subnet_get(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::get_subnet(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn ipam_reserve_ip(
    Json(b): Json<IpamReserveRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::reserve_ip(
        &b.subnet_id,
        &b.hostname,
        &b.purpose,
        &b.reserved_by,
        b.ttl_days,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn ipam_release_ip(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::release_ip(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn ipam_summary(
    Query(q): Query<IpamSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::get_ipam_summary(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn ipam_check_availability(
    Path(id): Path<String>,
    Query(q): Query<IpamAvailabilityQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dns_ipam::check_ip_availability(&id, q.count.unwrap_or(1))
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn dns_ipam_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"endpoints":[{"method":"GET","path":"/api/network/dns/records"},{"method":"POST","path":"/api/network/dns/records"},{"method":"GET","path":"/api/network/dns/records/{id}"},{"method":"DELETE","path":"/api/network/dns/records/{id}"},{"method":"GET","path":"/api/network/ipam/subnets"},{"method":"GET","path":"/api/network/ipam/subnets/{id}"},{"method":"POST","path":"/api/network/ipam/reserve"},{"method":"POST","path":"/api/network/ipam/release/{id}"},{"method":"GET","path":"/api/network/ipam/summary"},{"method":"GET","path":"/api/network/ipam/availability/{id}"}]}),
    )
}

// ─── Firewall Rules handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FwListQuery {
    site: Option<String>,
    direction: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FwCreateRequest {
    name: String,
    #[serde(rename = "sourceIp")]
    source_ip: String,
    #[serde(rename = "destIp")]
    dest_ip: String,
    protocol: String,
    action: String,
    direction: String,
    site: String,
    description: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FwUpdateRequest {
    action: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FwValidateRequest {
    name: String,
    #[serde(rename = "sourceIp")]
    source_ip: String,
    #[serde(rename = "destIp")]
    dest_ip: String,
    protocol: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FwRuleSetCreateRequest {
    name: String,
    #[serde(rename = "ruleIds")]
    rule_ids: Vec<String>,
    site: String,
    target: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FwConflictsQuery {
    site: Option<String>,
}

async fn firewall_rules_list(
    Query(q): Query<FwListQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::list_rules(
        q.site.as_deref().unwrap_or(""),
        q.direction.as_deref().unwrap_or(""),
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn firewall_rule_create(
    Json(b): Json<FwCreateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::create_rule(
        &b.name,
        &b.source_ip,
        &b.dest_ip,
        &b.protocol,
        &b.action,
        &b.direction,
        &b.site,
        &b.description,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn firewall_rule_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::get_rule(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn firewall_rule_delete(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::delete_rule(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn firewall_rule_update(
    Path(id): Path<String>,
    Json(b): Json<FwUpdateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::update_rule(&id, &b.action)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn firewall_rule_validate(
    Json(b): Json<FwValidateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::validate_rule(&b.name, &b.source_ip, &b.dest_ip, &b.protocol)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn firewall_rule_set_create(
    Json(b): Json<FwRuleSetCreateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::create_rule_set(&b.name, b.rule_ids, &b.site, &b.target)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn firewall_rule_set_apply(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::apply_rule_set(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn firewall_rule_set_revoke(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::revoke_rule_set(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn firewall_conflicts(
    Query(q): Query<FwConflictsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_rules::get_conflicts(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn firewall_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"endpoints":[{"method":"GET","path":"/api/network/firewall/rules"},{"method":"POST","path":"/api/network/firewall/rules"},{"method":"GET","path":"/api/network/firewall/rules/{id}"},{"method":"DELETE","path":"/api/network/firewall/rules/{id}"},{"method":"POST","path":"/api/network/firewall/rules/{id}/update"},{"method":"POST","path":"/api/network/firewall/validate"},{"method":"POST","path":"/api/network/firewall/rule-sets"},{"method":"POST","path":"/api/network/firewall/rule-sets/{id}/apply"},{"method":"POST","path":"/api/network/firewall/rule-sets/{id}/revoke"},{"method":"GET","path":"/api/network/firewall/conflicts"}]}),
    )
}

// ─── Storage Provisioning handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StorageSiteQuery {
    site: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StorageProvisionRequest {
    name: String,
    #[serde(rename = "sizeGb")]
    size_gb: u64,
    #[serde(rename = "volumeType")]
    volume_type: String,
    #[serde(rename = "arrayId")]
    array_id: String,
    site: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StorageExtendRequest {
    #[serde(rename = "additionalGb")]
    additional_gb: u64,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StorageMapRequest {
    hostname: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StorageCapacityRequest {
    #[serde(rename = "arrayId")]
    array_id: String,
    #[serde(rename = "requestedGb")]
    requested_gb: u64,
}

async fn storage_volumes_list(
    Query(q): Query<StorageSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::list_volumes(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn storage_volume_provision(
    Json(b): Json<StorageProvisionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::provision_volume(&b.name, b.size_gb, &b.volume_type, &b.array_id, &b.site)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn storage_volume_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::get_volume(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn storage_volume_extend(
    Path(id): Path<String>,
    Json(b): Json<StorageExtendRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::extend_volume(&id, b.additional_gb)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn storage_volume_map(
    Path(id): Path<String>,
    Json(b): Json<StorageMapRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::map_volume(&id, &b.hostname)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn storage_volume_unmap(
    Path(id): Path<String>,
    Json(b): Json<StorageMapRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::unmap_volume(&id, &b.hostname)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn storage_volume_retire(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::retire_volume(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn storage_arrays_list(
    Query(q): Query<StorageSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::list_arrays(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn storage_array_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::get_array(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn storage_check_capacity(
    Json(b): Json<StorageCapacityRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::check_capacity(&b.array_id, b.requested_gb)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn storage_report(
    Query(q): Query<StorageSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    storage_provisioning::get_storage_report(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn storage_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"endpoints":[{"method":"GET","path":"/api/datacenter/storage/volumes"},{"method":"POST","path":"/api/datacenter/storage/volumes"},{"method":"GET","path":"/api/datacenter/storage/volumes/{id}"},{"method":"POST","path":"/api/datacenter/storage/volumes/{id}/extend"},{"method":"POST","path":"/api/datacenter/storage/volumes/{id}/map"},{"method":"POST","path":"/api/datacenter/storage/volumes/{id}/unmap"},{"method":"POST","path":"/api/datacenter/storage/volumes/{id}/retire"},{"method":"GET","path":"/api/datacenter/storage/arrays"},{"method":"GET","path":"/api/datacenter/storage/arrays/{id}"},{"method":"POST","path":"/api/datacenter/storage/check-capacity"},{"method":"GET","path":"/api/datacenter/storage/report"}]}),
    )
}

// ─── K8s Container Namespace handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct K8sSiteQuery {
    site: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct K8sProvisionRequest {
    name: String,
    cluster: String,
    site: String,
    cpu: u32,
    memory: u32,
    storage: u32,
    environment: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct K8sQuotaRequest {
    cpu: u32,
    memory: u32,
    storage: u32,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct K8sValidateRequest {
    name: String,
    cluster: String,
}

async fn k8s_namespaces_list(
    Query(q): Query<K8sSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::list_namespaces(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn k8s_namespace_provision(
    Json(b): Json<K8sProvisionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::provision_namespace(
        &b.name,
        &b.cluster,
        &b.site,
        b.cpu,
        b.memory,
        b.storage,
        &b.environment,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn k8s_namespace_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::get_namespace(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn k8s_namespace_update_quota(
    Path(id): Path<String>,
    Json(b): Json<K8sQuotaRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::update_quota(&id, b.cpu, b.memory, b.storage)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn k8s_namespace_suspend(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::suspend_namespace(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn k8s_namespace_resume(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::resume_namespace(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn k8s_namespace_terminate(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::terminate_namespace(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn k8s_cluster_utilization(
    Query(q): Query<K8sSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::get_cluster_utilization(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn k8s_validate_name(
    Json(b): Json<K8sValidateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::validate_namespace_name(&b.name, &b.cluster)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn k8s_summary(
    Query(q): Query<K8sSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    container_namespace::get_k8s_summary(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn k8s_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"endpoints":[{"method":"GET","path":"/api/build/k8s/namespaces"},{"method":"POST","path":"/api/build/k8s/namespaces"},{"method":"GET","path":"/api/build/k8s/namespaces/{id}"},{"method":"POST","path":"/api/build/k8s/namespaces/{id}/quota"},{"method":"POST","path":"/api/build/k8s/namespaces/{id}/suspend"},{"method":"POST","path":"/api/build/k8s/namespaces/{id}/resume"},{"method":"POST","path":"/api/build/k8s/namespaces/{id}/terminate"},{"method":"GET","path":"/api/build/k8s/utilization"},{"method":"POST","path":"/api/build/k8s/validate-name"},{"method":"GET","path":"/api/build/k8s/summary"}]}),
    )
}

// ─── DR Testing handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DrSiteQuery {
    site: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DrPlanCreateRequest {
    name: String,
    site: String,
    #[serde(rename = "targetSite")]
    target_site: String,
    systems: Vec<String>,
    rpo: u32,
    rto: u32,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DrRpoRtoRequest {
    rpo: u32,
    rto: u32,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DrTestStartRequest {
    #[serde(rename = "planId")]
    plan_id: String,
    #[serde(rename = "scenarioType")]
    scenario_type: String,
    tester: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DrTestCompleteRequest {
    #[serde(rename = "testId")]
    test_id: String,
    result: String,
    #[serde(rename = "systemsFailed")]
    systems_failed: Vec<String>,
}

async fn dr_plans_list(
    Query(q): Query<DrSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::list_plans(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn dr_plan_create(
    Json(b): Json<DrPlanCreateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::create_plan(&b.name, &b.site, &b.target_site, b.systems, b.rpo, b.rto)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn dr_plan_get(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::get_plan(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn dr_plan_update_rpo_rto(
    Path(id): Path<String>,
    Json(b): Json<DrRpoRtoRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::update_rpo_rto(&id, b.rpo, b.rto)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn dr_test_start(
    Json(b): Json<DrTestStartRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::start_test(&b.plan_id, &b.scenario_type, &b.tester)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn dr_test_complete(
    Json(b): Json<DrTestCompleteRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::complete_test(&b.test_id, &b.result, b.systems_failed)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn dr_test_results(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::get_test_results(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn dr_tests_due() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::list_due_tests()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}
async fn dr_readiness(
    Query(q): Query<DrSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::get_dr_readiness(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn dr_scenarios(
    Query(q): Query<DrSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    dr_testing::list_scenarios(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn dr_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"endpoints":[{"method":"GET","path":"/api/protect/dr/plans"},{"method":"POST","path":"/api/protect/dr/plans"},{"method":"GET","path":"/api/protect/dr/plans/{id}"},{"method":"POST","path":"/api/protect/dr/plans/{id}/rpo-rto"},{"method":"POST","path":"/api/protect/dr/tests/start"},{"method":"POST","path":"/api/protect/dr/tests/complete"},{"method":"GET","path":"/api/protect/dr/tests/results/{id}"},{"method":"GET","path":"/api/protect/dr/due-tests"},{"method":"GET","path":"/api/protect/dr/readiness"},{"method":"GET","path":"/api/protect/dr/scenarios"}]}),
    )
}

// ─── Compliance Reporting handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ComplianceControlsQuery {
    #[serde(rename = "frameworkId")]
    framework_id: Option<String>,
    site: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ComplianceAssessRequest {
    status: String,
    #[serde(rename = "assessedBy")]
    assessed_by: String,
    #[serde(rename = "evidenceRef")]
    evidence_ref: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ComplianceReportGenerateRequest {
    #[serde(rename = "frameworkId")]
    framework_id: String,
    site: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ComplianceFindingsQuery {
    site: Option<String>,
    severity: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ComplianceResolveRequest {
    resolution: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ComplianceWaiveRequest {
    reason: String,
    #[serde(rename = "approvedBy")]
    approved_by: String,
    expiry: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ComplianceSiteQuery {
    site: Option<String>,
}

async fn compliance_frameworks() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::list_frameworks()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}
async fn compliance_framework_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::get_framework(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn compliance_controls_list(
    Query(q): Query<ComplianceControlsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::list_controls(
        q.framework_id.as_deref().unwrap_or(""),
        q.site.as_deref().unwrap_or(""),
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn compliance_control_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::get_control(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn compliance_control_assess(
    Path(id): Path<String>,
    Json(b): Json<ComplianceAssessRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::assess_control(&id, &b.status, &b.assessed_by, &b.evidence_ref)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn compliance_report_generate(
    Json(b): Json<ComplianceReportGenerateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::generate_report(&b.framework_id, &b.site)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn compliance_report_get(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::get_report(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn compliance_findings_list(
    Query(q): Query<ComplianceFindingsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::list_findings(
        q.site.as_deref().unwrap_or(""),
        q.severity.as_deref().unwrap_or(""),
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn compliance_finding_resolve(
    Path(id): Path<String>,
    Json(b): Json<ComplianceResolveRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::resolve_finding(&id, &b.resolution)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn compliance_finding_waive(
    Path(id): Path<String>,
    Json(b): Json<ComplianceWaiveRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::create_waiver(&id, &b.reason, &b.approved_by, &b.expiry)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn compliance_summary(
    Query(q): Query<ComplianceSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    compliance_reporting::get_compliance_summary(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn compliance_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"endpoints":[{"method":"GET","path":"/api/audit/compliance/frameworks"},{"method":"GET","path":"/api/audit/compliance/frameworks/{id}"},{"method":"GET","path":"/api/audit/compliance/controls"},{"method":"GET","path":"/api/audit/compliance/controls/{id}"},{"method":"POST","path":"/api/audit/compliance/controls/{id}/assess"},{"method":"POST","path":"/api/audit/compliance/reports/generate"},{"method":"GET","path":"/api/audit/compliance/reports/{id}"},{"method":"GET","path":"/api/audit/compliance/findings"},{"method":"POST","path":"/api/audit/compliance/findings/{id}/resolve"},{"method":"POST","path":"/api/audit/compliance/findings/{id}/waive"},{"method":"GET","path":"/api/audit/compliance/summary"}]}),
    )
}

// ─── Secrets Rotation handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SecretsListQuery {
    site: Option<String>,
    #[serde(rename = "secretType")]
    secret_type: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SecretsRegisterRequest {
    name: String,
    #[serde(rename = "secretType")]
    secret_type: String,
    #[serde(rename = "vaultPath")]
    vault_path: String,
    #[serde(rename = "intervalDays")]
    interval_days: u64,
    owner: String,
    site: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SecretsRotateRequest {
    #[serde(rename = "rotatedBy")]
    rotated_by: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SecretsExpiringQuery {
    days: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SecretsFailRequest {
    #[serde(rename = "rotationId")]
    rotation_id: String,
    error: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SecretsSiteQuery {
    site: Option<String>,
}

async fn secrets_list(
    Query(q): Query<SecretsListQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::list_secrets(
        q.site.as_deref().unwrap_or(""),
        q.secret_type.as_deref().unwrap_or(""),
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn secrets_register(
    Json(b): Json<SecretsRegisterRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::register_secret(
        &b.name,
        &b.secret_type,
        &b.vault_path,
        b.interval_days,
        &b.owner,
        &b.site,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn secrets_get(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::get_secret(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn secrets_rotate(
    Path(id): Path<String>,
    Json(b): Json<SecretsRotateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::rotate_secret(&id, &b.rotated_by)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn secrets_rotation_history(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::get_rotation_history(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn secrets_due_rotations() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::list_due_rotations()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}
async fn secrets_expiring(
    Query(q): Query<SecretsExpiringQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::list_expiring(q.days.unwrap_or(30))
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}
async fn secrets_rotate_all(
    Query(q): Query<SecretsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::force_rotate_all(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn secrets_rotation_summary(
    Query(q): Query<SecretsSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::get_rotation_summary(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn secrets_rotation_fail(
    Json(b): Json<SecretsFailRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    secrets_rotation::mark_rotation_failed(&b.rotation_id, &b.error)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn secrets_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"endpoints":[{"method":"GET","path":"/api/protect/secrets"},{"method":"POST","path":"/api/protect/secrets"},{"method":"GET","path":"/api/protect/secrets/{id}"},{"method":"POST","path":"/api/protect/secrets/{id}/rotate"},{"method":"GET","path":"/api/protect/secrets/{id}/history"},{"method":"GET","path":"/api/protect/secrets/due"},{"method":"GET","path":"/api/protect/secrets/expiring"},{"method":"POST","path":"/api/protect/secrets/rotate-all"},{"method":"GET","path":"/api/protect/secrets/summary"},{"method":"POST","path":"/api/protect/secrets/fail"}]}),
    )
}

// ─── Load Balancer handlers ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LbSiteQuery {
    site: Option<String>,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LbProvisionRequest {
    name: String,
    vip: String,
    port: u16,
    protocol: String,
    site: String,
    members: Vec<String>,
    algorithm: String,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LbMemberRequest {
    hostname: String,
    ip: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LbValidateVipRequest {
    vip: String,
    site: String,
}

async fn lb_vs_list(
    Query(q): Query<LbSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::list_virtual_servers(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn lb_provision(
    Json(b): Json<LbProvisionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::provision_lb(
        &b.name,
        &b.vip,
        b.port,
        &b.protocol,
        &b.site,
        b.members,
        &b.algorithm,
    )
    .map(Json)
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn lb_vs_get(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::get_virtual_server(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn lb_pool_member_add(
    Path(id): Path<String>,
    Json(b): Json<LbMemberRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::add_pool_member(&id, &b.hostname, &b.ip, b.port)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn lb_pool_member_remove(
    Path((id, _hostname)): Path<(String, String)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::remove_pool_member(&id, &_hostname)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn lb_vs_drain(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::drain_virtual_server(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn lb_vs_disable(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::disable_virtual_server(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn lb_vs_enable(Path(id): Path<String>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::enable_virtual_server(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}
async fn lb_status(Query(q): Query<LbSiteQuery>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::get_lb_status(q.site.as_deref().unwrap_or(""))
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn lb_validate_vip(
    Json(b): Json<LbValidateVipRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_balancer::validate_vip(&b.vip, &b.site)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}
async fn lb_contract() -> Json<Value> {
    Json(
        json!({"source":"static-seed","providerCallsEnabled":false,"liveExecutionEnabled":false,"endpoints":[{"method":"GET","path":"/api/network/loadbalancer/vs"},{"method":"POST","path":"/api/network/loadbalancer/vs"},{"method":"GET","path":"/api/network/loadbalancer/vs/{id}"},{"method":"POST","path":"/api/network/loadbalancer/vs/{id}/member"},{"method":"DELETE","path":"/api/network/loadbalancer/vs/{id}/member/{hostname}"},{"method":"POST","path":"/api/network/loadbalancer/vs/{id}/drain"},{"method":"POST","path":"/api/network/loadbalancer/vs/{id}/disable"},{"method":"POST","path":"/api/network/loadbalancer/vs/{id}/enable"},{"method":"GET","path":"/api/network/loadbalancer/status"},{"method":"POST","path":"/api/network/loadbalancer/validate-vip"}]}),
    )
}

// ─── Datacenter Readiness request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DatacenterSiteQuery {
    site: String,
}

// ─── Datacenter Readiness handlers ───

async fn datacenter_readiness_score_endpoint(
    Query(params): Query<DatacenterSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    datacenter_readiness::get_readiness_score(&params.site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn datacenter_site_report_endpoint(
    Query(params): Query<DatacenterSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    datacenter_readiness::get_site_report(&params.site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn datacenter_failing_checks_endpoint() -> Json<Value> {
    Json(datacenter_readiness::get_failing_checks().unwrap_or_else(
        |e| json!({"source": "dry-run", "error": e, "failing_count": 0, "failing_checks": []}),
    ))
}

async fn datacenter_check_power_endpoint(
    Query(params): Query<DatacenterSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    datacenter_readiness::check_power(&params.site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn datacenter_check_cooling_endpoint(
    Query(params): Query<DatacenterSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    datacenter_readiness::check_cooling(&params.site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn datacenter_check_rack_space_endpoint(
    Query(params): Query<DatacenterSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    datacenter_readiness::check_rack_space(&params.site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn datacenter_check_switchports_endpoint(
    Query(params): Query<DatacenterSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    datacenter_readiness::check_switchports(&params.site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn datacenter_full_readiness_endpoint(
    Query(params): Query<DatacenterSiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    datacenter_readiness::run_full_readiness(&params.site)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn datacenter_sites_endpoint() -> Json<Value> {
    Json(
        datacenter_readiness::get_sites()
            .unwrap_or_else(|e| json!({"source": "dry-run", "error": e, "sites": []})),
    )
}

// ─── SQL Server Deployment request types ───

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SqlDeployPlanRequest {
    #[serde(rename = "instanceName")]
    instance_name: String,
    #[serde(rename = "sqlVersion")]
    sql_version: Option<String>,
    edition: Option<String>,
    cpu: Option<u32>,
    #[serde(rename = "memoryGb")]
    memory_gb: Option<u32>,
    #[serde(rename = "dataDiskGb")]
    data_disk_gb: Option<u32>,
    #[serde(rename = "logDiskGb")]
    log_disk_gb: Option<u32>,
    #[serde(rename = "tempdbDiskGb")]
    tempdb_disk_gb: Option<u32>,
    collation: Option<String>,
    #[serde(rename = "serviceAccount")]
    service_account: String,
    site: String,
    #[serde(rename = "clusterMode")]
    cluster_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SqlDeployValidateRequest {
    #[serde(rename = "instanceName")]
    instance_name: Option<String>,
    #[serde(rename = "sqlVersion")]
    sql_version: Option<String>,
    edition: Option<String>,
    cpu: Option<u32>,
    #[serde(rename = "memoryGb")]
    memory_gb: Option<u32>,
    site: Option<String>,
    #[serde(rename = "clusterMode")]
    cluster_mode: Option<String>,
    #[serde(rename = "serviceAccount")]
    service_account: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SqlDeployInventoryQuery {
    site: Option<String>,
}

// ─── SQL Server Deployment handlers ───

async fn sql_deploy_plan(
    Json(body): Json<SqlDeployPlanRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let req = json!({
        "instance_name": body.instance_name,
        "sql_version": body.sql_version,
        "edition": body.edition,
        "cpu": body.cpu,
        "memory_gb": body.memory_gb,
        "data_disk_gb": body.data_disk_gb,
        "log_disk_gb": body.log_disk_gb,
        "tempdb_disk_gb": body.tempdb_disk_gb,
        "collation": body.collation,
        "service_account": body.service_account,
        "site": body.site,
        "cluster_mode": body.cluster_mode
    });
    sql_deployment::plan_deployment(req)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn sql_deploy_validate(
    Json(body): Json<SqlDeployValidateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let req = json!({
        "instance_name": body.instance_name,
        "sql_version": body.sql_version,
        "edition": body.edition,
        "cpu": body.cpu,
        "memory_gb": body.memory_gb,
        "site": body.site,
        "cluster_mode": body.cluster_mode,
        "service_account": body.service_account
    });
    sql_deployment::validate_deployment(req)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e}))))
}

async fn sql_deploy_install(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sql_deployment::install_sql(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn sql_deploy_configure(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sql_deployment::configure_sql(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn sql_deploy_verify(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sql_deployment::verify_sql(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn sql_deploy_backup(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sql_deployment::add_to_backup(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn sql_deploy_monitoring(
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sql_deployment::add_to_monitoring(&id)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, Json(json!({"error": e}))))
}

async fn sql_deploy_inventory(
    Query(params): Query<SqlDeployInventoryQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let site = params.site.as_deref().unwrap_or("");
    sql_deployment::get_inventory(site)
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))))
}

async fn sql_deployment_contract() -> Json<Value> {
    Json(json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveExecutionEnabled": false,
        "deploymentPlans": [
            "standalone-instance-plan",
            "failover-cluster-plan",
            "availability-group-plan",
            "disk-layout-plan",
            "runtime-identity-plan",
            "backup-policy-plan",
            "monitoring-plan",
            "cmdb-publication-plan"
        ],
        "topologies": ["standalone", "failover-cluster", "availability-group"],
        "supportedVersions": ["2019", "2022"],
        "supportedEditions": ["Standard", "Enterprise", "Developer"],
        "supportedSites": ["DEBER","DEFRA","FRPAR","GBLON","NLAMS"],
        "maxCpu": 256,
        "maxMemoryGb": 24576,
        "endpoints": [
            {"method": "POST", "path": "/api/build/sql/plan", "description": "Plan SQL Server deployment with instance config, disk layout, and service accounts"},
            {"method": "POST", "path": "/api/build/sql/validate", "description": "Validate deployment request — capacity, naming, version support"},
            {"method": "POST", "path": "/api/build/sql/install/{id}", "description": "Mock SQL Server installation"},
            {"method": "POST", "path": "/api/build/sql/configure/{id}", "description": "Mock post-install configuration — maxdop, memory, tempdb, backup defaults"},
            {"method": "POST", "path": "/api/build/sql/verify/{id}", "description": "Mock connectivity, version, and configuration verification"},
            {"method": "POST", "path": "/api/build/sql/backup/{id}", "description": "Mock Veeam application-aware backup registration"},
            {"method": "POST", "path": "/api/build/sql/monitoring/{id}", "description": "Mock Zabbix SQL template onboarding"},
            {"method": "GET", "path": "/api/build/sql/inventory?site={site}", "description": "List all SQL instances, optionally filtered by site"}
        ],
        "requiredGuards": [
            "request-preflight-ready",
            "topology-reviewed",
            "capacity-admission-ready",
            "disk-layout-reviewed",
            "runtime-identity-reviewed",
            "backup-plan-reviewed",
            "monitoring-plan-reviewed",
            "cmdb-publication-reviewed",
            "approval-route-assigned",
            "rollback-plan-ready",
            "evidence-redacted"
        ],
        "planSections": [
            "deploymentSummary",
            "topologyReview",
            "placementPlan",
            "diskLayoutPlan",
            "runtimeIdentityPlan",
            "backupPlan",
            "monitoringPlan",
            "cmdbPublicationPlan",
            "rollbackPlan",
            "evidenceReferences"
        ],
        "blockedReasons": [
            "provider-calls-disabled",
            "worker-execution-disabled",
            "live-deployment-disabled",
            "live-sql-change-disabled",
            "live-directory-change-disabled",
            "live-backup-change-disabled",
            "live-monitoring-change-disabled",
            "live-cmdb-change-disabled",
            "raw-sql-instance-data-disabled",
            "raw-database-data-disabled",
            "raw-path-data-disabled",
            "raw-provider-payloads-disabled",
            "sql-host-identifiers-disabled",
            "credential-values-disabled",
            "topology-missing",
            "disk-layout-missing",
            "runtime-identity-missing",
            "backup-plan-missing",
            "monitoring-plan-missing",
            "cmdb-context-missing",
            "approval-missing",
            "rollback-plan-missing",
            "evidence-not-redacted"
        ],
        "requiredEvidence": [
            "Deployment summary",
            "Topology review",
            "Placement and disk layout plan",
            "Runtime identity plan",
            "Backup policy assignment",
            "Monitoring template assignment",
            "CMDB publication plan",
            "Rollback plan",
            "Evidence references"
        ],
        "rules": [
            {
                "id": "no-live-sql-deployment",
                "decision": "block",
                "requirement": "SQL Server deployments return dry-run decisions only and never execute live installations, configuration changes, backup registrations, or monitoring onboarding.",
                "evidence": "Deployment summary"
            },
            {
                "id": "capacity-admission-required",
                "decision": "block",
                "requirement": "CPU, memory, and disk capacity must be validated against site resources before installation readiness.",
                "evidence": "Placement and disk layout plan"
            },
            {
                "id": "runtime-identity-reviewed",
                "decision": "block",
                "requirement": "Service account and cluster identity must be reviewed before SQL Server execution readiness.",
                "evidence": "Runtime identity plan"
            },
            {
                "id": "backup-monitoring-onboarded",
                "decision": "block",
                "requirement": "Veeam application-aware backup and Zabbix monitoring must be assigned before a deployment can be marked complete.",
                "evidence": "Backup policy assignment"
            }
        ]
    }))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn test_platform_summary_json() -> Value {
        json!({"productName":"Ryuki Infrastructure Platform","lifecycleStages":lifecycle_stages(),"components":components(),"guardrails":guardrails(),"browserIsolation":true,"localAuthorization":{"authenticationMode":"local-mock","configuredForProduction":false,"entraGroupsConfigured":false,"roleHeader":"X-Ryuki-Local-Role","requiredProductionProvider":"Microsoft Entra ID"}})
    }

    fn test_catalog_offerings_json() -> Value {
        json!({"source":"static-seed","catalogMode":"planned-offerings","catalogReadOnly":true,"providerCallsAllowed":false,"workflowMutationAllowed":false,"liveRequestCreationAllowed":false,"liveApprovalExecutionAllowed":false,"liveExecutionAllowed":false,"rawRequestPayloadsAllowed":false,"rawProviderPayloadsAllowed":false,"rawLogContentAllowed":false,"rawRowsAllowed":false,"rawRecipientDataAllowed":false,"credentialValuesAllowed":false,"tenantIdentifiersAllowed":false,"objectIdentifiersAllowed":false,"privateNetworkValuesAllowed":false,"categories":categories(),"offerings":[{"id":"windows-server-deployment","title":"Windows server deployment","category":"Build","priority":"P0","status":"planned"}]})
    }

    #[test]
    fn test_platform_summary_has_components() {
        let part = test_platform_summary_json();
        assert_eq!(part["productName"], "Ryuki Infrastructure Platform");
        assert!(part["components"].as_array().unwrap().len() > 5);
        assert_eq!(part["lifecycleStages"].as_array().unwrap().len(), 11);
    }

    #[test]
    fn test_catalog_offerings_is_static_seed() {
        let part = test_catalog_offerings_json();
        assert_eq!(part["source"], "static-seed");
        assert_eq!(part["catalogMode"], "planned-offerings");
        assert!(part["offerings"].as_array().unwrap().len() >= 1);
        assert_eq!(part["categories"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn test_components_returns_thirteen_plus() {
        let c = components();
        assert!(c.as_array().unwrap().len() >= 13);
        let names: Vec<&str> = c
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(names.contains(&"portal-ui"));
        assert!(names.contains(&"platform-api"));
    }
}
