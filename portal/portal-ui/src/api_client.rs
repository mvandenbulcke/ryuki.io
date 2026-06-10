use crate::api::{
    cluster_capacity_admission_path, cmdb_file_exchange_path, cmdb_reconciliation_path,
    cmdb_relationship_graph_path, dry_run_plan_path, evidence_summary_path,
    inventory_resource_overview_path, operation_runs_path, policy_outcomes_path,
    request_intake_path, request_list_path, same_origin_api_path, secret_references_path,
    ApiPathError,
};
use crate::models::{
    CapacityAdmissionSummary, CmdbFileExchangeSummary, CmdbReconciliationSummary,
    CmdbRelationshipSummary, DryRunPlanSummary, EvidenceSummary, InventoryResourceSummary,
    OperationRunSummary, PolicyOutcome, RequestIntakeSummary, RequestSummary,
    SecretReferenceCatalogStatus,
};
use serde::de::DeserializeOwned;
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiClientError {
    Path(ApiPathError),
    InvalidJson { resource: &'static str },
}

impl From<ApiPathError> for ApiClientError {
    fn from(error: ApiPathError) -> Self {
        Self::Path(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiResource<T> {
    label: &'static str,
    path: &'static str,
    _marker: PhantomData<fn() -> T>,
}

impl<T> ApiResource<T> {
    const fn new(label: &'static str, path: &'static str) -> Self {
        Self {
            label,
            path,
            _marker: PhantomData,
        }
    }

    pub fn label(&self) -> &'static str {
        self.label
    }

    pub fn same_origin_path(&self) -> Result<&'static str, ApiPathError> {
        same_origin_api_path(self.path)
    }
}

impl<T> ApiResource<T>
where
    T: DeserializeOwned,
{
    pub fn decode_json(&self, body: &str) -> Result<T, ApiClientError> {
        self.same_origin_path()?;
        serde_json::from_str(body).map_err(|_| ApiClientError::InvalidJson {
            resource: self.label,
        })
    }
}

pub fn request_intake_resource() -> ApiResource<Vec<RequestIntakeSummary>> {
    ApiResource::new("request-intake", request_intake_path())
}

pub fn dry_run_plan_resource() -> ApiResource<Vec<DryRunPlanSummary>> {
    ApiResource::new("dry-run-plan", dry_run_plan_path())
}

pub fn inventory_resource_overview_resource() -> ApiResource<Vec<InventoryResourceSummary>> {
    ApiResource::new(
        "inventory-resource-overview",
        inventory_resource_overview_path(),
    )
}

pub fn capacity_admission_resource() -> ApiResource<Vec<CapacityAdmissionSummary>> {
    ApiResource::new("capacity-admission", cluster_capacity_admission_path())
}

pub fn secret_references_resource() -> ApiResource<SecretReferenceCatalogStatus> {
    ApiResource::new("secret-references", secret_references_path())
}

pub fn cmdb_file_exchange_resource() -> ApiResource<Vec<CmdbFileExchangeSummary>> {
    ApiResource::new("cmdb-file-exchange", cmdb_file_exchange_path())
}

pub fn cmdb_reconciliation_resource() -> ApiResource<Vec<CmdbReconciliationSummary>> {
    ApiResource::new("cmdb-reconciliation", cmdb_reconciliation_path())
}

pub fn cmdb_relationship_graph_resource() -> ApiResource<Vec<CmdbRelationshipSummary>> {
    ApiResource::new("cmdb-relationship-graph", cmdb_relationship_graph_path())
}

pub fn policy_outcomes_resource() -> ApiResource<Vec<PolicyOutcome>> {
    ApiResource::new("policy-outcomes", policy_outcomes_path())
}

pub fn evidence_summary_resource() -> ApiResource<Vec<EvidenceSummary>> {
    ApiResource::new("evidence-summary", evidence_summary_path())
}

pub fn operation_runs_resource() -> ApiResource<Vec<OperationRunSummary>> {
    ApiResource::new("operation-runs", operation_runs_path())
}

pub fn request_list_resource() -> ApiResource<Vec<RequestSummary>> {
    ApiResource::new("request-list", request_list_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_paths_stay_same_origin_api_paths() {
        for path in [
            request_intake_resource().same_origin_path(),
            dry_run_plan_resource().same_origin_path(),
            inventory_resource_overview_resource().same_origin_path(),
            capacity_admission_resource().same_origin_path(),
            secret_references_resource().same_origin_path(),
            cmdb_file_exchange_resource().same_origin_path(),
            cmdb_reconciliation_resource().same_origin_path(),
            cmdb_relationship_graph_resource().same_origin_path(),
            policy_outcomes_resource().same_origin_path(),
            evidence_summary_resource().same_origin_path(),
            operation_runs_resource().same_origin_path(),
            request_list_resource().same_origin_path(),
        ] {
            assert!(path.expect("path must be valid").starts_with("/api/"));
        }
    }

    #[test]
    fn decode_json_returns_typed_safe_summaries() {
        let body = r#"[{"stage":"draft intake","validation_state":"preflight required","approval_state":"approval blocked","safe_summary":"safe summary only"}]"#;
        let decoded = request_intake_resource()
            .decode_json(body)
            .expect("safe summary JSON must decode");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].stage, "draft intake");
        assert_eq!(decoded[0].validation_state, "preflight required");
    }
}
