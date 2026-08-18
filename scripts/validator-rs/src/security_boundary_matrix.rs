//! Deterministic, read-only projection of the Platform Security Boundary matrix.
//!
//! The ControlTrace document remains the authority for controls, acceptance cases,
//! trace applicability, and evidence requirements. The status overlay contributes
//! repository implementation tracking only. This module verifies their exact
//! binding before joining them and never projects production acceptance.

use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CONTROL_TRACE_PATH: &str = "catalog/security-contracts/v1/control-trace.implementation.json";
const STATUS_OVERLAY_PATH: &str =
    "catalog/security-contracts/v1/control-trace-status-overlay.implementation.json";
const EXPECTED_OVERLAY_KIND: &str = "ControlTraceStatusOverlay";
const EXPECTED_AUTHORITY_SCOPE: &str = "repository-implementation-tracking-only";
const EXPECTED_STATUS_ASSURANCE: &str = "source-audited-declaration-without-conformance-receipt";
const WORKING_TREE_CONCURRENCY_ASSURANCE: &str = "trusted-stable-checkout-required";

#[derive(Debug, Serialize)]
struct MatrixProjection {
    document_kind: &'static str,
    projection_only: bool,
    production_acceptance_asserted: bool,
    repository_status_assurance: &'static str,
    working_tree_concurrency_assurance: &'static str,
    generated_from: GeneratedFrom,
    summary: MatrixSummary,
    rows: Vec<MatrixRow>,
}

#[derive(Debug, Serialize)]
struct GeneratedFrom {
    control_trace: SourceDocument,
    status_overlay: SourceDocument,
}

#[derive(Debug, Serialize)]
struct SourceDocument {
    path: &'static str,
    document_id: String,
    document_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger_version: Option<String>,
    raw_sha256: String,
}

#[derive(Debug, Serialize)]
struct MatrixSummary {
    active_trace_count: usize,
    work_package_counts: BTreeMap<String, usize>,
    repository_status_counts: BTreeMap<String, usize>,
    implementation_evidence_state_counts: BTreeMap<String, usize>,
    runtime_tracking_state_counts: BTreeMap<String, usize>,
    deployment_evidence_state_counts: BTreeMap<String, usize>,
    deployment_always_without_evidence_tier_count: usize,
}

#[derive(Debug, Serialize)]
struct MatrixRow {
    trace_id: String,
    work_package: String,
    control: Value,
    acceptance_case: Value,
    trace_contract: Value,
    repository: Value,
    evidence_state: EvidenceStates,
}

#[derive(Debug, Serialize)]
struct EvidenceStates {
    implementation: EvidenceAssessment,
    runtime_tracking: EvidenceAssessment,
    deployment: EvidenceAssessment,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceState {
    NotInScope,
    RequiredUnproven,
    NotEvaluated,
}

impl EvidenceState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotInScope => "not_in_scope",
            Self::RequiredUnproven => "required_unproven",
            Self::NotEvaluated => "not_evaluated",
        }
    }
}

#[derive(Debug, Serialize)]
struct EvidenceAssessment {
    state: EvidenceState,
    reason: &'static str,
}

pub(crate) fn render(root: &Path) -> Result<String, String> {
    let canonical_root = root.canonicalize().map_err(|error| {
        format!(
            "failed to resolve repository root {}: {error}",
            root.display()
        )
    })?;
    if !canonical_root.is_dir() {
        return Err(format!(
            "repository root is not a directory: {}",
            canonical_root.display()
        ));
    }

    let (validation_errors, snapshot) =
        crate::security_conformance::validate_repository_with_matrix_snapshot(&canonical_root)?;
    if !validation_errors.is_empty() {
        return Err(format!(
            "security boundary contracts failed semantic validation:\n{}",
            validation_errors.join("\n")
        ));
    }
    let snapshot = snapshot.ok_or_else(|| {
        "security boundary repository validation did not return the exact ControlTrace/status-overlay snapshot"
            .to_string()
    })?;
    let projection = build_matrix(
        &snapshot.control_trace,
        &snapshot.control_trace_raw_sha256,
        &snapshot.status_overlay,
        &snapshot.status_overlay_raw_sha256,
    )?;

    serde_json::to_string_pretty(&projection)
        .map_err(|error| format!("failed to serialize security boundary matrix: {error}"))
}

fn build_matrix(
    control_trace: &Value,
    control_trace_digest: &str,
    status_overlay: &Value,
    status_overlay_digest: &str,
) -> Result<MatrixProjection, String> {
    let control_trace_object = required_object(control_trace, "ControlTrace document")?;
    let overlay_object = required_object(status_overlay, "status overlay document")?;

    let control_trace_document_id =
        required_string(control_trace_object, "document_id", "ControlTrace document")?;
    let control_trace_document_version = required_u64(
        control_trace_object,
        "document_version",
        "ControlTrace document",
    )?;
    let control_trace_ledger_id =
        required_string(control_trace_object, "ledger_id", "ControlTrace document")?;
    let control_trace_ledger_version = required_string(
        control_trace_object,
        "ledger_version",
        "ControlTrace document",
    )?;

    expect_string(
        overlay_object,
        "contract_kind",
        EXPECTED_OVERLAY_KIND,
        "status overlay document",
    )?;
    expect_string(
        overlay_object,
        "authority_scope",
        EXPECTED_AUTHORITY_SCOPE,
        "status overlay document",
    )?;
    expect_string(
        overlay_object,
        "status_assurance",
        EXPECTED_STATUS_ASSURANCE,
        "status overlay document",
    )?;

    let overlay_document_id =
        required_string(overlay_object, "document_id", "status overlay document")?;
    let overlay_document_version = required_u64(
        overlay_object,
        "document_version",
        "status overlay document",
    )?;
    let control_trace_ref = required_object_field(
        overlay_object,
        "control_trace_ref",
        "status overlay document",
    )?;
    verify_binding(
        control_trace_ref,
        &control_trace_document_id,
        control_trace_document_version,
        &control_trace_ledger_id,
        &control_trace_ledger_version,
        control_trace_digest,
    )?;

    let controls = required_array(control_trace_object, "controls", "ControlTrace document")?;
    let acceptance_cases = required_array(
        control_trace_object,
        "acceptance_cases",
        "ControlTrace document",
    )?;
    let traces = required_array(control_trace_object, "traces", "ControlTrace document")?;
    let overlay_rows = required_array(overlay_object, "rows", "status overlay document")?;

    let controls_by_id = index_records(controls, "control_id", "ControlTrace controls")?;
    let acceptance_cases_by_id = index_records(
        acceptance_cases,
        "acceptance_case_id",
        "ControlTrace acceptance cases",
    )?;

    let mut active_traces = Vec::new();
    let mut active_trace_ids = BTreeSet::new();
    for trace in traces {
        let trace_object = required_object(trace, "ControlTrace trace")?;
        let lifecycle = required_string(trace_object, "trace_lifecycle", "ControlTrace trace")?;
        if lifecycle != "active" {
            continue;
        }
        let trace_id = required_string(trace_object, "trace_id", "ControlTrace trace")?;
        if !active_trace_ids.insert(trace_id.clone()) {
            return Err(format!(
                "ControlTrace has duplicate active trace_id {trace_id}"
            ));
        }
        active_traces.push((trace_id, trace));
    }

    if active_traces.len() != overlay_rows.len() {
        return Err(format!(
            "status overlay row count {} does not match active ControlTrace row count {}",
            overlay_rows.len(),
            active_traces.len()
        ));
    }

    let mut rows = Vec::with_capacity(active_traces.len());
    let mut work_package_counts = BTreeMap::new();
    let mut repository_status_counts = BTreeMap::new();
    let mut implementation_evidence_state_counts = empty_evidence_state_counts();
    let mut runtime_tracking_state_counts = empty_evidence_state_counts();
    let mut deployment_evidence_state_counts = empty_evidence_state_counts();
    let mut deployment_always_without_evidence_tier_count = 0;

    for ((trace_id, trace), overlay_row) in active_traces.iter().zip(overlay_rows) {
        let trace_object = required_object(trace, "ControlTrace trace")?;
        let overlay_row_object = required_object(overlay_row, "status overlay row")?;
        let overlay_trace_id =
            required_string(overlay_row_object, "trace_id", "status overlay row")?;
        if overlay_trace_id.as_str() != trace_id.as_str() {
            return Err(format!(
                "status overlay trace order mismatch: expected {trace_id}, found {overlay_trace_id}"
            ));
        }

        let control_id = required_string(trace_object, "control_id", trace_id)?;
        let acceptance_case_id = required_string(trace_object, "acceptance_case_id", trace_id)?;
        let control = controls_by_id.get(&control_id).ok_or_else(|| {
            format!("{trace_id} references unknown ControlTrace control {control_id}")
        })?;
        let acceptance_case = acceptance_cases_by_id
            .get(&acceptance_case_id)
            .ok_or_else(|| {
                format!(
                    "{trace_id} references unknown ControlTrace acceptance case {acceptance_case_id}"
                )
            })?;

        // Work-package ownership is derived from the authoritative control keyed
        // by control_id. The tracking overlay cannot restate or override it.
        let control_object = required_object(control, &format!("control {control_id}"))?;
        let work_package = required_string(
            control_object,
            "owning_work_package",
            &format!("control {control_id}"),
        )?;
        ensure_matching_ownership(trace_object, acceptance_case, trace_id, &work_package)?;

        let implementation_status = required_string(
            overlay_row_object,
            "implementation_status",
            &format!("status overlay row {trace_id}"),
        )?;
        if !matches!(
            implementation_status.as_str(),
            "not_implemented" | "partial" | "implemented"
        ) {
            return Err(format!(
                "status overlay row {trace_id} has unsupported implementation_status {implementation_status}"
            ));
        }

        let blocker_kinds = blocker_kinds(overlay_row_object, trace_id)?;
        let (evidence_state, deployment_tier_gap) =
            derive_evidence_state(trace_object, &blocker_kinds, trace_id)?;
        if deployment_tier_gap {
            deployment_always_without_evidence_tier_count += 1;
        }

        increment(&mut work_package_counts, &work_package);
        increment(&mut repository_status_counts, &implementation_status);
        increment(
            &mut implementation_evidence_state_counts,
            evidence_state.implementation.state.as_str(),
        );
        increment(
            &mut runtime_tracking_state_counts,
            evidence_state.runtime_tracking.state.as_str(),
        );
        increment(
            &mut deployment_evidence_state_counts,
            evidence_state.deployment.state.as_str(),
        );

        rows.push(MatrixRow {
            trace_id: trace_id.clone(),
            work_package,
            control: (*control).clone(),
            acceptance_case: (*acceptance_case).clone(),
            trace_contract: without_fields(
                trace_object,
                &[
                    "trace_id",
                    "control_id",
                    "acceptance_case_id",
                    "owning_work_package",
                    "owning_team",
                ],
            ),
            repository: without_fields(overlay_row_object, &["trace_id"]),
            evidence_state,
        });
    }

    Ok(MatrixProjection {
        document_kind: "platform-security-boundary-matrix",
        projection_only: true,
        production_acceptance_asserted: false,
        repository_status_assurance: EXPECTED_STATUS_ASSURANCE,
        working_tree_concurrency_assurance: WORKING_TREE_CONCURRENCY_ASSURANCE,
        generated_from: GeneratedFrom {
            control_trace: SourceDocument {
                path: CONTROL_TRACE_PATH,
                document_id: control_trace_document_id,
                document_version: control_trace_document_version,
                ledger_id: Some(control_trace_ledger_id),
                ledger_version: Some(control_trace_ledger_version),
                raw_sha256: control_trace_digest.to_string(),
            },
            status_overlay: SourceDocument {
                path: STATUS_OVERLAY_PATH,
                document_id: overlay_document_id,
                document_version: overlay_document_version,
                ledger_id: None,
                ledger_version: None,
                raw_sha256: status_overlay_digest.to_string(),
            },
        },
        summary: MatrixSummary {
            active_trace_count: rows.len(),
            work_package_counts,
            repository_status_counts,
            implementation_evidence_state_counts,
            runtime_tracking_state_counts,
            deployment_evidence_state_counts,
            deployment_always_without_evidence_tier_count,
        },
        rows,
    })
}

fn empty_evidence_state_counts() -> BTreeMap<String, usize> {
    [
        EvidenceState::NotEvaluated,
        EvidenceState::NotInScope,
        EvidenceState::RequiredUnproven,
    ]
    .into_iter()
    .map(|state| (state.as_str().to_string(), 0))
    .collect()
}

fn verify_binding(
    reference: &Map<String, Value>,
    document_id: &str,
    document_version: u64,
    ledger_id: &str,
    ledger_version: &str,
    raw_sha256: &str,
) -> Result<(), String> {
    let expectations = [
        ("document_id", document_id),
        ("ledger_id", ledger_id),
        ("ledger_version", ledger_version),
        ("raw_sha256", raw_sha256),
    ];
    for (field, expected) in expectations {
        let actual = required_string(reference, field, "status overlay control_trace_ref")?;
        if actual != expected {
            return Err(format!(
                "status overlay control_trace_ref.{field} mismatch: expected {expected}, found {actual}"
            ));
        }
    }
    let actual_version = required_u64(
        reference,
        "document_version",
        "status overlay control_trace_ref",
    )?;
    if actual_version != document_version {
        return Err(format!(
            "status overlay control_trace_ref.document_version mismatch: expected {document_version}, found {actual_version}"
        ));
    }
    Ok(())
}

fn index_records(
    records: &[Value],
    id_field: &str,
    label: &str,
) -> Result<BTreeMap<String, Value>, String> {
    let mut by_id = BTreeMap::new();
    for record in records {
        let object = required_object(record, label)?;
        let id = required_string(object, id_field, label)?;
        if by_id.insert(id.clone(), record.clone()).is_some() {
            return Err(format!("{label} contains duplicate {id_field} {id}"));
        }
    }
    Ok(by_id)
}

fn ensure_matching_ownership(
    trace: &Map<String, Value>,
    acceptance_case: &Value,
    trace_id: &str,
    derived_work_package: &str,
) -> Result<(), String> {
    let trace_work_package = required_string(trace, "owning_work_package", trace_id)?;
    if trace_work_package != derived_work_package {
        return Err(format!(
            "{trace_id} owning_work_package {trace_work_package} disagrees with control-derived {derived_work_package}"
        ));
    }
    let acceptance_object = required_object(acceptance_case, "ControlTrace acceptance case")?;
    let acceptance_work_package = required_string(
        acceptance_object,
        "owning_work_package",
        "ControlTrace acceptance case",
    )?;
    if acceptance_work_package != derived_work_package {
        return Err(format!(
            "{trace_id} acceptance-case work package {acceptance_work_package} disagrees with control-derived {derived_work_package}"
        ));
    }
    Ok(())
}

fn blocker_kinds(
    overlay_row: &Map<String, Value>,
    trace_id: &str,
) -> Result<BTreeSet<String>, String> {
    let blockers = required_array(
        overlay_row,
        "blockers",
        &format!("status overlay row {trace_id}"),
    )?;
    let mut kinds = BTreeSet::new();
    for blocker in blockers {
        let blocker_object = required_object(blocker, &format!("blocker for {trace_id}"))?;
        let kind = required_string(blocker_object, "kind", &format!("blocker for {trace_id}"))?;
        kinds.insert(kind);
    }
    Ok(kinds)
}

fn derive_evidence_state(
    trace: &Map<String, Value>,
    blocker_kinds: &BTreeSet<String>,
    trace_id: &str,
) -> Result<(EvidenceStates, bool), String> {
    let applicability = required_object_field(trace, "applicability_expression", trace_id)?;
    let minimum_tiers = required_object_field(trace, "minimum_evidence_tier", trace_id)?;
    let implementation = applicability
        .get("implementation")
        .ok_or_else(|| format!("{trace_id} is missing implementation applicability"))?;
    let implementation = required_object(
        implementation,
        &format!("{trace_id} implementation applicability"),
    )?;
    let implementation_operator = required_string(
        implementation,
        "operator",
        &format!("{trace_id} implementation applicability"),
    )?;
    let implementation_tier = minimum_tiers
        .get("implementation")
        .ok_or_else(|| format!("{trace_id} is missing minimum implementation evidence tier"))?;
    let implementation = if implementation_tier.is_null() {
        EvidenceAssessment {
            state: EvidenceState::NotInScope,
            reason: "the authoritative minimum implementation evidence tier is null",
        }
    } else {
        required_object(
            implementation_tier,
            &format!("{trace_id} minimum implementation evidence tier"),
        )?;
        match implementation_operator.as_str() {
            "never" => EvidenceAssessment {
                state: EvidenceState::NotInScope,
                reason: "the authoritative implementation applicability expression is never",
            },
            "always" => EvidenceAssessment {
                state: EvidenceState::RequiredUnproven,
                reason: "implementation evidence is unconditionally applicable and no verified repository-local conformance receipt is joined",
            },
            _ => EvidenceAssessment {
                state: EvidenceState::NotEvaluated,
                reason: "implementation applicability is conditional and no authoritative dimensions or verified receipt were evaluated",
            },
        }
    };

    let runtime_tracking = if blocker_kinds.contains("runtime_evidence") {
        EvidenceAssessment {
            state: EvidenceState::RequiredUnproven,
            reason: "the repository overlay records an unresolved runtime-evidence blocker; runtime is a tracking signal, not a ControlTrace evidence phase",
        }
    } else {
        EvidenceAssessment {
            state: EvidenceState::NotEvaluated,
            reason: "ControlTrace has no runtime applicability phase and this repository-only projection cannot attest runtime behavior; no overlay runtime blocker was recorded",
        }
    };

    let deployment = applicability
        .get("deployment")
        .ok_or_else(|| format!("{trace_id} is missing deployment applicability"))?;
    let deployment = required_object(deployment, &format!("{trace_id} deployment applicability"))?;
    let operator = required_string(
        deployment,
        "operator",
        &format!("{trace_id} deployment applicability"),
    )?;
    let deployment_tier = minimum_tiers
        .get("deployment")
        .ok_or_else(|| format!("{trace_id} is missing minimum deployment evidence tier"))?;
    let deployment_tier_gap = deployment_tier.is_null() && operator == "always";
    let deployment = if deployment_tier.is_null() {
        EvidenceAssessment {
            state: EvidenceState::NotInScope,
            reason: "the authoritative minimum deployment evidence tier is null; the projection cannot invent deployment scope",
        }
    } else {
        required_object(
            deployment_tier,
            &format!("{trace_id} minimum deployment evidence tier"),
        )?;
        match operator.as_str() {
            "never" => EvidenceAssessment {
                state: EvidenceState::NotInScope,
                reason: "the authoritative deployment applicability expression is never",
            },
            "always" => EvidenceAssessment {
                state: EvidenceState::RequiredUnproven,
                reason: "deployment evidence is unconditionally applicable and no verified deployment receipt is joined",
            },
            _ => EvidenceAssessment {
                state: EvidenceState::NotEvaluated,
                reason: "deployment applicability is conditional and no authoritative deployment dimensions or verified receipt were evaluated; tracking-only overlay blockers cannot establish applicability",
            },
        }
    };

    Ok((
        EvidenceStates {
            implementation,
            runtime_tracking,
            deployment,
        },
        deployment_tier_gap,
    ))
}

fn required_object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object"))
}

fn required_object_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    object
        .get(field)
        .ok_or_else(|| format!("{label} is missing {field}"))?
        .as_object()
        .ok_or_else(|| format!("{label}.{field} must be a JSON object"))
}

fn required_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<&'a [Value], String> {
    object
        .get(field)
        .ok_or_else(|| format!("{label} is missing {field}"))?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{label}.{field} must be a JSON array"))
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<String, String> {
    object
        .get(field)
        .ok_or_else(|| format!("{label} is missing {field}"))?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("{label}.{field} must be a nonempty string"))
}

fn required_u64(object: &Map<String, Value>, field: &str, label: &str) -> Result<u64, String> {
    object
        .get(field)
        .ok_or_else(|| format!("{label} is missing {field}"))?
        .as_u64()
        .ok_or_else(|| format!("{label}.{field} must be a nonnegative integer"))
}

fn expect_string(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    let actual = required_string(object, field, label)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label}.{field} must be {expected}, found {actual}"
        ))
    }
}

fn without_fields(object: &Map<String, Value>, excluded: &[&str]) -> Value {
    let mut projection = object.clone();
    for field in excluded {
        projection.remove(*field);
    }
    Value::Object(projection)
}

fn increment(counts: &mut BTreeMap<String, usize>, key: &str) {
    *counts.entry(key.to_string()).or_default() += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TRACE_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OVERLAY_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn control_trace(deployment_operator: &str) -> Value {
        json!({
            "document_id": "control-trace:test",
            "document_version": 2,
            "ledger_id": "test-ledger",
            "ledger_version": "1.1.0",
            "controls": [{
                "control_id": "SB-TEST-01",
                "title": "Test control",
                "owning_work_package": "SB-2",
                "owning_team": "test-team",
                "waivable": false
            }],
            "acceptance_cases": [{
                "acceptance_case_id": "AC-001",
                "title": "Test acceptance",
                "owning_work_package": "SB-2",
                "owning_team": "test-team"
            }],
            "traces": [{
                "trace_id": "TRACE-SB-TEST-01-AC-001",
                "control_id": "SB-TEST-01",
                "acceptance_case_id": "AC-001",
                "owning_work_package": "SB-2",
                "owning_team": "test-team",
                "applicability_expression": {
                    "implementation": {"operator": "always"},
                    "deployment": {"operator": deployment_operator}
                },
                "evidence_instance_dimensions": {"implementation": [], "deployment": []},
                "minimum_evidence_tier": {
                    "implementation": {"name": "repository_local", "rank": 1},
                    "deployment": {"name": "operator_environment", "rank": 2}
                },
                "fixture_or_probe_id": "test::probe",
                "pass_condition": "the test passes",
                "trace_lifecycle": "active",
                "supersedes_trace_id": null
            }]
        })
    }

    fn overlay(blockers: Value) -> Value {
        json!({
            "contract_kind": EXPECTED_OVERLAY_KIND,
            "schema_version": 1,
            "document_id": "control-trace-status-overlay:test",
            "document_version": 1,
            "authority_scope": EXPECTED_AUTHORITY_SCOPE,
            "status_assurance": EXPECTED_STATUS_ASSURANCE,
            "control_trace_ref": {
                "document_id": "control-trace:test",
                "document_version": 2,
                "ledger_id": "test-ledger",
                "ledger_version": "1.1.0",
                "raw_sha256": TRACE_DIGEST
            },
            "rows": [{
                "trace_id": "TRACE-SB-TEST-01-AC-001",
                "implementation_status": "partial",
                "source_paths": ["sources/test.rs"],
                "migration_paths": [],
                "test_paths": ["sources/test.rs"],
                "blockers": blockers,
                "dependency_control_ids": []
            }]
        })
    }

    fn project(trace: &Value, overlay: &Value) -> MatrixProjection {
        build_matrix(trace, TRACE_DIGEST, overlay, OVERLAY_DIGEST)
            .expect("fixture matrix should project")
    }

    #[test]
    fn projection_is_deterministic_and_control_owns_work_package() {
        let trace = control_trace("always");
        let overlay = overlay(json!([]));
        let first = serde_json::to_string_pretty(&project(&trace, &overlay)).unwrap();
        let second = serde_json::to_string_pretty(&project(&trace, &overlay)).unwrap();
        assert_eq!(first, second);

        let value: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(value["production_acceptance_asserted"], false);
        assert_eq!(
            value["repository_status_assurance"],
            EXPECTED_STATUS_ASSURANCE
        );
        assert_eq!(
            value["working_tree_concurrency_assurance"],
            WORKING_TREE_CONCURRENCY_ASSURANCE
        );
        assert_eq!(value["rows"][0]["work_package"], "SB-2");
        assert_eq!(
            value["rows"][0]["evidence_state"]["implementation"]["state"],
            "required_unproven"
        );
        assert_eq!(
            value["rows"][0]["evidence_state"]["runtime_tracking"]["state"],
            "not_evaluated"
        );
        assert_eq!(
            value["rows"][0]["evidence_state"]["deployment"]["state"],
            "required_unproven"
        );
    }

    #[test]
    fn runtime_blocker_and_explicit_never_are_projected_conservatively() {
        let trace = control_trace("never");
        let overlay = overlay(json!([{
            "kind": "runtime_evidence",
            "detail": "runtime receipt is unavailable"
        }, {
            "kind": "deployment_evidence",
            "detail": "deployment receipt is unavailable"
        }]));
        let value = serde_json::to_value(project(&trace, &overlay)).unwrap();
        assert_eq!(
            value["rows"][0]["evidence_state"]["runtime_tracking"]["state"],
            "required_unproven"
        );
        assert_eq!(
            value["rows"][0]["evidence_state"]["deployment"]["state"],
            "not_in_scope"
        );
    }

    #[test]
    fn conditional_deployment_remains_not_evaluated_despite_tracking_blockers() {
        let mut trace = control_trace("always");
        trace["traces"][0]["applicability_expression"]["deployment"] = json!({
            "operator": "equals",
            "dimension": "provider.kind",
            "value": "oidc"
        });
        trace["traces"][0]["evidence_instance_dimensions"]["deployment"] = json!(["provider.kind"]);
        let overlay = overlay(json!([{
            "kind": "deployment_evidence",
            "detail": "deployment receipt is unavailable"
        }, {
            "kind": "external_access",
            "detail": "external access is unavailable"
        }]));
        let value = serde_json::to_value(project(&trace, &overlay)).unwrap();
        assert_eq!(
            value["rows"][0]["evidence_state"]["deployment"]["state"],
            "not_evaluated"
        );
        assert_eq!(
            value["rows"][0]["repository"]["blockers"][0]["kind"],
            "deployment_evidence"
        );
    }

    #[test]
    fn null_deployment_tier_is_not_in_scope_and_counted_as_contract_gap() {
        let mut trace = control_trace("always");
        trace["traces"][0]["minimum_evidence_tier"]["deployment"] = Value::Null;
        let value = serde_json::to_value(project(&trace, &overlay(json!([])))).unwrap();
        assert_eq!(
            value["rows"][0]["evidence_state"]["deployment"]["state"],
            "not_in_scope"
        );
        assert_eq!(
            value["summary"]["deployment_always_without_evidence_tier_count"],
            1
        );
    }

    #[test]
    fn projection_rejects_binding_and_row_order_drift() {
        let trace = control_trace("always");
        let mut wrong_binding = overlay(json!([]));
        wrong_binding["control_trace_ref"]["raw_sha256"] = json!(OVERLAY_DIGEST);
        let binding_error = build_matrix(&trace, TRACE_DIGEST, &wrong_binding, OVERLAY_DIGEST)
            .expect_err("wrong digest must fail");
        assert!(binding_error.contains("raw_sha256 mismatch"));

        let mut wrong_order = overlay(json!([]));
        wrong_order["rows"][0]["trace_id"] = json!("TRACE-OTHER");
        let order_error = build_matrix(&trace, TRACE_DIGEST, &wrong_order, OVERLAY_DIGEST)
            .expect_err("wrong trace id must fail");
        assert!(order_error.contains("trace order mismatch"));
    }

    #[test]
    fn render_joins_the_checked_in_141_row_catalog_snapshot() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("checked-in repository root should resolve");
        let document = render(&root).expect("checked-in security boundary matrix should render");
        let value: Value = serde_json::from_str(&document).expect("matrix output should be JSON");

        assert_eq!(value["projection_only"], true);
        assert_eq!(value["production_acceptance_asserted"], false);
        assert_eq!(
            value["repository_status_assurance"],
            EXPECTED_STATUS_ASSURANCE
        );
        assert_eq!(
            value["working_tree_concurrency_assurance"],
            WORKING_TREE_CONCURRENCY_ASSURANCE
        );
        assert_eq!(value["summary"]["active_trace_count"], 141);
        assert_eq!(value["rows"].as_array().map(Vec::len), Some(141));
        let rows = value["rows"]
            .as_array()
            .expect("matrix rows should be an array");
        let operator_environment_count = rows
            .iter()
            .filter(|row| {
                row["trace_contract"]["minimum_evidence_tier"]["deployment"]["name"].as_str()
                    == Some("operator_environment")
            })
            .count();
        let externally_attested_trace_ids: Vec<_> = rows
            .iter()
            .filter(|row| {
                row["trace_contract"]["minimum_evidence_tier"]["deployment"]["name"].as_str()
                    == Some("externally_attested")
            })
            .map(|row| {
                row["trace_id"]
                    .as_str()
                    .expect("trace id should be a string")
            })
            .collect();
        assert_eq!(operator_environment_count, 139);
        assert_eq!(
            externally_attested_trace_ids,
            ["TRACE-SB-OPS-07-AC-016", "TRACE-SB-CONF-05-AC-055"]
        );
        assert!(rows.iter().all(|row| {
            row["trace_contract"]["evidence_instance_dimensions"]["deployment"]
                .as_array()
                .is_some_and(|dimensions| !dimensions.is_empty())
        }));
        assert_eq!(
            value["summary"]["repository_status_counts"]["implemented"],
            14
        );
        assert_eq!(value["summary"]["repository_status_counts"]["partial"], 118);
        assert_eq!(
            value["summary"]["repository_status_counts"]["not_implemented"],
            9
        );
        assert_eq!(
            value["summary"]["implementation_evidence_state_counts"]["required_unproven"],
            141
        );
        assert_eq!(
            value["summary"]["runtime_tracking_state_counts"]["required_unproven"],
            49
        );
        assert_eq!(
            value["summary"]["runtime_tracking_state_counts"]["not_evaluated"],
            92
        );
        assert_eq!(
            value["summary"]["deployment_evidence_state_counts"]["not_in_scope"],
            0
        );
        assert_eq!(
            value["summary"]["deployment_evidence_state_counts"]["required_unproven"],
            141
        );
        assert_eq!(
            value["summary"]["deployment_always_without_evidence_tier_count"],
            0
        );
        for source in ["control_trace", "status_overlay"] {
            let digest = value["generated_from"][source]["raw_sha256"]
                .as_str()
                .expect("source digest should be a string");
            assert!(digest.starts_with("sha256:"));
            assert_eq!(digest.len(), 71);
        }
    }
}
