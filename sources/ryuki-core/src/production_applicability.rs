//! Independent build-side derivation of implementation applicability.
//!
//! A production build manifest is an untrusted claim. This module derives the
//! exact implementation inventory from the authenticated ControlTrace and the
//! already measured build surface, then compares the claim row-for-row.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use thiserror::Error;

use crate::conformance_applicability::{
    ApplicabilityControlTraceBinding, ApplicabilityDimension, ApplicabilityDimensionValue,
    ApplicabilityInstance, ApplicabilityInventoryBinding, ApplicabilityScope, ApplicabilitySubject,
    ApplicabilityValidationError, MAX_APPLICABILITY_INVENTORY_INSTANCES,
    compare_applicability_instances, recompute_applicability_instance_id,
    recompute_applicability_inventory_binding,
};
use crate::production_build::{ProductionBuildManifest, ShippedAdapter};

const MAX_CONTROL_TRACES: usize = 4096;
const MAX_EXPRESSION_DEPTH: usize = 32;
const MAX_EXPRESSION_NODES: usize = 4096;
const MAX_EXPRESSION_OPERANDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedImplementationApplicability {
    pub binding: ApplicabilityInventoryBinding,
    pub instances: Vec<ApplicabilityInstance>,
}

#[derive(Debug, Error)]
pub enum ProductionApplicabilityError {
    #[error("invalid production applicability input: {0}")]
    Invalid(String),
    #[error(transparent)]
    Applicability(#[from] ApplicabilityValidationError),
}

/// Derive the complete build-owned implementation inventory.
///
/// Component rows cover every active, implementation-scoped applicable trace.
/// Adapter-capability rows cover each capability's mandatory baseline traces.
/// A null implementation minimum tier excludes the trace even if its expression
/// is `always`.
pub fn derive_implementation_applicability(
    control_trace: &Value,
    manifest: &ProductionBuildManifest,
) -> Result<DerivedImplementationApplicability, ProductionApplicabilityError> {
    validate_control_trace_identity(control_trace, manifest)?;
    let traces = required_array(control_trace, "traces", "ControlTrace")?;
    if traces.is_empty() || traces.len() > MAX_CONTROL_TRACES {
        return Err(invalid(format!(
            "ControlTrace must contain between 1 and {MAX_CONTROL_TRACES} traces"
        )));
    }

    let mut trace_by_id = BTreeMap::new();
    for trace in traces {
        let trace_id = required_str(trace, "trace_id", "ControlTrace row")?;
        if trace_by_id.insert(trace_id, trace).is_some() {
            return Err(invalid(format!(
                "ControlTrace contains duplicate trace_id {trace_id}"
            )));
        }
    }

    let trace_binding = ApplicabilityControlTraceBinding {
        document_id: manifest.control_trace_ref.document_id.clone(),
        document_version: manifest.control_trace_ref.document_version,
        content_digest: manifest.control_trace_ref.content_digest.clone(),
    };
    let mut instances = Vec::new();

    for trace in traces {
        if !trace_is_active(trace)? || !implementation_scope_exists(trace)? {
            continue;
        }
        let subject = ApplicabilitySubject::Component {
            component_id: manifest.component.component_id.clone(),
            component_version: manifest.component.component_version.clone(),
        };
        if let Some(instance) = derive_instance(&trace_binding, trace, manifest, subject)? {
            instances.push(instance);
        }
    }

    let adapter_instance_count =
        manifest
            .shipped_adapters
            .iter()
            .try_fold(0usize, |total, adapter| {
                let adapter_count = adapter
                    .capability_ids
                    .len()
                    .checked_mul(adapter.mandatory_baseline.required_trace_ids.len())
                    .ok_or_else(|| invalid("adapter applicability row count overflowed usize"))?;
                total
                    .checked_add(adapter_count)
                    .ok_or_else(|| invalid("adapter applicability row count overflowed usize"))
            })?;
    let total_instance_count = instances
        .len()
        .checked_add(adapter_instance_count)
        .ok_or_else(|| invalid("implementation applicability row count overflowed usize"))?;
    if total_instance_count > MAX_APPLICABILITY_INVENTORY_INSTANCES {
        return Err(invalid(format!(
            "derived implementation applicability would contain {total_instance_count} rows, exceeding the {MAX_APPLICABILITY_INVENTORY_INSTANCES}-row limit"
        )));
    }
    instances.reserve(adapter_instance_count);

    for adapter in &manifest.shipped_adapters {
        for capability_id in &adapter.capability_ids {
            for trace_id in &adapter.mandatory_baseline.required_trace_ids {
                let trace = trace_by_id.get(trace_id.as_str()).ok_or_else(|| {
                    invalid(format!(
                        "adapter {} baseline references unknown trace {trace_id}",
                        adapter.adapter_kind
                    ))
                })?;
                if !trace_is_active(trace)? {
                    return Err(invalid(format!(
                        "adapter {} baseline trace {trace_id} is not active",
                        adapter.adapter_kind
                    )));
                }
                if !implementation_scope_exists(trace)? {
                    return Err(invalid(format!(
                        "adapter {} baseline trace {trace_id} has no implementation evidence tier",
                        adapter.adapter_kind
                    )));
                }
                let subject = adapter_subject(adapter, capability_id);
                let Some(instance) = derive_instance(&trace_binding, trace, manifest, subject)?
                else {
                    return Err(invalid(format!(
                        "adapter {} capability {capability_id} baseline trace {trace_id} is not implementation-applicable",
                        adapter.adapter_kind
                    )));
                };
                instances.push(instance);
                if instances.len() > MAX_APPLICABILITY_INVENTORY_INSTANCES {
                    return Err(invalid(format!(
                        "derived implementation applicability exceeds the {MAX_APPLICABILITY_INVENTORY_INSTANCES}-row limit"
                    )));
                }
            }
        }
    }

    instances.sort_by(compare_applicability_instances);
    let binding = recompute_applicability_inventory_binding(&trace_binding, &instances)?;
    Ok(DerivedImplementationApplicability { binding, instances })
}

/// Require the manifest claim to equal the independently derived inventory.
pub fn validate_exact_implementation_applicability(
    control_trace: &Value,
    manifest: &ProductionBuildManifest,
) -> Result<(), ProductionApplicabilityError> {
    let expected = derive_implementation_applicability(control_trace, manifest)?;
    let claimed = &manifest.implementation_applicability_instances;
    if manifest.implementation_applicability != expected.binding || claimed != &expected.instances {
        let expected_ids = expected
            .instances
            .iter()
            .map(|row| row.applicability_instance_id.as_str())
            .collect::<BTreeSet<_>>();
        let claimed_ids = claimed
            .iter()
            .map(|row| row.applicability_instance_id.as_str())
            .collect::<BTreeSet<_>>();
        let missing = expected_ids.difference(&claimed_ids).count();
        let extra = claimed_ids.difference(&expected_ids).count();
        return Err(invalid(format!(
            "manifest implementation applicability is not the exact independently derived inventory ({} expected rows, {} claimed rows, {missing} missing ids, {extra} extra ids)",
            expected.instances.len(),
            claimed.len()
        )));
    }
    Ok(())
}

fn validate_control_trace_identity(
    control_trace: &Value,
    manifest: &ProductionBuildManifest,
) -> Result<(), ProductionApplicabilityError> {
    if required_str(control_trace, "contract_kind", "ControlTrace")? != "control-trace" {
        return Err(invalid(
            "ControlTrace contract_kind must equal control-trace",
        ));
    }
    let document_id = required_str(control_trace, "document_id", "ControlTrace")?;
    let document_version = control_trace
        .get("document_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("ControlTrace document_version must be a positive integer"))?;
    if document_version == 0
        || document_id != manifest.control_trace_ref.document_id
        || document_version != manifest.control_trace_ref.document_version
    {
        return Err(invalid(
            "ControlTrace identity does not match the build manifest reference",
        ));
    }
    Ok(())
}

fn derive_instance(
    trace_binding: &ApplicabilityControlTraceBinding,
    trace: &Value,
    manifest: &ProductionBuildManifest,
    subject: ApplicabilitySubject,
) -> Result<Option<ApplicabilityInstance>, ProductionApplicabilityError> {
    let trace_id = required_str(trace, "trace_id", "ControlTrace row")?;
    let owning_work_package = required_str(
        trace,
        "owning_work_package",
        &format!("ControlTrace row {trace_id}"),
    )?;
    let dimensions = derive_dimensions(trace, manifest, &subject)?;
    let dimension_map = dimensions
        .iter()
        .map(|dimension| {
            (
                dimension.name.clone(),
                dimension_value_as_json(&dimension.value),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expression = trace
        .pointer("/applicability_expression/implementation")
        .ok_or_else(|| {
            invalid(format!(
                "ControlTrace row {trace_id} omits implementation applicability expression"
            ))
        })?;
    let mut nodes = 0;
    if !evaluate_expression(expression, &dimension_map, 0, &mut nodes)? {
        return Ok(None);
    }

    let mut instance = ApplicabilityInstance {
        applicability_instance_id: String::new(),
        trace_id: trace_id.to_string(),
        owning_work_package: owning_work_package.to_string(),
        scope: ApplicabilityScope::Implementation,
        subject,
        dimensions,
    };
    instance.applicability_instance_id =
        recompute_applicability_instance_id(trace_binding, &instance)?;
    Ok(Some(instance))
}

fn derive_dimensions(
    trace: &Value,
    manifest: &ProductionBuildManifest,
    subject: &ApplicabilitySubject,
) -> Result<Vec<ApplicabilityDimension>, ProductionApplicabilityError> {
    let trace_id = required_str(trace, "trace_id", "ControlTrace row")?;
    let declared = trace
        .pointer("/evidence_instance_dimensions/implementation")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid(format!(
                "ControlTrace row {trace_id} omits implementation evidence dimensions"
            ))
        })?;
    let mut names = BTreeSet::new();
    for value in declared {
        let name = value.as_str().ok_or_else(|| {
            invalid(format!(
                "ControlTrace row {trace_id} has a non-string implementation dimension"
            ))
        })?;
        if !names.insert(name) {
            return Err(invalid(format!(
                "ControlTrace row {trace_id} repeats implementation dimension {name}"
            )));
        }
    }

    names
        .into_iter()
        .map(|name| {
            let value = authoritative_dimension_value(name, trace, manifest, subject)?;
            Ok(ApplicabilityDimension {
                name: name.to_string(),
                value,
            })
        })
        .collect()
}

fn authoritative_dimension_value(
    name: &str,
    trace: &Value,
    manifest: &ProductionBuildManifest,
    subject: &ApplicabilitySubject,
) -> Result<ApplicabilityDimensionValue, ProductionApplicabilityError> {
    let string = match name {
        "implementation.source_revision" => manifest.source.revision.as_str(),
        "implementation.artifact_digest" => manifest.runtime_executable.content_digest.as_str(),
        "implementation.fixture_or_probe_id" => {
            required_str(trace, "fixture_or_probe_id", "ControlTrace row")?
        }
        "implementation.subject_kind" => match subject {
            ApplicabilitySubject::Component { .. } => "component",
            ApplicabilitySubject::AdapterCapability { .. } => "adapter_capability",
            _ => {
                return Err(invalid(
                    "implementation derivation received a deployment subject",
                ));
            }
        },
        "implementation.component_id" => manifest.component.component_id.as_str(),
        "implementation.component_version" => manifest.component.component_version.as_str(),
        "implementation.adapter_kind" => match subject {
            ApplicabilitySubject::AdapterCapability { adapter_kind, .. } => adapter_kind,
            _ => return Err(unavailable_dimension(name, subject)),
        },
        "implementation.adapter_version" => match subject {
            ApplicabilitySubject::AdapterCapability {
                adapter_version, ..
            } => adapter_version,
            _ => return Err(unavailable_dimension(name, subject)),
        },
        "implementation.capability_id" => match subject {
            ApplicabilitySubject::AdapterCapability { capability_id, .. } => capability_id,
            _ => return Err(unavailable_dimension(name, subject)),
        },
        _ => {
            return Err(invalid(format!(
                "unsupported authoritative implementation dimension {name}"
            )));
        }
    };
    Ok(ApplicabilityDimensionValue::String(string.to_string()))
}

fn unavailable_dimension(
    name: &str,
    subject: &ApplicabilitySubject,
) -> ProductionApplicabilityError {
    invalid(format!(
        "authoritative dimension {name} is unavailable for subject {subject:?}"
    ))
}

fn dimension_value_as_json(value: &ApplicabilityDimensionValue) -> Value {
    serde_json::to_value(value).expect("applicability dimension serialization is infallible")
}

fn evaluate_expression(
    expression: &Value,
    dimensions: &BTreeMap<String, Value>,
    depth: usize,
    nodes: &mut usize,
) -> Result<bool, ProductionApplicabilityError> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(invalid("applicability expression exceeds maximum depth"));
    }
    *nodes += 1;
    if *nodes > MAX_EXPRESSION_NODES {
        return Err(invalid(
            "applicability expression exceeds maximum node count",
        ));
    }
    let operator = required_str(expression, "operator", "applicability expression")?;
    match operator {
        "always" => Ok(true),
        "never" => Ok(false),
        "all" | "any" => {
            let operands = required_array(expression, "operands", "applicability expression")?;
            if operands.is_empty() || operands.len() > MAX_EXPRESSION_OPERANDS {
                return Err(invalid(format!(
                    "{operator} applicability expression must have 1 through {MAX_EXPRESSION_OPERANDS} operands"
                )));
            }
            // Evaluate every operand before combining. Short-circuiting would
            // let an earlier true/false value hide an invalid dimension,
            // unsupported operator, or over-deep subtree in a later operand.
            let mut results = Vec::with_capacity(operands.len());
            for operand in operands {
                results.push(evaluate_expression(operand, dimensions, depth + 1, nodes)?);
            }
            if operator == "all" {
                Ok(results.into_iter().all(|result| result))
            } else {
                Ok(results.into_iter().any(|result| result))
            }
        }
        "not" => Ok(!evaluate_expression(
            expression
                .get("operand")
                .ok_or_else(|| invalid("not applicability expression omits operand"))?,
            dimensions,
            depth + 1,
            nodes,
        )?),
        "equals" | "not_equals" | "contains" => {
            let name = required_str(expression, "dimension", "applicability expression")?;
            let actual = dimensions.get(name).ok_or_else(|| {
                invalid(format!(
                    "expression references undeclared or unavailable dimension {name}"
                ))
            })?;
            let expected = expression
                .get("value")
                .ok_or_else(|| invalid(format!("{operator} expression omits value")))?;
            match operator {
                "equals" => Ok(actual == expected),
                "not_equals" => Ok(actual != expected),
                "contains" => match (actual, expected) {
                    (Value::Array(values), expected) => Ok(values.contains(expected)),
                    (Value::String(actual), Value::String(expected)) => {
                        Ok(actual.contains(expected))
                    }
                    _ => Err(invalid(format!(
                        "contains requires an array or string dimension: {name}"
                    ))),
                },
                _ => unreachable!(),
            }
        }
        "in" | "not_in" => {
            let name = required_str(expression, "dimension", "applicability expression")?;
            let actual = dimensions.get(name).ok_or_else(|| {
                invalid(format!(
                    "expression references undeclared or unavailable dimension {name}"
                ))
            })?;
            if actual.is_array() {
                return Err(invalid(format!(
                    "{operator} requires a scalar applicability dimension: {name}"
                )));
            }
            let values = required_array(expression, "values", "applicability expression")?;
            if values.is_empty() || values.len() > MAX_EXPRESSION_OPERANDS {
                return Err(invalid(format!(
                    "{operator} applicability expression must have 1 through {MAX_EXPRESSION_OPERANDS} values"
                )));
            }
            let present = values.contains(actual);
            Ok(if operator == "in" { present } else { !present })
        }
        _ => Err(invalid(format!(
            "unsupported applicability expression operator {operator}"
        ))),
    }
}

fn implementation_scope_exists(trace: &Value) -> Result<bool, ProductionApplicabilityError> {
    let tier = trace
        .pointer("/minimum_evidence_tier/implementation")
        .ok_or_else(|| invalid("ControlTrace row omits implementation minimum evidence tier"))?;
    Ok(!tier.is_null())
}

fn trace_is_active(trace: &Value) -> Result<bool, ProductionApplicabilityError> {
    Ok(required_str(trace, "trace_lifecycle", "ControlTrace row")? == "active")
}

fn adapter_subject(adapter: &ShippedAdapter, capability_id: &str) -> ApplicabilitySubject {
    ApplicabilitySubject::AdapterCapability {
        adapter_kind: adapter.adapter_kind.clone(),
        adapter_version: adapter.adapter_version.clone(),
        capability_id: capability_id.to_string(),
    }
}

fn required_str<'a>(
    value: &'a Value,
    field: &str,
    context: &str,
) -> Result<&'a str, ProductionApplicabilityError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{context} omits string field {field}")))
}

fn required_array<'a>(
    value: &'a Value,
    field: &str,
    context: &str,
) -> Result<&'a [Value], ProductionApplicabilityError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("{context} omits array field {field}")))
}

fn invalid(message: impl Into<String>) -> ProductionApplicabilityError {
    ProductionApplicabilityError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use crate::conformance_applicability::{
        APPLICABILITY_IDENTITY_CONTRACT, APPLICABILITY_INVENTORY_CONTRACT,
    };
    use crate::production_build::{
        BuildComponent, BuildEndian, BuildSelectorDisposition, BuildSource, BuildTarget,
        MandatoryCapabilityBaseline, OciSubject, OciSubjectKind,
        PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND, PRODUCTION_BUILD_MANIFEST_SCHEMA_URI,
        PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION, RuntimeExecutable, SelectorDisposition,
        SelectorDomain, SourceRevisionAlgorithm,
    };
    use crate::security_profile::{ArtifactKind, VersionedContentReference};
    use serde_json::json;

    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn manifest() -> ProductionBuildManifest {
        ProductionBuildManifest {
            schema_uri: PRODUCTION_BUILD_MANIFEST_SCHEMA_URI.into(),
            schema_version: PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION.into(),
            contract_kind: PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND.into(),
            document_id: "production-build-manifest:test".into(),
            document_version: 1,
            component: BuildComponent {
                component_id: "component:ryuki-api".into(),
                component_version: "1.2.3".into(),
                executable_name: "ryuki-api".into(),
                target: BuildTarget {
                    architecture: "x86_64".into(),
                    operating_system: "linux".into(),
                    family: "unix".into(),
                    pointer_width_bits: 64,
                    endian: BuildEndian::Little,
                },
            },
            source: BuildSource {
                revision_algorithm: SourceRevisionAlgorithm::GitSha1,
                revision: "a".repeat(40),
            },
            runtime_executable: RuntimeExecutable {
                content_digest: digest('b'),
                byte_length: 42,
            },
            oci_subject: OciSubject {
                subject_kind: OciSubjectKind::OciImageManifest,
                repository: "ghcr.io/example/ryuki-api".into(),
                content_digest: digest('c'),
            },
            control_trace_ref: VersionedContentReference {
                artifact_kind: ArtifactKind::ControlTrace,
                document_id: "control-trace:test".into(),
                document_version: 1,
                content_digest: digest('d'),
                artifact_locator: "catalog/security/control-trace.json".into(),
            },
            shipped_adapters: vec![ShippedAdapter {
                adapter_kind: "auth.test".into(),
                adapter_version: "1.2.3".into(),
                production_eligible: false,
                capability_ids: vec!["authenticate".into()],
                mandatory_baseline: MandatoryCapabilityBaseline {
                    document_id: "baseline:test".into(),
                    document_version: 1,
                    content_digest: digest('e'),
                    artifact_locator: "docs/test.md".into(),
                    required_trace_ids: vec!["TRACE-SB-CONF-04-AC-048".into()],
                },
            }],
            selector_dispositions: vec![BuildSelectorDisposition {
                selector_domain: SelectorDomain::AuthMode,
                selector: "test".into(),
                disposition: SelectorDisposition::Implemented,
                adapter_kind: Some("auth.test".into()),
            }],
            implementation_applicability: ApplicabilityInventoryBinding {
                identity_contract: APPLICABILITY_IDENTITY_CONTRACT.into(),
                inventory_contract: APPLICABILITY_INVENTORY_CONTRACT.into(),
                instance_count: 1,
                content_digest: digest('f'),
            },
            implementation_applicability_instances: Vec::new(),
        }
    }

    fn trace_fixture() -> Value {
        json!({
            "contract_kind": "control-trace",
            "document_id": "control-trace:test",
            "document_version": 1,
            "traces": [
                {
                    "trace_id": "TRACE-SB-CONF-03-AC-048",
                    "owning_work_package": "SB-0",
                    "trace_lifecycle": "active",
                    "applicability_expression": {"implementation": {"operator": "always"}},
                    "evidence_instance_dimensions": {"implementation": [
                        "implementation.artifact_digest",
                        "implementation.fixture_or_probe_id",
                        "implementation.source_revision"
                    ]},
                    "minimum_evidence_tier": {"implementation": {"name": "repository_local", "rank": 1}},
                    "fixture_or_probe_id": "security_conformance::ac_048"
                },
                {
                    "trace_id": "TRACE-SB-CONF-04-AC-048",
                    "owning_work_package": "SB-0",
                    "trace_lifecycle": "active",
                    "applicability_expression": {"implementation": {"operator": "always"}},
                    "evidence_instance_dimensions": {"implementation": []},
                    "minimum_evidence_tier": {"implementation": {"name": "repository_local", "rank": 1}},
                    "fixture_or_probe_id": "security_conformance::ac_048"
                },
                {
                    "trace_id": "TRACE-SB-CONF-05-AC-048",
                    "owning_work_package": "SB-0",
                    "trace_lifecycle": "active",
                    "applicability_expression": {"implementation": {"operator": "always"}},
                    "evidence_instance_dimensions": {"implementation": []},
                    "minimum_evidence_tier": {"implementation": null},
                    "fixture_or_probe_id": "security_conformance::ac_048"
                }
            ]
        })
    }

    #[test]
    fn derives_component_and_baseline_rows_but_excludes_null_tier() {
        let manifest = manifest();
        let derived = derive_implementation_applicability(&trace_fixture(), &manifest).unwrap();
        assert_eq!(derived.instances.len(), 3);
        assert!(derived.instances.iter().all(|row| {
            row.trace_id != "TRACE-SB-CONF-05-AC-048"
                && row.scope == ApplicabilityScope::Implementation
        }));
        assert_eq!(derived.binding.instance_count, 3);
    }

    #[test]
    fn exact_comparison_rejects_omission_and_accepts_derived_claim() {
        let trace = trace_fixture();
        let mut manifest = manifest();
        let derived = derive_implementation_applicability(&trace, &manifest).unwrap();
        manifest.implementation_applicability = derived.binding;
        manifest.implementation_applicability_instances = derived.instances;
        validate_exact_implementation_applicability(&trace, &manifest).unwrap();

        manifest.implementation_applicability_instances.pop();
        let trace_binding = ApplicabilityControlTraceBinding {
            document_id: manifest.control_trace_ref.document_id.clone(),
            document_version: manifest.control_trace_ref.document_version,
            content_digest: manifest.control_trace_ref.content_digest.clone(),
        };
        manifest.implementation_applicability = recompute_applicability_inventory_binding(
            &trace_binding,
            &manifest.implementation_applicability_instances,
        )
        .unwrap();
        assert!(validate_exact_implementation_applicability(&trace, &manifest).is_err());
    }

    #[test]
    fn baseline_trace_must_be_active_and_implementation_scoped() {
        let mut trace = trace_fixture();
        trace["traces"][1]["minimum_evidence_tier"]["implementation"] = Value::Null;
        let error = derive_implementation_applicability(&trace, &manifest())
            .unwrap_err()
            .to_string();
        assert!(error.contains("has no implementation evidence tier"));
    }

    #[test]
    fn boolean_expressions_validate_every_operand_before_combining() {
        let mut trace = trace_fixture();
        trace["traces"][0]["applicability_expression"]["implementation"] = json!({
            "operator": "all",
            "operands": [
                {"operator": "never"},
                {
                    "operator": "equals",
                    "dimension": "implementation.undeclared",
                    "value": "hidden"
                }
            ]
        });
        let error = derive_implementation_applicability(&trace, &manifest())
            .unwrap_err()
            .to_string();
        assert!(error.contains("undeclared or unavailable dimension"));
    }

    #[test]
    fn membership_expression_values_are_bounded() {
        let mut trace = trace_fixture();
        trace["traces"][0]["applicability_expression"]["implementation"] = json!({
            "operator": "in",
            "dimension": "implementation.source_revision",
            "values": vec!["a"; 65]
        });
        let error = derive_implementation_applicability(&trace, &manifest())
            .unwrap_err()
            .to_string();
        assert!(error.contains("1 through 64 values"));
    }

    #[test]
    fn oversized_adapter_fanout_is_rejected_before_row_allocation() {
        let mut manifest = manifest();
        manifest.shipped_adapters[0].capability_ids = (0..256)
            .map(|index| format!("capability-{index:03}"))
            .collect();
        manifest.shipped_adapters[0]
            .mandatory_baseline
            .required_trace_ids = vec!["TRACE-SB-CONF-04-AC-048".into(); 65];
        let error = derive_implementation_applicability(&trace_fixture(), &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exceeding the 16384-row limit"));
    }
}
