//! Canonical wire records for independently derived conformance applicability.
//!
//! This module owns identity, ordering, and inventory-digest mechanics only.
//! It deliberately does not derive instances from a ControlTrace, build
//! manifest, deployment profile, or provider registry. Callers must derive the
//! universe from those independently pinned inputs before using these helpers.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conformance_trust::{ConformanceTrustError, canonical_json_bytes};

pub const APPLICABILITY_IDENTITY_CONTRACT: &str = "ryuki-applicability-instance-v2";
pub const APPLICABILITY_INVENTORY_CONTRACT: &str = "ryuki-applicability-inventory-v2";
pub const APPLICABILITY_INSTANCE_ID_PREFIX: &str = "applicability:sha256:";
pub const MAX_APPLICABILITY_INVENTORY_INSTANCES: usize = 16_384;

const MAX_EXACT_JSON_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_DIMENSIONS_PER_INSTANCE: usize = 256;
const MAX_SCALARS_PER_SET: usize = 256;
const MAX_DIMENSION_NAME_BYTES: usize = 160;
const MAX_DIMENSION_STRING_BYTES: usize = 512;
const MAX_CANONICAL_NAME_BYTES: usize = 128;

/// Exact identity of the ControlTrace whose active rows are being projected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityControlTraceBinding {
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicabilityScope {
    Implementation,
    Deployment,
}

/// Authority-bearing subject whose conformance obligation is being projected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "subject_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicabilitySubject {
    Component {
        component_id: String,
        component_version: String,
    },
    AdapterCapability {
        adapter_kind: String,
        adapter_version: String,
        capability_id: String,
    },
    Deployment {
        deployment_id: String,
        deployment_profile_id: String,
        trust_domain_id: String,
        tenancy_mode: String,
    },
    ProviderCapability {
        deployment_id: String,
        provider_id: String,
        configuration_version: u64,
        descriptor_id: String,
        descriptor_version: u64,
        adapter_kind: String,
        adapter_version: String,
        capability_id: String,
    },
}

/// Scalar member of a set-valued applicability dimension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ApplicabilityScalar {
    Boolean(bool),
    Integer(i64),
    String(String),
}

/// A dimension is either one exact scalar or a canonical set of scalars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ApplicabilityDimensionValue {
    String(String),
    Boolean(bool),
    Integer(i64),
    Set(Vec<ApplicabilityScalar>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityDimension {
    pub name: String,
    pub value: ApplicabilityDimensionValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityInstance {
    pub applicability_instance_id: String,
    pub trace_id: String,
    pub owning_work_package: String,
    pub scope: ApplicabilityScope,
    pub subject: ApplicabilitySubject,
    pub dimensions: Vec<ApplicabilityDimension>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityInventoryBinding {
    pub identity_contract: String,
    pub inventory_contract: String,
    pub instance_count: u64,
    pub content_digest: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ApplicabilityValidationError {
    #[error("invalid conformance applicability: {0}")]
    Invalid(String),
    #[error("conformance applicability serialization failed: {0}")]
    Serialization(String),
    #[error("conformance applicability canonical JSON failed: {0}")]
    CanonicalJson(#[from] ConformanceTrustError),
}

#[derive(Serialize)]
struct InstanceIdentityPreimage<'a> {
    domain: &'static str,
    control_trace: &'a ApplicabilityControlTraceBinding,
    trace_id: &'a str,
    owning_work_package: &'a str,
    scope: ApplicabilityScope,
    subject: &'a ApplicabilitySubject,
    dimensions: &'a [ApplicabilityDimension],
}

#[derive(Serialize)]
struct InventoryPreimage<'a> {
    domain: &'static str,
    control_trace: &'a ApplicabilityControlTraceBinding,
    instances: &'a [ApplicabilityInstance],
}

/// Recompute an instance ID from its complete canonical identity preimage.
///
/// The supplied `applicability_instance_id` is deliberately excluded from the
/// preimage. All other fields and the exact ControlTrace binding are covered.
pub fn recompute_applicability_instance_id(
    control_trace: &ApplicabilityControlTraceBinding,
    instance: &ApplicabilityInstance,
) -> Result<String, ApplicabilityValidationError> {
    validate_control_trace_binding(control_trace)?;
    validate_instance_shape(instance)?;
    let preimage = InstanceIdentityPreimage {
        domain: APPLICABILITY_IDENTITY_CONTRACT,
        control_trace,
        trace_id: &instance.trace_id,
        owning_work_package: &instance.owning_work_package,
        scope: instance.scope,
        subject: &instance.subject,
        dimensions: &instance.dimensions,
    };
    Ok(format!(
        "{APPLICABILITY_INSTANCE_ID_PREFIX}{}",
        sha256_hex(&canonical_wire_bytes(&preimage)?)
    ))
}

/// Validate the canonical shape and exact recomputed identity of one instance.
pub fn validate_applicability_instance(
    control_trace: &ApplicabilityControlTraceBinding,
    instance: &ApplicabilityInstance,
) -> Result<(), ApplicabilityValidationError> {
    let expected = recompute_applicability_instance_id(control_trace, instance)?;
    if instance.applicability_instance_id != expected {
        return Err(invalid(format!(
            "applicability_instance_id does not match the canonical identity; expected {expected}"
        )));
    }
    Ok(())
}

/// Total ordering required for canonical inventories.
///
/// Scope is ordered implementation before deployment, followed by trace,
/// owning package, structured subject, dimensions, and the recomputed ID.
pub fn compare_applicability_instances(
    left: &ApplicabilityInstance,
    right: &ApplicabilityInstance,
) -> Ordering {
    scope_rank(left.scope)
        .cmp(&scope_rank(right.scope))
        .then_with(|| left.trace_id.cmp(&right.trace_id))
        .then_with(|| left.owning_work_package.cmp(&right.owning_work_package))
        .then_with(|| compare_subjects(&left.subject, &right.subject))
        .then_with(|| compare_dimensions(&left.dimensions, &right.dimensions))
        .then_with(|| {
            left.applicability_instance_id
                .cmp(&right.applicability_instance_id)
        })
}

/// Validate exact IDs, global uniqueness, bounds, and strict canonical order.
pub fn validate_applicability_inventory(
    control_trace: &ApplicabilityControlTraceBinding,
    instances: &[ApplicabilityInstance],
) -> Result<(), ApplicabilityValidationError> {
    validate_control_trace_binding(control_trace)?;
    if instances.is_empty() || instances.len() > MAX_APPLICABILITY_INVENTORY_INSTANCES {
        return Err(invalid(format!(
            "inventory must contain between 1 and {MAX_APPLICABILITY_INVENTORY_INSTANCES} instances"
        )));
    }

    let mut ids = BTreeSet::new();
    for (index, instance) in instances.iter().enumerate() {
        validate_applicability_instance(control_trace, instance).map_err(|error| {
            invalid(format!(
                "instance at index {index} failed validation: {error}"
            ))
        })?;
        if !ids.insert(instance.applicability_instance_id.as_str()) {
            return Err(invalid(format!(
                "duplicate applicability_instance_id {}",
                instance.applicability_instance_id
            )));
        }
        if index > 0
            && compare_applicability_instances(&instances[index - 1], instance) != Ordering::Less
        {
            return Err(invalid(format!(
                "instances are not in strict canonical order at index {index}"
            )));
        }
    }
    Ok(())
}

/// Recompute the binding for one already canonical, independently derived
/// inventory.
pub fn recompute_applicability_inventory_binding(
    control_trace: &ApplicabilityControlTraceBinding,
    instances: &[ApplicabilityInstance],
) -> Result<ApplicabilityInventoryBinding, ApplicabilityValidationError> {
    validate_applicability_inventory(control_trace, instances)?;
    let preimage = InventoryPreimage {
        domain: APPLICABILITY_INVENTORY_CONTRACT,
        control_trace,
        instances,
    };
    Ok(ApplicabilityInventoryBinding {
        identity_contract: APPLICABILITY_IDENTITY_CONTRACT.into(),
        inventory_contract: APPLICABILITY_INVENTORY_CONTRACT.into(),
        instance_count: u64::try_from(instances.len())
            .map_err(|_| invalid("inventory instance count does not fit u64"))?,
        content_digest: format!("sha256:{}", sha256_hex(&canonical_wire_bytes(&preimage)?)),
    })
}

/// Validate a claimed inventory binding against independently supplied rows.
pub fn validate_applicability_inventory_binding(
    control_trace: &ApplicabilityControlTraceBinding,
    instances: &[ApplicabilityInstance],
    binding: &ApplicabilityInventoryBinding,
) -> Result<(), ApplicabilityValidationError> {
    let expected = recompute_applicability_inventory_binding(control_trace, instances)?;
    if binding != &expected {
        return Err(invalid(format!(
            "inventory binding does not match canonical inventory; expected identity_contract={}, inventory_contract={}, instance_count={}, content_digest={}",
            expected.identity_contract,
            expected.inventory_contract,
            expected.instance_count,
            expected.content_digest
        )));
    }
    Ok(())
}

fn validate_control_trace_binding(
    binding: &ApplicabilityControlTraceBinding,
) -> Result<(), ApplicabilityValidationError> {
    validate_namespaced_id(
        "control_trace.document_id",
        &binding.document_id,
        "control-trace:",
    )?;
    validate_positive_exact_version("control_trace.document_version", binding.document_version)?;
    validate_nonzero_digest("control_trace.content_digest", &binding.content_digest)
}

fn validate_instance_shape(
    instance: &ApplicabilityInstance,
) -> Result<(), ApplicabilityValidationError> {
    validate_trace_id(&instance.trace_id)?;
    if !matches!(
        instance.owning_work_package.as_str(),
        "SB-0" | "SB-1" | "SB-2" | "SB-3" | "SB-4" | "SB-5" | "SB-6" | "SB-7" | "SB-8" | "SB-9"
    ) {
        return Err(invalid("owning_work_package must be SB-0 through SB-9"));
    }
    validate_subject(instance.scope, &instance.subject)?;
    validate_dimensions(instance.scope, &instance.dimensions)
}

fn validate_subject(
    scope: ApplicabilityScope,
    subject: &ApplicabilitySubject,
) -> Result<(), ApplicabilityValidationError> {
    match (scope, subject) {
        (
            ApplicabilityScope::Implementation,
            ApplicabilitySubject::Component {
                component_id,
                component_version,
            },
        ) => {
            validate_namespaced_id("subject.component_id", component_id, "component:")?;
            validate_semantic_version("subject.component_version", component_version)
        }
        (
            ApplicabilityScope::Implementation,
            ApplicabilitySubject::AdapterCapability {
                adapter_kind,
                adapter_version,
                capability_id,
            },
        ) => {
            validate_canonical_name("subject.adapter_kind", adapter_kind)?;
            validate_semantic_version("subject.adapter_version", adapter_version)?;
            validate_canonical_name("subject.capability_id", capability_id)
        }
        (
            ApplicabilityScope::Deployment,
            ApplicabilitySubject::Deployment {
                deployment_id,
                deployment_profile_id,
                trust_domain_id,
                tenancy_mode,
            },
        ) => {
            validate_namespaced_id("subject.deployment_id", deployment_id, "deployment:")?;
            validate_namespaced_id(
                "subject.deployment_profile_id",
                deployment_profile_id,
                "deployment-security-profile:",
            )?;
            validate_namespaced_id("subject.trust_domain_id", trust_domain_id, "trust-domain:")?;
            if !matches!(tenancy_mode.as_str(), "single_tenant" | "multi_tenant") {
                return Err(invalid(
                    "subject.tenancy_mode must be single_tenant or multi_tenant",
                ));
            }
            Ok(())
        }
        (
            ApplicabilityScope::Deployment,
            ApplicabilitySubject::ProviderCapability {
                deployment_id,
                provider_id,
                configuration_version,
                descriptor_id,
                descriptor_version,
                adapter_kind,
                adapter_version,
                capability_id,
            },
        ) => {
            validate_namespaced_id("subject.deployment_id", deployment_id, "deployment:")?;
            validate_namespaced_id("subject.provider_id", provider_id, "provider:")?;
            validate_positive_exact_version(
                "subject.configuration_version",
                *configuration_version,
            )?;
            validate_namespaced_id(
                "subject.descriptor_id",
                descriptor_id,
                "capability-descriptor:",
            )?;
            validate_positive_exact_version("subject.descriptor_version", *descriptor_version)?;
            validate_canonical_name("subject.adapter_kind", adapter_kind)?;
            validate_semantic_version("subject.adapter_version", adapter_version)?;
            validate_canonical_name("subject.capability_id", capability_id)
        }
        (ApplicabilityScope::Implementation, _) => Err(invalid(
            "implementation instances require a component or adapter_capability subject",
        )),
        (ApplicabilityScope::Deployment, _) => Err(invalid(
            "deployment instances require a deployment or provider_capability subject",
        )),
    }
}

fn validate_dimensions(
    scope: ApplicabilityScope,
    dimensions: &[ApplicabilityDimension],
) -> Result<(), ApplicabilityValidationError> {
    if dimensions.len() > MAX_DIMENSIONS_PER_INSTANCE {
        return Err(invalid(format!(
            "instance has more than {MAX_DIMENSIONS_PER_INSTANCE} dimensions"
        )));
    }
    let required_prefix = match scope {
        ApplicabilityScope::Implementation => "implementation.",
        ApplicabilityScope::Deployment => "deployment.",
    };
    let mut previous: Option<&str> = None;
    for dimension in dimensions {
        if previous.is_some_and(|name| name >= dimension.name.as_str()) {
            return Err(invalid(
                "dimension names must be strictly sorted and unique",
            ));
        }
        previous = Some(&dimension.name);
        validate_dimension_name(&dimension.name, required_prefix)?;
        validate_dimension_value(&dimension.value)?;
    }
    Ok(())
}

fn validate_dimension_name(
    value: &str,
    required_prefix: &str,
) -> Result<(), ApplicabilityValidationError> {
    if value.len() > MAX_DIMENSION_NAME_BYTES {
        return Err(invalid(format!(
            "dimension name exceeds {MAX_DIMENSION_NAME_BYTES} bytes"
        )));
    }
    let Some(suffix) = value.strip_prefix(required_prefix) else {
        return Err(invalid(format!(
            "dimension {value} must use the {required_prefix} scope prefix"
        )));
    };
    if !is_dimension_suffix(suffix) {
        return Err(invalid(format!("dimension name {value} is not canonical")));
    }
    Ok(())
}

fn validate_dimension_value(
    value: &ApplicabilityDimensionValue,
) -> Result<(), ApplicabilityValidationError> {
    match value {
        ApplicabilityDimensionValue::String(value) => validate_dimension_string(value),
        ApplicabilityDimensionValue::Boolean(_) => Ok(()),
        ApplicabilityDimensionValue::Integer(value) => validate_exact_integer(*value),
        ApplicabilityDimensionValue::Set(values) => {
            if values.is_empty() || values.len() > MAX_SCALARS_PER_SET {
                return Err(invalid(format!(
                    "set-valued dimension must contain 1 through {MAX_SCALARS_PER_SET} scalars"
                )));
            }
            let mut previous: Option<&ApplicabilityScalar> = None;
            for scalar in values {
                validate_scalar(scalar)?;
                if previous.is_some_and(|prior| compare_scalars(prior, scalar) != Ordering::Less) {
                    return Err(invalid(
                        "set-valued dimension scalars must be strictly sorted and unique",
                    ));
                }
                previous = Some(scalar);
            }
            Ok(())
        }
    }
}

fn validate_scalar(value: &ApplicabilityScalar) -> Result<(), ApplicabilityValidationError> {
    match value {
        ApplicabilityScalar::Boolean(_) => Ok(()),
        ApplicabilityScalar::Integer(value) => validate_exact_integer(*value),
        ApplicabilityScalar::String(value) => validate_dimension_string(value),
    }
}

fn validate_dimension_string(value: &str) -> Result<(), ApplicabilityValidationError> {
    if value.is_empty() || value.len() > MAX_DIMENSION_STRING_BYTES {
        return Err(invalid(format!(
            "dimension string must contain 1 through {MAX_DIMENSION_STRING_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_exact_integer(value: i64) -> Result<(), ApplicabilityValidationError> {
    if !(-MAX_EXACT_JSON_INTEGER..=MAX_EXACT_JSON_INTEGER).contains(&value) {
        return Err(invalid(format!(
            "dimension integer must be within ±{MAX_EXACT_JSON_INTEGER}"
        )));
    }
    Ok(())
}

fn compare_subjects(left: &ApplicabilitySubject, right: &ApplicabilitySubject) -> Ordering {
    subject_rank(left)
        .cmp(&subject_rank(right))
        .then_with(|| match (left, right) {
            (
                ApplicabilitySubject::Component {
                    component_id: left_id,
                    component_version: left_version,
                },
                ApplicabilitySubject::Component {
                    component_id: right_id,
                    component_version: right_version,
                },
            ) => left_id
                .cmp(right_id)
                .then_with(|| left_version.cmp(right_version)),
            (
                ApplicabilitySubject::AdapterCapability {
                    adapter_kind: left_kind,
                    adapter_version: left_version,
                    capability_id: left_capability,
                },
                ApplicabilitySubject::AdapterCapability {
                    adapter_kind: right_kind,
                    adapter_version: right_version,
                    capability_id: right_capability,
                },
            ) => left_kind
                .cmp(right_kind)
                .then_with(|| left_version.cmp(right_version))
                .then_with(|| left_capability.cmp(right_capability)),
            (
                ApplicabilitySubject::Deployment {
                    deployment_id: left_deployment,
                    deployment_profile_id: left_profile,
                    trust_domain_id: left_domain,
                    tenancy_mode: left_tenancy,
                },
                ApplicabilitySubject::Deployment {
                    deployment_id: right_deployment,
                    deployment_profile_id: right_profile,
                    trust_domain_id: right_domain,
                    tenancy_mode: right_tenancy,
                },
            ) => left_deployment
                .cmp(right_deployment)
                .then_with(|| left_profile.cmp(right_profile))
                .then_with(|| left_domain.cmp(right_domain))
                .then_with(|| left_tenancy.cmp(right_tenancy)),
            (
                ApplicabilitySubject::ProviderCapability {
                    deployment_id: left_deployment,
                    provider_id: left_provider,
                    configuration_version: left_configuration,
                    descriptor_id: left_descriptor,
                    descriptor_version: left_descriptor_version,
                    adapter_kind: left_adapter,
                    adapter_version: left_adapter_version,
                    capability_id: left_capability,
                },
                ApplicabilitySubject::ProviderCapability {
                    deployment_id: right_deployment,
                    provider_id: right_provider,
                    configuration_version: right_configuration,
                    descriptor_id: right_descriptor,
                    descriptor_version: right_descriptor_version,
                    adapter_kind: right_adapter,
                    adapter_version: right_adapter_version,
                    capability_id: right_capability,
                },
            ) => left_deployment
                .cmp(right_deployment)
                .then_with(|| left_provider.cmp(right_provider))
                .then_with(|| left_configuration.cmp(right_configuration))
                .then_with(|| left_descriptor.cmp(right_descriptor))
                .then_with(|| left_descriptor_version.cmp(right_descriptor_version))
                .then_with(|| left_adapter.cmp(right_adapter))
                .then_with(|| left_adapter_version.cmp(right_adapter_version))
                .then_with(|| left_capability.cmp(right_capability)),
            _ => Ordering::Equal,
        })
}

fn compare_dimensions(
    left: &[ApplicabilityDimension],
    right: &[ApplicabilityDimension],
) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = left
            .name
            .cmp(&right.name)
            .then_with(|| compare_dimension_values(&left.value, &right.value));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn compare_dimension_values(
    left: &ApplicabilityDimensionValue,
    right: &ApplicabilityDimensionValue,
) -> Ordering {
    dimension_value_rank(left)
        .cmp(&dimension_value_rank(right))
        .then_with(|| match (left, right) {
            (
                ApplicabilityDimensionValue::String(left),
                ApplicabilityDimensionValue::String(right),
            ) => left.cmp(right),
            (
                ApplicabilityDimensionValue::Boolean(left),
                ApplicabilityDimensionValue::Boolean(right),
            ) => left.cmp(right),
            (
                ApplicabilityDimensionValue::Integer(left),
                ApplicabilityDimensionValue::Integer(right),
            ) => left.cmp(right),
            (ApplicabilityDimensionValue::Set(left), ApplicabilityDimensionValue::Set(right)) => {
                compare_scalar_slices(left, right)
            }
            _ => Ordering::Equal,
        })
}

fn compare_scalar_slices(left: &[ApplicabilityScalar], right: &[ApplicabilityScalar]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = compare_scalars(left, right);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn compare_scalars(left: &ApplicabilityScalar, right: &ApplicabilityScalar) -> Ordering {
    scalar_rank(left)
        .cmp(&scalar_rank(right))
        .then_with(|| match (left, right) {
            (ApplicabilityScalar::Boolean(left), ApplicabilityScalar::Boolean(right)) => {
                left.cmp(right)
            }
            (ApplicabilityScalar::Integer(left), ApplicabilityScalar::Integer(right)) => {
                left.cmp(right)
            }
            (ApplicabilityScalar::String(left), ApplicabilityScalar::String(right)) => {
                left.cmp(right)
            }
            _ => Ordering::Equal,
        })
}

const fn scope_rank(scope: ApplicabilityScope) -> u8 {
    match scope {
        ApplicabilityScope::Implementation => 0,
        ApplicabilityScope::Deployment => 1,
    }
}

const fn subject_rank(subject: &ApplicabilitySubject) -> u8 {
    match subject {
        ApplicabilitySubject::Component { .. } => 0,
        ApplicabilitySubject::AdapterCapability { .. } => 1,
        ApplicabilitySubject::Deployment { .. } => 2,
        ApplicabilitySubject::ProviderCapability { .. } => 3,
    }
}

const fn dimension_value_rank(value: &ApplicabilityDimensionValue) -> u8 {
    match value {
        ApplicabilityDimensionValue::Boolean(_) => 0,
        ApplicabilityDimensionValue::Integer(_) => 1,
        ApplicabilityDimensionValue::String(_) => 2,
        ApplicabilityDimensionValue::Set(_) => 3,
    }
}

const fn scalar_rank(value: &ApplicabilityScalar) -> u8 {
    match value {
        ApplicabilityScalar::Boolean(_) => 0,
        ApplicabilityScalar::Integer(_) => 1,
        ApplicabilityScalar::String(_) => 2,
    }
}

fn canonical_wire_bytes(value: &impl Serialize) -> Result<Vec<u8>, ApplicabilityValidationError> {
    let value: Value = serde_json::to_value(value)
        .map_err(|error| ApplicabilityValidationError::Serialization(error.to_string()))?;
    canonical_json_bytes(&value).map_err(Into::into)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_trace_id(value: &str) -> Result<(), ApplicabilityValidationError> {
    let Some(suffix) = value.strip_prefix("TRACE-") else {
        return Err(invalid("trace_id must use the TRACE- namespace"));
    };
    if !(3..=128).contains(&suffix.len())
        || !suffix.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(invalid("trace_id is not canonical"));
    }
    Ok(())
}

fn validate_namespaced_id(
    label: &str,
    value: &str,
    prefix: &str,
) -> Result<(), ApplicabilityValidationError> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(invalid(format!("{label} must use the {prefix} namespace")));
    };
    if !(3..=127).contains(&suffix.len())
        || !suffix
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !suffix.bytes().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(invalid(format!("{label} is not canonical")));
    }
    Ok(())
}

fn validate_canonical_name(label: &str, value: &str) -> Result<(), ApplicabilityValidationError> {
    let bytes = value.as_bytes();
    if !(2..=MAX_CANONICAL_NAME_BYTES).contains(&bytes.len())
        || !bytes.first().is_some_and(u8::is_ascii_lowercase)
        || !bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(invalid(format!("{label} is not canonical")));
    }
    Ok(())
}

fn validate_semantic_version(label: &str, value: &str) -> Result<(), ApplicabilityValidationError> {
    if !(5..=128).contains(&value.len()) || !value.is_ascii() {
        return Err(invalid(format!("{label} is not a semantic version")));
    }
    let mut build_split = value.split('+');
    let core_and_prerelease = build_split.next().unwrap_or_default();
    if let Some(build) = build_split.next()
        && (build_split.next().is_some() || !valid_semver_identifiers(build, true))
    {
        return Err(invalid(format!("{label} is not a semantic version")));
    }
    let (core, prerelease) = core_and_prerelease
        .split_once('-')
        .map_or((core_and_prerelease, None), |(core, pre)| (core, Some(pre)));
    let mut components = core.split('.');
    let core_is_valid = (0..3).all(|_| {
        components.next().is_some_and(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component == "0" || !component.starts_with('0'))
        })
    }) && components.next().is_none();
    if !core_is_valid || prerelease.is_some_and(|value| !valid_semver_identifiers(value, false)) {
        return Err(invalid(format!("{label} is not a semantic version")));
    }
    Ok(())
}

fn valid_semver_identifiers(value: &str, allow_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (allow_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || identifier == "0"
                    || !identifier.starts_with('0'))
        })
}

fn validate_positive_exact_version(
    label: &str,
    value: u64,
) -> Result<(), ApplicabilityValidationError> {
    if value == 0 || value > MAX_EXACT_JSON_INTEGER as u64 {
        return Err(invalid(format!(
            "{label} must be between 1 and {MAX_EXACT_JSON_INTEGER}"
        )));
    }
    Ok(())
}

fn validate_nonzero_digest(label: &str, value: &str) -> Result<(), ApplicabilityValidationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid(format!(
            "{label} must use sha256:<64 lowercase hex>"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hex.bytes().all(|byte| byte == b'0')
    {
        return Err(invalid(format!(
            "{label} must use a nonzero sha256:<64 lowercase hex> digest"
        )));
    }
    Ok(())
}

fn is_dimension_suffix(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !matches!(bytes.last(), Some(b'.' | b'_' | b'-'))
        && !bytes
            .windows(2)
            .any(|pair| matches!(pair, [b'.' | b'_' | b'-', b'.' | b'_' | b'-']))
}

fn invalid(message: impl Into<String>) -> ApplicabilityValidationError {
    ApplicabilityValidationError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_binding() -> ApplicabilityControlTraceBinding {
        ApplicabilityControlTraceBinding {
            document_id: "control-trace:fixture-v2".into(),
            document_version: 7,
            content_digest: format!("sha256:{}", "a".repeat(64)),
        }
    }

    fn unsigned_component_instance() -> ApplicabilityInstance {
        ApplicabilityInstance {
            applicability_instance_id: String::new(),
            trace_id: "TRACE-SB-CONF-03-AC-048".into(),
            owning_work_package: "SB-0".into(),
            scope: ApplicabilityScope::Implementation,
            subject: ApplicabilitySubject::Component {
                component_id: "component:ryuki-api".into(),
                component_version: "1.2.3".into(),
            },
            dimensions: vec![
                ApplicabilityDimension {
                    name: "implementation.artifact_digest".into(),
                    value: ApplicabilityDimensionValue::String(format!(
                        "sha256:{}",
                        "b".repeat(64)
                    )),
                },
                ApplicabilityDimension {
                    name: "implementation.feature_set".into(),
                    value: ApplicabilityDimensionValue::Set(vec![
                        ApplicabilityScalar::Boolean(false),
                        ApplicabilityScalar::Boolean(true),
                        ApplicabilityScalar::Integer(7),
                        ApplicabilityScalar::String("repository-conformance".into()),
                    ]),
                },
                ApplicabilityDimension {
                    name: "implementation.source_revision".into(),
                    value: ApplicabilityDimensionValue::String("c".repeat(40)),
                },
            ],
        }
    }

    fn signed_component_instance() -> ApplicabilityInstance {
        let mut instance = unsigned_component_instance();
        instance.applicability_instance_id =
            recompute_applicability_instance_id(&trace_binding(), &instance).unwrap();
        instance
    }

    fn signed_adapter_instance() -> ApplicabilityInstance {
        let mut instance = ApplicabilityInstance {
            applicability_instance_id: String::new(),
            trace_id: "TRACE-SB-CONF-04-AC-048".into(),
            owning_work_package: "SB-0".into(),
            scope: ApplicabilityScope::Implementation,
            subject: ApplicabilitySubject::AdapterCapability {
                adapter_kind: "auth.entra-id".into(),
                adapter_version: "1.2.3".into(),
                capability_id: "token-validation".into(),
            },
            dimensions: vec![ApplicabilityDimension {
                name: "implementation.source_revision".into(),
                value: ApplicabilityDimensionValue::String("c".repeat(40)),
            }],
        };
        instance.applicability_instance_id =
            recompute_applicability_instance_id(&trace_binding(), &instance).unwrap();
        instance
    }

    #[test]
    fn fixed_instance_and_inventory_vectors_are_stable() {
        let component = signed_component_instance();
        assert_eq!(
            component.applicability_instance_id,
            "applicability:sha256:c93aa8e4a58d3136e4dd7fe1b8778c764c21156e72d13d80a73e8faede35953a"
        );
        let mut instances = vec![component, signed_adapter_instance()];
        instances.sort_by(compare_applicability_instances);
        let binding =
            recompute_applicability_inventory_binding(&trace_binding(), &instances).unwrap();
        assert_eq!(binding.identity_contract, APPLICABILITY_IDENTITY_CONTRACT);
        assert_eq!(binding.inventory_contract, APPLICABILITY_INVENTORY_CONTRACT);
        assert_eq!(binding.instance_count, 2);
        assert_eq!(
            binding.content_digest,
            "sha256:f98999030c896c6787209a78ef8735bb3a9c48c8664ddca6f618d6eda7dc37c4"
        );
        validate_applicability_inventory_binding(&trace_binding(), &instances, &binding).unwrap();
    }

    #[test]
    fn every_identity_axis_changes_the_instance_id() {
        let original = signed_component_instance();
        let original_id = original.applicability_instance_id.clone();

        let mut changed = original.clone();
        changed.trace_id = "TRACE-SB-CONF-04-AC-048".into();
        assert_ne!(
            recompute_applicability_instance_id(&trace_binding(), &changed).unwrap(),
            original_id
        );

        let mut changed = original.clone();
        changed.owning_work_package = "SB-1".into();
        assert_ne!(
            recompute_applicability_instance_id(&trace_binding(), &changed).unwrap(),
            original_id
        );

        let mut changed = original.clone();
        let ApplicabilitySubject::Component {
            component_version, ..
        } = &mut changed.subject
        else {
            unreachable!();
        };
        *component_version = "1.2.4".into();
        assert_ne!(
            recompute_applicability_instance_id(&trace_binding(), &changed).unwrap(),
            original_id
        );

        let mut changed = original.clone();
        changed.dimensions[0].value =
            ApplicabilityDimensionValue::String(format!("sha256:{}", "d".repeat(64)));
        assert_ne!(
            recompute_applicability_instance_id(&trace_binding(), &changed).unwrap(),
            original_id
        );

        let mut changed_trace = trace_binding();
        changed_trace.content_digest = format!("sha256:{}", "e".repeat(64));
        assert_ne!(
            recompute_applicability_instance_id(&changed_trace, &original).unwrap(),
            original_id
        );
    }

    #[test]
    fn dimensions_and_scalar_sets_require_strict_canonical_order() {
        let mut instance = unsigned_component_instance();
        instance.dimensions.swap(0, 1);
        assert!(
            recompute_applicability_instance_id(&trace_binding(), &instance)
                .unwrap_err()
                .to_string()
                .contains("strictly sorted")
        );

        let mut instance = unsigned_component_instance();
        let ApplicabilityDimensionValue::Set(values) = &mut instance.dimensions[1].value else {
            unreachable!();
        };
        values.swap(0, 1);
        assert!(
            recompute_applicability_instance_id(&trace_binding(), &instance)
                .unwrap_err()
                .to_string()
                .contains("strictly sorted")
        );

        let mut instance = unsigned_component_instance();
        let ApplicabilityDimensionValue::Set(values) = &mut instance.dimensions[1].value else {
            unreachable!();
        };
        values[1] = values[0].clone();
        assert!(
            recompute_applicability_instance_id(&trace_binding(), &instance)
                .unwrap_err()
                .to_string()
                .contains("strictly sorted")
        );
    }

    #[test]
    fn inventory_rejects_reordering_duplicates_and_stale_bindings() {
        let component = signed_component_instance();
        let adapter = signed_adapter_instance();
        let mut instances = vec![component, adapter];
        instances.sort_by(compare_applicability_instances);
        validate_applicability_inventory(&trace_binding(), &instances).unwrap();

        let mut reversed = instances.clone();
        reversed.reverse();
        assert!(
            validate_applicability_inventory(&trace_binding(), &reversed)
                .unwrap_err()
                .to_string()
                .contains("strict canonical order")
        );

        let duplicate = vec![instances[0].clone(), instances[0].clone()];
        assert!(
            validate_applicability_inventory(&trace_binding(), &duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate applicability_instance_id")
        );

        let mut binding =
            recompute_applicability_inventory_binding(&trace_binding(), &instances).unwrap();
        binding.instance_count += 1;
        assert!(
            validate_applicability_inventory_binding(&trace_binding(), &instances, &binding)
                .is_err()
        );
    }

    #[test]
    fn exact_integer_bounds_and_scope_subject_partition_are_enforced() {
        let mut instance = unsigned_component_instance();
        instance.dimensions.push(ApplicabilityDimension {
            name: "implementation.zz-exact-integer".into(),
            value: ApplicabilityDimensionValue::Integer(MAX_EXACT_JSON_INTEGER),
        });
        assert!(recompute_applicability_instance_id(&trace_binding(), &instance).is_ok());

        let last = instance.dimensions.last_mut().unwrap();
        last.value = ApplicabilityDimensionValue::Integer(MAX_EXACT_JSON_INTEGER + 1);
        assert!(
            recompute_applicability_instance_id(&trace_binding(), &instance)
                .unwrap_err()
                .to_string()
                .contains("dimension integer")
        );

        let mut wrong_scope = unsigned_component_instance();
        wrong_scope.scope = ApplicabilityScope::Deployment;
        assert!(
            recompute_applicability_instance_id(&trace_binding(), &wrong_scope)
                .unwrap_err()
                .to_string()
                .contains("deployment instances require")
        );
    }

    #[test]
    fn wire_records_reject_unknown_fields() {
        let mut value = serde_json::to_value(signed_component_instance()).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ApplicabilityInstance>(value).is_err());

        let value = serde_json::json!({
            "subject_kind": "component",
            "component_id": "component:ryuki-api",
            "component_version": "1.2.3",
            "unknown": true
        });
        assert!(serde_json::from_value::<ApplicabilitySubject>(value).is_err());
    }
}
