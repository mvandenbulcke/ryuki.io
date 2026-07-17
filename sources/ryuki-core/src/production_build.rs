//! Typed contract for the detached production build manifest.
//!
//! This document is untrusted input until the API loader binds its exact raw
//! bytes to deployment pins and compares it with the running executable and
//! the compiled build-surface inventory. Parsing this type never grants
//! production authority.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::conformance_applicability::{
    ApplicabilityControlTraceBinding, ApplicabilityInstance, ApplicabilityInventoryBinding,
    ApplicabilityScope, ApplicabilitySubject, compare_applicability_instances,
    recompute_applicability_instance_id, validate_applicability_instance,
    validate_applicability_inventory, validate_applicability_inventory_binding,
};
use crate::security_profile::{ArtifactKind, VersionedContentReference};

pub const PRODUCTION_BUILD_MANIFEST_SCHEMA_URI: &str =
    "https://ryuki.io/schemas/security-contracts/v1/production-build-manifest.schema.json";
pub const PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION: &str = "2.0.0";
pub const PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND: &str = "production-build-manifest";
pub const PRODUCTION_BUILD_COMPONENT_ID: &str = "component:ryuki-api";
pub const PRODUCTION_BUILD_EXECUTABLE_NAME: &str = "ryuki-api";

const MAX_ADAPTERS: usize = 256;
const MAX_CAPABILITIES_PER_ADAPTER: usize = 256;
const MAX_BASELINE_TRACES: usize = 4096;
const MAX_SELECTORS: usize = 1024;
const MAX_IMPLEMENTATION_APPLICABILITY_INSTANCES: usize = 16_384;
const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_RUNTIME_EXECUTABLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionBuildManifest {
    #[serde(rename = "$schema")]
    pub schema_uri: String,
    pub schema_version: String,
    pub contract_kind: String,
    pub document_id: String,
    pub document_version: u64,
    pub component: BuildComponent,
    pub source: BuildSource,
    pub runtime_executable: RuntimeExecutable,
    pub oci_subject: OciSubject,
    pub control_trace_ref: VersionedContentReference,
    pub shipped_adapters: Vec<ShippedAdapter>,
    pub selector_dispositions: Vec<BuildSelectorDisposition>,
    pub implementation_applicability: ApplicabilityInventoryBinding,
    pub implementation_applicability_instances: Vec<ApplicabilityInstance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildComponent {
    pub component_id: String,
    pub component_version: String,
    pub executable_name: String,
    pub target: BuildTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildTarget {
    pub architecture: String,
    pub operating_system: String,
    pub family: String,
    pub pointer_width_bits: u16,
    pub endian: BuildEndian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildEndian {
    Little,
    Big,
}

impl BuildEndian {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Little => "little",
            Self::Big => "big",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSource {
    pub revision_algorithm: SourceRevisionAlgorithm,
    pub revision: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRevisionAlgorithm {
    GitSha1,
    GitSha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeExecutable {
    pub content_digest: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciSubject {
    pub subject_kind: OciSubjectKind,
    pub repository: String,
    pub content_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciSubjectKind {
    OciImageIndex,
    OciImageManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShippedAdapter {
    pub adapter_kind: String,
    pub adapter_version: String,
    pub production_eligible: bool,
    pub capability_ids: Vec<String>,
    pub mandatory_baseline: MandatoryCapabilityBaseline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandatoryCapabilityBaseline {
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
    pub required_trace_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSelectorDisposition {
    pub selector_domain: SelectorDomain,
    pub selector: String,
    pub disposition: SelectorDisposition,
    pub adapter_kind: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorDomain {
    AuthMode,
    SecretProvider,
    IntegrationAdapter,
}

impl SelectorDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthMode => "auth_mode",
            Self::SecretProvider => "secret_provider",
            Self::IntegrationAdapter => "integration_adapter",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorDisposition {
    Implemented,
    Unsupported,
    CatalogOnly,
    Sentinel,
}

impl SelectorDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::Unsupported => "unsupported",
            Self::CatalogOnly => "catalog_only",
            Self::Sentinel => "sentinel",
        }
    }
}

impl ProductionBuildManifest {
    /// Enforces semantic invariants that JSON Schema cannot express, including
    /// strict ordering and cross-reference closure. Errors are sorted and
    /// deduplicated to keep startup diagnostics deterministic.
    pub fn validate_semantics(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.schema_uri != PRODUCTION_BUILD_MANIFEST_SCHEMA_URI {
            errors.push("$schema is not the canonical production build-manifest URI".into());
        }
        if self.schema_version != PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION {
            errors.push("schema_version is unsupported".into());
        }
        if self.contract_kind != PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND {
            errors.push("contract_kind must equal production-build-manifest".into());
        }
        validate_namespaced_id(
            "document_id",
            &self.document_id,
            "production-build-manifest:",
            &mut errors,
        );
        validate_positive_version("document_version", self.document_version, &mut errors);
        if self.component.component_id != PRODUCTION_BUILD_COMPONENT_ID {
            errors.push("component.component_id must equal component:ryuki-api".into());
        }
        if self.component.executable_name != PRODUCTION_BUILD_EXECUTABLE_NAME {
            errors.push("component.executable_name must equal ryuki-api".into());
        }
        if !is_semantic_version(&self.component.component_version) {
            errors.push("component.component_version is not a canonical semantic version".into());
        }
        for (label, value) in [
            (
                "component.target.architecture",
                &self.component.target.architecture,
            ),
            (
                "component.target.operating_system",
                &self.component.target.operating_system,
            ),
            ("component.target.family", &self.component.target.family),
        ] {
            if !is_canonical_target_name(value) {
                errors.push(format!("{label} is not canonical"));
            }
        }
        if !matches!(self.component.target.pointer_width_bits, 16 | 32 | 64) {
            errors.push("component.target.pointer_width_bits is unsupported".into());
        }
        let expected_revision_len = match self.source.revision_algorithm {
            SourceRevisionAlgorithm::GitSha1 => 40,
            SourceRevisionAlgorithm::GitSha256 => 64,
        };
        if self.source.revision.len() != expected_revision_len
            || !is_lower_hex(&self.source.revision)
        {
            errors.push("source revision does not match revision_algorithm".into());
        }
        validate_digest(
            "runtime_executable.content_digest",
            &self.runtime_executable.content_digest,
            &mut errors,
        );
        if !(1..=MAX_RUNTIME_EXECUTABLE_BYTES).contains(&self.runtime_executable.byte_length) {
            errors.push(format!(
                "runtime_executable.byte_length must be between 1 and {MAX_RUNTIME_EXECUTABLE_BYTES}"
            ));
        }
        validate_digest(
            "oci_subject.content_digest",
            &self.oci_subject.content_digest,
            &mut errors,
        );
        if !is_oci_repository(&self.oci_subject.repository) {
            errors.push("oci_subject.repository is not an untagged canonical repository".into());
        }
        validate_control_trace_reference(&self.control_trace_ref, &mut errors);

        if self.shipped_adapters.is_empty() || self.shipped_adapters.len() > MAX_ADAPTERS {
            errors.push(format!(
                "shipped_adapters must contain between 1 and {MAX_ADAPTERS} entries"
            ));
        }
        if self.selector_dispositions.is_empty() || self.selector_dispositions.len() > MAX_SELECTORS
        {
            errors.push(format!(
                "selector_dispositions must contain between 1 and {MAX_SELECTORS} entries"
            ));
        }
        let applicability_is_bounded = !self.implementation_applicability_instances.is_empty()
            && self.implementation_applicability_instances.len()
                <= MAX_IMPLEMENTATION_APPLICABILITY_INSTANCES;
        if !applicability_is_bounded {
            errors.push(format!(
                "implementation_applicability_instances must contain between 1 and {MAX_IMPLEMENTATION_APPLICABILITY_INSTANCES} entries"
            ));
        }

        let mut shipped = BTreeMap::<&str, &ShippedAdapter>::new();
        let mut previous_adapter = None;
        for adapter in &self.shipped_adapters {
            if previous_adapter.is_some_and(|previous| previous >= adapter.adapter_kind.as_str()) {
                errors.push("shipped_adapters must be strictly sorted by adapter_kind".into());
            }
            previous_adapter = Some(adapter.adapter_kind.as_str());
            if shipped.insert(&adapter.adapter_kind, adapter).is_some() {
                errors.push(format!(
                    "duplicate shipped adapter {}",
                    adapter.adapter_kind
                ));
            }
            validate_adapter(adapter, &mut errors);
        }

        let mut implemented_selector_kinds = BTreeSet::new();
        let mut selector_keys = BTreeSet::new();
        let mut previous_selector: Option<(&str, &str)> = None;
        for selector in &self.selector_dispositions {
            let key = (
                selector.selector_domain.as_str(),
                selector.selector.as_str(),
            );
            if previous_selector.is_some_and(|previous| previous >= key) {
                errors.push(
                    "selector_dispositions must be strictly sorted by domain and selector".into(),
                );
            }
            previous_selector = Some(key);
            if !selector_keys.insert(key) {
                errors.push(format!(
                    "duplicate selector {}:{}",
                    selector.selector_domain.as_str(),
                    selector.selector
                ));
            }
            if !is_canonical_name(&selector.selector, 96) {
                errors.push(format!("selector {} is not canonical", selector.selector));
            }
            match (selector.disposition, selector.adapter_kind.as_deref()) {
                (SelectorDisposition::Implemented, Some(kind)) => {
                    if !shipped.contains_key(kind) {
                        errors.push(format!(
                            "implemented selector {} references unshipped adapter {kind}",
                            selector.selector
                        ));
                    }
                    implemented_selector_kinds.insert(kind);
                }
                (SelectorDisposition::CatalogOnly, Some(kind)) => {
                    if shipped.contains_key(kind) {
                        errors.push(format!(
                            "catalog-only selector {} references shipped adapter {kind}",
                            selector.selector
                        ));
                    }
                    if !is_canonical_name(kind, 96) {
                        errors.push(format!(
                            "catalog-only selector {} has a noncanonical adapter kind",
                            selector.selector
                        ));
                    }
                }
                (SelectorDisposition::Unsupported | SelectorDisposition::Sentinel, None) => {}
                _ => errors.push(format!(
                    "selector {} has an invalid disposition-to-adapter binding",
                    selector.selector
                )),
            }
        }
        for kind in shipped.keys() {
            if !implemented_selector_kinds.contains(kind) {
                errors.push(format!(
                    "shipped adapter {kind} has no implemented selector disposition"
                ));
            }
        }

        if applicability_is_bounded {
            let trace_binding = ApplicabilityControlTraceBinding {
                document_id: self.control_trace_ref.document_id.clone(),
                document_version: self.control_trace_ref.document_version,
                content_digest: self.control_trace_ref.content_digest.clone(),
            };
            let instances = &self.implementation_applicability_instances;

            if let Err(error) = validate_applicability_inventory(&trace_binding, instances) {
                errors.push(format!(
                    "implementation_applicability_instances are invalid: {error}"
                ));
            }
            if let Err(error) = validate_applicability_inventory_binding(
                &trace_binding,
                instances,
                &self.implementation_applicability,
            ) {
                errors.push(format!(
                    "implementation_applicability binding does not exactly match its instances: {error}"
                ));
            }

            let mut instance_ids = BTreeSet::new();
            let mut previous_instance: Option<&ApplicabilityInstance> = None;
            let mut component_subject_present = false;
            let mut adapter_subject_traces = BTreeMap::<(String, String), BTreeSet<String>>::new();

            for (index, instance) in instances.iter().enumerate() {
                if previous_instance.is_some_and(|previous| {
                    compare_applicability_instances(previous, instance) != Ordering::Less
                }) {
                    errors.push(
                        "implementation_applicability_instances must be in strict canonical order"
                            .into(),
                    );
                }
                previous_instance = Some(instance);

                if instance.scope != ApplicabilityScope::Implementation {
                    errors.push(format!(
                        "implementation_applicability_instances[{index}] must use implementation scope"
                    ));
                }
                if !instance_ids.insert(instance.applicability_instance_id.as_str()) {
                    errors.push(format!(
                        "duplicate applicability_instance_id {}",
                        instance.applicability_instance_id
                    ));
                }
                if let Err(error) = validate_applicability_instance(&trace_binding, instance) {
                    errors.push(format!(
                        "implementation_applicability_instances[{index}] is invalid: {error}"
                    ));
                }
                match recompute_applicability_instance_id(&trace_binding, instance) {
                    Ok(expected_id) if expected_id != instance.applicability_instance_id => {
                        errors.push(format!(
                            "implementation_applicability_instances[{index}] applicability_instance_id does not match its canonical identity"
                        ));
                    }
                    Err(error) => errors.push(format!(
                        "implementation_applicability_instances[{index}] identity cannot be recomputed: {error}"
                    )),
                    _ => {}
                }

                match &instance.subject {
                    ApplicabilitySubject::Component {
                        component_id,
                        component_version,
                    } => {
                        let exact_component = component_id == &self.component.component_id
                            && component_version == &self.component.component_version;
                        if !exact_component {
                            errors.push(format!(
                                "implementation_applicability_instances[{index}] component subject does not match the manifest component identity and version"
                            ));
                        } else {
                            component_subject_present = true;
                        }
                    }
                    ApplicabilitySubject::AdapterCapability {
                        adapter_kind,
                        adapter_version,
                        capability_id,
                    } => match shipped.get(adapter_kind.as_str()) {
                        Some(adapter) => {
                            let version_matches =
                                adapter.adapter_version.as_str() == adapter_version.as_str();
                            let capability_matches = adapter
                                .capability_ids
                                .binary_search_by(|item| item.as_str().cmp(capability_id.as_str()))
                                .is_ok();
                            if !version_matches {
                                errors.push(format!(
                                    "implementation_applicability_instances[{index}] adapter {adapter_kind} version does not match the shipped adapter"
                                ));
                            }
                            if !capability_matches {
                                errors.push(format!(
                                    "implementation_applicability_instances[{index}] references unknown capability {adapter_kind}:{capability_id}"
                                ));
                            }
                            if version_matches && capability_matches {
                                adapter_subject_traces
                                    .entry((adapter_kind.clone(), capability_id.clone()))
                                    .or_default()
                                    .insert(instance.trace_id.clone());
                            }
                        }
                        None => errors.push(format!(
                            "implementation_applicability_instances[{index}] references unshipped adapter {adapter_kind}"
                        )),
                    },
                    ApplicabilitySubject::Deployment { .. }
                    | ApplicabilitySubject::ProviderCapability { .. } => errors.push(format!(
                        "implementation_applicability_instances[{index}] uses a deployment-owned subject"
                    )),
                }
            }

            if !component_subject_present {
                errors.push(
                    "implementation_applicability_instances omit the exact component subject"
                        .into(),
                );
            }
            for adapter in &self.shipped_adapters {
                for capability in &adapter.capability_ids {
                    let key = (adapter.adapter_kind.clone(), capability.clone());
                    let Some(traces) = adapter_subject_traces.get(&key) else {
                        errors.push(format!(
                            "implementation_applicability_instances omit shipped adapter capability {}:{}",
                            adapter.adapter_kind, capability
                        ));
                        continue;
                    };
                    for required_trace in &adapter.mandatory_baseline.required_trace_ids {
                        if !traces.contains(required_trace) {
                            errors.push(format!(
                                "shipped adapter capability {}:{} omits mandatory baseline trace {required_trace}",
                                adapter.adapter_kind, capability
                            ));
                        }
                    }
                }
            }
        }

        errors.sort();
        errors.dedup();
        errors
    }
}

fn validate_adapter(adapter: &ShippedAdapter, errors: &mut Vec<String>) {
    if !is_canonical_name(&adapter.adapter_kind, 96) {
        errors.push(format!(
            "shipped adapter {} has a noncanonical kind",
            adapter.adapter_kind
        ));
    }
    if !is_semantic_version(&adapter.adapter_version) {
        errors.push(format!(
            "shipped adapter {} has a noncanonical version",
            adapter.adapter_kind
        ));
    }
    if adapter.capability_ids.is_empty()
        || adapter.capability_ids.len() > MAX_CAPABILITIES_PER_ADAPTER
        || !strictly_sorted(adapter.capability_ids.iter().map(String::as_str))
    {
        errors.push(format!(
            "shipped adapter {} capability_ids must be nonempty, unique, sorted, and bounded",
            adapter.adapter_kind
        ));
    }
    for capability in &adapter.capability_ids {
        if !is_canonical_name(capability, 96) {
            errors.push(format!(
                "shipped adapter {} has invalid capability {capability}",
                adapter.adapter_kind
            ));
        }
    }
    let baseline = &adapter.mandatory_baseline;
    validate_namespaced_id(
        "mandatory_baseline.document_id",
        &baseline.document_id,
        "baseline:",
        errors,
    );
    validate_positive_version(
        &format!(
            "shipped adapter {} baseline document_version",
            adapter.adapter_kind
        ),
        baseline.document_version,
        errors,
    );
    validate_digest(
        "mandatory_baseline.content_digest",
        &baseline.content_digest,
        errors,
    );
    if !is_normalized_relative_locator(&baseline.artifact_locator, false) {
        errors.push(format!(
            "shipped adapter {} baseline locator is not normalized",
            adapter.adapter_kind
        ));
    }
    if baseline.required_trace_ids.is_empty()
        || baseline.required_trace_ids.len() > MAX_BASELINE_TRACES
        || !strictly_sorted(baseline.required_trace_ids.iter().map(String::as_str))
    {
        errors.push(format!(
            "shipped adapter {} baseline trace ids must be nonempty, unique, sorted, and bounded",
            adapter.adapter_kind
        ));
    }
    for trace in &baseline.required_trace_ids {
        if !is_trace_id(trace) {
            errors.push(format!(
                "shipped adapter {} has invalid baseline trace {trace}",
                adapter.adapter_kind
            ));
        }
    }
}

fn validate_control_trace_reference(
    reference: &VersionedContentReference,
    errors: &mut Vec<String>,
) {
    if reference.artifact_kind != ArtifactKind::ControlTrace {
        errors.push("control_trace_ref.artifact_kind must equal control-trace".into());
    }
    validate_namespaced_id(
        "control_trace_ref.document_id",
        &reference.document_id,
        "control-trace:",
        errors,
    );
    validate_positive_version(
        "control_trace_ref.document_version",
        reference.document_version,
        errors,
    );
    validate_digest(
        "control_trace_ref.content_digest",
        &reference.content_digest,
        errors,
    );
    if !is_normalized_relative_locator(&reference.artifact_locator, true) {
        errors.push(
            "control_trace_ref.artifact_locator must be a normalized relative JSON file".into(),
        );
    }
}

fn validate_namespaced_id(label: &str, value: &str, prefix: &str, errors: &mut Vec<String>) {
    let Some(suffix) = value.strip_prefix(prefix) else {
        errors.push(format!("{label} must use the {prefix} namespace"));
        return;
    };
    if !is_namespaced_id_suffix(suffix) {
        errors.push(format!("{label} is not canonical"));
    }
}

fn validate_positive_version(label: &str, value: u64, errors: &mut Vec<String>) {
    if !(1..=MAX_EXACT_JSON_INTEGER).contains(&value) {
        errors.push(format!(
            "{label} must be between 1 and {MAX_EXACT_JSON_INTEGER}"
        ));
    }
}

fn validate_digest(label: &str, value: &str, errors: &mut Vec<String>) {
    let Some(hex) = value.strip_prefix("sha256:") else {
        errors.push(format!("{label} must use sha256:<64 lowercase hex>"));
        return;
    };
    if hex.len() != 64 || !is_lower_hex(hex) || hex.bytes().all(|byte| byte == b'0') {
        errors.push(format!(
            "{label} must use a nonzero sha256:<64 lowercase hex> digest"
        ));
    }
}

fn is_canonical_name(value: &str, max_len: usize) -> bool {
    let bytes = value.as_bytes();
    (2..=max_len).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_namespaced_id_suffix(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=127).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_canonical_target_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=64).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_semantic_version(value: &str) -> bool {
    if !(5..=128).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    let mut build_split = value.split('+');
    let Some(version_and_pre) = build_split.next() else {
        return false;
    };
    if let Some(build) = build_split.next()
        && (build_split.next().is_some() || !valid_semver_identifiers(build, true))
    {
        return false;
    }
    let (core, prerelease) = version_and_pre
        .split_once('-')
        .map_or((version_and_pre, None), |(core, pre)| (core, Some(pre)));
    let mut core_parts = core.split('.');
    let core_is_valid = (0..3).all(|_| {
        core_parts.next().is_some_and(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'))
        })
    }) && core_parts.next().is_none();
    core_is_valid && prerelease.is_none_or(|prerelease| valid_semver_identifiers(prerelease, false))
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

fn is_oci_repository(value: &str) -> bool {
    (3..=256).contains(&value.len())
        && !value.contains('@')
        && !value.contains(':')
        && !value.contains("//")
        && value.split('/').all(|part| {
            !part.is_empty()
                && !matches!(part, "." | "..")
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && part.bytes().skip(1).all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

fn is_normalized_relative_locator(value: &str, require_json: bool) -> bool {
    let valid_length = if require_json {
        (8..=512).contains(&value.len())
    } else {
        (3..=512).contains(&value.len())
    };
    if !valid_length || value.contains('\\') {
        return false;
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return false;
    }
    let components = value.split('/').collect::<Vec<_>>();
    if components.len() < 2 {
        return false;
    }
    if require_json {
        components.iter().all(|component| {
            component
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && component
                    .bytes()
                    .skip(1)
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        }) && path.extension().and_then(|extension| extension.to_str()) == Some("json")
    } else {
        components.iter().all(|component| {
            component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    }
}

fn is_trace_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("TRACE-") else {
        return false;
    };
    (3..=128).contains(&suffix.len())
        && suffix.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn strictly_sorted<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let Some(mut previous) = values.next() else {
        return true;
    };
    for current in values {
        if previous >= current {
            return false;
        }
        previous = current;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance_applicability::{
        ApplicabilityDimension, ApplicabilityDimensionValue,
        recompute_applicability_inventory_binding,
    };

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn control_trace_ref() -> VersionedContentReference {
        VersionedContentReference {
            artifact_kind: ArtifactKind::ControlTrace,
            document_id: "control-trace:fixture".into(),
            document_version: 1,
            content_digest: digest('d'),
            artifact_locator: "catalog/security/control-trace.json".into(),
        }
    }

    fn trace_binding(reference: &VersionedContentReference) -> ApplicabilityControlTraceBinding {
        ApplicabilityControlTraceBinding {
            document_id: reference.document_id.clone(),
            document_version: reference.document_version,
            content_digest: reference.content_digest.clone(),
        }
    }

    fn applicability_instance(
        reference: &VersionedContentReference,
        trace_id: &str,
        subject: ApplicabilitySubject,
        probe_id: &str,
    ) -> ApplicabilityInstance {
        let binding = trace_binding(reference);
        let mut instance = ApplicabilityInstance {
            applicability_instance_id: format!("applicability:sha256:{}", "0".repeat(64)),
            trace_id: trace_id.into(),
            owning_work_package: "SB-0".into(),
            scope: ApplicabilityScope::Implementation,
            subject,
            dimensions: vec![ApplicabilityDimension {
                name: "implementation.fixture_or_probe_id".into(),
                value: ApplicabilityDimensionValue::String(probe_id.into()),
            }],
        };
        instance.applicability_instance_id =
            recompute_applicability_instance_id(&binding, &instance).unwrap();
        instance
    }

    fn rebind_applicability(manifest: &mut ProductionBuildManifest) {
        manifest
            .implementation_applicability_instances
            .sort_by(compare_applicability_instances);
        manifest.implementation_applicability = recompute_applicability_inventory_binding(
            &trace_binding(&manifest.control_trace_ref),
            &manifest.implementation_applicability_instances,
        )
        .unwrap();
    }

    fn valid_manifest() -> ProductionBuildManifest {
        let control_trace_ref = control_trace_ref();
        let mut implementation_applicability_instances = vec![
            applicability_instance(
                &control_trace_ref,
                "TRACE-SB-CONF-03-AC-048",
                ApplicabilitySubject::AdapterCapability {
                    adapter_kind: "auth.entra-id".into(),
                    adapter_version: "0.1.0".into(),
                    capability_id: "authenticate".into(),
                },
                "security_conformance::adapter_ac_048",
            ),
            applicability_instance(
                &control_trace_ref,
                "TRACE-SB-CONF-04-AC-048",
                ApplicabilitySubject::Component {
                    component_id: PRODUCTION_BUILD_COMPONENT_ID.into(),
                    component_version: "0.1.0".into(),
                },
                "security_conformance::component_ac_048",
            ),
        ];
        implementation_applicability_instances.sort_by(compare_applicability_instances);
        let implementation_applicability = recompute_applicability_inventory_binding(
            &trace_binding(&control_trace_ref),
            &implementation_applicability_instances,
        )
        .unwrap();

        ProductionBuildManifest {
            schema_uri: PRODUCTION_BUILD_MANIFEST_SCHEMA_URI.into(),
            schema_version: PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION.into(),
            contract_kind: PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND.into(),
            document_id: "production-build-manifest:fixture".into(),
            document_version: 1,
            component: BuildComponent {
                component_id: PRODUCTION_BUILD_COMPONENT_ID.into(),
                component_version: "0.1.0".into(),
                executable_name: PRODUCTION_BUILD_EXECUTABLE_NAME.into(),
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
                repository: "ghcr.io/example/ryuki-platform-api".into(),
                content_digest: digest('c'),
            },
            control_trace_ref,
            shipped_adapters: vec![ShippedAdapter {
                adapter_kind: "auth.entra-id".into(),
                adapter_version: "0.1.0".into(),
                production_eligible: false,
                capability_ids: vec!["authenticate".into()],
                mandatory_baseline: MandatoryCapabilityBaseline {
                    document_id: "baseline:fixture".into(),
                    document_version: 1,
                    content_digest: digest('e'),
                    artifact_locator: "docs/architecture/baseline.md".into(),
                    required_trace_ids: vec!["TRACE-SB-CONF-03-AC-048".into()],
                },
            }],
            selector_dispositions: vec![BuildSelectorDisposition {
                selector_domain: SelectorDomain::AuthMode,
                selector: "entra-id".into(),
                disposition: SelectorDisposition::Implemented,
                adapter_kind: Some("auth.entra-id".into()),
            }],
            implementation_applicability,
            implementation_applicability_instances,
        }
    }

    #[test]
    fn complete_manifest_is_semantically_valid() {
        assert!(valid_manifest().validate_semantics().is_empty());
    }

    #[test]
    fn production_eligibility_is_a_measured_adapter_fact() {
        let mut manifest = valid_manifest();
        manifest.shipped_adapters[0].production_eligible = true;
        assert!(manifest.validate_semantics().is_empty());
    }

    #[test]
    fn source_algorithm_and_nonzero_digests_are_enforced() {
        let mut manifest = valid_manifest();
        manifest.source.revision = "a".repeat(64);
        manifest.runtime_executable.content_digest = digest('0');
        let errors = manifest.validate_semantics().join("; ");
        assert!(errors.contains("revision_algorithm"));
        assert!(errors.contains("nonzero"));
    }

    #[test]
    fn adapter_and_selector_inventories_cannot_self_shrink() {
        let mut manifest = valid_manifest();
        manifest.selector_dispositions.clear();
        manifest
            .implementation_applicability_instances
            .retain(|instance| matches!(&instance.subject, ApplicabilitySubject::Component { .. }));
        let errors = manifest.validate_semantics().join("; ");
        assert!(errors.contains("selector_dispositions"));
        assert!(errors.contains("no implemented selector"));
        assert!(errors.contains("omit shipped adapter capability"));
    }

    #[test]
    fn applicability_rows_are_canonical_recomputed_and_unique() {
        let mut manifest = valid_manifest();
        manifest.implementation_applicability_instances.swap(0, 1);
        let errors = manifest.validate_semantics().join("; ");
        assert!(errors.contains("strict canonical order"));

        let mut manifest = valid_manifest();
        manifest.implementation_applicability_instances[1].applicability_instance_id = manifest
            .implementation_applicability_instances[0]
            .applicability_instance_id
            .clone();
        assert!(
            manifest
                .validate_semantics()
                .join("; ")
                .contains("duplicate applicability_instance_id")
        );
    }

    #[test]
    fn repeated_trace_and_subject_are_allowed_for_distinct_dimensions() {
        let mut manifest = valid_manifest();
        let mut repeated = manifest
            .implementation_applicability_instances
            .iter()
            .find(|instance| matches!(&instance.subject, ApplicabilitySubject::Component { .. }))
            .unwrap()
            .clone();
        repeated.dimensions[0].value =
            ApplicabilityDimensionValue::String("security_conformance::second_probe".into());
        repeated.applicability_instance_id = recompute_applicability_instance_id(
            &trace_binding(&manifest.control_trace_ref),
            &repeated,
        )
        .unwrap();
        manifest
            .implementation_applicability_instances
            .push(repeated);
        rebind_applicability(&mut manifest);

        assert!(manifest.validate_semantics().is_empty());
    }

    #[test]
    fn inventory_binding_and_subject_authority_are_exact() {
        let mut manifest = valid_manifest();
        manifest.implementation_applicability.instance_count += 1;
        assert!(
            manifest
                .validate_semantics()
                .join("; ")
                .contains("binding does not exactly match")
        );

        let mut manifest = valid_manifest();
        let binding = trace_binding(&manifest.control_trace_ref);
        let row = manifest
            .implementation_applicability_instances
            .iter_mut()
            .find(|instance| {
                matches!(
                    &instance.subject,
                    ApplicabilitySubject::AdapterCapability { .. }
                )
            })
            .unwrap();
        if let ApplicabilitySubject::AdapterCapability {
            adapter_version, ..
        } = &mut row.subject
        {
            *adapter_version = "9.9.9".into();
        }
        row.applicability_instance_id = recompute_applicability_instance_id(&binding, row).unwrap();
        rebind_applicability(&mut manifest);
        assert!(
            manifest
                .validate_semantics()
                .join("; ")
                .contains("version does not match")
        );
    }

    #[test]
    fn deployment_scope_and_subjects_are_rejected() {
        let mut manifest = valid_manifest();
        manifest.implementation_applicability_instances[0].scope = ApplicabilityScope::Deployment;
        let errors = manifest.validate_semantics().join("; ");
        assert!(errors.contains("must use implementation scope"));
    }

    #[test]
    fn unknown_fields_are_rejected_by_typed_deserialization() {
        let mut value = serde_json::to_value(valid_manifest()).unwrap();
        value["component"]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ProductionBuildManifest>(value).is_err());
    }
}
