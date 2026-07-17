//! Independent derivation of production deployment applicability.
//!
//! The public input records in this module are typed claims. Constructing them
//! grants no production authority. A caller must first bind each claim to the
//! exact authenticated build, deployment-profile, provider-registry,
//! security-limit, ControlTrace, and checkpoint artifacts. This module then
//! derives a closed applicability inventory; it does not authenticate those
//! artifacts or authorize startup.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use thiserror::Error;

use crate::conformance_applicability::{
    ApplicabilityControlTraceBinding, ApplicabilityDimension, ApplicabilityDimensionValue,
    ApplicabilityInstance, ApplicabilityInventoryBinding, ApplicabilityScalar, ApplicabilityScope,
    ApplicabilitySubject, ApplicabilityValidationError, MAX_APPLICABILITY_INVENTORY_INSTANCES,
    compare_applicability_instances, recompute_applicability_instance_id,
    recompute_applicability_inventory_binding,
};
use crate::production_applicability::{
    ProductionApplicabilityError, derive_implementation_applicability,
};
use crate::production_build::{
    MandatoryCapabilityBaseline, OciSubjectKind, ProductionBuildManifest, ShippedAdapter,
};
use crate::security_profile::{
    ArtifactKind, DeploymentSecurityProfile, DocumentLifecycleState, ProviderLifecycleState,
    SecurityProfile, TenancyMode, VersionedContentReference,
};

const MAX_CONTROL_TRACES: usize = 4096;
const MAX_TRUST_DOMAINS: usize = 32;
const MAX_ACTIVE_PROVIDERS: usize = 256;
const MAX_CAPABILITIES_PER_PROVIDER: usize = 256;
const MAX_EXPRESSION_DEPTH: usize = 32;
const MAX_EXPRESSION_NODES: usize = 4096;
const MAX_EXPRESSION_OPERANDS: usize = 64;
const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Independently retained checkpoint facts for one exact trust domain.
///
/// This is a claim record, not a verification capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentCheckpointApplicabilityClaim {
    pub trust_domain_id: String,
    pub authority_id: String,
    pub authority_epoch: u64,
    pub sequence: u64,
    pub trust_registry_digest: String,
    pub trust_registry_locator: String,
}

/// Exact reference fields from a provider capability descriptor.
///
/// The build-owned trace list deliberately is not present here. Deployment
/// baseline ownership remains in [`MandatoryCapabilityBaseline`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMandatoryBaselineClaim {
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
}

/// Typed projection of one provider configuration selected as active.
///
/// Values remain untrusted claims until an authenticated provider-registry
/// loader constructs and binds the surrounding registry projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProviderApplicabilityClaim {
    pub provider_id: String,
    pub provider_kind: String,
    pub configuration_version: u64,
    pub configuration_payload_digest: String,
    pub lifecycle_record_version: u64,
    pub lifecycle_state: ProviderLifecycleState,
    pub trust_domain_id: String,
    pub descriptor_id: String,
    pub descriptor_version: u64,
    pub adapter_kind: String,
    pub adapter_version: String,
    pub advertised_capability_ids: Vec<String>,
    pub production_eligible: bool,
    pub mandatory_baseline_ref: ProviderMandatoryBaselineClaim,
}

/// Typed active-provider projection for one exact provider-registry artifact.
///
/// This record grants no authority merely because it is constructible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProviderRegistryApplicabilityClaim {
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
    pub registry_version: u64,
    pub active_providers: Vec<ActiveProviderApplicabilityClaim>,
}

/// Typed version projection for the exact selected security-limit artifact.
///
/// This record grants no authority merely because it is constructible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityLimitApplicabilityClaim {
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
    pub profile_version: u64,
}

/// Exact deployed OCI subject tuple reported by an independently verified
/// workload/deployment proof.
///
/// This constructible record is not that proof. The API admission layer must
/// create it only after reconciling a workload identity with the manifest's
/// exact OCI subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployedArtifactApplicabilityClaim {
    pub subject_kind: OciSubjectKind,
    pub repository: String,
    pub subject_digest: String,
}

/// Complete independent claims needed to derive deployment applicability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionDeploymentApplicabilityClaims {
    pub checkpoints: Vec<DeploymentCheckpointApplicabilityClaim>,
    pub provider_registry: ActiveProviderRegistryApplicabilityClaim,
    pub security_limit_profile: SecurityLimitApplicabilityClaim,
    pub deployed_artifact: DeployedArtifactApplicabilityClaim,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedDeploymentApplicability {
    pub binding: ApplicabilityInventoryBinding,
    pub instances: Vec<ApplicabilityInstance>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedProductionApplicability {
    pub binding: ApplicabilityInventoryBinding,
    pub instances: Vec<ApplicabilityInstance>,
}

#[derive(Debug, Error)]
pub enum ProductionDeploymentApplicabilityError {
    #[error("invalid production deployment applicability input: {0}")]
    Invalid(String),
    #[error(transparent)]
    Applicability(#[from] ApplicabilityValidationError),
    #[error(transparent)]
    Implementation(#[from] ProductionApplicabilityError),
}

/// Derive the exact deployment-owned inventory from independently bound facts.
///
/// Every active trace with a non-null deployment evidence tier is evaluated
/// once per profile trust domain using a deployment subject. Each active
/// provider capability is additionally evaluated against the shipped
/// adapter's build-owned mandatory baseline. A baseline trace that is absent,
/// inactive, deployment-null, or inapplicable fails closed.
pub fn derive_production_deployment_applicability(
    control_trace: &Value,
    manifest: &ProductionBuildManifest,
    profile: &DeploymentSecurityProfile,
    claims: &ProductionDeploymentApplicabilityClaims,
) -> Result<DerivedDeploymentApplicability, ProductionDeploymentApplicabilityError> {
    validate_roots(control_trace, manifest, profile, claims)?;
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

    let trust_domains = exact_trust_domains(profile)?;
    let checkpoints = validate_checkpoints(profile, claims, &trust_domains)?;
    let shipped = validate_provider_inventory(manifest, profile, claims, &trust_domains)?;
    let trace_binding = ApplicabilityControlTraceBinding {
        document_id: manifest.control_trace_ref.document_id.clone(),
        document_version: manifest.control_trace_ref.document_version,
        content_digest: manifest.control_trace_ref.content_digest.clone(),
    };
    let mut instances = Vec::new();

    for trace in traces {
        if !trace_is_active(trace)? || !deployment_scope_exists(trace)? {
            continue;
        }
        if trace_requires_provider_capability_subject(trace)? {
            continue;
        }
        for trust_domain_id in &trust_domains {
            let checkpoint = checkpoints
                .get(trust_domain_id.as_str())
                .expect("checkpoint equality was validated");
            let subject = ApplicabilitySubject::Deployment {
                deployment_id: profile.deployment_id.clone(),
                deployment_profile_id: profile.document_id.clone(),
                trust_domain_id: trust_domain_id.clone(),
                tenancy_mode: tenancy_mode(profile.tenancy_mode).into(),
            };
            if let Some(instance) = derive_instance(
                &trace_binding,
                trace,
                manifest,
                profile,
                claims,
                checkpoint,
                None,
                None,
                subject,
            )? {
                push_bounded_instance(&mut instances, instance)?;
            }
        }
    }

    for provider in &claims.provider_registry.active_providers {
        let adapter = shipped
            .get(provider.adapter_kind.as_str())
            .expect("provider-to-build equality was validated");
        let checkpoint = checkpoints
            .get(provider.trust_domain_id.as_str())
            .expect("provider trust-domain membership was validated");
        for capability_id in &provider.advertised_capability_ids {
            for trace_id in &adapter.mandatory_baseline.required_trace_ids {
                let trace = trace_by_id.get(trace_id.as_str()).ok_or_else(|| {
                    invalid(format!(
                        "adapter {} deployment baseline references unknown trace {trace_id}",
                        adapter.adapter_kind
                    ))
                })?;
                if !trace_is_active(trace)? {
                    return Err(invalid(format!(
                        "adapter {} deployment baseline trace {trace_id} is not active",
                        adapter.adapter_kind
                    )));
                }
                if !deployment_scope_exists(trace)? {
                    return Err(invalid(format!(
                        "adapter {} deployment baseline trace {trace_id} has no deployment evidence tier",
                        adapter.adapter_kind
                    )));
                }
                let subject = provider_subject(profile, provider, capability_id);
                let Some(instance) = derive_instance(
                    &trace_binding,
                    trace,
                    manifest,
                    profile,
                    claims,
                    checkpoint,
                    Some(provider),
                    Some(capability_id),
                    subject,
                )?
                else {
                    return Err(invalid(format!(
                        "adapter {} capability {capability_id} deployment baseline trace {trace_id} is not applicable",
                        adapter.adapter_kind
                    )));
                };
                push_bounded_instance(&mut instances, instance)?;
            }
        }
    }

    if instances.is_empty() {
        return Err(invalid("derived deployment applicability is empty"));
    }
    instances.sort_by(compare_applicability_instances);
    let binding = recompute_applicability_inventory_binding(&trace_binding, &instances)?;
    Ok(DerivedDeploymentApplicability { binding, instances })
}

/// Require a supplied deployment inventory to equal independent derivation.
pub fn validate_exact_production_deployment_applicability(
    control_trace: &Value,
    manifest: &ProductionBuildManifest,
    profile: &DeploymentSecurityProfile,
    claims: &ProductionDeploymentApplicabilityClaims,
    claimed_binding: &ApplicabilityInventoryBinding,
    claimed_instances: &[ApplicabilityInstance],
) -> Result<(), ProductionDeploymentApplicabilityError> {
    let expected =
        derive_production_deployment_applicability(control_trace, manifest, profile, claims)?;
    if claimed_binding != &expected.binding || claimed_instances != expected.instances {
        let expected_ids = expected
            .instances
            .iter()
            .map(|instance| instance.applicability_instance_id.as_str())
            .collect::<BTreeSet<_>>();
        let claimed_ids = claimed_instances
            .iter()
            .map(|instance| instance.applicability_instance_id.as_str())
            .collect::<BTreeSet<_>>();
        return Err(invalid(format!(
            "claimed deployment applicability is not exact ({} expected rows, {} claimed rows, {} missing ids, {} extra ids)",
            expected.instances.len(),
            claimed_instances.len(),
            expected_ids.difference(&claimed_ids).count(),
            claimed_ids.difference(&expected_ids).count(),
        )));
    }
    Ok(())
}

/// Derive one exact implementation-plus-deployment production universe.
///
/// The resulting binding is the only inventory suitable for package receipt
/// partitioning. Receipt-authored rows never participate in this derivation.
pub fn derive_complete_production_applicability(
    control_trace: &Value,
    manifest: &ProductionBuildManifest,
    profile: &DeploymentSecurityProfile,
    claims: &ProductionDeploymentApplicabilityClaims,
) -> Result<DerivedProductionApplicability, ProductionDeploymentApplicabilityError> {
    let implementation = derive_implementation_applicability(control_trace, manifest)?;
    let deployment =
        derive_production_deployment_applicability(control_trace, manifest, profile, claims)?;
    let total = implementation
        .instances
        .len()
        .checked_add(deployment.instances.len())
        .ok_or_else(|| invalid("complete production applicability count overflowed usize"))?;
    if total > MAX_APPLICABILITY_INVENTORY_INSTANCES {
        return Err(invalid(format!(
            "complete production applicability contains {total} rows, exceeding the {MAX_APPLICABILITY_INVENTORY_INSTANCES}-row limit"
        )));
    }
    let mut instances = implementation.instances;
    instances.extend(deployment.instances);
    instances.sort_by(compare_applicability_instances);
    let trace_binding = ApplicabilityControlTraceBinding {
        document_id: manifest.control_trace_ref.document_id.clone(),
        document_version: manifest.control_trace_ref.document_version,
        content_digest: manifest.control_trace_ref.content_digest.clone(),
    };
    let binding = recompute_applicability_inventory_binding(&trace_binding, &instances)?;
    Ok(DerivedProductionApplicability { binding, instances })
}

fn validate_roots(
    control_trace: &Value,
    manifest: &ProductionBuildManifest,
    profile: &DeploymentSecurityProfile,
    claims: &ProductionDeploymentApplicabilityClaims,
) -> Result<(), ProductionDeploymentApplicabilityError> {
    if required_str(control_trace, "contract_kind", "ControlTrace")? != "control-trace" {
        return Err(invalid(
            "ControlTrace contract_kind must equal control-trace",
        ));
    }
    let trace_id = required_str(control_trace, "document_id", "ControlTrace")?;
    let trace_version = positive_u64(control_trace, "document_version", "ControlTrace")?;
    if trace_id != manifest.control_trace_ref.document_id
        || trace_version != manifest.control_trace_ref.document_version
    {
        return Err(invalid(
            "ControlTrace identity does not match the production build manifest reference",
        ));
    }
    if !same_reference(&profile.control_trace_ref, &manifest.control_trace_ref)
        || profile.control_trace_ref.artifact_kind != ArtifactKind::ControlTrace
    {
        return Err(invalid(
            "deployment profile and build manifest must bind the same exact ControlTrace reference",
        ));
    }
    if profile.security_profile != SecurityProfile::Production
        || profile.lifecycle.state != DocumentLifecycleState::Active
    {
        return Err(invalid(
            "deployment applicability requires an active production deployment profile",
        ));
    }
    if profile.applicability.security_profiles.as_slice() != [SecurityProfile::Production]
        || profile.applicability.deployment_ids.len() != 1
        || profile.applicability.deployment_ids[0] != profile.deployment_id
    {
        return Err(invalid(
            "deployment profile applicability must exactly select its production deployment",
        ));
    }
    validate_exact_reference_claim(
        "provider registry",
        &profile.provider_registry_ref,
        ArtifactKind::ProviderRegistry,
        &claims.provider_registry.document_id,
        claims.provider_registry.document_version,
        &claims.provider_registry.content_digest,
        &claims.provider_registry.artifact_locator,
    )?;
    positive_exact(
        "provider registry registry_version",
        claims.provider_registry.registry_version,
    )?;
    validate_exact_reference_claim(
        "security limit profile",
        &profile.security_limit_profile_ref,
        ArtifactKind::SecurityLimitProfile,
        &claims.security_limit_profile.document_id,
        claims.security_limit_profile.document_version,
        &claims.security_limit_profile.content_digest,
        &claims.security_limit_profile.artifact_locator,
    )?;
    positive_exact(
        "security limit profile profile_version",
        claims.security_limit_profile.profile_version,
    )?;
    if claims.deployed_artifact.subject_kind != manifest.oci_subject.subject_kind
        || claims.deployed_artifact.repository != manifest.oci_subject.repository
        || claims.deployed_artifact.subject_digest != manifest.oci_subject.content_digest
    {
        return Err(invalid(
            "verified deployed OCI subject tuple does not match the production build manifest",
        ));
    }
    validate_nonzero_digest(
        "verified deployed OCI subject digest",
        &claims.deployed_artifact.subject_digest,
    )?;
    for (label, value) in [
        (
            "deployment profile document_version",
            profile.document_version,
        ),
        (
            "deployment profile deployment_profile_version",
            profile.deployment_profile_version,
        ),
        ("deployment profile policy_version", profile.policy_version),
        (
            "deployment profile platform_configuration_version",
            profile.platform_configuration_version,
        ),
    ] {
        positive_exact(label, value)?;
    }
    Ok(())
}

fn exact_trust_domains(
    profile: &DeploymentSecurityProfile,
) -> Result<Vec<String>, ProductionDeploymentApplicabilityError> {
    let domains = &profile.trust_topology.trust_domain_ids;
    if domains.is_empty() || domains.len() > MAX_TRUST_DOMAINS {
        return Err(invalid(format!(
            "profile must select between 1 and {MAX_TRUST_DOMAINS} trust domains"
        )));
    }
    let unique = domains.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() != domains.len() {
        return Err(invalid(
            "profile trust-domain inventory contains duplicates",
        ));
    }
    Ok(unique.into_iter().collect())
}

fn validate_checkpoints<'a>(
    profile: &DeploymentSecurityProfile,
    claims: &'a ProductionDeploymentApplicabilityClaims,
    trust_domains: &[String],
) -> Result<
    BTreeMap<&'a str, &'a DeploymentCheckpointApplicabilityClaim>,
    ProductionDeploymentApplicabilityError,
> {
    if claims.checkpoints.len() != trust_domains.len() {
        return Err(invalid(
            "checkpoint claim inventory must exactly cover profile trust domains",
        ));
    }
    let expected = trust_domains
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeMap::new();
    let mut previous = None;
    for checkpoint in &claims.checkpoints {
        if previous.is_some_and(|value| value >= checkpoint.trust_domain_id.as_str()) {
            return Err(invalid(
                "checkpoint claims must be strictly sorted by trust_domain_id",
            ));
        }
        previous = Some(checkpoint.trust_domain_id.as_str());
        if actual
            .insert(checkpoint.trust_domain_id.as_str(), checkpoint)
            .is_some()
        {
            return Err(invalid("checkpoint claim inventory contains duplicates"));
        }
        positive_exact("checkpoint authority_epoch", checkpoint.authority_epoch)?;
        positive_exact("checkpoint sequence", checkpoint.sequence)?;
        if checkpoint.authority_id.trim() != checkpoint.authority_id
            || checkpoint.authority_id.is_empty()
            || checkpoint.authority_id.len() > 160
        {
            return Err(invalid("checkpoint authority_id is not canonical"));
        }
        if checkpoint.trust_registry_digest
            != profile.conformance_trust_root_registry_ref.content_digest
            || checkpoint.trust_registry_locator
                != profile.conformance_trust_root_registry_ref.artifact_locator
        {
            return Err(invalid(
                "checkpoint trust-registry binding does not match the selected profile reference",
            ));
        }
    }
    if actual.keys().copied().collect::<BTreeSet<_>>() != expected {
        return Err(invalid(
            "checkpoint claim inventory has missing or extra trust domains",
        ));
    }
    Ok(actual)
}

fn validate_provider_inventory<'a>(
    manifest: &'a ProductionBuildManifest,
    _profile: &DeploymentSecurityProfile,
    claims: &ProductionDeploymentApplicabilityClaims,
    trust_domains: &[String],
) -> Result<BTreeMap<&'a str, &'a ShippedAdapter>, ProductionDeploymentApplicabilityError> {
    if claims.provider_registry.active_providers.is_empty()
        || claims.provider_registry.active_providers.len() > MAX_ACTIVE_PROVIDERS
    {
        return Err(invalid(format!(
            "active provider inventory must contain between 1 and {MAX_ACTIVE_PROVIDERS} entries"
        )));
    }
    let shipped = manifest
        .shipped_adapters
        .iter()
        .map(|adapter| (adapter.adapter_kind.as_str(), adapter))
        .collect::<BTreeMap<_, _>>();
    if shipped.len() != manifest.shipped_adapters.len() {
        return Err(invalid("build manifest repeats a shipped adapter kind"));
    }
    let trust_domains = trust_domains
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut previous_provider = None;
    for provider in &claims.provider_registry.active_providers {
        if previous_provider.is_some_and(|value| value >= provider.provider_id.as_str()) {
            return Err(invalid(
                "active providers must be strictly sorted by provider_id",
            ));
        }
        previous_provider = Some(provider.provider_id.as_str());
        if provider.lifecycle_state != ProviderLifecycleState::Active {
            return Err(invalid(format!(
                "provider {} is not active",
                provider.provider_id
            )));
        }
        if !trust_domains.contains(provider.trust_domain_id.as_str()) {
            return Err(invalid(format!(
                "provider {} selects a trust domain outside the deployment profile",
                provider.provider_id
            )));
        }
        positive_exact(
            "provider configuration_version",
            provider.configuration_version,
        )?;
        positive_exact(
            "provider lifecycle_record_version",
            provider.lifecycle_record_version,
        )?;
        if provider.provider_kind.trim() != provider.provider_kind
            || provider.provider_kind.is_empty()
            || provider.provider_kind.len() > 96
        {
            return Err(invalid(format!(
                "provider {} has a noncanonical provider kind",
                provider.provider_id
            )));
        }
        validate_nonzero_digest(
            "provider configuration payload digest",
            &provider.configuration_payload_digest,
        )?;
        positive_exact("provider descriptor_version", provider.descriptor_version)?;
        let adapter = shipped.get(provider.adapter_kind.as_str()).ok_or_else(|| {
            invalid(format!(
                "active provider {} references unshipped adapter {}",
                provider.provider_id, provider.adapter_kind
            ))
        })?;
        if !adapter.production_eligible || !provider.production_eligible {
            return Err(invalid(format!(
                "active provider {} and shipped adapter {} must both be production eligible",
                provider.provider_id, provider.adapter_kind
            )));
        }
        if provider.adapter_version != adapter.adapter_version {
            return Err(invalid(format!(
                "active provider {} adapter version does not match the shipped build",
                provider.provider_id
            )));
        }
        if provider.advertised_capability_ids.is_empty()
            || provider.advertised_capability_ids.len() > MAX_CAPABILITIES_PER_PROVIDER
            || !strictly_sorted(
                provider
                    .advertised_capability_ids
                    .iter()
                    .map(String::as_str),
            )
            || provider.advertised_capability_ids != adapter.capability_ids
        {
            return Err(invalid(format!(
                "active provider {} capability inventory must exactly equal the shipped adapter inventory",
                provider.provider_id
            )));
        }
        if adapter.mandatory_baseline.required_trace_ids.is_empty()
            || adapter.mandatory_baseline.required_trace_ids.len() > MAX_CONTROL_TRACES
            || !strictly_sorted(
                adapter
                    .mandatory_baseline
                    .required_trace_ids
                    .iter()
                    .map(String::as_str),
            )
        {
            return Err(invalid(format!(
                "shipped adapter {} build-owned baseline traces must be nonempty, unique, sorted, and bounded",
                adapter.adapter_kind
            )));
        }
        if !same_baseline_ref(
            &provider.mandatory_baseline_ref,
            &adapter.mandatory_baseline,
        ) {
            return Err(invalid(format!(
                "active provider {} mandatory baseline reference does not match the build-owned baseline",
                provider.provider_id
            )));
        }
    }
    Ok(shipped)
}

fn push_bounded_instance(
    instances: &mut Vec<ApplicabilityInstance>,
    instance: ApplicabilityInstance,
) -> Result<(), ProductionDeploymentApplicabilityError> {
    if instances.len() == MAX_APPLICABILITY_INVENTORY_INSTANCES {
        return Err(invalid(format!(
            "derived deployment applicability exceeds the {MAX_APPLICABILITY_INVENTORY_INSTANCES}-row limit"
        )));
    }
    instances.push(instance);
    Ok(())
}

fn trace_requires_provider_capability_subject(
    trace: &Value,
) -> Result<bool, ProductionDeploymentApplicabilityError> {
    let trace_id = required_str(trace, "trace_id", "ControlTrace row")?;
    let dimensions = trace
        .pointer("/evidence_instance_dimensions/deployment")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid(format!(
                "ControlTrace row {trace_id} omits deployment dimensions"
            ))
        })?;
    for dimension in dimensions {
        let name = dimension.as_str().ok_or_else(|| {
            invalid(format!(
                "ControlTrace row {trace_id} has a non-string dimension"
            ))
        })?;
        if is_provider_capability_dimension(name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_provider_capability_dimension(name: &str) -> bool {
    matches!(
        name,
        "deployment.provider_id"
            | "deployment.provider_kind"
            | "deployment.provider_configuration_digest"
            | "deployment.provider_configuration_version"
            | "deployment.provider_descriptor_id"
            | "deployment.provider_descriptor_version"
            | "deployment.adapter_kind"
            | "deployment.adapter_version"
            | "deployment.capability_id"
            | "deployment.provider_production_eligible"
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_instance(
    trace_binding: &ApplicabilityControlTraceBinding,
    trace: &Value,
    manifest: &ProductionBuildManifest,
    profile: &DeploymentSecurityProfile,
    claims: &ProductionDeploymentApplicabilityClaims,
    checkpoint: &DeploymentCheckpointApplicabilityClaim,
    provider: Option<&ActiveProviderApplicabilityClaim>,
    capability_id: Option<&str>,
    subject: ApplicabilitySubject,
) -> Result<Option<ApplicabilityInstance>, ProductionDeploymentApplicabilityError> {
    let trace_id = required_str(trace, "trace_id", "ControlTrace row")?;
    let owning_work_package = required_str(trace, "owning_work_package", "ControlTrace row")?;
    let dimensions = derive_dimensions(
        trace,
        manifest,
        profile,
        claims,
        checkpoint,
        provider,
        capability_id,
    )?;
    let dimension_map = dimensions
        .iter()
        .map(|dimension| {
            (
                dimension.name.clone(),
                serde_json::to_value(&dimension.value)
                    .expect("applicability dimension serialization is infallible"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expression = trace
        .pointer("/applicability_expression/deployment")
        .ok_or_else(|| {
            invalid(format!(
                "ControlTrace row {trace_id} omits deployment expression"
            ))
        })?;
    let mut nodes = 0;
    if !evaluate_expression(expression, &dimension_map, 0, &mut nodes)? {
        return Ok(None);
    }
    let mut instance = ApplicabilityInstance {
        applicability_instance_id: String::new(),
        trace_id: trace_id.into(),
        owning_work_package: owning_work_package.into(),
        scope: ApplicabilityScope::Deployment,
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
    profile: &DeploymentSecurityProfile,
    claims: &ProductionDeploymentApplicabilityClaims,
    checkpoint: &DeploymentCheckpointApplicabilityClaim,
    provider: Option<&ActiveProviderApplicabilityClaim>,
    capability_id: Option<&str>,
) -> Result<Vec<ApplicabilityDimension>, ProductionDeploymentApplicabilityError> {
    let trace_id = required_str(trace, "trace_id", "ControlTrace row")?;
    let declared = trace
        .pointer("/evidence_instance_dimensions/deployment")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid(format!(
                "ControlTrace row {trace_id} omits deployment dimensions"
            ))
        })?;
    let mut names = BTreeSet::new();
    for item in declared {
        let name = item.as_str().ok_or_else(|| {
            invalid(format!(
                "ControlTrace row {trace_id} has a non-string dimension"
            ))
        })?;
        if !names.insert(name) {
            return Err(invalid(format!(
                "ControlTrace row {trace_id} repeats deployment dimension {name}"
            )));
        }
    }
    names
        .into_iter()
        .map(|name| {
            Ok(ApplicabilityDimension {
                name: name.into(),
                value: authoritative_dimension(
                    name,
                    manifest,
                    profile,
                    claims,
                    checkpoint,
                    provider,
                    capability_id,
                )?,
            })
        })
        .collect()
}

fn authoritative_dimension(
    name: &str,
    _manifest: &ProductionBuildManifest,
    profile: &DeploymentSecurityProfile,
    claims: &ProductionDeploymentApplicabilityClaims,
    checkpoint: &DeploymentCheckpointApplicabilityClaim,
    provider: Option<&ActiveProviderApplicabilityClaim>,
    capability_id: Option<&str>,
) -> Result<ApplicabilityDimensionValue, ProductionDeploymentApplicabilityError> {
    let string = |value: &str| ApplicabilityDimensionValue::String(value.into());
    let integer = |label: &str, value: u64| {
        exact_integer(label, value).map(ApplicabilityDimensionValue::Integer)
    };
    match name {
        "deployment.subject_kind" => Ok(string(if provider.is_some() {
            "provider_capability"
        } else {
            "deployment"
        })),
        "deployment.deployment_id" => Ok(string(&profile.deployment_id)),
        "deployment.deployment_profile_id" => Ok(string(&profile.document_id)),
        "deployment.deployment_profile_version" => {
            integer(name, profile.deployment_profile_version)
        }
        "deployment.security_profile" => Ok(string(profile.security_profile.as_str())),
        "deployment.trust_domain_id" => Ok(string(&checkpoint.trust_domain_id)),
        "deployment.tenancy_mode" => Ok(string(tenancy_mode(profile.tenancy_mode))),
        "deployment.provider_registry_version" => {
            integer(name, claims.provider_registry.registry_version)
        }
        "deployment.provider_registry_digest" => {
            Ok(string(&claims.provider_registry.content_digest))
        }
        "deployment.provider_registry_locator" => {
            Ok(string(&claims.provider_registry.artifact_locator))
        }
        "deployment.policy_version" => integer(name, profile.policy_version),
        "deployment.configuration_version" => integer(name, profile.platform_configuration_version),
        "deployment.security_limit_profile_version" => {
            integer(name, claims.security_limit_profile.profile_version)
        }
        "deployment.security_limit_profile_digest" => {
            Ok(string(&claims.security_limit_profile.content_digest))
        }
        "deployment.security_limit_profile_locator" => {
            Ok(string(&claims.security_limit_profile.artifact_locator))
        }
        "deployment.artifact_digest" => Ok(string(&claims.deployed_artifact.subject_digest)),
        "deployment.oci_subject_digest" => Ok(string(&claims.deployed_artifact.subject_digest)),
        "deployment.conformance_trust_checkpoint_authority_id" => {
            Ok(string(&checkpoint.authority_id))
        }
        "deployment.conformance_trust_checkpoint_authority_epoch" => {
            integer(name, checkpoint.authority_epoch)
        }
        "deployment.conformance_trust_checkpoint_sequence" => integer(name, checkpoint.sequence),
        "deployment.conformance_trust_registry_digest" => {
            Ok(string(&checkpoint.trust_registry_digest))
        }
        "deployment.conformance_trust_registry_locator" => {
            Ok(string(&checkpoint.trust_registry_locator))
        }
        "deployment.enabled_feature_ids" => {
            let values = profile
                .enabled_features
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if values.is_empty() || values.len() != profile.enabled_features.len() {
                return Err(invalid(
                    "deployment.enabled_feature_ids requires a nonempty unique profile feature inventory",
                ));
            }
            Ok(ApplicabilityDimensionValue::Set(
                values
                    .into_iter()
                    .map(ApplicabilityScalar::String)
                    .collect(),
            ))
        }
        "deployment.provider_id" => Ok(string(&required_provider(name, provider)?.provider_id)),
        "deployment.provider_kind" => Ok(string(&required_provider(name, provider)?.provider_kind)),
        "deployment.provider_configuration_digest" => Ok(string(
            &required_provider(name, provider)?.configuration_payload_digest,
        )),
        "deployment.provider_configuration_version" => integer(
            name,
            required_provider(name, provider)?.configuration_version,
        ),
        "deployment.provider_descriptor_id" => {
            Ok(string(&required_provider(name, provider)?.descriptor_id))
        }
        "deployment.provider_descriptor_version" => {
            integer(name, required_provider(name, provider)?.descriptor_version)
        }
        "deployment.adapter_kind" => Ok(string(&required_provider(name, provider)?.adapter_kind)),
        "deployment.adapter_version" => {
            Ok(string(&required_provider(name, provider)?.adapter_version))
        }
        "deployment.capability_id" => capability_id.map(string).ok_or_else(|| {
            invalid("deployment.capability_id requires a provider-capability subject")
        }),
        "deployment.provider_production_eligible" => Ok(ApplicabilityDimensionValue::Boolean(
            required_provider(name, provider)?.production_eligible,
        )),
        _ => Err(invalid(format!(
            "unsupported authoritative deployment dimension {name}"
        ))),
    }
}

fn required_provider<'a>(
    name: &str,
    provider: Option<&'a ActiveProviderApplicabilityClaim>,
) -> Result<&'a ActiveProviderApplicabilityClaim, ProductionDeploymentApplicabilityError> {
    provider.ok_or_else(|| invalid(format!("dimension {name} requires a provider subject")))
}

fn evaluate_expression(
    expression: &Value,
    dimensions: &BTreeMap<String, Value>,
    depth: usize,
    nodes: &mut usize,
) -> Result<bool, ProductionDeploymentApplicabilityError> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(invalid("deployment expression exceeds maximum depth"));
    }
    *nodes += 1;
    if *nodes > MAX_EXPRESSION_NODES {
        return Err(invalid("deployment expression exceeds maximum node count"));
    }
    let operator = required_str(expression, "operator", "deployment expression")?;
    match operator {
        "always" => Ok(true),
        "never" => Ok(false),
        "all" | "any" => {
            let operands = required_array(expression, "operands", "deployment expression")?;
            if operands.is_empty() || operands.len() > MAX_EXPRESSION_OPERANDS {
                return Err(invalid(format!(
                    "{operator} deployment expression must contain 1 through {MAX_EXPRESSION_OPERANDS} operands"
                )));
            }
            let mut results = Vec::with_capacity(operands.len());
            for operand in operands {
                results.push(evaluate_expression(operand, dimensions, depth + 1, nodes)?);
            }
            Ok(if operator == "all" {
                results.into_iter().all(|value| value)
            } else {
                results.into_iter().any(|value| value)
            })
        }
        "not" => Ok(!evaluate_expression(
            expression
                .get("operand")
                .ok_or_else(|| invalid("not deployment expression omits operand"))?,
            dimensions,
            depth + 1,
            nodes,
        )?),
        "equals" | "not_equals" | "contains" => {
            let name = required_str(expression, "dimension", "deployment expression")?;
            let actual = dimensions.get(name).ok_or_else(|| {
                invalid(format!(
                    "deployment expression references undeclared dimension {name}"
                ))
            })?;
            let expected = expression
                .get("value")
                .ok_or_else(|| invalid(format!("{operator} deployment expression omits value")))?;
            match operator {
                "equals" => Ok(actual == expected),
                "not_equals" => Ok(actual != expected),
                "contains" => match (actual, expected) {
                    (Value::Array(values), expected) => Ok(values.contains(expected)),
                    (Value::String(actual), Value::String(expected)) => {
                        Ok(actual.contains(expected))
                    }
                    _ => Err(invalid("contains requires an array or string dimension")),
                },
                _ => unreachable!(),
            }
        }
        "in" | "not_in" => {
            let name = required_str(expression, "dimension", "deployment expression")?;
            let actual = dimensions.get(name).ok_or_else(|| {
                invalid(format!(
                    "deployment expression references undeclared dimension {name}"
                ))
            })?;
            if actual.is_array() {
                return Err(invalid("in/not_in requires a scalar dimension"));
            }
            let values = required_array(expression, "values", "deployment expression")?;
            if values.is_empty() || values.len() > MAX_EXPRESSION_OPERANDS {
                return Err(invalid(format!(
                    "{operator} deployment expression must contain 1 through {MAX_EXPRESSION_OPERANDS} values"
                )));
            }
            let present = values.contains(actual);
            Ok(if operator == "in" { present } else { !present })
        }
        _ => Err(invalid(format!(
            "unsupported deployment expression operator {operator}"
        ))),
    }
}

fn deployment_scope_exists(trace: &Value) -> Result<bool, ProductionDeploymentApplicabilityError> {
    let tier = trace
        .pointer("/minimum_evidence_tier/deployment")
        .ok_or_else(|| invalid("ControlTrace row omits deployment minimum evidence tier"))?;
    Ok(!tier.is_null())
}

fn trace_is_active(trace: &Value) -> Result<bool, ProductionDeploymentApplicabilityError> {
    Ok(required_str(trace, "trace_lifecycle", "ControlTrace row")? == "active")
}

fn provider_subject(
    profile: &DeploymentSecurityProfile,
    provider: &ActiveProviderApplicabilityClaim,
    capability_id: &str,
) -> ApplicabilitySubject {
    ApplicabilitySubject::ProviderCapability {
        deployment_id: profile.deployment_id.clone(),
        provider_id: provider.provider_id.clone(),
        configuration_version: provider.configuration_version,
        descriptor_id: provider.descriptor_id.clone(),
        descriptor_version: provider.descriptor_version,
        adapter_kind: provider.adapter_kind.clone(),
        adapter_version: provider.adapter_version.clone(),
        capability_id: capability_id.into(),
    }
}

fn same_reference(left: &VersionedContentReference, right: &VersionedContentReference) -> bool {
    left.artifact_kind == right.artifact_kind
        && left.document_id == right.document_id
        && left.document_version == right.document_version
        && left.content_digest == right.content_digest
        && left.artifact_locator == right.artifact_locator
}

#[allow(clippy::too_many_arguments)]
fn validate_exact_reference_claim(
    label: &str,
    reference: &VersionedContentReference,
    expected_kind: ArtifactKind,
    document_id: &str,
    document_version: u64,
    content_digest: &str,
    artifact_locator: &str,
) -> Result<(), ProductionDeploymentApplicabilityError> {
    if reference.artifact_kind != expected_kind
        || reference.document_id != document_id
        || reference.document_version != document_version
        || reference.content_digest != content_digest
        || reference.artifact_locator != artifact_locator
    {
        return Err(invalid(format!(
            "{label} claim does not match the exact deployment profile reference"
        )));
    }
    positive_exact(&format!("{label} document_version"), document_version)
}

fn same_baseline_ref(
    provider: &ProviderMandatoryBaselineClaim,
    build: &MandatoryCapabilityBaseline,
) -> bool {
    provider.document_id == build.document_id
        && provider.document_version == build.document_version
        && provider.content_digest == build.content_digest
        && provider.artifact_locator == build.artifact_locator
}

fn tenancy_mode(value: TenancyMode) -> &'static str {
    match value {
        TenancyMode::SingleTenant => "single_tenant",
        TenancyMode::MultiTenant => "multi_tenant",
    }
}

fn positive_u64(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<u64, ProductionDeploymentApplicabilityError> {
    let value = value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("{context} omits positive integer {field}")))?;
    positive_exact(&format!("{context}.{field}"), value)?;
    Ok(value)
}

fn positive_exact(label: &str, value: u64) -> Result<(), ProductionDeploymentApplicabilityError> {
    if value == 0 || value > MAX_EXACT_JSON_INTEGER {
        return Err(invalid(format!(
            "{label} must be between 1 and {MAX_EXACT_JSON_INTEGER}"
        )));
    }
    Ok(())
}

fn validate_nonzero_digest(
    label: &str,
    digest: &str,
) -> Result<(), ProductionDeploymentApplicabilityError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(invalid(format!("{label} is not a SHA-256 digest")));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || hex.bytes().all(|byte| byte == b'0')
    {
        return Err(invalid(format!(
            "{label} must be a nonzero lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn exact_integer(label: &str, value: u64) -> Result<i64, ProductionDeploymentApplicabilityError> {
    positive_exact(label, value)?;
    i64::try_from(value).map_err(|_| invalid(format!("{label} does not fit i64")))
}

fn strictly_sorted<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let Some(mut previous) = values.next() else {
        return false;
    };
    for value in values {
        if previous >= value {
            return false;
        }
        previous = value;
    }
    true
}

fn required_str<'a>(
    value: &'a Value,
    field: &str,
    context: &str,
) -> Result<&'a str, ProductionDeploymentApplicabilityError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{context} omits string field {field}")))
}

fn required_array<'a>(
    value: &'a Value,
    field: &str,
    context: &str,
) -> Result<&'a [Value], ProductionDeploymentApplicabilityError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("{context} omits array field {field}")))
}

fn invalid(message: impl Into<String>) -> ProductionDeploymentApplicabilityError {
    ProductionDeploymentApplicabilityError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::conformance_applicability::{
        APPLICABILITY_IDENTITY_CONTRACT, APPLICABILITY_INVENTORY_CONTRACT,
    };
    use crate::production_build::{
        BuildComponent, BuildEndian, BuildSelectorDisposition, BuildSource, BuildTarget,
        MandatoryCapabilityBaseline, OciSubject, OciSubjectKind,
        PRODUCTION_BUILD_MANIFEST_CONTRACT_KIND, PRODUCTION_BUILD_MANIFEST_SCHEMA_URI,
        PRODUCTION_BUILD_MANIFEST_SCHEMA_VERSION, RuntimeExecutable, SelectorDisposition,
        SelectorDomain, ShippedAdapter, SourceRevisionAlgorithm,
    };
    use crate::security_profile::{
        DeploymentApplicability, EvaluationScope, SecurityProfile, TrustTopologyKind,
    };

    use super::*;

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
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
                production_eligible: true,
                capability_ids: vec!["authenticate".into()],
                mandatory_baseline: MandatoryCapabilityBaseline {
                    document_id: "baseline:test".into(),
                    document_version: 1,
                    content_digest: digest('e'),
                    artifact_locator: "docs/test.md".into(),
                    required_trace_ids: vec!["TRACE-SB-PROVIDER-AC-001".into()],
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

    fn profile(manifest: &ProductionBuildManifest) -> DeploymentSecurityProfile {
        let mut profile: DeploymentSecurityProfile = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/deployment-security-profile.implementation.json"
        ))
        .unwrap();
        profile.document_id = "deployment-security-profile:test".into();
        profile.document_version = 7;
        profile.lifecycle.state = DocumentLifecycleState::Active;
        profile.deployment_id = "deployment:test".into();
        profile.security_profile = SecurityProfile::Production;
        profile.tenancy_mode = TenancyMode::SingleTenant;
        profile.applicability = DeploymentApplicability {
            evaluation_scope: EvaluationScope::Deployment,
            security_profiles: vec![SecurityProfile::Production],
            deployment_ids: vec![profile.deployment_id.clone()],
            enabled_feature_ids: profile.enabled_features.clone(),
        };
        profile.trust_topology.topology_kind = TrustTopologyKind::SingleTrustDomain;
        profile.trust_topology.trust_domain_ids = vec!["trust-domain:test".into()];
        profile.control_trace_ref = manifest.control_trace_ref.clone();
        profile
    }

    fn claims(profile: &DeploymentSecurityProfile) -> ProductionDeploymentApplicabilityClaims {
        ProductionDeploymentApplicabilityClaims {
            checkpoints: vec![DeploymentCheckpointApplicabilityClaim {
                trust_domain_id: "trust-domain:test".into(),
                authority_id: "conformance-trust-checkpoint-authority:test".into(),
                authority_epoch: 3,
                sequence: 9,
                trust_registry_digest: profile
                    .conformance_trust_root_registry_ref
                    .content_digest
                    .clone(),
                trust_registry_locator: profile
                    .conformance_trust_root_registry_ref
                    .artifact_locator
                    .clone(),
            }],
            provider_registry: ActiveProviderRegistryApplicabilityClaim {
                document_id: profile.provider_registry_ref.document_id.clone(),
                document_version: profile.provider_registry_ref.document_version,
                content_digest: profile.provider_registry_ref.content_digest.clone(),
                artifact_locator: profile.provider_registry_ref.artifact_locator.clone(),
                registry_version: 11,
                active_providers: vec![ActiveProviderApplicabilityClaim {
                    provider_id: "provider:test".into(),
                    provider_kind: "oidc".into(),
                    configuration_version: 2,
                    configuration_payload_digest: digest('8'),
                    lifecycle_record_version: 5,
                    lifecycle_state: ProviderLifecycleState::Active,
                    trust_domain_id: "trust-domain:test".into(),
                    descriptor_id: "capability-descriptor:test".into(),
                    descriptor_version: 4,
                    adapter_kind: "auth.test".into(),
                    adapter_version: "1.2.3".into(),
                    advertised_capability_ids: vec!["authenticate".into()],
                    production_eligible: true,
                    mandatory_baseline_ref: ProviderMandatoryBaselineClaim {
                        document_id: "baseline:test".into(),
                        document_version: 1,
                        content_digest: digest('e'),
                        artifact_locator: "docs/test.md".into(),
                    },
                }],
            },
            security_limit_profile: SecurityLimitApplicabilityClaim {
                document_id: profile.security_limit_profile_ref.document_id.clone(),
                document_version: profile.security_limit_profile_ref.document_version,
                content_digest: profile.security_limit_profile_ref.content_digest.clone(),
                artifact_locator: profile.security_limit_profile_ref.artifact_locator.clone(),
                profile_version: 13,
            },
            deployed_artifact: DeployedArtifactApplicabilityClaim {
                subject_kind: OciSubjectKind::OciImageManifest,
                repository: "ghcr.io/example/ryuki-api".into(),
                subject_digest: digest('c'),
            },
        }
    }

    fn trace_fixture() -> Value {
        json!({
            "contract_kind": "control-trace",
            "document_id": "control-trace:test",
            "document_version": 1,
            "traces": [
                {
                    "trace_id": "TRACE-SB-DEPLOY-AC-001",
                    "owning_work_package": "SB-0",
                    "trace_lifecycle": "active",
                    "applicability_expression": {
                        "implementation": {"operator": "always"},
                        "deployment": {"operator": "always"}
                    },
                    "evidence_instance_dimensions": {
                        "implementation": [],
                        "deployment": [
                        "deployment.artifact_digest",
                        "deployment.configuration_version",
                        "deployment.deployment_id",
                        "deployment.deployment_profile_id",
                        "deployment.deployment_profile_version",
                        "deployment.policy_version",
                        "deployment.provider_registry_version",
                        "deployment.security_limit_profile_version"
                    ]},
                    "minimum_evidence_tier": {
                        "implementation": {"name": "repository_local", "rank": 1},
                        "deployment": {"name": "externally_attested", "rank": 3}
                    }
                },
                {
                    "trace_id": "TRACE-SB-PROVIDER-AC-001",
                    "owning_work_package": "SB-7",
                    "trace_lifecycle": "active",
                    "applicability_expression": {
                        "implementation": {"operator": "always"},
                        "deployment": {"operator": "always"}
                    },
                    "evidence_instance_dimensions": {
                        "implementation": [],
                        "deployment": [
                        "deployment.conformance_trust_checkpoint_authority_epoch",
                        "deployment.conformance_trust_checkpoint_authority_id",
                        "deployment.conformance_trust_checkpoint_sequence",
                        "deployment.trust_domain_id"
                    ]},
                    "minimum_evidence_tier": {
                        "implementation": {"name": "repository_local", "rank": 1},
                        "deployment": {"name": "externally_attested", "rank": 3}
                    }
                },
                {
                    "trace_id": "TRACE-SB-NULL-AC-001",
                    "owning_work_package": "SB-8",
                    "trace_lifecycle": "active",
                    "applicability_expression": {
                        "implementation": {"operator": "always"},
                        "deployment": {"operator": "always"}
                    },
                    "evidence_instance_dimensions": {
                        "implementation": [],
                        "deployment": []
                    },
                    "minimum_evidence_tier": {
                        "implementation": null,
                        "deployment": null
                    }
                }
            ]
        })
    }

    #[test]
    fn derives_each_deployment_trace_and_build_owned_provider_baseline() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let claims = claims(&profile);
        let derived = derive_production_deployment_applicability(
            &trace_fixture(),
            &manifest,
            &profile,
            &claims,
        )
        .unwrap();
        assert_eq!(derived.instances.len(), 3);
        assert_eq!(derived.binding.instance_count, 3);
        assert!(derived.instances.iter().all(|instance| {
            instance.scope == ApplicabilityScope::Deployment
                && instance.trace_id != "TRACE-SB-NULL-AC-001"
        }));
        assert!(derived.instances.iter().any(|instance| matches!(
            &instance.subject,
            ApplicabilitySubject::ProviderCapability { .. }
        )));
        let deployment_profile_version = derived
            .instances
            .iter()
            .find(|instance| instance.trace_id == "TRACE-SB-DEPLOY-AC-001")
            .and_then(|instance| {
                instance
                    .dimensions
                    .iter()
                    .find(|dimension| dimension.name == "deployment.deployment_profile_version")
            })
            .expect("deployment profile version dimension");
        assert_eq!(
            deployment_profile_version.value,
            ApplicabilityDimensionValue::Integer(
                i64::try_from(profile.deployment_profile_version).unwrap()
            )
        );
    }

    #[test]
    fn combines_implementation_and_deployment_into_one_canonical_inventory() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let claims = claims(&profile);
        let combined = derive_complete_production_applicability(
            &trace_fixture(),
            &manifest,
            &profile,
            &claims,
        )
        .unwrap();
        assert_eq!(combined.instances.len(), 6);
        assert_eq!(combined.binding.instance_count, 6);
        assert!(
            combined
                .instances
                .windows(2)
                .all(|pair| compare_applicability_instances(&pair[0], &pair[1]).is_lt())
        );
        assert!(
            combined
                .instances
                .iter()
                .any(|instance| { instance.scope == ApplicabilityScope::Implementation })
        );
        assert!(
            combined
                .instances
                .iter()
                .any(|instance| instance.scope == ApplicabilityScope::Deployment)
        );
    }

    #[test]
    fn exact_validator_rejects_an_omitted_row() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let claims = claims(&profile);
        let mut derived = derive_production_deployment_applicability(
            &trace_fixture(),
            &manifest,
            &profile,
            &claims,
        )
        .unwrap();
        derived.instances.pop();
        let error = validate_exact_production_deployment_applicability(
            &trace_fixture(),
            &manifest,
            &profile,
            &claims,
            &derived.binding,
            &derived.instances,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("is not exact"));
    }

    #[test]
    fn deployed_artifact_must_match_the_build_oci_subject() {
        let manifest = manifest();
        let profile = profile(&manifest);
        for mismatched in [
            DeployedArtifactApplicabilityClaim {
                subject_kind: OciSubjectKind::OciImageIndex,
                repository: manifest.oci_subject.repository.clone(),
                subject_digest: manifest.oci_subject.content_digest.clone(),
            },
            DeployedArtifactApplicabilityClaim {
                subject_kind: manifest.oci_subject.subject_kind,
                repository: "ghcr.io/example/wrong".into(),
                subject_digest: manifest.oci_subject.content_digest.clone(),
            },
            DeployedArtifactApplicabilityClaim {
                subject_kind: manifest.oci_subject.subject_kind,
                repository: manifest.oci_subject.repository.clone(),
                subject_digest: digest('9'),
            },
        ] {
            let mut claims = claims(&profile);
            claims.deployed_artifact = mismatched;
            let error = derive_production_deployment_applicability(
                &trace_fixture(),
                &manifest,
                &profile,
                &claims,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("verified deployed OCI subject tuple"));
        }
    }

    #[test]
    fn provider_dimensions_are_derived_only_for_provider_capability_subjects() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let claims = claims(&profile);
        let mut trace = trace_fixture();
        trace["traces"][1]["evidence_instance_dimensions"]["deployment"] = json!([
            "deployment.capability_id",
            "deployment.provider_configuration_digest",
            "deployment.provider_id",
            "deployment.subject_kind"
        ]);
        trace["traces"][1]["applicability_expression"]["deployment"] = json!({
            "operator": "all",
            "operands": [
                {"operator": "equals", "dimension": "deployment.subject_kind", "value": "provider_capability"},
                {"operator": "equals", "dimension": "deployment.provider_id", "value": "provider:test"},
                {"operator": "equals", "dimension": "deployment.provider_configuration_digest", "value": digest('8')},
                {"operator": "equals", "dimension": "deployment.capability_id", "value": "authenticate"}
            ]
        });

        let derived =
            derive_production_deployment_applicability(&trace, &manifest, &profile, &claims)
                .unwrap();
        let provider_rows = derived
            .instances
            .iter()
            .filter(|instance| instance.trace_id == "TRACE-SB-PROVIDER-AC-001")
            .collect::<Vec<_>>();
        assert_eq!(provider_rows.len(), 1);
        assert!(matches!(
            &provider_rows[0].subject,
            ApplicabilitySubject::ProviderCapability { .. }
        ));
        let dimensions = provider_rows[0]
            .dimensions
            .iter()
            .map(|dimension| (dimension.name.as_str(), &dimension.value))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            dimensions["deployment.provider_id"],
            &ApplicabilityDimensionValue::String("provider:test".into())
        );
        assert_eq!(
            dimensions["deployment.provider_configuration_digest"],
            &ApplicabilityDimensionValue::String(digest('8'))
        );
        assert_eq!(
            dimensions["deployment.capability_id"],
            &ApplicabilityDimensionValue::String("authenticate".into())
        );
    }

    #[test]
    fn fanout_bound_counts_only_derived_active_deployment_rows() {
        let manifest = manifest();
        let mut profile = profile(&manifest);
        profile.trust_topology.topology_kind = TrustTopologyKind::FederatedTrustDomains;
        profile.trust_topology.trust_domain_ids = (0..32)
            .map(|index| format!("trust-domain:{index:03}"))
            .collect();
        let mut claims = claims(&profile);
        claims.provider_registry.active_providers[0].trust_domain_id = "trust-domain:000".into();
        claims.checkpoints = profile
            .trust_topology
            .trust_domain_ids
            .iter()
            .map(|trust_domain_id| DeploymentCheckpointApplicabilityClaim {
                trust_domain_id: trust_domain_id.clone(),
                authority_id: "conformance-trust-checkpoint-authority:test".into(),
                authority_epoch: 3,
                sequence: 9,
                trust_registry_digest: profile
                    .conformance_trust_root_registry_ref
                    .content_digest
                    .clone(),
                trust_registry_locator: profile
                    .conformance_trust_root_registry_ref
                    .artifact_locator
                    .clone(),
            })
            .collect();
        let mut trace = trace_fixture();
        let traces = trace["traces"].as_array_mut().unwrap();
        for index in 0..510 {
            traces.push(json!({
                "trace_id": format!("TRACE-RETIRED-{index:04}"),
                "trace_lifecycle": "retired"
            }));
        }

        let derived =
            derive_production_deployment_applicability(&trace, &manifest, &profile, &claims)
                .unwrap();
        assert_eq!(derived.instances.len(), 65);
    }

    #[test]
    fn current_null_deployment_baseline_fails_closed() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let claims = claims(&profile);
        let mut trace = trace_fixture();
        trace["traces"][1]["minimum_evidence_tier"]["deployment"] = Value::Null;
        let error =
            derive_production_deployment_applicability(&trace, &manifest, &profile, &claims)
                .unwrap_err()
                .to_string();
        assert!(error.contains("has no deployment evidence tier"));
    }

    #[test]
    fn provider_cannot_subtract_or_add_shipped_capabilities() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let mut claims = claims(&profile);
        claims.provider_registry.active_providers[0]
            .advertised_capability_ids
            .push("extra".into());
        let error = derive_production_deployment_applicability(
            &trace_fixture(),
            &manifest,
            &profile,
            &claims,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("must exactly equal"));
    }

    #[test]
    fn provider_and_build_must_both_be_production_eligible() {
        let mut manifest = manifest();
        manifest.shipped_adapters[0].production_eligible = false;
        let profile = profile(&manifest);
        let claims = claims(&profile);
        let error = derive_production_deployment_applicability(
            &trace_fixture(),
            &manifest,
            &profile,
            &claims,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("must both be production eligible"));
    }

    #[test]
    fn provider_baseline_reference_must_equal_build_owned_baseline() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let mut claims = claims(&profile);
        claims.provider_registry.active_providers[0]
            .mandatory_baseline_ref
            .content_digest = digest('9');
        let error = derive_production_deployment_applicability(
            &trace_fixture(),
            &manifest,
            &profile,
            &claims,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("build-owned baseline"));
    }

    #[test]
    fn checkpoint_inventory_cannot_omit_or_add_a_trust_domain() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let mut claims = claims(&profile);
        claims.checkpoints[0].trust_domain_id = "trust-domain:other".into();
        let error = derive_production_deployment_applicability(
            &trace_fixture(),
            &manifest,
            &profile,
            &claims,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("missing or extra trust domains"));
    }

    #[test]
    fn boolean_expression_checks_hidden_invalid_operands() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let claims = claims(&profile);
        let mut trace = trace_fixture();
        trace["traces"][0]["applicability_expression"]["deployment"] = json!({
            "operator": "all",
            "operands": [
                {"operator": "never"},
                {"operator": "equals", "dimension": "deployment.undeclared", "value": "x"}
            ]
        });
        let error =
            derive_production_deployment_applicability(&trace, &manifest, &profile, &claims)
                .unwrap_err()
                .to_string();
        assert!(error.contains("undeclared dimension"));
    }

    #[test]
    fn membership_expression_values_are_bounded() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let claims = claims(&profile);
        let mut trace = trace_fixture();
        trace["traces"][0]["applicability_expression"]["deployment"] = json!({
            "operator": "in",
            "dimension": "deployment.deployment_id",
            "values": vec!["deployment:test"; 65]
        });
        let error =
            derive_production_deployment_applicability(&trace, &manifest, &profile, &claims)
                .unwrap_err()
                .to_string();
        assert!(error.contains("1 through 64 values"));
    }

    #[test]
    fn exact_registry_and_limit_bindings_are_required() {
        let manifest = manifest();
        let profile = profile(&manifest);
        let mut limit_claims = claims(&profile);
        limit_claims.security_limit_profile.profile_version = 0;
        assert!(
            derive_production_deployment_applicability(
                &trace_fixture(),
                &manifest,
                &profile,
                &limit_claims,
            )
            .unwrap_err()
            .to_string()
            .contains("profile_version")
        );

        let mut registry_claims = claims(&profile);
        registry_claims.provider_registry.content_digest = digest('8');
        assert!(
            derive_production_deployment_applicability(
                &trace_fixture(),
                &manifest,
                &profile,
                &registry_claims,
            )
            .unwrap_err()
            .to_string()
            .contains("provider registry claim")
        );
    }
}
