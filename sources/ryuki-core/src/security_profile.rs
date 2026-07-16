use std::collections::HashSet;
use std::path::{Component, Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const DEPLOYMENT_SECURITY_PROFILE_SCHEMA_URI: &str =
    "https://ryuki.io/schemas/security-contracts/v1/deployment-security-profile.schema.json";
pub const DEPLOYMENT_SECURITY_PROFILE_SCHEMA_VERSION: &str = "1.0.0";
pub const DEPLOYMENT_SECURITY_PROFILE_CONTRACT_KIND: &str = "deployment-security-profile";

const REQUIRED_PRODUCTION_GUARDS: [GuardId; 8] = [
    GuardId::DurablePostgresql,
    GuardId::ApprovedSecretProvider,
    GuardId::HttpsPublicUrls,
    GuardId::SecureCookies,
    GuardId::NonDevelopmentAuthenticator,
    GuardId::ExternalSigningKeyMaterial,
    GuardId::MockDependenciesDisabled,
    GuardId::FirstOwnerPathClosed,
];

/// The one executable root for a serving process.
///
/// This type intentionally mirrors the published JSON Schema field-for-field.
/// JSON Schema validation runs before deserialization at the API boundary;
/// these semantic checks enforce cross-field rules that JSON Schema cannot.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSecurityProfile {
    #[serde(rename = "$schema")]
    pub schema_uri: String,
    pub schema_version: String,
    pub contract_kind: String,
    pub document_id: String,
    pub document_version: u64,
    pub lifecycle: DocumentLifecycle,
    pub applicability: DeploymentApplicability,
    pub deployment_profile_version: u64,
    pub deployment_id: String,
    pub security_profile: SecurityProfile,
    pub platform_configuration_version: u64,
    pub policy_version: u64,
    pub tenancy_mode: TenancyMode,
    pub trust_topology: TrustTopology,
    pub provider_registry_ref: VersionedContentReference,
    pub provider_lifecycle_snapshot_ref: ProviderLifecycleReference,
    pub action_resource_registry_ref: VersionedContentReference,
    pub security_limit_profile_ref: VersionedContentReference,
    pub control_plane_topology_ref: VersionedContentReference,
    pub egress_policy_ref: VersionedContentReference,
    pub retention_policy_ref: VersionedContentReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_overlay: Option<MigrationOverlay>,
    pub enabled_features: Vec<String>,
    pub runtime_guard_evidence: RuntimeGuardEvidence,
}

/// Independently pinned process expectations used when a profile is selected
/// for startup. These values must come from deployment configuration, not from
/// the profile document being evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupAdmissionContext {
    pub deployment_id: String,
    pub security_profile: SecurityProfile,
    pub profile_digest: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentLifecycle {
    pub state: DocumentLifecycleState,
    pub effective_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<VersionedContentReference>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentLifecycleState {
    ImplementationOnly,
    Candidate,
    Active,
    Deprecated,
    Retired,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentApplicability {
    pub evaluation_scope: EvaluationScope,
    pub security_profiles: Vec<SecurityProfile>,
    pub deployment_ids: Vec<String>,
    pub enabled_feature_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationScope {
    Deployment,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SecurityProfile {
    Development,
    Test,
    Production,
}

impl SecurityProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
    }

    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }

    pub const fn admits_development_fixture(self) -> bool {
        matches!(self, Self::Development | Self::Test)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenancyMode {
    SingleTenant,
    MultiTenant,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustTopology {
    pub topology_kind: TrustTopologyKind,
    pub trust_domain_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy_ref: Option<VersionedContentReference>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustTopologyKind {
    SingleTrustDomain,
    FederatedTrustDomains,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionedContentReference {
    pub artifact_kind: ArtifactKind,
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    DeploymentSecurityProfile,
    ProviderRegistry,
    ActionResourceRegistry,
    SecurityLimitProfile,
    ControlPlaneTopology,
    EgressPolicy,
    RetentionPolicy,
    FederationPolicy,
    PackageExitReceipt,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderLifecycleReference {
    pub artifact_kind: ProviderLifecycleArtifactKind,
    pub document_id: String,
    pub document_version: u64,
    pub content_digest: String,
    pub artifact_locator: String,
    pub projection: ProviderLifecycleProjection,
    pub required_states: Vec<ProviderLifecycleState>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderLifecycleArtifactKind {
    ProviderRegistry,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleProjection {
    ProviderLifecycle,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleState {
    Validated,
    Active,
    Draining,
    Quarantined,
    Removed,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationOverlay {
    pub overlay_id: String,
    pub overlay_version: u64,
    pub security_profile: SecurityProfile,
    pub authority_source: MigrationAuthoritySource,
    pub legacy_selector_present: bool,
    pub provider_registry_present: bool,
    pub retirement_deadline: String,
    pub conflict_telemetry_name: String,
    pub grants_authority: bool,
    pub live_execution_allowed: bool,
    pub zero_consumer_receipt_ref: VersionedContentReference,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationAuthoritySource {
    ProviderRegistry,
    LegacyAuthMode,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeGuardEvidence {
    pub mode: RuntimeGuardMode,
    pub guards: Vec<GuardEvidence>,
    pub runtime_cross_check_required: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeGuardMode {
    NotApplicable,
    ReceiptBound,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardEvidence {
    pub guard_id: GuardId,
    pub control_ids: Vec<String>,
    pub receipt_ref: VersionedContentReference,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum GuardId {
    DurablePostgresql,
    ApprovedSecretProvider,
    HttpsPublicUrls,
    SecureCookies,
    NonDevelopmentAuthenticator,
    ExternalSigningKeyMaterial,
    MockDependenciesDisabled,
    FirstOwnerPathClosed,
}

impl DeploymentSecurityProfile {
    /// Validate structural cross-field invariants at an injected time.
    /// Artifact bytes, schema validity, and signature/provenance are checked by
    /// the loader; this method never authorizes startup or turns receipt-shaped
    /// metadata into trust.
    pub fn validate_structure_at(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut errors = Vec::new();

        if self.schema_uri != DEPLOYMENT_SECURITY_PROFILE_SCHEMA_URI {
            errors.push("$schema must equal the canonical deployment profile schema URI".into());
        }
        if self.schema_version != DEPLOYMENT_SECURITY_PROFILE_SCHEMA_VERSION {
            errors.push("schema_version is unsupported".into());
        }
        if self.contract_kind != DEPLOYMENT_SECURITY_PROFILE_CONTRACT_KIND {
            errors.push("contract_kind must equal deployment-security-profile".into());
        }
        validate_id(
            &self.document_id,
            "deployment-security-profile:",
            "document_id",
            &mut errors,
        );
        validate_id(
            &self.deployment_id,
            "deployment:",
            "deployment_id",
            &mut errors,
        );
        for (label, value) in [
            ("document_version", self.document_version),
            (
                "deployment_profile_version",
                self.deployment_profile_version,
            ),
            (
                "platform_configuration_version",
                self.platform_configuration_version,
            ),
            ("policy_version", self.policy_version),
        ] {
            if value == 0 {
                errors.push(format!("{label} must be greater than zero"));
            }
        }

        match parse_timestamp(
            "lifecycle.effective_at",
            &self.lifecycle.effective_at,
            &mut errors,
        ) {
            Some(effective_at)
                if self.lifecycle.state == DocumentLifecycleState::Active && effective_at > now =>
            {
                errors.push("an active deployment profile cannot be future-dated".into());
            }
            _ => {}
        }
        if self.lifecycle.state == DocumentLifecycleState::Retired {
            errors.push("a retired deployment profile cannot be selected for startup".into());
        }

        if self.applicability.security_profiles.len() != 1
            || self.applicability.security_profiles[0] != self.security_profile
        {
            errors
                .push("applicability.security_profiles must exactly match security_profile".into());
        }
        if self.applicability.deployment_ids.len() != 1
            || self.applicability.deployment_ids[0] != self.deployment_id
        {
            errors.push("applicability.deployment_ids must exactly match deployment_id".into());
        }
        if !same_unique_strings(
            &self.applicability.enabled_feature_ids,
            &self.enabled_features,
        ) {
            errors.push(
                "applicability.enabled_feature_ids must exactly match enabled_features".into(),
            );
        }
        require_unique_strings("enabled_features", &self.enabled_features, &mut errors);

        self.validate_trust_topology(&mut errors);
        self.validate_references(&mut errors);
        self.validate_runtime_guards(&mut errors);

        if let Some(overlay) = &self.migration_overlay {
            self.validate_overlay(overlay, now, &mut errors);
        }

        if self.security_profile.is_production() {
            if self.tenancy_mode != TenancyMode::SingleTenant {
                errors.push(
                    "production multi_tenant is blocked until complete tenant isolation is proven"
                        .into(),
                );
            }
            if self.lifecycle.state != DocumentLifecycleState::Active {
                errors.push("production requires an active deployment profile document".into());
            }
        }

        errors.sort();
        errors.dedup();
        errors
    }

    /// Validate whether this document may be selected for process startup.
    ///
    /// Production admission intentionally remains unavailable until the API
    /// loader verifies receipt signatures, provenance, expiry, artifact bytes,
    /// and live runtime facts. Receipt-shaped JSON alone is never sufficient.
    pub fn validate_for_startup(
        &self,
        expected: &StartupAdmissionContext,
        actual_profile_digest: &str,
        now: DateTime<Utc>,
    ) -> Vec<String> {
        let mut errors = self.validate_structure_at(now);

        validate_digest(
            "startup expected profile_digest",
            &expected.profile_digest,
            &mut errors,
        );
        validate_digest(
            "startup actual profile_digest",
            actual_profile_digest,
            &mut errors,
        );
        if actual_profile_digest != expected.profile_digest {
            errors
                .push("deployment profile digest does not match the pinned profile_digest".into());
        }
        if self.deployment_id != expected.deployment_id {
            errors.push("deployment profile does not match the pinned deployment_id".into());
        }
        if self.security_profile != expected.security_profile {
            errors.push("deployment profile does not match the pinned security_profile".into());
        }
        if self.lifecycle.state != DocumentLifecycleState::Active {
            errors.push("startup requires an active deployment profile document".into());
        }
        if expected.security_profile.is_production() {
            errors.push(
                "production startup is blocked until trusted conformance receipts and runtime facts are verified"
                    .into(),
            );
        }

        errors.sort();
        errors.dedup();
        errors
    }

    fn validate_trust_topology(&self, errors: &mut Vec<String>) {
        if self.trust_topology.trust_domain_ids.is_empty() {
            errors.push("trust_topology.trust_domain_ids must not be empty".into());
        }
        require_unique_strings(
            "trust_topology.trust_domain_ids",
            &self.trust_topology.trust_domain_ids,
            errors,
        );
        for id in &self.trust_topology.trust_domain_ids {
            validate_id(id, "trust-domain:", "trust_domain_id", errors);
        }
        match self.trust_topology.topology_kind {
            TrustTopologyKind::SingleTrustDomain => {
                if self.trust_topology.trust_domain_ids.len() != 1 {
                    errors.push("single_trust_domain requires exactly one trust domain".into());
                }
                if self.trust_topology.federation_policy_ref.is_some() {
                    errors.push("single_trust_domain forbids federation_policy_ref".into());
                }
            }
            TrustTopologyKind::FederatedTrustDomains => {
                if self.trust_topology.trust_domain_ids.len() < 2 {
                    errors
                        .push("federated_trust_domains requires at least two trust domains".into());
                }
                if self.trust_topology.federation_policy_ref.is_none() {
                    errors.push("federated_trust_domains requires federation_policy_ref".into());
                }
            }
        }
    }

    fn validate_references(&self, errors: &mut Vec<String>) {
        if let Some(reference) = &self.lifecycle.supersedes {
            validate_reference(
                "lifecycle.supersedes",
                reference,
                ArtifactKind::DeploymentSecurityProfile,
                "deployment-security-profile:",
                errors,
            );
            if reference.document_id != self.document_id {
                errors.push("lifecycle.supersedes must preserve document_id".into());
            }
            if reference.document_version >= self.document_version {
                errors.push("lifecycle.supersedes must reference a lower document_version".into());
            }
        }

        for (label, reference, expected_kind, expected_prefix) in [
            (
                "provider_registry_ref",
                &self.provider_registry_ref,
                ArtifactKind::ProviderRegistry,
                "provider-registry:",
            ),
            (
                "action_resource_registry_ref",
                &self.action_resource_registry_ref,
                ArtifactKind::ActionResourceRegistry,
                "action-resource-registry:",
            ),
            (
                "security_limit_profile_ref",
                &self.security_limit_profile_ref,
                ArtifactKind::SecurityLimitProfile,
                "security-limit-profile:",
            ),
            (
                "control_plane_topology_ref",
                &self.control_plane_topology_ref,
                ArtifactKind::ControlPlaneTopology,
                "control-plane-topology:",
            ),
            (
                "egress_policy_ref",
                &self.egress_policy_ref,
                ArtifactKind::EgressPolicy,
                "egress-policy:",
            ),
            (
                "retention_policy_ref",
                &self.retention_policy_ref,
                ArtifactKind::RetentionPolicy,
                "retention-policy:",
            ),
        ] {
            validate_reference(label, reference, expected_kind, expected_prefix, errors);
        }
        if let Some(reference) = &self.trust_topology.federation_policy_ref {
            validate_reference(
                "trust_topology.federation_policy_ref",
                reference,
                ArtifactKind::FederationPolicy,
                "federation-policy:",
                errors,
            );
        }

        let lifecycle = &self.provider_lifecycle_snapshot_ref;
        validate_id(
            &lifecycle.document_id,
            "provider-registry:",
            "provider_lifecycle_snapshot_ref.document_id",
            errors,
        );
        validate_digest(
            "provider_lifecycle_snapshot_ref.content_digest",
            &lifecycle.content_digest,
            errors,
        );
        validate_locator(
            "provider_lifecycle_snapshot_ref.artifact_locator",
            &lifecycle.artifact_locator,
            errors,
        );
        if lifecycle.document_version == 0 {
            errors.push(
                "provider_lifecycle_snapshot_ref.document_version must be greater than zero".into(),
            );
        }
        if lifecycle.required_states.as_slice() != [ProviderLifecycleState::Active] {
            errors.push(
                "provider_lifecycle_snapshot_ref.required_states must be exactly [active]".into(),
            );
        }

        if lifecycle.document_id != self.provider_registry_ref.document_id
            || lifecycle.document_version != self.provider_registry_ref.document_version
            || lifecycle.content_digest != self.provider_registry_ref.content_digest
            || lifecycle.artifact_locator != self.provider_registry_ref.artifact_locator
        {
            errors.push(
                "provider lifecycle snapshot must bind the exact provider registry artifact".into(),
            );
        }
    }

    fn validate_runtime_guards(&self, errors: &mut Vec<String>) {
        if !self.runtime_guard_evidence.runtime_cross_check_required {
            errors.push("runtime_guard_evidence.runtime_cross_check_required must be true".into());
        }
        if self.security_profile.is_production() {
            if self.runtime_guard_evidence.mode != RuntimeGuardMode::ReceiptBound {
                errors.push("production runtime guards must be receipt_bound".into());
            }
            let actual = self
                .runtime_guard_evidence
                .guards
                .iter()
                .map(|guard| guard.guard_id)
                .collect::<HashSet<_>>();
            let expected = REQUIRED_PRODUCTION_GUARDS
                .into_iter()
                .collect::<HashSet<_>>();
            if actual != expected
                || self.runtime_guard_evidence.guards.len() != REQUIRED_PRODUCTION_GUARDS.len()
            {
                errors
                    .push("production requires exactly one receipt for every runtime guard".into());
            }
            for guard in &self.runtime_guard_evidence.guards {
                if guard.control_ids.is_empty() {
                    errors.push(format!(
                        "runtime guard {:?} has no control_ids",
                        guard.guard_id
                    ));
                }
                require_unique_strings("runtime guard control_ids", &guard.control_ids, errors);
                validate_reference(
                    "runtime guard receipt_ref",
                    &guard.receipt_ref,
                    ArtifactKind::PackageExitReceipt,
                    "package-exit-receipt:",
                    errors,
                );
            }
        } else {
            if self.runtime_guard_evidence.mode != RuntimeGuardMode::NotApplicable {
                errors.push("non-production runtime guard mode must be not_applicable".into());
            }
            if !self.runtime_guard_evidence.guards.is_empty() {
                errors.push(
                    "non-production profiles must not carry production guard receipts".into(),
                );
            }
        }
    }

    fn validate_overlay(
        &self,
        overlay: &MigrationOverlay,
        now: DateTime<Utc>,
        errors: &mut Vec<String>,
    ) {
        validate_id(
            &overlay.overlay_id,
            "migration-overlay:",
            "migration_overlay.overlay_id",
            errors,
        );
        if overlay.overlay_version == 0 {
            errors.push("migration_overlay.overlay_version must be greater than zero".into());
        }
        if overlay.security_profile != self.security_profile {
            errors.push("migration overlay profile must exactly match the root profile".into());
        }
        if !overlay.legacy_selector_present || !overlay.provider_registry_present {
            errors.push("migration overlay requires both conflicting authority selectors".into());
        }
        if overlay.grants_authority || overlay.live_execution_allowed {
            errors.push("migration overlay cannot grant authority or enable live execution".into());
        }
        match DateTime::parse_from_rfc3339(&overlay.retirement_deadline) {
            Ok(deadline) if deadline.with_timezone(&Utc) > now => {}
            Ok(_) => errors.push("migration overlay retirement_deadline has expired".into()),
            Err(_) => errors.push("migration overlay retirement_deadline is not RFC3339".into()),
        }
        if self.enabled_features.iter().any(|feature| {
            matches!(
                feature.as_str(),
                "live-execution" | "provider-live-execution"
            )
        }) {
            errors.push("migration overlay forbids live-execution features".into());
        }
        validate_reference(
            "migration_overlay.zero_consumer_receipt_ref",
            &overlay.zero_consumer_receipt_ref,
            ArtifactKind::PackageExitReceipt,
            "package-exit-receipt:",
            errors,
        );
    }
}

fn validate_reference(
    label: &str,
    reference: &VersionedContentReference,
    expected_kind: ArtifactKind,
    expected_prefix: &str,
    errors: &mut Vec<String>,
) {
    if reference.artifact_kind != expected_kind {
        errors.push(format!(
            "{label}.artifact_kind does not match {expected_kind:?}"
        ));
    }
    validate_id(
        &reference.document_id,
        expected_prefix,
        &format!("{label}.document_id"),
        errors,
    );
    if reference.document_version == 0 {
        errors.push(format!(
            "{label}.document_version must be greater than zero"
        ));
    }
    validate_digest(
        &format!("{label}.content_digest"),
        &reference.content_digest,
        errors,
    );
    validate_locator(
        &format!("{label}.artifact_locator"),
        &reference.artifact_locator,
        errors,
    );
}

fn validate_id(value: &str, prefix: &str, label: &str, errors: &mut Vec<String>) {
    let Some(suffix) = value.strip_prefix(prefix) else {
        errors.push(format!("{label} must use the {prefix} namespace"));
        return;
    };
    let bytes = suffix.as_bytes();
    let valid = (3..=127).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if !valid {
        errors.push(format!("{label} is not a canonical lowercase identifier"));
    }
}

fn validate_digest(label: &str, value: &str, errors: &mut Vec<String>) {
    let Some(hex) = value.strip_prefix("sha256:") else {
        errors.push(format!("{label} must be a sha256 digest"));
        return;
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        errors.push(format!(
            "{label} must contain 64 lowercase hexadecimal characters"
        ));
    } else if hex.bytes().all(|byte| byte == b'0') {
        errors.push(format!(
            "{label} must not use the unresolved all-zero digest"
        ));
    }
}

fn validate_locator(label: &str, value: &str, errors: &mut Vec<String>) {
    if value.starts_with("json-pointer:#/") {
        return;
    }
    let path = Path::new(value);
    if path.is_absolute()
        || value.is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        errors.push(format!("{label} must be a safe repository-relative path"));
    }
}

fn parse_timestamp(label: &str, value: &str, errors: &mut Vec<String>) -> Option<DateTime<Utc>> {
    if value.trim() != value {
        errors.push(format!("{label} must be a trimmed RFC3339 timestamp"));
        return None;
    }
    match DateTime::parse_from_rfc3339(value) {
        Ok(timestamp) => Some(timestamp.with_timezone(&Utc)),
        Err(_) => {
            errors.push(format!("{label} must be a trimmed RFC3339 timestamp"));
            None
        }
    }
}

fn require_unique_strings(label: &str, values: &[String], errors: &mut Vec<String>) {
    let unique = values.iter().collect::<HashSet<_>>();
    if unique.len() != values.len() {
        errors.push(format!("{label} contains duplicates"));
    }
}

fn same_unique_strings(left: &[String], right: &[String]) -> bool {
    let left_set = left.iter().collect::<HashSet<_>>();
    let right_set = right.iter().collect::<HashSet<_>>();
    left.len() == left_set.len() && right.len() == right_set.len() && left_set == right_set
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    const TEST_PROFILE_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture() -> DeploymentSecurityProfile {
        serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/deployment-security-profile.implementation.json"
        ))
        .expect("checked-in profile must match the Rust contract")
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap()
    }

    fn structurally_complete_production_profile() -> DeploymentSecurityProfile {
        let mut profile = fixture();
        profile.security_profile = SecurityProfile::Production;
        profile.applicability.security_profiles = vec![SecurityProfile::Production];
        profile.tenancy_mode = TenancyMode::SingleTenant;
        profile.lifecycle.state = DocumentLifecycleState::Active;
        profile.lifecycle.effective_at = "2026-07-16T00:00:00Z".into();
        profile.runtime_guard_evidence.mode = RuntimeGuardMode::ReceiptBound;
        profile.runtime_guard_evidence.guards = REQUIRED_PRODUCTION_GUARDS
            .into_iter()
            .enumerate()
            .map(|(index, guard_id)| GuardEvidence {
                guard_id,
                control_ids: vec!["SB-CFG-01".into()],
                receipt_ref: VersionedContentReference {
                    artifact_kind: ArtifactKind::PackageExitReceipt,
                    document_id: format!("package-exit-receipt:fixture-{index}"),
                    document_version: 1,
                    content_digest: format!("sha256:{:064x}", index + 1),
                    artifact_locator: format!("receipts/fixture-{index}.json"),
                },
            })
            .collect();
        profile
    }

    #[test]
    fn checked_in_profile_round_trips_without_semantic_loss() {
        let raw: serde_json::Value = serde_json::from_str(include_str!(
            "../../../catalog/security-contracts/v1/deployment-security-profile.implementation.json"
        ))
        .unwrap();
        let typed = fixture();
        assert_eq!(serde_json::to_value(&typed).unwrap(), raw);
        assert_eq!(
            typed.validate_structure_at(fixed_now()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn unknown_fields_and_unknown_profiles_are_rejected() {
        let mut raw = serde_json::to_value(fixture()).unwrap();
        raw.as_object_mut()
            .unwrap()
            .insert("fallback".into(), json!(true));
        assert!(serde_json::from_value::<DeploymentSecurityProfile>(raw).is_err());

        let mut raw = serde_json::to_value(fixture()).unwrap();
        raw["security_profile"] = json!("prod");
        assert!(serde_json::from_value::<DeploymentSecurityProfile>(raw).is_err());
    }

    #[test]
    fn production_multi_tenant_remains_representable_but_fails_admission() {
        let mut profile = fixture();
        profile.security_profile = SecurityProfile::Production;
        profile.applicability.security_profiles = vec![SecurityProfile::Production];
        profile.tenancy_mode = TenancyMode::MultiTenant;
        profile.lifecycle.state = DocumentLifecycleState::Active;

        let errors = profile.validate_structure_at(fixed_now());
        assert!(errors.iter().any(|error| error.contains("multi_tenant")));
        assert!(errors.iter().any(|error| error.contains("receipt_bound")));
    }

    #[test]
    fn migration_overlay_is_profile_bound_non_authoritative_and_time_bounded() {
        let mut profile = fixture();
        profile.migration_overlay = Some(MigrationOverlay {
            overlay_id: "migration-overlay:test-legacy-auth".into(),
            overlay_version: 1,
            security_profile: SecurityProfile::Test,
            authority_source: MigrationAuthoritySource::LegacyAuthMode,
            legacy_selector_present: true,
            provider_registry_present: true,
            retirement_deadline: "2026-07-17T00:00:00+00:00".into(),
            conflict_telemetry_name: "security.migration.conflict".into(),
            grants_authority: false,
            live_execution_allowed: false,
            zero_consumer_receipt_ref: VersionedContentReference {
                artifact_kind: ArtifactKind::PackageExitReceipt,
                document_id: "package-exit-receipt:test-overlay-retirement".into(),
                document_version: 1,
                content_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                artifact_locator: "receipts/test-overlay-retirement.json".into(),
            },
        });
        assert!(profile.validate_structure_at(fixed_now()).is_empty());

        profile
            .migration_overlay
            .as_mut()
            .unwrap()
            .retirement_deadline = "2026-07-16T11:59:59Z".into();
        assert!(
            profile
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("expired"))
        );
    }

    #[test]
    fn zero_digest_and_parent_traversal_are_rejected() {
        let mut profile = fixture();
        profile.provider_registry_ref.content_digest = format!("sha256:{}", "0".repeat(64));
        profile.provider_registry_ref.artifact_locator = "../provider.json".into();
        let errors = profile.validate_structure_at(fixed_now());
        assert!(errors.iter().any(|error| error.contains("all-zero")));
        assert!(
            errors
                .iter()
                .any(|error| error.contains("repository-relative"))
        );
    }

    #[test]
    fn startup_context_prevents_profile_self_downgrade() {
        let profile = fixture();
        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: SecurityProfile::Production,
                profile_digest: TEST_PROFILE_DIGEST.into(),
            },
            TEST_PROFILE_DIGEST,
            fixed_now(),
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("pinned security_profile"))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("production startup is blocked"))
        );
    }

    #[test]
    fn receipt_shaped_metadata_never_authorizes_production_startup() {
        let profile = structurally_complete_production_profile();
        assert!(profile.validate_structure_at(fixed_now()).is_empty());

        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: SecurityProfile::Production,
                profile_digest: TEST_PROFILE_DIGEST.into(),
            },
            TEST_PROFILE_DIGEST,
            fixed_now(),
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("production startup is blocked"))
        );
    }

    #[test]
    fn provider_projection_requires_only_active_state() {
        let mut profile = fixture();
        profile.provider_lifecycle_snapshot_ref.required_states =
            vec![ProviderLifecycleState::Quarantined];
        assert!(
            profile
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("exactly [active]"))
        );
    }

    #[test]
    fn startup_rejects_malformed_profile_digests() {
        let profile = fixture();
        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: profile.security_profile,
                profile_digest: "SHA256:not-lowercase".into(),
            },
            "sha256:GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
            fixed_now(),
        );

        assert!(
            errors
                .iter()
                .any(|error| error == "startup expected profile_digest must be a sha256 digest")
        );
        assert!(errors.iter().any(|error| {
            error
                == "startup actual profile_digest must contain 64 lowercase hexadecimal characters"
        }));
    }

    #[test]
    fn startup_rejects_zero_profile_digests() {
        let profile = fixture();
        let zero_digest = format!("sha256:{}", "0".repeat(64));
        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: profile.security_profile,
                profile_digest: zero_digest.clone(),
            },
            &zero_digest,
            fixed_now(),
        );

        assert!(errors.iter().any(|error| {
            error == "startup expected profile_digest must not use the unresolved all-zero digest"
        }));
        assert!(errors.iter().any(|error| {
            error == "startup actual profile_digest must not use the unresolved all-zero digest"
        }));
    }

    #[test]
    fn startup_rejects_a_profile_digest_that_does_not_match_its_pin() {
        let profile = fixture();
        let errors = profile.validate_for_startup(
            &StartupAdmissionContext {
                deployment_id: profile.deployment_id.clone(),
                security_profile: profile.security_profile,
                profile_digest: TEST_PROFILE_DIGEST.into(),
            },
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            fixed_now(),
        );

        assert!(errors.iter().any(|error| {
            error == "deployment profile digest does not match the pinned profile_digest"
        }));
    }

    #[test]
    fn active_profiles_cannot_be_future_dated() {
        let mut profile = fixture();
        profile.lifecycle.state = DocumentLifecycleState::Active;
        profile.lifecycle.effective_at = "2026-07-16T12:00:01Z".into();
        assert!(
            profile
                .validate_structure_at(fixed_now())
                .iter()
                .any(|error| error.contains("future-dated"))
        );
    }

    #[test]
    fn supersedes_is_same_document_lower_version_and_safe() {
        let mut profile = fixture();
        profile.document_version = 2;
        profile.lifecycle.supersedes = Some(VersionedContentReference {
            artifact_kind: ArtifactKind::DeploymentSecurityProfile,
            document_id: profile.document_id.clone(),
            document_version: 1,
            content_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            artifact_locator: "catalog/security-contracts/v1/profile-v1.json".into(),
        });
        assert!(profile.validate_structure_at(fixed_now()).is_empty());

        let supersedes = profile.lifecycle.supersedes.as_mut().unwrap();
        supersedes.document_version = 2;
        supersedes.artifact_locator = "../profile-v1.json".into();
        let errors = profile.validate_structure_at(fixed_now());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("lower document_version"))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("repository-relative"))
        );
    }
}
