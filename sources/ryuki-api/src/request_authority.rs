//! Exact credential authority for typed request-instance reads.
//!
//! Authentication establishes this evidence before a handler runs. The
//! request repository must then revalidate it in the same database transaction
//! that will resolve the request row. Raw bearer values are never retained:
//! only exact, domain-separated digests and durable authority coordinates cross
//! this boundary.

use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use ryuki_core::security_profile::SecurityProfile;
use ryuki_core::PrincipalId;
use ryuki_engine::auth::{ActorClass, AuthSession};
use ryuki_engine::authorization::{
    ActorKind, AssuranceLevel, BindingDigest, BindingVersion, DeploymentProfile, ExplicitScope,
    PolicyRole, RequestReadExpectedAuthority, RequestReadKernelEvidence,
    RequestReadPrincipalEvidence,
};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::human_authority::{HumanAuthorityMode, InteractiveHumanAuthorityContext};
use crate::security_contracts::RequestReadSecurityNamespace;

const SESSION_BINDING_DIGEST_DOMAIN: &[u8] = b"ryuki-request-read-session-binding-v1";
const DEVELOPMENT_CREDENTIAL_ID_DOMAIN: &[u8] = b"ryuki-request-read-development-credential-v1";
const DEVELOPMENT_AUDIENCE_DOMAIN: &[u8] = b"ryuki-request-read-development-audience-v1";
const DEVELOPMENT_KEY_ID_DOMAIN: &[u8] = b"ryuki-request-read-development-key-id-v1";
const DEVELOPMENT_FIXTURE_PRINCIPAL_UUID: u128 = 0x018f_3f54_8f5e_7bb7_9f06_1f3c_c6f8_19d5;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestAuthorityError {
    #[error("request-read authority binding is invalid: {0}")]
    InvalidBinding(&'static str),
    #[error("request-read credential is stale or no longer authoritative")]
    StaleCredential,
    #[error("API tokens are not admitted for typed request reads")]
    ApiTokenNotAdmitted,
    #[error("request-read authority database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("request-read authorization binding failed")]
    Authorization(#[from] ryuki_engine::authorization::AuthorizationError),
}

/// Exact non-secret digests emitted by a credential validator.
///
/// `credential_id` identifies this bearer/session without retaining it,
/// `audience` binds the validated recipient set (or the exact deployment
/// recipient for a database-local platform session), and `key_id` binds the
/// exact validation key generation. Callers must digest validated canonical
/// values rather than display labels or unverified JOSE fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestReadCredentialDigests {
    credential_id: [u8; 32],
    audience: [u8; 32],
    key_id: [u8; 32],
}

impl RequestReadCredentialDigests {
    pub(crate) fn new(
        credential_id: [u8; 32],
        audience: [u8; 32],
        key_id: [u8; 32],
    ) -> Result<Self, RequestAuthorityError> {
        if credential_id == [0; 32] || audience == [0; 32] || key_id == [0; 32] {
            return Err(RequestAuthorityError::InvalidBinding(
                "credential digests must be non-zero",
            ));
        }
        Ok(Self {
            credential_id,
            audience,
            key_id,
        })
    }
}

impl fmt::Debug for RequestReadCredentialDigests {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestReadCredentialDigests(<redacted>)")
    }
}

/// Exact validity and assurance interval proved by the credential validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestReadCredentialWindow {
    credential_version: BindingVersion,
    authenticated_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    assurance: AssuranceLevel,
    assurance_expires_at: DateTime<Utc>,
}

impl RequestReadCredentialWindow {
    pub(crate) fn new(
        credential_version: u64,
        authenticated_at: DateTime<Utc>,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        assurance: AssuranceLevel,
        assurance_expires_at: DateTime<Utc>,
    ) -> Result<Self, RequestAuthorityError> {
        if authenticated_at > expires_at
            || not_before > expires_at
            || assurance_expires_at <= authenticated_at
            || assurance_expires_at > expires_at
        {
            return Err(RequestAuthorityError::InvalidBinding(
                "credential validity interval",
            ));
        }
        Ok(Self {
            credential_version: BindingVersion::new(credential_version)?,
            authenticated_at,
            not_before,
            expires_at,
            assurance,
            assurance_expires_at,
        })
    }
}

/// Durable session credential metadata. The administrative UUID is not a
/// bearer; the 32-byte verifier is already a keyed, non-reversible digest.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PersistedSessionCredential {
    session_record_id: Uuid,
    bearer_verifier_digest: [u8; 32],
    created_at: DateTime<Utc>,
    window: RequestReadCredentialWindow,
    digests: RequestReadCredentialDigests,
}

impl PersistedSessionCredential {
    pub(crate) fn new(
        session_record_id: Uuid,
        bearer_verifier_digest: [u8; 32],
        created_at: DateTime<Utc>,
        window: RequestReadCredentialWindow,
        digests: RequestReadCredentialDigests,
    ) -> Result<Self, RequestAuthorityError> {
        if session_record_id.is_nil()
            || bearer_verifier_digest == [0; 32]
            || bearer_verifier_digest != digests.credential_id
            || created_at != window.authenticated_at
        {
            return Err(RequestAuthorityError::InvalidBinding(
                "persisted-session credential metadata",
            ));
        }
        Ok(Self {
            session_record_id,
            bearer_verifier_digest,
            created_at,
            window,
            digests,
        })
    }
}

impl fmt::Debug for PersistedSessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedSessionCredential")
            .field("session_record_id", &self.session_record_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.window.expires_at)
            .field("digests", &"<redacted>")
            .finish()
    }
}

/// Metadata retained from one directly validated federated bearer. Validation
/// must have covered the exact JOSE key, audience, signature and time claims.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DirectFederatedCredential {
    window: RequestReadCredentialWindow,
    digests: RequestReadCredentialDigests,
    provider: String,
    issuer: String,
    subject: String,
}

impl DirectFederatedCredential {
    pub(crate) fn new(
        window: RequestReadCredentialWindow,
        digests: RequestReadCredentialDigests,
        provider: String,
        issuer: String,
        subject: String,
    ) -> Result<Self, RequestAuthorityError> {
        validate_identifier(&provider)?;
        validate_identifier(&issuer)?;
        validate_identifier(&subject)?;
        Ok(Self {
            window,
            digests,
            provider,
            issuer,
            subject,
        })
    }
}

impl fmt::Debug for DirectFederatedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectFederatedCredential")
            .field("authenticated_at", &self.window.authenticated_at)
            .field("not_before", &self.window.not_before)
            .field("expires_at", &self.window.expires_at)
            .field("provider", &self.provider)
            .field("issuer", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("digests", &"<redacted>")
            .finish()
    }
}

/// Explicit marker for the derived API-token family. There is deliberately no
/// conversion from this type into [`RequestReadAuthority`]: the current
/// provider registry has no exact token audience/action/lifecycle authority.
#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct UnadmittedApiTokenRequestReadCredential {
    token_record_id: Uuid,
    expires_at: DateTime<Utc>,
    credential_id_digest: [u8; 32],
}

#[allow(dead_code)]
impl UnadmittedApiTokenRequestReadCredential {
    pub(crate) fn new(
        token_record_id: Uuid,
        expires_at: DateTime<Utc>,
        credential_id_digest: [u8; 32],
    ) -> Result<Self, RequestAuthorityError> {
        if token_record_id.is_nil() || credential_id_digest == [0; 32] {
            return Err(RequestAuthorityError::InvalidBinding(
                "API-token credential metadata",
            ));
        }
        Ok(Self {
            token_record_id,
            expires_at,
            credential_id_digest,
        })
    }

    pub(crate) const fn request_read_denial(&self) -> RequestAuthorityError {
        RequestAuthorityError::ApiTokenNotAdmitted
    }
}

impl fmt::Debug for UnadmittedApiTokenRequestReadCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnadmittedApiTokenRequestReadCredential")
            .field("token_record_id", &self.token_record_id)
            .field("expires_at", &self.expires_at)
            .field("credential_id_digest", &"<redacted>")
            .finish()
    }
}

/// Exact interactive identity and human-assignment projection admitted by the
/// authentication boundary. Fields stay private so handlers cannot rewrite
/// provider provenance, scopes, roles or monotonic versions.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct InteractiveRequestReadPrincipal {
    principal_id: PrincipalId,
    principal_lifecycle_version: BindingVersion,
    principal_authority_version: BindingVersion,
    principal_key_id: Uuid,
    principal_key_version: BindingVersion,
    principal_link_id: Uuid,
    principal_link_version: BindingVersion,
    carrier_mode: String,
    source_provider: String,
    source_issuer: String,
    source_subject: String,
    identity_authority_digest: [u8; 32],
    identity_last_asserted_at: Option<DateTime<Utc>>,
    identity_fresh_until: Option<DateTime<Utc>>,
    roles: Vec<String>,
    site_mode: HumanAuthorityMode,
    site_scope: Vec<String>,
    environment_mode: HumanAuthorityMode,
    environment_scope: Vec<String>,
    policy_roles: BTreeSet<PolicyRole>,
}

impl InteractiveRequestReadPrincipal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        session: &AuthSession,
        authority: &InteractiveHumanAuthorityContext,
        identity_authority_digest: [u8; 32],
        identity_last_asserted_at: Option<DateTime<Utc>>,
        identity_fresh_until: Option<DateTime<Utc>>,
    ) -> Result<Self, RequestAuthorityError> {
        let binding = authority.principal_binding;
        validate_identifier(&authority.provider)?;
        validate_identifier(&authority.issuer)?;
        validate_identifier(&authority.subject)?;
        if !session.token_valid
            || session.actor_class != ActorClass::VerifiedHuman
            || identity_authority_digest == [0; 32]
            || binding.principal_key_id.is_nil()
            || binding.principal_link_id.is_nil()
            || session.principal_id != Some(binding.principal_id)
            || authority.identity_epoch != binding.principal_lifecycle_version
            || authority.assignment_version != binding.principal_authority_version
            || authority.roles != session.roles
            || authority.site_scope != session.site_scope
            || authority.environment_scope != session.environment_scope
        {
            return Err(RequestAuthorityError::InvalidBinding(
                "interactive principal does not match its admitted session",
            ));
        }
        validate_axis(authority.site_mode, &authority.site_scope)?;
        validate_axis(authority.environment_mode, &authority.environment_scope)?;
        if authority.provider == "local" {
            // Local identity authority is reconciled from immutable startup
            // configuration. Its exact row still carries `last_asserted_at`,
            // but the federated staleness deadline does not apply.
            if identity_fresh_until.is_some() {
                return Err(RequestAuthorityError::InvalidBinding(
                    "local identity cannot carry federated freshness",
                ));
            }
        } else {
            let (Some(asserted_at), Some(fresh_until)) =
                (identity_last_asserted_at, identity_fresh_until)
            else {
                return Err(RequestAuthorityError::InvalidBinding(
                    "federated identity freshness is required",
                ));
            };
            if fresh_until <= asserted_at {
                return Err(RequestAuthorityError::InvalidBinding(
                    "federated identity freshness interval",
                ));
            }
        }

        let policy_roles = policy_roles_for_session(session);
        if policy_roles.is_empty() {
            return Err(RequestAuthorityError::InvalidBinding(
                "interactive principal has no request-read policy role",
            ));
        }

        Ok(Self {
            principal_id: binding.principal_id,
            principal_lifecycle_version: positive_i64_version(binding.principal_lifecycle_version)?,
            principal_authority_version: positive_i64_version(binding.principal_authority_version)?,
            principal_key_id: binding.principal_key_id,
            principal_key_version: positive_i64_version(binding.principal_key_version)?,
            principal_link_id: binding.principal_link_id,
            principal_link_version: positive_i64_version(binding.principal_link_version)?,
            carrier_mode: session.provider_mode.clone(),
            source_provider: authority.provider.clone(),
            source_issuer: authority.issuer.clone(),
            source_subject: authority.subject.clone(),
            identity_authority_digest,
            identity_last_asserted_at,
            identity_fresh_until,
            roles: authority.roles.clone(),
            site_mode: authority.site_mode,
            site_scope: authority.site_scope.clone(),
            environment_mode: authority.environment_mode,
            environment_scope: authority.environment_scope.clone(),
            policy_roles,
        })
    }
}

impl fmt::Debug for InteractiveRequestReadPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InteractiveRequestReadPrincipal")
            .field("principal_id", &self.principal_id)
            .field(
                "principal_lifecycle_version",
                &self.principal_lifecycle_version,
            )
            .field(
                "principal_authority_version",
                &self.principal_authority_version,
            )
            .field("principal_key_id", &self.principal_key_id)
            .field("principal_key_version", &self.principal_key_version)
            .field("principal_link_id", &self.principal_link_id)
            .field("principal_link_version", &self.principal_link_version)
            .field("source_provider", &self.source_provider)
            .field("source_issuer", &"<redacted>")
            .field("source_subject", &"<redacted>")
            .field("identity_authority_digest", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestReadNamespace {
    deployment_id: String,
    trust_domain_id: String,
    tenant_id: Option<String>,
    profile: DeploymentProfile,
    policy_version: BindingVersion,
    policy_digest: BindingDigest,
    action_registry_version: BindingVersion,
    action_registry_digest: BindingDigest,
    maximum_authority_version: BindingVersion,
    maximum_authority_digest: BindingDigest,
    provider_id: String,
    provider_configuration_version: BindingVersion,
    provider_lifecycle_version: BindingVersion,
    credential_source_provider: String,
}

impl TryFrom<RequestReadSecurityNamespace> for RequestReadNamespace {
    type Error = RequestAuthorityError;

    fn try_from(value: RequestReadSecurityNamespace) -> Result<Self, Self::Error> {
        for identifier in [
            value.deployment_id.as_str(),
            value.trust_domain_id.as_str(),
            value.provider_id.as_str(),
            value.credential_source_provider.as_str(),
        ] {
            validate_identifier(identifier)?;
        }
        if value
            .tenant_id
            .as_deref()
            .is_some_and(|tenant| validate_identifier(tenant).is_err())
        {
            return Err(RequestAuthorityError::InvalidBinding("tenant id"));
        }
        let profile = match value.security_profile {
            SecurityProfile::Development => DeploymentProfile::Development,
            SecurityProfile::Test => DeploymentProfile::Test,
            SecurityProfile::Production => DeploymentProfile::Production,
        };
        Ok(Self {
            deployment_id: value.deployment_id,
            trust_domain_id: value.trust_domain_id,
            tenant_id: value.tenant_id,
            profile,
            policy_version: BindingVersion::new(value.policy_version)?,
            policy_digest: BindingDigest::from_sha256(&value.profile_digest)?,
            action_registry_version: BindingVersion::new(value.action_registry_version)?,
            action_registry_digest: BindingDigest::from_sha256(&value.action_registry_digest)?,
            maximum_authority_version: BindingVersion::new(value.maximum_authority_version)?,
            maximum_authority_digest: BindingDigest::from_sha256(&value.maximum_authority_digest)?,
            provider_id: value.provider_id,
            provider_configuration_version: BindingVersion::new(
                value.provider_configuration_version,
            )?,
            provider_lifecycle_version: BindingVersion::new(value.provider_lifecycle_version)?,
            credential_source_provider: value.credential_source_provider,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialKind {
    PersistedSession,
    DirectFederated,
    DevelopmentFixture,
    #[cfg(test)]
    TestFixture,
}

#[derive(Clone, PartialEq, Eq)]
struct CredentialEvidence {
    kind: CredentialKind,
    window: RequestReadCredentialWindow,
    digests: RequestReadCredentialDigests,
}

#[derive(Clone, PartialEq, Eq)]
enum RequestReadPrincipal {
    Interactive(Box<InteractiveRequestReadPrincipal>),
    DevelopmentFixture {
        principal_id: PrincipalId,
        site_scope: Vec<String>,
        environment_scope: Vec<String>,
    },
    #[cfg(test)]
    TestFixture {
        actor_kind: ActorKind,
        principal_id: PrincipalId,
        site_scope: Vec<String>,
        environment_scope: Vec<String>,
        policy_roles: BTreeSet<PolicyRole>,
    },
}

#[derive(Clone, PartialEq, Eq)]
enum RevalidationSource {
    PersistedSession(Box<PersistedSessionCredential>),
    DirectFederated,
    DevelopmentFixture,
    #[cfg(test)]
    TestFixture,
}

/// Opaque, non-serialized authority attached by authentication middleware.
/// Possession is not yet a permit: the repository must revalidate it and then
/// pass its exact principal evidence to the process-local authorization kernel.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RequestReadAuthority {
    namespace: RequestReadNamespace,
    principal: RequestReadPrincipal,
    credential: CredentialEvidence,
    revalidation: RevalidationSource,
    session_binding_digest: [u8; 32],
}

impl RequestReadAuthority {
    pub(crate) fn from_persisted_session(
        namespace: RequestReadSecurityNamespace,
        principal: InteractiveRequestReadPrincipal,
        credential: PersistedSessionCredential,
    ) -> Result<Self, RequestAuthorityError> {
        if principal.carrier_mode != "persisted-session" {
            return Err(RequestAuthorityError::InvalidBinding(
                "persisted session carrier mode",
            ));
        }
        let namespace = RequestReadNamespace::try_from(namespace)?;
        validate_interactive_namespace(&namespace, &principal)?;
        let evidence = CredentialEvidence {
            kind: CredentialKind::PersistedSession,
            window: credential.window,
            digests: credential.digests,
        };
        Ok(Self::seal(
            namespace,
            RequestReadPrincipal::Interactive(Box::new(principal)),
            evidence,
            RevalidationSource::PersistedSession(Box::new(credential)),
        ))
    }

    pub(crate) fn from_direct_federated(
        namespace: RequestReadSecurityNamespace,
        principal: InteractiveRequestReadPrincipal,
        credential: DirectFederatedCredential,
    ) -> Result<Self, RequestAuthorityError> {
        if principal.carrier_mode != principal.source_provider
            || principal.source_provider == "local"
            || credential.provider != principal.source_provider
            || credential.issuer != principal.source_issuer
            || credential.subject != principal.source_subject
        {
            return Err(RequestAuthorityError::InvalidBinding(
                "direct federated carrier mode",
            ));
        }
        let namespace = RequestReadNamespace::try_from(namespace)?;
        validate_interactive_namespace(&namespace, &principal)?;
        let evidence = CredentialEvidence {
            kind: CredentialKind::DirectFederated,
            window: credential.window,
            digests: credential.digests,
        };
        Ok(Self::seal(
            namespace,
            RequestReadPrincipal::Interactive(Box::new(principal)),
            evidence,
            RevalidationSource::DirectFederated,
        ))
    }

    pub(crate) fn development_fixture(
        namespace: RequestReadSecurityNamespace,
        session: &AuthSession,
        authenticated_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, RequestAuthorityError> {
        let namespace = RequestReadNamespace::try_from(namespace)?;
        if namespace.profile == DeploymentProfile::Production
            || namespace.credential_source_provider != "development-fixture"
            || session.actor_class != ActorClass::Simulated
            || session.provider_mode != "static-dry-run"
            || session.token_valid
            || session.principal_id.is_some()
            || !ryuki_engine::auth::check_permission(session, "admin")
        {
            return Err(RequestAuthorityError::InvalidBinding(
                "development fixture admission",
            ));
        }
        let credential_id = digest_parts(
            DEVELOPMENT_CREDENTIAL_ID_DOMAIN,
            &[
                namespace.deployment_id.as_bytes(),
                namespace.trust_domain_id.as_bytes(),
                namespace.provider_id.as_bytes(),
                development_fixture_principal_id().as_uuid().as_bytes(),
            ],
        );
        let digests = RequestReadCredentialDigests::new(
            credential_id,
            digest_parts(
                DEVELOPMENT_AUDIENCE_DOMAIN,
                &[
                    namespace.deployment_id.as_bytes(),
                    namespace.trust_domain_id.as_bytes(),
                ],
            ),
            digest_parts(
                DEVELOPMENT_KEY_ID_DOMAIN,
                &[
                    namespace.provider_id.as_bytes(),
                    namespace
                        .provider_configuration_version
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                ],
            ),
        )?;
        let window = RequestReadCredentialWindow::new(
            namespace.provider_configuration_version.get(),
            authenticated_at,
            authenticated_at,
            expires_at,
            AssuranceLevel::SingleFactor,
            expires_at,
        )?;
        let evidence = CredentialEvidence {
            kind: CredentialKind::DevelopmentFixture,
            window,
            digests,
        };
        Ok(Self::seal(
            namespace,
            RequestReadPrincipal::DevelopmentFixture {
                principal_id: development_fixture_principal_id(),
                site_scope: session.site_scope.clone(),
                environment_scope: session.environment_scope.clone(),
            },
            evidence,
            RevalidationSource::DevelopmentFixture,
        ))
    }

    /// Unit-test-only admission seam for direct handler tests. It is compiled
    /// out of production and preserves the supplied principal, roles, and
    /// scopes so tests exercise owner/scope policy instead of an all-powerful
    /// synthetic administrator.
    #[cfg(test)]
    pub(crate) fn test_fixture(session: &AuthSession) -> Self {
        let now = Utc::now();
        let policy_roles = policy_roles_for_session(session);
        let principal_id = session
            .principal_id
            .unwrap_or_else(development_fixture_principal_id);
        let namespace = RequestReadNamespace {
            deployment_id: "deployment:test".into(),
            trust_domain_id: "trust-domain:test".into(),
            tenant_id: None,
            profile: DeploymentProfile::Test,
            policy_version: BindingVersion::new(1).expect("positive test policy version"),
            policy_digest: BindingDigest::sha256(
                b"ryuki-request-read-test-policy-v1",
                principal_id.as_uuid().as_bytes(),
            ),
            action_registry_version: BindingVersion::new(1)
                .expect("positive test action-registry version"),
            action_registry_digest: BindingDigest::sha256(
                b"ryuki-request-read-test-action-registry-v1",
                principal_id.as_uuid().as_bytes(),
            ),
            maximum_authority_version: BindingVersion::new(1)
                .expect("positive test maximum-authority version"),
            maximum_authority_digest: BindingDigest::sha256(
                b"ryuki-request-read-test-maximum-authority-v1",
                principal_id.as_uuid().as_bytes(),
            ),
            provider_id: "provider:test-fixture".into(),
            provider_configuration_version: BindingVersion::new(1)
                .expect("positive test provider version"),
            provider_lifecycle_version: BindingVersion::new(1)
                .expect("positive test provider lifecycle version"),
            credential_source_provider: "test-fixture".into(),
        };
        let principal = RequestReadPrincipal::TestFixture {
            actor_kind: ActorKind::VerifiedHuman,
            principal_id,
            site_scope: session.site_scope.clone(),
            environment_scope: session.environment_scope.clone(),
            policy_roles,
        };
        let evidence = CredentialEvidence {
            kind: CredentialKind::TestFixture,
            window: RequestReadCredentialWindow::new(
                1,
                now,
                now,
                now + chrono::Duration::hours(1),
                AssuranceLevel::MultiFactor,
                now + chrono::Duration::hours(1),
            )
            .expect("valid test credential interval"),
            digests: RequestReadCredentialDigests::new(
                digest_parts(
                    b"ryuki-request-read-test-credential-v1",
                    &[principal_id.as_uuid().as_bytes()],
                ),
                digest_parts(
                    b"ryuki-request-read-test-audience-v1",
                    &[session.provider_mode.as_bytes()],
                ),
                digest_parts(
                    b"ryuki-request-read-test-key-v1",
                    &[session.display_name.as_bytes()],
                ),
            )
            .expect("non-zero test credential digests"),
        };
        Self::seal(
            namespace,
            principal,
            evidence,
            RevalidationSource::TestFixture,
        )
    }

    fn seal(
        namespace: RequestReadNamespace,
        principal: RequestReadPrincipal,
        credential: CredentialEvidence,
        revalidation: RevalidationSource,
    ) -> Self {
        let session_binding_digest =
            binding_digest(&namespace, &principal, &credential, &revalidation);
        Self {
            namespace,
            principal,
            credential,
            revalidation,
            session_binding_digest,
        }
    }

    /// Revalidate credential and authority state before resolving the request
    /// row. The returned receipt is intentionally opaque; the raw authority
    /// cannot produce kernel principal evidence without it.
    pub(crate) async fn prepare_request_row_lookup_tx<'authority>(
        &'authority self,
        tx: &mut Transaction<'_, Postgres>,
        now: DateTime<Utc>,
    ) -> Result<RevalidatedRequestReadAuthority<'authority>, RequestAuthorityError> {
        self.ensure_time_current(now)?;
        match (&self.principal, &self.revalidation) {
            (
                RequestReadPrincipal::Interactive(principal),
                RevalidationSource::PersistedSession(session),
            ) => revalidate_persisted_session(tx, principal, session, now).await?,
            (RequestReadPrincipal::Interactive(principal), RevalidationSource::DirectFederated) => {
                revalidate_direct_federated(tx, principal).await?
            }
            (_, RevalidationSource::DevelopmentFixture) => {
                return Err(RequestAuthorityError::InvalidBinding(
                    "development fixture cannot enter a database reader",
                ));
            }
            #[cfg(test)]
            (_, RevalidationSource::TestFixture) => {}
            _ => {
                return Err(RequestAuthorityError::InvalidBinding(
                    "credential revalidation kind",
                ));
            }
        }
        Ok(RevalidatedRequestReadAuthority { authority: self })
    }

    /// Admit only the explicit non-production, no-database fixture.
    pub(crate) fn prepare_local_request_lookup(
        &self,
        now: DateTime<Utc>,
    ) -> Result<RevalidatedRequestReadAuthority<'_>, RequestAuthorityError> {
        self.ensure_time_current(now)?;
        let admitted = matches!(self.revalidation, RevalidationSource::DevelopmentFixture);
        #[cfg(test)]
        let admitted = admitted || matches!(self.revalidation, RevalidationSource::TestFixture);
        if !admitted || self.namespace.profile == DeploymentProfile::Production {
            return Err(RequestAuthorityError::InvalidBinding(
                "local request lookup requires a development fixture",
            ));
        }
        Ok(RevalidatedRequestReadAuthority { authority: self })
    }

    fn ensure_time_current(&self, now: DateTime<Utc>) -> Result<(), RequestAuthorityError> {
        let window = self.credential.window;
        if now < window.not_before
            || now < window.authenticated_at
            || now >= window.expires_at
            || now >= window.assurance_expires_at
        {
            return Err(RequestAuthorityError::StaleCredential);
        }
        if let RequestReadPrincipal::Interactive(principal) = &self.principal {
            if principal
                .identity_last_asserted_at
                .is_some_and(|asserted_at| asserted_at > now)
                || principal
                    .identity_fresh_until
                    .is_some_and(|fresh_until| now >= fresh_until)
            {
                return Err(RequestAuthorityError::StaleCredential);
            }
        }
        Ok(())
    }

    fn kernel_evidence(&self) -> RequestReadKernelEvidence {
        RequestReadKernelEvidence {
            profile: self.namespace.profile,
            expected_authority: RequestReadExpectedAuthority {
                deployment_id: self.namespace.deployment_id.clone(),
                trust_domain_id: self.namespace.trust_domain_id.clone(),
                tenant_id: self.namespace.tenant_id.clone(),
                provider_id: self.namespace.provider_id.clone(),
                provider_configuration_version: self.namespace.provider_configuration_version,
                provider_lifecycle_version: self.namespace.provider_lifecycle_version,
            },
            policy_version: self.namespace.policy_version,
            policy_digest: self.namespace.policy_digest,
            action_registry_version: self.namespace.action_registry_version,
            action_registry_digest: self.namespace.action_registry_digest,
            maximum_authority_version: self.namespace.maximum_authority_version,
            maximum_authority_digest: self.namespace.maximum_authority_digest,
        }
    }

    pub(crate) fn deployment_id(&self) -> &str {
        &self.namespace.deployment_id
    }

    pub(crate) fn trust_domain_id(&self) -> &str {
        &self.namespace.trust_domain_id
    }

    pub(crate) fn tenant_id(&self) -> Option<&str> {
        self.namespace.tenant_id.as_deref()
    }
}

impl fmt::Debug for RequestReadAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestReadAuthority")
            .field("deployment_id", &self.namespace.deployment_id)
            .field("trust_domain_id", &self.namespace.trust_domain_id)
            .field("credential_kind", &self.credential.kind)
            .field("credential", &"<redacted>")
            .field("session_binding_digest", &"<redacted>")
            .finish()
    }
}

/// Receipt proving the repository revalidated this authority immediately
/// before its private row resolver. It cannot be built by a handler.
pub(crate) struct RevalidatedRequestReadAuthority<'authority> {
    authority: &'authority RequestReadAuthority,
}

impl RevalidatedRequestReadAuthority<'_> {
    /// Prove that audit attribution is the exact session projection carried by
    /// this revalidated credential authority. Authorization and audit may not
    /// independently name different principals, carriers, roles, or scopes.
    pub(crate) fn ensure_audit_session(
        &self,
        session: &AuthSession,
    ) -> Result<(), RequestAuthorityError> {
        let matches = match &self.authority.principal {
            RequestReadPrincipal::Interactive(principal) => {
                session.token_valid
                    && session.actor_class == ActorClass::VerifiedHuman
                    && session.principal_id == Some(principal.principal_id)
                    && session.provider_mode == principal.carrier_mode.as_str()
                    && session.roles.as_slice() == principal.roles.as_slice()
                    && session.site_scope.as_slice() == principal.site_scope.as_slice()
                    && session.environment_scope.as_slice()
                        == principal.environment_scope.as_slice()
            }
            RequestReadPrincipal::DevelopmentFixture {
                site_scope,
                environment_scope,
                ..
            } => {
                !session.token_valid
                    && session.actor_class == ActorClass::Simulated
                    && session.provider_mode == "static-dry-run"
                    && session.principal_id.is_none()
                    && session.site_scope.as_slice() == site_scope.as_slice()
                    && session.environment_scope.as_slice() == environment_scope.as_slice()
                    && ryuki_engine::auth::check_permission(session, "admin")
            }
            #[cfg(test)]
            RequestReadPrincipal::TestFixture {
                principal_id,
                site_scope,
                environment_scope,
                policy_roles,
                ..
            } => {
                let expected_principal = session
                    .principal_id
                    .unwrap_or_else(development_fixture_principal_id);
                expected_principal == *principal_id
                    && session.site_scope.as_slice() == site_scope.as_slice()
                    && session.environment_scope.as_slice() == environment_scope.as_slice()
                    && policy_roles_for_session(session) == *policy_roles
            }
        };
        if matches {
            Ok(())
        } else {
            Err(RequestAuthorityError::InvalidBinding(
                "audit session differs from request-read authority",
            ))
        }
    }

    /// Return the exact audit projection for this revalidated authority. The
    /// credential-free development fixture has no external session principal,
    /// so the authority supplies its fixed internal fixture principal only
    /// after the original session has passed [`Self::ensure_audit_session`].
    pub(crate) fn audit_session(
        &self,
        session: &AuthSession,
    ) -> Result<AuthSession, RequestAuthorityError> {
        self.ensure_audit_session(session)?;
        let mut attributed = session.clone();
        match &self.authority.principal {
            RequestReadPrincipal::DevelopmentFixture { principal_id, .. } => {
                attributed.principal_id = Some(*principal_id);
            }
            #[cfg(test)]
            RequestReadPrincipal::TestFixture { principal_id, .. } => {
                attributed.principal_id = Some(*principal_id);
            }
            RequestReadPrincipal::Interactive(_) => {}
        }
        Ok(attributed)
    }

    pub(crate) fn kernel_evidence(&self) -> RequestReadKernelEvidence {
        self.authority.kernel_evidence()
    }

    pub(crate) fn principal_evidence(
        &self,
        requested_expires_at: DateTime<Utc>,
    ) -> Result<RequestReadPrincipalEvidence, RequestAuthorityError> {
        let authority = self.authority;
        let window = authority.credential.window;
        let mut expires_at = [
            requested_expires_at,
            window.expires_at,
            window.assurance_expires_at,
        ]
        .into_iter()
        .min()
        .expect("credential expiry set is non-empty");
        if let RequestReadPrincipal::Interactive(principal) = &authority.principal {
            if let Some(identity_fresh_until) = principal.identity_fresh_until {
                expires_at = expires_at.min(identity_fresh_until);
            }
        }
        let (actor_kind, principal_id, lifecycle_version, authority_version, scopes, policy_roles) =
            match &authority.principal {
                RequestReadPrincipal::Interactive(principal) => (
                    ActorKind::VerifiedHuman,
                    principal.principal_id,
                    principal.principal_lifecycle_version,
                    principal.principal_authority_version,
                    (
                        explicit_scope(principal.site_mode, &principal.site_scope)?,
                        explicit_scope(principal.environment_mode, &principal.environment_scope)?,
                    ),
                    principal.policy_roles.clone(),
                ),
                RequestReadPrincipal::DevelopmentFixture {
                    principal_id,
                    site_scope,
                    environment_scope,
                } => (
                    ActorKind::DevelopmentFixture,
                    *principal_id,
                    authority.namespace.provider_lifecycle_version,
                    authority.namespace.provider_configuration_version,
                    (
                        fixture_scope(site_scope)?,
                        fixture_scope(environment_scope)?,
                    ),
                    BTreeSet::from([PolicyRole::PlatformAdministrator]),
                ),
                #[cfg(test)]
                RequestReadPrincipal::TestFixture {
                    actor_kind,
                    principal_id,
                    site_scope,
                    environment_scope,
                    policy_roles,
                } => (
                    *actor_kind,
                    *principal_id,
                    authority.namespace.provider_lifecycle_version,
                    authority.namespace.provider_configuration_version,
                    (
                        fixture_scope(site_scope)?,
                        fixture_scope(environment_scope)?,
                    ),
                    policy_roles.clone(),
                ),
            };

        Ok(RequestReadPrincipalEvidence {
            actor_kind,
            principal_id,
            deployment_id: authority.namespace.deployment_id.clone(),
            trust_domain_id: authority.namespace.trust_domain_id.clone(),
            tenant_id: authority.namespace.tenant_id.clone(),
            credential_id: format!(
                "credential:sha256:{}",
                lowercase_hex(&authority.session_binding_digest)
            ),
            credential_version: window.credential_version,
            provider_id: authority.namespace.provider_id.clone(),
            provider_configuration_version: authority.namespace.provider_configuration_version,
            provider_lifecycle_version: authority.namespace.provider_lifecycle_version,
            credential_expires_at: window.expires_at,
            assurance: window.assurance,
            audience_digest: BindingDigest::from_bytes(authority.credential.digests.audience),
            key_id_digest: BindingDigest::from_bytes(authority.credential.digests.key_id),
            authenticated_at: window.authenticated_at,
            assurance_expires_at: window.assurance_expires_at,
            lifecycle_version,
            authority_version,
            site_scope: scopes.0,
            environment_scope: scopes.1,
            policy_roles,
            expires_at,
        })
    }

    pub(crate) fn deployment_id(&self) -> &str {
        self.authority.deployment_id()
    }

    pub(crate) fn trust_domain_id(&self) -> &str {
        self.authority.trust_domain_id()
    }

    pub(crate) fn tenant_id(&self) -> Option<&str> {
        self.authority.tenant_id()
    }
}

async fn revalidate_persisted_session(
    tx: &mut Transaction<'_, Postgres>,
    principal: &InteractiveRequestReadPrincipal,
    credential: &PersistedSessionCredential,
    now: DateTime<Utc>,
) -> Result<(), RequestAuthorityError> {
    prepare_authority_reader(tx, principal).await?;
    let matched = sqlx::query_scalar::<_, i32>(
        "SELECT 1 \
         FROM sessions s \
         JOIN principal_keys k \
           ON k.principal_key_id = s.principal_key_id \
          AND k.key_version = s.principal_key_version \
         JOIN principal_links l \
           ON l.principal_link_id = s.principal_link_id \
          AND l.link_version = s.principal_link_version \
          AND l.principal_key_id = s.principal_key_id \
          AND l.principal_id = s.principal_id \
         JOIN principals p \
           ON p.principal_id = s.principal_id \
          AND p.lifecycle_version = s.principal_lifecycle_version \
          AND p.authority_version = s.principal_authority_version \
         WHERE s.session_record_id = $1 \
           AND s.bearer_verifier = $2 \
           AND s.principal_id = $3 \
           AND s.principal_lifecycle_version = $4 \
           AND s.principal_authority_version = $5 \
           AND s.principal_key_id = $6 \
           AND s.principal_key_version = $7 \
           AND s.principal_link_id = $8 \
           AND s.principal_link_version = $9 \
           AND s.roles = $10 \
           AND s.created_at = $11 \
           AND s.expires_at = $12 \
           AND s.expires_at > $13 \
           AND k.provider_id = $14 \
           AND k.issuer = $15 \
           AND k.subject = $16 \
           AND k.key_state = 'active' \
           AND l.link_state = 'active' \
           AND p.lifecycle_state = 'active' \
           AND $10::TEXT[] <@ p.role_allowlist \
           AND s.site_authority_mode = $17 \
           AND s.site_scope = $18 \
           AND s.environment_authority_mode = $19 \
           AND s.environment_scope = $20 \
           AND (p.site_authority_mode = 'global' OR ( \
                p.site_authority_mode = 'scoped' \
                AND $17 = 'scoped' \
                AND $18::TEXT[] <@ p.site_scope)) \
           AND (p.environment_authority_mode = 'global' OR ( \
                p.environment_authority_mode = 'scoped' \
                AND $19 = 'scoped' \
                AND $20::TEXT[] <@ p.environment_scope)) \
           AND NOT EXISTS ( \
               SELECT 1 FROM principal_provider_tombstones t \
               WHERE t.provider_id = k.provider_id \
           ) \
           AND NOT EXISTS ( \
               SELECT 1 FROM principal_key_tombstones t \
               WHERE t.principal_key_id = k.principal_key_id \
           ) \
         FOR SHARE OF s, k, l, p",
    )
    .bind(credential.session_record_id)
    .bind(credential.bearer_verifier_digest.as_slice())
    .bind(principal.principal_id.into_uuid())
    .bind(version_i64(principal.principal_lifecycle_version)?)
    .bind(version_i64(principal.principal_authority_version)?)
    .bind(principal.principal_key_id)
    .bind(version_i64(principal.principal_key_version)?)
    .bind(principal.principal_link_id)
    .bind(version_i64(principal.principal_link_version)?)
    .bind(&principal.roles)
    .bind(credential.created_at)
    .bind(credential.window.expires_at)
    .bind(now)
    .bind(&principal.source_provider)
    .bind(&principal.source_issuer)
    .bind(&principal.source_subject)
    .bind(principal.site_mode.as_db())
    .bind(&principal.site_scope)
    .bind(principal.environment_mode.as_db())
    .bind(&principal.environment_scope)
    .fetch_optional(&mut **tx)
    .await?;
    if matched.is_none() {
        return Err(RequestAuthorityError::StaleCredential);
    }
    Ok(())
}

async fn revalidate_direct_federated(
    tx: &mut Transaction<'_, Postgres>,
    principal: &InteractiveRequestReadPrincipal,
) -> Result<(), RequestAuthorityError> {
    prepare_authority_reader(tx, principal).await?;
    let matched = sqlx::query_scalar::<_, i32>(
        "SELECT 1 \
         FROM principal_keys k \
         JOIN principal_links l \
           ON l.principal_key_id = k.principal_key_id \
         JOIN principals p \
           ON p.principal_id = l.principal_id \
         WHERE k.provider_id = $1 \
           AND k.issuer = $2 \
           AND k.subject = $3 \
           AND k.principal_key_id = $4 \
           AND k.key_version = $5 \
           AND k.key_state = 'active' \
           AND l.principal_link_id = $6 \
           AND l.link_version = $7 \
           AND l.link_state = 'active' \
           AND p.principal_id = $8 \
           AND p.lifecycle_version = $9 \
           AND p.authority_version = $10 \
           AND p.lifecycle_state = 'active' \
           AND $11::TEXT[] <@ p.role_allowlist \
           AND (p.site_authority_mode = 'global' OR ( \
                p.site_authority_mode = 'scoped' \
                AND $12 = 'scoped' \
                AND $13::TEXT[] <@ p.site_scope)) \
           AND (p.environment_authority_mode = 'global' OR ( \
                p.environment_authority_mode = 'scoped' \
                AND $14 = 'scoped' \
                AND $15::TEXT[] <@ p.environment_scope)) \
           AND NOT EXISTS ( \
               SELECT 1 FROM principal_provider_tombstones t \
               WHERE t.provider_id = k.provider_id \
           ) \
           AND NOT EXISTS ( \
               SELECT 1 FROM principal_key_tombstones t \
               WHERE t.principal_key_id = k.principal_key_id \
           ) \
         FOR SHARE OF k, l, p",
    )
    .bind(&principal.source_provider)
    .bind(&principal.source_issuer)
    .bind(&principal.source_subject)
    .bind(principal.principal_key_id)
    .bind(version_i64(principal.principal_key_version)?)
    .bind(principal.principal_link_id)
    .bind(version_i64(principal.principal_link_version)?)
    .bind(principal.principal_id.into_uuid())
    .bind(version_i64(principal.principal_lifecycle_version)?)
    .bind(version_i64(principal.principal_authority_version)?)
    .bind(&principal.roles)
    .bind(principal.site_mode.as_db())
    .bind(&principal.site_scope)
    .bind(principal.environment_mode.as_db())
    .bind(&principal.environment_scope)
    .fetch_optional(&mut **tx)
    .await?;
    if matched.is_none() {
        return Err(RequestAuthorityError::StaleCredential);
    }
    Ok(())
}

async fn prepare_authority_reader(
    tx: &mut Transaction<'_, Postgres>,
    principal: &InteractiveRequestReadPrincipal,
) -> Result<(), RequestAuthorityError> {
    crate::principal_registry::prepare_reader_tx(
        tx,
        &principal.source_provider,
        &principal.source_issuer,
        &principal.source_subject,
    )
    .await
    .map_err(|error| match error {
        crate::principal_registry::PrincipalRegistryError::Database(error) => {
            RequestAuthorityError::Database(error)
        }
        crate::principal_registry::PrincipalRegistryError::NotActive
        | crate::principal_registry::PrincipalRegistryError::InvalidStoredBinding => {
            RequestAuthorityError::StaleCredential
        }
    })
}

fn validate_interactive_namespace(
    namespace: &RequestReadNamespace,
    principal: &InteractiveRequestReadPrincipal,
) -> Result<(), RequestAuthorityError> {
    if namespace.credential_source_provider != principal.source_provider {
        return Err(RequestAuthorityError::InvalidBinding(
            "credential source differs from security-contract projection",
        ));
    }
    if namespace.profile == DeploymentProfile::Production && principal.source_provider == "local" {
        return Err(RequestAuthorityError::InvalidBinding(
            "local interactive authority is not production credential authority",
        ));
    }
    Ok(())
}

fn validate_axis(mode: HumanAuthorityMode, values: &[String]) -> Result<(), RequestAuthorityError> {
    match mode {
        HumanAuthorityMode::Global if values.is_empty() => Ok(()),
        HumanAuthorityMode::Scoped
            if !values.is_empty()
                && values
                    .iter()
                    .all(|value| validate_identifier(value).is_ok()) =>
        {
            Ok(())
        }
        HumanAuthorityMode::Unknown
        | HumanAuthorityMode::Revoked
        | HumanAuthorityMode::Global
        | HumanAuthorityMode::Scoped => Err(RequestAuthorityError::InvalidBinding(
            "interactive authority scope",
        )),
    }
}

fn explicit_scope(
    mode: HumanAuthorityMode,
    values: &[String],
) -> Result<ExplicitScope, RequestAuthorityError> {
    validate_axis(mode, values)?;
    match mode {
        HumanAuthorityMode::Global => Ok(ExplicitScope::global()),
        HumanAuthorityMode::Scoped => Ok(ExplicitScope::scoped(
            values.iter().cloned().collect::<BTreeSet<_>>(),
        )?),
        HumanAuthorityMode::Unknown | HumanAuthorityMode::Revoked => Err(
            RequestAuthorityError::InvalidBinding("interactive authority scope"),
        ),
    }
}

fn fixture_scope(values: &[String]) -> Result<ExplicitScope, RequestAuthorityError> {
    if values.is_empty() {
        return Ok(ExplicitScope::global());
    }
    Ok(ExplicitScope::scoped(
        values.iter().cloned().collect::<BTreeSet<_>>(),
    )?)
}

fn policy_roles_for_session(session: &AuthSession) -> BTreeSet<PolicyRole> {
    let mut policy_roles = BTreeSet::new();
    if ryuki_engine::auth::check_permission(session, "admin") {
        policy_roles.insert(PolicyRole::PlatformAdministrator);
    }
    if ryuki_engine::auth::check_permission(session, "audit") {
        policy_roles.insert(PolicyRole::Auditor);
    }
    if ryuki_engine::auth::check_permission(session, "request") {
        policy_roles.insert(PolicyRole::Requester);
    }
    policy_roles
}

fn positive_i64_version(value: i64) -> Result<BindingVersion, RequestAuthorityError> {
    let value = u64::try_from(value)
        .map_err(|_| RequestAuthorityError::InvalidBinding("authority version"))?;
    Ok(BindingVersion::new(value)?)
}

fn development_fixture_principal_id() -> PrincipalId {
    PrincipalId::from_uuid(Uuid::from_u128(DEVELOPMENT_FIXTURE_PRINCIPAL_UUID))
        .expect("the development-fixture principal UUID is non-nil")
}

fn version_i64(version: BindingVersion) -> Result<i64, RequestAuthorityError> {
    i64::try_from(version.get())
        .map_err(|_| RequestAuthorityError::InvalidBinding("authority version"))
}

fn validate_identifier(value: &str) -> Result<(), RequestAuthorityError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(RequestAuthorityError::InvalidBinding("identifier"));
    }
    Ok(())
}

fn binding_digest(
    namespace: &RequestReadNamespace,
    principal: &RequestReadPrincipal,
    credential: &CredentialEvidence,
    revalidation: &RevalidationSource,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, SESSION_BINDING_DIGEST_DOMAIN);
    hash_str(&mut hasher, &namespace.deployment_id);
    hash_str(&mut hasher, &namespace.trust_domain_id);
    hash_optional_str(&mut hasher, namespace.tenant_id.as_deref());
    hash_str(&mut hasher, &namespace.provider_id);
    hash_u64(&mut hasher, namespace.provider_configuration_version.get());
    hash_u64(&mut hasher, namespace.provider_lifecycle_version.get());
    hash_str(&mut hasher, &namespace.credential_source_provider);
    match principal {
        RequestReadPrincipal::Interactive(principal) => {
            hash_u64(&mut hasher, 1);
            hash_uuid(&mut hasher, principal.principal_id.as_uuid());
            hash_u64(&mut hasher, principal.principal_lifecycle_version.get());
            hash_u64(&mut hasher, principal.principal_authority_version.get());
            hash_uuid(&mut hasher, &principal.principal_key_id);
            hash_u64(&mut hasher, principal.principal_key_version.get());
            hash_uuid(&mut hasher, &principal.principal_link_id);
            hash_u64(&mut hasher, principal.principal_link_version.get());
            hash_str(&mut hasher, &principal.carrier_mode);
            hash_str(&mut hasher, &principal.source_provider);
            hash_str(&mut hasher, &principal.source_issuer);
            hash_str(&mut hasher, &principal.source_subject);
            hash_bytes(&mut hasher, &principal.identity_authority_digest);
            hash_optional_time(&mut hasher, principal.identity_last_asserted_at);
            hash_optional_time(&mut hasher, principal.identity_fresh_until);
            hash_strings(&mut hasher, &principal.roles);
            hash_str(&mut hasher, principal.site_mode.as_db());
            hash_strings(&mut hasher, &principal.site_scope);
            hash_str(&mut hasher, principal.environment_mode.as_db());
            hash_strings(&mut hasher, &principal.environment_scope);
        }
        RequestReadPrincipal::DevelopmentFixture {
            principal_id,
            site_scope,
            environment_scope,
        } => {
            hash_u64(&mut hasher, 2);
            hash_uuid(&mut hasher, principal_id.as_uuid());
            hash_strings(&mut hasher, site_scope);
            hash_strings(&mut hasher, environment_scope);
        }
        #[cfg(test)]
        RequestReadPrincipal::TestFixture {
            actor_kind,
            principal_id,
            site_scope,
            environment_scope,
            policy_roles,
        } => {
            hash_u64(&mut hasher, 3);
            hash_u64(&mut hasher, *actor_kind as u64);
            hash_uuid(&mut hasher, principal_id.as_uuid());
            hash_strings(&mut hasher, site_scope);
            hash_strings(&mut hasher, environment_scope);
            for role in policy_roles {
                hash_u64(&mut hasher, *role as u64);
            }
        }
    }
    hash_u64(
        &mut hasher,
        match credential.kind {
            CredentialKind::PersistedSession => 1,
            CredentialKind::DirectFederated => 2,
            CredentialKind::DevelopmentFixture => 3,
            #[cfg(test)]
            CredentialKind::TestFixture => 4,
        },
    );
    hash_bytes(&mut hasher, &credential.digests.credential_id);
    hash_bytes(&mut hasher, &credential.digests.audience);
    hash_bytes(&mut hasher, &credential.digests.key_id);
    hash_u64(&mut hasher, credential.window.credential_version.get());
    hash_time(&mut hasher, credential.window.authenticated_at);
    hash_time(&mut hasher, credential.window.not_before);
    hash_time(&mut hasher, credential.window.expires_at);
    hash_u64(&mut hasher, assurance_code(credential.window.assurance));
    hash_time(&mut hasher, credential.window.assurance_expires_at);
    match revalidation {
        RevalidationSource::PersistedSession(session) => {
            hash_u64(&mut hasher, 1);
            hash_bytes(&mut hasher, session.session_record_id.as_bytes());
            hash_bytes(&mut hasher, &session.bearer_verifier_digest);
            hash_time(&mut hasher, session.created_at);
        }
        RevalidationSource::DirectFederated => hash_u64(&mut hasher, 2),
        RevalidationSource::DevelopmentFixture => hash_u64(&mut hasher, 3),
        #[cfg(test)]
        RevalidationSource::TestFixture => hash_u64(&mut hasher, 4),
    }
    hasher.finalize().into()
}

const fn assurance_code(assurance: AssuranceLevel) -> u64 {
    match assurance {
        AssuranceLevel::SingleFactor => 1,
        AssuranceLevel::MultiFactor => 2,
        AssuranceLevel::PhishingResistant => 3,
    }
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, domain);
    for part in parts {
        hash_bytes(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_uuid(hasher: &mut Sha256, value: &Uuid) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn hash_time(hasher: &mut Sha256, value: DateTime<Utc>) {
    hasher.update(value.timestamp().to_be_bytes());
    hasher.update(value.timestamp_subsec_nanos().to_be_bytes());
}

fn hash_optional_time(hasher: &mut Sha256, value: Option<DateTime<Utc>>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_time(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_optional_str(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_str(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_strings(hasher: &mut Sha256, values: &[String]) {
    hash_u64(hasher, values.len() as u64);
    for value in values {
        hash_str(hasher, value);
    }
}

fn lowercase_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal_registry::PrincipalBinding;
    use ryuki_engine::auth::{ActorClass, APP_ROLE_REQUESTER};

    fn principal(value: u128) -> PrincipalId {
        PrincipalId::from_uuid(Uuid::from_u128(value)).expect("non-nil test principal")
    }

    fn binding(principal_id: PrincipalId, key: u128, link: u128) -> PrincipalBinding {
        PrincipalBinding {
            principal_id,
            principal_lifecycle_version: 3,
            principal_authority_version: 7,
            principal_key_id: Uuid::from_u128(key),
            principal_key_version: 5,
            principal_link_id: Uuid::from_u128(link),
            principal_link_version: 11,
        }
    }

    fn context(
        principal_binding: PrincipalBinding,
        provider: &str,
        subject: &str,
    ) -> InteractiveHumanAuthorityContext {
        InteractiveHumanAuthorityContext {
            principal_binding,
            provider: provider.to_string(),
            issuer: "https://issuer.example.test".to_string(),
            subject: subject.to_string(),
            identity_epoch: principal_binding.principal_lifecycle_version,
            assignment_version: principal_binding.principal_authority_version,
            roles: vec![APP_ROLE_REQUESTER.to_string()],
            site_mode: HumanAuthorityMode::Global,
            site_scope: Vec::new(),
            environment_mode: HumanAuthorityMode::Global,
            environment_scope: Vec::new(),
        }
    }

    fn session(principal_id: PrincipalId, provider: &str) -> AuthSession {
        AuthSession {
            principal_id: Some(principal_id),
            display_user_id: principal_id.to_string(),
            display_name: "Opaque principal".to_string(),
            roles: vec![APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            provider_mode: provider.to_string(),
            actor_class: ActorClass::VerifiedHuman,
            site_scope: Vec::new(),
            environment_scope: Vec::new(),
        }
    }

    #[test]
    fn provider_subject_never_substitutes_for_registry_principal() {
        let now = Utc::now();
        let internal = principal(1);
        let authority = context(binding(internal, 2, 3), "oidc-primary", "shared-subject");
        let admitted = InteractiveRequestReadPrincipal::new(
            &session(internal, "oidc-primary"),
            &authority,
            [7; 32],
            Some(now),
            Some(now + chrono::Duration::minutes(10)),
        )
        .expect("registry binding is admitted independently of source subject");

        assert_eq!(admitted.principal_id, internal);
        assert_eq!(admitted.source_subject, "shared-subject");
        assert_ne!(admitted.principal_id.to_string(), admitted.source_subject);
    }

    #[test]
    fn equal_subjects_from_distinct_providers_keep_distinct_owners() {
        let now = Utc::now();
        let first_id = principal(10);
        let second_id = principal(20);
        let first_context = context(
            binding(first_id, 11, 12),
            "oidc-primary",
            "collision-subject",
        );
        let second_context = context(binding(second_id, 21, 22), "entra-id", "collision-subject");

        let first = InteractiveRequestReadPrincipal::new(
            &session(first_id, "oidc-primary"),
            &first_context,
            [1; 32],
            Some(now),
            Some(now + chrono::Duration::minutes(10)),
        )
        .expect("first provider binding");
        let second = InteractiveRequestReadPrincipal::new(
            &session(second_id, "entra-id"),
            &second_context,
            [2; 32],
            Some(now),
            Some(now + chrono::Duration::minutes(10)),
        )
        .expect("second provider binding");

        assert_eq!(first.source_subject, second.source_subject);
        assert_ne!(first.source_provider, second.source_provider);
        assert_ne!(first.principal_id, second.principal_id);
    }

    #[test]
    fn session_principal_must_equal_the_registry_binding() {
        let now = Utc::now();
        let bound = principal(30);
        let substituted = principal(31);
        let authority = context(binding(bound, 32, 33), "oidc-primary", "subject");

        let error = InteractiveRequestReadPrincipal::new(
            &session(substituted, "oidc-primary"),
            &authority,
            [3; 32],
            Some(now),
            Some(now + chrono::Duration::minutes(10)),
        )
        .expect_err("session substitution must fail closed");

        assert!(matches!(error, RequestAuthorityError::InvalidBinding(_)));
    }
}
