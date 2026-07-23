//! Immutable ownership boundary for every process-local human authenticator.
//!
//! Authentication used to construct its Entra bearer validator, generic OIDC
//! callback dependencies, Entra browser-SSO dependencies, and local-login
//! throttle independently while composing the router.  That made it possible
//! to measure one object at startup while requests used another.  This module
//! constructs those objects once and retains them under one `Arc` so a later
//! production guard can attest the exact runtime used by every consumer.

use std::fmt;
use std::sync::Arc;

use ryuki_core::config::{AuthMode, RyukiConfig};
#[cfg(test)]
use ryuki_core::security_profile::ProviderLifecycleState;
use ryuki_core::security_profile::{
    authenticator_browser_state_authority_binding_digest,
    authenticator_cache_partition_binding_digest, authenticator_inventory_digest,
    authenticator_origin_binding_digest, authenticator_protocol_binding_digest,
    authenticator_runtime_binding_digest, validate_authenticator_runtime_path_preimages,
    AuthenticatorBrowserClientAuthentication, AuthenticatorBrowserExchangeAuthorityProjection,
    AuthenticatorBrowserStateAuthorityProjection, AuthenticatorCacheKind,
    AuthenticatorCachePartitionProjection, AuthenticatorCredentialCarrier,
    AuthenticatorCredentialProfileRuntimeProjection, AuthenticatorCredentialReuse,
    AuthenticatorDerivedSessionAuthorityProjection, AuthenticatorKeySourceKind,
    AuthenticatorNonceBinding, AuthenticatorOriginProjection,
    AuthenticatorPresentationReplayDefense, AuthenticatorProofBinding,
    AuthenticatorProtocolBindingProjection, AuthenticatorReplayRuntimeProjection,
    AuthenticatorRuntimeBindingProjection, AuthenticatorRuntimeOwnership,
    AuthenticatorRuntimePathIdentityProjection, AuthenticatorRuntimePathProjection,
    AuthenticatorRuntimePathRole, AuthenticatorSenderConstraint,
    AuthenticatorVerifierRuntimeProjection, ExpectedAuthenticatorBinding, ExpectedProviderBinding,
    ProductionAuthenticatorKind, RuntimeGuardExpectedValue, AUTHENTICATOR_BROWSER_PKCE_METHOD_S256,
    AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID,
    AUTHENTICATOR_BROWSER_STATE_CONSUME_OPERATION, AUTHENTICATOR_BROWSER_STATE_CONTRACT_SETTING,
    AUTHENTICATOR_BROWSER_STATE_CONTRACT_VERSION, AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID,
    AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS, AUTHENTICATOR_BROWSER_STATE_RELATION_V3,
    AUTHENTICATOR_DERIVED_SESSION_CREDENTIAL_FORMAT, AUTHENTICATOR_DERIVED_SESSION_RELATION,
    AUTHENTICATOR_DERIVED_SESSION_VERIFIER_ALGORITHM,
    AUTHENTICATOR_DERIVED_SESSION_VERIFIER_COLUMN_V3,
    AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::contracts::LocalLoginThrottle;
use crate::cookie_runtime::{
    ApiCookieRuntime, ApiCookieRuntimeObservation, ApiCookieRuntimeObservationMode,
};
use crate::entra_auth::{
    EntraBearerKeySourceKind, EntraBearerRuntimeObservation, EntraTokenValidator,
};
use crate::entra_sso::{EntraSsoDeps, EntraSsoRuntimeObservation};
use crate::oidc_callback::{
    OidcCallbackDeps, OidcIdTokenKeySourceKind, OidcIdTokenValidator, ReqwestTokenExchanger,
    TokenExchanger,
};
use crate::security_contracts::{
    ResolvedAuthenticatorBearerLimits, ResolvedAuthenticatorBrowserLimits,
    ResolvedEntraAuthenticatorAuthority,
};
use crate::session_credentials::{
    DerivedSessionCredentialRuntime, DerivedSessionRuntimeObservation,
};

const DISABLED_OIDC_TOKEN_ENDPOINT: &str = "https://disabled.invalid/token";
const DISABLED_OIDC_JWKS_ENDPOINT: &str = "https://disabled.invalid/jwks";
const DISABLED_OIDC_ISSUER: &str = "https://disabled.invalid/issuer";
const DISABLED_OIDC_AUDIENCE: &str = "disabled";
const GENERIC_OIDC_NOT_ADMITTED: &str =
    "generic OIDC is not admitted until one exact D/P/Q/R runtime authority is implemented; keep RYUKI_OIDC__ENABLED=false";
const OIDC_CLOCK_SKEW_SECONDS: u64 = 60;
const AUTHENTICATOR_LEAF_DIGEST_CONTRACT: &[u8] = b"ryuki-authenticator-runtime-leaf-binding-v1";

const ENTRA_BEARER_PATH_ID: &str = "authenticator-path:api-bearer";
const ENTRA_BEARER_PATH_VERSION: u64 = 1;
const ENTRA_BEARER_VERIFIER_ID: &str = "authenticator-verifier:api-bearer";
const ENTRA_BEARER_VERIFIER_VERSION: u64 = 1;
const ENTRA_BEARER_PROFILE_ID: &str = "credential-profile:api-bearer";
const ENTRA_BEARER_PROFILE_VERSION: u64 = 1;
const ENTRA_BEARER_CONSUMER_ID: &str = "runtime-consumer:entra-bearer-request-admission";
const ENTRA_BEARER_CACHE_OWNER_ID: &str = "authenticator-cache-owner:api-bearer";
const ENTRA_BEARER_CACHE_PARTITION_ID: &str = "authenticator-cache-partition:api-bearer";

const ENTRA_BROWSER_PATH_ID: &str = "authenticator-path:browser-sso";
const ENTRA_BROWSER_PATH_VERSION: u64 = 1;
const ENTRA_BROWSER_VERIFIER_ID: &str = "authenticator-verifier:browser-sso";
const ENTRA_BROWSER_VERIFIER_VERSION: u64 = 1;
const ENTRA_BROWSER_PROFILE_ID: &str = "credential-profile:browser-sso";
const ENTRA_BROWSER_PROFILE_VERSION: u64 = 1;
const ENTRA_BROWSER_CONSUMER_ID: &str = "runtime-consumer:entra-browser-sso";
const ENTRA_BROWSER_CACHE_OWNER_ID: &str = "authenticator-cache-owner:browser-sso";
const ENTRA_BROWSER_CACHE_PARTITION_ID: &str = "authenticator-cache-partition:browser-sso";
const ENTRA_BROWSER_EXCHANGE_AUTHORITY_ID: &str = "authenticator-exchange-authority:oidc-browser";
const ENTRA_BROWSER_EXCHANGE_AUTHORITY_VERSION: u64 = 2;
const ENTRA_BROWSER_STATE_AUTHORITY_ID: &str = "authenticator-state-authority:oidc-login-state";
const ENTRA_BROWSER_STATE_AUTHORITY_VERSION: u64 = 3;
const ENTRA_BROWSER_SESSION_AUTHORITY_ID: &str = "authenticator-session-authority:browser-session";
const ENTRA_BROWSER_SESSION_AUTHORITY_VERSION: u64 = 3;
const ENTRA_ISSUER_AUTHORITY_BINDING_DOMAIN: &[u8] = b"entra-issuer-authority-binding";
const DIRECT_BEARER_PATH_KIND: &str = "bearer";
const BROWSER_DERIVED_SESSION_PATH_KIND: &str = "browser-derived-session";

const GENERIC_OIDC_ISSUER_AUTHORITY_BINDING_DOMAIN: &[u8] =
    b"generic-oidc-issuer-authority-binding";
const GENERIC_OIDC_AUDIENCE_CLIENT_BINDING_DOMAIN: &[u8] = b"generic-oidc-audience-client-binding";

/// Closed classification of the authentication mode owned by this runtime.
///
/// Only `EntraOidc` describes a currently implemented production posture.
/// The other variants remain observable so development keeps working, but
/// cannot be confused with a production authenticator during admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProductionAuthenticatorPosture {
    EntraOidc,
    CredentialFreeMockDryRun,
    CredentialFreeStaticDryRun,
    PasswordLocal,
}

/// Current process-local consumers of the authenticator owner.
///
/// This list is intentionally closed to implementations that exist in this
/// binary. Broker, passkey, service-principal, API-token, and workload
/// authenticators must not appear until they have their own runtime owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticatorRuntimeConsumer {
    EntraBearerRequestAdmission,
    EntraBrowserSso,
    GenericOidcBrowserCallback,
    LocalPasswordLogin,
    CredentialFreeRequestAdmission,
}

/// The client-authentication mechanism actually used by the generic browser
/// callback. Only presence is retained; credential material is never copied
/// into the observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenericOidcClientAuthentication {
    Disabled,
    ClientSecretPost { credential_present: bool },
}

/// Closed verifier algorithm policy implemented by both current OIDC paths.
/// A free-form algorithm label would let a future caller claim policy that the
/// retained validators do not actually enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticatorSignatureAlgorithm {
    Rs256,
}

/// Independently measured, non-secret leaves of the exact retained runtime.
///
/// The binding digests are computed here from admitted configuration using
/// distinct domains. They are neither caller-supplied expected values nor an
/// aggregate authenticator-inventory digest. Raw issuer, authority, tenant,
/// client, object, token, and credential values are not retained.
#[derive(PartialEq, Eq)]
pub(crate) struct AuthenticatorRuntimeObservation {
    posture: ProductionAuthenticatorPosture,
    consumers: Box<[AuthenticatorRuntimeConsumer]>,
    entra_validator_observation: Option<Arc<EntraBearerRuntimeObservation>>,
    entra_browser_clock_skew_limit_id: Option<String>,
    entra_browser_maximum_clock_skew_seconds: Option<u64>,
    derived_session_observation: Arc<DerivedSessionRuntimeObservation>,
    generic_oidc_enabled: bool,
    generic_oidc_issuer_authority_binding_digest: Option<String>,
    generic_oidc_audience_client_binding_digest: Option<String>,
    generic_oidc_signature_algorithm: Option<AuthenticatorSignatureAlgorithm>,
    generic_oidc_validation_leeway_seconds: Option<u64>,
    generic_oidc_client_authentication: GenericOidcClientAuthentication,
}

impl fmt::Debug for AuthenticatorRuntimeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatorRuntimeObservation")
            .field("posture", &self.posture)
            .field("consumers", &self.consumers)
            .field("identity_bindings", &"[REDACTED]")
            .field("verifier_policy", &"[RETAINED]")
            .field("limit_authorities", &"[RETAINED]")
            .finish()
    }
}

impl AuthenticatorRuntimeObservation {
    fn measure(
        config: &RyukiConfig,
        entra_validator_observation: Option<Arc<EntraBearerRuntimeObservation>>,
        authenticator_browser_limits: Option<&ResolvedAuthenticatorBrowserLimits>,
        derived_session_observation: Arc<DerivedSessionRuntimeObservation>,
    ) -> Result<Self, String> {
        let posture = match &config.auth_mode {
            AuthMode::EntraId => ProductionAuthenticatorPosture::EntraOidc,
            AuthMode::MockDryRun => ProductionAuthenticatorPosture::CredentialFreeMockDryRun,
            AuthMode::StaticDryRun => ProductionAuthenticatorPosture::CredentialFreeStaticDryRun,
            AuthMode::Local => ProductionAuthenticatorPosture::PasswordLocal,
        };

        let exact_session_policy = derived_session_observation.as_ref();
        let configured_session_credential = !config.session.credential_hmac_key.is_empty();
        if exact_session_policy.enabled() != configured_session_credential
            || exact_session_policy.maximum_session_age_seconds()
                != config.session.cookie_max_age_secs
            || exact_session_policy.federated_authority_max_staleness_seconds()
                != config.session.federated_authority_max_staleness_secs
            || exact_session_policy.credential_format_id() != "session-credential:opaque-random-v1"
            || exact_session_policy.verifier_algorithm_id() != "hmac-sha256"
            || exact_session_policy.credential_random_bytes() != 32
            || exact_session_policy.database_representation_id()
                != "session-verifier:keyed-digest-only-v1"
            || (exact_session_policy.enabled()
                && !exact_session_policy
                    .key_identity_binding_digest()
                    .is_some_and(|digest| digest.starts_with("sha256:")))
            || (!exact_session_policy.enabled()
                && exact_session_policy.key_identity_binding_digest().is_some())
        {
            return Err(
                "retained derived-session authority does not implement the closed runtime policy"
                    .to_string(),
            );
        }

        if posture == ProductionAuthenticatorPosture::EntraOidc {
            let exact_policy = entra_validator_observation.as_deref().ok_or_else(|| {
                "Entra posture has no retained bearer validator observation".to_string()
            })?;
            if exact_policy.key_source_kind() != EntraBearerKeySourceKind::NetworkJwks
                || !exact_policy
                    .issuer_authority_binding_digest()
                    .starts_with("sha256:")
                || !exact_policy
                    .audience_client_binding_digest()
                    .starts_with("sha256:")
                || !exact_policy
                    .key_source_binding_digest()
                    .starts_with("sha256:")
                || exact_policy.jwks_ttl_seconds().is_none()
                || exact_policy.clock_skew_limit_id() != "limit:authenticator.clock-skew"
                || u32::try_from(exact_policy.maximum_clock_skew_seconds()).is_err()
                || exact_policy.credential_lifetime_limit_id()
                    != "limit:authenticator.oidc-access-token-lifetime"
                || exact_policy.maximum_credential_lifetime_seconds() == 0
                || exact_policy.accepted_algorithm_ids() != ["rs256"]
                || exact_policy.required_claim_ids()
                    != ["aud", "exp", "iat", "iss", "nbf", "oid", "sub"]
                || exact_policy.provider_subject_claim_id() != "oid"
                || !exact_policy.expiration_required()
                || !exact_policy.not_before_required()
                || !exact_policy.issued_at_required()
                || exact_policy.nonce_required()
                || exact_policy.redirects_allowed()
            {
                return Err(
                    "retained Entra bearer validator does not implement the closed runtime policy"
                        .to_string(),
                );
            }
        } else if entra_validator_observation.is_some() {
            return Err(
                "non-Entra posture cannot retain a dormant bearer validator observation".into(),
            );
        }

        let entra_browser_configured = posture == ProductionAuthenticatorPosture::EntraOidc
            && !config.entra_redirect_uri.is_empty();
        let (entra_browser_clock_skew_limit_id, entra_browser_maximum_clock_skew_seconds) = match (
            entra_browser_configured,
            authenticator_browser_limits,
        ) {
            (true, Some(limits)) => {
                limits.verify_integrity()?;
                if limits.clock_skew_limit_id() != "limit:authenticator.clock-skew"
                    || u32::try_from(limits.maximum_clock_skew_seconds()).is_err()
                {
                    return Err(
                        "retained Entra browser limits do not implement the closed runtime policy"
                            .into(),
                    );
                }
                let bearer_observation =
                    entra_validator_observation.as_deref().ok_or_else(|| {
                        "configured Entra browser path has no retained bearer observation"
                            .to_string()
                    })?;
                if bearer_observation.clock_skew_limit_id() != limits.clock_skew_limit_id()
                    || bearer_observation.maximum_clock_skew_seconds()
                        != limits.maximum_clock_skew_seconds()
                {
                    return Err(
                        "retained Entra bearer and browser paths resolve different clock-skew authority"
                            .into(),
                    );
                }
                (
                    Some(limits.clock_skew_limit_id().to_owned()),
                    Some(limits.maximum_clock_skew_seconds()),
                )
            }
            (true, None) => {
                return Err(
                    "configured Entra browser path has no retained browser-limit authority".into(),
                );
            }
            (false, Some(_)) => {
                return Err(
                    "runtime observation cannot retain dormant Entra browser-limit authority"
                        .into(),
                );
            }
            (false, None) => (None, None),
        };

        let mut consumers = match posture {
            ProductionAuthenticatorPosture::EntraOidc => {
                let mut consumers = vec![AuthenticatorRuntimeConsumer::EntraBearerRequestAdmission];
                if entra_browser_configured {
                    consumers.push(AuthenticatorRuntimeConsumer::EntraBrowserSso);
                }
                consumers
            }
            ProductionAuthenticatorPosture::CredentialFreeMockDryRun
            | ProductionAuthenticatorPosture::CredentialFreeStaticDryRun => {
                vec![AuthenticatorRuntimeConsumer::CredentialFreeRequestAdmission]
            }
            ProductionAuthenticatorPosture::PasswordLocal => {
                vec![AuthenticatorRuntimeConsumer::LocalPasswordLogin]
            }
        };
        if config.oidc.enabled {
            consumers.push(AuthenticatorRuntimeConsumer::GenericOidcBrowserCallback);
        }

        let (
            generic_oidc_issuer_authority_binding_digest,
            generic_oidc_audience_client_binding_digest,
            generic_oidc_validation_leeway_seconds,
            generic_oidc_client_authentication,
        ) = if config.oidc.enabled {
            let issuer = validated_exact_identity_url(&config.oidc.issuer, "generic OIDC issuer")?;
            (
                Some(leaf_binding_digest(
                    GENERIC_OIDC_ISSUER_AUTHORITY_BINDING_DOMAIN,
                    &[issuer.as_bytes()],
                )),
                Some(leaf_binding_digest(
                    GENERIC_OIDC_AUDIENCE_CLIENT_BINDING_DOMAIN,
                    &[config.oidc.client_id.as_bytes()],
                )),
                Some(OIDC_CLOCK_SKEW_SECONDS),
                GenericOidcClientAuthentication::ClientSecretPost {
                    credential_present: !config.oidc.client_secret.is_empty(),
                },
            )
        } else {
            (None, None, None, GenericOidcClientAuthentication::Disabled)
        };

        Ok(Self {
            posture,
            consumers: consumers.into_boxed_slice(),
            entra_validator_observation,
            entra_browser_clock_skew_limit_id,
            entra_browser_maximum_clock_skew_seconds,
            derived_session_observation,
            generic_oidc_enabled: config.oidc.enabled,
            generic_oidc_issuer_authority_binding_digest,
            generic_oidc_audience_client_binding_digest,
            generic_oidc_signature_algorithm: config
                .oidc
                .enabled
                .then_some(AuthenticatorSignatureAlgorithm::Rs256),
            generic_oidc_validation_leeway_seconds,
            generic_oidc_client_authentication,
        })
    }

    pub(crate) fn posture(&self) -> ProductionAuthenticatorPosture {
        self.posture
    }

    pub(crate) fn derived_session_observation(&self) -> &Arc<DerivedSessionRuntimeObservation> {
        &self.derived_session_observation
    }

    #[cfg(test)]
    pub(crate) fn consumers(&self) -> &[AuthenticatorRuntimeConsumer] {
        &self.consumers
    }

    #[cfg(test)]
    pub(crate) fn entra_issuer_authority_binding_digest(&self) -> Option<&str> {
        self.entra_validator_observation
            .as_deref()
            .map(EntraBearerRuntimeObservation::issuer_authority_binding_digest)
    }

    #[cfg(test)]
    pub(crate) fn entra_audience_client_binding_digest(&self) -> Option<&str> {
        self.entra_validator_observation
            .as_deref()
            .map(EntraBearerRuntimeObservation::audience_client_binding_digest)
    }

    #[cfg(test)]
    pub(crate) fn entra_signature_algorithm(&self) -> Option<AuthenticatorSignatureAlgorithm> {
        self.entra_validator_observation
            .as_deref()
            .and_then(|observation| {
                (observation.accepted_algorithm_ids() == ["rs256"])
                    .then_some(AuthenticatorSignatureAlgorithm::Rs256)
            })
    }

    #[cfg(test)]
    pub(crate) fn entra_jwks_ttl_seconds(&self) -> u64 {
        self.entra_validator_observation
            .as_deref()
            .and_then(EntraBearerRuntimeObservation::jwks_ttl_seconds)
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn entra_validation_leeway_seconds(&self) -> u64 {
        self.entra_validator_observation
            .as_deref()
            .map(EntraBearerRuntimeObservation::validation_leeway_seconds)
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn entra_clock_skew_limit_id(&self) -> Option<&str> {
        self.entra_validator_observation
            .as_deref()
            .map(EntraBearerRuntimeObservation::clock_skew_limit_id)
    }

    #[cfg(test)]
    pub(crate) fn entra_credential_lifetime_limit_id(&self) -> Option<&str> {
        self.entra_validator_observation
            .as_deref()
            .map(EntraBearerRuntimeObservation::credential_lifetime_limit_id)
    }

    #[cfg(test)]
    pub(crate) fn entra_maximum_credential_lifetime_seconds(&self) -> Option<u64> {
        self.entra_validator_observation
            .as_deref()
            .map(EntraBearerRuntimeObservation::maximum_credential_lifetime_seconds)
    }

    #[cfg(test)]
    pub(crate) fn entra_browser_clock_skew_limit_id(&self) -> Option<&str> {
        self.entra_browser_clock_skew_limit_id.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn entra_browser_maximum_clock_skew_seconds(&self) -> Option<u64> {
        self.entra_browser_maximum_clock_skew_seconds
    }

    #[cfg(test)]
    pub(crate) fn entra_key_source_kind(&self) -> Option<EntraBearerKeySourceKind> {
        self.entra_validator_observation
            .as_deref()
            .map(EntraBearerRuntimeObservation::key_source_kind)
    }

    #[cfg(test)]
    pub(crate) fn entra_key_source_binding_digest(&self) -> Option<&str> {
        self.entra_validator_observation
            .as_deref()
            .map(EntraBearerRuntimeObservation::key_source_binding_digest)
    }

    #[cfg(test)]
    pub(crate) fn generic_oidc_enabled(&self) -> bool {
        self.generic_oidc_enabled
    }

    #[cfg(test)]
    pub(crate) fn generic_oidc_issuer_authority_binding_digest(&self) -> Option<&str> {
        self.generic_oidc_issuer_authority_binding_digest.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn generic_oidc_audience_client_binding_digest(&self) -> Option<&str> {
        self.generic_oidc_audience_client_binding_digest.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn generic_oidc_signature_algorithm(
        &self,
    ) -> Option<AuthenticatorSignatureAlgorithm> {
        self.generic_oidc_signature_algorithm
    }

    #[cfg(test)]
    pub(crate) fn generic_oidc_validation_leeway_seconds(&self) -> Option<u64> {
        self.generic_oidc_validation_leeway_seconds
    }

    #[cfg(test)]
    pub(crate) fn generic_oidc_client_authentication(&self) -> GenericOidcClientAuthentication {
        self.generic_oidc_client_authentication
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticatorRuntimePostureError {
    #[error("credential-free authentication cannot satisfy production admission")]
    CredentialFree,
    #[error("password-based local authentication cannot satisfy production admission")]
    PasswordLocal,
    #[error("an additional unbound authenticator cannot satisfy production admission")]
    UnboundAuthenticator,
    #[error("the retained derived-session credential authority is unavailable")]
    DerivedSessionCredentialUnavailable,
}

fn normalized_identity_url(raw: &str, label: &'static str) -> Result<String, String> {
    crate::oidc_callback::parse_identity_endpoint(raw)
        .map(|url| url.to_string())
        .map_err(|reason| format!("{label} is invalid: {reason}"))
}

fn validated_exact_identity_url(raw: &str, label: &'static str) -> Result<String, String> {
    crate::oidc_callback::parse_identity_endpoint(raw)
        .map(|_| raw.to_owned())
        .map_err(|reason| format!("{label} is invalid: {reason}"))
}

fn leaf_binding_digest(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, AUTHENTICATOR_LEAF_DIGEST_CONTRACT);
    update_length_prefixed(&mut digest, domain);
    for field in fields {
        update_length_prefixed(&mut digest, field);
    }
    let digest = digest.finalize();
    format!("sha256:{digest:x}")
}

fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

#[derive(Clone, PartialEq, Eq)]
struct MeasuredAuthenticatorPath {
    path: AuthenticatorRuntimePathProjection,
    cache_partition: AuthenticatorCachePartitionProjection,
    protocol_binding: AuthenticatorProtocolBindingProjection,
}

#[derive(Clone)]
struct MeasuredEntraRuntime {
    projection: AuthenticatorRuntimeBindingProjection,
    runtime_binding_digest: String,
    authenticator_inventory_digest: String,
    measured_inventory_value: RuntimeGuardExpectedValue,
    direct_bearer_path: MeasuredAuthenticatorPath,
    browser: Option<MeasuredAuthenticatorPath>,
}

impl MeasuredEntraRuntime {
    fn exactly_matches(&self, other: &Self) -> bool {
        self.projection == other.projection
            && self.runtime_binding_digest == other.runtime_binding_digest
            && self.authenticator_inventory_digest == other.authenticator_inventory_digest
            && self.measured_inventory_value == other.measured_inventory_value
            && self.direct_bearer_path == other.direct_bearer_path
            && self.browser == other.browser
    }
}

/// Test-only bridge used by the authenticated synthetic D fixture. It exposes
/// only the same independently measured path projection that production seals;
/// callers still have to rebuild and re-hash D/P/Q through the normal contract
/// loader before a runtime can be admitted.
#[cfg(test)]
pub(crate) struct FixtureMeasuredEntraPaths {
    pub(crate) direct_bearer_path: AuthenticatorRuntimePathProjection,
    pub(crate) browser: Option<AuthenticatorRuntimePathProjection>,
}

fn digest_bytes(value: &str, label: &'static str) -> Result<[u8; 32], String> {
    let encoded = value
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("{label} does not use the canonical sha256 prefix"))?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} is not canonical lowercase hexadecimal SHA-256"
        ));
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut bytes)
        .map_err(|_| format!("{label} could not be decoded as SHA-256"))?;
    if bytes == [0_u8; 32] {
        return Err(format!("{label} cannot be the all-zero digest"));
    }
    Ok(bytes)
}

fn checked_milliseconds(duration: std::time::Duration, label: &'static str) -> Result<u64, String> {
    u64::try_from(duration.as_millis())
        .map_err(|_| format!("{label} exceeds the canonical millisecond range"))
}

fn checked_usize(value: usize, label: &'static str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{label} exceeds the canonical integer range"))
}

// These arguments are the closed canonical identity tuple. Keeping them
// explicit makes each call site auditable against the path contract.
#[allow(clippy::too_many_arguments)]
fn path_identity(
    authority: &ResolvedEntraAuthenticatorAuthority,
    role: AuthenticatorRuntimePathRole,
    path_id: &'static str,
    path_version: u64,
    verifier_id: &'static str,
    verifier_version: u64,
    token_profile: &'static str,
    issuer_binding_digest: &str,
    audience_set_binding_digest: &str,
    key_source_binding_digest: &str,
) -> AuthenticatorRuntimePathIdentityProjection {
    AuthenticatorRuntimePathIdentityProjection {
        provider_id: authority.provider_id().to_owned(),
        provider_configuration_version: authority.provider_configuration_version(),
        provider_policy_binding_digest: authority.provider_policy_binding_digest().to_owned(),
        path_role: role,
        path_id: path_id.to_owned(),
        path_version,
        verifier_id: verifier_id.to_owned(),
        verifier_version,
        token_profile: token_profile.to_owned(),
        issuer_binding_digest: issuer_binding_digest.to_owned(),
        audience_set_binding_digest: audience_set_binding_digest.to_owned(),
        key_source_kind: AuthenticatorKeySourceKind::JwtJwks,
        key_source_binding_digest: key_source_binding_digest.to_owned(),
    }
}

fn measure_entra_bearer_path(
    authority: &ResolvedEntraAuthenticatorAuthority,
    observation: &EntraBearerRuntimeObservation,
) -> Result<MeasuredAuthenticatorPath, String> {
    if authority.bearer_path_id() != ENTRA_BEARER_PATH_ID
        || authority.bearer_path_version() != ENTRA_BEARER_PATH_VERSION
        || observation.key_source_kind() != EntraBearerKeySourceKind::NetworkJwks
        || observation.accepted_algorithm_ids() != ["rs256"]
        || observation.required_claim_ids() != ["aud", "exp", "iat", "iss", "nbf", "oid", "sub"]
        || observation.provider_subject_claim_id() != "oid"
        || !observation.expiration_required()
        || !observation.not_before_required()
        || !observation.issued_at_required()
        || observation.nonce_required()
        || observation.redirects_allowed()
        || observation.clock_skew_limit_id() != "limit:authenticator.clock-skew"
        || observation.credential_lifetime_limit_id()
            != "limit:authenticator.oidc-access-token-lifetime"
        || observation.maximum_credential_lifetime_seconds() == 0
    {
        return Err("live Entra bearer path differs from the closed runtime policy".into());
    }
    let maximum_clock_skew_seconds = u32::try_from(observation.maximum_clock_skew_seconds())
        .map_err(|_| {
            "live Entra bearer clock-skew authority exceeds the D integer range".to_string()
        })?;
    let identity = path_identity(
        authority,
        AuthenticatorRuntimePathRole::DirectBearer,
        ENTRA_BEARER_PATH_ID,
        ENTRA_BEARER_PATH_VERSION,
        ENTRA_BEARER_VERIFIER_ID,
        ENTRA_BEARER_VERIFIER_VERSION,
        "jwt-access-token",
        observation.issuer_authority_binding_digest(),
        observation.audience_client_binding_digest(),
        observation.key_source_binding_digest(),
    );
    let cache_partition = AuthenticatorCachePartitionProjection {
        path_identity: identity.clone(),
        cache_owner_id: ENTRA_BEARER_CACHE_OWNER_ID.into(),
        cache_partition_id: ENTRA_BEARER_CACHE_PARTITION_ID.into(),
        cache_kinds: vec![AuthenticatorCacheKind::JwksKeySet],
        retained_consumer_ids: vec![ENTRA_BEARER_CONSUMER_ID.into()],
    };
    let replay = AuthenticatorReplayRuntimeProjection {
        credential_reuse: AuthenticatorCredentialReuse::ReusableUntilExpiry,
        credential_lifetime_limit_id: Some(observation.credential_lifetime_limit_id().to_owned()),
        maximum_credential_lifetime_seconds: Some(
            observation.maximum_credential_lifetime_seconds(),
        ),
        sender_constraint: AuthenticatorSenderConstraint::None,
        presentation_replay_defense: AuthenticatorPresentationReplayDefense::None,
        nonce_binding: AuthenticatorNonceBinding::None,
        replay_store_binding_digest: None,
    };
    let protocol_binding = AuthenticatorProtocolBindingProjection {
        path_identity: identity,
        carrier: AuthenticatorCredentialCarrier::AuthorizationBearer,
        proof_binding: AuthenticatorProofBinding::Bearer,
        replay: replay.clone(),
        browser_exchange_authority: None,
        browser_state_authority: None,
        derived_session_authority: None,
    };
    let cache_partition_binding_digest =
        authenticator_cache_partition_binding_digest(&cache_partition)
            .map_err(|error| format!("live Entra bearer cache preimage is invalid: {error}"))?;
    let protocol_binding_digest = authenticator_protocol_binding_digest(&protocol_binding)
        .map_err(|error| format!("live Entra bearer protocol preimage is invalid: {error}"))?;
    let path = AuthenticatorRuntimePathProjection {
        path_id: ENTRA_BEARER_PATH_ID.into(),
        path_version: ENTRA_BEARER_PATH_VERSION,
        verifier: AuthenticatorVerifierRuntimeProjection {
            verifier_id: ENTRA_BEARER_VERIFIER_ID.into(),
            verifier_version: ENTRA_BEARER_VERIFIER_VERSION,
            issuer_binding_digest: observation.issuer_authority_binding_digest().to_owned(),
            audience_set_binding_digest: observation.audience_client_binding_digest().to_owned(),
            accepted_algorithm_ids: observation
                .accepted_algorithm_ids()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            required_claim_ids: observation
                .required_claim_ids()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            provider_subject_claim_id: observation.provider_subject_claim_id().to_owned(),
            key_source_kind: AuthenticatorKeySourceKind::JwtJwks,
            key_source_binding_digest: observation.key_source_binding_digest().to_owned(),
            expiration_required: observation.expiration_required(),
            not_before_required: observation.not_before_required(),
            issued_at_required: observation.issued_at_required(),
            nonce_required: observation.nonce_required(),
            clock_skew_limit_id: observation.clock_skew_limit_id().to_owned(),
            maximum_clock_skew_seconds,
            redirects_allowed: observation.redirects_allowed(),
        },
        credential_profile: AuthenticatorCredentialProfileRuntimeProjection {
            profile_id: ENTRA_BEARER_PROFILE_ID.into(),
            profile_version: ENTRA_BEARER_PROFILE_VERSION,
            token_profile: "jwt-access-token".into(),
            carrier: AuthenticatorCredentialCarrier::AuthorizationBearer,
            proof_binding: AuthenticatorProofBinding::Bearer,
            replay,
        },
        cache_partition_binding_digest,
        protocol_binding_digest,
        retained_consumer_ids: vec![ENTRA_BEARER_CONSUMER_ID.into()],
    };
    Ok(MeasuredAuthenticatorPath {
        path,
        cache_partition,
        protocol_binding,
    })
}

fn browser_state_authority(
    limits: &ResolvedAuthenticatorBrowserLimits,
) -> AuthenticatorBrowserStateAuthorityProjection {
    AuthenticatorBrowserStateAuthorityProjection {
        state_authority_id: ENTRA_BROWSER_STATE_AUTHORITY_ID.into(),
        state_authority_version: ENTRA_BROWSER_STATE_AUTHORITY_VERSION,
        relation_name: AUTHENTICATOR_BROWSER_STATE_RELATION_V3.into(),
        writer_contract_setting: AUTHENTICATOR_BROWSER_STATE_CONTRACT_SETTING.into(),
        writer_contract_version: AUTHENTICATOR_BROWSER_STATE_CONTRACT_VERSION,
        consume_operation: AUTHENTICATOR_BROWSER_STATE_CONSUME_OPERATION.into(),
        state_lifetime_limit_id: limits.state_lifetime_limit_id().to_owned(),
        maximum_state_lifetime_seconds: limits.maximum_state_lifetime_seconds(),
        pkce_method: AUTHENTICATOR_BROWSER_PKCE_METHOD_S256.into(),
        nonce_required: true,
        browser_binding_required: true,
        exact_origin_match_required: true,
    }
}

fn validate_derived_session_runtime(
    observation: &DerivedSessionRuntimeObservation,
) -> Result<(&str, u64, u64), String> {
    let key_identity = observation
        .key_identity_binding_digest()
        .ok_or_else(|| "live derived-session authority has no retained key identity".to_string())?;
    if !observation.enabled()
        || observation.credential_format_id() != "session-credential:opaque-random-v1"
        || observation.verifier_algorithm_id() != "hmac-sha256"
        || observation.credential_random_bytes() != 32
        || observation.database_representation_id() != "session-verifier:keyed-digest-only-v1"
        || observation.maximum_session_age_seconds() == 0
        || observation.federated_authority_max_staleness_seconds() == 0
        || observation.federated_authority_max_staleness_seconds()
            > observation.maximum_session_age_seconds()
    {
        return Err("live derived-session authority differs from the closed runtime policy".into());
    }
    let _ = digest_bytes(key_identity, "derived-session key identity digest")?;
    Ok((
        key_identity,
        observation.maximum_session_age_seconds(),
        observation.federated_authority_max_staleness_seconds(),
    ))
}

fn measure_entra_browser_path(
    authority: &ResolvedEntraAuthenticatorAuthority,
    observation: &EntraSsoRuntimeObservation,
    derived_session: &DerivedSessionRuntimeObservation,
    cookie_runtime: &ApiCookieRuntimeObservation,
) -> Result<MeasuredAuthenticatorPath, String> {
    let limits = authority.browser_limits().ok_or_else(|| {
        "live Entra browser path has no exact resolved limit authority".to_string()
    })?;
    limits.verify_integrity()?;
    if authority.browser_path_id() != Some(ENTRA_BROWSER_PATH_ID)
        || authority.browser_path_version() != Some(ENTRA_BROWSER_PATH_VERSION)
        || !observation.mode_is_entra()
        || !observation.configured()
        || !observation.authorization_endpoint_https_only()
        || !observation.redirect_uri_https_only()
        || observation.accepted_algorithm_ids() != ["rs256"]
        || observation.required_claim_ids() != ["aud", "exp", "iss", "nbf", "nonce", "oid", "sub"]
        || observation.provider_subject_claim_id() != "oid"
        || !observation.expiration_required()
        || !observation.not_before_required()
        || observation.issued_at_required()
        || !observation.nonce_required()
        || observation.redirects_allowed()
        || observation.client_authentication() != AuthenticatorBrowserClientAuthentication::None
        || observation.client_credential_present()
        || observation.pkce_method() != AUTHENTICATOR_BROWSER_PKCE_METHOD_S256
        || !observation.browser_binding_required()
        || !observation.id_token_required()
        || observation.provider_tokens_persisted()
        || observation.provider_tokens_exposed()
        || observation.clock_skew_limit_id() != Some("limit:authenticator.clock-skew")
        || limits.state_lifetime_limit_id() != AUTHENTICATOR_BROWSER_STATE_LIFETIME_LIMIT_ID
        || limits.maximum_state_lifetime_seconds()
            != AUTHENTICATOR_BROWSER_STATE_MAXIMUM_TTL_SECONDS
        || limits.session_maximum_age_limit_id()
            != AUTHENTICATOR_BROWSER_SESSION_MAXIMUM_AGE_LIMIT_ID
        || limits.federated_authority_staleness_limit_id()
            != AUTHENTICATOR_FEDERATED_AUTHORITY_STALENESS_LIMIT_ID
    {
        return Err("live Entra browser path differs from the closed runtime policy".into());
    }
    let maximum_clock_skew_seconds = observation
        .maximum_clock_skew_seconds()
        .ok_or_else(|| "live Entra browser path has no clock-skew authority".to_string())?;
    let maximum_clock_skew_seconds = u32::try_from(maximum_clock_skew_seconds).map_err(|_| {
        "live Entra browser clock-skew authority exceeds the D integer range".to_string()
    })?;
    let exchanger = observation.token_exchanger();
    let validator = observation.id_token_validator();
    let jwks = validator
        .network_jwks()
        .ok_or_else(|| "live Entra browser validator does not retain network JWKS".to_string())?;
    if exchanger.grant_type() != "authorization_code"
        || !exchanger.endpoint_https_only()
        || exchanger.redirects_allowed()
        || exchanger.ambient_proxy_allowed()
        || !exchanger.pkce_verifier_included()
        || !exchanger.redirect_uri_bound()
        || !exchanger.client_id_bound()
        || !exchanger.client_secret_form_parameter_optional()
        || !validator.issuer_https_only()
        || validator.key_source_kind() != OidcIdTokenKeySourceKind::NetworkJwks
        || validator.accepted_algorithm_ids() != ["rs256"]
        || validator.required_claim_ids() != ["exp", "nbf", "iss", "aud", "sub", "nonce"]
        || !validator.expiration_required()
        || !validator.not_before_required()
        || !validator.nonce_required()
        || validator.leeway_seconds() != u64::from(maximum_clock_skew_seconds)
        || !jwks.endpoint_https_only()
        || jwks.redirects_allowed()
        || jwks.ambient_proxy_allowed()
    {
        return Err(
            "live Entra browser exchanger or validator differs from the closed network policy"
                .into(),
        );
    }
    let (credential_key_identity_digest, maximum_session_age_seconds, staleness_seconds) =
        validate_derived_session_runtime(derived_session)?;
    if limits.maximum_session_age_seconds() != maximum_session_age_seconds
        || limits.maximum_federated_authority_staleness_seconds() != staleness_seconds
        || limits.clock_skew_limit_id() != observation.clock_skew_limit_id().unwrap_or_default()
        || limits.maximum_clock_skew_seconds() != u64::from(maximum_clock_skew_seconds)
    {
        return Err(
            "live Entra browser values differ from the exact resolved limit authority".into(),
        );
    }
    if observation.session_credentials() != derived_session {
        return Err(
            "live Entra browser dependencies and retained session authority were measured from different objects"
                .into(),
        );
    }
    if cookie_runtime.mode() != ApiCookieRuntimeObservationMode::SecureProduction
        || observation.cookie_runtime().mode() != cookie_runtime.mode()
        || observation.cookie_runtime().production() != cookie_runtime.production()
        || observation.cookie_runtime().policy_inventory_digest()
            != cookie_runtime.policy_inventory_digest()
    {
        return Err(
            "live Entra browser dependencies do not retain the production cookie authority".into(),
        );
    }
    let cookie_policy_binding_digest = cookie_runtime
        .policy_inventory_digest()
        .ok_or_else(|| "production cookie authority has no inventory digest".to_string())?;
    let _ = digest_bytes(
        cookie_policy_binding_digest,
        "production cookie policy inventory digest",
    )?;

    let identity = path_identity(
        authority,
        AuthenticatorRuntimePathRole::BrowserDerivedSession,
        ENTRA_BROWSER_PATH_ID,
        ENTRA_BROWSER_PATH_VERSION,
        ENTRA_BROWSER_VERIFIER_ID,
        ENTRA_BROWSER_VERIFIER_VERSION,
        "oidc-id-token",
        validator.issuer_binding_digest(),
        validator.audience_binding_digest(),
        observation.key_source_binding_digest(),
    );
    let cache_partition = AuthenticatorCachePartitionProjection {
        path_identity: identity.clone(),
        cache_owner_id: ENTRA_BROWSER_CACHE_OWNER_ID.into(),
        cache_partition_id: ENTRA_BROWSER_CACHE_PARTITION_ID.into(),
        cache_kinds: vec![
            AuthenticatorCacheKind::BrowserLoginState,
            AuthenticatorCacheKind::DerivedSessionCredential,
            AuthenticatorCacheKind::JwksKeySet,
            AuthenticatorCacheKind::NonceReplay,
        ],
        retained_consumer_ids: vec![ENTRA_BROWSER_CONSUMER_ID.into()],
    };
    let browser_state_authority = browser_state_authority(limits);
    let replay_store_binding_digest =
        authenticator_browser_state_authority_binding_digest(&browser_state_authority)
            .map_err(|error| format!("live Entra browser state authority is invalid: {error}"))?;
    let replay = AuthenticatorReplayRuntimeProjection {
        credential_reuse: AuthenticatorCredentialReuse::SingleUse,
        credential_lifetime_limit_id: None,
        maximum_credential_lifetime_seconds: None,
        sender_constraint: AuthenticatorSenderConstraint::None,
        presentation_replay_defense: AuthenticatorPresentationReplayDefense::SingleUseState,
        nonce_binding: AuthenticatorNonceBinding::OidcLogin,
        replay_store_binding_digest: Some(replay_store_binding_digest),
    };
    let protocol_binding = AuthenticatorProtocolBindingProjection {
        path_identity: identity,
        carrier: AuthenticatorCredentialCarrier::OauthCallback,
        proof_binding: AuthenticatorProofBinding::PkceS256,
        replay: replay.clone(),
        browser_exchange_authority: Some(AuthenticatorBrowserExchangeAuthorityProjection {
            exchange_authority_id: ENTRA_BROWSER_EXCHANGE_AUTHORITY_ID.into(),
            exchange_authority_version: ENTRA_BROWSER_EXCHANGE_AUTHORITY_VERSION,
            authorization_endpoint_binding_digest: observation
                .authorization_endpoint_binding_digest()
                .to_owned(),
            token_endpoint_binding_digest: exchanger.token_endpoint_binding_digest().to_owned(),
            redirect_uri_binding_digest: observation.redirect_uri_binding_digest().to_owned(),
            client_id_binding_digest: observation.client_id_binding_digest().to_owned(),
            scopes_binding_digest: observation.scopes_binding_digest().to_owned(),
            client_authentication: observation.client_authentication(),
            client_credential_present: observation.client_credential_present(),
            connect_timeout_milliseconds: checked_milliseconds(
                exchanger.connect_timeout(),
                "Entra browser exchange connect timeout",
            )?,
            request_timeout_milliseconds: checked_milliseconds(
                exchanger.request_timeout(),
                "Entra browser exchange request timeout",
            )?,
            response_maximum_bytes: checked_usize(
                exchanger.maximum_response_bytes(),
                "Entra browser exchange response bound",
            )?,
            https_required: true,
            redirects_allowed: exchanger.redirects_allowed(),
            ambient_proxy_allowed: exchanger.ambient_proxy_allowed(),
            pkce_verifier_sent: exchanger.pkce_verifier_included(),
            id_token_required: observation.id_token_required(),
            provider_tokens_persisted: observation.provider_tokens_persisted(),
            provider_tokens_exposed: observation.provider_tokens_exposed(),
        }),
        browser_state_authority: Some(browser_state_authority),
        derived_session_authority: Some(AuthenticatorDerivedSessionAuthorityProjection {
            session_authority_id: ENTRA_BROWSER_SESSION_AUTHORITY_ID.into(),
            session_authority_version: ENTRA_BROWSER_SESSION_AUTHORITY_VERSION,
            relation_name: AUTHENTICATOR_DERIVED_SESSION_RELATION.into(),
            credential_format: AUTHENTICATOR_DERIVED_SESSION_CREDENTIAL_FORMAT.into(),
            credential_verifier_algorithm: AUTHENTICATOR_DERIVED_SESSION_VERIFIER_ALGORITHM.into(),
            credential_key_identity_digest: credential_key_identity_digest.to_owned(),
            verifier_column_name: AUTHENTICATOR_DERIVED_SESSION_VERIFIER_COLUMN_V3.into(),
            session_maximum_age_limit_id: limits.session_maximum_age_limit_id().to_owned(),
            maximum_session_age_seconds,
            federated_authority_staleness_limit_id: limits
                .federated_authority_staleness_limit_id()
                .to_owned(),
            maximum_federated_authority_staleness_seconds: staleness_seconds,
            exact_origin_copy_required: true,
            cookie_policy_binding_digest: cookie_policy_binding_digest.to_owned(),
        }),
    };
    let cache_partition_binding_digest =
        authenticator_cache_partition_binding_digest(&cache_partition)
            .map_err(|error| format!("live Entra browser cache preimage is invalid: {error}"))?;
    let protocol_binding_digest = authenticator_protocol_binding_digest(&protocol_binding)
        .map_err(|error| format!("live Entra browser protocol preimage is invalid: {error}"))?;
    let path = AuthenticatorRuntimePathProjection {
        path_id: ENTRA_BROWSER_PATH_ID.into(),
        path_version: ENTRA_BROWSER_PATH_VERSION,
        verifier: AuthenticatorVerifierRuntimeProjection {
            verifier_id: ENTRA_BROWSER_VERIFIER_ID.into(),
            verifier_version: ENTRA_BROWSER_VERIFIER_VERSION,
            issuer_binding_digest: validator.issuer_binding_digest().to_owned(),
            audience_set_binding_digest: validator.audience_binding_digest().to_owned(),
            accepted_algorithm_ids: observation
                .accepted_algorithm_ids()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            required_claim_ids: observation
                .required_claim_ids()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            provider_subject_claim_id: observation.provider_subject_claim_id().to_owned(),
            key_source_kind: AuthenticatorKeySourceKind::JwtJwks,
            key_source_binding_digest: observation.key_source_binding_digest().to_owned(),
            expiration_required: observation.expiration_required(),
            not_before_required: observation.not_before_required(),
            issued_at_required: observation.issued_at_required(),
            nonce_required: observation.nonce_required(),
            clock_skew_limit_id: observation
                .clock_skew_limit_id()
                .expect("validated browser clock-skew authority")
                .to_owned(),
            maximum_clock_skew_seconds,
            redirects_allowed: observation.redirects_allowed(),
        },
        credential_profile: AuthenticatorCredentialProfileRuntimeProjection {
            profile_id: ENTRA_BROWSER_PROFILE_ID.into(),
            profile_version: ENTRA_BROWSER_PROFILE_VERSION,
            token_profile: "oidc-id-token".into(),
            carrier: AuthenticatorCredentialCarrier::OauthCallback,
            proof_binding: AuthenticatorProofBinding::PkceS256,
            replay,
        },
        cache_partition_binding_digest,
        protocol_binding_digest,
        retained_consumer_ids: vec![ENTRA_BROWSER_CONSUMER_ID.into()],
    };
    Ok(MeasuredAuthenticatorPath {
        path,
        cache_partition,
        protocol_binding,
    })
}

#[cfg(test)]
pub(crate) fn fixture_measured_entra_paths(
    authority: &ResolvedEntraAuthenticatorAuthority,
    bearer_validator: &EntraTokenValidator,
    entra_sso_dependencies: &Arc<EntraSsoDeps>,
    derived_session_credentials: &Arc<DerivedSessionCredentialRuntime>,
    cookie_runtime: &Arc<ApiCookieRuntime>,
) -> Result<FixtureMeasuredEntraPaths, String> {
    authority.verify_integrity()?;
    let direct_bearer_path =
        measure_entra_bearer_path(authority, &bearer_validator.runtime_observation())?;
    let browser = authority
        .browser_path_id()
        .map(|_| {
            let cookie_observation = cookie_runtime.live_observation().map_err(|error| {
                format!("fixture cookie authority could not be measured: {error}")
            })?;
            measure_entra_browser_path(
                authority,
                &entra_sso_dependencies.runtime_observation(),
                &derived_session_credentials.runtime_observation(),
                &cookie_observation,
            )
        })
        .transpose()?;
    Ok(FixtureMeasuredEntraPaths {
        direct_bearer_path: direct_bearer_path.path,
        browser: browser.map(|path| path.path),
    })
}

fn measure_entra_runtime(
    authority: &ResolvedEntraAuthenticatorAuthority,
    bearer_observation: &EntraBearerRuntimeObservation,
    sso_observation: &EntraSsoRuntimeObservation,
    derived_session_observation: &DerivedSessionRuntimeObservation,
    cookie_observation: &ApiCookieRuntimeObservation,
) -> Result<MeasuredEntraRuntime, String> {
    authority.verify_integrity()?;
    let _ = validate_derived_session_runtime(derived_session_observation)?;
    if !sso_observation.mode_is_entra()
        || sso_observation.session_credentials() != derived_session_observation
        || cookie_observation.mode() != ApiCookieRuntimeObservationMode::SecureProduction
        || sso_observation.cookie_runtime().mode() != cookie_observation.mode()
        || sso_observation.cookie_runtime().production() != cookie_observation.production()
        || sso_observation.cookie_runtime().policy_inventory_digest()
            != cookie_observation.policy_inventory_digest()
    {
        return Err(
            "live Entra runtime does not retain exact production session and cookie authority"
                .into(),
        );
    }
    let direct_bearer_path = measure_entra_bearer_path(authority, bearer_observation)?;
    let browser = match authority.browser_path_id() {
        Some(_) => Some(measure_entra_browser_path(
            authority,
            sso_observation,
            derived_session_observation,
            cookie_observation,
        )?),
        None if sso_observation.configured() => {
            return Err(
                "live Entra browser path is configured but absent from the retained D".into(),
            );
        }
        None => None,
    };
    let mut capability_ids = Vec::with_capacity(2);
    if browser.is_some() {
        capability_ids.push("browser-sso".into());
    }
    capability_ids.push("token-validation".into());
    let mut credential_paths = vec![direct_bearer_path.path.clone()];
    if let Some(browser) = &browser {
        credential_paths.push(browser.path.clone());
    }
    let declared = authority.declared_runtime_binding_projection();
    let projection = AuthenticatorRuntimeBindingProjection {
        provider: declared.provider.clone(),
        binding_document_reference: authority.binding_document_reference().clone(),
        authenticator_kind: ProductionAuthenticatorKind::Oidc,
        provider_policy_binding_digest: authority.provider_policy_binding_digest().to_owned(),
        capability_ids,
        credential_paths,
        ownership: AuthenticatorRuntimeOwnership {
            single_runtime_owner: true,
            ambient_reconfiguration_allowed: false,
        },
    };

    for measured_path in std::iter::once(&direct_bearer_path).chain(browser.iter()) {
        validate_authenticator_runtime_path_preimages(
            declared,
            &measured_path.cache_partition,
            &measured_path.protocol_binding,
        )
        .map_err(|error| {
            format!("live authenticator path does not reconcile with exact D: {error}")
        })?;
        validate_authenticator_runtime_path_preimages(
            &projection,
            &measured_path.cache_partition,
            &measured_path.protocol_binding,
        )
        .map_err(|error| format!("measured authenticator path is internally invalid: {error}"))?;
    }
    if &projection != declared {
        return Err(
            "independently measured Entra runtime projection differs from exact D/P/Q authority"
                .into(),
        );
    }
    let runtime_binding_digest = authenticator_runtime_binding_digest(&projection)
        .map_err(|error| format!("measured Entra runtime R is invalid: {error}"))?;
    let d = authority
        .binding_document_reference()
        .content_digest
        .as_str();
    let p = authority.provider_configuration_payload_digest();
    let q = authority.provider_policy_binding_digest();
    if [d, p, q, runtime_binding_digest.as_str()]
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .len()
        != 4
    {
        return Err("measured Entra runtime violates D/P/Q/R digest separation".into());
    }
    let authenticators = vec![ExpectedAuthenticatorBinding {
        provider: projection.provider.clone(),
        authenticator_kind: projection.authenticator_kind,
        runtime_binding_digest: runtime_binding_digest.clone(),
    }];
    let authenticator_inventory_digest = authenticator_inventory_digest(&authenticators)
        .map_err(|error| format!("measured authenticator inventory is invalid: {error}"))?;
    let measured_inventory_value = RuntimeGuardExpectedValue::NonDevelopmentAuthenticator {
        authenticator_inventory_digest: authenticator_inventory_digest.clone(),
        authenticators,
    };
    Ok(MeasuredEntraRuntime {
        projection,
        runtime_binding_digest,
        authenticator_inventory_digest,
        measured_inventory_value,
        direct_bearer_path,
        browser,
    })
}

/// Sealed live measurement R for the one exact retained Entra authenticator.
///
/// Construction is private and takes concrete runtime allocations, never an R
/// digest or caller-projected path. Integrity checks remeasure every immutable
/// leaf and reconcile both canonical preimages with the exact authenticated D.
pub(crate) struct VerifiedEntraAuthenticatorRuntimeBinding {
    authority: Arc<ResolvedEntraAuthenticatorAuthority>,
    bearer_validator: Arc<EntraTokenValidator>,
    bearer_observation: Arc<EntraBearerRuntimeObservation>,
    entra_sso_dependencies: Arc<EntraSsoDeps>,
    entra_sso_observation: Arc<EntraSsoRuntimeObservation>,
    derived_session_credentials: Arc<DerivedSessionCredentialRuntime>,
    derived_session_observation: Arc<DerivedSessionRuntimeObservation>,
    cookie_runtime: Arc<ApiCookieRuntime>,
    cookie_observation: ApiCookieRuntimeObservation,
    measured: MeasuredEntraRuntime,
}

impl fmt::Debug for VerifiedEntraAuthenticatorRuntimeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedEntraAuthenticatorRuntimeBinding")
            .field("authority", &"[RETAINED]")
            .field("runtime_allocations", &"[RETAINED]")
            .field("runtime_projection", &"[REDACTED]")
            .field("runtime_binding_digest", &"[REDACTED]")
            .field("authenticator_inventory", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VerifiedEntraAuthenticatorRuntimeBinding {
    #[allow(clippy::too_many_arguments)]
    fn seal(
        authority: Arc<ResolvedEntraAuthenticatorAuthority>,
        bearer_validator: Arc<EntraTokenValidator>,
        bearer_observation: Arc<EntraBearerRuntimeObservation>,
        entra_sso_dependencies: Arc<EntraSsoDeps>,
        derived_session_credentials: Arc<DerivedSessionCredentialRuntime>,
        derived_session_observation: Arc<DerivedSessionRuntimeObservation>,
        cookie_runtime: Arc<ApiCookieRuntime>,
    ) -> Result<Arc<Self>, String> {
        authority.verify_integrity()?;
        let entra_sso_observation = entra_sso_dependencies.runtime_observation();
        let cookie_observation = cookie_runtime
            .live_observation()
            .map_err(|error| format!("live cookie authority could not be measured: {error}"))?;
        let sealed = Arc::new(Self {
            measured: measure_entra_runtime(
                &authority,
                &bearer_observation,
                &entra_sso_observation,
                &derived_session_observation,
                &cookie_observation,
            )?,
            authority,
            bearer_validator,
            bearer_observation,
            entra_sso_dependencies,
            entra_sso_observation,
            derived_session_credentials,
            derived_session_observation,
            cookie_runtime,
            cookie_observation,
        });
        sealed.verify_integrity()?;
        Ok(sealed)
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), String> {
        self.authority.verify_integrity()?;
        if !self
            .bearer_validator
            .retains_bearer_limits(self.authority.bearer_limits())
            || *self.bearer_observation != self.bearer_validator.runtime_observation()
            || !self
                .entra_sso_dependencies
                .retains_runtime_observation(&self.entra_sso_observation)
            || !self.entra_sso_dependencies.remeasures_runtime_observation()
            || !self
                .entra_sso_dependencies
                .retains_session_credentials(&self.derived_session_credentials)
            || !self
                .entra_sso_dependencies
                .retains_cookie_runtime(&self.cookie_runtime)
            || !self
                .entra_sso_dependencies
                .retains_browser_limits(&self.authority.browser_limits().map(Arc::clone))
            || *self.derived_session_observation
                != self.derived_session_credentials.runtime_observation()
        {
            return Err(
                "sealed Entra runtime lost an exact retained allocation or live observation".into(),
            );
        }
        self.cookie_observation
            .verify_retained_runtime(&self.cookie_runtime)
            .map_err(|error| format!("sealed cookie observation lost its runtime: {error}"))?;
        self.entra_sso_observation
            .cookie_runtime()
            .verify_retained_runtime(&self.cookie_runtime)
            .map_err(|error| {
                format!("sealed Entra SSO cookie observation lost its runtime: {error}")
            })?;
        let remeasured = measure_entra_runtime(
            &self.authority,
            &self.bearer_observation,
            &self.entra_sso_observation,
            &self.derived_session_observation,
            &self.cookie_observation,
        )?;
        if !remeasured.exactly_matches(&self.measured) {
            return Err("sealed Entra runtime differs from independent live remeasurement".into());
        }
        Ok(())
    }

    pub(crate) fn measured_projection(&self) -> &AuthenticatorRuntimeBindingProjection {
        &self.measured.projection
    }

    pub(crate) fn runtime_binding_digest(&self) -> &str {
        &self.measured.runtime_binding_digest
    }

    pub(crate) fn provider_binding(&self) -> &ExpectedProviderBinding {
        &self.measured.projection.provider
    }

    pub(crate) fn measured_authenticator_inventory_value(&self) -> &RuntimeGuardExpectedValue {
        &self.measured.measured_inventory_value
    }

    pub(crate) fn measured_authenticator_inventory_digest(&self) -> &str {
        &self.measured.authenticator_inventory_digest
    }

    /// Return the independently measured inventory in the guard's comparison
    /// shape. This is an observed candidate, never receipt authority: callers
    /// must compare it with the authenticated challenge expectation.
    pub(crate) fn expected_authenticator_inventory_value(&self) -> &RuntimeGuardExpectedValue {
        self.measured_authenticator_inventory_value()
    }

    /// Return the independently measured inventory digest. The name reflects
    /// the guard comparison slot; it is not a declaration-side expectation.
    pub(crate) fn expected_authenticator_inventory_digest(&self) -> &str {
        self.measured_authenticator_inventory_digest()
    }

    pub(crate) fn retains_authority(
        &self,
        authority: &Arc<ResolvedEntraAuthenticatorAuthority>,
    ) -> bool {
        Arc::ptr_eq(&self.authority, authority)
    }

    pub(crate) fn retains_bearer_validator(&self, validator: &Arc<EntraTokenValidator>) -> bool {
        Arc::ptr_eq(&self.bearer_validator, validator)
            && self.bearer_validator.runtime_observation() == *self.bearer_observation
    }

    /// Return the exact retained session-credential authority only after the
    /// complete sealed runtime has been independently remeasured. Callers must
    /// not accept a separately supplied equal-looking runtime alongside R.
    pub(crate) fn derived_session_credentials(
        &self,
    ) -> Result<Arc<DerivedSessionCredentialRuntime>, String> {
        self.verify_integrity()?;
        Ok(Arc::clone(&self.derived_session_credentials))
    }

    pub(crate) fn direct_bearer_origin(
        self: &Arc<Self>,
    ) -> Result<Arc<VerifiedDirectBearerAuthenticatorOrigin>, String> {
        VerifiedDirectBearerAuthenticatorOrigin::seal(Arc::clone(self))
    }

    pub(crate) fn browser_origin(
        self: &Arc<Self>,
    ) -> Result<Option<Arc<VerifiedBrowserAuthenticatorOrigin>>, String> {
        self.verify_integrity()?;
        let browser_path_count = self
            .measured_projection()
            .credential_paths
            .iter()
            .filter(|path| {
                path.path_id == ENTRA_BROWSER_PATH_ID
                    && path.path_version == ENTRA_BROWSER_PATH_VERSION
                    && path.credential_profile.token_profile == "oidc-id-token"
            })
            .count();
        match browser_path_count {
            0 if self.authority.browser_path_id().is_none() => Ok(None),
            1 if self.authority.browser_path_id() == Some(ENTRA_BROWSER_PATH_ID)
                && self.authority.browser_path_version() == Some(ENTRA_BROWSER_PATH_VERSION) =>
            {
                VerifiedBrowserAuthenticatorOrigin::seal(Arc::clone(self)).map(Some)
            }
            _ => {
                Err("sealed Entra runtime has an inconsistent browser-origin path inventory".into())
            }
        }
    }

    pub(crate) fn verify_direct_bearer_identity(
        self: &Arc<Self>,
        identity: &crate::entra_auth::VerifiedEntraBearerIdentity,
    ) -> Result<Arc<VerifiedDirectBearerAuthenticatorOrigin>, String> {
        self.verify_integrity()?;
        identity
            .verify_integrity()
            .map_err(|error| format!("validated Entra bearer identity is invalid: {error}"))?;
        if !self.retains_bearer_validator(identity.source_validator()) {
            return Err(
                "validated Entra bearer identity came from a substituted validator allocation"
                    .into(),
            );
        }
        let origin = self.direct_bearer_origin()?;
        if !origin.retains_entra_runtime_binding(self)
            || !origin.matches_validated_issuer(identity.issuer())
        {
            return Err(
                "validated Entra bearer identity does not match the sealed direct-bearer origin"
                    .into(),
            );
        }
        Ok(origin)
    }

    pub(crate) fn retains_entra_sso_dependencies(&self, dependencies: &Arc<EntraSsoDeps>) -> bool {
        Arc::ptr_eq(&self.entra_sso_dependencies, dependencies)
            && self
                .entra_sso_dependencies
                .retains_runtime_observation(&self.entra_sso_observation)
    }

    #[cfg(test)]
    fn retains_bearer_observation(&self, observation: &Arc<EntraBearerRuntimeObservation>) -> bool {
        Arc::ptr_eq(&self.bearer_observation, observation)
    }

    #[cfg(test)]
    fn retains_derived_session_credentials(
        &self,
        runtime: &Arc<DerivedSessionCredentialRuntime>,
    ) -> bool {
        Arc::ptr_eq(&self.derived_session_credentials, runtime)
    }

    #[cfg(test)]
    fn retains_cookie_runtime(&self, runtime: &Arc<ApiCookieRuntime>) -> bool {
        Arc::ptr_eq(&self.cookie_runtime, runtime)
    }
}

/// Canonical provenance for the exact direct-bearer path retained by one
/// sealed Entra runtime. The source allocation is kept private so an equal-
/// looking provider/configuration projection cannot replace the live R owner.
pub(crate) struct VerifiedDirectBearerAuthenticatorOrigin {
    runtime_binding: Arc<VerifiedEntraAuthenticatorRuntimeBinding>,
    origin_projection: AuthenticatorOriginProjection,
    origin_binding_digest: String,
    origin_binding_digest_bytes: [u8; 32],
    issuer_authority_binding_digest: String,
}

impl fmt::Debug for VerifiedDirectBearerAuthenticatorOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDirectBearerAuthenticatorOrigin")
            .field("origin", &"[REDACTED]")
            .field("origin_binding_digest", &"[REDACTED]")
            .field("issuer_authority_binding_digest", &"[REDACTED]")
            .field("path_kind", &DIRECT_BEARER_PATH_KIND)
            .finish_non_exhaustive()
    }
}

fn entra_direct_bearer_origin_projection(
    runtime_binding: &VerifiedEntraAuthenticatorRuntimeBinding,
) -> Result<(AuthenticatorOriginProjection, String), String> {
    runtime_binding.verify_integrity()?;
    let authority = runtime_binding.authority.as_ref();
    let bearer_paths = runtime_binding
        .measured_projection()
        .credential_paths
        .iter()
        .filter(|path| path.credential_profile.token_profile == "jwt-access-token")
        .collect::<Vec<_>>();
    let bearer_path = match bearer_paths.as_slice() {
        [path]
            if path.path_id == ENTRA_BEARER_PATH_ID
                && path.path_version == ENTRA_BEARER_PATH_VERSION
                && authority.bearer_path_id() == path.path_id
                && authority.bearer_path_version() == path.path_version
                && path.verifier.issuer_binding_digest
                    == runtime_binding
                        .bearer_observation
                        .issuer_authority_binding_digest() =>
        {
            *path
        }
        _ => {
            return Err("sealed Entra runtime does not retain one exact direct-bearer path".into());
        }
    };
    let projection = AuthenticatorOriginProjection {
        deployment_id: authority.deployment_id().to_owned(),
        trust_domain_id: authority.trust_domain_id().to_owned(),
        tenant_id: authority.tenant_id().map(str::to_owned),
        provider_id: authority.provider_id().to_owned(),
        provider_configuration_version: authority.provider_configuration_version(),
        provider_configuration_payload_digest: authority
            .provider_configuration_payload_digest()
            .to_owned(),
        provider_lifecycle_record_version: authority.provider_lifecycle_record_version(),
        provider_lifecycle_state: authority.provider_lifecycle_state(),
        binding_document_reference: authority.binding_document_reference().clone(),
        provider_policy_binding_digest: authority.provider_policy_binding_digest().to_owned(),
        runtime_binding_digest: runtime_binding.runtime_binding_digest().to_owned(),
        path_id: bearer_path.path_id.clone(),
        path_version: bearer_path.path_version,
    };
    Ok((
        projection,
        bearer_path.verifier.issuer_binding_digest.clone(),
    ))
}

impl VerifiedDirectBearerAuthenticatorOrigin {
    fn seal(
        runtime_binding: Arc<VerifiedEntraAuthenticatorRuntimeBinding>,
    ) -> Result<Arc<Self>, String> {
        let (origin_projection, issuer_authority_binding_digest) =
            entra_direct_bearer_origin_projection(&runtime_binding)?;
        let origin_binding_digest = authenticator_origin_binding_digest(&origin_projection)
            .map_err(|error| format!("direct-bearer authenticator origin is invalid: {error}"))?;
        let origin_binding_digest_bytes = digest_bytes(
            &origin_binding_digest,
            "direct-bearer authenticator origin digest",
        )?;
        let sealed = Arc::new(Self {
            runtime_binding,
            origin_projection,
            origin_binding_digest,
            origin_binding_digest_bytes,
            issuer_authority_binding_digest,
        });
        sealed.verify_integrity()?;
        Ok(sealed)
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), String> {
        let (reprojected, remeasured_issuer_digest) =
            entra_direct_bearer_origin_projection(&self.runtime_binding)?;
        let redigested = authenticator_origin_binding_digest(&reprojected).map_err(|error| {
            format!("retained direct-bearer authenticator origin is invalid: {error}")
        })?;
        let decoded = digest_bytes(
            &redigested,
            "retained direct-bearer authenticator origin digest",
        )?;
        if reprojected != self.origin_projection
            || redigested != self.origin_binding_digest
            || decoded != self.origin_binding_digest_bytes
            || remeasured_issuer_digest != self.issuer_authority_binding_digest
        {
            return Err(
                "retained direct-bearer authenticator origin differs from canonical remeasurement"
                    .into(),
            );
        }
        Ok(())
    }

    pub(crate) fn origin_projection(&self) -> &AuthenticatorOriginProjection {
        &self.origin_projection
    }

    pub(crate) fn origin_binding_digest(&self) -> &str {
        &self.origin_binding_digest
    }

    pub(crate) fn origin_binding_digest_bytes(&self) -> &[u8; 32] {
        &self.origin_binding_digest_bytes
    }

    pub(crate) fn provider_binding(&self) -> &ExpectedProviderBinding {
        self.runtime_binding.provider_binding()
    }

    pub(crate) fn provider_id(&self) -> &str {
        &self.origin_projection.provider_id
    }

    pub(crate) fn path_id(&self) -> &str {
        &self.origin_projection.path_id
    }

    pub(crate) fn path_version(&self) -> u64 {
        self.origin_projection.path_version
    }

    pub(crate) fn path_kind(&self) -> &'static str {
        DIRECT_BEARER_PATH_KIND
    }

    pub(crate) fn federated_authority_max_staleness_seconds(&self) -> Result<u64, String> {
        self.verify_integrity()?;
        let session_credentials = self.runtime_binding.derived_session_credentials()?;
        let maximum_staleness = session_credentials.federated_authority_max_staleness_seconds();
        if maximum_staleness == 0 {
            return Err(
                "sealed direct-bearer origin has no federated-authority staleness budget".into(),
            );
        }
        Ok(maximum_staleness)
    }

    /// Compare the exact signed issuer string against the issuer retained by
    /// the sealed validator without exposing or accepting a provider identity.
    pub(crate) fn matches_validated_issuer(&self, issuer: &str) -> bool {
        leaf_binding_digest(ENTRA_ISSUER_AUTHORITY_BINDING_DOMAIN, &[issuer.as_bytes()])
            == self.issuer_authority_binding_digest
    }

    pub(crate) fn retains_entra_runtime_binding(
        &self,
        runtime_binding: &Arc<VerifiedEntraAuthenticatorRuntimeBinding>,
    ) -> bool {
        Arc::ptr_eq(&self.runtime_binding, runtime_binding)
    }
}

enum BrowserAuthenticatorOriginSource {
    Entra(Arc<VerifiedEntraAuthenticatorRuntimeBinding>),
    #[cfg(test)]
    Fixture(String),
}

/// Exact canonical provenance for one live browser-derived session path.
///
/// Production construction is possible only from a sealed live R allocation.
/// The digest bytes are decoded from the canonical origin digest and are never
/// accepted from a caller.
pub(crate) struct VerifiedBrowserAuthenticatorOrigin {
    source: BrowserAuthenticatorOriginSource,
    origin_projection: AuthenticatorOriginProjection,
    origin_binding_digest: String,
    origin_binding_digest_bytes: [u8; 32],
}

impl fmt::Debug for VerifiedBrowserAuthenticatorOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBrowserAuthenticatorOrigin")
            .field("origin", &"[REDACTED]")
            .field("origin_binding_digest", &"[REDACTED]")
            .field("path_kind", &BROWSER_DERIVED_SESSION_PATH_KIND)
            .finish_non_exhaustive()
    }
}

fn entra_browser_origin_projection(
    runtime_binding: &VerifiedEntraAuthenticatorRuntimeBinding,
) -> Result<AuthenticatorOriginProjection, String> {
    runtime_binding.verify_integrity()?;
    let authority = runtime_binding.authority.as_ref();
    let browser_paths = runtime_binding
        .measured_projection()
        .credential_paths
        .iter()
        .filter(|path| path.credential_profile.token_profile == "oidc-id-token")
        .collect::<Vec<_>>();
    let browser_path = match browser_paths.as_slice() {
        [path]
            if path.path_id == ENTRA_BROWSER_PATH_ID
                && path.path_version == ENTRA_BROWSER_PATH_VERSION
                && authority.browser_path_id() == Some(path.path_id.as_str())
                && authority.browser_path_version() == Some(path.path_version) =>
        {
            *path
        }
        _ => {
            return Err(
                "sealed Entra runtime does not retain one exact browser-derived session path"
                    .into(),
            );
        }
    };
    Ok(AuthenticatorOriginProjection {
        deployment_id: authority.deployment_id().to_owned(),
        trust_domain_id: authority.trust_domain_id().to_owned(),
        tenant_id: authority.tenant_id().map(str::to_owned),
        provider_id: authority.provider_id().to_owned(),
        provider_configuration_version: authority.provider_configuration_version(),
        provider_configuration_payload_digest: authority
            .provider_configuration_payload_digest()
            .to_owned(),
        provider_lifecycle_record_version: authority.provider_lifecycle_record_version(),
        provider_lifecycle_state: authority.provider_lifecycle_state(),
        binding_document_reference: authority.binding_document_reference().clone(),
        provider_policy_binding_digest: authority.provider_policy_binding_digest().to_owned(),
        runtime_binding_digest: runtime_binding.runtime_binding_digest().to_owned(),
        path_id: browser_path.path_id.clone(),
        path_version: browser_path.path_version,
    })
}

#[cfg(test)]
fn fixture_browser_origin_projection(label: &str) -> AuthenticatorOriginProjection {
    let digest = |domain: &'static [u8]| leaf_binding_digest(domain, &[label.as_bytes()]);
    AuthenticatorOriginProjection {
        deployment_id: format!("deployment:fixture-{label}"),
        trust_domain_id: format!("trust-domain:fixture-{label}"),
        tenant_id: None,
        provider_id: format!("provider:fixture-{label}"),
        provider_configuration_version: 1,
        provider_configuration_payload_digest: digest(b"browser-origin-fixture-p"),
        provider_lifecycle_record_version: 1,
        provider_lifecycle_state: ProviderLifecycleState::Active,
        binding_document_reference:
            ryuki_core::security_profile::AuthenticatorRuntimeBindingDocumentReference {
                document_id: format!("authenticator-runtime-binding:fixture-{label}"),
                document_version: 1,
                content_digest: digest(b"browser-origin-fixture-d"),
                artifact_locator: format!(
                    "catalog/security-contracts/v1/authenticator-runtime-binding.{label}.json"
                ),
            },
        provider_policy_binding_digest: digest(b"browser-origin-fixture-q"),
        runtime_binding_digest: digest(b"browser-origin-fixture-r"),
        path_id: format!("authenticator-path:fixture-{label}-browser"),
        path_version: 1,
    }
}

impl VerifiedBrowserAuthenticatorOrigin {
    fn seal(
        runtime_binding: Arc<VerifiedEntraAuthenticatorRuntimeBinding>,
    ) -> Result<Arc<Self>, String> {
        let projection = entra_browser_origin_projection(&runtime_binding)?;
        Self::seal_projection(
            BrowserAuthenticatorOriginSource::Entra(runtime_binding),
            projection,
        )
    }

    fn seal_projection(
        source: BrowserAuthenticatorOriginSource,
        origin_projection: AuthenticatorOriginProjection,
    ) -> Result<Arc<Self>, String> {
        let origin_binding_digest = authenticator_origin_binding_digest(&origin_projection)
            .map_err(|error| format!("browser authenticator origin is invalid: {error}"))?;
        let origin_binding_digest_bytes = digest_bytes(
            &origin_binding_digest,
            "browser authenticator origin digest",
        )?;
        let sealed = Arc::new(Self {
            source,
            origin_projection,
            origin_binding_digest,
            origin_binding_digest_bytes,
        });
        sealed.verify_integrity()?;
        Ok(sealed)
    }

    #[cfg(test)]
    pub(crate) fn fixture(label: &str) -> Arc<Self> {
        let bytes = label.as_bytes();
        assert!(
            (3..=48).contains(&bytes.len())
                && bytes.first().is_some_and(u8::is_ascii_lowercase)
                && bytes.iter().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                }),
            "browser-origin fixture labels must be canonical lowercase identifiers"
        );
        Self::seal_projection(
            BrowserAuthenticatorOriginSource::Fixture(label.to_owned()),
            fixture_browser_origin_projection(label),
        )
        .expect("browser-origin fixture must satisfy the production canonical invariants")
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), String> {
        let reprojected = match &self.source {
            BrowserAuthenticatorOriginSource::Entra(runtime_binding) => {
                entra_browser_origin_projection(runtime_binding)?
            }
            #[cfg(test)]
            BrowserAuthenticatorOriginSource::Fixture(label) => {
                fixture_browser_origin_projection(label)
            }
        };
        let redigested = authenticator_origin_binding_digest(&reprojected).map_err(|error| {
            format!("retained browser authenticator origin is invalid: {error}")
        })?;
        let decoded = digest_bytes(&redigested, "retained browser authenticator origin digest")?;
        if reprojected != self.origin_projection
            || redigested != self.origin_binding_digest
            || decoded != self.origin_binding_digest_bytes
        {
            return Err(
                "retained browser authenticator origin differs from canonical remeasurement".into(),
            );
        }
        Ok(())
    }

    pub(crate) fn origin_projection(&self) -> &AuthenticatorOriginProjection {
        &self.origin_projection
    }

    pub(crate) fn origin_binding_digest(&self) -> &str {
        &self.origin_binding_digest
    }

    pub(crate) fn origin_binding_digest_bytes(&self) -> &[u8; 32] {
        &self.origin_binding_digest_bytes
    }

    pub(crate) fn provider_id(&self) -> &str {
        &self.origin_projection.provider_id
    }

    pub(crate) fn path_id(&self) -> &str {
        &self.origin_projection.path_id
    }

    pub(crate) fn path_version(&self) -> u64 {
        self.origin_projection.path_version
    }

    pub(crate) fn path_kind(&self) -> &'static str {
        BROWSER_DERIVED_SESSION_PATH_KIND
    }

    pub(crate) fn retains_entra_runtime_binding(
        &self,
        runtime_binding: &Arc<VerifiedEntraAuthenticatorRuntimeBinding>,
    ) -> bool {
        matches!(
            &self.source,
            BrowserAuthenticatorOriginSource::Entra(retained)
                if Arc::ptr_eq(retained, runtime_binding)
        )
    }

    pub(crate) fn retains_entra_sso_dependencies(&self, dependencies: &Arc<EntraSsoDeps>) -> bool {
        match &self.source {
            BrowserAuthenticatorOriginSource::Entra(runtime_binding) => {
                runtime_binding.retains_entra_sso_dependencies(dependencies)
            }
            #[cfg(test)]
            BrowserAuthenticatorOriginSource::Fixture(_) => false,
        }
    }
}

/// Handler-facing, post-seal composition of the exact Entra browser runtime
/// and the provenance derived from its measured R. Keeping this as one opaque
/// Extension prevents independent dependency/origin substitution.
pub(crate) struct VerifiedEntraSsoHandlerDeps {
    base: Arc<EntraSsoDeps>,
    origin: Arc<VerifiedBrowserAuthenticatorOrigin>,
    #[cfg(test)]
    synthetic_origin_allowed: bool,
}

impl fmt::Debug for VerifiedEntraSsoHandlerDeps {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedEntraSsoHandlerDeps")
            .field("base", &"[RETAINED]")
            .field("origin", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VerifiedEntraSsoHandlerDeps {
    fn seal(
        base: Arc<EntraSsoDeps>,
        origin: Arc<VerifiedBrowserAuthenticatorOrigin>,
    ) -> Result<Arc<Self>, String> {
        let sealed = Arc::new(Self {
            base,
            origin,
            #[cfg(test)]
            synthetic_origin_allowed: false,
        });
        sealed.verify_integrity()?;
        Ok(sealed)
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        base: Arc<EntraSsoDeps>,
        origin: Arc<VerifiedBrowserAuthenticatorOrigin>,
    ) -> Arc<Self> {
        assert!(matches!(
            &origin.source,
            BrowserAuthenticatorOriginSource::Fixture(_)
        ));
        let sealed = Arc::new(Self {
            base,
            origin,
            synthetic_origin_allowed: true,
        });
        sealed
            .verify_integrity()
            .expect("test Entra handler dependencies must retain exact fixture allocations");
        sealed
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), String> {
        self.origin.verify_integrity()?;
        let origin_retains_base = self.origin.retains_entra_sso_dependencies(&self.base);
        #[cfg(test)]
        let origin_retains_base = origin_retains_base
            || (self.synthetic_origin_allowed
                && matches!(
                    &self.origin.source,
                    BrowserAuthenticatorOriginSource::Fixture(_)
                ));
        if !self.base.remeasures_runtime_observation() || !origin_retains_base {
            return Err(
                "Entra SSO handler authority does not retain one exact measured dependency set"
                    .into(),
            );
        }
        Ok(())
    }

    pub(crate) fn base(&self) -> &Arc<EntraSsoDeps> {
        &self.base
    }

    pub(crate) fn origin(&self) -> &Arc<VerifiedBrowserAuthenticatorOrigin> {
        &self.origin
    }
}

/// One non-cloneable owner for the exact authenticator objects used by the API.
///
/// Callers share this allocation through `Arc<ApiAuthenticatorRuntime>`.  The
/// contained objects are intentionally private, and startup composition gives
/// production consumers only Arc clones originating from this owner.
pub(crate) struct ApiAuthenticatorRuntime {
    auth_mode: AuthMode,
    generic_oidc_enabled: bool,
    operational_observation: Arc<AuthenticatorRuntimeObservation>,
    api_cookie_runtime: Arc<ApiCookieRuntime>,
    entra_authenticator_authority: Option<Arc<ResolvedEntraAuthenticatorAuthority>>,
    authenticator_bearer_limits: Option<Arc<ResolvedAuthenticatorBearerLimits>>,
    authenticator_browser_limits: Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
    entra_bearer_validator: Option<Arc<EntraTokenValidator>>,
    entra_bearer_observation: Option<Arc<EntraBearerRuntimeObservation>>,
    derived_session_credentials: Arc<DerivedSessionCredentialRuntime>,
    derived_session_observation: Arc<DerivedSessionRuntimeObservation>,
    verified_entra_runtime_binding: Option<Arc<VerifiedEntraAuthenticatorRuntimeBinding>>,
    browser_authenticator_origin: Option<Arc<VerifiedBrowserAuthenticatorOrigin>>,
    oidc_callback_dependencies: Arc<OidcCallbackDeps>,
    entra_sso_dependencies: Arc<EntraSsoDeps>,
    entra_sso_handler_dependencies: Option<Arc<VerifiedEntraSsoHandlerDeps>>,
    local_login_throttle: Arc<LocalLoginThrottle>,
}

impl ApiAuthenticatorRuntime {
    /// Construct every process-local authenticator exactly once from already
    /// admitted startup configuration.
    pub(crate) fn from_admitted_config(
        config: &RyukiConfig,
        api_cookie_runtime: Arc<ApiCookieRuntime>,
        entra_authenticator_authority: Option<Arc<ResolvedEntraAuthenticatorAuthority>>,
        production_profile: bool,
    ) -> Result<Arc<Self>, String> {
        if config.oidc.enabled {
            return Err(GENERIC_OIDC_NOT_ADMITTED.into());
        }
        api_cookie_runtime
            .validate_config_binding(config, production_profile)
            .map_err(|error| error.to_string())?;
        let (authenticator_bearer_limits, authenticator_browser_limits) = if config.auth_mode
            == AuthMode::EntraId
        {
            let authority = entra_authenticator_authority.as_ref().ok_or_else(|| {
                    "Entra runtime requires one exact authenticator authority resolved from the active security contract"
                        .to_string()
                })?;
            authority.verify_integrity()?;

            let configured_browser_path = !config.entra_redirect_uri.is_empty();
            let declared_browser_path = authority.browser_path_id().is_some();
            let resolved_browser_limits = authority.browser_limits().is_some();
            if declared_browser_path != resolved_browser_limits {
                return Err(
                    "Entra authority has inconsistent browser path and limit ownership".into(),
                );
            }
            match (configured_browser_path, declared_browser_path) {
                (true, false) => {
                    return Err(
                            "configured Entra browser SSO has no exact browser path in the retained authenticator D"
                                .into(),
                        );
                }
                (false, true) => {
                    return Err(
                            "retained authenticator D declares a dormant Entra browser path without a configured redirect"
                                .into(),
                        );
                }
                _ => {}
            }

            (
                Some(Arc::clone(authority.bearer_limits())),
                if configured_browser_path {
                    authority.browser_limits().map(Arc::clone)
                } else {
                    None
                },
            )
        } else {
            if entra_authenticator_authority.is_some() {
                return Err(
                    "non-Entra runtime cannot retain dormant Entra authenticator authority".into(),
                );
            }
            (None, None)
        };
        let (entra_bearer_validator, entra_bearer_observation) = if config.auth_mode
            == AuthMode::EntraId
        {
            let limits = authenticator_bearer_limits.as_ref().ok_or_else(|| {
                    "Entra runtime requires exact bearer limits resolved from the active security contract"
                        .to_string()
                })?;
            limits.verify_integrity()?;
            let validator = Arc::new(EntraTokenValidator::from_app_config(
                &config.entra_tenant_id,
                &config.entra_client_id,
                &config.entra_authority,
                config.entra_jwks_ttl_secs,
                Arc::clone(limits),
            ));
            if !validator.retains_bearer_limits(limits) {
                return Err(
                    "Entra bearer validator did not retain the admitted limit authority".into(),
                );
            }
            let observation = Arc::new(validator.runtime_observation());
            (Some(validator), Some(observation))
        } else {
            (None, None)
        };
        match (
            config.auth_mode == AuthMode::EntraId && !config.entra_redirect_uri.is_empty(),
            authenticator_browser_limits.is_some(),
        ) {
            (true, false) => {
                return Err(
                    "configured Entra browser SSO requires exact browser limits resolved from the active security contract"
                        .into(),
                );
            }
            (false, true) => {
                return Err("runtime cannot retain dormant Entra browser-limit authority".into());
            }
            _ => {}
        }
        if let Some(browser_limits) = authenticator_browser_limits.as_deref() {
            browser_limits.verify_integrity()?;
            let bearer_limits = authenticator_bearer_limits.as_deref().ok_or_else(|| {
                "Entra browser limits cannot be retained without bearer-limit authority".to_string()
            })?;
            if browser_limits.clock_skew_limit_id() != bearer_limits.clock_skew_limit_id()
                || browser_limits.maximum_clock_skew_seconds()
                    != bearer_limits.maximum_clock_skew_seconds()
            {
                return Err(
                    "Entra bearer and browser paths must retain the same resolved clock-skew authority"
                        .into(),
                );
            }
        }
        let derived_session_credentials =
            DerivedSessionCredentialRuntime::from_admitted_config(&config.session)
                .map_err(|error| error.to_string())?;
        let derived_session_observation =
            Arc::new(derived_session_credentials.runtime_observation());
        let operational_observation = Arc::new(AuthenticatorRuntimeObservation::measure(
            config,
            entra_bearer_observation.as_ref().map(Arc::clone),
            authenticator_browser_limits.as_deref(),
            Arc::clone(&derived_session_observation),
        )?);

        let (token_endpoint, jwks_endpoint, issuer, audience) = if config.oidc.enabled {
            // The issuer claim is an exact protocol identifier. Parse it to
            // enforce the endpoint policy, but retain the configured spelling:
            // `Url::to_string()` adds a trailing slash to a bare origin and
            // would make otherwise-valid `iss` claims fail exact comparison.
            let issuer = validated_exact_identity_url(&config.oidc.issuer, "generic OIDC issuer")?;
            (
                normalized_identity_url(
                    &config.oidc.token_endpoint,
                    "generic OIDC token endpoint",
                )?,
                normalized_identity_url(&config.oidc.jwks_uri, "generic OIDC JWKS endpoint")?,
                issuer,
                config.oidc.client_id.clone(),
            )
        } else {
            (
                DISABLED_OIDC_TOKEN_ENDPOINT.to_string(),
                DISABLED_OIDC_JWKS_ENDPOINT.to_string(),
                DISABLED_OIDC_ISSUER.to_string(),
                DISABLED_OIDC_AUDIENCE.to_string(),
            )
        };
        let exchanger: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(ReqwestTokenExchanger::new(token_endpoint));
        let validator = Arc::new(OidcIdTokenValidator::new(
            jwks_endpoint,
            issuer,
            audience,
            OIDC_CLOCK_SKEW_SECONDS,
        ));
        // Generic OIDC has no resolved D/P/Q authority yet. It must never
        // borrow the separately measured Entra origin merely because both
        // paths happen to use authorization code + PKCE.
        let generic_oidc_origin: Option<Arc<VerifiedBrowserAuthenticatorOrigin>> = None;
        let oidc_callback_dependencies = Arc::new(OidcCallbackDeps::new(
            exchanger,
            validator,
            Arc::clone(&derived_session_credentials),
            Arc::clone(&api_cookie_runtime),
            generic_oidc_origin.as_ref().map(Arc::clone),
        )?);
        if !oidc_callback_dependencies.retains_browser_authenticator_origin(&generic_oidc_origin) {
            return Err("generic OIDC dependencies retained a foreign browser origin".into());
        }
        let entra_sso_dependencies = EntraSsoDeps::from_app_config(
            config,
            authenticator_browser_limits.as_ref().map(Arc::clone),
            Arc::clone(&derived_session_credentials),
            Arc::clone(&api_cookie_runtime),
        );
        if !entra_sso_dependencies.retains_browser_limits(&authenticator_browser_limits) {
            return Err(
                "Entra browser SSO dependencies did not retain the admitted limit authority".into(),
            );
        }
        let verified_entra_runtime_binding = if config.auth_mode == AuthMode::EntraId
            && !config.oidc.enabled
            && derived_session_credentials.enabled()
            && api_cookie_runtime.secure_policy_set().is_some()
        {
            Some(VerifiedEntraAuthenticatorRuntimeBinding::seal(
                Arc::clone(
                    entra_authenticator_authority
                        .as_ref()
                        .expect("validated Entra authority must be present"),
                ),
                Arc::clone(
                    entra_bearer_validator
                        .as_ref()
                        .expect("validated Entra bearer validator must be present"),
                ),
                Arc::clone(
                    entra_bearer_observation
                        .as_ref()
                        .expect("validated Entra bearer observation must be present"),
                ),
                Arc::clone(&entra_sso_dependencies),
                Arc::clone(&derived_session_credentials),
                Arc::clone(&derived_session_observation),
                Arc::clone(&api_cookie_runtime),
            )?)
        } else {
            None
        };
        let browser_authenticator_origin = verified_entra_runtime_binding
            .as_ref()
            .map(VerifiedEntraAuthenticatorRuntimeBinding::browser_origin)
            .transpose()?
            .flatten();
        let entra_sso_handler_dependencies = browser_authenticator_origin
            .as_ref()
            .map(|origin| {
                VerifiedEntraSsoHandlerDeps::seal(
                    Arc::clone(&entra_sso_dependencies),
                    Arc::clone(origin),
                )
            })
            .transpose()?;

        Ok(Arc::new(Self {
            auth_mode: config.auth_mode.clone(),
            generic_oidc_enabled: config.oidc.enabled,
            operational_observation,
            api_cookie_runtime,
            entra_authenticator_authority,
            authenticator_bearer_limits,
            authenticator_browser_limits,
            entra_bearer_validator,
            entra_bearer_observation,
            derived_session_credentials,
            derived_session_observation,
            verified_entra_runtime_binding,
            browser_authenticator_origin,
            oidc_callback_dependencies,
            entra_sso_dependencies,
            entra_sso_handler_dependencies,
            local_login_throttle: Arc::new(LocalLoginThrottle::default()),
        }))
    }

    pub(crate) fn auth_mode(&self) -> &AuthMode {
        &self.auth_mode
    }

    /// Exact non-secret operational leaves measured by the private
    /// constructor. Callers can retain this Arc but cannot forge an
    /// observation through a public constructor.
    pub(crate) fn operational_observation(&self) -> &Arc<AuthenticatorRuntimeObservation> {
        &self.operational_observation
    }

    /// Reject every currently implemented development or password posture.
    /// A generic OIDC callback cannot launder a rejected base mode because
    /// admission is determined by the closed `auth_mode` posture first.
    pub(crate) fn validate_production_posture(
        &self,
    ) -> Result<&AuthenticatorRuntimeObservation, AuthenticatorRuntimePostureError> {
        match self.operational_observation.posture() {
            ProductionAuthenticatorPosture::EntraOidc
                if !self.derived_session_credentials.enabled() =>
            {
                Err(AuthenticatorRuntimePostureError::DerivedSessionCredentialUnavailable)
            }
            ProductionAuthenticatorPosture::EntraOidc
                if !self.has_closed_entra_authenticator_authority()
                    || !self.has_closed_entra_bearer_authority()
                    || !self.has_closed_entra_browser_authority()
                    || !self.has_measured_entra_runtime_binding() =>
            {
                Err(AuthenticatorRuntimePostureError::UnboundAuthenticator)
            }
            ProductionAuthenticatorPosture::EntraOidc if self.generic_oidc_enabled => {
                Err(AuthenticatorRuntimePostureError::UnboundAuthenticator)
            }
            ProductionAuthenticatorPosture::EntraOidc => Ok(&self.operational_observation),
            ProductionAuthenticatorPosture::CredentialFreeMockDryRun
            | ProductionAuthenticatorPosture::CredentialFreeStaticDryRun => {
                Err(AuthenticatorRuntimePostureError::CredentialFree)
            }
            ProductionAuthenticatorPosture::PasswordLocal => {
                Err(AuthenticatorRuntimePostureError::PasswordLocal)
            }
        }
    }

    fn has_closed_entra_authenticator_authority(&self) -> bool {
        let Some(authority) = self.entra_authenticator_authority.as_ref() else {
            return false;
        };
        if authority.verify_integrity().is_err() {
            return false;
        }
        let retains_bearer_limits = self
            .authenticator_bearer_limits
            .as_ref()
            .is_some_and(|limits| Arc::ptr_eq(limits, authority.bearer_limits()));
        let retains_browser_limits = match (
            self.authenticator_browser_limits.as_ref(),
            authority.browser_limits(),
        ) {
            (Some(retained), Some(declared)) => Arc::ptr_eq(retained, declared),
            (None, None) => true,
            _ => false,
        };
        retains_bearer_limits && retains_browser_limits
    }

    fn has_closed_entra_bearer_authority(&self) -> bool {
        match (
            self.authenticator_bearer_limits.as_ref(),
            self.entra_bearer_validator.as_deref(),
            self.entra_bearer_observation.as_deref(),
        ) {
            (Some(limits), Some(validator), Some(observation)) => {
                limits.verify_integrity().is_ok()
                    && validator.retains_bearer_limits(limits)
                    && *observation == validator.runtime_observation()
            }
            _ => false,
        }
    }

    fn has_closed_entra_browser_authority(&self) -> bool {
        match (
            self.authenticator_browser_limits.as_ref(),
            self.operational_observation
                .entra_browser_clock_skew_limit_id
                .as_deref(),
            self.operational_observation
                .entra_browser_maximum_clock_skew_seconds,
        ) {
            (Some(limits), Some(limit_id), Some(maximum_seconds)) => {
                limits.verify_integrity().is_ok()
                    && limits.clock_skew_limit_id() == limit_id
                    && limits.maximum_clock_skew_seconds() == maximum_seconds
                    && self
                        .entra_sso_dependencies
                        .retains_browser_limits(&self.authenticator_browser_limits)
            }
            (None, None, None) => self.entra_sso_dependencies.retains_browser_limits(&None),
            _ => false,
        }
    }

    fn has_measured_entra_runtime_binding(&self) -> bool {
        let (Some(binding), Some(authority), Some(bearer_validator), Some(bearer_observation)) = (
            self.verified_entra_runtime_binding.as_ref(),
            self.entra_authenticator_authority.as_ref(),
            self.entra_bearer_validator.as_ref(),
            self.entra_bearer_observation.as_ref(),
        ) else {
            return false;
        };
        if binding.verify_integrity().is_err()
            || !binding.cookie_observation.production()
            || self.measured_entra_runtime_projection() != Some(binding.measured_projection())
            || self.measured_entra_runtime_binding_digest()
                != Some(binding.runtime_binding_digest())
            || self.measured_authenticator_inventory_value()
                != Some(binding.measured_authenticator_inventory_value())
            || self.measured_authenticator_inventory_digest()
                != Some(binding.measured_authenticator_inventory_digest())
            || self.expected_authenticator_inventory_value()
                != Some(binding.expected_authenticator_inventory_value())
            || self.expected_authenticator_inventory_digest()
                != Some(binding.expected_authenticator_inventory_digest())
            || !binding.retains_authority(authority)
            || !binding.retains_entra_sso_dependencies(&self.entra_sso_dependencies)
            || !Arc::ptr_eq(&binding.bearer_validator, bearer_validator)
            || !Arc::ptr_eq(&binding.bearer_observation, bearer_observation)
            || !Arc::ptr_eq(
                &binding.derived_session_credentials,
                &self.derived_session_credentials,
            )
            || !Arc::ptr_eq(
                &binding.derived_session_observation,
                &self.derived_session_observation,
            )
            || !Arc::ptr_eq(&binding.cookie_runtime, &self.api_cookie_runtime)
        {
            return false;
        }
        match (
            authority.browser_path_id(),
            self.browser_authenticator_origin.as_ref(),
            self.entra_sso_handler_dependencies.as_ref(),
        ) {
            (Some(_), Some(origin), Some(handler)) => {
                origin.verify_integrity().is_ok()
                    && origin.retains_entra_runtime_binding(binding)
                    && handler.verify_integrity().is_ok()
                    && Arc::ptr_eq(handler.base(), &self.entra_sso_dependencies)
                    && Arc::ptr_eq(handler.origin(), origin)
            }
            (None, None, None) => true,
            _ => false,
        }
    }

    pub(crate) fn api_cookie_runtime(&self) -> Arc<ApiCookieRuntime> {
        Arc::clone(&self.api_cookie_runtime)
    }

    pub(crate) fn entra_authenticator_authority(
        &self,
    ) -> Option<Arc<ResolvedEntraAuthenticatorAuthority>> {
        self.entra_authenticator_authority.as_ref().map(Arc::clone)
    }

    #[cfg(test)]
    pub(crate) fn authenticator_bearer_limits(
        &self,
    ) -> Option<Arc<ResolvedAuthenticatorBearerLimits>> {
        self.authenticator_bearer_limits.as_ref().map(Arc::clone)
    }

    #[cfg(test)]
    pub(crate) fn authenticator_browser_limits(
        &self,
    ) -> Option<Arc<ResolvedAuthenticatorBrowserLimits>> {
        self.authenticator_browser_limits.as_ref().map(Arc::clone)
    }

    pub(crate) fn entra_bearer_validator(&self) -> Option<Arc<EntraTokenValidator>> {
        self.entra_bearer_validator.as_ref().map(Arc::clone)
    }

    pub(crate) fn entra_bearer_observation(&self) -> Option<Arc<EntraBearerRuntimeObservation>> {
        self.entra_bearer_observation.as_ref().map(Arc::clone)
    }

    pub(crate) fn derived_session_credentials(&self) -> Arc<DerivedSessionCredentialRuntime> {
        Arc::clone(&self.derived_session_credentials)
    }

    pub(crate) fn derived_session_observation(&self) -> Arc<DerivedSessionRuntimeObservation> {
        Arc::clone(&self.derived_session_observation)
    }

    pub(crate) fn verified_entra_runtime_binding(
        &self,
    ) -> Option<Arc<VerifiedEntraAuthenticatorRuntimeBinding>> {
        self.verified_entra_runtime_binding.as_ref().map(Arc::clone)
    }

    pub(crate) fn measured_entra_runtime_projection(
        &self,
    ) -> Option<&AuthenticatorRuntimeBindingProjection> {
        self.verified_entra_runtime_binding
            .as_deref()
            .map(VerifiedEntraAuthenticatorRuntimeBinding::measured_projection)
    }

    pub(crate) fn measured_entra_runtime_binding_digest(&self) -> Option<&str> {
        self.verified_entra_runtime_binding
            .as_deref()
            .map(VerifiedEntraAuthenticatorRuntimeBinding::runtime_binding_digest)
    }

    pub(crate) fn measured_authenticator_inventory_value(
        &self,
    ) -> Option<&RuntimeGuardExpectedValue> {
        self.verified_entra_runtime_binding
            .as_deref()
            .map(VerifiedEntraAuthenticatorRuntimeBinding::measured_authenticator_inventory_value)
    }

    pub(crate) fn measured_authenticator_inventory_digest(&self) -> Option<&str> {
        self.verified_entra_runtime_binding
            .as_deref()
            .map(VerifiedEntraAuthenticatorRuntimeBinding::measured_authenticator_inventory_digest)
    }

    /// Guard-shaped view of the independently measured inventory. It remains
    /// runtime evidence and must be compared with authenticated receipt state.
    pub(crate) fn expected_authenticator_inventory_value(
        &self,
    ) -> Option<&RuntimeGuardExpectedValue> {
        self.verified_entra_runtime_binding
            .as_deref()
            .map(VerifiedEntraAuthenticatorRuntimeBinding::expected_authenticator_inventory_value)
    }

    /// Guard-shaped digest of the independently measured inventory, not a
    /// declaration-side expectation.
    pub(crate) fn expected_authenticator_inventory_digest(&self) -> Option<&str> {
        self.verified_entra_runtime_binding
            .as_deref()
            .map(VerifiedEntraAuthenticatorRuntimeBinding::expected_authenticator_inventory_digest)
    }

    pub(crate) fn browser_authenticator_origin(
        &self,
    ) -> Option<Arc<VerifiedBrowserAuthenticatorOrigin>> {
        self.browser_authenticator_origin.as_ref().map(Arc::clone)
    }

    pub(crate) fn oidc_callback_dependencies(&self) -> Arc<OidcCallbackDeps> {
        Arc::clone(&self.oidc_callback_dependencies)
    }

    pub(crate) fn entra_sso_dependencies(&self) -> Arc<EntraSsoDeps> {
        Arc::clone(&self.entra_sso_dependencies)
    }

    pub(crate) fn entra_sso_handler_dependencies(
        &self,
    ) -> Option<Arc<VerifiedEntraSsoHandlerDeps>> {
        self.entra_sso_handler_dependencies.as_ref().map(Arc::clone)
    }

    pub(crate) fn local_login_throttle(&self) -> Arc<LocalLoginThrottle> {
        Arc::clone(&self.local_login_throttle)
    }

    pub(crate) fn retains_cookie_runtime(&self, runtime: &Arc<ApiCookieRuntime>) -> bool {
        Arc::ptr_eq(&self.api_cookie_runtime, runtime)
    }

    pub(crate) fn retains_operational_observation(
        &self,
        observation: &Arc<AuthenticatorRuntimeObservation>,
    ) -> bool {
        Arc::ptr_eq(&self.operational_observation, observation)
    }

    pub(crate) fn retains_entra_authenticator_authority(
        &self,
        authority: &Option<Arc<ResolvedEntraAuthenticatorAuthority>>,
    ) -> bool {
        let same_owner = match (&self.entra_authenticator_authority, authority) {
            (Some(retained), Some(candidate)) => Arc::ptr_eq(retained, candidate),
            (None, None) => true,
            _ => false,
        };
        same_owner
            && match &self.auth_mode {
                AuthMode::EntraId => self.has_closed_entra_authenticator_authority(),
                AuthMode::MockDryRun | AuthMode::StaticDryRun | AuthMode::Local => {
                    self.entra_authenticator_authority.is_none()
                }
            }
    }

    pub(crate) fn retains_entra_bearer_validator(
        &self,
        validator: &Option<Arc<EntraTokenValidator>>,
    ) -> bool {
        match (&self.entra_bearer_validator, validator) {
            (Some(retained), Some(candidate)) => Arc::ptr_eq(retained, candidate),
            (None, None) => true,
            _ => false,
        }
    }

    pub(crate) fn retains_entra_bearer_observation(
        &self,
        observation: &Option<Arc<EntraBearerRuntimeObservation>>,
    ) -> bool {
        match (&self.entra_bearer_observation, observation) {
            (Some(retained), Some(candidate)) => Arc::ptr_eq(retained, candidate),
            (None, None) => true,
            _ => false,
        }
    }

    pub(crate) fn remeasures_entra_bearer_observation(&self) -> bool {
        match (
            self.entra_bearer_validator.as_deref(),
            self.entra_bearer_observation.as_deref(),
        ) {
            (Some(validator), Some(observation)) => *observation == validator.runtime_observation(),
            (None, None) => true,
            _ => false,
        }
    }

    pub(crate) fn retains_authenticator_bearer_limits(
        &self,
        limits: &Option<Arc<ResolvedAuthenticatorBearerLimits>>,
    ) -> bool {
        let same_owner = match (&self.authenticator_bearer_limits, limits) {
            (Some(retained), Some(candidate)) => Arc::ptr_eq(retained, candidate),
            (None, None) => true,
            _ => false,
        };
        same_owner
            && match (
                self.entra_bearer_validator.as_deref(),
                self.authenticator_bearer_limits.as_ref(),
            ) {
                (Some(validator), Some(retained)) => validator.retains_bearer_limits(retained),
                (None, None) => true,
                _ => false,
            }
    }

    pub(crate) fn retains_authenticator_browser_limits(
        &self,
        limits: &Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
    ) -> bool {
        let same_owner = match (&self.authenticator_browser_limits, limits) {
            (Some(retained), Some(candidate)) => Arc::ptr_eq(retained, candidate),
            (None, None) => true,
            _ => false,
        };
        same_owner && self.entra_sso_dependencies.retains_browser_limits(limits)
    }

    pub(crate) fn retains_derived_session_credentials(
        &self,
        runtime: &Arc<DerivedSessionCredentialRuntime>,
    ) -> bool {
        Arc::ptr_eq(&self.derived_session_credentials, runtime)
    }

    pub(crate) fn retains_derived_session_observation(
        &self,
        observation: &Arc<DerivedSessionRuntimeObservation>,
    ) -> bool {
        Arc::ptr_eq(&self.derived_session_observation, observation)
            && Arc::ptr_eq(
                self.operational_observation.derived_session_observation(),
                observation,
            )
    }

    pub(crate) fn remeasures_derived_session_observation(&self) -> bool {
        *self.derived_session_observation == self.derived_session_credentials.runtime_observation()
    }

    pub(crate) fn retains_verified_entra_runtime_binding(
        &self,
        binding: &Option<Arc<VerifiedEntraAuthenticatorRuntimeBinding>>,
    ) -> bool {
        match (&self.verified_entra_runtime_binding, binding) {
            (Some(retained), Some(candidate)) => {
                Arc::ptr_eq(retained, candidate) && retained.verify_integrity().is_ok()
            }
            (None, None) => true,
            _ => false,
        }
    }

    pub(crate) fn retains_browser_authenticator_origin(
        &self,
        origin: &Option<Arc<VerifiedBrowserAuthenticatorOrigin>>,
    ) -> bool {
        match (&self.browser_authenticator_origin, origin) {
            (Some(retained), Some(candidate)) => {
                Arc::ptr_eq(retained, candidate) && retained.verify_integrity().is_ok()
            }
            (None, None) => true,
            _ => false,
        }
    }

    pub(crate) fn retains_oidc_callback_dependencies(
        &self,
        dependencies: &Arc<OidcCallbackDeps>,
    ) -> bool {
        Arc::ptr_eq(&self.oidc_callback_dependencies, dependencies)
    }

    pub(crate) fn retains_entra_sso_dependencies(&self, dependencies: &Arc<EntraSsoDeps>) -> bool {
        Arc::ptr_eq(&self.entra_sso_dependencies, dependencies)
    }

    pub(crate) fn retains_entra_sso_handler_dependencies(
        &self,
        dependencies: &Option<Arc<VerifiedEntraSsoHandlerDeps>>,
    ) -> bool {
        match (&self.entra_sso_handler_dependencies, dependencies) {
            (Some(retained), Some(candidate)) => {
                Arc::ptr_eq(retained, candidate) && retained.verify_integrity().is_ok()
            }
            (None, None) => true,
            _ => false,
        }
    }

    pub(crate) fn retains_local_login_throttle(&self, throttle: &Arc<LocalLoginThrottle>) -> bool {
        Arc::ptr_eq(&self.local_login_throttle, throttle)
    }
}

impl fmt::Debug for ApiAuthenticatorRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiAuthenticatorRuntime")
            .field("auth_mode", &self.auth_mode.as_str())
            .field("generic_oidc_enabled", &self.generic_oidc_enabled)
            .field("operational_observation", &"[RETAINED]")
            .field("api_cookie_runtime", &"[RETAINED]")
            .field("entra_authenticator_authority", &"[RETAINED]")
            .field("authenticator_bearer_limits", &"[RETAINED]")
            .field("authenticator_browser_limits", &"[RETAINED]")
            .field("entra_bearer_validator", &"[RETAINED]")
            .field("entra_bearer_observation", &"[RETAINED]")
            .field("derived_session_credentials", &"[RETAINED]")
            .field("derived_session_observation", &"[RETAINED]")
            .field("verified_entra_runtime_binding", &"[RETAINED]")
            .field("browser_authenticator_origin", &"[REDACTED]")
            .field("oidc_callback_dependencies", &"[RETAINED]")
            .field("entra_sso_dependencies", &"[RETAINED]")
            .field("entra_sso_handler_dependencies", &"[RETAINED]")
            .field("local_login_throttle", &"[RETAINED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_runtime(
        config: &RyukiConfig,
    ) -> (Arc<ApiCookieRuntime>, Arc<ApiAuthenticatorRuntime>) {
        build_runtime_with_profile(config, 60, 3_600, false)
    }

    fn build_runtime_with_limits(
        config: &RyukiConfig,
        clock_skew_seconds: u64,
        maximum_lifetime_seconds: u64,
    ) -> (Arc<ApiCookieRuntime>, Arc<ApiAuthenticatorRuntime>) {
        build_runtime_with_profile(config, clock_skew_seconds, maximum_lifetime_seconds, false)
    }

    fn build_production_runtime(
        config: &RyukiConfig,
    ) -> (Arc<ApiCookieRuntime>, Arc<ApiAuthenticatorRuntime>) {
        build_runtime_with_profile(config, 60, 3_600, true)
    }

    fn build_runtime_with_profile(
        config: &RyukiConfig,
        clock_skew_seconds: u64,
        maximum_lifetime_seconds: u64,
        production_profile: bool,
    ) -> (Arc<ApiCookieRuntime>, Arc<ApiAuthenticatorRuntime>) {
        let cookie_runtime = ApiCookieRuntime::from_admitted_config(config, production_profile)
            .expect("test config must construct cookie runtime");
        let entra_authenticator_authority = (config.auth_mode == AuthMode::EntraId).then(|| {
            ResolvedEntraAuthenticatorAuthority::fixture(
                config,
                clock_skew_seconds,
                maximum_lifetime_seconds,
                !config.entra_redirect_uri.is_empty(),
            )
        });
        let authenticator_runtime = ApiAuthenticatorRuntime::from_admitted_config(
            config,
            Arc::clone(&cookie_runtime),
            entra_authenticator_authority,
            production_profile,
        )
        .expect("test config must construct authenticator runtime");
        (cookie_runtime, authenticator_runtime)
    }

    #[test]
    fn retains_exact_cookie_and_authenticator_allocations() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        config.entra_tenant_id = "tenant-retention-fixture".into();
        config.entra_client_id = "client-retention-fixture".into();
        config.entra_redirect_uri = "https://portal.example.test/entra/callback".into();
        config.session.credential_hmac_key = "k".repeat(32);
        let (cookie_runtime, runtime) = build_production_runtime(&config);
        let observation = Arc::clone(runtime.operational_observation());
        let entra_authenticator_authority = runtime.entra_authenticator_authority();
        let bearer_limits = runtime.authenticator_bearer_limits();
        let browser_limits = runtime.authenticator_browser_limits();
        let entra_bearer_validator = runtime.entra_bearer_validator();
        let entra_bearer_observation = runtime.entra_bearer_observation();
        let derived_session_credentials = runtime.derived_session_credentials();
        let derived_session_observation = runtime.derived_session_observation();
        let verified_entra_runtime_binding = runtime.verified_entra_runtime_binding();
        let browser_authenticator_origin = runtime.browser_authenticator_origin();
        let oidc_callback_dependencies = runtime.oidc_callback_dependencies();
        let entra_sso_dependencies = runtime.entra_sso_dependencies();
        let entra_sso_handler_dependencies = runtime.entra_sso_handler_dependencies();
        let local_login_throttle = runtime.local_login_throttle();

        assert!(runtime.retains_cookie_runtime(&cookie_runtime));
        assert!(runtime.retains_operational_observation(&observation));
        assert!(runtime.retains_entra_authenticator_authority(&entra_authenticator_authority));
        assert!(entra_authenticator_authority
            .as_ref()
            .is_some_and(|authority| authority.verify_integrity().is_ok()));
        assert!(runtime.retains_authenticator_bearer_limits(&bearer_limits));
        assert!(runtime.retains_authenticator_browser_limits(&browser_limits));
        assert!(runtime.retains_entra_bearer_validator(&entra_bearer_validator));
        assert!(runtime.retains_entra_bearer_observation(&entra_bearer_observation));
        assert!(runtime.remeasures_entra_bearer_observation());
        assert!(runtime.retains_derived_session_credentials(&derived_session_credentials));
        assert!(runtime.retains_derived_session_observation(&derived_session_observation));
        assert!(runtime.remeasures_derived_session_observation());
        assert!(runtime.retains_verified_entra_runtime_binding(&verified_entra_runtime_binding));
        assert!(runtime.retains_browser_authenticator_origin(&browser_authenticator_origin));
        assert!(runtime.retains_oidc_callback_dependencies(&oidc_callback_dependencies));
        assert!(runtime.retains_entra_sso_dependencies(&entra_sso_dependencies));
        assert!(runtime.retains_entra_sso_handler_dependencies(&entra_sso_handler_dependencies));
        assert!(runtime.retains_local_login_throttle(&local_login_throttle));
        assert!(
            oidc_callback_dependencies.retains_session_credentials(&derived_session_credentials)
        );
        assert!(oidc_callback_dependencies.retains_cookie_runtime(&cookie_runtime));
        assert!(entra_sso_dependencies.retains_session_credentials(&derived_session_credentials));
        assert!(entra_sso_dependencies.retains_cookie_runtime(&cookie_runtime));
        assert!(entra_sso_dependencies.retains_browser_limits(&browser_limits));
        assert!(oidc_callback_dependencies.retains_browser_authenticator_origin(&None));
        let verified_binding = verified_entra_runtime_binding
            .as_ref()
            .expect("production Entra runtime binding");
        assert!(verified_binding.verify_integrity().is_ok());
        assert!(verified_binding.retains_authority(
            entra_authenticator_authority
                .as_ref()
                .expect("Entra authority")
        ));
        assert!(verified_binding.retains_bearer_observation(
            entra_bearer_observation
                .as_ref()
                .expect("Entra bearer observation")
        ));
        assert!(verified_binding.retains_derived_session_credentials(&derived_session_credentials));
        assert!(verified_binding.retains_cookie_runtime(&cookie_runtime));
        assert!(verified_binding
            .expected_authenticator_inventory_digest()
            .starts_with("sha256:"));
        assert!(matches!(
            verified_binding.expected_authenticator_inventory_value(),
            RuntimeGuardExpectedValue::NonDevelopmentAuthenticator { authenticators, .. }
                if authenticators.len() == 1
        ));
        let origin = browser_authenticator_origin
            .as_ref()
            .expect("production browser origin");
        assert!(origin.verify_integrity().is_ok());
        assert!(origin.retains_entra_runtime_binding(verified_binding));
        assert_eq!(origin.provider_id(), "provider:fixture-entra");
        assert_eq!(origin.path_id(), ENTRA_BROWSER_PATH_ID);
        assert_eq!(origin.path_version(), ENTRA_BROWSER_PATH_VERSION);
        assert_eq!(origin.path_kind(), BROWSER_DERIVED_SESSION_PATH_KIND);
        assert_eq!(origin.origin_binding_digest_bytes().len(), 32);
        let derived_browser_origin = verified_binding
            .browser_origin()
            .expect("sealed R must derive its browser-origin inventory")
            .expect("configured browser path must have an origin");
        assert!(derived_browser_origin.retains_entra_runtime_binding(verified_binding));
        assert_eq!(
            derived_browser_origin.origin_projection(),
            origin.origin_projection()
        );
        assert_eq!(
            derived_browser_origin.origin_binding_digest(),
            origin.origin_binding_digest()
        );
        let handler_dependencies = entra_sso_handler_dependencies
            .as_ref()
            .expect("sealed Entra handler dependencies");
        assert!(handler_dependencies.verify_integrity().is_ok());
        assert!(Arc::ptr_eq(
            handler_dependencies.base(),
            &entra_sso_dependencies
        ));
        assert!(Arc::ptr_eq(handler_dependencies.origin(), origin));
        assert!(Arc::ptr_eq(
            &runtime.api_cookie_runtime(),
            &runtime.api_cookie_runtime()
        ));
        assert!(Arc::ptr_eq(
            entra_authenticator_authority
                .as_ref()
                .expect("Entra authenticator authority"),
            runtime
                .entra_authenticator_authority()
                .as_ref()
                .expect("same Entra authenticator authority")
        ));
        assert!(Arc::ptr_eq(
            bearer_limits.as_ref().expect("Entra bearer limits"),
            entra_authenticator_authority
                .as_ref()
                .expect("Entra authenticator authority")
                .bearer_limits()
        ));
        assert!(Arc::ptr_eq(
            bearer_limits.as_ref().expect("Entra bearer limits"),
            runtime
                .authenticator_bearer_limits()
                .as_ref()
                .expect("same Entra bearer limits")
        ));
        assert!(Arc::ptr_eq(
            browser_limits.as_ref().expect("Entra browser limits"),
            entra_authenticator_authority
                .as_ref()
                .expect("Entra authenticator authority")
                .browser_limits()
                .expect("authority browser limits")
        ));
        assert!(Arc::ptr_eq(
            browser_limits.as_ref().expect("Entra browser limits"),
            runtime
                .authenticator_browser_limits()
                .as_ref()
                .expect("same Entra browser limits")
        ));
        assert!(Arc::ptr_eq(
            entra_bearer_validator.as_ref().expect("Entra validator"),
            runtime
                .entra_bearer_validator()
                .as_ref()
                .expect("same Entra validator")
        ));
        assert!(Arc::ptr_eq(
            entra_bearer_observation
                .as_ref()
                .expect("Entra observation"),
            runtime
                .entra_bearer_observation()
                .as_ref()
                .expect("same Entra observation")
        ));
        assert!(Arc::ptr_eq(
            &runtime.derived_session_credentials(),
            &runtime.derived_session_credentials()
        ));
        assert!(Arc::ptr_eq(
            &runtime.derived_session_observation(),
            &runtime.derived_session_observation()
        ));
        assert!(Arc::ptr_eq(
            &runtime.oidc_callback_dependencies(),
            &runtime.oidc_callback_dependencies()
        ));
        assert!(Arc::ptr_eq(
            &runtime.entra_sso_dependencies(),
            &runtime.entra_sso_dependencies()
        ));
        assert!(Arc::ptr_eq(
            &runtime.local_login_throttle(),
            &runtime.local_login_throttle()
        ));

        let (other_cookie_runtime, other_runtime) = build_production_runtime(&config);
        assert!(!derived_browser_origin.retains_entra_runtime_binding(
            &other_runtime
                .verified_entra_runtime_binding()
                .expect("equal-looking production Entra runtime binding")
        ));
        assert!(!runtime.retains_cookie_runtime(&other_cookie_runtime));
        assert!(!runtime.retains_operational_observation(other_runtime.operational_observation()));
        assert!(!runtime
            .retains_entra_authenticator_authority(&other_runtime.entra_authenticator_authority()));
        assert!(!runtime
            .retains_authenticator_bearer_limits(&other_runtime.authenticator_bearer_limits()));
        assert!(!runtime
            .retains_authenticator_browser_limits(&other_runtime.authenticator_browser_limits()));
        assert!(!runtime.retains_entra_bearer_validator(&other_runtime.entra_bearer_validator()));
        assert!(
            !runtime.retains_entra_bearer_observation(&other_runtime.entra_bearer_observation())
        );
        assert!(!runtime
            .retains_derived_session_credentials(&other_runtime.derived_session_credentials()));
        assert!(!runtime
            .retains_derived_session_observation(&other_runtime.derived_session_observation()));
        assert!(!runtime.retains_verified_entra_runtime_binding(
            &other_runtime.verified_entra_runtime_binding()
        ));
        assert!(!runtime
            .retains_browser_authenticator_origin(&other_runtime.browser_authenticator_origin()));
        assert!(!runtime
            .retains_oidc_callback_dependencies(&other_runtime.oidc_callback_dependencies()));
        assert!(!runtime.retains_entra_sso_dependencies(&other_runtime.entra_sso_dependencies()));
        assert!(!runtime.retains_entra_sso_handler_dependencies(
            &other_runtime.entra_sso_handler_dependencies()
        ));
        assert!(!runtime.retains_local_login_throttle(&other_runtime.local_login_throttle()));

        let equal_but_distinct_authority = Some(ResolvedEntraAuthenticatorAuthority::fixture(
            &config, 60, 3_600, true,
        ));
        let equal_but_distinct_limits = equal_but_distinct_authority
            .as_ref()
            .map(|authority| Arc::clone(authority.bearer_limits()));
        let equal_but_distinct_browser = equal_but_distinct_authority
            .as_ref()
            .and_then(|authority| authority.browser_limits().map(Arc::clone));
        assert!(!runtime.retains_entra_authenticator_authority(&equal_but_distinct_authority));
        assert!(!runtime.retains_authenticator_bearer_limits(&equal_but_distinct_limits));
        assert!(!runtime.retains_authenticator_browser_limits(&equal_but_distinct_browser));
    }

    #[test]
    fn direct_bearer_origin_retains_canonical_runtime_and_rejects_substitution() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        config.entra_tenant_id = "tenant-direct-origin-fixture".into();
        config.entra_client_id = "client-direct-origin-fixture".into();
        config.session.credential_hmac_key = "k".repeat(32);
        let (_, runtime) = build_production_runtime(&config);
        let runtime_binding = runtime
            .verified_entra_runtime_binding()
            .expect("production Entra runtime binding");
        let validator = runtime
            .entra_bearer_validator()
            .expect("production Entra validator");
        let identity = crate::entra_auth::VerifiedEntraBearerIdentity::fixture(
            Arc::clone(&validator),
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "Direct Origin Fixture",
            &[],
            ryuki_engine::auth::ActorClass::VerifiedHuman,
        );
        let origin = runtime_binding
            .verify_direct_bearer_identity(&identity)
            .expect("identity from the retained validator must seal a direct origin");

        assert!(origin.verify_integrity().is_ok());
        assert!(origin.retains_entra_runtime_binding(&runtime_binding));
        assert_eq!(origin.provider_id(), "provider:fixture-entra");
        assert_eq!(
            origin.provider_binding().provider_id.as_str(),
            origin.provider_id()
        );
        assert_eq!(origin.path_id(), ENTRA_BEARER_PATH_ID);
        assert_eq!(origin.path_version(), ENTRA_BEARER_PATH_VERSION);
        assert_eq!(origin.path_kind(), DIRECT_BEARER_PATH_KIND);
        assert!(origin.matches_validated_issuer(identity.issuer()));
        assert_eq!(origin.origin_projection().provider_id, origin.provider_id());
        assert!(origin.origin_binding_digest().starts_with("sha256:"));
        assert_eq!(origin.origin_binding_digest_bytes().len(), 32);
        assert_eq!(
            origin
                .federated_authority_max_staleness_seconds()
                .expect("sealed session authority must expose exact staleness"),
            config.session.federated_authority_max_staleness_secs
        );
        assert!(Arc::ptr_eq(
            &runtime_binding
                .derived_session_credentials()
                .expect("sealed runtime must expose its retained session authority"),
            &runtime.derived_session_credentials()
        ));

        let (_, other_runtime) = build_production_runtime(&config);
        let other_runtime_binding = other_runtime
            .verified_entra_runtime_binding()
            .expect("equal-looking production Entra runtime binding");
        let other_validator = other_runtime
            .entra_bearer_validator()
            .expect("equal-looking production Entra validator");
        let substituted_identity = crate::entra_auth::VerifiedEntraBearerIdentity::fixture(
            other_validator,
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "Direct Origin Fixture",
            &[],
            ryuki_engine::auth::ActorClass::VerifiedHuman,
        );
        assert!(runtime_binding
            .verify_direct_bearer_identity(&substituted_identity)
            .is_err());
        assert!(!origin.retains_entra_runtime_binding(&other_runtime_binding));
    }

    #[test]
    fn production_bearer_only_runtime_seals_r_without_browser_origin() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        config.entra_tenant_id = "tenant-bearer-only-fixture".into();
        config.entra_client_id = "client-bearer-only-fixture".into();
        config.session.credential_hmac_key = "b".repeat(32);

        let (_, runtime) = build_production_runtime(&config);
        let binding = runtime
            .verified_entra_runtime_binding()
            .expect("production bearer-only R");

        assert!(binding.verify_integrity().is_ok());
        assert_eq!(
            binding.measured_projection().capability_ids,
            vec!["token-validation".to_string()]
        );
        assert_eq!(binding.measured_projection().credential_paths.len(), 1);
        assert_eq!(
            binding.measured_projection().credential_paths[0].path_id,
            ENTRA_BEARER_PATH_ID
        );
        assert!(runtime.browser_authenticator_origin().is_none());
        assert!(binding
            .browser_origin()
            .expect("bearer-only R must have a consistent browser inventory")
            .is_none());
        assert!(runtime.entra_sso_handler_dependencies().is_none());
        assert!(runtime.validate_production_posture().is_ok());
    }

    #[test]
    fn browser_origin_fixture_uses_canonical_distinct_digest_preimages() {
        let first = VerifiedBrowserAuthenticatorOrigin::fixture("oidc-origin-a");
        let same = VerifiedBrowserAuthenticatorOrigin::fixture("oidc-origin-a");
        let other = VerifiedBrowserAuthenticatorOrigin::fixture("oidc-origin-b");

        assert!(first.verify_integrity().is_ok());
        assert_eq!(first.origin_projection(), same.origin_projection());
        assert_eq!(first.origin_binding_digest(), same.origin_binding_digest());
        assert_ne!(first.origin_binding_digest(), other.origin_binding_digest());
        assert_eq!(
            digest_bytes(first.origin_binding_digest(), "fixture origin").unwrap(),
            *first.origin_binding_digest_bytes()
        );
        let projection = first.origin_projection();
        let distinct = [
            first.origin_binding_digest(),
            projection
                .binding_document_reference
                .content_digest
                .as_str(),
            projection.provider_configuration_payload_digest.as_str(),
            projection.provider_policy_binding_digest.as_str(),
            projection.runtime_binding_digest.as_str(),
        ]
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
        assert_eq!(distinct.len(), 5);
        assert_eq!(first.path_kind(), BROWSER_DERIVED_SESSION_PATH_KIND);

        let rendered = format!("{first:?}");
        assert!(!rendered.contains(first.provider_id()));
        assert!(!rendered.contains(first.origin_binding_digest()));
    }

    #[test]
    fn digest_byte_decoder_rejects_noncanonical_and_zero_values() {
        assert!(digest_bytes(&format!("sha256:{}", "0".repeat(64)), "zero fixture").is_err());
        assert!(digest_bytes(&format!("sha256:{}", "A".repeat(64)), "uppercase fixture").is_err());
        assert!(digest_bytes("sha256:abcd", "short fixture").is_err());
        assert!(digest_bytes(&format!("sha512:{}", "a".repeat(64)), "prefix fixture").is_err());
    }

    #[test]
    fn disabled_oidc_records_explicit_disabled_runtime_state() {
        let config = RyukiConfig::default();
        assert!(!config.oidc.enabled);

        let (_, runtime) = build_runtime(&config);

        assert!(!runtime.generic_oidc_enabled);
        assert_eq!(runtime.auth_mode(), &config.auth_mode);
        let observation = runtime.operational_observation();
        assert_eq!(
            observation.posture(),
            ProductionAuthenticatorPosture::CredentialFreeMockDryRun
        );
        assert_eq!(
            observation.consumers(),
            &[AuthenticatorRuntimeConsumer::CredentialFreeRequestAdmission]
        );
        assert_eq!(
            observation.generic_oidc_client_authentication(),
            GenericOidcClientAuthentication::Disabled
        );
        assert!(!observation.generic_oidc_enabled());
        assert!(observation
            .generic_oidc_issuer_authority_binding_digest()
            .is_none());
        assert!(observation
            .generic_oidc_audience_client_binding_digest()
            .is_none());
        assert_eq!(observation.generic_oidc_validation_leeway_seconds(), None);
        assert_eq!(observation.generic_oidc_signature_algorithm(), None);
        assert_eq!(observation.entra_browser_clock_skew_limit_id(), None);
        assert_eq!(observation.entra_browser_maximum_clock_skew_seconds(), None);
        assert!(runtime.entra_authenticator_authority().is_none());
        assert!(runtime.retains_entra_authenticator_authority(&None));
        assert!(runtime.authenticator_bearer_limits().is_none());
        assert!(runtime.authenticator_browser_limits().is_none());
        assert!(runtime.entra_bearer_validator().is_none());
        assert!(runtime.entra_bearer_observation().is_none());
    }

    #[test]
    fn constructor_rejects_missing_dormant_and_path_mismatched_entra_authority() {
        let mut entra = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        entra.entra_tenant_id = "tenant-limit-construction-fixture".into();
        entra.entra_client_id = "client-limit-construction-fixture".into();
        let cookie_runtime = ApiCookieRuntime::from_admitted_config(&entra, false)
            .expect("test config must construct cookie runtime");

        let missing_authority = ApiAuthenticatorRuntime::from_admitted_config(
            &entra,
            Arc::clone(&cookie_runtime),
            None,
            false,
        )
        .expect_err("Entra must not construct without its retained declaration authority");
        assert!(missing_authority.contains("requires one exact authenticator authority"));

        let exact_bearer_only_authority =
            ResolvedEntraAuthenticatorAuthority::fixture(&entra, 60, 3_600, false);
        let exact_bearer_only_runtime = ApiAuthenticatorRuntime::from_admitted_config(
            &entra,
            Arc::clone(&cookie_runtime),
            Some(Arc::clone(&exact_bearer_only_authority)),
            false,
        )
        .expect("bearer-only Entra may retain a D that declares no browser path");
        assert!(exact_bearer_only_runtime
            .retains_entra_authenticator_authority(&Some(exact_bearer_only_authority,)));
        assert!(exact_bearer_only_runtime
            .authenticator_browser_limits()
            .is_none());

        let browser_authority_without_redirect =
            ResolvedEntraAuthenticatorAuthority::fixture(&entra, 60, 3_600, true);
        let dormant_browser = ApiAuthenticatorRuntime::from_admitted_config(
            &entra,
            Arc::clone(&cookie_runtime),
            Some(browser_authority_without_redirect),
            false,
        )
        .expect_err("bearer-only Entra must reject a dormant browser path in D");
        assert!(dormant_browser.contains("declares a dormant Entra browser path"));

        entra.entra_redirect_uri = "https://portal.example.test/entra/callback".into();
        let browser_cookie_runtime = ApiCookieRuntime::from_admitted_config(&entra, false)
            .expect("browser test config must construct cookie runtime");
        let bearer_only_authority =
            ResolvedEntraAuthenticatorAuthority::fixture(&entra, 60, 3_600, false);
        let missing_browser = ApiAuthenticatorRuntime::from_admitted_config(
            &entra,
            Arc::clone(&browser_cookie_runtime),
            Some(bearer_only_authority),
            false,
        )
        .expect_err("configured Entra browser SSO must have an exact browser path in D");
        assert!(missing_browser.contains("has no exact browser path"));

        let non_entra = RyukiConfig::default();
        let non_entra_cookie_runtime = ApiCookieRuntime::from_admitted_config(&non_entra, false)
            .expect("non-Entra test config must construct cookie runtime");
        let dormant_authority =
            ResolvedEntraAuthenticatorAuthority::fixture(&entra, 60, 3_600, true);
        let dormant_direct_authority = ApiAuthenticatorRuntime::from_admitted_config(
            &non_entra,
            non_entra_cookie_runtime,
            Some(dormant_authority),
            false,
        )
        .expect_err("non-Entra modes must reject dormant Entra declaration authority");
        assert!(dormant_direct_authority.contains("non-Entra runtime cannot retain dormant"));
    }

    #[test]
    fn enabled_generic_oidc_is_rejected_before_runtime_construction() {
        let cookie_config = RyukiConfig::default();
        let cookie_runtime = ApiCookieRuntime::from_admitted_config(&cookie_config, false)
            .expect("disabled generic OIDC must construct the development cookie runtime");

        for auth_mode in [
            AuthMode::MockDryRun,
            AuthMode::StaticDryRun,
            AuthMode::Local,
            AuthMode::EntraId,
        ] {
            let mut config = RyukiConfig {
                auth_mode,
                ..RyukiConfig::default()
            };
            config.oidc.enabled = true;
            let error = ApiAuthenticatorRuntime::from_admitted_config(
                &config,
                Arc::clone(&cookie_runtime),
                None,
                false,
            )
            .expect_err("unbound generic OIDC must fail startup in every base mode");
            assert_eq!(error, GENERIC_OIDC_NOT_ADMITTED);
        }
    }

    #[test]
    fn production_posture_rejects_credential_free_and_password_local_modes() {
        for mode in [AuthMode::MockDryRun, AuthMode::StaticDryRun] {
            let config = RyukiConfig {
                auth_mode: mode,
                ..RyukiConfig::default()
            };
            let (_, runtime) = build_runtime(&config);
            assert_eq!(
                runtime.validate_production_posture(),
                Err(AuthenticatorRuntimePostureError::CredentialFree)
            );
        }

        let config = RyukiConfig {
            auth_mode: AuthMode::Local,
            ..RyukiConfig::default()
        };
        let (_, runtime) = build_runtime(&config);
        assert_eq!(
            runtime.validate_production_posture(),
            Err(AuthenticatorRuntimePostureError::PasswordLocal)
        );
        assert_eq!(
            runtime.operational_observation().consumers(),
            &[AuthenticatorRuntimeConsumer::LocalPasswordLogin]
        );
    }

    #[test]
    fn entra_oidc_is_the_only_current_production_posture() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        config.entra_tenant_id = "tenant-posture-fixture".to_string();
        config.entra_client_id = "client-posture-fixture".to_string();
        config.entra_redirect_uri = "https://portal.example.test/entra/callback".to_string();
        config.session.credential_hmac_key = "k".repeat(32);

        let (_, runtime) = build_production_runtime(&config);
        let observation = runtime
            .validate_production_posture()
            .expect("Entra OIDC must be the current production posture");

        assert_eq!(
            observation.posture(),
            ProductionAuthenticatorPosture::EntraOidc
        );
        assert_eq!(
            observation.consumers(),
            &[
                AuthenticatorRuntimeConsumer::EntraBearerRequestAdmission,
                AuthenticatorRuntimeConsumer::EntraBrowserSso,
            ]
        );
        assert!(observation
            .entra_issuer_authority_binding_digest()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert!(observation
            .entra_audience_client_binding_digest()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert_eq!(
            observation.entra_signature_algorithm(),
            Some(AuthenticatorSignatureAlgorithm::Rs256)
        );
        assert_eq!(
            observation.entra_key_source_kind(),
            Some(EntraBearerKeySourceKind::NetworkJwks)
        );
        assert!(observation
            .entra_key_source_binding_digest()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert_eq!(
            observation.entra_jwks_ttl_seconds(),
            config.entra_jwks_ttl_secs
        );
        assert_eq!(observation.entra_validation_leeway_seconds(), 60);
        assert_eq!(
            observation.entra_clock_skew_limit_id(),
            Some("limit:authenticator.clock-skew")
        );
        assert_eq!(
            observation.entra_credential_lifetime_limit_id(),
            Some("limit:authenticator.oidc-access-token-lifetime")
        );
        assert_eq!(
            observation.entra_maximum_credential_lifetime_seconds(),
            Some(3_600)
        );
        assert_eq!(
            observation.entra_browser_clock_skew_limit_id(),
            Some("limit:authenticator.clock-skew")
        );
        assert_eq!(
            observation.entra_browser_maximum_clock_skew_seconds(),
            Some(60)
        );
        assert!(
            runtime.retains_authenticator_browser_limits(&runtime.authenticator_browser_limits())
        );
        assert!(observation.derived_session_observation().enabled());
    }

    #[test]
    fn entra_production_posture_rejects_a_disabled_session_authority() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        config.entra_tenant_id = "tenant-posture-fixture".to_string();
        config.entra_client_id = "client-posture-fixture".to_string();
        config.entra_redirect_uri = "https://portal.example.test/entra/callback".to_string();

        let (_, runtime) = build_runtime(&config);
        assert_eq!(
            runtime.validate_production_posture(),
            Err(AuthenticatorRuntimePostureError::DerivedSessionCredentialUnavailable)
        );
    }

    #[test]
    fn observation_digests_identity_leaves_and_never_retains_raw_values() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        config.entra_authority = "https://entra-authority.example.test".to_string();
        config.entra_tenant_id = "tenant-observation-fixture".to_string();
        config.entra_client_id = "entra-client-observation-fixture".to_string();
        config.entra_redirect_uri = "https://portal.example.test/entra/callback".to_string();

        let (_, runtime) = build_runtime(&config);
        let rendered = format!("{:?}", runtime.operational_observation());

        for raw in [
            config.entra_authority.as_str(),
            config.entra_tenant_id.as_str(),
            config.entra_client_id.as_str(),
        ] {
            assert!(
                !rendered.contains(raw),
                "observation leaked raw identity material"
            );
        }
        let mut changed_client = config.clone();
        changed_client.entra_client_id = "different-entra-client-fixture".to_string();
        changed_client.entra_jwks_ttl_secs += 1;
        let (_, changed_runtime) = build_runtime_with_limits(&changed_client, 61, 3_599);
        assert_eq!(
            runtime
                .operational_observation()
                .entra_issuer_authority_binding_digest(),
            changed_runtime
                .operational_observation()
                .entra_issuer_authority_binding_digest()
        );
        assert_ne!(
            runtime
                .operational_observation()
                .entra_audience_client_binding_digest(),
            changed_runtime
                .operational_observation()
                .entra_audience_client_binding_digest()
        );
        assert_ne!(
            runtime.operational_observation().entra_jwks_ttl_seconds(),
            changed_runtime
                .operational_observation()
                .entra_jwks_ttl_seconds()
        );
        assert_ne!(
            runtime
                .operational_observation()
                .entra_key_source_binding_digest(),
            changed_runtime
                .operational_observation()
                .entra_key_source_binding_digest(),
            "the exact retained JWKS TTL is part of the key-source binding"
        );
        assert_ne!(
            runtime
                .operational_observation()
                .entra_validation_leeway_seconds(),
            changed_runtime
                .operational_observation()
                .entra_validation_leeway_seconds()
        );
        assert_ne!(
            runtime
                .operational_observation()
                .entra_browser_maximum_clock_skew_seconds(),
            changed_runtime
                .operational_observation()
                .entra_browser_maximum_clock_skew_seconds()
        );
        assert_ne!(
            runtime
                .operational_observation()
                .entra_maximum_credential_lifetime_seconds(),
            changed_runtime
                .operational_observation()
                .entra_maximum_credential_lifetime_seconds()
        );
        assert_eq!(
            changed_runtime
                .operational_observation()
                .entra_signature_algorithm(),
            Some(AuthenticatorSignatureAlgorithm::Rs256)
        );
    }

    #[test]
    fn debug_output_redacts_every_retained_handle() {
        let config = RyukiConfig::default();
        let (_, runtime) = build_runtime(&config);

        let rendered = format!("{runtime:?}");

        assert!(rendered.contains("ApiAuthenticatorRuntime"));
        assert!(rendered.contains("[RETAINED]"));
        assert!(!rendered.contains(&config.entra_authority));
        assert!(!rendered.contains(DISABLED_OIDC_TOKEN_ENDPOINT));
        assert!(!rendered.contains(DISABLED_OIDC_JWKS_ENDPOINT));
    }
}
