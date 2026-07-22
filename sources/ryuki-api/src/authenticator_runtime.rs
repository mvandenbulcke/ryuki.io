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
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::contracts::LocalLoginThrottle;
use crate::cookie_runtime::ApiCookieRuntime;
use crate::entra_auth::{
    EntraBearerKeySourceKind, EntraBearerRuntimeObservation, EntraTokenValidator,
};
use crate::entra_sso::EntraSsoDeps;
use crate::oidc_callback::{
    OidcCallbackDeps, OidcIdTokenValidator, ReqwestTokenExchanger, TokenExchanger,
};
use crate::session_credentials::{
    DerivedSessionCredentialRuntime, DerivedSessionRuntimeObservation,
};

const DISABLED_OIDC_TOKEN_ENDPOINT: &str = "https://disabled.invalid/token";
const DISABLED_OIDC_JWKS_ENDPOINT: &str = "https://disabled.invalid/jwks";
const DISABLED_OIDC_ISSUER: &str = "https://disabled.invalid/issuer";
const DISABLED_OIDC_AUDIENCE: &str = "disabled";
const OIDC_CLOCK_SKEW_SECONDS: u64 = 60;
const AUTHENTICATOR_LEAF_DIGEST_CONTRACT: &[u8] = b"ryuki-authenticator-runtime-leaf-binding-v1";

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
            .finish()
    }
}

impl AuthenticatorRuntimeObservation {
    fn measure(
        config: &RyukiConfig,
        entra_validator_observation: Arc<EntraBearerRuntimeObservation>,
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
            let exact_policy = entra_validator_observation.as_ref();
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
                || u32::try_from(exact_policy.validation_leeway_seconds()).is_err()
                || exact_policy.accepted_algorithm_ids() != ["rs256"]
                || exact_policy.required_claim_ids() != ["aud", "exp", "iat", "iss", "nbf", "sub"]
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
        }

        let mut consumers = match posture {
            ProductionAuthenticatorPosture::EntraOidc => {
                let mut consumers = vec![AuthenticatorRuntimeConsumer::EntraBearerRequestAdmission];
                if !config.entra_tenant_id.is_empty()
                    && !config.entra_client_id.is_empty()
                    && !config.entra_redirect_uri.is_empty()
                {
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
            entra_validator_observation: (posture == ProductionAuthenticatorPosture::EntraOidc)
                .then_some(entra_validator_observation),
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
    entra_bearer_validator: Arc<EntraTokenValidator>,
    entra_bearer_observation: Arc<EntraBearerRuntimeObservation>,
    derived_session_credentials: Arc<DerivedSessionCredentialRuntime>,
    derived_session_observation: Arc<DerivedSessionRuntimeObservation>,
    oidc_callback_dependencies: Arc<OidcCallbackDeps>,
    entra_sso_dependencies: Arc<EntraSsoDeps>,
    local_login_throttle: Arc<LocalLoginThrottle>,
}

impl ApiAuthenticatorRuntime {
    /// Construct every process-local authenticator exactly once from already
    /// admitted startup configuration.
    pub(crate) fn from_admitted_config(
        config: &RyukiConfig,
        api_cookie_runtime: Arc<ApiCookieRuntime>,
        production_profile: bool,
    ) -> Result<Arc<Self>, String> {
        api_cookie_runtime
            .validate_config_binding(config, production_profile)
            .map_err(|error| error.to_string())?;
        let entra_bearer_validator = Arc::new(EntraTokenValidator::from_app_config(
            &config.entra_tenant_id,
            &config.entra_client_id,
            &config.entra_authority,
            config.entra_jwks_ttl_secs,
            config.entra_leeway_secs,
        ));
        let entra_bearer_observation = Arc::new(entra_bearer_validator.runtime_observation());
        let derived_session_credentials =
            DerivedSessionCredentialRuntime::from_admitted_config(&config.session)
                .map_err(|error| error.to_string())?;
        let derived_session_observation =
            Arc::new(derived_session_credentials.runtime_observation());
        let operational_observation = Arc::new(AuthenticatorRuntimeObservation::measure(
            config,
            Arc::clone(&entra_bearer_observation),
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
        let oidc_callback_dependencies = Arc::new(OidcCallbackDeps {
            exchanger,
            validator,
            session_credentials: Arc::clone(&derived_session_credentials),
            cookie_runtime: Arc::clone(&api_cookie_runtime),
        });
        let entra_sso_dependencies = EntraSsoDeps::from_app_config(
            config,
            Arc::clone(&derived_session_credentials),
            Arc::clone(&api_cookie_runtime),
        );

        Ok(Arc::new(Self {
            auth_mode: config.auth_mode.clone(),
            generic_oidc_enabled: config.oidc.enabled,
            operational_observation,
            api_cookie_runtime,
            entra_bearer_validator,
            entra_bearer_observation,
            derived_session_credentials,
            derived_session_observation,
            oidc_callback_dependencies,
            entra_sso_dependencies,
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

    pub(crate) fn api_cookie_runtime(&self) -> Arc<ApiCookieRuntime> {
        Arc::clone(&self.api_cookie_runtime)
    }

    pub(crate) fn entra_bearer_validator(&self) -> Arc<EntraTokenValidator> {
        Arc::clone(&self.entra_bearer_validator)
    }

    pub(crate) fn entra_bearer_observation(&self) -> Arc<EntraBearerRuntimeObservation> {
        Arc::clone(&self.entra_bearer_observation)
    }

    pub(crate) fn derived_session_credentials(&self) -> Arc<DerivedSessionCredentialRuntime> {
        Arc::clone(&self.derived_session_credentials)
    }

    pub(crate) fn derived_session_observation(&self) -> Arc<DerivedSessionRuntimeObservation> {
        Arc::clone(&self.derived_session_observation)
    }

    pub(crate) fn oidc_callback_dependencies(&self) -> Arc<OidcCallbackDeps> {
        Arc::clone(&self.oidc_callback_dependencies)
    }

    pub(crate) fn entra_sso_dependencies(&self) -> Arc<EntraSsoDeps> {
        Arc::clone(&self.entra_sso_dependencies)
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

    pub(crate) fn retains_entra_bearer_validator(
        &self,
        validator: &Arc<EntraTokenValidator>,
    ) -> bool {
        Arc::ptr_eq(&self.entra_bearer_validator, validator)
    }

    pub(crate) fn retains_entra_bearer_observation(
        &self,
        observation: &Arc<EntraBearerRuntimeObservation>,
    ) -> bool {
        Arc::ptr_eq(&self.entra_bearer_observation, observation)
    }

    pub(crate) fn remeasures_entra_bearer_observation(&self) -> bool {
        *self.entra_bearer_observation == self.entra_bearer_validator.runtime_observation()
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

    pub(crate) fn retains_oidc_callback_dependencies(
        &self,
        dependencies: &Arc<OidcCallbackDeps>,
    ) -> bool {
        Arc::ptr_eq(&self.oidc_callback_dependencies, dependencies)
    }

    pub(crate) fn retains_entra_sso_dependencies(&self, dependencies: &Arc<EntraSsoDeps>) -> bool {
        Arc::ptr_eq(&self.entra_sso_dependencies, dependencies)
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
            .field("entra_bearer_validator", &"[RETAINED]")
            .field("entra_bearer_observation", &"[RETAINED]")
            .field("derived_session_credentials", &"[RETAINED]")
            .field("derived_session_observation", &"[RETAINED]")
            .field("oidc_callback_dependencies", &"[RETAINED]")
            .field("entra_sso_dependencies", &"[RETAINED]")
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
        let cookie_runtime = ApiCookieRuntime::from_admitted_config(config, false)
            .expect("test config must construct cookie runtime");
        let authenticator_runtime = ApiAuthenticatorRuntime::from_admitted_config(
            config,
            Arc::clone(&cookie_runtime),
            false,
        )
        .expect("test config must construct authenticator runtime");
        (cookie_runtime, authenticator_runtime)
    }

    #[test]
    fn retains_exact_cookie_and_authenticator_allocations() {
        let config = RyukiConfig::default();
        let (cookie_runtime, runtime) = build_runtime(&config);
        let observation = Arc::clone(runtime.operational_observation());
        let entra_bearer_validator = runtime.entra_bearer_validator();
        let entra_bearer_observation = runtime.entra_bearer_observation();
        let derived_session_credentials = runtime.derived_session_credentials();
        let derived_session_observation = runtime.derived_session_observation();
        let oidc_callback_dependencies = runtime.oidc_callback_dependencies();
        let entra_sso_dependencies = runtime.entra_sso_dependencies();
        let local_login_throttle = runtime.local_login_throttle();

        assert!(runtime.retains_cookie_runtime(&cookie_runtime));
        assert!(runtime.retains_operational_observation(&observation));
        assert!(runtime.retains_entra_bearer_validator(&entra_bearer_validator));
        assert!(runtime.retains_entra_bearer_observation(&entra_bearer_observation));
        assert!(runtime.remeasures_entra_bearer_observation());
        assert!(runtime.retains_derived_session_credentials(&derived_session_credentials));
        assert!(runtime.retains_derived_session_observation(&derived_session_observation));
        assert!(runtime.remeasures_derived_session_observation());
        assert!(runtime.retains_oidc_callback_dependencies(&oidc_callback_dependencies));
        assert!(runtime.retains_entra_sso_dependencies(&entra_sso_dependencies));
        assert!(runtime.retains_local_login_throttle(&local_login_throttle));
        assert!(
            oidc_callback_dependencies.retains_session_credentials(&derived_session_credentials)
        );
        assert!(oidc_callback_dependencies.retains_cookie_runtime(&cookie_runtime));
        assert!(entra_sso_dependencies.retains_session_credentials(&derived_session_credentials));
        assert!(entra_sso_dependencies.retains_cookie_runtime(&cookie_runtime));
        assert!(Arc::ptr_eq(
            &runtime.api_cookie_runtime(),
            &runtime.api_cookie_runtime()
        ));
        assert!(Arc::ptr_eq(
            &runtime.entra_bearer_validator(),
            &runtime.entra_bearer_validator()
        ));
        assert!(Arc::ptr_eq(
            &runtime.entra_bearer_observation(),
            &runtime.entra_bearer_observation()
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

        let (other_cookie_runtime, other_runtime) = build_runtime(&config);
        assert!(!runtime.retains_cookie_runtime(&other_cookie_runtime));
        assert!(!runtime.retains_operational_observation(other_runtime.operational_observation()));
        assert!(!runtime.retains_entra_bearer_validator(&other_runtime.entra_bearer_validator()));
        assert!(
            !runtime.retains_entra_bearer_observation(&other_runtime.entra_bearer_observation())
        );
        assert!(!runtime
            .retains_derived_session_credentials(&other_runtime.derived_session_credentials()));
        assert!(!runtime
            .retains_derived_session_observation(&other_runtime.derived_session_observation()));
        assert!(!runtime
            .retains_oidc_callback_dependencies(&other_runtime.oidc_callback_dependencies()));
        assert!(!runtime.retains_entra_sso_dependencies(&other_runtime.entra_sso_dependencies()));
        assert!(!runtime.retains_local_login_throttle(&other_runtime.local_login_throttle()));
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
    }

    #[test]
    fn enabled_oidc_constructs_one_retained_dependency_set() {
        let mut config = RyukiConfig::default();
        config.oidc.enabled = true;
        config.oidc.token_endpoint = "https://identity.example.test/token".to_string();
        config.oidc.jwks_uri = "https://identity.example.test/jwks".to_string();
        config.oidc.issuer = "https://identity.example.test".to_string();
        config.oidc.client_id = "runtime-test-client".to_string();

        let (_, runtime) = build_runtime(&config);

        assert!(runtime.generic_oidc_enabled);
        assert!(Arc::ptr_eq(
            &runtime.oidc_callback_dependencies(),
            &runtime.oidc_callback_dependencies()
        ));
        let observation = runtime.operational_observation();
        assert!(observation.generic_oidc_enabled());
        assert!(observation
            .generic_oidc_issuer_authority_binding_digest()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert!(observation
            .generic_oidc_audience_client_binding_digest()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert_eq!(
            observation.generic_oidc_validation_leeway_seconds(),
            Some(OIDC_CLOCK_SKEW_SECONDS)
        );
        assert_eq!(
            observation.generic_oidc_signature_algorithm(),
            Some(AuthenticatorSignatureAlgorithm::Rs256)
        );
        assert_eq!(
            observation.generic_oidc_client_authentication(),
            GenericOidcClientAuthentication::ClientSecretPost {
                credential_present: false,
            }
        );
        assert!(observation
            .consumers()
            .contains(&AuthenticatorRuntimeConsumer::GenericOidcBrowserCallback));
        assert_eq!(
            validated_exact_identity_url("https://identity.example.test", "generic OIDC issuer")
                .unwrap(),
            "https://identity.example.test"
        );

        let mut slash_variant = config;
        slash_variant.oidc.issuer = "https://identity.example.test/".to_string();
        let (_, slash_runtime) = build_runtime(&slash_variant);
        assert_ne!(
            observation.generic_oidc_issuer_authority_binding_digest(),
            slash_runtime
                .operational_observation()
                .generic_oidc_issuer_authority_binding_digest(),
            "exact issuer spellings must remain distinct verifier bindings"
        );
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

        let (_, runtime) = build_runtime(&config);
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
        assert_eq!(
            observation.entra_validation_leeway_seconds(),
            config.entra_leeway_secs
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
    fn generic_oidc_cannot_launder_password_local_into_production() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::Local,
            ..RyukiConfig::default()
        };
        config.oidc.enabled = true;
        config.oidc.token_endpoint = "https://identity.example.test/token".to_string();
        config.oidc.jwks_uri = "https://identity.example.test/jwks".to_string();
        config.oidc.issuer = "https://identity.example.test/issuer".to_string();
        config.oidc.client_id = "local-sidecar-client".to_string();

        let (_, runtime) = build_runtime(&config);

        assert_eq!(
            runtime.validate_production_posture(),
            Err(AuthenticatorRuntimePostureError::PasswordLocal)
        );
        assert_eq!(
            runtime.operational_observation().consumers(),
            &[
                AuthenticatorRuntimeConsumer::LocalPasswordLogin,
                AuthenticatorRuntimeConsumer::GenericOidcBrowserCallback,
            ]
        );
    }

    #[test]
    fn entra_oidc_rejects_an_unbound_generic_oidc_sidecar() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            ..RyukiConfig::default()
        };
        config.entra_tenant_id = "tenant-sidecar-fixture".to_string();
        config.entra_client_id = "entra-sidecar-fixture".to_string();
        config.entra_redirect_uri = "https://portal.example.test/entra/callback".to_string();
        config.oidc.enabled = true;
        config.oidc.token_endpoint = "https://identity.example.test/token".to_string();
        config.oidc.jwks_uri = "https://identity.example.test/jwks".to_string();
        config.oidc.issuer = "https://identity.example.test/issuer".to_string();
        config.oidc.client_id = "generic-sidecar-client".to_string();
        config.session.credential_hmac_key = "k".repeat(32);

        let (_, runtime) = build_runtime(&config);

        assert_eq!(
            runtime.validate_production_posture(),
            Err(AuthenticatorRuntimePostureError::UnboundAuthenticator)
        );
        assert_eq!(
            runtime.operational_observation().consumers(),
            &[
                AuthenticatorRuntimeConsumer::EntraBearerRequestAdmission,
                AuthenticatorRuntimeConsumer::EntraBrowserSso,
                AuthenticatorRuntimeConsumer::GenericOidcBrowserCallback,
            ]
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
        config.oidc.enabled = true;
        config.oidc.issuer = "https://generic-issuer.example.test/issuer".to_string();
        config.oidc.token_endpoint = "https://generic-issuer.example.test/token".to_string();
        config.oidc.jwks_uri = "https://generic-issuer.example.test/jwks".to_string();
        config.oidc.client_id = "generic-client-observation-fixture".to_string();
        config.oidc.client_secret = "synthetic-observation-credential".to_string(); // secret-scan-allow: synthetic non-credential used only for a non-leak assertion

        let (_, runtime) = build_runtime(&config);
        let rendered = format!("{:?}", runtime.operational_observation());

        for raw in [
            config.entra_authority.as_str(),
            config.entra_tenant_id.as_str(),
            config.entra_client_id.as_str(),
            config.oidc.issuer.as_str(),
            config.oidc.client_id.as_str(),
            config.oidc.client_secret.as_str(),
        ] {
            assert!(
                !rendered.contains(raw),
                "observation leaked raw identity material"
            );
        }
        assert_eq!(
            runtime
                .operational_observation()
                .generic_oidc_client_authentication(),
            GenericOidcClientAuthentication::ClientSecretPost {
                credential_present: true,
            }
        );

        let mut changed_client = config.clone();
        changed_client.entra_client_id = "different-entra-client-fixture".to_string();
        changed_client.entra_jwks_ttl_secs += 1;
        changed_client.entra_leeway_secs += 1;
        let (_, changed_runtime) = build_runtime(&changed_client);
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
