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

use crate::contracts::LocalLoginThrottle;
use crate::cookie_runtime::ApiCookieRuntime;
use crate::entra_auth::EntraTokenValidator;
use crate::entra_sso::EntraSsoDeps;
use crate::oidc_callback::{
    OidcCallbackDeps, OidcIdTokenValidator, ReqwestTokenExchanger, TokenExchanger,
};

const DISABLED_OIDC_TOKEN_ENDPOINT: &str = "https://disabled.invalid/token";
const DISABLED_OIDC_JWKS_ENDPOINT: &str = "https://disabled.invalid/jwks";
const DISABLED_OIDC_ISSUER: &str = "https://disabled.invalid/issuer";
const DISABLED_OIDC_AUDIENCE: &str = "disabled";
const OIDC_CLOCK_SKEW_SECONDS: u64 = 60;

/// One non-cloneable owner for the exact authenticator objects used by the API.
///
/// Callers share this allocation through `Arc<ApiAuthenticatorRuntime>`.  The
/// contained objects are intentionally private, and startup composition gives
/// production consumers only Arc clones originating from this owner.
pub(crate) struct ApiAuthenticatorRuntime {
    auth_mode: AuthMode,
    generic_oidc_enabled: bool,
    api_cookie_runtime: Arc<ApiCookieRuntime>,
    entra_bearer_validator: Arc<EntraTokenValidator>,
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

        let (token_endpoint, jwks_endpoint, issuer, audience) = if config.oidc.enabled {
            (
                config.oidc.token_endpoint.as_str(),
                config.oidc.jwks_uri.as_str(),
                config.oidc.issuer.as_str(),
                config.oidc.client_id.as_str(),
            )
        } else {
            (
                DISABLED_OIDC_TOKEN_ENDPOINT,
                DISABLED_OIDC_JWKS_ENDPOINT,
                DISABLED_OIDC_ISSUER,
                DISABLED_OIDC_AUDIENCE,
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
        });

        Ok(Arc::new(Self {
            auth_mode: config.auth_mode.clone(),
            generic_oidc_enabled: config.oidc.enabled,
            api_cookie_runtime,
            entra_bearer_validator,
            oidc_callback_dependencies,
            entra_sso_dependencies: EntraSsoDeps::from_app_config(config),
            local_login_throttle: Arc::new(LocalLoginThrottle::default()),
        }))
    }

    pub(crate) fn auth_mode(&self) -> &AuthMode {
        &self.auth_mode
    }

    #[cfg(test)]
    fn api_cookie_runtime(&self) -> Arc<ApiCookieRuntime> {
        Arc::clone(&self.api_cookie_runtime)
    }

    pub(crate) fn entra_bearer_validator(&self) -> Arc<EntraTokenValidator> {
        Arc::clone(&self.entra_bearer_validator)
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
}

impl fmt::Debug for ApiAuthenticatorRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiAuthenticatorRuntime")
            .field("auth_mode", &self.auth_mode.as_str())
            .field("generic_oidc_enabled", &self.generic_oidc_enabled)
            .field("api_cookie_runtime", &"[RETAINED]")
            .field("entra_bearer_validator", &"[RETAINED]")
            .field("oidc_callback_dependencies", &"[RETAINED]")
            .field("entra_sso_dependencies", &"[RETAINED]")
            .field("local_login_throttle", &"[RETAINED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(config: &RyukiConfig) -> (Arc<ApiCookieRuntime>, Arc<ApiAuthenticatorRuntime>) {
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
        let (cookie_runtime, runtime) = runtime(&config);

        assert!(runtime.retains_cookie_runtime(&cookie_runtime));
        assert!(Arc::ptr_eq(
            &runtime.api_cookie_runtime(),
            &runtime.api_cookie_runtime()
        ));
        assert!(Arc::ptr_eq(
            &runtime.entra_bearer_validator(),
            &runtime.entra_bearer_validator()
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
    }

    #[test]
    fn disabled_oidc_records_explicit_disabled_runtime_state() {
        let config = RyukiConfig::default();
        assert!(!config.oidc.enabled);

        let (_, runtime) = runtime(&config);

        assert!(!runtime.generic_oidc_enabled);
        assert_eq!(runtime.auth_mode(), &config.auth_mode);
    }

    #[test]
    fn enabled_oidc_constructs_one_retained_dependency_set() {
        let mut config = RyukiConfig::default();
        config.oidc.enabled = true;
        config.oidc.token_endpoint = "https://identity.example.test/token".to_string();
        config.oidc.jwks_uri = "https://identity.example.test/jwks".to_string();
        config.oidc.issuer = "https://identity.example.test".to_string();
        config.oidc.client_id = "runtime-test-client".to_string();

        let (_, runtime) = runtime(&config);

        assert!(runtime.generic_oidc_enabled);
        assert!(Arc::ptr_eq(
            &runtime.oidc_callback_dependencies(),
            &runtime.oidc_callback_dependencies()
        ));
    }

    #[test]
    fn debug_output_redacts_every_retained_handle() {
        let config = RyukiConfig::default();
        let (_, runtime) = runtime(&config);

        let rendered = format!("{runtime:?}");

        assert!(rendered.contains("ApiAuthenticatorRuntime"));
        assert!(rendered.contains("[RETAINED]"));
        assert!(!rendered.contains(&config.entra_authority));
        assert!(!rendered.contains(DISABLED_OIDC_TOKEN_ENDPOINT));
        assert!(!rendered.contains(DISABLED_OIDC_JWKS_ENDPOINT));
    }
}
