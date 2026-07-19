//! Process-lifetime ownership for the effective API browser-cookie policy.
//!
//! Secure mode retains the exact core policy allocation that a production
//! runtime guard measures. Explicit plain-HTTP loopback development uses a
//! separately typed mode that can never satisfy production admission.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use ryuki_core::config::RyukiConfig;
use ryuki_core::cookie_policy::{
    CookiePolicyError, ProductionApiCookiePolicyConfig, RetainedCookiePolicySet,
};
use ryuki_core::security_profile::{CookieSameSitePolicy, RuntimeGuardExpectedValue};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum ApiCookieRuntimeError {
    #[error("API cookie runtime is invalid: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Policy(#[from] CookiePolicyError),
}

enum ApiCookieRuntimeMode {
    Secure {
        policies: Arc<RetainedCookiePolicySet>,
    },
    LoopbackDevelopment {
        listener: SocketAddr,
        session_max_age_secs: u64,
        session_same_site: CookieSameSitePolicy,
    },
}

/// One immutable process-lifetime cookie authority. The value is intentionally
/// not `Clone`; consumers receive typed handles that share its outer `Arc`.
pub(crate) struct ApiCookieRuntime {
    production: bool,
    mode: ApiCookieRuntimeMode,
}

impl fmt::Debug for ApiCookieRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ApiCookieRuntime");
        debug.field("production", &self.production);
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => debug.field("mode", &"secure").field(
                "policy_inventory_digest",
                &policies.policy_inventory_digest(),
            ),
            ApiCookieRuntimeMode::LoopbackDevelopment { .. } => {
                debug.field("mode", &"loopback-development")
            }
        };
        debug.finish_non_exhaustive()
    }
}

impl ApiCookieRuntime {
    /// Construct the one cookie authority before global startup state is
    /// initialized. `production` comes only from the authenticated deployment
    /// security profile, never from application configuration.
    pub(crate) fn from_admitted_config(
        config: &RyukiConfig,
        production: bool,
    ) -> Result<Arc<Self>, ApiCookieRuntimeError> {
        let same_site = parse_same_site(&config.session.cookie_same_site)?;
        if production {
            if !config.session.cookie_secure {
                return Err(ApiCookieRuntimeError::Invalid(
                    "production requires Secure browser cookies",
                ));
            }
            if !config.session.cookie_http_only {
                return Err(ApiCookieRuntimeError::Invalid(
                    "production configuration must assert HttpOnly browser cookies",
                ));
            }
            if same_site == CookieSameSitePolicy::None {
                return Err(ApiCookieRuntimeError::Invalid(
                    "production SameSite=None is unavailable until logout has an explicit CSRF boundary",
                ));
            }
        }

        let mode = if config.session.cookie_secure {
            ApiCookieRuntimeMode::Secure {
                policies: RetainedCookiePolicySet::production_api(
                    ProductionApiCookiePolicyConfig {
                        session_max_age_secs: config.session.cookie_max_age_secs,
                        session_same_site: same_site,
                    },
                )?,
            }
        } else {
            if production {
                return Err(ApiCookieRuntimeError::Invalid(
                    "loopback cookie policy cannot satisfy production admission",
                ));
            }
            let listener = parse_loopback_listener(&config.server.bind_address)?;
            if config.session.cookie_max_age_secs == 0
                || config.session.cookie_max_age_secs > i64::MAX as u64
            {
                return Err(ApiCookieRuntimeError::Invalid(
                    "session Max-Age must be in 1..=i64::MAX",
                ));
            }
            ApiCookieRuntimeMode::LoopbackDevelopment {
                listener,
                session_max_age_secs: config.session.cookie_max_age_secs,
                session_same_site: same_site,
            }
        };

        Ok(Arc::new(Self { production, mode }))
    }

    /// The exact retained allocation to move into the secure-cookie witness.
    /// Loopback development has no witness-capable projection.
    pub(crate) fn secure_policy_set(&self) -> Option<&Arc<RetainedCookiePolicySet>> {
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => Some(policies),
            ApiCookieRuntimeMode::LoopbackDevelopment { .. } => None,
        }
    }

    pub(crate) fn measured_production_value(
        &self,
    ) -> Result<RuntimeGuardExpectedValue, ApiCookieRuntimeError> {
        if !self.production {
            return Err(ApiCookieRuntimeError::Invalid(
                "non-production cookie runtime cannot produce production evidence",
            ));
        }
        self.secure_policy_set()
            .ok_or(ApiCookieRuntimeError::Invalid(
                "production cookie runtime lost its secure policy allocation",
            ))?
            .measured_expected_value()
            .map_err(Into::into)
    }

    /// Recheck that the retained authority still projects the exact immutable
    /// startup configuration and authenticated security-profile class.
    pub(crate) fn validate_config_binding(
        &self,
        config: &RyukiConfig,
        production: bool,
    ) -> Result<(), ApiCookieRuntimeError> {
        if self.production != production
            || self.is_secure_mode() != config.session.cookie_secure
            || self.session_max_age_secs() != config.session.cookie_max_age_secs
            || self.session_same_site() != parse_same_site(&config.session.cookie_same_site)?
            || (production && !config.session.cookie_http_only)
        {
            return Err(ApiCookieRuntimeError::Invalid(
                "retained cookie authority differs from immutable startup configuration",
            ));
        }
        if let ApiCookieRuntimeMode::LoopbackDevelopment { listener, .. } = &self.mode {
            if *listener != parse_loopback_listener(&config.server.bind_address)? {
                return Err(ApiCookieRuntimeError::Invalid(
                    "retained loopback listener differs from immutable startup configuration",
                ));
            }
        }
        if let Some(policies) = self.secure_policy_set() {
            policies.verify_integrity()?;
        }
        if production {
            let _ = self.measured_production_value()?;
        }
        Ok(())
    }

    fn is_secure_mode(&self) -> bool {
        matches!(self.mode, ApiCookieRuntimeMode::Secure { .. })
    }

    pub(crate) fn session_max_age_secs(&self) -> u64 {
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => policies.api_session().max_age_secs(),
            ApiCookieRuntimeMode::LoopbackDevelopment {
                session_max_age_secs,
                ..
            } => *session_max_age_secs,
        }
    }

    pub(crate) fn session_same_site(&self) -> CookieSameSitePolicy {
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => policies.api_session().same_site(),
            ApiCookieRuntimeMode::LoopbackDevelopment {
                session_same_site, ..
            } => *session_same_site,
        }
    }
}

fn parse_loopback_listener(value: &str) -> Result<SocketAddr, ApiCookieRuntimeError> {
    let listener = value.parse::<SocketAddr>().map_err(|_| {
        ApiCookieRuntimeError::Invalid("loopback cookie mode requires a literal socket address")
    })?;
    if !listener.ip().is_loopback() {
        return Err(ApiCookieRuntimeError::Invalid(
            "loopback cookie mode requires a loopback listener",
        ));
    }
    Ok(listener)
}

fn parse_same_site(value: &str) -> Result<CookieSameSitePolicy, ApiCookieRuntimeError> {
    match value {
        "strict" => Ok(CookieSameSitePolicy::Strict),
        "lax" => Ok(CookieSameSitePolicy::Lax),
        "none" => Ok(CookieSameSitePolicy::None),
        _ => Err(ApiCookieRuntimeError::Invalid(
            "SameSite must be strict, lax, or none",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secure_config() -> RyukiConfig {
        let mut config = RyukiConfig::default();
        config.session.cookie_secure = true;
        config.session.cookie_http_only = true;
        config.session.cookie_same_site = "lax".into();
        config.session.cookie_max_age_secs = 86_400;
        config
    }

    #[test]
    fn production_retains_one_exact_core_policy_allocation() {
        let runtime = ApiCookieRuntime::from_admitted_config(&secure_config(), true).unwrap();
        let first = Arc::clone(runtime.secure_policy_set().unwrap());
        let second = Arc::clone(runtime.secure_policy_set().unwrap());
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(
            runtime.measured_production_value().unwrap(),
            first.measured_expected_value().unwrap()
        );
        assert!(runtime.production);
        assert!(runtime.is_secure_mode());
        runtime
            .validate_config_binding(&secure_config(), true)
            .unwrap();
    }

    #[test]
    fn production_rejects_insecure_non_http_only_and_none_policies() {
        let mut config = secure_config();
        config.session.cookie_secure = false;
        assert!(ApiCookieRuntime::from_admitted_config(&config, true).is_err());

        let mut config = secure_config();
        config.session.cookie_http_only = false;
        assert!(ApiCookieRuntime::from_admitted_config(&config, true).is_err());

        let mut config = secure_config();
        config.session.cookie_same_site = "none".into();
        assert!(ApiCookieRuntime::from_admitted_config(&config, true).is_err());
    }

    #[test]
    fn loopback_mode_is_separate_and_never_produces_production_evidence() {
        let mut config = secure_config();
        config.session.cookie_secure = false;
        config.server.bind_address = "127.0.0.1:8080".into();
        let runtime = ApiCookieRuntime::from_admitted_config(&config, false).unwrap();
        assert!(!runtime.is_secure_mode());
        assert!(runtime.secure_policy_set().is_none());
        assert!(runtime.measured_production_value().is_err());
        assert_eq!(runtime.session_max_age_secs(), 86_400);
        assert_eq!(runtime.session_same_site(), CookieSameSitePolicy::Lax);

        config.server.bind_address = "0.0.0.0:8080".into();
        assert!(ApiCookieRuntime::from_admitted_config(&config, false).is_err());
    }

    #[test]
    fn retained_runtime_rejects_mutated_binding_inputs() {
        let production_config = secure_config();
        let production_runtime =
            ApiCookieRuntime::from_admitted_config(&production_config, true).unwrap();
        let mut non_http_only = production_config;
        non_http_only.session.cookie_http_only = false;
        assert!(production_runtime
            .validate_config_binding(&non_http_only, true)
            .is_err());

        let mut loopback_config = secure_config();
        loopback_config.session.cookie_secure = false;
        loopback_config.server.bind_address = "127.0.0.1:8080".into();
        let loopback_runtime =
            ApiCookieRuntime::from_admitted_config(&loopback_config, false).unwrap();

        loopback_config.server.bind_address = "127.0.0.1:8081".into();
        assert!(loopback_runtime
            .validate_config_binding(&loopback_config, false)
            .is_err());
        loopback_config.server.bind_address = "0.0.0.0:8080".into();
        assert!(loopback_runtime
            .validate_config_binding(&loopback_config, false)
            .is_err());
    }

    #[test]
    fn debug_exposes_only_mode_and_non_secret_inventory_identity() {
        let mut config = secure_config();
        config.session.credential_hmac_key = "must-not-appear".into();
        let runtime = ApiCookieRuntime::from_admitted_config(&config, true).unwrap();
        let debug = format!("{runtime:?}");
        assert!(debug.contains("policy_inventory_digest"));
        assert!(!debug.contains("must-not-appear"));
        assert!(!debug.contains("__Host-"));
    }
}
