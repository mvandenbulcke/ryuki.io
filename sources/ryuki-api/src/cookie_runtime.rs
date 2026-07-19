//! Process-lifetime ownership for the effective API browser-cookie policy.
//!
//! Secure mode retains the exact core policy allocation that a production
//! runtime guard measures. Explicit plain-HTTP loopback development uses a
//! separately typed mode that can never satisfy production admission.

use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::header::SET_COOKIE;
use axum::http::{header::InvalidHeaderValue, HeaderMap, HeaderValue};
use axum::response::Response;
use ryuki_core::config::RyukiConfig;
use ryuki_core::cookie_policy::{
    CookiePolicyConsumer, CookiePolicyError, ProductionApiCookiePolicyConfig,
    RetainedCookiePolicySet,
};
use ryuki_core::security_profile::{CookieSameSitePolicy, RuntimeGuardExpectedValue};
use thiserror::Error;

const SECURE_SESSION_COOKIE_NAME: &str = "__Host-ryuki_session";
const LOOPBACK_SESSION_COOKIE_NAME: &str = "ryuki_session";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum ApiCookieRuntimeError {
    #[error("API cookie runtime is invalid: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Policy(#[from] CookiePolicyError),
}

#[derive(Debug, Error)]
pub(crate) enum CookieEmissionError {
    #[error("cookie consumer is not present in the retained policy inventory")]
    ConsumerBinding,
    #[error("session cookie value does not match the opaque bearer profile")]
    InvalidSessionValue,
    #[error("cookie response field could not be encoded")]
    Encoding(#[source] InvalidHeaderValue),
}

/// Validated independent `Set-Cookie` fields. The inner values are private and
/// the type deliberately implements neither `Debug` nor `Clone` because a
/// session-issuance field contains bearer material.
pub(crate) struct SetCookieFields {
    values: Vec<HeaderValue>,
}

impl SetCookieFields {
    fn from_strings(values: Vec<String>) -> Result<Self, CookieEmissionError> {
        Ok(Self {
            values: values
                .into_iter()
                .map(|value| HeaderValue::from_str(&value).map_err(CookieEmissionError::Encoding))
                .collect::<Result<_, _>>()?,
        })
    }

    /// Append each cookie as its own HTTP field. `Set-Cookie` is not a list
    /// header and must never be comma-joined.
    pub(crate) fn append_to(self, response: &mut Response) {
        for value in self.values {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }

    #[cfg(test)]
    fn field_values(&self) -> Vec<&str> {
        self.values
            .iter()
            .map(|value| value.to_str().expect("test cookie field must be text"))
            .collect()
    }
}

mod consumer {
    pub(crate) enum LocalSessionIssuer {}
    pub(crate) enum EntraSessionIssuer {}
    pub(crate) enum OidcSessionIssuer {}
    pub(crate) enum SessionLogoutRetirer {}
    pub(crate) enum SessionAuthParser {}
    pub(crate) enum SessionLookupAdmissionParser {}
    pub(crate) enum SessionLogoutParser {}
}

pub(crate) trait SessionIssuerConsumer {
    const ID: CookiePolicyConsumer;
}

impl SessionIssuerConsumer for consumer::LocalSessionIssuer {
    const ID: CookiePolicyConsumer = CookiePolicyConsumer::ApiLocalSessionIssuer;
}

impl SessionIssuerConsumer for consumer::EntraSessionIssuer {
    const ID: CookiePolicyConsumer = CookiePolicyConsumer::ApiEntraSessionIssuer;
}

impl SessionIssuerConsumer for consumer::OidcSessionIssuer {
    const ID: CookiePolicyConsumer = CookiePolicyConsumer::ApiOidcSessionIssuer;
}

pub(crate) trait SessionRetirerConsumer {
    const ID: CookiePolicyConsumer;
}

impl SessionRetirerConsumer for consumer::SessionLogoutRetirer {
    const ID: CookiePolicyConsumer = CookiePolicyConsumer::ApiSessionLogoutRetirer;
}

pub(crate) trait SessionParserConsumer {
    const ID: CookiePolicyConsumer;
}

impl SessionParserConsumer for consumer::SessionAuthParser {
    const ID: CookiePolicyConsumer = CookiePolicyConsumer::ApiSessionAuthParser;
}

impl SessionParserConsumer for consumer::SessionLookupAdmissionParser {
    const ID: CookiePolicyConsumer = CookiePolicyConsumer::ApiSessionLookupAdmissionParser;
}

impl SessionParserConsumer for consumer::SessionLogoutParser {
    const ID: CookiePolicyConsumer = CookiePolicyConsumer::ApiSessionLogoutParser;
}

/// A non-forgeable capability for one declared session-cookie issuer. Its
/// private constructor always retains the exact process-lifetime runtime Arc.
pub(crate) struct SessionCookieIssuer<C> {
    runtime: Arc<ApiCookieRuntime>,
    _consumer: PhantomData<fn() -> C>,
}

pub(crate) type ApiLocalSessionIssuer = SessionCookieIssuer<consumer::LocalSessionIssuer>;
pub(crate) type ApiEntraSessionIssuer = SessionCookieIssuer<consumer::EntraSessionIssuer>;
pub(crate) type ApiOidcSessionIssuer = SessionCookieIssuer<consumer::OidcSessionIssuer>;

impl<C> SessionCookieIssuer<C> {
    fn new(runtime: Arc<ApiCookieRuntime>) -> Self {
        Self {
            runtime,
            _consumer: PhantomData,
        }
    }
}

impl<C: SessionIssuerConsumer> SessionCookieIssuer<C> {
    pub(crate) fn issue(
        &self,
        session_bearer: &str,
    ) -> Result<SetCookieFields, CookieEmissionError> {
        if !self.runtime.session_issuer_is_bound(C::ID) {
            return Err(CookieEmissionError::ConsumerBinding);
        }
        if !crate::session_credentials::is_well_formed_session_bearer(session_bearer) {
            return Err(CookieEmissionError::InvalidSessionValue);
        }
        self.runtime.session_cookie_fields(session_bearer, false)
    }
}

/// A separate capability for logout retirement; it cannot issue a bearer.
pub(crate) struct SessionCookieRetirer<C> {
    runtime: Arc<ApiCookieRuntime>,
    _consumer: PhantomData<fn() -> C>,
}

pub(crate) type ApiSessionLogoutRetirer = SessionCookieRetirer<consumer::SessionLogoutRetirer>;

impl<C> SessionCookieRetirer<C> {
    fn new(runtime: Arc<ApiCookieRuntime>) -> Self {
        Self {
            runtime,
            _consumer: PhantomData,
        }
    }
}

impl<C: SessionRetirerConsumer> SessionCookieRetirer<C> {
    pub(crate) fn retire(&self) -> Result<SetCookieFields, CookieEmissionError> {
        if !self.runtime.session_issuer_is_bound(C::ID) {
            return Err(CookieEmissionError::ConsumerBinding);
        }
        self.runtime.session_cookie_fields("", true)
    }
}

/// Cookie evidence is explicitly tri-state so malformed or ambiguous browser
/// input cannot be mistaken for absence and fall through to another carrier.
pub(crate) enum CookieEvidence<'a> {
    Absent,
    Value(&'a str),
    Invalid,
}

/// A non-forgeable capability for one declared session-cookie parser. Every
/// parser handle owns an Arc clone of the exact retained runtime authority.
pub(crate) struct SessionCookieParser<C> {
    runtime: Arc<ApiCookieRuntime>,
    _consumer: PhantomData<fn() -> C>,
}

pub(crate) type ApiSessionAuthParser = SessionCookieParser<consumer::SessionAuthParser>;
pub(crate) type ApiSessionLookupAdmissionParser =
    SessionCookieParser<consumer::SessionLookupAdmissionParser>;
pub(crate) type ApiSessionLogoutParser = SessionCookieParser<consumer::SessionLogoutParser>;

impl<C> SessionCookieParser<C> {
    fn new(runtime: Arc<ApiCookieRuntime>) -> Self {
        Self {
            runtime,
            _consumer: PhantomData,
        }
    }
}

impl<C: SessionParserConsumer> SessionCookieParser<C> {
    pub(crate) fn parse<'a>(&self, headers: &'a HeaderMap) -> CookieEvidence<'a> {
        if !self.runtime.session_parser_is_bound(C::ID) {
            return CookieEvidence::Invalid;
        }
        match self.runtime.session_cookie_evidence(headers) {
            CookieEvidence::Value(value)
                if !crate::session_credentials::is_well_formed_session_bearer(value) =>
            {
                CookieEvidence::Invalid
            }
            evidence => evidence,
        }
    }
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

    pub(crate) fn local_session_issuer(self: &Arc<Self>) -> ApiLocalSessionIssuer {
        SessionCookieIssuer::new(Arc::clone(self))
    }

    pub(crate) fn entra_session_issuer(self: &Arc<Self>) -> ApiEntraSessionIssuer {
        SessionCookieIssuer::new(Arc::clone(self))
    }

    pub(crate) fn oidc_session_issuer(self: &Arc<Self>) -> ApiOidcSessionIssuer {
        SessionCookieIssuer::new(Arc::clone(self))
    }

    pub(crate) fn session_logout_retirer(self: &Arc<Self>) -> ApiSessionLogoutRetirer {
        SessionCookieRetirer::new(Arc::clone(self))
    }

    pub(crate) fn session_auth_parser(self: &Arc<Self>) -> ApiSessionAuthParser {
        SessionCookieParser::new(Arc::clone(self))
    }

    pub(crate) fn session_lookup_admission_parser(
        self: &Arc<Self>,
    ) -> ApiSessionLookupAdmissionParser {
        SessionCookieParser::new(Arc::clone(self))
    }

    pub(crate) fn session_logout_parser(self: &Arc<Self>) -> ApiSessionLogoutParser {
        SessionCookieParser::new(Arc::clone(self))
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

    fn session_cookie_fields(
        &self,
        value: &str,
        retire: bool,
    ) -> Result<SetCookieFields, CookieEmissionError> {
        let mut fields = Vec::with_capacity(2);
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => {
                let policy = policies.api_session();
                debug_assert_eq!(policy.cookie_name(), SECURE_SESSION_COOKIE_NAME);
                fields.push(render_cookie_field(
                    policy.cookie_name(),
                    value,
                    if retire { 0 } else { policy.max_age_secs() },
                    policy.path(),
                    policy.http_only(),
                    policy.secure(),
                    policy.same_site(),
                ));
                for retired_name in policy.retired_cookie_names() {
                    fields.push(render_cookie_field(
                        retired_name,
                        "",
                        0,
                        policy.path(),
                        policy.http_only(),
                        policy.secure(),
                        policy.same_site(),
                    ));
                }
            }
            ApiCookieRuntimeMode::LoopbackDevelopment {
                session_max_age_secs,
                session_same_site,
                ..
            } => fields.push(render_cookie_field(
                LOOPBACK_SESSION_COOKIE_NAME,
                value,
                if retire { 0 } else { *session_max_age_secs },
                "/",
                true,
                false,
                *session_same_site,
            )),
        }
        SetCookieFields::from_strings(fields)
    }

    fn session_issuer_is_bound(&self, consumer: CookiePolicyConsumer) -> bool {
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => policies
                .api_session()
                .issuer_consumers()
                .contains(&consumer),
            ApiCookieRuntimeMode::LoopbackDevelopment { .. } => matches!(
                consumer,
                CookiePolicyConsumer::ApiLocalSessionIssuer
                    | CookiePolicyConsumer::ApiEntraSessionIssuer
                    | CookiePolicyConsumer::ApiOidcSessionIssuer
                    | CookiePolicyConsumer::ApiSessionLogoutRetirer
            ),
        }
    }

    fn session_parser_is_bound(&self, consumer: CookiePolicyConsumer) -> bool {
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => policies
                .api_session()
                .parser_consumers()
                .contains(&consumer),
            ApiCookieRuntimeMode::LoopbackDevelopment { .. } => matches!(
                consumer,
                CookiePolicyConsumer::ApiSessionAuthParser
                    | CookiePolicyConsumer::ApiSessionLookupAdmissionParser
                    | CookiePolicyConsumer::ApiSessionLogoutParser
            ),
        }
    }

    fn session_cookie_evidence<'a>(&self, headers: &'a HeaderMap) -> CookieEvidence<'a> {
        let mut credential = None;
        for raw_cookie_header in headers.get_all(axum::http::header::COOKIE).iter() {
            let cookie_header = match raw_cookie_header.to_str() {
                Ok(value) => value,
                Err(_) => return CookieEvidence::Invalid,
            };
            for pair in cookie_header.split(';') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                let Some((name, value)) = pair.split_once('=') else {
                    return CookieEvidence::Invalid;
                };
                let name = name.trim();
                if name.is_empty() {
                    return CookieEvidence::Invalid;
                }
                if !self.is_known_session_cookie_name(name) {
                    continue;
                }
                if credential.is_some() {
                    return CookieEvidence::Invalid;
                }
                credential = Some((name, value.trim()));
            }
        }

        let Some((name, value)) = credential else {
            return CookieEvidence::Absent;
        };
        if name != self.selected_session_cookie_name() {
            return CookieEvidence::Invalid;
        }
        CookieEvidence::Value(value)
    }

    fn selected_session_cookie_name(&self) -> &str {
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => policies.api_session().cookie_name(),
            ApiCookieRuntimeMode::LoopbackDevelopment { .. } => LOOPBACK_SESSION_COOKIE_NAME,
        }
    }

    fn is_known_session_cookie_name(&self, name: &str) -> bool {
        match &self.mode {
            ApiCookieRuntimeMode::Secure { policies } => {
                let policy = policies.api_session();
                name == policy.cookie_name()
                    || policy
                        .retired_cookie_names()
                        .iter()
                        .any(|retired| retired == name)
            }
            ApiCookieRuntimeMode::LoopbackDevelopment { .. } => {
                name == LOOPBACK_SESSION_COOKIE_NAME || name == SECURE_SESSION_COOKIE_NAME
            }
        }
    }
}

fn render_cookie_field(
    name: &str,
    value: &str,
    max_age_secs: u64,
    path: &str,
    http_only: bool,
    secure: bool,
    same_site: CookieSameSitePolicy,
) -> String {
    let mut field = format!("{name}={value}; Path={path}");
    if http_only {
        field.push_str("; HttpOnly");
    }
    field.push_str(&format!(
        "; Max-Age={max_age_secs}; SameSite={}",
        same_site_attribute(same_site)
    ));
    if secure {
        field.push_str("; Secure");
    }
    field
}

fn same_site_attribute(value: CookieSameSitePolicy) -> &'static str {
    match value {
        CookieSameSitePolicy::Strict => "Strict",
        CookieSameSitePolicy::Lax => "Lax",
        CookieSameSitePolicy::None => "None",
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
    fn session_issuer_handles_retain_exact_runtime_and_emit_closed_fields() {
        let runtime = ApiCookieRuntime::from_admitted_config(&secure_config(), true).unwrap();
        let local = runtime.local_session_issuer();
        let entra = runtime.entra_session_issuer();
        let oidc = runtime.oidc_session_issuer();
        assert!(Arc::ptr_eq(&runtime, &local.runtime));
        assert!(Arc::ptr_eq(&runtime, &entra.runtime));
        assert!(Arc::ptr_eq(&runtime, &oidc.runtime));

        let session_value = crate::session_credentials::generate_session_bearer();
        let fields = local.issue(session_value.as_str()).unwrap();
        assert_eq!(
            fields.field_values(),
            vec![
                format!(
                    "__Host-ryuki_session={}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax; Secure",
                    session_value.as_str()
                ),
                "ryuki_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure".into(),
            ]
        );

        let mut response = Response::new(axum::body::Body::empty());
        fields.append_to(&mut response);
        assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 2);
        assert!(local.issue("not-a-session-bearer").is_err());
    }

    #[test]
    fn session_logout_retirer_clears_every_secure_name() {
        let runtime = ApiCookieRuntime::from_admitted_config(&secure_config(), true).unwrap();
        let retirer = runtime.session_logout_retirer();
        assert!(Arc::ptr_eq(&runtime, &retirer.runtime));
        assert_eq!(
            retirer.retire().unwrap().field_values(),
            vec![
                "__Host-ryuki_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure",
                "ryuki_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure",
            ]
        );
    }

    #[test]
    fn loopback_session_handles_emit_only_the_unprefixed_cookie() {
        let mut config = secure_config();
        config.session.cookie_secure = false;
        config.session.cookie_same_site = "strict".into();
        config.server.bind_address = "127.0.0.1:8080".into();
        let runtime = ApiCookieRuntime::from_admitted_config(&config, false).unwrap();
        let session_value = crate::session_credentials::generate_session_bearer();
        assert_eq!(
            runtime
                .local_session_issuer()
                .issue(session_value.as_str())
                .unwrap()
                .field_values(),
            vec![format!(
                "ryuki_session={}; Path=/; HttpOnly; Max-Age=86400; SameSite=Strict",
                session_value.as_str()
            )]
        );
        assert_eq!(
            runtime
                .session_logout_retirer()
                .retire()
                .unwrap()
                .field_values(),
            vec!["ryuki_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Strict"]
        );
    }

    #[test]
    fn session_parser_handles_retain_exact_runtime_and_closed_consumer_binding() {
        let runtime = ApiCookieRuntime::from_admitted_config(&secure_config(), true).unwrap();
        let auth = runtime.session_auth_parser();
        let lookup = runtime.session_lookup_admission_parser();
        let logout = runtime.session_logout_parser();
        assert!(Arc::ptr_eq(&runtime, &auth.runtime));
        assert!(Arc::ptr_eq(&runtime, &lookup.runtime));
        assert!(Arc::ptr_eq(&runtime, &logout.runtime));

        let session_value = crate::session_credentials::generate_session_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!("__Host-ryuki_session={}", session_value.as_str()))
                .unwrap(),
        );
        for evidence in [
            auth.parse(&headers),
            lookup.parse(&headers),
            logout.parse(&headers),
        ] {
            let CookieEvidence::Value(value) = evidence else {
                panic!("declared parser must return the selected session value");
            };
            assert_eq!(value, session_value.as_str());
        }
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
