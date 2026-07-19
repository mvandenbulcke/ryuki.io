//! Closed, retained browser-cookie policy for production runtime admission.
//!
//! The policy set is deliberately factory-owned. Callers may select only the
//! typed session lifetime and SameSite value; cookie names, security flags,
//! purposes, issuer/parser inventories, and digest contracts cannot be supplied
//! by configuration or reconstructed by individual handlers.

use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conformance_trust::canonical_json_bytes;
use crate::security_profile::{
    CookieSameSitePolicy, ExpectedCookiePolicy, RuntimeGuardExpectedValue,
};

pub const COOKIE_POLICY_BINDING_DIGEST_CONTRACT: &str = "ryuki-cookie-policy-binding-v1";
pub const COOKIE_POLICY_INVENTORY_DIGEST_CONTRACT: &str = "ryuki-cookie-policy-inventory-v1";

const API_ENTRA_BINDING_POLICY_ID: &str = "cookie-policy:api-entra-login-binding";
const API_OIDC_BINDING_POLICY_ID: &str = "cookie-policy:api-oidc-login-binding";
const API_SESSION_POLICY_ID: &str = "cookie-policy:api-session";
const SECURE_ENTRA_BINDING_COOKIE_NAME: &str = "__Host-entra_login_csrf";
const SECURE_OIDC_BINDING_COOKIE_NAME: &str = "__Host-oidc_login_csrf";
const SECURE_SESSION_COOKIE_NAME: &str = "__Host-ryuki_session";
const RETIRED_SESSION_COOKIE_NAME: &str = "ryuki_session";
const LOGIN_BINDING_MAX_AGE_SECS: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CookiePurpose {
    ApiSession,
    ApiEntraLoginBinding,
    ApiOidcLoginBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CookieLifetimeSource {
    ConfiguredSession,
    FixedLoginState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CookieValueProfile {
    OpaqueSessionBearerV1,
    LoginBindingBase64url256V1,
}

/// Closed identifiers for every API code path allowed to write or consume a
/// credential-bearing browser cookie. Clearing/retirement is an issuer action
/// because it emits a `Set-Cookie` field under the same policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CookiePolicyConsumer {
    ApiEntraBindingIssuer,
    ApiEntraBindingParser,
    ApiEntraSessionIssuer,
    ApiLocalSessionIssuer,
    ApiOidcBindingIssuer,
    ApiOidcBindingParser,
    ApiOidcSessionIssuer,
    ApiSessionAuthParser,
    ApiSessionLookupAdmissionParser,
    ApiSessionLogoutParser,
    ApiSessionLogoutRetirer,
}

impl CookiePolicyConsumer {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ApiEntraBindingIssuer => "api-entra-binding-issuer",
            Self::ApiEntraBindingParser => "api-entra-binding-parser",
            Self::ApiEntraSessionIssuer => "api-entra-session-issuer",
            Self::ApiLocalSessionIssuer => "api-local-session-issuer",
            Self::ApiOidcBindingIssuer => "api-oidc-binding-issuer",
            Self::ApiOidcBindingParser => "api-oidc-binding-parser",
            Self::ApiOidcSessionIssuer => "api-oidc-session-issuer",
            Self::ApiSessionAuthParser => "api-session-auth-parser",
            Self::ApiSessionLookupAdmissionParser => "api-session-lookup-admission-parser",
            Self::ApiSessionLogoutParser => "api-session-logout-parser",
            Self::ApiSessionLogoutRetirer => "api-session-logout-retirer",
        }
    }
}

const API_SESSION_ISSUERS: [CookiePolicyConsumer; 4] = [
    CookiePolicyConsumer::ApiEntraSessionIssuer,
    CookiePolicyConsumer::ApiLocalSessionIssuer,
    CookiePolicyConsumer::ApiOidcSessionIssuer,
    CookiePolicyConsumer::ApiSessionLogoutRetirer,
];
const API_SESSION_PARSERS: [CookiePolicyConsumer; 3] = [
    CookiePolicyConsumer::ApiSessionAuthParser,
    CookiePolicyConsumer::ApiSessionLogoutParser,
    CookiePolicyConsumer::ApiSessionLookupAdmissionParser,
];
const API_ENTRA_BINDING_ISSUERS: [CookiePolicyConsumer; 1] =
    [CookiePolicyConsumer::ApiEntraBindingIssuer];
const API_ENTRA_BINDING_PARSERS: [CookiePolicyConsumer; 1] =
    [CookiePolicyConsumer::ApiEntraBindingParser];
const API_OIDC_BINDING_ISSUERS: [CookiePolicyConsumer; 1] =
    [CookiePolicyConsumer::ApiOidcBindingIssuer];
const API_OIDC_BINDING_PARSERS: [CookiePolicyConsumer; 1] =
    [CookiePolicyConsumer::ApiOidcBindingParser];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionApiCookiePolicyConfig {
    pub session_max_age_secs: u64,
    pub session_same_site: CookieSameSitePolicy,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CookiePolicyError {
    #[error("production cookie policy is invalid: {0}")]
    Invalid(&'static str),
    #[error("production cookie policy could not be canonically projected")]
    Projection,
}

/// One immutable effective issuer/parser policy. All fields are non-secret.
/// Construction is private so a caller cannot mint digest authority for an
/// arbitrary name, consumer set, or weakened security flag.
#[derive(Debug, PartialEq, Eq)]
pub struct RetainedCookiePolicy {
    policy_id: String,
    purpose: CookiePurpose,
    cookie_name: String,
    secure: bool,
    http_only: bool,
    path: String,
    domain: Option<String>,
    same_site: CookieSameSitePolicy,
    lifetime_source: CookieLifetimeSource,
    max_age_secs: u64,
    value_profile: CookieValueProfile,
    retired_cookie_names: Box<[String]>,
    issuer_consumers: Box<[CookiePolicyConsumer]>,
    parser_consumers: Box<[CookiePolicyConsumer]>,
    policy_digest: String,
}

impl RetainedCookiePolicy {
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn purpose(&self) -> CookiePurpose {
        self.purpose
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn http_only(&self) -> bool {
        self.http_only
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    pub fn same_site(&self) -> CookieSameSitePolicy {
        self.same_site
    }

    pub fn lifetime_source(&self) -> CookieLifetimeSource {
        self.lifetime_source
    }

    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    pub fn value_profile(&self) -> CookieValueProfile {
        self.value_profile
    }

    pub fn retired_cookie_names(&self) -> &[String] {
        &self.retired_cookie_names
    }

    pub fn issuer_consumers(&self) -> &[CookiePolicyConsumer] {
        &self.issuer_consumers
    }

    pub fn parser_consumers(&self) -> &[CookiePolicyConsumer] {
        &self.parser_consumers
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    fn expected_policy(&self) -> ExpectedCookiePolicy {
        ExpectedCookiePolicy {
            policy_id: self.policy_id.clone(),
            cookie_name: self.cookie_name.clone(),
            secure: self.secure,
            http_only: self.http_only,
            path: self.path.clone(),
            domain: self.domain.clone(),
            same_site: self.same_site,
            policy_digest: self.policy_digest.clone(),
        }
    }
}

/// The exact immutable API cookie inventory retained by runtime admission and
/// shared with every API issuer/parser. The set itself is intentionally not
/// `Clone`; callers share the factory-returned `Arc`.
#[derive(Debug, PartialEq, Eq)]
pub struct RetainedCookiePolicySet {
    policies: Box<[RetainedCookiePolicy]>,
    policy_inventory_digest: String,
}

impl RetainedCookiePolicySet {
    /// Construct the complete shipped API inventory. Production callers cannot
    /// select names, omit a registered consumer, weaken flags, or inject either
    /// digest. Login-binding policies are retained even when a provider is
    /// disabled because those routes remain part of the shipped API surface.
    pub fn production_api(
        config: ProductionApiCookiePolicyConfig,
    ) -> Result<Arc<Self>, CookiePolicyError> {
        if config.session_max_age_secs == 0 || config.session_max_age_secs > i64::MAX as u64 {
            return Err(CookiePolicyError::Invalid(
                "session Max-Age must be in 1..=i64::MAX",
            ));
        }

        let mut policies = vec![
            unsealed_policy(
                API_ENTRA_BINDING_POLICY_ID,
                CookiePurpose::ApiEntraLoginBinding,
                SECURE_ENTRA_BINDING_COOKIE_NAME,
                CookieSameSitePolicy::Lax,
                CookieLifetimeSource::FixedLoginState,
                LOGIN_BINDING_MAX_AGE_SECS,
                CookieValueProfile::LoginBindingBase64url256V1,
                &[],
                &API_ENTRA_BINDING_ISSUERS,
                &API_ENTRA_BINDING_PARSERS,
            ),
            unsealed_policy(
                API_OIDC_BINDING_POLICY_ID,
                CookiePurpose::ApiOidcLoginBinding,
                SECURE_OIDC_BINDING_COOKIE_NAME,
                CookieSameSitePolicy::Lax,
                CookieLifetimeSource::FixedLoginState,
                LOGIN_BINDING_MAX_AGE_SECS,
                CookieValueProfile::LoginBindingBase64url256V1,
                &[],
                &API_OIDC_BINDING_ISSUERS,
                &API_OIDC_BINDING_PARSERS,
            ),
            unsealed_policy(
                API_SESSION_POLICY_ID,
                CookiePurpose::ApiSession,
                SECURE_SESSION_COOKIE_NAME,
                config.session_same_site,
                CookieLifetimeSource::ConfiguredSession,
                config.session_max_age_secs,
                CookieValueProfile::OpaqueSessionBearerV1,
                &[RETIRED_SESSION_COOKIE_NAME],
                &API_SESSION_ISSUERS,
                &API_SESSION_PARSERS,
            ),
        ];
        policies.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
        for policy in &mut policies {
            validate_policy(policy)?;
            policy.policy_digest = policy_binding_digest(policy)?;
        }
        let policy_inventory_digest = policy_inventory_digest(&policies)?;
        let set = Self {
            policies: policies.into_boxed_slice(),
            policy_inventory_digest,
        };
        set.verify_integrity()?;
        Ok(Arc::new(set))
    }

    pub fn policies(&self) -> &[RetainedCookiePolicy] {
        &self.policies
    }

    pub fn api_session(&self) -> &RetainedCookiePolicy {
        self.policy(CookiePurpose::ApiSession)
    }

    pub fn api_entra_login_binding(&self) -> &RetainedCookiePolicy {
        self.policy(CookiePurpose::ApiEntraLoginBinding)
    }

    pub fn api_oidc_login_binding(&self) -> &RetainedCookiePolicy {
        self.policy(CookiePurpose::ApiOidcLoginBinding)
    }

    pub fn policy_inventory_digest(&self) -> &str {
        &self.policy_inventory_digest
    }

    /// Recompute every closed projection. Runtime admission calls this on the
    /// same retained allocation handed to handlers before comparing the complete
    /// measured expected value with receipt-bound authority.
    pub fn verify_integrity(&self) -> Result<(), CookiePolicyError> {
        if self.policies.len() != 3
            || !strictly_sorted_unique_by(&self.policies, |policy| policy.policy_id.as_str())
        {
            return Err(CookiePolicyError::Invalid(
                "API policy inventory must contain exactly three sorted policies",
            ));
        }
        for policy in &self.policies {
            validate_policy(policy)?;
            if policy.policy_digest != policy_binding_digest(policy)? {
                return Err(CookiePolicyError::Invalid(
                    "stored policy digest differs from the effective policy",
                ));
            }
        }
        if self.policy_inventory_digest != policy_inventory_digest(&self.policies)? {
            return Err(CookiePolicyError::Invalid(
                "stored inventory digest differs from the effective inventory",
            ));
        }
        Ok(())
    }

    /// Exact live measurement consumed by `SecureCookiesWitness`. This is not
    /// authority: only equality with the receipt-bound expected value under the
    /// workload-specific guard challenge can authorize admission.
    pub fn measured_expected_value(&self) -> Result<RuntimeGuardExpectedValue, CookiePolicyError> {
        self.verify_integrity()?;
        Ok(RuntimeGuardExpectedValue::SecureCookies {
            policies: self
                .policies
                .iter()
                .map(RetainedCookiePolicy::expected_policy)
                .collect(),
            policy_inventory_digest: self.policy_inventory_digest.clone(),
        })
    }

    fn policy(&self, purpose: CookiePurpose) -> &RetainedCookiePolicy {
        self.policies
            .iter()
            .find(|policy| policy.purpose == purpose)
            .expect("closed production API cookie inventory lost a required purpose")
    }
}

#[allow(clippy::too_many_arguments)]
fn unsealed_policy(
    policy_id: &str,
    purpose: CookiePurpose,
    cookie_name: &str,
    same_site: CookieSameSitePolicy,
    lifetime_source: CookieLifetimeSource,
    max_age_secs: u64,
    value_profile: CookieValueProfile,
    retired_cookie_names: &[&str],
    issuer_consumers: &[CookiePolicyConsumer],
    parser_consumers: &[CookiePolicyConsumer],
) -> RetainedCookiePolicy {
    RetainedCookiePolicy {
        policy_id: policy_id.to_owned(),
        purpose,
        cookie_name: cookie_name.to_owned(),
        secure: true,
        http_only: true,
        path: "/".into(),
        domain: None,
        same_site,
        lifetime_source,
        max_age_secs,
        value_profile,
        retired_cookie_names: retired_cookie_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        issuer_consumers: issuer_consumers.to_vec().into_boxed_slice(),
        parser_consumers: parser_consumers.to_vec().into_boxed_slice(),
        policy_digest: String::new(),
    }
}

fn validate_policy(policy: &RetainedCookiePolicy) -> Result<(), CookiePolicyError> {
    if !valid_policy_id(&policy.policy_id) {
        return Err(CookiePolicyError::Invalid("policy id is not canonical"));
    }
    if !valid_host_cookie_name(&policy.cookie_name)
        || !policy.secure
        || !policy.http_only
        || policy.path != "/"
        || policy.domain.is_some()
    {
        return Err(CookiePolicyError::Invalid(
            "production policy must use a canonical __Host- cookie",
        ));
    }
    if policy.max_age_secs == 0 || policy.max_age_secs > i64::MAX as u64 {
        return Err(CookiePolicyError::Invalid(
            "policy Max-Age must be in 1..=i64::MAX",
        ));
    }
    if policy.issuer_consumers.is_empty()
        || policy.parser_consumers.is_empty()
        || !strictly_sorted_unique_by(&policy.issuer_consumers, |consumer| consumer.as_str())
        || !strictly_sorted_unique_by(&policy.parser_consumers, |consumer| consumer.as_str())
    {
        return Err(CookiePolicyError::Invalid(
            "issuer and parser inventories must be nonempty, sorted, and unique",
        ));
    }
    if !strictly_sorted_unique_by(&policy.retired_cookie_names, String::as_str) {
        return Err(CookiePolicyError::Invalid(
            "retired cookie names must be sorted and unique",
        ));
    }

    let exact = match policy.purpose {
        CookiePurpose::ApiSession => {
            policy.policy_id == API_SESSION_POLICY_ID
                && policy.cookie_name == SECURE_SESSION_COOKIE_NAME
                && policy.lifetime_source == CookieLifetimeSource::ConfiguredSession
                && policy.value_profile == CookieValueProfile::OpaqueSessionBearerV1
                && policy.retired_cookie_names.len() == 1
                && policy.retired_cookie_names[0] == RETIRED_SESSION_COOKIE_NAME
                && policy.issuer_consumers.as_ref() == API_SESSION_ISSUERS.as_slice()
                && policy.parser_consumers.as_ref() == API_SESSION_PARSERS.as_slice()
        }
        CookiePurpose::ApiEntraLoginBinding => {
            policy.policy_id == API_ENTRA_BINDING_POLICY_ID
                && policy.cookie_name == SECURE_ENTRA_BINDING_COOKIE_NAME
                && policy.same_site == CookieSameSitePolicy::Lax
                && policy.lifetime_source == CookieLifetimeSource::FixedLoginState
                && policy.max_age_secs == LOGIN_BINDING_MAX_AGE_SECS
                && policy.value_profile == CookieValueProfile::LoginBindingBase64url256V1
                && policy.retired_cookie_names.is_empty()
                && policy.issuer_consumers.as_ref() == API_ENTRA_BINDING_ISSUERS.as_slice()
                && policy.parser_consumers.as_ref() == API_ENTRA_BINDING_PARSERS.as_slice()
        }
        CookiePurpose::ApiOidcLoginBinding => {
            policy.policy_id == API_OIDC_BINDING_POLICY_ID
                && policy.cookie_name == SECURE_OIDC_BINDING_COOKIE_NAME
                && policy.same_site == CookieSameSitePolicy::Lax
                && policy.lifetime_source == CookieLifetimeSource::FixedLoginState
                && policy.max_age_secs == LOGIN_BINDING_MAX_AGE_SECS
                && policy.value_profile == CookieValueProfile::LoginBindingBase64url256V1
                && policy.retired_cookie_names.is_empty()
                && policy.issuer_consumers.as_ref() == API_OIDC_BINDING_ISSUERS.as_slice()
                && policy.parser_consumers.as_ref() == API_OIDC_BINDING_PARSERS.as_slice()
        }
    };
    if !exact {
        return Err(CookiePolicyError::Invalid(
            "policy differs from its closed purpose contract",
        ));
    }
    Ok(())
}

fn valid_policy_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("cookie-policy:") else {
        return false;
    };
    (3..=127).contains(&suffix.len())
        && suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
        && suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_host_cookie_name(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("__Host-") else {
        return false;
    };
    (3..=120).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn strictly_sorted_unique_by<T>(values: &[T], key: impl Fn(&T) -> &str) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

#[derive(Serialize)]
struct CookiePolicyBindingProjection<'a> {
    digest_contract: &'static str,
    policy_id: &'a str,
    purpose: CookiePurpose,
    cookie_name: &'a str,
    secure: bool,
    http_only: bool,
    path: &'a str,
    domain: Option<&'a str>,
    same_site: CookieSameSitePolicy,
    lifetime_source: CookieLifetimeSource,
    max_age_secs: u64,
    value_profile: CookieValueProfile,
    retired_cookie_names: &'a [String],
    issuer_consumers: &'a [CookiePolicyConsumer],
    parser_consumers: &'a [CookiePolicyConsumer],
}

impl<'a> From<&'a RetainedCookiePolicy> for CookiePolicyBindingProjection<'a> {
    fn from(policy: &'a RetainedCookiePolicy) -> Self {
        Self {
            digest_contract: COOKIE_POLICY_BINDING_DIGEST_CONTRACT,
            policy_id: &policy.policy_id,
            purpose: policy.purpose,
            cookie_name: &policy.cookie_name,
            secure: policy.secure,
            http_only: policy.http_only,
            path: &policy.path,
            domain: policy.domain.as_deref(),
            same_site: policy.same_site,
            lifetime_source: policy.lifetime_source,
            max_age_secs: policy.max_age_secs,
            value_profile: policy.value_profile,
            retired_cookie_names: &policy.retired_cookie_names,
            issuer_consumers: &policy.issuer_consumers,
            parser_consumers: &policy.parser_consumers,
        }
    }
}

#[derive(Serialize)]
struct CookiePolicyInventoryEntry<'a> {
    policy: CookiePolicyBindingProjection<'a>,
    policy_digest: &'a str,
}

#[derive(Serialize)]
struct CookiePolicyInventoryProjection<'a> {
    digest_contract: &'static str,
    policies: Vec<CookiePolicyInventoryEntry<'a>>,
}

fn policy_binding_digest(policy: &RetainedCookiePolicy) -> Result<String, CookiePolicyError> {
    digest_projection(&CookiePolicyBindingProjection::from(policy))
}

fn policy_inventory_digest(policies: &[RetainedCookiePolicy]) -> Result<String, CookiePolicyError> {
    digest_projection(&CookiePolicyInventoryProjection {
        digest_contract: COOKIE_POLICY_INVENTORY_DIGEST_CONTRACT,
        policies: policies
            .iter()
            .map(|policy| CookiePolicyInventoryEntry {
                policy: CookiePolicyBindingProjection::from(policy),
                policy_digest: &policy.policy_digest,
            })
            .collect(),
    })
}

fn digest_projection(projection: &impl Serialize) -> Result<String, CookiePolicyError> {
    let value: Value =
        serde_json::to_value(projection).map_err(|_| CookiePolicyError::Projection)?;
    let canonical = canonical_json_bytes(&value).map_err(|_| CookiePolicyError::Projection)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRA_POLICY_DIGEST: &str =
        "sha256:dd2524c0de18cc5e6af3f6f917b3d9084d5ee8e0348a9197bad15d8c4f35aa70";
    const OIDC_POLICY_DIGEST: &str =
        "sha256:58daba94f8a546b3ecb66ef47d68d373d031a9aeb86a5b3a3a60c722917dbbb9";
    const SESSION_POLICY_DIGEST: &str =
        "sha256:f64e6fef4fa12a22a0e15fb87ca3f10bb9d1212b76d129dd1cfb91f00ac043e1";
    const INVENTORY_DIGEST: &str =
        "sha256:5d41f46cb07894ac33d14824daeccdc7e466577383fc0a463f9a919949a0bbc7";

    fn fixture() -> Arc<RetainedCookiePolicySet> {
        RetainedCookiePolicySet::production_api(ProductionApiCookiePolicyConfig {
            session_max_age_secs: 86_400,
            session_same_site: CookieSameSitePolicy::Lax,
        })
        .expect("closed production API cookie policy must construct")
    }

    #[test]
    fn production_api_policy_has_stable_canonical_golden_digests() {
        let set = fixture();
        assert_eq!(set.policies().len(), 3);
        assert_eq!(
            set.policies()
                .iter()
                .map(|policy| (policy.policy_id(), policy.policy_digest()))
                .collect::<Vec<_>>(),
            vec![
                (API_ENTRA_BINDING_POLICY_ID, ENTRA_POLICY_DIGEST),
                (API_OIDC_BINDING_POLICY_ID, OIDC_POLICY_DIGEST),
                (API_SESSION_POLICY_ID, SESSION_POLICY_DIGEST),
            ]
        );
        assert_eq!(set.policy_inventory_digest(), INVENTORY_DIGEST);
        assert!(set.verify_integrity().is_ok());
    }

    #[test]
    fn measured_expected_value_is_the_complete_sorted_effective_inventory() {
        let set = fixture();
        let RuntimeGuardExpectedValue::SecureCookies {
            policies,
            policy_inventory_digest,
        } = set
            .measured_expected_value()
            .expect("the retained policy must measure")
        else {
            panic!("cookie policy must project only the secure-cookies variant");
        };
        assert_eq!(policy_inventory_digest, INVENTORY_DIGEST);
        assert_eq!(
            policies
                .iter()
                .map(|policy| policy.policy_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                API_ENTRA_BINDING_POLICY_ID,
                API_OIDC_BINDING_POLICY_ID,
                API_SESSION_POLICY_ID,
            ]
        );
        assert!(policies.iter().all(|policy| {
            policy.cookie_name.starts_with("__Host-")
                && policy.secure
                && policy.http_only
                && policy.path == "/"
                && policy.domain.is_none()
        }));
    }

    #[test]
    fn factory_retains_one_allocation_and_rejects_invalid_session_lifetimes() {
        let set = fixture();
        let shared = Arc::clone(&set);
        assert!(Arc::ptr_eq(&set, &shared));

        for session_max_age_secs in [0, i64::MAX as u64 + 1] {
            assert_eq!(
                RetainedCookiePolicySet::production_api(ProductionApiCookiePolicyConfig {
                    session_max_age_secs,
                    session_same_site: CookieSameSitePolicy::Lax,
                })
                .unwrap_err(),
                CookiePolicyError::Invalid("session Max-Age must be in 1..=i64::MAX")
            );
        }
    }

    #[test]
    fn only_session_policy_and_inventory_follow_typed_session_configuration() {
        let baseline = fixture();
        let changed = RetainedCookiePolicySet::production_api(ProductionApiCookiePolicyConfig {
            session_max_age_secs: 7_200,
            session_same_site: CookieSameSitePolicy::Strict,
        })
        .expect("strict session policy must be admitted");

        assert_eq!(
            baseline.api_entra_login_binding().policy_digest(),
            changed.api_entra_login_binding().policy_digest()
        );
        assert_eq!(
            baseline.api_oidc_login_binding().policy_digest(),
            changed.api_oidc_login_binding().policy_digest()
        );
        assert_ne!(
            baseline.api_session().policy_digest(),
            changed.api_session().policy_digest()
        );
        assert_ne!(
            baseline.policy_inventory_digest(),
            changed.policy_inventory_digest()
        );
        assert_eq!(
            changed.api_session().same_site(),
            CookieSameSitePolicy::Strict
        );
        assert_eq!(changed.api_session().max_age_secs(), 7_200);
    }

    #[test]
    fn weakened_cookie_shape_cannot_survive_integrity_verification() {
        let mut set = fixture();
        Arc::get_mut(&mut set)
            .expect("fixture has one owner")
            .policies
            .iter_mut()
            .find(|policy| policy.purpose == CookiePurpose::ApiSession)
            .expect("session policy")
            .secure = false;
        assert_eq!(
            set.verify_integrity().unwrap_err(),
            CookiePolicyError::Invalid("production policy must use a canonical __Host- cookie")
        );

        let mut set = fixture();
        Arc::get_mut(&mut set)
            .expect("fixture has one owner")
            .policies[0]
            .domain = Some("example.test".into());
        assert!(set.verify_integrity().is_err());

        let mut set = fixture();
        Arc::get_mut(&mut set)
            .expect("fixture has one owner")
            .policies[1]
            .cookie_name = "oidc_login_csrf".into();
        assert!(set.verify_integrity().is_err());
    }

    #[test]
    fn missing_duplicate_or_reordered_consumers_fail_closed() {
        let mut missing = fixture();
        Arc::get_mut(&mut missing)
            .expect("fixture has one owner")
            .policies[2]
            .issuer_consumers = API_SESSION_ISSUERS[..3].to_vec().into_boxed_slice();
        assert!(missing.verify_integrity().is_err());

        let mut duplicate = fixture();
        Arc::get_mut(&mut duplicate)
            .expect("fixture has one owner")
            .policies[2]
            .parser_consumers = vec![
            CookiePolicyConsumer::ApiSessionAuthParser,
            CookiePolicyConsumer::ApiSessionAuthParser,
        ]
        .into_boxed_slice();
        assert_eq!(
            duplicate.verify_integrity().unwrap_err(),
            CookiePolicyError::Invalid(
                "issuer and parser inventories must be nonempty, sorted, and unique"
            )
        );

        let mut reordered = fixture();
        Arc::get_mut(&mut reordered)
            .expect("fixture has one owner")
            .policies[2]
            .issuer_consumers
            .swap(0, 1);
        assert!(reordered.verify_integrity().is_err());
    }

    #[test]
    fn policy_and_inventory_digest_tampering_fail_independently() {
        let mut policy_tamper = fixture();
        Arc::get_mut(&mut policy_tamper)
            .expect("fixture has one owner")
            .policies[0]
            .policy_digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            policy_tamper.verify_integrity().unwrap_err(),
            CookiePolicyError::Invalid("stored policy digest differs from the effective policy")
        );

        let mut inventory_tamper = fixture();
        Arc::get_mut(&mut inventory_tamper)
            .expect("fixture has one owner")
            .policy_inventory_digest = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            inventory_tamper.verify_integrity().unwrap_err(),
            CookiePolicyError::Invalid(
                "stored inventory digest differs from the effective inventory"
            )
        );
    }

    #[test]
    fn policy_order_and_purpose_identity_are_not_interchangeable() {
        let mut reordered = fixture();
        Arc::get_mut(&mut reordered)
            .expect("fixture has one owner")
            .policies
            .swap(0, 1);
        assert_eq!(
            reordered.verify_integrity().unwrap_err(),
            CookiePolicyError::Invalid(
                "API policy inventory must contain exactly three sorted policies"
            )
        );

        let mut cross_wired = fixture();
        Arc::get_mut(&mut cross_wired)
            .expect("fixture has one owner")
            .policies[0]
            .purpose = CookiePurpose::ApiOidcLoginBinding;
        assert_eq!(
            cross_wired.verify_integrity().unwrap_err(),
            CookiePolicyError::Invalid("policy differs from its closed purpose contract")
        );
    }

    #[test]
    fn non_scalar_policy_material_is_covered_by_the_policy_digest() {
        let set = fixture();
        let session = set.api_session();

        let mut changed_consumers = RetainedCookiePolicy {
            policy_id: session.policy_id.clone(),
            purpose: session.purpose,
            cookie_name: session.cookie_name.clone(),
            secure: session.secure,
            http_only: session.http_only,
            path: session.path.clone(),
            domain: session.domain.clone(),
            same_site: session.same_site,
            lifetime_source: session.lifetime_source,
            max_age_secs: session.max_age_secs,
            value_profile: session.value_profile,
            retired_cookie_names: session.retired_cookie_names.clone(),
            issuer_consumers: session.issuer_consumers.clone(),
            parser_consumers: session.parser_consumers.clone(),
            policy_digest: String::new(),
        };
        changed_consumers.issuer_consumers[0] = CookiePolicyConsumer::ApiOidcBindingIssuer;
        assert_ne!(
            policy_binding_digest(session).unwrap(),
            policy_binding_digest(&changed_consumers).unwrap()
        );

        let mut changed_retirement = changed_consumers;
        changed_retirement.issuer_consumers = session.issuer_consumers.clone();
        changed_retirement.retired_cookie_names = Vec::new().into_boxed_slice();
        assert_ne!(
            policy_binding_digest(session).unwrap(),
            policy_binding_digest(&changed_retirement).unwrap()
        );
    }
}
