//! Startup-only checks that couple the browser-visible portal posture to the
//! independently configured platform API.
#![cfg(feature = "ssr")]

use crate::api::platform_summary_path;
use crate::models::ApiPlatformSummary;
use crate::security::{PortalConfigError, PortalPublicOrigin};
use crate::upstream::{UpstreamClient, UpstreamResponse, EXECUTION_MODE_ENV};
use ryuki_core::config::AuthMode;

fn requires_auth_posture_preflight(live: bool, public_origin: &PortalPublicOrigin) -> bool {
    live && !public_origin.is_loopback()
}

fn validate_bootstrap_auth_mode(auth_mode: &str) -> Result<(), PortalConfigError> {
    let auth_mode = auth_mode.trim().to_ascii_lowercase();
    if auth_mode.is_empty() {
        return Err(PortalConfigError::new(
            EXECUTION_MODE_ENV,
            "live-provider startup could not verify the upstream authentication mode",
        ));
    }
    if AuthMode::parse(&auth_mode).is_some_and(|mode| mode.is_credential_free()) {
        return Err(PortalConfigError::new(
            EXECUTION_MODE_ENV,
            "live-provider on a non-loopback public origin rejects credential-free upstream authentication",
        ));
    }
    Ok(())
}

fn validate_bootstrap_response(response: &UpstreamResponse) -> Result<(), PortalConfigError> {
    if !response.is_success() {
        return Err(PortalConfigError::new(
            EXECUTION_MODE_ENV,
            "live-provider startup could not read the upstream authentication bootstrap",
        ));
    }
    let summary: ApiPlatformSummary = response.json().map_err(|_| {
        PortalConfigError::new(
            EXECUTION_MODE_ENV,
            "live-provider startup received a malformed upstream authentication bootstrap",
        )
    })?;
    validate_bootstrap_auth_mode(&summary.local_authorization.authentication_mode)
}

/// Before an externally visible live portal begins serving, read the existing
/// public bootstrap contract and reject credential-free API authority. The
/// explicitly local loopback demo remains available, while an unreachable,
/// non-successful, or malformed bootstrap response fails closed.
pub async fn validate_live_provider_auth_posture(
    upstream: &UpstreamClient,
    public_origin: &PortalPublicOrigin,
) -> Result<(), PortalConfigError> {
    if !requires_auth_posture_preflight(upstream.live(), public_origin) {
        return Ok(());
    }

    let response = upstream
        .get(platform_summary_path(), None)
        .await
        .map_err(|_| {
            PortalConfigError::new(
                EXECUTION_MODE_ENV,
                "live-provider startup could not reach the upstream authentication bootstrap",
            )
        })?;
    validate_bootstrap_response(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn external_origin() -> PortalPublicOrigin {
        PortalPublicOrigin::parse("https://portal.example.test", false).unwrap()
    }

    fn loopback_origin() -> PortalPublicOrigin {
        PortalPublicOrigin::parse("http://127.0.0.1:18000", true).unwrap()
    }

    fn bootstrap_response(auth_mode: &str) -> UpstreamResponse {
        UpstreamResponse {
            status: 200,
            body: serde_json::json!({
                "productName": "Ryuki Infrastructure Platform",
                "localAuthorization": {"authenticationMode": auth_mode}
            })
            .to_string(),
            total_count: None,
        }
    }

    #[test]
    fn external_live_portal_requires_auth_posture_preflight() {
        assert!(requires_auth_posture_preflight(true, &external_origin()));
        assert!(!requires_auth_posture_preflight(false, &external_origin()));
    }

    #[test]
    fn loopback_live_portal_preserves_the_local_dry_run_demo() {
        assert!(!requires_auth_posture_preflight(true, &loopback_origin()));
        assert!(validate_bootstrap_auth_mode("mock-dry-run").is_err());
        assert!(validate_bootstrap_auth_mode("static-dry-run").is_err());
    }

    #[test]
    fn external_live_portal_rejects_only_credential_free_modes() {
        for mode in ["mock-dry-run", "static-dry-run", "", "   "] {
            assert!(
                validate_bootstrap_response(&bootstrap_response(mode)).is_err(),
                "unsafe or unverifiable mode {mode:?} must fail closed"
            );
        }
        for mode in ["local", "entra-id", "oidc", "provider-registry-v2"] {
            assert!(
                validate_bootstrap_response(&bootstrap_response(mode)).is_ok(),
                "credentialed provider-neutral mode {mode:?} must remain supported"
            );
        }
    }

    #[test]
    fn external_live_portal_fails_closed_on_unusable_bootstrap_contract() {
        let non_success = UpstreamResponse {
            status: 401,
            body: "{}".to_string(),
            total_count: None,
        };
        let malformed = UpstreamResponse {
            status: 200,
            body: r#"{"productName":"Ryuki Infrastructure Platform"}"#.to_string(),
            total_count: None,
        };
        assert!(validate_bootstrap_response(&non_success).is_err());
        assert!(validate_bootstrap_response(&malformed).is_err());
    }
}
