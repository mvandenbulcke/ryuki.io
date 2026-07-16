use ryuki_core::config::{AuthMode, RyukiConfig};

/// Load and validate the startup configuration.
///
/// Configuration is a security boundary: parse and validation failures must
/// stop startup instead of silently selecting permissive development defaults.
pub fn load_config() -> Result<RyukiConfig, String> {
    let config =
        RyukiConfig::load().map_err(|error| format!("failed to load configuration: {error}"))?;
    validate_loaded_config(config)
}

/// Applies every process-startup validation step to one already parsed
/// configuration. Keeping this separate from environment/file loading makes
/// the fail-closed startup boundary directly testable.
fn validate_loaded_config(config: RyukiConfig) -> Result<RyukiConfig, String> {
    validate_loaded_config_with_secret_validation(
        config,
        crate::integration::validate_secret_manager_startup,
    )
}

fn validate_loaded_config_with_secret_validation(
    config: RyukiConfig,
    validate_secret_manager: impl FnOnce(&RyukiConfig) -> Result<(), String>,
) -> Result<RyukiConfig, String> {
    let validation_errors = config.validate();
    if !validation_errors.is_empty() {
        return Err(format!(
            "configuration validation failed:\n  - {}",
            validation_errors.join("\n  - ")
        ));
    }

    // Provider credentials and endpoints are process-owned configuration, not
    // ordinary request data. Reject partial, mismatched, or unsafe transport
    // state before any listener is opened; dependent operations still fail
    // closed when the provider is intentionally left entirely unconfigured.
    validate_secret_manager(&config)?;

    validate_identity_endpoints(&config)?;

    let validation_warnings = config.validation_warnings();
    if !validation_warnings.is_empty() {
        eprintln!("Configuration validation warnings:");
        for warning in &validation_warnings {
            eprintln!("  - {warning}");
        }
    }

    Ok(config)
}

fn validate_identity_endpoint(label: &str, raw: &str) -> Result<url::Url, String> {
    crate::oidc_callback::parse_identity_endpoint(raw)
        .map_err(|reason| format!("{label} is not an admitted identity endpoint ({reason})"))
}

/// Close the startup-to-runtime gap for browser authorization URLs as well as
/// the token and JWKS clients. Constructors may then safely assume that every
/// enabled identity endpoint has passed the same transport policy.
fn validate_identity_endpoints(config: &RyukiConfig) -> Result<(), String> {
    if config.oidc.enabled {
        let issuer = validate_identity_endpoint("oidc.issuer", &config.oidc.issuer)?;
        if issuer.query().is_some() {
            return Err("oidc.issuer must not contain a query".into());
        }
        for (label, endpoint) in [
            (
                "oidc.authorize_endpoint",
                config.oidc.authorize_endpoint.as_str(),
            ),
            ("oidc.token_endpoint", config.oidc.token_endpoint.as_str()),
            ("oidc.jwks_uri", config.oidc.jwks_uri.as_str()),
            ("oidc.redirect_uri", config.oidc.redirect_uri.as_str()),
        ] {
            validate_identity_endpoint(label, endpoint)?;
        }
    }

    if config.auth_mode == AuthMode::EntraId {
        let authority = validate_identity_endpoint("entra_authority", &config.entra_authority)?;
        if authority.query().is_some() {
            return Err("entra_authority must not contain a query".into());
        }
        if !config.entra_redirect_uri.is_empty() {
            validate_identity_endpoint("entra_redirect_uri", &config.entra_redirect_uri)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod startup_validation_tests {
    use super::*;

    fn validate_test_config(config: RyukiConfig) -> Result<RyukiConfig, String> {
        // Identity/cookie tests are pure and must not depend on an operator's
        // ambient VAULT_* process environment. Secret-manager snapshots have
        // dedicated pure tests in integration.rs.
        validate_loaded_config_with_secret_validation(config, |_| Ok(()))
    }

    fn configured_oidc() -> RyukiConfig {
        let mut config = RyukiConfig::default();
        config.oidc.enabled = true;
        config.oidc.issuer = "https://identity.example.test".into();
        config.oidc.authorize_endpoint = "https://identity.example.test/authorize".into();
        config.oidc.token_endpoint = "https://identity.example.test/token".into();
        config.oidc.jwks_uri = "https://identity.example.test/jwks".into();
        config.oidc.redirect_uri = "https://portal.example.test/api/auth/oidc/callback".into();
        config.oidc.client_id = "client".into();
        config.oidc.client_secret = "x".repeat(32);
        config.session.credential_hmac_key = "x".repeat(32);
        config
    }

    fn configured_local(platform_url: &str, cookie_secure: bool) -> RyukiConfig {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::Local,
            platform_url: platform_url.into(),
            ..Default::default()
        };
        // Placeholder credential for tests only; never a runtime secret.
        config.local_auth = serde_json::from_value(serde_json::json!({
            "users": "operator:placeholder-pass-1:PlatformAdmin",
            "site_authority": "global",
            "environment_authority": "global"
        }))
        .expect("placeholder local-auth config should parse");
        config.session.cookie_secure = cookie_secure;
        config.session.credential_hmac_key = "x".repeat(32);
        config
    }

    #[test]
    fn identity_endpoint_validation_rejects_each_remote_cleartext_oidc_url() {
        for label in [
            "oidc.issuer",
            "oidc.authorize_endpoint",
            "oidc.token_endpoint",
            "oidc.jwks_uri",
            "oidc.redirect_uri",
        ] {
            let mut config = configured_oidc();
            let cleartext = format!(
                "http://identity.example.test/{}",
                label.trim_start_matches("oidc.").replace('_', "-")
            );
            match label {
                "oidc.issuer" => config.oidc.issuer = cleartext,
                "oidc.authorize_endpoint" => config.oidc.authorize_endpoint = cleartext,
                "oidc.token_endpoint" => config.oidc.token_endpoint = cleartext,
                "oidc.jwks_uri" => config.oidc.jwks_uri = cleartext,
                "oidc.redirect_uri" => config.oidc.redirect_uri = cleartext,
                _ => unreachable!("closed OIDC endpoint manifest"),
            }

            let error = validate_identity_endpoints(&config).unwrap_err();
            assert!(error.contains(label), "wrong field in error: {error}");
            assert!(error.contains("https-required"), "wrong policy: {error}");
        }
    }

    #[test]
    fn identity_endpoint_validation_rejects_query_bearing_issuer() {
        let mut config = configured_oidc();
        config.oidc.issuer = "https://identity.example.test/issuer?alternate=tenant".into();
        assert_eq!(
            validate_identity_endpoints(&config).unwrap_err(),
            "oidc.issuer must not contain a query"
        );
    }

    #[test]
    fn identity_endpoint_validation_covers_entra_authority_and_redirect() {
        let mut config = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            entra_tenant_id: "synthetic-tenant".into(),
            entra_client_id: "synthetic-client".into(),
            entra_authority: "https://login.example.test?alternate=host".into(),
            entra_redirect_uri: "https://portal.example.test/api/auth/entra/callback".into(),
            ..Default::default()
        };
        assert_eq!(
            validate_identity_endpoints(&config).unwrap_err(),
            "entra_authority must not contain a query"
        );

        config.entra_authority = "https://login.example.test".into();
        config.entra_redirect_uri = "http://portal.example.test/api/auth/entra/callback".into();
        let error = validate_identity_endpoints(&config).unwrap_err();
        assert!(error.contains("entra_redirect_uri"));
        assert!(error.contains("https-required"));
    }

    #[test]
    fn identity_endpoint_validation_accepts_distinct_secure_hosts() {
        let mut config = configured_oidc();
        config.oidc.authorize_endpoint = "https://authorize.example.test/login".into();
        config.oidc.token_endpoint = "https://tokens.example.test/exchange".into();
        config.oidc.jwks_uri = "https://keys.example.test/jwks".into();
        assert!(validate_identity_endpoints(&config).is_ok());
    }

    #[test]
    fn startup_rejects_insecure_cookie_for_https_public_origin() {
        let mut config = RyukiConfig {
            platform_url: "https://platform.example.test".into(),
            ..Default::default()
        };
        config.session.cookie_secure = false;

        let error = validate_test_config(config).unwrap_err();
        assert!(error.contains("session.cookie_secure"));
        assert!(error.contains("non-loopback public origins"));
    }

    #[test]
    fn startup_rejects_insecure_cookie_for_remote_http_public_origin() {
        let mut config = RyukiConfig {
            platform_url: "http://platform.example.test".into(),
            ..Default::default()
        };
        config.session.cookie_secure = false;

        let error = validate_test_config(config).unwrap_err();
        assert!(error.contains("session.cookie_secure"));
    }

    #[test]
    fn startup_rejects_insecure_cookie_for_secure_browser_callbacks() {
        let mut oidc = configured_oidc();
        oidc.session.cookie_secure = false;
        let error = validate_test_config(oidc).unwrap_err();
        assert!(error.contains("oidc.redirect_uri"));
        assert!(error.contains("cookie_secure=false"));

        let mut entra = RyukiConfig {
            auth_mode: AuthMode::EntraId,
            entra_tenant_id: "configured".into(),
            entra_client_id: "configured".into(),
            entra_redirect_uri: "https://portal.example.test/api/auth/entra/callback".into(),
            ..Default::default()
        };
        entra.session.cookie_secure = false;
        entra.session.credential_hmac_key = "x".repeat(32);
        let error = validate_test_config(entra).unwrap_err();
        assert!(error.contains("entra_redirect_uri"));
        assert!(error.contains("cookie_secure=false"));
    }

    #[test]
    fn startup_accepts_explicit_loopback_http_cookie_mode() {
        for platform_url in [
            "http://localhost:18080",
            "http://127.0.0.1:18080",
            "http://[::1]:18080",
        ] {
            let mut config = configured_local(platform_url, false);
            // Container processes commonly bind the bridge interface while
            // the published browser origin remains loopback-only.
            config.server.bind_address = "0.0.0.0:8080".into();

            assert!(
                validate_test_config(config).is_ok(),
                "loopback development origin should be admitted: {platform_url}"
            );
        }
    }

    #[test]
    fn startup_accepts_secure_public_origin_behind_plain_internal_listener() {
        let mut config = configured_local("https://platform.example.test", true);
        // TLS may terminate at the trusted ingress; cookie policy follows the
        // browser-visible origin, not this internal listener address.
        config.server.bind_address = "0.0.0.0:8080".into();
        assert!(validate_test_config(config).is_ok());
    }
}

fn is_entra_configured(tenant_id: &str, client_id: &str) -> bool {
    !tenant_id.is_empty() && !client_id.is_empty()
}

fn is_tls_configured(cert_path: &Option<String>, key_path: &Option<String>) -> bool {
    cert_path.is_some() && key_path.is_some()
}

pub fn get_platform_status() -> serde_json::Value {
    let config = crate::config_store::get_app_config();
    let validation_errors = config.validate();
    let validation_warnings = config.validation_warnings();
    let entra_tenant_configured = !config.entra_tenant_id.is_empty();
    let entra_client_configured = !config.entra_client_id.is_empty();
    let tls_configured =
        is_tls_configured(&config.server.tls_cert_path, &config.server.tls_key_path);
    serde_json::json!({
        "platform_name": config.platform_name,
        "platform_url": config.platform_url,
        "auth_mode": config.auth_mode.as_str(),
        "entra_authority": config.entra_authority,
        "entra_configured": is_entra_configured(&config.entra_tenant_id, &config.entra_client_id),
        "entra_tenant_configured": entra_tenant_configured,
        "entra_client_configured": entra_client_configured,
        "database": {
            "url": "[redacted]",
            "provider": config.database_provider.as_str(),
            "connected": crate::database::get_db().is_some(),
        },
        "providers": {
            "secret": config.secret_provider.as_str(),
            "kubernetes": config.kubernetes_runtime.as_str(),
            "hypervisor": config.hypervisor_provider.as_str(),
            "monitoring": config.monitoring_provider.as_str(),
            "backup": config.backup_provider.as_str(),
            "storage": config.storage_provider.as_str(),
            "dns": config.dns_provider.as_str(),
            "ipam": config.ipam_provider.as_str(),
            "load_balancer": config.load_balancer_provider.as_str(),
            "firewall": config.firewall_provider.as_str(),
            "build": config.build_provider.as_str(),
            "network": config.network_provider.as_str(),
        },
        "server": {
            "bind_address": config.server.bind_address,
            "shutdown_timeout_secs": config.server.shutdown_timeout_secs,
            "request_timeout_secs": config.server.request_timeout_secs,
            "max_body_size_bytes": config.server.max_body_size_bytes,
            "pool_max_connections": config.server.pool_max_connections,
            "pool_min_connections": config.server.pool_min_connections,
            "pool_idle_timeout_secs": config.server.pool_idle_timeout_secs,
            "pool_acquire_timeout_secs": config.server.pool_acquire_timeout_secs,
            "pool_max_lifetime_secs": config.server.pool_max_lifetime_secs,
            "compression_quality": config.server.compression_quality,
            "keep_alive_timeout_secs": config.server.keep_alive_timeout_secs,
            "max_concurrent_connections": config.server.max_concurrent_connections,
            "tls_configured": tls_configured,
            "tls_enabled": false,
            "tls_runtime": "plain-http",
        },
        "rate_limit": {
            "enabled": config.rate_limit.enabled,
            "requests_per_second": config.rate_limit.requests_per_second,
            "burst_size": config.rate_limit.burst_size,
            "path_overrides_enforced": true,
            "path_overrides": config.rate_limit.path_overrides.iter().map(|(path, ov)| {
                (path.clone(), serde_json::json!({
                    "requests_per_second": ov.requests_per_second,
                    "burst_size": ov.burst_size,
                }))
            }).collect::<serde_json::Map<String, serde_json::Value>>(),
        },
        "cors": {
            "allowed_origins": config.cors.allowed_origins,
            "max_age_secs": config.cors.max_age_secs,
        },
        "logging": {
            "level": format!("{:?}", config.logging.level),
            "format": format!("{:?}", config.logging.format),
        },
        "security": {
            "csp": config.security.content_security_policy,
            "hsts_enabled": config.security.hsts_enabled,
            "hsts_max_age_secs": config.security.hsts_max_age_secs,
        },
        "security_limits": {
            "session_lookup_admission":
                crate::session_lookup_admission::security_limit_readback(
                    config.server.pool_max_connections,
                ),
        },
        "smtp": {
            "enabled": config.smtp.enabled,
            "host": config.smtp.host,
            "port": config.smtp.port,
            "from_address": config.smtp.from_address,
            "use_tls": config.smtp.use_tls,
        },
        "log_extended": {
            "file_path": config.log_extended.file_path,
            "retention_days": config.log_extended.retention_days,
        },
        "session": {
            "cookie_max_age_secs": config.session.cookie_max_age_secs,
            "federated_authority_max_staleness_secs": config.session.federated_authority_max_staleness_secs,
            "cookie_secure": config.session.cookie_secure,
            "cookie_http_only": config.session.cookie_http_only,
            "cookie_same_site": config.session.cookie_same_site,
        },
        "retention": {
            "daily_backups": config.retention.daily_backups,
            "weekly_backups": config.retention.weekly_backups,
            "monthly_backups": config.retention.monthly_backups,
            "yearly_backups": config.retention.yearly_backups,
        },
        "maintenance_window": {
            "enabled": config.maintenance_window.enabled,
            "day_of_week": config.maintenance_window.day_of_week,
            "start_hour_utc": config.maintenance_window.start_hour_utc,
            "duration_hours": config.maintenance_window.duration_hours,
        },
        "validation_errors": validation_errors,
        "validation_warnings": validation_warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_status_includes_value_free_session_lookup_limit_readback() {
        let mut config = RyukiConfig::default();
        config.server.pool_max_connections = 5;
        crate::config_store::init_with_config(
            "/tmp/ryuki-unused-session-limit-readback-test.json",
            &config,
        );

        let status = get_platform_status();
        let limits = &status["security_limits"]["session_lookup_admission"];
        assert_eq!(
            limits["profile_version"].as_str(),
            Some("session-lookup-v1")
        );
        assert_eq!(limits["unknown_lookup"]["selected_slots"].as_u64(), Some(4));
        assert_eq!(
            limits["unknown_lookup"]["selected_miss_budget"].as_u64(),
            Some(32)
        );
        let projection = limits.to_string();
        for prohibited in ["verifier", "bearer", "cache_occupancy", "prewarm_loaded"] {
            assert!(!projection.contains(prohibited));
        }
    }

    #[test]
    fn test_entra_configured_requires_tenant_and_client() {
        assert!(!is_entra_configured("tenant", ""));
        assert!(!is_entra_configured("", "client"));
        assert!(is_entra_configured("tenant", "client"));
    }

    #[test]
    fn test_tls_configured_requires_cert_and_key() {
        let cert = Some("/tmp/server.crt".to_string());
        let key = Some("/tmp/server.key".to_string());
        assert!(!is_tls_configured(&cert, &None));
        assert!(!is_tls_configured(&None, &key));
        assert!(is_tls_configured(&cert, &key));
    }
}
