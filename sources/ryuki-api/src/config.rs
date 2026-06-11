use ryuki_core::config::RyukiConfig;

pub fn load_config() -> RyukiConfig {
    match RyukiConfig::load() {
        Ok(config) => {
            let validation_errors = config.validate();
            if !validation_errors.is_empty() {
                eprintln!("Configuration validation warnings:");
                for error in &validation_errors {
                    eprintln!("  - {error}");
                }
            }
            config
        }
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            eprintln!("Falling back to default configuration");
            RyukiConfig::default()
        }
    }
}

pub fn get_platform_status() -> serde_json::Value {
    let config = crate::config_store::get_app_config();
    let validation_errors = config.validate();
    serde_json::json!({
        "platform_name": config.platform_name,
        "platform_url": config.platform_url,
        "auth_mode": config.auth_mode.as_str(),
        "entra_authority": config.entra_authority,
        "entra_configured": !config.entra_tenant_id.is_empty(),
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
            "tls_enabled": config.server.tls_cert_path.is_some(),
        },
        "rate_limit": {
            "enabled": config.rate_limit.enabled,
            "requests_per_second": config.rate_limit.requests_per_second,
            "burst_size": config.rate_limit.burst_size,
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
        "smtp": {
            "enabled": config.smtp.enabled,
            "host": config.smtp.host,
            "port": config.smtp.port,
            "from_address": config.smtp.from_address,
            "use_tls": config.smtp.use_tls,
        },
        "session": {
            "cookie_max_age_secs": config.session.cookie_max_age_secs,
            "cookie_secure": config.session.cookie_secure,
            "cookie_http_only": config.session.cookie_http_only,
            "cookie_same_site": config.session.cookie_same_site,
        },
        "validation_errors": validation_errors,
    })
}
