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
            "provider": format!("{:?}", config.database_provider),
            "connected": crate::database::get_db().is_some(),
        },
        "providers": {
            "secret": format!("{:?}", config.secret_provider),
            "kubernetes": format!("{:?}", config.kubernetes_runtime),
            "monitoring": format!("{:?}", config.monitoring_provider),
            "backup": format!("{:?}", config.backup_provider),
        },
        "server": {
            "bind_address": config.server.bind_address,
            "shutdown_timeout_secs": config.server.shutdown_timeout_secs,
        },
        "rate_limit": {
            "enabled": config.rate_limit.enabled,
            "requests_per_second": config.rate_limit.requests_per_second,
            "burst_size": config.rate_limit.burst_size,
        },
        "cors": {
            "allowed_origins": config.cors.allowed_origins,
        },
        "logging": {
            "level": format!("{:?}", config.logging.level),
            "format": format!("{:?}", config.logging.format),
        },
        "validation_errors": validation_errors,
    })
}
