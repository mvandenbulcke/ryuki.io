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
    let config = load_config();
    let validation_errors = config.validate();
    serde_json::json!({
        "platform_name": config.platform_name,
        "auth_mode": config.auth_mode.as_str(),
        "database_provider": format!("{:?}", config.database_provider),
        "secret_provider": format!("{:?}", config.secret_provider),
        "kubernetes_runtime": format!("{:?}", config.kubernetes_runtime),
        "monitoring_provider": format!("{:?}", config.monitoring_provider),
        "backup_provider": format!("{:?}", config.backup_provider),
        "logging_level": format!("{:?}", config.logging.level),
        "rate_limit_enabled": config.rate_limit.enabled,
        "validation_errors": validation_errors,
    })
}
