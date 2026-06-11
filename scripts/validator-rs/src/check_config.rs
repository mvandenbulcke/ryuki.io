use ryuki_core::config::RyukiConfig;

pub fn run() {
    println!("=== Ryuki Platform Config Validation ===\n");

    match RyukiConfig::load() {
        Ok(config) => {
            println!("[OK] Configuration loaded successfully\n");

            println!("Server:");
            println!("  bind_address: {}", config.server.bind_address);
            println!("  shutdown_timeout_secs: {}", config.server.shutdown_timeout_secs);
            println!("  request_timeout_secs: {}", config.server.request_timeout_secs);
            println!();

            println!("Platform:");
            println!("  name: {}", config.platform_name);
            println!("  url: {}", config.platform_url);
            println!("  auth_mode: {:?}", config.auth_mode);
            println!();

            println!("Providers:");
            println!("  database: {:?}", config.database_provider);
            println!("  secret: {:?}", config.secret_provider);
            println!("  kubernetes: {:?}", config.kubernetes_runtime);
            println!("  monitoring: {:?}", config.monitoring_provider);
            println!("  backup: {:?}", config.backup_provider);
            println!();

            println!("Rate Limit:");
            println!("  enabled: {}", config.rate_limit.enabled);
            if config.rate_limit.enabled {
                println!("  requests_per_second: {}", config.rate_limit.requests_per_second);
                println!("  burst_size: {}", config.rate_limit.burst_size);
            }
            println!();

            println!("Logging:");
            println!("  level: {:?}", config.logging.level);
            println!("  format: {:?}", config.logging.format);
            println!();

            let validation_errors = config.validate();
            if validation_errors.is_empty() {
                println!("[OK] Config validation passed");
                println!("\nStatus: VALID");
                std::process::exit(0);
            } else {
                println!("[FAIL] Config validation errors:");
                for err in &validation_errors {
                    println!("  - {err}");
                }
                println!("\nStatus: INVALID");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("[FAIL] Failed to load configuration: {e}");
            eprintln!("\nStatus: ERROR");
            std::process::exit(1);
        }
    }
}
