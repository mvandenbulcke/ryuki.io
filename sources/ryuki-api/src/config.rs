#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub entra_tenant_id: String,
    pub entra_client_id: String,
    pub entra_authority: String,
    pub platform_name: String,
    pub platform_url: String,
    pub auth_mode: String,
    pub api_bind_addr: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database_url: "postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform".to_string(),
            entra_tenant_id: String::new(),
            entra_client_id: String::new(),
            entra_authority: "https://login.microsoftonline.com".to_string(),
            platform_name: "Ryuki Infrastructure Platform".to_string(),
            platform_url: "http://localhost:18080".to_string(),
            auth_mode: "mock-dry-run".to_string(),
            api_bind_addr: "0.0.0.0:8080".to_string(),
        }
    }
}

pub fn load() -> AppConfig {
    let mut config = AppConfig::default();

    if let Ok(v) = std::env::var("DATABASE_URL") {
        config.database_url = v;
    }
    if let Ok(v) = std::env::var("ENTRA_TENANT_ID") {
        config.entra_tenant_id = v;
    }
    if let Ok(v) = std::env::var("ENTRA_CLIENT_ID") {
        config.entra_client_id = v;
    }
    if let Ok(v) = std::env::var("ENTRA_AUTHORITY") {
        config.entra_authority = v;
    }
    if let Ok(v) = std::env::var("PLATFORM_NAME") {
        config.platform_name = v;
    }
    if let Ok(v) = std::env::var("PLATFORM_URL") {
        config.platform_url = v;
    }
    if let Ok(v) = std::env::var("AUTH_MODE") {
        config.auth_mode = v;
    }
    if let Ok(v) = std::env::var("API_BIND_ADDR") {
        config.api_bind_addr = v;
    }

    config
}
