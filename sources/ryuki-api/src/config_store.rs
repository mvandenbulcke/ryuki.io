use ryuki_core::types::PlatformConfig;
use std::path::Path;
use std::sync::OnceLock;
use tokio::sync::Mutex;

static STORE: OnceLock<Mutex<ConfigStore>> = OnceLock::new();
static APP_CONFIG: OnceLock<crate::config::AppConfig> = OnceLock::new();

#[derive(Debug)]
pub struct ConfigStore {
    path: String,
}

impl ConfigStore {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    pub fn load_config(&self) -> PlatformConfig {
        let mut config = PlatformConfig::default();

        if let Some(app_cfg) = APP_CONFIG.get() {
            config.entra_tenant_id = app_cfg.entra_tenant_id.clone();
            config.entra_client_id = app_cfg.entra_client_id.clone();
            config.entra_authority = app_cfg.entra_authority.clone();
            config.auth_mode = app_cfg.auth_mode.clone();
            config.platform_name = app_cfg.platform_name.clone();
            config.platform_url = app_cfg.platform_url.clone();
        }

        if Path::new(&self.path).exists() {
            if let Ok(contents) = std::fs::read_to_string(&self.path) {
                if let Ok(file_config) = serde_json::from_str::<PlatformConfig>(&contents) {
                    if !file_config.entra_tenant_id.is_empty() {
                        config.entra_tenant_id = file_config.entra_tenant_id;
                    }
                    if !file_config.entra_client_id.is_empty() {
                        config.entra_client_id = file_config.entra_client_id;
                    }
                    if !file_config.entra_authority.is_empty() {
                        config.entra_authority = file_config.entra_authority;
                    }
                    if !file_config.auth_mode.is_empty() {
                        config.auth_mode = file_config.auth_mode;
                    }
                }
            }
        }

        config
    }

    pub fn save_config(&self, config: &PlatformConfig) -> Result<(), String> {
        let contents = serde_json::to_string_pretty(config)
            .map_err(|e| format!("failed to serialize config: {e}"))?;
        std::fs::write(&self.path, contents)
            .map_err(|e| format!("failed to write config file: {e}"))
    }
}

pub fn init_with_config(path: &str, app_cfg: &crate::config::AppConfig) {
    let _ = APP_CONFIG.set(app_cfg.clone());
    let store = ConfigStore::new(path);
    STORE
        .set(Mutex::new(store))
        .expect("config store already initialized");
}

pub fn get_app_config() -> &'static crate::config::AppConfig {
    APP_CONFIG.get().expect("app config not initialized")
}

pub async fn load_config() -> PlatformConfig {
    let store = STORE.get().expect("config store not initialized");
    store.lock().await.load_config()
}

pub async fn save_config(config: &PlatformConfig) -> Result<(), String> {
    let store = STORE.get().expect("config store not initialized");
    store.lock().await.save_config(config)
}
