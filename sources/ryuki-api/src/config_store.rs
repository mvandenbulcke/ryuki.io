use ryuki_core::config::RyukiConfig;
use ryuki_core::types::PlatformConfig;
use std::path::Path;
use std::sync::OnceLock;
use tokio::sync::Mutex;

static STORE: OnceLock<Mutex<ConfigStore>> = OnceLock::new();
static APP_CONFIG: OnceLock<RyukiConfig> = OnceLock::new();

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

    pub fn load_config(&self) -> Result<PlatformConfig, String> {
        let mut config = PlatformConfig::default();

        if let Some(app_cfg) = APP_CONFIG.get() {
            config.entra_tenant_id = app_cfg.entra_tenant_id.clone();
            config.entra_client_id = app_cfg.entra_client_id.clone();
            config.entra_authority = app_cfg.entra_authority.clone();
            config.auth_mode = app_cfg.auth_mode.as_str().to_string();
            config.platform_name = app_cfg.platform_name.clone();
            config.platform_url = app_cfg.platform_url.clone();
        }

        if Path::new(&self.path).exists() {
            let contents = std::fs::read_to_string(&self.path)
                .map_err(|e| format!("failed to read config file: {e}"))?;
            let file_config = serde_json::from_str::<PlatformConfig>(&contents)
                .map_err(|e| format!("failed to parse config file: {e}"))?;
            return Ok(file_config);
        }

        Ok(config)
    }

    pub fn save_config(&self, config: &PlatformConfig) -> Result<(), String> {
        let contents = serde_json::to_string_pretty(config)
            .map_err(|e| format!("failed to serialize config: {e}"))?;
        std::fs::write(&self.path, contents)
            .map_err(|e| format!("failed to write config file: {e}"))
    }
}

pub fn init_with_config(path: &str, app_cfg: &RyukiConfig) {
    let _ = APP_CONFIG.set(app_cfg.clone());
    let store = ConfigStore::new(path);
    STORE
        .set(Mutex::new(store))
        .expect("config store already initialized");
}

pub fn get_app_config() -> &'static RyukiConfig {
    APP_CONFIG.get().expect("app config not initialized")
}

pub async fn load_config() -> Result<PlatformConfig, String> {
    let store = STORE.get().expect("config store not initialized");
    store.lock().await.load_config()
}

pub async fn save_config(config: &PlatformConfig) -> Result<(), String> {
    let store = STORE.get().expect("config store not initialized");
    store.lock().await.save_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config_path() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("ryuki-platform-config-{nanos}.json"))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn test_load_config_reads_full_file_config() {
        let path = temp_config_path();
        let expected = PlatformConfig {
            storage_provider: "netapp".to_string(),
            retention_daily_backups: 45,
            max_concurrent_connections: 1024,
            ..Default::default()
        };
        std::fs::write(&path, serde_json::to_string(&expected).unwrap()).unwrap();

        let store = ConfigStore::new(&path);
        let loaded = store.load_config().expect("config file should load");
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.storage_provider, "netapp");
        assert_eq!(loaded.retention_daily_backups, 45);
        assert_eq!(loaded.max_concurrent_connections, 1024);
    }

    #[test]
    fn test_load_config_returns_error_for_invalid_file_config() {
        let path = temp_config_path();
        std::fs::write(&path, "{not-json").unwrap();

        let store = ConfigStore::new(&path);
        let result = store.load_config();
        let _ = std::fs::remove_file(&path);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse config file"));
    }
}
