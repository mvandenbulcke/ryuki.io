use ryuki_core::config::RyukiConfig;
use ryuki_core::types::PlatformConfig;
use std::path::Path;
use std::sync::Arc;
#[cfg(not(test))]
use std::sync::OnceLock;
use tokio::sync::Mutex;

#[cfg(not(test))]
static STORE: OnceLock<Mutex<ConfigStore>> = OnceLock::new();
#[cfg(not(test))]
static STARTUP_CONFIG: OnceLock<ImmutableStartupConfig> = OnceLock::new();

/// The immutable configuration admitted before startup side effects begin.
///
/// Keeping the application configuration and its validated security contract
/// in the same value prevents consumers from observing a configuration that
/// was initialized without the contract that authorized it.
#[cfg(not(test))]
struct ImmutableStartupConfig {
    app_config: RyukiConfig,
    security_contract: crate::security_contracts::SecurityContractContext,
    api_cookie_runtime: Arc<crate::cookie_runtime::ApiCookieRuntime>,
    api_authenticator_runtime: Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
}

// Existing unit tests initialize only the application configuration. Keep
// that compatibility isolated to test builds: production construction always
// requires a validated security contract.
#[cfg(test)]
struct ImmutableStartupConfig {
    app_config: RyukiConfig,
    security_contract: Option<crate::security_contracts::SecurityContractContext>,
    api_cookie_runtime: Arc<crate::cookie_runtime::ApiCookieRuntime>,
    api_authenticator_runtime: Option<Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>>,
}

#[cfg(test)]
thread_local! {
    // Auth-mode tests require different immutable startup configurations. A
    // process-global OnceLock makes the first test silently dictate every later
    // test's mode, so test builds scope the paired value to the Rust test thread.
    // The small fixtures are leaked intentionally: callers receive `static`
    // references, and repeated initialization must never invalidate one.
    static TEST_STORE: std::cell::RefCell<Option<&'static Mutex<ConfigStore>>> = const {
        std::cell::RefCell::new(None)
    };
    static TEST_STARTUP_CONFIG: std::cell::RefCell<Option<&'static ImmutableStartupConfig>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(not(test))]
fn startup_config_if_initialized() -> Option<&'static ImmutableStartupConfig> {
    STARTUP_CONFIG.get()
}

#[cfg(test)]
fn startup_config_if_initialized() -> Option<&'static ImmutableStartupConfig> {
    TEST_STARTUP_CONFIG.with(|slot| *slot.borrow())
}

fn app_config_if_initialized() -> Option<&'static RyukiConfig> {
    startup_config_if_initialized().map(|config| &config.app_config)
}

#[cfg(not(test))]
fn config_store() -> &'static Mutex<ConfigStore> {
    STORE.get().expect("config store not initialized")
}

#[cfg(test)]
fn config_store() -> &'static Mutex<ConfigStore> {
    TEST_STORE.with(|slot| slot.borrow().expect("config store not initialized"))
}

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

        if let Some(app_cfg) = app_config_if_initialized() {
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

#[cfg(not(test))]
pub fn init_with_security_contract(
    path: &str,
    app_cfg: &RyukiConfig,
    security_contract: crate::security_contracts::SecurityContractContext,
    api_cookie_runtime: Arc<crate::cookie_runtime::ApiCookieRuntime>,
    api_authenticator_runtime: Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
) {
    STARTUP_CONFIG
        .set(ImmutableStartupConfig {
            app_config: app_cfg.clone(),
            security_contract,
            api_cookie_runtime,
            api_authenticator_runtime,
        })
        .unwrap_or_else(|_| panic!("startup config already initialized"));
    let store = ConfigStore::new(path);
    STORE
        .set(Mutex::new(store))
        .expect("config store already initialized");
}

#[cfg(test)]
pub fn init_with_security_contract(
    path: &str,
    app_cfg: &RyukiConfig,
    security_contract: crate::security_contracts::SecurityContractContext,
    api_cookie_runtime: Arc<crate::cookie_runtime::ApiCookieRuntime>,
    api_authenticator_runtime: Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>,
) {
    TEST_STARTUP_CONFIG.with(|slot| {
        *slot.borrow_mut() = Some(Box::leak(Box::new(ImmutableStartupConfig {
            app_config: app_cfg.clone(),
            security_contract: Some(security_contract),
            api_cookie_runtime,
            api_authenticator_runtime: Some(api_authenticator_runtime),
        })));
    });
    TEST_STORE.with(|slot| {
        *slot.borrow_mut() = Some(Box::leak(Box::new(Mutex::new(ConfigStore::new(path)))));
    });
}

/// Test-only compatibility helper for callers that do not exercise startup
/// admission. Production initialization cannot omit the security contract.
#[cfg(test)]
pub fn init_with_config(path: &str, app_cfg: &RyukiConfig) {
    let api_cookie_runtime =
        crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(app_cfg, false)
            .expect("test config must construct an API cookie runtime");
    TEST_STARTUP_CONFIG.with(|slot| {
        *slot.borrow_mut() = Some(Box::leak(Box::new(ImmutableStartupConfig {
            app_config: app_cfg.clone(),
            security_contract: None,
            api_cookie_runtime,
            api_authenticator_runtime: None,
        })));
    });
    TEST_STORE.with(|slot| {
        *slot.borrow_mut() = Some(Box::leak(Box::new(Mutex::new(ConfigStore::new(path)))));
    });
}

pub fn get_app_config() -> &'static RyukiConfig {
    app_config_if_initialized().expect("app config not initialized")
}

pub fn get_api_cookie_runtime() -> Arc<crate::cookie_runtime::ApiCookieRuntime> {
    Arc::clone(
        &startup_config_if_initialized()
            .expect("startup config not initialized")
            .api_cookie_runtime,
    )
}

#[cfg(not(test))]
pub fn get_api_authenticator_runtime() -> Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>
{
    Arc::clone(
        &startup_config_if_initialized()
            .expect("startup config not initialized")
            .api_authenticator_runtime,
    )
}

#[cfg(test)]
pub fn get_api_authenticator_runtime() -> Arc<crate::authenticator_runtime::ApiAuthenticatorRuntime>
{
    Arc::clone(
        startup_config_if_initialized()
            .expect("startup config not initialized")
            .api_authenticator_runtime
            .as_ref()
            .expect("authenticator runtime not initialized"),
    )
}

#[cfg(not(test))]
pub fn get_security_contract_context() -> &'static crate::security_contracts::SecurityContractContext
{
    &startup_config_if_initialized()
        .expect("startup config not initialized")
        .security_contract
}

#[cfg(test)]
pub fn get_security_contract_context() -> &'static crate::security_contracts::SecurityContractContext
{
    startup_config_if_initialized()
        .expect("startup config not initialized")
        .security_contract
        .as_ref()
        .expect("security contract context not initialized")
}

/// The configured auth mode, or the default (`MockDryRun`) when the config store
/// is not initialized (e.g. unit tests). Never panics — use this on hot paths
/// (like the separation-of-duties gate) that can run before/without init.
pub fn auth_mode_or_default() -> ryuki_core::config::AuthMode {
    app_config_if_initialized()
        .map(|c| c.auth_mode.clone())
        .unwrap_or_default()
}

pub async fn load_config() -> Result<PlatformConfig, String> {
    config_store().lock().await.load_config()
}

pub async fn save_config(config: &PlatformConfig) -> Result<(), String> {
    config_store().lock().await.save_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config_path() -> String {
        // A process-global atomic counter guarantees a distinct path per call
        // even when parallel tests hit the same clock tick (macOS SystemTime
        // resolution is coarser than nanoseconds, so `as_nanos()` alone collides
        // under concurrency — two tests then share a file and clobber each
        // other's contents, making the invalid-config test read valid JSON).
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("ryuki-platform-config-{nanos}-{seq}.json"))
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

    #[test]
    #[should_panic(expected = "security contract context not initialized")]
    fn compatibility_initializer_never_fabricates_security_contract_context() {
        init_with_config("test-only-config.json", &RyukiConfig::default());

        let _ = get_security_contract_context();
    }

    #[test]
    #[should_panic(expected = "authenticator runtime not initialized")]
    fn compatibility_initializer_never_fabricates_authenticator_runtime() {
        init_with_config("test-only-config.json", &RyukiConfig::default());

        let _ = get_api_authenticator_runtime();
    }
}
