//! ryuki-agent binary — entry point.
//!
//! Loads configuration, resolves the Ed25519 identity, then enters the
//! pull-loop via [`ryuki_agent::run::run_loop`].
//!
//! ## Registration (TODO S5)
//!
//! Self-registration via `CpClient::register_new` is a later slice.  For now
//! the agent MUST already be enrolled and approved in the CP; the token is
//! supplied via `RYUKI_AGENT_TOKEN`.  Leave a clear marker here so S5 can slot
//! registration in before the `run_loop` call.

use std::sync::Arc;
use std::time::Duration;

use ryuki_agent::{
    client::CpClient, config::AgentConfig, executor::RunnerExecutor, identity::AgentIdentity,
    outbox::Outbox, run::run_loop,
};
use tracing::info;

#[tokio::main]
async fn main() {
    // Init structured logging from RUST_LOG (default: info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load configuration from RYUKI_AGENT_* env vars.
    let cfg = match AgentConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "configuration error");
            std::process::exit(1);
        }
    };

    // The bearer token is sent on every request. Warn (don't fail — local/e2e
    // runs use http://127.0.0.1) if the control plane is reached over cleartext.
    if cfg.cp_base_url.starts_with("http://") {
        tracing::warn!(
            cp_base_url = %cfg.cp_base_url,
            "control-plane URL is cleartext http:// — the agent bearer token will be sent unencrypted; use https:// in production"
        );
    }

    info!(
        cp_base_url = %cfg.cp_base_url,
        platform    = %cfg.platform,
        key_path    = %cfg.key_path.display(),
        poll_interval_secs = cfg.poll_interval_secs,
        lease_secs  = cfg.lease_secs,
        "ryuki-agent starting"
    );

    // Load or generate the Ed25519 identity.
    let identity = if cfg.key_path.exists() {
        match AgentIdentity::load(&cfg.key_path) {
            Ok(id) => {
                info!(key_id = %id.public_key_b64(), "loaded existing agent identity");
                id
            }
            Err(e) => {
                tracing::error!(error = %e, path = %cfg.key_path.display(), "failed to load identity");
                std::process::exit(1);
            }
        }
    } else {
        let id = AgentIdentity::generate();
        if let Err(e) = id.save(&cfg.key_path) {
            tracing::error!(error = %e, path = %cfg.key_path.display(), "failed to save identity");
            std::process::exit(1);
        }
        info!(key_id = %id.public_key_b64(), path = %cfg.key_path.display(), "generated new agent identity");
        id
    };

    let identity = Arc::new(identity);

    // TODO S5: self-registration via CpClient::register_new when no token exists.
    // For now the agent MUST be pre-enrolled + approved; the token comes from
    // RYUKI_AGENT_TOKEN.  The agent_id is the platform string for now (S4c);
    // make it separately configurable in S5.
    let agent_id = cfg.platform.clone();

    info!(
        agent_id   = %agent_id,
        public_key = %identity.public_key_b64(),
        "agent identity ready — entering pull-loop"
    );

    // Build dependencies.
    let cp = CpClient::new(&cfg.cp_base_url, &agent_id, &cfg.token);
    let executor = RunnerExecutor::new(Arc::clone(&identity));

    // Outbox lives next to the key file (same directory) or falls back to cwd/outbox.
    let outbox_dir = cfg
        .key_path
        .parent()
        .map(|p| p.join("outbox"))
        .unwrap_or_else(|| std::path::PathBuf::from("outbox"));

    let outbox = match Outbox::create_dir(&outbox_dir) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, path = %outbox_dir.display(), "failed to create outbox directory");
            std::process::exit(1);
        }
    };

    let poll_interval = Duration::from_secs(cfg.poll_interval_secs);

    // Enter the pull-loop. This never returns under normal operation.
    run_loop(&cp, &executor, &identity, &agent_id, &outbox, poll_interval).await;
}
