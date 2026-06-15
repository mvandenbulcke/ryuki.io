//! ryuki-agent binary — entry point.
//!
//! Loads configuration, resolves the Ed25519 identity, optionally fetches and
//! pins the CP public key (when `allow_live` is set), then enters the pull-loop
//! via [`ryuki_agent::run::run_loop`].
//!
//! ## CP key pin (S5b-2b-ii)
//!
//! When `RYUKI_AGENT_ALLOW_LIVE=true`, the agent fetches the CP's Ed25519
//! public key via `GET /api/agents/cp-public-key` and pins it via `pin_cp_key`.
//! The pinned key is held for the lifetime of the process and passed to
//! `run_loop` so the gate can verify `VerifiedLiveContext` grants.
//!
//! If the fetch fails (network error, CP unreachable), the agent logs a warning
//! and continues with `cp_verifying_key = None`.  In that state:
//! - `LivePlan` jobs are still executed (the gate only checks `allow_live`).
//! - `LiveApply` jobs are refused (the gate cannot verify the grant).
//!
//! ## Registration (TODO S5)
//!
//! Self-registration via `CpClient::register_new` is a later slice.  For now
//! the agent MUST already be enrolled and approved in the CP; the token is
//! supplied via `RYUKI_AGENT_TOKEN`.

use std::sync::Arc;
use std::time::Duration;

use ryuki_agent::{
    client::CpClient, config::AgentConfig, executor::RunnerExecutor, identity::AgentIdentity,
    live::pin_cp_key, live_exec::RunnerLiveExecutor, outbox::Outbox, run::run_loop,
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
    let live_exec = RunnerLiveExecutor::from_env();

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

    // S5b: fetch and pin the CP public key when live execution is enabled.
    //
    // The pinned key is required to verify VerifiedLiveContext grants before
    // any LiveApply job is executed.  If the fetch fails, we continue with
    // `None` — LivePlan jobs will still run; LiveApply jobs will be refused.
    let cp_verifying_key = if cfg.allow_live {
        match cp.fetch_cp_public_key().await {
            Ok(b64) => match pin_cp_key(&b64) {
                Ok(vk) => {
                    info!("CP public key pinned — LiveApply grant verification is active");
                    Some(vk)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to decode CP public key — LiveApply jobs will be refused \
                         (no grant verification possible)"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to fetch CP public key — LiveApply jobs will be refused \
                     (no grant verification possible)"
                );
                None
            }
        }
    } else {
        None
    };

    let poll_interval = Duration::from_secs(cfg.poll_interval_secs);

    // Enter the pull-loop. This never returns under normal operation.
    run_loop(
        &cp,
        &executor,
        &live_exec,
        &identity,
        &agent_id,
        &outbox,
        poll_interval,
        cp_verifying_key.as_ref(),
        cfg.allow_live,
    )
    .await;
}
