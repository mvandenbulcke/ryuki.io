//! ryuki-agent — per-platform execution agent binary.
//!
//! ## S4a scope (this file)
//!
//! - Init structured logging.
//! - Load `AgentConfig` from environment.
//! - Load or generate `AgentIdentity` (Ed25519 key).
//! - Build an `AgentRegistration` ready to post.
//! - Log what would happen next (register / poll).
//!
//! ## TODO S4b
//!
//! - Pull-loop: `CpClient::poll()` → `CpClient::ack()` → run via `ryuki-runner`
//!   → sign result envelope → `CpClient::post_result()`.
//! - Durable outbox: write signed result before posting; retry until CP acks.
//! - Heartbeat ticker (parallel to pull-loop).
//! - Graceful shutdown on SIGTERM.
//! - `--allow-live` flag for `LivePlan`/`LiveApply` modes (S5).

mod client;
mod config;
mod executor;
mod identity;
mod outbox;
mod result;

use ryuki_protocol::AgentRegistration;
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
    let cfg = match config::AgentConfig::from_env() {
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
        match identity::AgentIdentity::load(&cfg.key_path) {
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
        let id = identity::AgentIdentity::generate();
        if let Err(e) = id.save(&cfg.key_path) {
            tracing::error!(error = %e, path = %cfg.key_path.display(), "failed to save identity");
            std::process::exit(1);
        }
        info!(key_id = %id.public_key_b64(), path = %cfg.key_path.display(), "generated new agent identity");
        id
    };

    // Build the registration payload (sent to POST /api/agents/register on first run).
    // In S4b this is wired to CpClient::register_new when no token exists yet,
    // or skipped when the agent is already enrolled.
    let registration = AgentRegistration {
        agent_id: cfg.platform.clone(), // S4b: make agent_id separately configurable
        platform: cfg.platform.clone(),
        capabilities: cfg.capabilities.clone(),
        public_key: identity.public_key_b64(),
    };

    info!(
        agent_id   = %registration.agent_id,
        public_key = %registration.public_key,
        "agent identity ready (S4b: will register if not yet enrolled)"
    );

    // TODO S4b: pull-loop + execute + sign + outbox
    // The skeleton below shows the intended S4b structure:
    //
    //   let cp = client::CpClient::new(&cfg.cp_base_url, &registration.agent_id, &cfg.token);
    //   loop {
    //       match cp.poll().await {
    //           Ok(Some(job)) => {
    //               // ack → run via ryuki-runner → sign → outbox → post_result
    //           }
    //           Ok(None) => tokio::time::sleep(Duration::from_secs(cfg.poll_interval_secs)).await,
    //           Err(e) => { tracing::warn!(error = %e, "poll error"); /* backoff */ }
    //       }
    //   }

    info!("S4a foundation ready — S4b will wire the pull-loop");
}
