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
//! ## Registration (S5)
//!
//! First-boot self-registration is wired: when no token is available from
//! `RYUKI_AGENT_TOKEN` or the token file, and `RYUKI_AGENT_SELF_REGISTER=true`,
//! the agent registers via `CpClient::register_new`, persists the returned
//! token to the token file (0600, create-only), and **exits 0** pending admin
//! approval. See [`self_register_and_exit`] for the exit-vs-poll rationale.
//! Token precedence is documented in `config.rs`.

use std::sync::Arc;
use std::time::Duration;

use ryuki_agent::{
    client::{ClientError, CpClient},
    config::AgentConfig,
    executor::RunnerExecutor,
    identity::AgentIdentity,
    live::pin_cp_key,
    live_exec::RunnerLiveExecutor,
    outbox::Outbox,
    run::run_loop,
    token::{resolve_token, save_token_file, validate_register_response, ResolvedToken},
};
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
        token_path  = %cfg.token_path.display(),
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

    // The agent_id is the platform string for now (S4c); making it separately
    // configurable is a follow-up slice.
    let agent_id = cfg.platform.clone();

    // Resolve the bearer token: RYUKI_AGENT_TOKEN → token file → first-boot
    // self-registration (precedence documented in config.rs). Fail-closed: any
    // malformed source is fatal here rather than a 401/403 on every request.
    let token = match resolve_token(&cfg) {
        Ok(ResolvedToken::FromEnv(token)) => {
            if cfg.token_path.exists() {
                info!(
                    token_path = %cfg.token_path.display(),
                    "RYUKI_AGENT_TOKEN is set — it takes precedence over the token file"
                );
            }
            token
        }
        Ok(ResolvedToken::FromFile(token)) => {
            info!(
                token_path = %cfg.token_path.display(),
                "loaded agent token from token file"
            );
            token
        }
        Ok(ResolvedToken::SelfRegister) => {
            self_register_and_exit(&cfg, &identity, &agent_id).await;
        }
        Err(e) => {
            tracing::error!(error = %e, "no agent token available");
            std::process::exit(1);
        }
    };

    info!(
        agent_id   = %agent_id,
        public_key = %identity.public_key_b64(),
        "agent identity ready — entering pull-loop"
    );

    // Build dependencies.
    let cp = CpClient::new(&cfg.cp_base_url, &agent_id, &token);

    // Wire protocol compatibility handshake — runs for EVERY agent, live or not
    // (the CP→agent half of the version check; the CP-side extractor is the
    // agent→CP half). A CONFIRMED version mismatch is fatal: the agent refuses to
    // start rather than fail opaquely mid-job on a drifted wire schema. A
    // network/HTTP failure fetching the version is NON-fatal (matches the lenient
    // CP-key fetch below): we cannot confirm, so we warn and let the pull-loop —
    // and the CP-side gate — remain the backstop.
    match cp.ensure_cp_protocol_compatible().await {
        Ok(cp_version) => info!(
            cp_protocol_version = cp_version,
            agent_protocol_version = ryuki_protocol::PROTOCOL_VERSION,
            "CP wire protocol is compatible"
        ),
        Err(ClientError::IncompatibleProtocol {
            cp_version,
            supported,
        }) => {
            tracing::error!(
                cp_protocol_version = cp_version,
                supported = ?supported,
                "control plane speaks an incompatible wire protocol version — \
                 upgrade this agent; refusing to start"
            );
            std::process::exit(1);
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not confirm CP wire protocol compatibility (CP unreachable?) — \
                 continuing; the CP will still reject an unsupported version per request"
            );
        }
    }

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
    let outbox_drain_interval = Duration::from_secs(cfg.outbox_drain_interval_secs);

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
        cfg.max_outbox_attempts,
        outbox_drain_interval,
    )
    .await;
}

/// First-boot self-registration: register with the CP, persist the one-time
/// token to the token file (0600, create-only), print operator instructions,
/// and **exit 0**.
///
/// ## Why exit(0) instead of polling until approved
///
/// There is no unambiguous status-poll affordance: every authenticated agent
/// endpoint returns 403 for BOTH a `pending` and a `revoked` agent, so a
/// wait-for-approval loop could not terminate correctly on a revoked agent
/// without string-matching error bodies (a brittle, unversioned contract).
/// Exiting 0 is simpler and converges naturally: under a supervisor (systemd
/// `Restart=`), the next boot loads the token file and enters the pull-loop,
/// whose existing behavior already warn-tolerates 403s until the admin
/// approval flips them to 2xx. An interactive operator gets an explicit,
/// unmissable "pending approval" hand-off instead of a silent warn-loop.
async fn self_register_and_exit(
    cfg: &AgentConfig,
    identity: &AgentIdentity,
    agent_id: &str,
) -> ! {
    info!(
        agent_id,
        platform = %cfg.platform,
        cp_base_url = %cfg.cp_base_url,
        "no agent token found — attempting first-boot self-registration"
    );

    let reg = AgentRegistration {
        agent_id: agent_id.to_owned(),
        platform: cfg.platform.clone(),
        capabilities: cfg.capabilities.clone(),
        public_key: identity.public_key_b64(),
    };

    let resp = match CpClient::register_new(&cfg.cp_base_url, &reg).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(
                error = %e,
                agent_id,
                "self-registration failed. If this agent_id is already registered \
                 (HTTP 409), restore its token file or have an admin revoke/delete \
                 the stale enrollment before re-registering"
            );
            std::process::exit(1);
        }
    };

    // Fail-closed: never persist a response we cannot vouch for. The CP shows
    // the plaintext token exactly once, so validation happens BEFORE the write.
    if let Err(e) = validate_register_response(&resp, agent_id) {
        tracing::error!(
            error = %e,
            "control plane returned a malformed registration response — refusing to persist"
        );
        std::process::exit(1);
    }

    if let Err(e) = save_token_file(&cfg.token_path, &resp.token) {
        // The registration is already consumed server-side and the plaintext
        // token is shown only once. Deliberately do NOT print the token as a
        // fallback — logs outlive processes (journald etc.) and a credential in
        // logs is worse than a repeated enrollment. Recovery is explicit.
        tracing::error!(
            error = %e,
            agent_id,
            token_path = %cfg.token_path.display(),
            "registration succeeded but the token could NOT be persisted; the \
             one-time token is now lost. An admin must delete/revoke the pending \
             agent before retrying self-registration"
        );
        std::process::exit(1);
    }

    info!(
        agent_id,
        token_path = %cfg.token_path.display(),
        "self-registration complete — token persisted (0600); agent is PENDING admin approval"
    );
    info!(
        "next step: an admin must approve this agent: \
         POST {}/api/admin/agents/{}/approve with body {{\"platform\": \"{}\"}}",
        cfg.cp_base_url, agent_id, cfg.platform
    );
    info!("after approval, start the agent again — it will load the token from the token file");
    std::process::exit(0);
}
