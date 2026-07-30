//! ryuki-agent binary — entry point.
//!
//! Loads configuration, resolves the Ed25519 identity, optionally fetches and
//! pins the CP grant keyset and deployment/trust-domain scope (when
//! `allow_live` is set), then enters the pull-loop
//! via [`ryuki_agent::run::run_loop`].
//!
//! ## CP key pin (S5b-2b-ii)
//!
//! When `RYUKI_AGENT_ALLOW_LIVE=true`, the agent fetches the CP's Ed25519
//! public keyset via `GET /api/agents/cp-public-key` and pins it together with
//! the canonical local grant scope via `pin_cp_grant_authority`. The combined
//! authority is held for the lifetime of the process and passed to
//! `run_loop` so the gate can verify `VerifiedLiveContext` grants.
//!
//! If the fetch fails (network error, CP unreachable), the agent logs a warning
//! and continues with `cp_grant_authority = None`. In that state:
//! - `LivePlan` jobs are still executed (the gate only checks `allow_live`).
//! - `LiveApply` jobs are refused (the gate cannot verify the grant).
//!
//! ## Registration (S5)
//!
//! First-boot self-registration is wired: when no token is available from
//! `RYUKI_AGENT_TOKEN` or the token file, and `RYUKI_AGENT_SELF_REGISTER=true`,
//! the agent consumes the preprovisioned one-time enrollment challenge and
//! signs the exact claim with its existing Ed25519 workload key. It then
//! registers via `CpClient::register_new`, persists the returned token to the
//! token file (0600, create-only), and **exits 0** pending admin approval. See
//! [`self_register_and_exit`] for the exit-vs-poll rationale.
//! Token precedence is documented in `config.rs`.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ryuki_agent::{
    client::{ClientError, CpClient},
    config::AgentConfig,
    executor::RunnerExecutor,
    identity::AgentIdentity,
    live::pin_cp_grant_authority,
    live_exec::RunnerLiveExecutor,
    outbox::Outbox,
    run::run_loop,
    token::{resolve_token, save_token_file, validate_register_response, ResolvedToken},
};
use ryuki_protocol::{sign_agent_enrollment_proof, AgentRegistration};
use tracing::info;

#[derive(Debug, Eq, PartialEq)]
enum StartupMode {
    Run,
    PrintEnrollmentPublicKey,
}

fn parse_startup_mode(args: impl IntoIterator<Item = OsString>) -> Result<StartupMode, String> {
    let args: Vec<OsString> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(StartupMode::Run),
        [arg] if arg.as_os_str() == OsStr::new("--enrollment-public-key") => {
            Ok(StartupMode::PrintEnrollmentPublicKey)
        }
        _ => Err(
            "unsupported arguments; use no arguments to run the agent or exactly \
             --enrollment-public-key to stage its enrollment identity"
                .to_owned(),
        ),
    }
}

/// Load or create the durable workload key and print only its public half.
///
/// Trusted provisioning calls this before requesting a challenge, so the
/// control plane binds admission to the exact key the normal agent process
/// subsequently loads. No token, challenge, control-plane URL, or provider
/// credential is read in this mode.
fn print_enrollment_public_key() -> Result<(), String> {
    let key_path = std::env::var_os("RYUKI_AGENT_KEY_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("agent.key"));
    let identity = if key_path.exists() {
        AgentIdentity::load(&key_path)
            .map_err(|error| format!("failed to load enrollment identity: {error}"))?
    } else {
        let identity = AgentIdentity::generate();
        identity
            .save(&key_path)
            .map_err(|error| format!("failed to save enrollment identity: {error}"))?;
        identity
    };
    println!("{}", identity.public_key_b64());
    Ok(())
}

#[tokio::main]
async fn main() {
    let startup_mode = match parse_startup_mode(std::env::args_os().skip(1)) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };
    if startup_mode == StartupMode::PrintEnrollmentPublicKey {
        if let Err(error) = print_enrollment_public_key() {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
        return;
    }

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

    // The parser already rejected every remote cleartext endpoint. Keep the
    // explicit local development exception visible to operators.
    if cfg.cp_base_url.is_insecure_loopback() {
        tracing::warn!(
            cp_base_url = %cfg.cp_base_url,
            "control-plane URL uses explicitly enabled loopback HTTP for local development/testing; use HTTPS outside the local harness"
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
    let cp = match CpClient::from_endpoint(&cfg.cp_base_url, &agent_id, &token) {
        Ok(cp) => cp,
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize control-plane client");
            std::process::exit(1);
        }
    };

    // Fetch the bootstrap document ONCE for every agent. Compatibility and the
    // exact keyset publication are intentionally taken from the same typed
    // response. A confirmed mismatch is fatal. Transport or schema failure is
    // non-fatal for non-live agents; live jobs remain fail-closed below because
    // no verification keyset can be pinned.
    let cp_bootstrap = match cp.fetch_cp_keyset_response().await {
        Ok(response) => match CpClient::require_compatible_protocol(response.protocol_version) {
            Ok(()) => {
                info!(
                    cp_protocol_version = response.protocol_version,
                    agent_protocol_version = ryuki_protocol::PROTOCOL_VERSION,
                    "CP wire protocol is compatible"
                );
                Some(response)
            }
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
            Err(_) => unreachable!("protocol compatibility has one failure variant"),
        },
        Err(_) => {
            tracing::warn!(
                "could not fetch a valid CP bootstrap document — continuing without a \
                 pinned grant keyset; the CP still gates subsequent request versions"
            );
            None
        }
    };

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

    // S5b: pin the keyset from that same bootstrap response when live execution
    // is enabled.
    //
    // The pinned key is required to verify VerifiedLiveContext grants before
    // any LiveApply job is executed.  If the fetch fails, we continue with
    // `None` — LivePlan jobs will still run; LiveApply jobs will be refused.
    let cp_grant_authority = if cfg.allow_live {
        match (
            cp_bootstrap.map(|response| response.keyset),
            cfg.live_grant_scope.clone(),
        ) {
            (Some(keyset), Some(scope)) => match pin_cp_grant_authority(keyset, scope) {
                Ok(authority) => {
                    info!(
                        keyset_version = authority.keyset().keyset_version,
                        key_count = authority.keyset().keys.len(),
                        "CP grant authority pinned — signature and deployment/trust-domain scope verification are active"
                    );
                    Some(authority)
                }
                Err(_) => {
                    tracing::warn!(
                        "CP bootstrap keyset failed structural validation — LiveApply jobs will be refused \
                         (no grant verification possible)"
                    );
                    None
                }
            },
            (None, _) => {
                tracing::warn!(
                    "CP bootstrap keyset is unavailable — LiveApply jobs will be refused \
                     (no grant verification possible)"
                );
                None
            }
            // AgentConfig makes this unreachable when allow_live is true, but
            // retain a fail-closed guard at the startup wiring boundary.
            (_, None) => {
                tracing::warn!(
                    "live grant scope is unavailable — mutating live jobs will be refused"
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
        cp_grant_authority.as_ref(),
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
async fn self_register_and_exit(cfg: &AgentConfig, identity: &AgentIdentity, agent_id: &str) -> ! {
    info!(
        agent_id,
        platform = %cfg.platform,
        cp_base_url = %cfg.cp_base_url,
        "no agent token found — attempting first-boot self-registration"
    );

    let enrollment_challenge_id = cfg
        .enrollment_challenge_id
        .expect("self-registration config requires a challenge id");
    let enrollment_challenge = cfg
        .enrollment_challenge
        .as_deref()
        .expect("self-registration config requires a one-time challenge");
    let public_key = identity.public_key_b64();
    let enrollment_proof = sign_agent_enrollment_proof(
        enrollment_challenge_id,
        enrollment_challenge,
        agent_id,
        &cfg.platform,
        &public_key,
        identity.signing_key(),
    );
    let reg = AgentRegistration {
        enrollment_challenge_id,
        enrollment_challenge: enrollment_challenge.to_owned(),
        agent_id: agent_id.to_owned(),
        platform: cfg.platform.clone(),
        capabilities: cfg.capabilities.clone(),
        public_key,
        enrollment_proof,
    };

    let resp = match CpClient::register_new(&cfg.cp_base_url, &reg).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(
                error = %e,
                agent_id,
                "self-registration failed. Retry only with the same private staged \
                 challenge while it remains valid. If the control plane already \
                 consumed it or reports an existing identity, restore the token or \
                 complete the approved enrollment-recovery procedure before a trusted \
                 administrator issues a fresh key-bound challenge"
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
             one-time token is now lost. Do not retry or revoke expecting the \
             human-readable id to become reusable: an administrator must complete \
             the approved enrollment-recovery procedure before issuing a fresh challenge"
        );
        std::process::exit(1);
    }

    info!(
        agent_id,
        token_path = %cfg.token_path.display(),
        "self-registration complete — token persisted (0600); agent is PENDING admin approval"
    );
    info!(
        "next step: an admin must review GET {}/api/admin/agents and copy this \
         enrollment's immutable enrollment_id and public_key_fingerprint",
        cfg.cp_base_url
    );
    info!(
        "then approve the reviewed enrollment: POST {}/api/admin/agents/{}/approve \
         with body {{\"enrollment_id\":\"<from-list>\",\"public_key_fingerprint\":\
         \"<from-list>\",\"platform\":\"{}\"}}",
        cfg.cp_base_url, agent_id, cfg.platform
    );
    info!("after approval, start the agent again — it will load the token from the token file");
    std::process::exit(0);
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[test]
    fn startup_mode_is_explicit_and_non_composable() {
        assert_eq!(
            parse_startup_mode(Vec::<OsString>::new()).unwrap(),
            StartupMode::Run
        );
        assert_eq!(
            parse_startup_mode([OsString::from("--enrollment-public-key")]).unwrap(),
            StartupMode::PrintEnrollmentPublicKey
        );
        for args in [
            vec![OsString::from("--unknown")],
            vec![
                OsString::from("--enrollment-public-key"),
                OsString::from("extra"),
            ],
        ] {
            assert!(parse_startup_mode(args).is_err());
        }
    }
}
