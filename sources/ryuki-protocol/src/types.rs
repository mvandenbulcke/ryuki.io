//! Wire types for the Ryuki agent↔control-plane protocol.
//! All types derive serde for over-the-wire JSON; all are pure data (no IO).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Job execution mode
// ---------------------------------------------------------------------------

/// The execution modes.  The agent MUST NOT elevate the mode on its own.
///
/// - `OfflineDryRun` — no platform access; validate + plan without providers.
/// - `LivePlan`     — reads live state (`terraform plan` / `ansible --check`).
/// - `LiveApply`    — mutates.  Requires a CP-signed `VerifiedLiveContext`.
/// - `LiveDestroy`  — DESTROYS a step's applied resources (`terraform destroy`).
///   Requires a CP-signed, step-bound `VerifiedLiveContext`, exactly like
///   `LiveApply`. Used only by #42's auto compensating teardown: when a step
///   of a multi-step live request fails after earlier steps applied, the CP
///   mints a LiveDestroy job per already-applied step (in reverse dependency
///   order) to roll it back. Unlike `LiveApply` there is no plan-then-apply
///   digest match — a destroy removes the step's own isolated workspace state
///   (its bound), not a pre-approved plan; the grant's step-job binding +
///   signature + expiry + `--allow-live` are the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobMode {
    OfflineDryRun,
    LivePlan,
    LiveApply,
    LiveDestroy,
}

// ---------------------------------------------------------------------------
// Job status
// ---------------------------------------------------------------------------

/// Lifecycle status of a job, as tracked by the control plane.
/// This is the agent-DISPATCHABLE subset of the CP-side state machine; agents MUST
/// NOT report these values — use [`JobResultStatus`] for agent-reported terminal
/// outcomes. Some CP-INTERNAL terminal statuses (`DeadLettered`, `Cancelled`) exist
/// in the `agent_jobs.status` DB CHECK but are intentionally NOT modelled here: they
/// are never dispatched (poll filters `status = 'Pending'`) and admin reads carry
/// `status` as a String, so they never decode into this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Created, not yet leased.
    Pending,
    /// Lease issued; agent has not yet acknowledged.
    Leased,
    /// Agent has acknowledged (`ack` received).
    Running,
    /// Completed successfully.
    Succeeded,
    /// Completed with failure.
    Failed,
    /// Lease timed out (non-mutating job — safe to redispatch).
    Expired,
    /// `LiveApply` lease timed out — operator must reconcile before re-dispatch.
    ReconcileRequired,
    /// Agent refused to execute `LiveApply` (missing grant / plan divergence / no
    /// `--allow-live` flag).
    LiveRefused,
}

// ---------------------------------------------------------------------------
// Job result status (agent-reported terminal outcomes only)
// ---------------------------------------------------------------------------

/// The set of terminal execution outcomes an **agent** may report.
///
/// This is intentionally narrower than [`JobStatus`], which covers the full
/// CP lifecycle (Pending, Leased, Running, Expired, ReconcileRequired).
/// Agents MUST only report one of these values; the CP rejects any result
/// that carries a value outside this set.
///
/// Variants are aligned with `ryuki-engine`'s `RunStatus` where sensible:
/// - `CheckOk`    — offline/dry-run validation passed (no platform access).
/// - `Planned`    — live plan completed (read-only); plan artifact attached.
/// - `Applied`    — live apply completed successfully.
/// - `Verified`   — post-apply verification passed. CP-INTERNAL: the engine's
///   `RunStatus` has no `Verified` variant and `map_run_status` never produces it,
///   so a first-party agent cannot report it. The CP REJECTS an inbound result
///   carrying `Verified` (see `post_job_result_with_pool`) so a result cannot forge
///   a verification step that never ran. Do NOT have an agent emit this.
/// - `Failed`     — execution failed at any stage.
/// - `LiveRefused`— agent refused `LiveApply` (missing grant / plan divergence /
///   `--allow-live` flag absent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobResultStatus {
    CheckOk,
    Planned,
    Applied,
    Verified,
    Failed,
    LiveRefused,
}

/// Whether an agent-reported terminal status is valid for an execution mode.
/// `Verified` is deliberately absent: it is a control-plane-derived outcome.
pub fn job_result_status_allowed(mode: &JobMode, status: &JobResultStatus) -> bool {
    match mode {
        JobMode::OfflineDryRun => matches!(
            status,
            JobResultStatus::CheckOk | JobResultStatus::Planned | JobResultStatus::Failed
        ),
        JobMode::LivePlan => matches!(
            status,
            JobResultStatus::CheckOk
                | JobResultStatus::Planned
                | JobResultStatus::Failed
                | JobResultStatus::LiveRefused
        ),
        JobMode::LiveApply | JobMode::LiveDestroy => matches!(
            status,
            JobResultStatus::Applied | JobResultStatus::Failed | JobResultStatus::LiveRefused
        ),
    }
}

// ---------------------------------------------------------------------------
// Agent capabilities
// ---------------------------------------------------------------------------

/// Version string for a specific Terraform provider (name → version).
pub type ProviderVersions = BTreeMap<String, String>;

/// Tool capabilities advertised by an agent at registration time.
/// The control plane does NOT trust self-declared capabilities for auth
/// decisions; they are reconciled against a trusted inventory by the admin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCapability {
    /// e.g. `"1.9.5"`
    pub version: String,
    /// Terraform-local provider name → version (for example `vsphere`, not the
    /// registry source address `vmware/vsphere`). Must be empty for Ansible.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_versions: ProviderVersions,
}

/// Full capability set of an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Capabilities {
    /// Terraform binary capability, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terraform: Option<ToolCapability>,
    /// Ansible binary capability, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ansible: Option<ToolCapability>,
}

// ---------------------------------------------------------------------------
// Agent registration
// ---------------------------------------------------------------------------

/// Prefix and exact lowercase-hex width of one-time enrollment bootstrap
/// challenges. Shared by the issuer, API verifier, and agent config parser so
/// a deployment cannot silently accept different credential shapes.
pub const AGENT_ENROLLMENT_CHALLENGE_PREFIX: &str = "ryc_";
pub const AGENT_ENROLLMENT_CHALLENGE_HEX_BYTES: usize = 64;

/// Sent by the agent on `POST /api/agents/register`.
/// Remains in `Pending` status until an admin approves it and reconciles
/// capabilities against the trusted inventory.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRegistration {
    /// Identifier of the short-lived enrollment challenge pre-created by an
    /// administrator or trusted provisioning workflow.
    pub enrollment_challenge_id: Uuid,
    /// One-time bootstrap secret returned only when the challenge is created.
    /// The control plane stores only its SHA-256 digest and consumes it
    /// atomically with registration.
    pub enrollment_challenge: String,
    /// Stable agent identifier (e.g. `"defra-vcenter-01"`).
    pub agent_id: String,
    /// Platform / site this agent serves (e.g. `"defra"`).
    pub platform: String,
    /// Self-declared capabilities (reconciled by admin, not trusted for authz).
    pub capabilities: Capabilities,
    /// Base64-encoded Ed25519 verifying (public) key.
    /// The control plane stores this; every subsequent signed payload from this
    /// agent is verified against it.
    pub public_key: String,
    /// Base64 Ed25519 signature over the domain-separated enrollment claim.
    /// This proves possession of the private half of `public_key`; the signed
    /// bytes also bind the one-time challenge and every identity field above.
    pub enrollment_proof: String,
}

impl std::fmt::Debug for AgentRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentRegistration")
            .field("enrollment_challenge_id", &self.enrollment_challenge_id)
            .field("enrollment_challenge", &"<redacted>")
            .field("agent_id", &self.agent_id)
            .field("platform", &self.platform)
            .field("capabilities", &self.capabilities)
            .field("public_key", &self.public_key)
            .field("enrollment_proof", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Job specification
// ---------------------------------------------------------------------------

/// Positive, monotonic version of the request resource authorized by a job,
/// approval grant, or signed result.
///
/// The transparent non-zero representation keeps the JSON wire value numeric
/// while making zero unrepresentable in locally constructed protocol values.
/// Because fields of this type have no serde default, peers that omit the
/// version or send zero fail deserialization instead of silently falling back
/// to an unversioned request authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestResourceVersion(NonZeroU64);

impl RequestResourceVersion {
    /// Construct a positive request-resource version.
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the positive numeric wire value.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for RequestResourceVersion {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or("request_resource_version must be positive")
    }
}

impl TryFrom<i64> for RequestResourceVersion {
    type Error = &'static str;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        let value =
            u64::try_from(value).map_err(|_| "request_resource_version must be positive")?;
        Self::try_from(value)
    }
}

impl From<RequestResourceVersion> for u64 {
    fn from(value: RequestResourceVersion) -> Self {
        value.get()
    }
}

impl std::fmt::Display for RequestResourceVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, formatter)
    }
}

/// Return whether a control-plane Terraform state key is safe for substitution
/// into the operator's quoted backend-HCL template.
pub fn is_safe_state_key(state_key: &str) -> bool {
    !state_key.is_empty()
        && state_key.len() <= 128
        && state_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// References the IaC artefacts by stable identifier + digest, never by
/// inline content.  Credentials are **never** in the spec — the agent
/// resolves them from its own environment/secret store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    /// The upstream change-request id this job implements.
    pub request_id: Uuid,
    /// Exact positive, monotonic version of `request_id` authorized when the
    /// control plane created this job. Agents and result ingestion must reject
    /// a job, grant, or result whose independently signed versions disagree.
    pub request_resource_version: RequestResourceVersion,
    /// The service-catalogue offering being executed.
    pub offering_id: Uuid,
    /// Stable reference to the IaC template (path or content-addressed id).
    pub iac_ref: String,
    /// SHA-256 hex digest of the IaC template at the time the job was created.
    pub iac_digest: String,
    /// Variable overrides (non-secret; secrets are env-injected by the agent).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
    /// Opaque control-plane-owned key that selects this job's Terraform state.
    ///
    /// New control planes set this on every dispatched spec. It is optional on
    /// the wire so agents can still decode jobs persisted by an older control
    /// plane; live Terraform execution rejects an absent or unsafe key before
    /// invoking the runner. A single-job request reuses one request key, while
    /// every orchestration step reuses its own distinct step key for plan,
    /// apply, and destroy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    /// Requested execution mode.
    pub mode: JobMode,
}

// ---------------------------------------------------------------------------
// Job lease (fencing)
// ---------------------------------------------------------------------------

/// Issued by the control plane when an agent polls and wins a `SKIP LOCKED`
/// row.  The agent must present the `fencing_token` in every subsequent call
/// for this attempt; stale attempts are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobLease {
    /// Unique identifier for this specific attempt (monotonically new on every
    /// (re-)dispatch).
    pub attempt_id: Uuid,
    /// Monotonically increasing per-job counter.  The CP only accepts results
    /// from the highest-seen `lease_generation`; stale attempts are rejected.
    pub lease_generation: u64,
    /// Opaque fencing token (e.g. a random UUID string). Must be echoed back in
    /// `ack` and running-heartbeat renewal calls. Results are independently
    /// fenced by the signed attempt id, lease generation, and CP nonce.
    pub fencing_token: String,
    /// Absolute deadline (CP DB time — no client clock).  After this the CP
    /// transitions the job per §5 (redispatch or ReconcileRequired).
    pub deadline: DateTime<Utc>,
    /// Per-lease one-time nonce generated by the control plane.
    ///
    /// The agent MUST copy this value verbatim into [`SignedEnvelope::cp_nonce`]
    /// before signing the result.  The CP binds the nonce to the signed envelope
    /// to prevent replay attacks across attempts.
    ///
    /// **Freshness is CP-enforced (S3):** the CP generates a new random nonce
    /// for every lease issuance; it MUST reject any result whose `cp_nonce`
    /// does not match the nonce recorded for that `attempt_id`.
    pub cp_nonce: String,
}

/// Agent heartbeat payload.
///
/// Idle heartbeats set every lease field to `None`. A heartbeat for a running
/// job MUST populate all four lease fields; the control plane uses them as an
/// exact ownership fence before extending the database-clock lease deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHeartbeat {
    /// Running job whose lease should be renewed. Omit together with every
    /// other lease field for an idle heartbeat.
    pub running_job_id: Option<Uuid>,
    /// Exact lease attempt identifier issued with `running_job_id`.
    pub attempt_id: Option<Uuid>,
    /// Exact lease generation issued by the control plane.
    pub lease_generation: Option<u64>,
    /// Exact opaque fencing token issued for this attempt. Partial or stale
    /// four-field fences are rejected.
    pub fencing_token: Option<String>,
}

impl AgentHeartbeat {
    pub fn idle() -> Self {
        Self {
            running_job_id: None,
            attempt_id: None,
            lease_generation: None,
            fencing_token: None,
        }
    }

    pub fn renewing(job_id: Uuid, lease: &JobLease) -> Self {
        Self {
            running_job_id: Some(job_id),
            attempt_id: Some(lease.attempt_id),
            lease_generation: Some(lease.lease_generation),
            fencing_token: Some(lease.fencing_token.clone()),
        }
    }
}

/// Successful heartbeat response. `lease_deadline` is present only when the
/// request renewed an exact running-job lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHeartbeatResponse {
    /// Identifier of the authenticated enrolled agent.
    pub agent_id: String,
    /// Control-plane timestamp recorded for this heartbeat.
    pub last_seen_at: DateTime<Utc>,
    /// Renewed database-clock lease deadline; present only for a valid running
    /// job fence and omitted for an idle heartbeat.
    pub lease_deadline: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Job (the full dispatched unit)
// ---------------------------------------------------------------------------

/// A dispatchable unit of work, as returned by `GET /api/agents/{id}/jobs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    /// Immutable enrollment row of the authenticated assignee returning this
    /// job. Live grants sign the same id; mismatch is refusal-only.
    pub agent_enrollment_id: Uuid,
    /// Platform / site this job targets.
    pub platform: String,
    pub spec: JobSpec,
    pub status: JobStatus,
    /// Present when the job has been leased.
    pub lease: Option<JobLease>,
    /// CP-signed approval grant — required for `LiveApply` and `LiveDestroy`.
    pub live_context: Option<VerifiedLiveContext>,
}

// ---------------------------------------------------------------------------
// Job result (idempotency key)
// ---------------------------------------------------------------------------

/// Posted by the agent to `POST /api/agents/{id}/jobs/{job}/result`.
/// The triple `(job_id, attempt_id, result_id)` is the idempotency key —
/// the CP must de-duplicate on this triple.
///
/// `result_id` MUST equal `SignedEnvelope::result_id`; the CP equality-checks
/// this in S3 before persisting the result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: Uuid,
    pub attempt_id: Uuid,
    /// A fresh UUID generated by the agent before writing to its durable outbox.
    /// Guarantees that a retried POST (after timeout) is not double-processed.
    /// Must equal [`SignedEnvelope::result_id`] — the CP enforces this (S3).
    pub result_id: Uuid,
    pub status: JobResultStatus,
    /// SHA-256 hex digest of the complete canonical raw plan before redaction.
    /// Required only for a successful `LivePlan` (`status = Planned`) and
    /// absent for every other mode/status. The control plane equality-checks
    /// this against [`SignedEnvelope::raw_plan_digest`] before persisting it.
    pub raw_plan_digest: Option<String>,
    /// SHA-256 hex digest of the (redacted) evidence pack.
    /// The evidence bytes are posted separately (multipart / blob store reference).
    pub evidence_digest: String,
    /// The `SignedEnvelope` that binds all of the above for tamper-evident storage.
    pub signed_envelope: SignedEnvelope,
}

// ---------------------------------------------------------------------------
// Execution trust profile — non-secret live-execution provenance
// ---------------------------------------------------------------------------

/// Canonical schema for the non-secret execution inputs that must remain
/// identical between an approved `LivePlan` and the later mutation.
pub const EXECUTION_TRUST_PROFILE_SCHEMA_VERSION: &str = "ryuki.execution-trust-profile.v2";
/// Closed reviewed-live policy allowlist understood by this protocol version.
pub const EXECUTION_TRUST_PROFILE_ALLOWLIST_VERSION: &str = "ryuki.reviewed-live-allowlist.v2";
/// Local executable admission policy used by the runner.
pub const EXECUTABLE_PROVENANCE_POLICY_VERSION: &str = "ryuki.approved-executable.v1";
/// Only explicitly declared, agent-resolved secret sets may authorize current
/// live provider credentials. Ambient CLI/default/in-cluster metadata chains
/// are outside the reviewed profile and fail closed.
pub const PROVIDER_CREDENTIAL_AUTHORITY_MODE: &str = "ryuki.offering-declared-typed-secret-set.v1";
/// Canonical namespace for a non-secret operator-managed reference to the
/// exact vSphere destination/account credential set. The opaque suffix must
/// identify a provisioning record, never contain a hostname, account name,
/// credential, tenant id, or other provider-returned value.
pub const PROVIDER_AUTHORITY_ID_PREFIX: &str = "provider-authority/vsphere/";

/// Canonical namespace for a non-secret operator-managed reference to the
/// backend credential principal selected by trusted provisioning. The
/// backend kind is the first path component after this prefix, followed by an
/// opaque provisioning-record identifier that must not contain credentials,
/// account names, tenant ids, endpoints, or provider-returned values.
pub const BACKEND_CREDENTIAL_AUTHORITY_ID_PREFIX: &str = "backend-credential-authority/";

/// Validate the public reference metadata that versions the provider
/// destination/account credential set. Operators must rotate `version`
/// whenever any member of that set changes, including VSPHERE_SERVER or
/// VSPHERE_USER; secret values themselves never enter this protocol.
pub fn provider_authority_reference_is_canonical(id: &str, version: &str) -> bool {
    let Some(suffix) = id.strip_prefix(PROVIDER_AUTHORITY_ID_PREFIX) else {
        return false;
    };
    let suffix_valid = !suffix.is_empty()
        && id.len() <= 256
        && !suffix.starts_with('/')
        && !suffix.ends_with('/')
        && !suffix.contains("//")
        && suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b'/')
        });
    let version_valid = (2..=64).contains(&version.len())
        && version.starts_with('v')
        && version.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        });
    suffix_valid && version_valid
}

/// Validate the public reference metadata that versions the backend
/// credential principal. Trusted provisioning must rotate `revision` whenever
/// the backend principal, destination, or any credential member changes. The
/// current environment-backed seam validates only this public shape; it does
/// not prove atomic co-resolution with secret material.
pub fn backend_credential_authority_reference_is_canonical(
    backend_kind: &str,
    id: &str,
    revision: &str,
) -> bool {
    let backend_kind_valid = !backend_kind.is_empty()
        && backend_kind.len() <= 32
        && backend_kind.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    let Some(scoped_id) = id.strip_prefix(BACKEND_CREDENTIAL_AUTHORITY_ID_PREFIX) else {
        return false;
    };
    let Some(suffix) = scoped_id
        .strip_prefix(backend_kind)
        .and_then(|value| value.strip_prefix('/'))
    else {
        return false;
    };
    let suffix_valid = backend_kind_valid
        && !suffix.is_empty()
        && id.len() <= 256
        && !suffix.starts_with('/')
        && !suffix.ends_with('/')
        && !suffix.contains("//")
        && suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b'/')
        });
    let revision_valid = (2..=64).contains(&revision.len())
        && revision.starts_with('v')
        && revision.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        });
    suffix_valid && revision_valid
}
/// Terraform state-containment half enforced by `IsolatedBackendConfig`.
/// Profile derivation composes this with the runner's exported descendant-
/// containment version, so either boundary changing invalidates approval.
pub const TERRAFORM_STATE_ISOLATION_POLICY_VERSION: &str = "ryuki.terraform-isolated-state-key.v1";

/// Full, non-secret live-execution identity reported by the planning agent.
/// Raw backend HCL, credentials, provider data, and other secret-bearing values
/// are deliberately absent. Privacy-safe backend and provider authority
/// fields describe those inputs without exposing them: the backend digest is a
/// computed commitment, while provider and backend credential authorities are
/// currently operator-asserted versioned references pending typed atomic
/// credential co-resolution.
/// The canonical digest is produced by `execution_trust_profile_digest`; field
/// order is therefore security-critical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTrustProfile {
    pub schema_version: String,
    pub allowlist_version: String,
    pub platform: String,
    /// Exact reviewed offering slug whose embedded provider lock was used.
    pub offering: String,
    pub runner_kind: String,
    pub provider_source: String,
    pub provider_version: String,
    /// Stable non-secret reference to the exact provider destination/account
    /// credential set selected by trusted provisioning.
    pub provider_authority_id: String,
    /// Immutable version of `provider_authority_id`; must change whenever any
    /// destination/account/credential member changes.
    pub provider_authority_version: String,
    /// Backend TYPE parsed from the validated agent-local backend template.
    /// The template and all of its values never cross this boundary.
    pub backend_kind: String,
    /// Stable non-secret provisioning-record reference for the exact backend
    /// credential principal selected by trusted provisioning.
    pub backend_credential_authority_id: String,
    /// Immutable revision of `backend_credential_authority_id`; must change
    /// whenever the backend principal, destination, or credential set changes.
    pub backend_credential_authority_revision: String,
    /// SHA-256 commitment to the isolation-validated backend semantics. Secret
    /// scalars are represented by typed markers and URL credentials are
    /// sanitized before hashing; raw backend values never cross the boundary.
    pub backend_authority_digest: String,
    pub executable_kind: String,
    /// Canonical path admitted by the runner's existing provenance checks.
    pub executable_path: String,
    /// Version identity proven by the runner's bounded executable probe.
    pub executable_version: String,
    /// Optional content pin from the existing executable approval policy.
    pub executable_sha256: Option<String>,
    pub executable_provenance_policy_version: String,
    pub provider_credential_authority_mode: String,
    pub backend_credential_authority_mode: String,
    pub containment_policy_version: String,
    pub iac_digest: String,
    pub state_key: String,
}

/// Exact plan-owner and execution-profile authority carried by a CP-signed
/// live grant. The immutable enrollment row prevents an agent-id reuse or key
/// rotation from inheriting a previously reviewed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveExecutionAuthority {
    pub assigned_agent_id: String,
    pub assigned_agent_enrollment_id: Uuid,
    pub assigned_agent_key_fingerprint: String,
    pub execution_trust_profile_digest: String,
}

// ---------------------------------------------------------------------------
// VerifiedLiveContext — CP-signed approval grant
// ---------------------------------------------------------------------------

/// Canonical deployment and trust-domain namespace for one control-plane
/// mutation grant.
///
/// These identifiers are public routing authority, not secret material. The
/// fields remain private so locally constructed scopes cannot bypass the same
/// canonical scoped-id rules used by `ryuki-core`: each value must use its
/// exact namespace and carry a 3-through-127-byte lowercase suffix whose first
/// byte is alphanumeric and whose remaining bytes are lowercase alphanumeric,
/// `.`, `_`, or `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneGrantScope {
    deployment_id: String,
    trust_domain_id: String,
}

/// Value-free failure reasons for control-plane grant scope validation.
///
/// The rejected identifier is deliberately never retained or formatted into
/// the error, so an untrusted wire value cannot be reflected into logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlPlaneGrantScopeError {
    #[error("control-plane grant deployment_id is not canonical")]
    InvalidDeploymentId,
    #[error("control-plane grant trust_domain_id is not canonical")]
    InvalidTrustDomainId,
}

impl ControlPlaneGrantScope {
    /// Validate and construct one exact deployment/trust-domain grant scope.
    pub fn new(
        deployment_id: impl Into<String>,
        trust_domain_id: impl Into<String>,
    ) -> Result<Self, ControlPlaneGrantScopeError> {
        let deployment_id = deployment_id.into();
        if !control_plane_grant_scoped_id_is_canonical(&deployment_id, "deployment:") {
            return Err(ControlPlaneGrantScopeError::InvalidDeploymentId);
        }

        let trust_domain_id = trust_domain_id.into();
        if !control_plane_grant_scoped_id_is_canonical(&trust_domain_id, "trust-domain:") {
            return Err(ControlPlaneGrantScopeError::InvalidTrustDomainId);
        }

        Ok(Self {
            deployment_id,
            trust_domain_id,
        })
    }

    /// Exact canonical deployment identity.
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    /// Exact canonical cryptographic trust-domain identity.
    pub fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }
}

fn control_plane_grant_scoped_id_is_canonical(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    let bytes = suffix.as_bytes();
    (3..=127).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Issued by the control plane for an approved `LiveApply` or step rollback
/// `LiveDestroy`.
/// The agent verifies this against the CP's own public key before executing.
///
/// Signable fields (fixed order, see `signing_bytes_vlc`):
/// `request_id, request_resource_version, deployment_id, trust_domain_id,
/// platform, job_spec_digest, approved_plan_digest, approved_plan_job_id,
/// approved_plan_attempt_id, approver, expiry (RFC 3339), step_job_id,
/// execution_authority, signing_key_id`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedLiveContext {
    /// The upstream change-request id.
    pub request_id: Uuid,
    /// Exact positive, monotonic version of the request whose reviewed state
    /// this grant authorizes. A different request version requires a new plan,
    /// approval decision, and grant.
    pub request_resource_version: RequestResourceVersion,
    /// Exact canonical deployment identity this grant authorizes. This is a
    /// required top-level wire field and is independently signature-bound from
    /// the destination platform/site.
    pub deployment_id: String,
    /// Exact canonical cryptographic trust domain this grant authorizes. This
    /// is a required top-level wire field and is independently signature-bound
    /// from both deployment and destination platform/site.
    pub trust_domain_id: String,
    /// Exact destination platform/site this grant authorizes. The issuer copies
    /// the same canonical value into the signed grant and the dispatched
    /// [`Job`]; the agent refuses a validly signed grant whose value does not
    /// equal `Job::platform` before any live mutation.
    pub platform: String,
    /// SHA-256 digest of the exact canonical [`JobSpec`] this grant authorizes.
    /// The agent recomputes it before any live mutation, binding the grant to
    /// the spec's mode, IaC reference/digest, variables, and Terraform state key.
    pub job_spec_digest: String,
    /// SHA-256 hex digest of the plan the approver reviewed.
    /// The agent re-plans and MUST match this before applying.
    pub approved_plan_digest: String,
    /// Immutable `agent_jobs.id` of the exact successful LivePlan result the
    /// approver reviewed. A digest is not a unique row identity: two plans can
    /// produce the same digest under different execution authorities.
    pub approved_plan_job_id: Uuid,
    /// Exact leased attempt that produced the approved plan. The CP verifies
    /// this against both the locked plan row and its signed result envelope
    /// before minting the grant.
    pub approved_plan_attempt_id: Uuid,
    /// Identity of the approver (e.g. username or `subject` claim).
    pub approver: String,
    /// Grant expiry (CP DB time).  The agent MUST reject an expired grant.
    pub expiry: DateTime<Utc>,
    /// Binds this grant to ONE specific dispatched step job (`Job::id`), so it
    /// cannot be replayed against a different step or against a later
    /// re-dispatch of the same step (a re-dispatch mints a new job id).
    ///
    /// `None` is the whole-request grant shape; `Some(id)` is valid ONLY when
    /// applied against the job whose `Job::id == id` and is required for
    /// step-scoped live work. The signing domain is versioned so grants made
    /// before any required authority field was introduced fail verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_job_id: Option<Uuid>,
    /// Exact successful-plan owner and canonical execution-profile digest.
    /// This required field is immutable under the CP signature.
    pub execution_authority: LiveExecutionAuthority,
    /// Stable `kid` of the exact control-plane grant key that produced the
    /// signature. [`crate::crypto::sign_vlc`] always overwrites this field with
    /// the deterministic id of the supplied Ed25519 key before signing. Agents
    /// use it to select one member of the versioned CP verification keyset and
    /// reject unknown or revoked keys without trial-verifying every key.
    pub signing_key_id: String,
    /// Base64-encoded Ed25519 signature over the canonical bytes of the fields
    /// above.  Produced by `sign_vlc`; verified by `verify_vlc`.
    pub signature: String,
}

impl VerifiedLiveContext {
    /// Validate the signed wire identifiers and return their typed exact scope.
    pub fn validated_scope(&self) -> Result<ControlPlaneGrantScope, ControlPlaneGrantScopeError> {
        ControlPlaneGrantScope::new(self.deployment_id.clone(), self.trust_domain_id.clone())
    }
}

/// Maximum number of simultaneously published control-plane grant verifying
/// keys. Rotation needs only one active key and a short, bounded overlap set.
pub const MAX_CONTROL_PLANE_GRANT_KEYS: usize = 8;

/// Public disposition of a control-plane grant key. Only the active member may
/// mint new grants; both active and verify-only members may verify grants during
/// a bounded rotation overlap. Revoked keys are removed from the keyset and
/// therefore fail as unknown `kid`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlPlaneGrantKeyDisposition {
    Active,
    VerifyOnly,
}

/// One non-secret member of the control-plane grant verification keyset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneGrantVerifyingKey {
    /// Deterministic id bound to `public_key` by the protocol verifier.
    pub key_id: String,
    /// Canonical base64 encoding of the 32-byte Ed25519 public key.
    pub public_key: String,
    pub disposition: ControlPlaneGrantKeyDisposition,
}

/// Versioned public keyset fetched and pinned by execution agents.
///
/// `keys` is a nonempty, strictly `key_id`-sorted set with exactly one active
/// member matching `active_key_id`. A higher `keyset_version` represents an
/// operator-authorized rotation, revocation, or rollback publication. Reusing a
/// version for different bytes and decreasing the version both fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneGrantKeyset {
    pub keyset_version: u64,
    pub active_key_id: String,
    pub keys: Vec<ControlPlaneGrantVerifyingKey>,
}

/// Atomic bootstrap document returned by the control plane to an execution
/// agent. The protocol version and the exact keyset are intentionally carried
/// in one response so compatibility cannot be checked against a different
/// publication than the keys that are pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneGrantKeysetResponse {
    pub keyset: ControlPlaneGrantKeyset,
    pub protocol_version: u32,
}

// ---------------------------------------------------------------------------
// Redaction policy vocabulary — the shared CP/agent contract
// ---------------------------------------------------------------------------

/// The redaction policy version the agent stamps into every `SignedEnvelope`
/// (the agent emits this; the CP recognises it). It is an opaque identifier
/// SLUG, not a semver number — bump it (e.g. `ryuki-redaction-v2`) when the
/// redaction rules change, and place the new value in
/// [`SUPPORTED_REDACTION_POLICY_VERSIONS`] so the CP will accept results under
/// it. Superseded policies with known gaps must be removed rather than retained
/// for compatibility. Both sides reference this one constant so emission and
/// acceptance can never silently drift.
pub const REDACTION_POLICY_VERSION: &str = "ryuki-redaction-v2";

/// The closed set of `redaction_policy_version` values the control plane will
/// accept at result ingestion. `redaction_policy_version` is the ONE
/// `SignedEnvelope` string field with no authoritative per-result counterpart to
/// cross-check, so the CP gates it against this allowlist (fail-closed): a result
/// redacted under a policy the CP does not recognise is rejected, which both
/// closes the field as a free-form text channel and refuses evidence the CP
/// cannot interpret. Keep this in lockstep with the policies the CP actually
/// understands.
pub const SUPPORTED_REDACTION_POLICY_VERSIONS: &[&str] = &[REDACTION_POLICY_VERSION];

/// Exact schema identifier for the only Terraform live-plan evidence envelope
/// that may cross the runner/control-plane boundary. The runner emits this and
/// approval parsing requires it, preventing legacy full-plan JSON from being
/// mistaken for a safe projection.
pub const TERRAFORM_LIVE_PLAN_EVIDENCE_SCHEMA_VERSION: &str =
    "ryuki.terraform.live-plan-evidence.v1";

// ---------------------------------------------------------------------------
// Wire protocol version — the CP↔agent schema-compatibility marker
// ---------------------------------------------------------------------------

/// Monotonic version of the CP↔agent WIRE SCHEMA (the shapes in this module).
///
/// This is distinct from [`REDACTION_POLICY_VERSION`], which versions the
/// redaction *ruleset*, not the wire schema. Bump this whenever a wire struct
/// gains/loses/changes a field in a way an old peer could not parse compatibly,
/// and add the new value to [`SUPPORTED_PROTOCOL_VERSIONS`].
///
/// **INVARIANT — this is a COMPATIBILITY MARKER ONLY.** It travels UNSIGNED, in
/// the [`PROTOCOL_VERSION_HEADER`] transport header, so it can be read *before*
/// body deserialisation and signature verification (it names *which* schema a
/// payload is — burying it inside a signed struct would be circular). Because it
/// is unsigned it MUST NEVER be used to select a signing domain, weaken result
/// verification, or change the interpretation of any signed field. A future
/// version that changes SIGNED bytes MUST bump the signing domain separator in
/// `crypto` (or bind the version into the signed bytes at that point) — it must
/// not lean on this header. The threat model is accidental drift, not forgery:
/// a tampered header yields a version-mismatch *rejection* (denial), never a
/// verification bypass, because every security-sensitive field stays signed.
/// Version 2 adds `JobSpec.state_key` as a live-execution safety boundary. An
/// older v1 agent would ignore that field, execute against its legacy shared or
/// local backend, and only reveal the mismatch when the CP rejects its result
/// digest after execution. This version is therefore intentionally not
/// interoperable with v1 for any job mode.
///
/// Version 3 replaces first-writer public enrollment with a preprovisioned,
/// single-use challenge and an Ed25519 proof-of-possession signature. A v2
/// agent cannot produce those required registration fields, so v2 and v3 are
/// intentionally not interoperable at the enrollment boundary.
///
/// Version 4 adds the required destination `platform` to the CP-signed
/// [`VerifiedLiveContext`] and moves that grant to a new signing domain. A v3
/// peer or legacy grant cannot be interpreted without this mutation-authority
/// binding, so the cutover intentionally rejects v3 rather than running a
/// mixed-signing-domain fleet.
///
/// Version 5 binds every mutation grant to the successful planning agent's
/// immutable enrollment/key and to a canonical non-secret execution trust
/// profile. It also signs that full profile into every successful live result.
/// Legacy v4 grants and v2 result signatures are intentionally rejected.
///
/// Version 6 binds every grant to the exact immutable successful-plan job and
/// leased attempt, binds every result to the exact immutable agent enrollment,
/// and advances the trust-profile schema for provider/backend authority. Legacy
/// v5 digest-only grants and v3 result signatures are intentionally rejected.
/// Version 6 also adds `raw_plan_digest` as an additive-optional trailing signed
/// field. Its `None` encoding contributes zero bytes, preserving existing v6
/// signatures, while result validation requires `Some` for every successful
/// LivePlan so legacy redacted-digest commitments fail closed at ingestion.
///
/// Version 7 makes the positive request resource version required in every
/// [`JobSpec`], [`VerifiedLiveContext`], and [`SignedEnvelope`]. Both signed
/// message types advance to `ryuki-v5/signed-envelope` and
/// `ryuki-v7/verified-live-context`, so a v6 peer or signature cannot be
/// reinterpreted as version-bound authority. Mixed v6/v7 operation is
/// intentionally unsupported because accepting an omitted version would
/// silently downgrade approval and result freshness.
///
/// Version 8 adds the required control-plane grant `kid`, binds it into the
/// `ryuki-v8/verified-live-context` signature domain, and replaces the single
/// CP public-key response with a versioned active/verify-only keyset. A v7
/// agent cannot select the correct overlap key or refuse an unknown/revoked
/// `kid`, so mixed v7/v8 operation is intentionally unsupported.
///
/// Version 9 makes canonical `deployment_id` and `trust_domain_id` identities
/// required in every [`VerifiedLiveContext`] and binds both into the
/// `ryuki-v9/verified-live-context` signature domain. A v8 grant can bind only
/// its destination platform/site and therefore cannot be reinterpreted as
/// deployment- and trust-domain-scoped authority. Mixed v8/v9 operation is
/// intentionally unsupported.
pub const PROTOCOL_VERSION: u32 = 9;

/// The closed set of wire-protocol versions a peer will accept, gated
/// fail-closed exactly like [`SUPPORTED_REDACTION_POLICY_VERSIONS`]. During a
/// rollout that introduces version N, widen this to `&[N-1, N]` so a mixed fleet
/// interoperates, then narrow to `&[N]` once every peer is upgraded. Both the CP
/// (accepting agent requests) and the agent (accepting the CP's advertised
/// version) reference this ONE constant, so emission and acceptance cannot drift.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[9];

/// The version an absent [`PROTOCOL_VERSION_HEADER`] is resolved to. A peer that
/// predates protocol versioning sends no header; it is, by definition, speaking
/// the schema that existed before the field — version 1. The resolved value is
/// STILL allowlist-checked against [`SUPPORTED_PROTOCOL_VERSIONS`], so this is a
/// non-breaking backfill, not a bypass: the day `1` leaves the allowlist, an
/// absent header is rejected too. Mirrors the `agents.protocol_version` column
/// default.
pub const PROTOCOL_VERSION_LEGACY: u32 = 1;

/// Transport header carrying the sender's [`PROTOCOL_VERSION`] on every
/// agent↔CP request (decimal `u32`). Lower-case so it matches `http::HeaderName`
/// canonicalisation directly.
pub const PROTOCOL_VERSION_HEADER: &str = "x-ryuki-protocol-version";

// ---------------------------------------------------------------------------
// SignedEnvelope — tamper-evident result binding
// ---------------------------------------------------------------------------

/// Binds the full execution context for every result posted by the agent.
/// The CP verifies the signature against the enrolled agent public key and
/// rejects stale attempts via `(attempt_id, lease_generation, cp_nonce)`.
///
/// **Signable fields** (fixed order — everything except `signature`; domain
/// separator `ryuki-v5/signed-envelope`):
/// `agent_id, agent_enrollment_id, platform, job_id, attempt_id, lease_generation, request_id,
///  request_resource_version, result_id, mode (serialised), status (serialised), job_spec_digest,
///  approved_plan_digest, execution_trust_profile, evidence_digest,
///  redaction_policy_version, timestamp (RFC 3339), key_id, cp_nonce,
///  raw_plan_digest (additive-optional trailing field)`
///
/// `result_id` MUST equal [`JobResult::result_id`]; the CP equality-checks this
/// in S3 to prevent `result_id` forgery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub agent_id: String,
    /// Immutable UUID of the exact agent enrollment that authenticated and
    /// signed this result. Human-readable `agent_id` values and signing keys
    /// may be reused only by a later enrollment; this value prevents that
    /// later row from inheriting an earlier result's authority.
    pub agent_enrollment_id: Uuid,
    pub platform: String,
    pub job_id: Uuid,
    pub attempt_id: Uuid,
    pub lease_generation: u64,
    pub request_id: Uuid,
    /// Exact positive request version copied from the dispatched [`JobSpec`].
    /// It is signature-bound and must equal the current stored request and any
    /// applicable [`VerifiedLiveContext`] at result ingestion.
    pub request_resource_version: RequestResourceVersion,
    /// Idempotency key generated by the agent before writing to its durable
    /// outbox.  Bound by the signature to prevent forgery.  Must equal
    /// [`JobResult::result_id`] — the CP enforces this (S3).
    pub result_id: Uuid,
    /// Serialised `JobMode` label (e.g. `"live_apply"`).
    pub mode: JobMode,
    /// Terminal execution outcome reported by the agent.
    pub status: JobResultStatus,
    /// SHA-256 hex digest of the canonical `JobSpec` bytes.
    pub job_spec_digest: String,
    /// SHA-256 hex digest of the approved plan — `None` for non-`LiveApply` modes.
    pub approved_plan_digest: Option<String>,
    /// SHA-256 hex digest of the complete canonical raw plan before redaction.
    /// Required only for `LivePlan + Planned`; all other mode/status pairs must
    /// carry `None`. This is deliberately distinct from `evidence_digest`,
    /// which commits only to the safe post-redaction evidence pack.
    pub raw_plan_digest: Option<String>,
    /// Full canonical, non-secret live execution profile. Required by the CP
    /// for successful LivePlan/LiveApply/LiveDestroy results and absent for
    /// offline or refused outcomes. Its canonical digest is signed, so neither
    /// JSON field order nor unknown extension fields can alter its meaning.
    pub execution_trust_profile: Option<ExecutionTrustProfile>,
    /// SHA-256 hex digest of the (post-redaction) evidence pack.
    pub evidence_digest: String,
    /// Identifier of the redaction policy the agent applied — an opaque slug
    /// (e.g. [`REDACTION_POLICY_VERSION`] = `"ryuki-redaction-v2"`), NOT a semver
    /// number. The CP accepts only values in
    /// [`SUPPORTED_REDACTION_POLICY_VERSIONS`] at ingestion.
    pub redaction_policy_version: String,
    /// Agent-local timestamp at the moment of signing (informational; CP uses its
    /// own clock for the authoritative timestamp).
    pub timestamp: DateTime<Utc>,
    /// Key fingerprint / `key_id` — identifies which enrolled key signed this.
    pub key_id: String,
    /// One-time nonce from [`JobLease::cp_nonce`].  The agent copies it verbatim
    /// into the envelope; the CP verifies it against the stored lease nonce to
    /// prevent replay attacks.
    pub cp_nonce: String,
    /// Base64-encoded Ed25519 signature over the canonical bytes of the fields
    /// above.  Produced by `sign`; verified by `verify`.
    pub signature: String,
}

#[cfg(test)]
mod result_status_tests {
    use super::*;

    #[test]
    fn provider_authority_reference_is_closed_and_non_secret_shaped() {
        assert!(provider_authority_reference_is_canonical(
            "provider-authority/vsphere/defra-prod-fixture",
            "v17"
        ));
        for (id, version) in [
            ("vsphere/fixture", "v1"),
            ("provider-authority/vsphere/", "v1"),
            ("provider-authority/vsphere/private host", "v1"),
            ("provider-authority/vsphere/fixture", "1"),
            ("provider-authority/vsphere/fixture", "V1"),
        ] {
            assert!(!provider_authority_reference_is_canonical(id, version));
        }
    }

    #[test]
    fn backend_credential_authority_reference_is_closed_kind_scoped_and_non_secret_shaped() {
        assert!(backend_credential_authority_reference_is_canonical(
            "s3",
            "backend-credential-authority/s3/defra-prod-fixture",
            "v17"
        ));
        for (kind, id, revision) in [
            ("s3", "s3/fixture", "v1"),
            ("s3", "backend-credential-authority/s3/", "v1"),
            (
                "s3",
                "backend-credential-authority/s3/private account",
                "v1",
            ),
            ("s3", "backend-credential-authority/http/fixture", "v1"),
            ("s3", "backend-credential-authority/s3/fixture", "1"),
            ("s3", "backend-credential-authority/s3/fixture", "V1"),
        ] {
            assert!(!backend_credential_authority_reference_is_canonical(
                kind, id, revision
            ));
        }
    }

    #[test]
    fn result_status_matrix_is_fail_closed() {
        assert!(job_result_status_allowed(
            &JobMode::OfflineDryRun,
            &JobResultStatus::CheckOk
        ));
        assert!(job_result_status_allowed(
            &JobMode::LivePlan,
            &JobResultStatus::Planned
        ));
        assert!(job_result_status_allowed(
            &JobMode::LivePlan,
            &JobResultStatus::CheckOk
        ));
        assert!(job_result_status_allowed(
            &JobMode::LiveApply,
            &JobResultStatus::Applied
        ));
        assert!(job_result_status_allowed(
            &JobMode::LiveDestroy,
            &JobResultStatus::Applied
        ));

        assert!(!job_result_status_allowed(
            &JobMode::LiveDestroy,
            &JobResultStatus::Planned
        ));
        assert!(!job_result_status_allowed(
            &JobMode::LiveApply,
            &JobResultStatus::CheckOk
        ));
        for mode in [
            JobMode::OfflineDryRun,
            JobMode::LivePlan,
            JobMode::LiveApply,
            JobMode::LiveDestroy,
        ] {
            assert!(!job_result_status_allowed(
                &mode,
                &JobResultStatus::Verified
            ));
        }
    }

    #[test]
    fn heartbeat_renewal_copies_the_complete_lease_fence() {
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 9,
            fencing_token: "opaque-fence".to_owned(),
            deadline: Utc::now(),
            cp_nonce: "nonce".to_owned(),
        };
        let job_id = Uuid::new_v4();
        let heartbeat = AgentHeartbeat::renewing(job_id, &lease);
        assert_eq!(heartbeat.running_job_id, Some(job_id));
        assert_eq!(heartbeat.attempt_id, Some(lease.attempt_id));
        assert_eq!(heartbeat.lease_generation, Some(9));
        assert_eq!(heartbeat.fencing_token.as_deref(), Some("opaque-fence"));
    }
}
