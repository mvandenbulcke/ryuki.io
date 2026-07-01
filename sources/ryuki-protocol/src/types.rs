//! Wire types for the Ryuki agent↔control-plane protocol.
//! All types derive serde for over-the-wire JSON; all are pure data (no IO).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Job execution mode
// ---------------------------------------------------------------------------

/// The three execution modes.  The agent MUST NOT elevate the mode on its own.
///
/// - `OfflineDryRun` — no platform access; validate + plan without providers.
/// - `LivePlan`     — reads live state (`terraform plan` / `ansible --check`).
/// - `LiveApply`    — mutates.  Requires a CP-signed `VerifiedLiveContext`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobMode {
    OfflineDryRun,
    LivePlan,
    LiveApply,
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
    /// Provider name → version (Terraform only; empty for Ansible).
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

/// Sent by the agent on `POST /api/agents/register`.
/// Remains in `Pending` status until an admin approves it and reconciles
/// capabilities against the trusted inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRegistration {
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
}

// ---------------------------------------------------------------------------
// Job specification
// ---------------------------------------------------------------------------

/// References the IaC artefacts by stable identifier + digest, never by
/// inline content.  Credentials are **never** in the spec — the agent
/// resolves them from its own environment/secret store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    /// The upstream change-request id this job implements.
    pub request_id: Uuid,
    /// The service-catalogue offering being executed.
    pub offering_id: Uuid,
    /// Stable reference to the IaC template (path or content-addressed id).
    pub iac_ref: String,
    /// SHA-256 hex digest of the IaC template at the time the job was created.
    pub iac_digest: String,
    /// Variable overrides (non-secret; secrets are env-injected by the agent).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
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
    /// Opaque fencing token (e.g. a random UUID string).  Must be echoed back
    /// in `ack`, `heartbeat`, and `result` calls.
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

// ---------------------------------------------------------------------------
// Job (the full dispatched unit)
// ---------------------------------------------------------------------------

/// A dispatchable unit of work, as returned by `GET /api/agents/{id}/jobs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    /// Platform / site this job targets.
    pub platform: String,
    pub spec: JobSpec,
    pub status: JobStatus,
    /// Present when the job has been leased.
    pub lease: Option<JobLease>,
    /// CP-signed approval grant — required for `LiveApply`; absent for other modes.
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
    /// SHA-256 hex digest of the (redacted) evidence pack.
    /// The evidence bytes are posted separately (multipart / blob store reference).
    pub evidence_digest: String,
    /// The `SignedEnvelope` that binds all of the above for tamper-evident storage.
    pub signed_envelope: SignedEnvelope,
}

// ---------------------------------------------------------------------------
// VerifiedLiveContext — CP-signed approval grant
// ---------------------------------------------------------------------------

/// Issued by the control plane when an operator approves a `LiveApply`.
/// The agent verifies this against the CP's own public key before executing.
///
/// Signable fields (fixed order, see `signing_bytes_vlc`):
/// `request_id, approved_plan_digest, approver, expiry (RFC 3339)`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedLiveContext {
    /// The upstream change-request id.
    pub request_id: Uuid,
    /// SHA-256 hex digest of the plan the approver reviewed.
    /// The agent re-plans and MUST match this before applying.
    pub approved_plan_digest: String,
    /// Identity of the approver (e.g. username or `subject` claim).
    pub approver: String,
    /// Grant expiry (CP DB time).  The agent MUST reject an expired grant.
    pub expiry: DateTime<Utc>,
    /// Base64-encoded Ed25519 signature over the canonical bytes of the fields
    /// above.  Produced by `sign_vlc`; verified by `verify_vlc`.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Redaction policy vocabulary — the shared CP/agent contract
// ---------------------------------------------------------------------------

/// The redaction policy version the agent stamps into every `SignedEnvelope`
/// (the agent emits this; the CP recognises it). It is an opaque identifier
/// SLUG, not a semver number — bump it (e.g. `ryuki-redaction-v2`) when the
/// redaction rules change, and add the new value to
/// [`SUPPORTED_REDACTION_POLICY_VERSIONS`] so the CP will accept results under
/// it. Both sides reference this one constant so emission and acceptance can
/// never silently drift.
pub const REDACTION_POLICY_VERSION: &str = "ryuki-redaction-v1";

/// The closed set of `redaction_policy_version` values the control plane will
/// accept at result ingestion. `redaction_policy_version` is the ONE
/// `SignedEnvelope` string field with no authoritative per-result counterpart to
/// cross-check, so the CP gates it against this allowlist (fail-closed): a result
/// redacted under a policy the CP does not recognise is rejected, which both
/// closes the field as a free-form text channel and refuses evidence the CP
/// cannot interpret. Keep this in lockstep with the policies the CP actually
/// understands.
pub const SUPPORTED_REDACTION_POLICY_VERSIONS: &[&str] = &[REDACTION_POLICY_VERSION];

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
pub const PROTOCOL_VERSION: u32 = 1;

/// The closed set of wire-protocol versions a peer will accept, gated
/// fail-closed exactly like [`SUPPORTED_REDACTION_POLICY_VERSIONS`]. During a
/// rollout that introduces version N, widen this to `&[N-1, N]` so a mixed fleet
/// interoperates, then narrow to `&[N]` once every peer is upgraded. Both the CP
/// (accepting agent requests) and the agent (accepting the CP's advertised
/// version) reference this ONE constant, so emission and acceptance cannot drift.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[1];

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
/// separator `ryuki-v2/signed-envelope`):
/// `agent_id, platform, job_id, attempt_id, lease_generation, request_id,
///  result_id, mode (serialised), status (serialised), job_spec_digest,
///  approved_plan_digest, evidence_digest, redaction_policy_version,
///  timestamp (RFC 3339), key_id, cp_nonce`
///
/// `result_id` MUST equal [`JobResult::result_id`]; the CP equality-checks this
/// in S3 to prevent `result_id` forgery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub agent_id: String,
    pub platform: String,
    pub job_id: Uuid,
    pub attempt_id: Uuid,
    pub lease_generation: u64,
    pub request_id: Uuid,
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
    /// SHA-256 hex digest of the (post-redaction) evidence pack.
    pub evidence_digest: String,
    /// Identifier of the redaction policy the agent applied — an opaque slug
    /// (e.g. [`REDACTION_POLICY_VERSION`] = `"ryuki-redaction-v1"`), NOT a semver
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
