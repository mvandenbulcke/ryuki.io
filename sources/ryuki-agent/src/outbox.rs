//! Durable at-least-once delivery outbox.
//!
//! ## At-least-once delivery contract
//!
//! 1. `enqueue`: serialise `ResultBody` → `<dir>/<result_id>.json`, fsync.
//!    Write BEFORE any network POST — the result is durable before the attempt.
//! 2. POST to the CP.
//! 3. On 2xx (including idempotent 200): `mark_delivered` removes the file.
//! 4. On failure / crash: `list_pending` at startup returns all un-delivered
//!    results.  The agent replays them; the CP's idempotency key
//!    (`job_id, attempt_id, result_id`) deduplicates the replay.
//!
//! ## Idempotency guarantee
//!
//! `result_id` is generated once in `build_signed_result` and bound by the
//! Ed25519 signature.  The CP returns idempotent-200 for a valid signed replay
//! of an already-recorded result.  The outbox therefore delivers exactly-once
//! semantics via at-least-once HTTP + CP-side idempotency.
//!
//! ## Attempt tracking and quarantine
//!
//! A sidecar file `<dir>/<result_id>.attempts` (plain u32 text) tracks how many
//! transient-failure attempts have been made.  This persists across restarts.
//! When the count reaches the configured `max_attempts`, the entry is
//! **quarantined**: the JSON file is moved to `<dir>/dead/<result_id>.json` and
//! the sidecar is removed.  Quarantined files are never re-posted.
//!
//! The signed `ResultBody` JSON is **never mutated** — the attempt counter lives
//! only in the sidecar so the Ed25519 signature remains valid for potential
//! manual replay.
//!
//! `OperatorAlert` errors (401, 403) are kept in the outbox without incrementing
//! the attempt counter — they must be resolved by a human, not retried to death.
//!
//! ## list_pending filtering
//!
//! `list_pending` reads only top-level `*.json` files.  It skips:
//! - Subdirectories (including `dead/`).
//! - Files whose extension is not exactly `.json` (including `*.attempts`).
//! - Incompatible or corrupt JSON is moved byte-for-byte to `dead/` instead of
//!   being warned-and-skipped forever after a protocol cutover.
//!
//! ## Security note
//!
//! Evidence is scrubbed before it reaches the outbox (the runner applies
//! value-based scrubbing; the executor wraps the RunOutcome as JSON).  The
//! outbox files are not secret but contain execution logs; restrict access
//! via filesystem permissions on the outbox directory (controlled by the
//! caller / systemd unit).

use std::path::PathBuf;

use thiserror::Error;
use uuid::Uuid;

use crate::result::ResultBody;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum OutboxError {
    #[error("I/O error for outbox path {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialise ResultBody: {0}")]
    Serialise(String),
    /// Returned when a specific file cannot be deserialised (not used by
    /// `list_pending` which skips corrupt files, but kept for callers that
    /// want to surface individual parse errors).
    #[allow(dead_code)]
    #[error("failed to deserialise outbox file {path}: {source}")]
    Deserialise {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

// ---------------------------------------------------------------------------
// Outbox
// ---------------------------------------------------------------------------

/// File-based durable outbox for signed `ResultBody` values.
///
/// One file per pending result: `<dir>/<result_id>.json`.
/// The `result_id` in the filename is the canonical idempotency key; the file
/// is removed by `mark_delivered` after a successful HTTP 2xx response.
///
/// See the module-level doc for attempt-tracking and quarantine semantics.
pub struct Outbox {
    dir: PathBuf,
}

impl Outbox {
    /// Create an `Outbox` backed by `dir`.
    ///
    /// `dir` must exist and be writable; this constructor does not create it.
    /// Use `Outbox::create_dir` if you want to create the directory first.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Create `dir` (and all parents) if it does not exist, then open the outbox.
    pub fn create_dir(dir: impl Into<PathBuf>) -> Result<Self, OutboxError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| OutboxError::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        Ok(Self { dir })
    }

    // ------------------------------------------------------------------
    // enqueue
    // ------------------------------------------------------------------

    /// Persist `body` to `<dir>/<result_id>.json` with fsync.
    ///
    /// The `result_id` is extracted from `body.job_result.result_id`.
    /// Write BEFORE any network POST — the result survives a crash between
    /// enqueue and the successful HTTP response.
    ///
    /// If a file for this `result_id` already exists (e.g. a duplicate enqueue
    /// after a partial write), the existing file is KEPT and this call succeeds
    /// silently (idempotent enqueue — the existing file is the durable copy).
    pub fn enqueue(&self, body: &ResultBody) -> Result<(), OutboxError> {
        let result_id = body.job_result.result_id;
        let path = self.file_path(result_id);

        // Serialise BEFORE opening the file.
        let json =
            serde_json::to_vec_pretty(body).map_err(|e| OutboxError::Serialise(e.to_string()))?;

        // Use create_new so a duplicate enqueue does not clobber the existing file.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);

        // On Unix, create the file as owner-read/write (0600) for defence-in-depth.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let mut file = match opts.open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // File already exists — the result is already enqueued (idempotent).
                return Ok(());
            }
            Err(e) => {
                return Err(OutboxError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };

        use std::io::Write;
        file.write_all(&json).map_err(|e| OutboxError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        // fsync: ensure bytes hit disk before we consider the write durable.
        file.sync_all().map_err(|e| OutboxError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        // fsync the CONTAINING DIRECTORY too: sync_all() on the file persists its
        // contents but not necessarily its directory ENTRY, so a hard crash could
        // lose a freshly-created result the module's contract promises survives.
        // (Unix; directory fsync is the standard crash-durability step. On other
        // platforms this is skipped — the agent targets Unix hosts.)
        #[cfg(unix)]
        {
            let dir = std::fs::File::open(&self.dir).map_err(|e| OutboxError::Io {
                path: self.dir.display().to_string(),
                source: e,
            })?;
            dir.sync_all().map_err(|e| OutboxError::Io {
                path: self.dir.display().to_string(),
                source: e,
            })?;
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // list_pending
    // ------------------------------------------------------------------

    /// Return all pending (un-delivered) `ResultBody` values.
    ///
    /// Reads only top-level `*.json` files in `dir`.  Subdirectories (including
    /// `dead/`) and non-`.json` files (including `.attempts` sidecars) are
    /// silently skipped. Files that fail to deserialise are quarantined
    /// byte-for-byte so incompatible signed results remain available for
    /// operator recovery without blocking every future drain pass.
    ///
    /// The order of returned results is filesystem-dependent (not guaranteed).
    pub fn list_pending(&self) -> Result<Vec<ResultBody>, OutboxError> {
        let mut results = Vec::new();

        let entries = std::fs::read_dir(&self.dir).map_err(|e| OutboxError::Io {
            path: self.dir.display().to_string(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| OutboxError::Io {
                path: self.dir.display().to_string(),
                source: e,
            })?;

            let path = entry.path();

            // Skip subdirectories (this is how we exclude dead/).
            if path.is_dir() {
                continue;
            }

            // Only read files with the exact extension ".json".
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "outbox: failed to read pending file — skipping"
                    );
                    continue;
                }
            };

            match serde_json::from_slice::<ResultBody>(&data) {
                Ok(body) => results.push(body),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "outbox: pending file is incompatible or corrupt — quarantining raw bytes"
                    );
                    self.quarantine_path(&path)?;
                }
            }
        }

        Ok(results)
    }

    // ------------------------------------------------------------------
    // mark_delivered
    // ------------------------------------------------------------------

    /// Remove `<dir>/<result_id>.json` after a successful HTTP 2xx response.
    ///
    /// Also removes the `.attempts` sidecar if present (idempotent).
    ///
    /// Idempotent: if the file has already been removed (e.g. a duplicate
    /// mark_delivered call), this returns `Ok(())`.
    pub fn mark_delivered(&self, result_id: Uuid) -> Result<(), OutboxError> {
        let path = self.file_path(result_id);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already removed — idempotent.
            }
            Err(e) => {
                return Err(OutboxError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        }
        // Best-effort: clean up the sidecar even if the main file was already gone.
        self.clear_attempts(result_id)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Attempt tracking (sidecar)
    // ------------------------------------------------------------------

    /// Increment the persistent attempt counter for `result_id`.
    ///
    /// Reads `<dir>/<result_id>.attempts`, increments, writes back.  Returns
    /// the new (post-increment) count.  If the sidecar does not exist, the
    /// count starts at 0 before increment (first call returns 1).
    pub fn record_attempt(&self, result_id: Uuid) -> Result<u32, OutboxError> {
        let path = self.attempts_path(result_id);
        let current = self.read_attempts_raw(&path)?;
        let next = current.saturating_add(1);
        self.write_attempts_raw(&path, next)?;
        Ok(next)
    }

    /// Remove the `.attempts` sidecar for `result_id` (idempotent).
    ///
    /// Called after `mark_delivered` or after quarantine (the file has already
    /// been moved to `dead/` so the sidecar in the main dir must be removed).
    pub fn clear_attempts(&self, result_id: Uuid) -> Result<(), OutboxError> {
        let path = self.attempts_path(result_id);
        match std::fs::remove_file(&path) {
            Ok(()) | Err(_) => Ok(()), // NotFound or any other error: ignore.
        }
    }

    // ------------------------------------------------------------------
    // Quarantine
    // ------------------------------------------------------------------

    /// Move `<dir>/<result_id>.json` to `<dir>/dead/<result_id>.json`.
    ///
    /// Creates `<dir>/dead/` on first use.  Also removes the `.attempts`
    /// sidecar in the main directory.
    ///
    /// The signed `ResultBody` JSON is copied byte-for-byte — it is NEVER
    /// mutated (the Ed25519 signature must remain valid for manual replay).
    ///
    /// If the source file does not exist (e.g. already quarantined), returns
    /// `Ok(())` (idempotent).
    pub fn quarantine(&self, result_id: Uuid) -> Result<(), OutboxError> {
        self.quarantine_path(&self.file_path(result_id))?;
        self.clear_attempts(result_id)
    }

    fn quarantine_path(&self, src: &std::path::Path) -> Result<(), OutboxError> {
        let dead_dir = self.dead_dir();
        std::fs::create_dir_all(&dead_dir).map_err(|e| OutboxError::Io {
            path: dead_dir.display().to_string(),
            source: e,
        })?;

        let file_name = src.file_name().ok_or_else(|| OutboxError::Io {
            path: src.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "outbox quarantine source has no file name",
            ),
        })?;
        let dst = dead_dir.join(file_name);

        match std::fs::rename(src, &dst) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Source already gone — idempotent.
            }
            Err(e) => {
                // rename(2) can fail across filesystems (EXDEV). Fall back to
                // copy + remove so tempdir-based tests and cross-fs setups work.
                if e.raw_os_error() == Some(libc_exdev()) {
                    std::fs::copy(src, &dst).map_err(|ce| OutboxError::Io {
                        path: dst.display().to_string(),
                        source: ce,
                    })?;
                    std::fs::remove_file(src).map_err(|re| OutboxError::Io {
                        path: src.display().to_string(),
                        source: re,
                    })?;
                } else {
                    return Err(OutboxError::Io {
                        path: src.display().to_string(),
                        source: e,
                    });
                }
            }
        }

        if let Some(result_id) = src
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| Uuid::parse_str(stem).ok())
        {
            self.clear_attempts(result_id)?;
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn file_path(&self, result_id: Uuid) -> PathBuf {
        self.dir.join(format!("{}.json", result_id))
    }

    fn attempts_path(&self, result_id: Uuid) -> PathBuf {
        self.dir.join(format!("{}.attempts", result_id))
    }

    fn dead_dir(&self) -> PathBuf {
        self.dir.join("dead")
    }

    fn read_attempts_raw(&self, path: &std::path::Path) -> Result<u32, OutboxError> {
        match std::fs::read_to_string(path) {
            Ok(s) => s.trim().parse::<u32>().map_err(|_| OutboxError::Io {
                path: path.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "attempts file contains non-numeric data",
                ),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(OutboxError::Io {
                path: path.display().to_string(),
                source: e,
            }),
        }
    }

    fn write_attempts_raw(&self, path: &std::path::Path, count: u32) -> Result<(), OutboxError> {
        std::fs::write(path, count.to_string()).map_err(|e| OutboxError::Io {
            path: path.display().to_string(),
            source: e,
        })
    }
}

/// Cross-platform EXDEV constant (rename across filesystems).
/// On non-Unix platforms this returns a sentinel that will never match.
fn libc_exdev() -> i32 {
    #[cfg(target_os = "linux")]
    return 18; // EXDEV on Linux
    #[cfg(target_os = "macos")]
    return 18; // EXDEV on macOS
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return -1; // Sentinel — will never match a real OS error code.
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ryuki_protocol::{
        job_spec_digest, sha256_hex, sign, JobMode, JobResult, JobResultStatus, JobSpec,
        SignedEnvelope,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    use crate::identity::AgentIdentity;

    // -----------------------------------------------------------------------
    // Fixture helpers
    // -----------------------------------------------------------------------

    /// Build a minimal `ResultBody` with a given `result_id` for outbox tests.
    /// We construct a signed envelope so the struct is fully valid, even though
    /// the outbox only cares about JSON round-tripping.
    fn make_result_body(result_id: Uuid) -> ResultBody {
        let identity = AgentIdentity::generate();
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some("request-test".to_string()),
            mode: JobMode::OfflineDryRun,
        };
        let spec_digest = job_spec_digest(&spec);
        let evidence = b"stub evidence".to_vec();
        let evidence_digest = sha256_hex(&evidence);

        let unsigned = SignedEnvelope {
            agent_id: "test-agent".to_string(),
            agent_enrollment_id: Uuid::nil(),
            platform: "test-platform".to_string(),
            job_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: spec.request_id,
            request_resource_version: spec.request_resource_version,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: identity.public_key_b64(),
            cp_nonce: Uuid::new_v4().to_string(),
            signature: String::new(),
        };
        let signed_envelope = sign(unsigned, identity.signing_key());

        let job_result = JobResult {
            job_id: signed_envelope.job_id,
            attempt_id: signed_envelope.attempt_id,
            result_id: signed_envelope.result_id,
            status: signed_envelope.status.clone(),
            raw_plan_digest: signed_envelope.raw_plan_digest.clone(),
            evidence_digest: signed_envelope.evidence_digest.clone(),
            signed_envelope,
        };

        ResultBody {
            job_result,
            evidence,
            evidence_json: Some(serde_json::json!({"stub": true})),
        }
    }

    // -----------------------------------------------------------------------
    // enqueue → list_pending roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn enqueue_and_list_pending_roundtrip() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        let result_id = Uuid::new_v4();
        let body = make_result_body(result_id);

        outbox.enqueue(&body).expect("enqueue must succeed");

        let pending = outbox.list_pending().expect("list_pending must succeed");
        assert_eq!(pending.len(), 1, "one pending result expected");
        assert_eq!(
            pending[0].job_result.result_id, result_id,
            "result_id must survive round-trip"
        );
    }

    // -----------------------------------------------------------------------
    // mark_delivered removes the file
    // -----------------------------------------------------------------------

    #[test]
    fn mark_delivered_removes_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        let result_id = Uuid::new_v4();
        let body = make_result_body(result_id);

        outbox.enqueue(&body).expect("enqueue");
        outbox
            .mark_delivered(result_id)
            .expect("mark_delivered must succeed");

        let pending = outbox.list_pending().expect("list_pending");
        assert!(
            pending.is_empty(),
            "pending list must be empty after mark_delivered"
        );
    }

    // -----------------------------------------------------------------------
    // list_pending after delivery is empty
    // -----------------------------------------------------------------------

    #[test]
    fn list_pending_empty_after_delivery() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        outbox.enqueue(&make_result_body(id1)).expect("enqueue 1");
        outbox.enqueue(&make_result_body(id2)).expect("enqueue 2");

        outbox.mark_delivered(id1).expect("deliver 1");
        outbox.mark_delivered(id2).expect("deliver 2");

        let pending = outbox.list_pending().expect("list_pending");
        assert!(pending.is_empty(), "all delivered — list must be empty");
    }

    // -----------------------------------------------------------------------
    // multiple pending results survive
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_pending_results_all_listed() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        for &id in &ids {
            outbox.enqueue(&make_result_body(id)).expect("enqueue");
        }

        let pending = outbox.list_pending().expect("list_pending");
        assert_eq!(pending.len(), 3, "all three pending results must be listed");
        // Verify all result_ids are present (order not guaranteed).
        let pending_ids: std::collections::HashSet<Uuid> =
            pending.iter().map(|b| b.job_result.result_id).collect();
        for &id in &ids {
            assert!(
                pending_ids.contains(&id),
                "result_id {id} must be in pending list"
            );
        }
    }

    // -----------------------------------------------------------------------
    // mark_delivered is idempotent (second call on missing file is Ok)
    // -----------------------------------------------------------------------

    #[test]
    fn mark_delivered_is_idempotent() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        let id = Uuid::new_v4();
        outbox.enqueue(&make_result_body(id)).expect("enqueue");
        outbox.mark_delivered(id).expect("first delivery");

        // Second call on an already-removed file must NOT error.
        assert!(
            outbox.mark_delivered(id).is_ok(),
            "second mark_delivered on removed file must be Ok"
        );
    }

    // -----------------------------------------------------------------------
    // enqueue is idempotent (duplicate enqueue does not corrupt the file)
    // -----------------------------------------------------------------------

    #[test]
    fn enqueue_is_idempotent() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        let id = Uuid::new_v4();
        let body = make_result_body(id);

        outbox.enqueue(&body).expect("first enqueue");
        // Second enqueue with the same result_id must not error and must not
        // clobber the existing file.
        assert!(
            outbox.enqueue(&body).is_ok(),
            "duplicate enqueue must be Ok (idempotent)"
        );

        let pending = outbox.list_pending().expect("list_pending");
        assert_eq!(pending.len(), 1, "still exactly one pending result");
    }

    // -----------------------------------------------------------------------
    // create_dir creates directory
    // -----------------------------------------------------------------------

    #[test]
    fn create_dir_creates_nonexistent_directory() {
        let parent = tempfile::TempDir::new().expect("tempdir");
        let new_dir = parent.path().join("outbox").join("nested");

        let outbox = Outbox::create_dir(&new_dir).expect("create_dir must succeed");

        assert!(
            new_dir.exists(),
            "create_dir must have created the directory"
        );

        // Should work immediately.
        let id = Uuid::new_v4();
        outbox
            .enqueue(&make_result_body(id))
            .expect("enqueue in new dir");
        let pending = outbox.list_pending().expect("list_pending");
        assert_eq!(pending.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Attempt tracking: record_attempt increments + persists
    // -----------------------------------------------------------------------

    #[test]
    fn record_attempt_increments_and_persists() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let id = Uuid::new_v4();

        // First call: sidecar does not exist yet → starts at 0, increments to 1.
        let n = outbox.record_attempt(id).expect("record_attempt 1");
        assert_eq!(n, 1, "first attempt must return 1");

        // Second call: sidecar now contains 1 → increments to 2.
        let n = outbox.record_attempt(id).expect("record_attempt 2");
        assert_eq!(n, 2, "second attempt must return 2");

        // Third call: increments to 3.
        let n = outbox.record_attempt(id).expect("record_attempt 3");
        assert_eq!(n, 3, "third attempt must return 3");

        // Verify the sidecar file exists on disk.
        let sidecar = dir.path().join(format!("{}.attempts", id));
        assert!(sidecar.exists(), "sidecar must exist after record_attempt");
    }

    // -----------------------------------------------------------------------
    // Attempt tracking: clear_attempts removes the sidecar
    // -----------------------------------------------------------------------

    #[test]
    fn clear_attempts_removes_sidecar() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let id = Uuid::new_v4();

        outbox.record_attempt(id).expect("record_attempt");
        let sidecar = dir.path().join(format!("{}.attempts", id));
        assert!(sidecar.exists(), "sidecar must exist before clear");

        outbox.clear_attempts(id).expect("clear_attempts");
        assert!(
            !sidecar.exists(),
            "sidecar must be gone after clear_attempts"
        );
    }

    // -----------------------------------------------------------------------
    // clear_attempts is idempotent (sidecar already gone)
    // -----------------------------------------------------------------------

    #[test]
    fn clear_attempts_is_idempotent() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let id = Uuid::new_v4();

        // No sidecar exists — clear_attempts must not error.
        assert!(
            outbox.clear_attempts(id).is_ok(),
            "clear_attempts on nonexistent sidecar must be Ok"
        );
    }

    // -----------------------------------------------------------------------
    // mark_delivered also clears the attempts sidecar
    // -----------------------------------------------------------------------

    #[test]
    fn mark_delivered_clears_attempts_sidecar() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let id = Uuid::new_v4();
        let body = make_result_body(id);

        outbox.enqueue(&body).expect("enqueue");
        outbox.record_attempt(id).expect("record_attempt");

        let sidecar = dir.path().join(format!("{}.attempts", id));
        assert!(sidecar.exists(), "sidecar must exist before mark_delivered");

        outbox.mark_delivered(id).expect("mark_delivered");

        assert!(
            !sidecar.exists(),
            "mark_delivered must remove the attempts sidecar"
        );
    }

    // -----------------------------------------------------------------------
    // Quarantine: moves json to dead/, removes sidecar, list_pending ignores dead/
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_moves_json_to_dead_dir() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let id = Uuid::new_v4();
        let body = make_result_body(id);

        outbox.enqueue(&body).expect("enqueue");
        outbox.record_attempt(id).expect("record_attempt");

        outbox.quarantine(id).expect("quarantine");

        // Main dir: JSON gone, sidecar gone.
        let json_path = dir.path().join(format!("{}.json", id));
        let sidecar = dir.path().join(format!("{}.attempts", id));
        assert!(
            !json_path.exists(),
            "json must be gone from main dir after quarantine"
        );
        assert!(!sidecar.exists(), "sidecar must be gone after quarantine");

        // dead/ dir: JSON present.
        let dead_path = dir.path().join("dead").join(format!("{}.json", id));
        assert!(dead_path.exists(), "json must be in dead/ after quarantine");

        // list_pending must return empty (dead/ is excluded).
        let pending = outbox.list_pending().expect("list_pending");
        assert!(
            pending.is_empty(),
            "list_pending must be empty after quarantine (dead/ excluded)"
        );
    }

    #[test]
    fn incompatible_legacy_entry_is_quarantined_byte_for_byte() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let id = Uuid::new_v4();
        let body = make_result_body(id);
        let mut legacy = serde_json::to_value(body).expect("serialize fixture");
        legacy["job_result"]["signed_envelope"]
            .as_object_mut()
            .expect("signed envelope")
            .remove("request_resource_version");
        let raw = serde_json::to_vec_pretty(&legacy).expect("legacy JSON");
        let source = dir.path().join(format!("{id}.json"));
        std::fs::write(&source, &raw).expect("write legacy outbox entry");
        outbox.record_attempt(id).expect("attempt sidecar");

        let pending = outbox.list_pending().expect("scan outbox");
        assert!(pending.is_empty());
        assert!(!source.exists());
        assert!(!dir.path().join(format!("{id}.attempts")).exists());
        let quarantined = dir.path().join("dead").join(format!("{id}.json"));
        assert_eq!(std::fs::read(quarantined).expect("raw quarantine"), raw);
    }

    // -----------------------------------------------------------------------
    // list_pending ignores .attempts sidecars in the main dir
    // -----------------------------------------------------------------------

    #[test]
    fn list_pending_ignores_attempts_sidecars() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let id = Uuid::new_v4();
        let body = make_result_body(id);

        outbox.enqueue(&body).expect("enqueue");
        outbox.record_attempt(id).expect("record_attempt");

        // The sidecar must NOT appear in list_pending.
        let pending = outbox.list_pending().expect("list_pending");
        assert_eq!(
            pending.len(),
            1,
            "only the json file must appear, not the .attempts sidecar"
        );
        assert_eq!(pending[0].job_result.result_id, id);
    }

    // -----------------------------------------------------------------------
    // quarantine is idempotent (source already gone)
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_is_idempotent() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let id = Uuid::new_v4();
        let body = make_result_body(id);

        outbox.enqueue(&body).expect("enqueue");
        outbox.quarantine(id).expect("first quarantine");

        // Second quarantine: source is gone — must be Ok.
        assert!(
            outbox.quarantine(id).is_ok(),
            "second quarantine on already-quarantined id must be Ok"
        );
    }
}
