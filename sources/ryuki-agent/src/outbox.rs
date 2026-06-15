//! Durable at-least-once delivery outbox.
// S4c wires Outbox into the pull-loop.  Suppress dead-code warnings until then.
#![allow(dead_code)]
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
                })
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

        Ok(())
    }

    // ------------------------------------------------------------------
    // list_pending
    // ------------------------------------------------------------------

    /// Return all pending (un-delivered) `ResultBody` values.
    ///
    /// Reads every `*.json` file in `dir`.  Non-`*.json` files are ignored.
    /// Files that fail to deserialise are skipped with a logged warning (they
    /// could be corrupt partial writes — the caller should alert an operator).
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
                        "outbox: failed to deserialise pending file — skipping (possible corrupt write)"
                    );
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
    /// Idempotent: if the file has already been removed (e.g. a duplicate
    /// mark_delivered call), this returns `Ok(())`.
    pub fn mark_delivered(&self, result_id: Uuid) -> Result<(), OutboxError> {
        let path = self.file_path(result_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already removed — idempotent.
                Ok(())
            }
            Err(e) => Err(OutboxError::Io {
                path: path.display().to_string(),
                source: e,
            }),
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn file_path(&self, result_id: Uuid) -> PathBuf {
        self.dir.join(format!("{}.json", result_id))
    }
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
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::OfflineDryRun,
        };
        let spec_digest = job_spec_digest(&spec);
        let evidence = b"stub evidence".to_vec();
        let evidence_digest = sha256_hex(&evidence);

        let unsigned = SignedEnvelope {
            agent_id: "test-agent".to_string(),
            platform: "test-platform".to_string(),
            job_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "ryuki-redaction-v1".to_string(),
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
}
